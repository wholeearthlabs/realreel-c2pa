// Ceremony tool: builds and signs the RealReel C2PA CA hierarchy.
//
// One subcommand per certificate, run in order during the recorded ceremony
// (see the app repo's docs/runbooks/c2pa-ca-key-ceremony.md):
//
//   deno run -A ca/tools/build-ca-certs.ts root --out out/realreel-c2pa-root.pem
//   deno run -A ca/tools/build-ca-certs.ts ica  --root out/realreel-c2pa-root.pem --out out/realreel-claim-signing-ca.pem
//   deno run -A ca/tools/build-ca-certs.ts ocsp --root out/realreel-c2pa-root.pem --out out/realreel-ocsp-responder-1.pem
//
// Add --dry-run to build and display the certificate WITHOUT signing (for
// pre-ceremony review). Keyring/location default to realreel-ca-v2 / the
// `us` multi-region; override with env RING / LOC.
//
// Audit properties (why a script is acceptable ceremony tooling):
//   1. All certificate values are hardcoded in the PROFILES table below —
//      reviewed at a pinned git commit that the ceremony reads aloud. There is
//      no config indirection, and buildCaCert() lints the table against the
//      C2PA Certificate Policy §7.1 MUSTs before encoding anything.
//   2. Every to-be-signed certificate is printed field-by-field — including
//      the subject key's curve and SPKI SHA-256, the SKI/AKI, and the TBS
//      SHA-256 — and the tool PAUSES for explicit "SIGN" confirmation before
//      any KMS call.
//   3. After signing, the tool re-parses its own output and verifies that the
//      embedded TBS byte-equals the approved TBS, that the embedded subject
//      public key byte-equals the KMS-fetched SPKI, and that the signature
//      verifies against the root public key — so "what was displayed" and
//      "what was signed" cannot diverge silently. The final artifact is plain
//      X.509, independently checkable with openssl by the second person.
//
// KMS access: subject public keys are fetched with
// `gcloud kms keys versions get-public-key`; signing shells out to
// `gcloud kms asymmetric-sign` using the operator's gcloud auth (the
// ceremony's temporary grant). The ROOT key signs all three certificates.

import {
  asn1js,
  base64ToBytes,
  encodeTBS,
  extractSpkiDer,
  extractSubjectPublicKeyBytes,
  finalizeLeafPEM,
  findExtensionByOid,
  parseCertFromPem,
  pkijs,
} from "../_shared/attestation/pki.ts";
import { p384 } from "npm:@noble/curves@1.9.7/nist.js";

// pki.ts's TBS/finalize helpers are certificate-generic despite the "leaf"
// naming; re-exported under ceremony names so call sites read correctly.
export const encodeCertTBS = encodeTBS;
export const finalizeCertPem = finalizeLeafPEM;

// --- Profile table (mirrors Appendix A of the ceremony runbook, which -----
// --- mirrors C2PA Certificate Policy §7.1) --------------------------------

const O = "Whole Earth Labs LLC";
const C = "US";

const OID = {
  countryName: "2.5.4.6",
  organizationName: "2.5.4.10",
  commonName: "2.5.4.3",
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  certificatePolicies: "2.5.29.32",
  subjectKeyIdentifier: "2.5.29.14",
  authorityKeyIdentifier: "2.5.29.35",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  ocspNoCheck: "1.3.6.1.5.5.7.48.1.5",
  ecdsaWithSHA384: "1.2.840.10045.4.3.3",
  adOcsp: "1.3.6.1.5.5.7.48.1",
  adCaIssuers: "1.3.6.1.5.5.7.48.2",
  ekuEmailProtection: "1.3.6.1.5.5.7.3.4",
  ekuOcspSigning: "1.3.6.1.5.5.7.3.9",
  ekuDocumentSigning: "1.3.6.1.5.5.7.3.36",
  ekuC2PAClaimSigning: "1.3.6.1.4.1.62558.2.1",
  c2paCertPolicy: "1.3.6.1.4.1.62558.1.1",
} as const;

const EC_CURVE_NAMES: Record<string, string> = {
  "1.2.840.10045.3.1.7": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
};

// KeyUsage BIT STRING, MSB-first: digitalSignature=0x80(bit0),
// keyCertSign=0x04(bit5), cRLSign=0x02(bit6).
const KU_CA = { bytes: new Uint8Array([0x06]), unusedBits: 1 }; // keyCertSign|cRLSign
const KU_DS = { bytes: new Uint8Array([0x80]), unusedBits: 7 }; // digitalSignature

export interface CaProfile {
  cn: string;
  kmsKey: string; // subject key (whose public key goes in the cert)
  selfSigned: boolean;
  validityDays: number;
  basicConstraints: { cA: boolean; pathLen?: number };
  keyUsage: { bytes: Uint8Array; unusedBits: number };
  eku: string[] | null;
  certificatePolicies: string[] | null;
  aia: { ocspUrl: string; caIssuersUrl: string } | null;
  ocspNoCheck: boolean;
}

export const PROFILES: Record<"root" | "ica" | "ocsp", CaProfile> = {
  root: {
    cn: "RealReel C2PA Root CA",
    kmsKey: "realreel-root",
    selfSigned: true,
    validityDays: 9131, // ~25 y; >2049 expiry forces GeneralizedTime (handled below)
    basicConstraints: { cA: true, pathLen: 1 },
    keyUsage: KU_CA,
    eku: null, // absent on root
    certificatePolicies: null, // optional on root; omitted
    aia: null, // MUST NOT on root
    ocspNoCheck: false,
  },
  ica: {
    cn: "RealReel Claim Signing CA",
    kmsKey: "realreel-claim-ica",
    selfSigned: false,
    validityDays: 1825, // CP cap: 1827
    basicConstraints: { cA: true, pathLen: 0 },
    keyUsage: KU_CA,
    eku: [
      OID.ekuC2PAClaimSigning,
      OID.ekuDocumentSigning,
      OID.ekuEmailProtection,
    ],
    certificatePolicies: [OID.c2paCertPolicy],
    aia: {
      ocspUrl: "http://ocsp.realreel.xyz",
      // RFC 5280 §4.2.2.1: the caIssuers target must serve a DER-encoded
      // certificate (or certs-only CMS), NOT PEM — hence .cer. A .pem copy is
      // served alongside for humans (runbook §7).
      caIssuersUrl: "http://pki.realreel.xyz/realreel-c2pa-root.cer",
    },
    ocspNoCheck: false,
  },
  ocsp: {
    cn: "RealReel OCSP Responder 1",
    kmsKey: "realreel-ocsp-root",
    selfSigned: false,
    // Short deliberately: the cert carries ocsp-nocheck, so it is unrevocable
    // for its whole life and RFC 6960 §4.2.2.2.1 says treat compromise like a
    // CA-key compromise. 366d ⇒ one recorded root mini-ceremony per year.
    validityDays: 366,
    basicConstraints: { cA: false },
    keyUsage: KU_DS,
    eku: [OID.ekuOcspSigning], // exactly id-kp-OCSPSigning
    certificatePolicies: null,
    aia: null, // MUST NOT on the responder
    ocspNoCheck: true,
  },
};

// Hard invariants from CP §7.1 — buildCaCert() refuses to encode a
// non-conformant cert even if the table above is edited carelessly.
export function lintProfile(name: string, p: CaProfile): void {
  const fail = (msg: string) => {
    throw new Error(`profile lint failed for '${name}': ${msg}`);
  };
  const kuIs = (byte: number, unused: number) =>
    p.keyUsage.bytes.length === 1 && p.keyUsage.bytes[0] === byte &&
    p.keyUsage.unusedBits === unused;

  if (name === "root") {
    if (!p.selfSigned) fail("root must be self-signed");
    if (!p.basicConstraints.cA) fail("root must be CA:TRUE");
    if ((p.basicConstraints.pathLen ?? 99) > 2) {
      fail("root pathLen must be ≤2 (CP root profile)");
    }
    if (!kuIs(0x06, 1)) fail("root KU must be exactly keyCertSign|cRLSign");
    if (p.eku) fail("root MUST NOT carry EKU");
    if (p.aia) fail("root MUST NOT carry AIA");
  }
  if (name === "ica") {
    if (p.validityDays > 1827) {
      fail(`issuing CA validity ${p.validityDays}d exceeds CP cap of 1827d`);
    }
    if (!p.basicConstraints.cA || p.basicConstraints.pathLen !== 0) {
      fail("issuing CA must be CA:TRUE pathlen 0");
    }
    if (!kuIs(0x06, 1)) fail("issuing CA KU must be exactly keyCertSign|cRLSign");
    if (!p.aia?.ocspUrl) fail("issuing CA MUST carry AIA/OCSP");
    if (!p.certificatePolicies?.includes(OID.c2paCertPolicy)) {
      fail("issuing CA MUST carry the C2PA certificate policy OID");
    }
    if (!p.eku?.includes(OID.ekuC2PAClaimSigning)) {
      fail("issuing CA EKU MUST contain c2pa-kp-claimSigning");
    }
  }
  if (name === "ocsp") {
    if (p.basicConstraints.cA) fail("OCSP responder must be CA:FALSE");
    if (!kuIs(0x80, 7)) fail("OCSP responder KU must be exactly digitalSignature");
    if (
      !p.ocspNoCheck || p.eku?.length !== 1 || p.eku[0] !== OID.ekuOcspSigning
    ) {
      fail("OCSP responder MUST be exactly id-kp-OCSPSigning + ocsp-nocheck");
    }
    if (p.aia) fail("OCSP responder MUST NOT carry AIA");
  }
}

// --- DN (canonical one-attribute-per-RDN, as in pki.ts) -------------------

function subjectDn(cn: string): pkijs.RelativeDistinguishedNames {
  const attrs = [
    { type: OID.countryName, value: C, cls: asn1js.PrintableString },
    { type: OID.organizationName, value: O, cls: asn1js.Utf8String },
    { type: OID.commonName, value: cn, cls: asn1js.Utf8String },
  ];
  const dn = new pkijs.RelativeDistinguishedNames({
    typesAndValues: attrs.map((a) =>
      new pkijs.AttributeTypeAndValue({
        type: a.type,
        value: new a.cls({ value: a.value }),
      })
    ),
  });
  (dn as unknown as { toSchema: () => asn1js.Sequence }).toSchema = () =>
    new asn1js.Sequence({
      value: attrs.map((a) =>
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: a.type }),
                new a.cls({ value: a.value }),
              ],
            }),
          ],
        })
      ),
    });
  return dn;
}

// --- Small helpers --------------------------------------------------------

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as
    | ArrayBuffer;
}

function spkiPemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(stripped);
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

async function sha(alg: "SHA-1" | "SHA-256" | "SHA-384", data: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest(alg, toArrayBuffer(data)));
}

// BIT STRING / OCTET STRING content bytes with the same valueHexView →
// valueHex fallback pki.ts uses (survives pkijs internal changes better than
// a single accessor).
function blockBytes(node: unknown): Uint8Array {
  const vb = (node as { valueBlock?: unknown }).valueBlock as {
    valueHexView?: Uint8Array;
    valueHex?: ArrayBuffer;
  };
  if (vb?.valueHexView) return new Uint8Array(vb.valueHexView);
  if (vb?.valueHex) return new Uint8Array(vb.valueHex);
  throw new Error("cannot extract ASN.1 value bytes");
}

function pointBytesFromSpkiDer(spkiDer: Uint8Array): Uint8Array {
  const asn1 = asn1js.fromBER(toArrayBuffer(spkiDer));
  if (asn1.offset === -1) throw new Error("unparseable SPKI");
  const spki = new pkijs.PublicKeyInfo({ schema: asn1.result });
  return blockBytes(spki.subjectPublicKey);
}

function curveNameFromSpkiDer(spkiDer: Uint8Array): string {
  const asn1 = asn1js.fromBER(toArrayBuffer(spkiDer));
  const spki = new pkijs.PublicKeyInfo({ schema: asn1.result });
  const params = spki.algorithm.algorithmParams;
  if (params instanceof asn1js.ObjectIdentifier) {
    return EC_CURVE_NAMES[params.valueBlock.toString()] ?? "unknown-curve";
  }
  return "unknown-curve";
}

// Decode the SKI keyIdentifier from a built/parsed cert (extnValue inner DER
// is an OCTET STRING).
function decodeSki(cert: pkijs.Certificate): Uint8Array {
  const inner = findExtensionByOid(cert, OID.subjectKeyIdentifier);
  if (!inner) throw new Error("cert has no SubjectKeyIdentifier");
  const parsed = asn1js.fromBER(toArrayBuffer(inner));
  if (parsed.offset === -1) throw new Error("unparseable SKI extension");
  return blockBytes(parsed.result);
}

// Decode the AKI keyIdentifier ([0] within the SEQUENCE).
function decodeAki(cert: pkijs.Certificate): Uint8Array {
  const inner = findExtensionByOid(cert, OID.authorityKeyIdentifier);
  if (!inner) throw new Error("cert has no AuthorityKeyIdentifier");
  const parsed = asn1js.fromBER(toArrayBuffer(inner));
  if (parsed.offset === -1) throw new Error("unparseable AKI extension");
  const first =
    (parsed.result.valueBlock as unknown as { value: unknown[] }).value[0];
  return blockBytes(first);
}

// --- Certificate assembly -------------------------------------------------

export interface BuildInputs {
  profile: CaProfile;
  subjectSpkiDer: Uint8Array;
  // Issuer cert for ica/ocsp; undefined for the self-signed root.
  issuerCert?: pkijs.Certificate;
  serialNumber: Uint8Array; // 1..20 bytes; normalized here (see below)
  now: Date;
}

export async function buildCaCert(
  inputs: BuildInputs,
): Promise<pkijs.Certificate> {
  const { profile: p } = inputs;

  // Lint against CP §7.1 before encoding anything. Name resolved by CN so
  // copies of a PROFILES entry (e.g. in tests) are linted as that profile.
  const entry = Object.entries(PROFILES).find(([, v]) => v.cn === p.cn);
  if (entry) lintProfile(entry[0], p);

  const cert = new pkijs.Certificate();
  cert.version = 2; // v3

  // X.509 serials must be positive, minimally-encoded DER INTEGERs. Masking
  // the high bit guarantees positive; forcing byte0 nonzero guarantees
  // minimal (asn1js emits valueHex verbatim, so a leading 0x00 followed by a
  // byte <0x80 would be non-minimal DER that openssl rejects).
  const serial = new Uint8Array(inputs.serialNumber);
  serial[0] = serial[0] & 0x7f;
  if (serial[0] === 0x00) serial[0] = 0x01;
  cert.serialNumber = new asn1js.Integer({ valueHex: toArrayBuffer(serial) });

  const subject = subjectDn(p.cn);
  cert.subject = subject;
  cert.issuer = inputs.issuerCert ? inputs.issuerCert.subject : subjectDn(p.cn);

  const notBefore = new Date(inputs.now.getTime() - 5 * 60_000);
  notBefore.setMilliseconds(0);
  const notAfter = new Date(
    notBefore.getTime() + p.validityDays * 86_400_000,
  );
  // RFC 5280 §4.1.2.5: dates through 2049 use UTCTime, 2050+ MUST use
  // GeneralizedTime. The 25-year root crosses that boundary.
  const timeType = (d: Date) => (d.getUTCFullYear() >= 2050 ? 1 : 0);
  cert.notBefore = new pkijs.Time({ type: timeType(notBefore), value: notBefore });
  cert.notAfter = new pkijs.Time({ type: timeType(notAfter), value: notAfter });

  {
    const asn1 = asn1js.fromBER(toArrayBuffer(inputs.subjectSpkiDer));
    if (asn1.offset === -1) throw new Error("unparseable subject SPKI");
    cert.subjectPublicKeyInfo = new pkijs.PublicKeyInfo({ schema: asn1.result });
  }

  const sigAlg = new pkijs.AlgorithmIdentifier({
    algorithmId: OID.ecdsaWithSHA384,
  });
  cert.signature = sigAlg;
  cert.signatureAlgorithm = sigAlg;

  cert.extensions = [];
  const push = (extnID: string, critical: boolean, valueDer: ArrayBuffer) =>
    cert.extensions!.push(
      new pkijs.Extension({ extnID, critical, extnValue: valueDer }),
    );

  push(
    OID.basicConstraints,
    true,
    new pkijs.BasicConstraints({
      cA: p.basicConstraints.cA,
      ...(p.basicConstraints.pathLen !== undefined
        ? { pathLenConstraint: p.basicConstraints.pathLen }
        : {}),
    }).toSchema().toBER(false),
  );

  push(
    OID.keyUsage,
    true,
    new asn1js.BitString({
      valueHex: toArrayBuffer(p.keyUsage.bytes),
      unusedBits: p.keyUsage.unusedBits,
    }).toBER(false),
  );

  if (p.eku) {
    push(
      OID.extKeyUsage,
      false,
      new pkijs.ExtKeyUsage({ keyPurposes: [...p.eku] }).toSchema().toBER(
        false,
      ),
    );
  }

  if (p.certificatePolicies) {
    push(
      OID.certificatePolicies,
      false,
      new pkijs.CertificatePolicies({
        certificatePolicies: p.certificatePolicies.map((oid) =>
          new pkijs.PolicyInformation({ policyIdentifier: oid })
        ),
      }).toSchema().toBER(false),
    );
  }

  if (p.aia) {
    push(
      OID.authorityInfoAccess,
      false,
      new pkijs.InfoAccess({
        accessDescriptions: [
          new pkijs.AccessDescription({
            accessMethod: OID.adOcsp,
            accessLocation: new pkijs.GeneralName({
              type: 6,
              value: p.aia.ocspUrl,
            }),
          }),
          new pkijs.AccessDescription({
            accessMethod: OID.adCaIssuers,
            accessLocation: new pkijs.GeneralName({
              type: 6,
              value: p.aia.caIssuersUrl,
            }),
          }),
        ],
      }).toSchema().toBER(false),
    );
  }

  if (p.ocspNoCheck) {
    push(OID.ocspNoCheck, false, new asn1js.Null().toBER(false));
  }

  // SKI: SHA-1 over the subject public key BITS (RFC 5280 method 1).
  const ski = await sha("SHA-1", extractSubjectPublicKeyBytes(cert));
  push(
    OID.subjectKeyIdentifier,
    false,
    new asn1js.OctetString({ valueHex: toArrayBuffer(ski) }).toBER(false),
  );

  // AKI keyIdentifier: issuer's SKI (root: its own SKI).
  const issuerSki = inputs.issuerCert ? decodeSki(inputs.issuerCert) : ski;
  push(
    OID.authorityKeyIdentifier,
    false,
    new asn1js.Sequence({
      value: [
        new asn1js.Primitive({
          idBlock: { tagClass: 3, tagNumber: 0 },
          valueHex: toArrayBuffer(issuerSki),
        }),
      ],
    }).toBER(false),
  );

  return cert;
}

// Post-sign self-check: the finished cert's TBS must byte-equal the approved
// TBS, its embedded subject public key must byte-equal the KMS-fetched SPKI,
// and the signature must verify against the ROOT public key. Makes
// "displayed", "fetched", and "signed" impossible to diverge silently.
export async function selfVerify(
  finishedPem: string,
  approvedTbs: Uint8Array,
  rootSpkiDer: Uint8Array,
  expectedSubjectSpkiDer: Uint8Array,
): Promise<void> {
  const parsed = parseCertFromPem(finishedPem);

  const roundTrip = encodeCertTBS(parsed);
  if (hex(roundTrip) !== hex(approvedTbs)) {
    throw new Error("self-verify FAILED: signed TBS differs from approved TBS");
  }

  if (hex(extractSpkiDer(parsed)) !== hex(new Uint8Array(expectedSubjectSpkiDer))) {
    throw new Error(
      "self-verify FAILED: certified public key differs from the KMS-fetched subject SPKI",
    );
  }

  const point = pointBytesFromSpkiDer(rootSpkiDer);
  const sigBits = blockBytes(parsed.signatureValue);
  const digest = await sha("SHA-384", approvedTbs);
  const sig = p384.Signature.fromDER(sigBits).toCompactRawBytes();
  if (!p384.verify(sig, digest, point, { lowS: false })) {
    throw new Error(
      "self-verify FAILED: signature does not verify against the root public key",
    );
  }
}

// --- Human review rendering ----------------------------------------------

export async function renderReview(
  name: string,
  p: CaProfile,
  cert: pkijs.Certificate,
  tbs: Uint8Array,
  subjectSpkiDer: Uint8Array,
): Promise<string> {
  const dn = (rdn: pkijs.RelativeDistinguishedNames) =>
    rdn.typesAndValues
      .map((tv) => {
        const short: Record<string, string> = {
          "2.5.4.3": "CN",
          "2.5.4.6": "C",
          "2.5.4.10": "O",
        };
        return `${short[tv.type] ?? tv.type}=${tv.value.valueBlock.value}`;
      })
      .join(", ");
  const serial = hex(
    new Uint8Array(cert.serialNumber.valueBlock.valueHexView),
  );
  const lines = [
    `=== ${name.toUpperCase()} — to-be-signed certificate ===`,
    `Subject:        ${dn(cert.subject)}`,
    `Issuer:         ${dn(cert.issuer)}`,
    `Serial (hex):   ${serial} (${serial.length / 2} octets)`,
    `Not before:     ${cert.notBefore.value.toISOString()}`,
    `Not after:      ${cert.notAfter.value.toISOString()}  (${p.validityDays} days)`,
    `Sig algorithm:  ecdsa-with-SHA384`,
    `Subject key:    EC ${curveNameFromSpkiDer(subjectSpkiDer)}, from KMS key '${p.kmsKey}'`,
    `SPKI SHA-256:   ${hex(await sha("SHA-256", subjectSpkiDer))}`,
    `SKI:            ${hex(decodeSki(cert))}`,
    `AKI:            ${hex(decodeAki(cert))}`,
    `Basic constr.:  critical, CA=${p.basicConstraints.cA}` +
    (p.basicConstraints.pathLen !== undefined
      ? `, pathlen=${p.basicConstraints.pathLen}`
      : ""),
    `Key usage:      critical, ${
      p.keyUsage === KU_CA ? "keyCertSign, cRLSign" : "digitalSignature"
    }`,
    `EKU:            ${p.eku ? p.eku.join(", ") : "(absent)"}`,
    `Cert policies:  ${
      p.certificatePolicies ? p.certificatePolicies.join(", ") : "(absent)"
    }`,
    `AIA:            ${
      p.aia
        ? `OCSP ${p.aia.ocspUrl} | caIssuers ${p.aia.caIssuersUrl}`
        : "(absent)"
    }`,
    `OCSP no-check:  ${p.ocspNoCheck ? "present (NULL)" : "(absent)"}`,
    `TBS SHA-256:    ${hex(await sha("SHA-256", tbs))}`,
    `=========================================================`,
  ];
  return lines.join("\n");
}

// --- gcloud plumbing (CLI only; tests use the exported builders) ----------

const RING = Deno.env.get("RING") ?? "realreel-ca-v2";
const LOC = Deno.env.get("LOC") ?? "us"; // multi-region: supports HSM and
// backs the plan's multi-region-redundancy answer to CP §6.2.1 off-site backup

async function gcloud(args: string[]): Promise<void> {
  const out = await new Deno.Command("gcloud", { args }).output();
  if (!out.success) {
    throw new Error(
      `gcloud ${args[0]} ${args[1] ?? ""} failed:\n` +
        new TextDecoder().decode(out.stderr),
    );
  }
}

async function kmsPublicKeyDer(key: string): Promise<Uint8Array> {
  const tmp = await Deno.makeTempFile({ suffix: ".pem" });
  await gcloud([
    "kms",
    "keys",
    "versions",
    "get-public-key",
    "1",
    "--key",
    key,
    "--keyring",
    RING,
    "--location",
    LOC,
    "--output-file",
    tmp,
  ]);
  const pem = await Deno.readTextFile(tmp);
  await Deno.remove(tmp);
  return spkiPemToDer(pem);
}

// Signs with the ROOT key (the only signing key in the ceremony). gcloud
// hashes the input with SHA-384 client-side and returns a DER ECDSA signature.
async function kmsSignWithRoot(tbs: Uint8Array): Promise<Uint8Array> {
  const inFile = await Deno.makeTempFile({ suffix: ".der" });
  const sigFile = await Deno.makeTempFile({ suffix: ".sig" });
  try {
    await Deno.writeFile(inFile, tbs);
    await gcloud([
      "kms",
      "asymmetric-sign",
      "--version",
      "1",
      "--key",
      "realreel-root",
      "--keyring",
      RING,
      "--location",
      LOC,
      "--digest-algorithm",
      "sha384",
      "--input-file",
      inFile,
      "--signature-file",
      sigFile,
    ]);
    return await Deno.readFile(sigFile);
  } finally {
    await Deno.remove(inFile).catch(() => {});
    await Deno.remove(sigFile).catch(() => {});
  }
}

// --- CLI ------------------------------------------------------------------

function parseArgs(argv: string[]) {
  const usage = () => {
    console.error(
      "usage: build-ca-certs.ts <root|ica|ocsp> [--root <root.pem>] --out <file> [--dry-run]",
    );
    Deno.exit(2);
  };
  const step = argv[0] as "root" | "ica" | "ocsp";
  if (!PROFILES[step]) usage();
  const get = (flag: string) => {
    const i = argv.indexOf(flag);
    const v = i >= 0 ? argv[i + 1] : undefined;
    // A following flag token means the value is missing, not "--dry-run".
    return v && !v.startsWith("--") ? v : undefined;
  };
  const dryRun = argv.includes("--dry-run");
  const outPath = get("--out");
  const rootPemPath = get("--root");
  // Validate EVERYTHING before any KMS interaction: a signature taken and
  // then dropped because --out was missing would burn an on-camera root-key
  // AsymmetricSign (and fire the usage alert) for nothing.
  if (!dryRun && !outPath) {
    console.error("--out <file> is required (checked before anything signs)");
    usage();
  }
  if (step !== "root" && !rootPemPath) {
    console.error(`'${step}' requires --root <root.pem>`);
    usage();
  }
  return { step, rootPemPath, outPath, dryRun };
}

if (import.meta.main) {
  const { step, rootPemPath, outPath, dryRun } = parseArgs(Deno.args);
  const profile = PROFILES[step];

  let issuerCert: pkijs.Certificate | undefined;
  let rootSpkiDer: Uint8Array;
  if (step === "root") {
    rootSpkiDer = await kmsPublicKeyDer(profile.kmsKey);
  } else {
    issuerCert = parseCertFromPem(await Deno.readTextFile(rootPemPath!));
    rootSpkiDer = extractSpkiDer(issuerCert);
  }

  const subjectSpkiDer = step === "root"
    ? rootSpkiDer
    : await kmsPublicKeyDer(profile.kmsKey);

  const serialNumber = new Uint8Array(20);
  crypto.getRandomValues(serialNumber);

  const cert = await buildCaCert({
    profile,
    subjectSpkiDer,
    issuerCert,
    serialNumber,
    now: new Date(),
  });
  const tbs = encodeCertTBS(cert);

  console.log(await renderReview(step, profile, cert, tbs, subjectSpkiDer));

  if (dryRun) {
    console.log("--dry-run: stopping before signature. Nothing was signed.");
    Deno.exit(0);
  }

  const answer = prompt(
    'Second Trusted Person has read the fields aloud and approved. Type "SIGN" to invoke Cloud KMS with the root key, anything else to abort:',
  );
  if (answer !== "SIGN") {
    console.log("Aborted. Nothing was signed.");
    Deno.exit(1);
  }

  const signature = await kmsSignWithRoot(tbs);
  const pem = finalizeCertPem(cert, signature);
  await selfVerify(pem, tbs, rootSpkiDer, subjectSpkiDer);

  const dir = outPath!.split("/").slice(0, -1).join("/");
  if (dir) await Deno.mkdir(dir, { recursive: true });
  await Deno.writeTextFile(outPath!, pem);

  const pemSha = hex(
    await sha("SHA-256", new TextEncoder().encode(pem)),
  );
  console.log(
    "self-verify OK: signed TBS matches approved TBS; certified key matches the KMS SPKI; signature verifies against the root public key.",
  );
  console.log(`wrote ${outPath}`);
  console.log(`PEM SHA-256 (read aloud): ${pemSha}`);
}
