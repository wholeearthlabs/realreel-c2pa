// X.509 / ASN.1 helpers built on pkijs. Used by both the iOS App Attest
// validator and the Android KeyStore attestation validator, for cert parsing
// and chain validation. (CBOR decoding for App Attest lives in apple.ts.)

// deno-lint-ignore-file no-explicit-any
import * as pkijs from "npm:pkijs@3.2.4";
import * as asn1js from "npm:asn1js@3.0.5";

// Defensive: this module mutates `globalThis.process` to work around a pkijs +
// Supabase-Edge-Runtime quirk (see below). That mutation is only safe in Deno;
// in Node, it would clobber the real EventEmitter `process` global. The
// _shared/attestation/ directory is structurally Edge-only, but a runtime
// guard makes accidental imports from non-Deno code (e.g. React Native) fail
// loudly instead of corrupting global state.
if (typeof Deno === "undefined") {
  throw new Error(
    "ca/_shared/attestation/pki.ts is Deno-only. Do not import from React Native or other non-Deno runtimes.",
  );
}

// pkijs needs a CryptoEngine registered before any cert signature work.
//
// Why this is awkward in Supabase Edge Runtime:
//   pkijs's setEngine() detects "Node" by checking that `process` exists with
//   a `pid` property and `window` is undefined. It then stashes the engine on
//   `globalThis[process.pid].pkijs.engine`. Supabase polyfills `process` but
//   exposes `pid` as `undefined`, so pkijs ends up doing
//   `globalThis["undefined"] = {}` — and the `"undefined"` property of the
//   Window-class global is non-writable, so the assignment throws.
//
// Fix: patch `process.pid` to a real string key BEFORE calling setEngine, and
// pre-create the stash slot with a plain mutable object. pkijs then writes
// `engine` into our pre-populated stash and getEngine() reads it back.
{
  const g = globalThis as Record<string, unknown>;
  const stashKey = "__pkijs_deno_stash";

  // Pre-populate the slot pkijs will look for. This must be a plain mutable
  // object — pkijs writes `slot.pkijs.engine = ...` later.
  g[stashKey] = { pkijs: {} };

  // Override ONLY `process.pid`, not the whole process object: Supabase's
  // `process` polyfill is an EventEmitter that later code reads (process.on,
  // process.env), so replacing it would break those. Direct assignment fails
  // because `pid` is a getter; Object.defineProperty installs a real data
  // property, with a wholesale-replacement fallback if it's non-configurable.
  const proc = g.process as { pid?: unknown } | undefined;
  if (proc) {
    try {
      Object.defineProperty(proc, "pid", {
        value: stashKey,
        writable: true,
        configurable: true,
      });
    } catch {
      // Non-configurable somehow — fall back to the heavier shim.
      g.process = { pid: stashKey };
    }
  } else {
    // No `process` polyfill at all — provide a minimal one.
    g.process = { pid: stashKey };
  }

  pkijs.setEngine(
    "deno-webcrypto",
    new pkijs.CryptoEngine({
      name: "deno-webcrypto",
      crypto: globalThis.crypto,
      subtle: globalThis.crypto.subtle,
    }),
  );
}

// --- PEM/DER conversions -----------------------------------------------

export function pemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(stripped);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// --- Certificate parsing -----------------------------------------------

export function parseCertFromDer(der: Uint8Array): pkijs.Certificate {
  const ab = der.buffer.slice(
    der.byteOffset,
    der.byteOffset + der.byteLength,
  ) as ArrayBuffer;
  const asn1 = asn1js.fromBER(ab);
  if (asn1.offset === -1) {
    throw new Error("failed to parse DER as ASN.1");
  }
  return new pkijs.Certificate({ schema: asn1.result });
}

export function parseCertFromPem(pem: string): pkijs.Certificate {
  return parseCertFromDer(pemToDer(pem));
}

// --- Chain verification ------------------------------------------------

// Verifies that `chain[0]` (leaf) chains up through `chain[1..]` (intermediates)
// to one of the provided trusted roots. Throws on failure with a concrete reason.
//
// Notes:
//   * pkijs's CertificateChainValidationEngine handles signature verification at
//     each link, validity-period checks, and basic constraints.
//   * The chain array is leaf-first (matching how Apple's x5c and Android's
//     keystore cert chain are both ordered).
//   * We pass `findIssuer` undefined → pkijs builds the chain from the supplied
//     certs and trusted roots automatically.
export async function verifyChainToTrustedRoots(
  chain: pkijs.Certificate[],
  trustedRoots: pkijs.Certificate[],
): Promise<void> {
  if (chain.length === 0) throw new Error("empty cert chain");
  if (trustedRoots.length === 0) throw new Error("no trusted roots configured");

  const engine = new pkijs.CertificateChainValidationEngine({
    certs: [...chain],
    trustedCerts: [...trustedRoots],
  });

  const result = await engine.verify();
  if (!result.result) {
    throw new Error(
      `chain validation failed: ${result.resultMessage || "unknown"}`,
    );
  }
}

// --- Extension lookup --------------------------------------------------

// Returns the raw extnValue (DER bytes) of the extension with the given OID,
// or null if no such extension is present.
export function findExtensionByOid(
  cert: pkijs.Certificate,
  oid: string,
): Uint8Array | null {
  const exts = cert.extensions ?? [];
  for (const ext of exts) {
    if (ext.extnID === oid) {
      // ext.extnValue is an asn1js OctetString; valueBlock.valueHex is the raw
      // bytes of the OCTET STRING contents.
      const hex = (ext.extnValue.valueBlock as any).valueHexView as
        | Uint8Array
        | undefined;
      if (hex) return new Uint8Array(hex);
      // Older pkijs versions: fall back to valueHex (ArrayBuffer).
      const ab = (ext.extnValue.valueBlock as any).valueHex as
        | ArrayBuffer
        | undefined;
      if (ab) return new Uint8Array(ab);
      return null;
    }
  }
  return null;
}

// --- Public key extraction --------------------------------------------

// Returns the DER-encoded SubjectPublicKeyInfo of the certificate's public key.
// This is the format we store in user_signing_keys.public_key for the SE key,
// so the caller can constant-time-compare.
export function extractSpkiDer(cert: pkijs.Certificate): Uint8Array {
  const ber = cert.subjectPublicKeyInfo.toSchema().toBER(false);
  return new Uint8Array(ber);
}

// Returns just the raw subjectPublicKey bits (no SPKI envelope) — useful for
// hashing where Apple's spec says "SHA-256 over the public key bytes" without
// further qualification (App Attest credCert keyId derivation).
export function extractSubjectPublicKeyBytes(
  cert: pkijs.Certificate,
): Uint8Array {
  const bv = cert.subjectPublicKeyInfo.subjectPublicKey;
  const hex = (bv.valueBlock as any).valueHexView as Uint8Array | undefined;
  if (hex) return new Uint8Array(hex);
  const ab = (bv.valueBlock as any).valueHex as ArrayBuffer | undefined;
  if (ab) return new Uint8Array(ab);
  throw new Error("could not extract subject public key bytes");
}

// --- Hashing + comparison ----------------------------------------------

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(buf);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// Constant-time byte comparison. Returns true iff equal.
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Errors ------------------------------------------------------------

export class AttestationError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AttestationError";
    this.code = code;
  }
}

// --- CSR (PKCS#10) parsing & verification ------------------------------
//
// CSR handling lives here (not in a separate `csr.ts`) because it shares the
// same pkijs CryptoEngine setup that the cert helpers above already depend on.
// Splitting would force a second engine-init block or a cross-file import that
// risks ordering bugs.

export function csrPemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN CERTIFICATE REQUEST-----/g, "")
    .replace(/-----END CERTIFICATE REQUEST-----/g, "")
    .replace(/-----BEGIN NEW CERTIFICATE REQUEST-----/g, "")
    .replace(/-----END NEW CERTIFICATE REQUEST-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(stripped);
}

export function parseCSRFromPem(pem: string): pkijs.CertificationRequest {
  const der = csrPemToDer(pem);
  const ab = der.buffer.slice(
    der.byteOffset,
    der.byteOffset + der.byteLength,
  ) as ArrayBuffer;
  const asn1 = asn1js.fromBER(ab);
  if (asn1.offset === -1) {
    throw new AttestationError(
      "CSR_PARSE_FAILED",
      "Could not parse PEM as PKCS#10 ASN.1",
    );
  }
  try {
    return new pkijs.CertificationRequest({ schema: asn1.result });
  } catch (e) {
    throw new AttestationError(
      "CSR_PARSE_FAILED",
      `Not a valid CertificationRequest: ${(e as Error).message}`,
    );
  }
}

// Cryptographically verify the CSR's self-signature, which proves the requester
// possesses the private key for the subject SPKI. This is the C2PA-relevant
// possession proof; we then constant-time-compare the SPKI against the attested
// SE/StrongBox key separately in register-signing-key.
export async function verifyCSRSignature(
  csr: pkijs.CertificationRequest,
): Promise<void> {
  let ok = false;
  try {
    ok = await csr.verify();
  } catch (e) {
    throw new AttestationError(
      "CSR_SIG_INVALID",
      `CSR signature verification threw: ${(e as Error).message}`,
    );
  }
  if (!ok) {
    throw new AttestationError(
      "CSR_SIG_INVALID",
      "CSR self-signature did not verify",
    );
  }
}

// DER-encoded SubjectPublicKeyInfo from a CSR. Same shape as
// extractSpkiDer(cert), so the caller can constant-time-compare against the
// attested public key without conversion.
export function extractCSRSpkiDer(
  csr: pkijs.CertificationRequest,
): Uint8Array {
  const ber = csr.subjectPublicKeyInfo.toSchema().toBER(false);
  return new Uint8Array(ber);
}

// --- Leaf cert construction (CA issuance) ------------------------------

// Standard X.509 OIDs we set/inspect repeatedly. Named locally rather than
// imported from pkijs (pkijs doesn't export a comprehensive OID dictionary).
const OID = {
  // RDN attributes
  countryName: "2.5.4.6",
  organizationName: "2.5.4.10",
  organizationalUnitName: "2.5.4.11",
  commonName: "2.5.4.3",
  // Extensions
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectKeyIdentifier: "2.5.29.14",
  authorityKeyIdentifier: "2.5.29.35",
  // Signature algorithms
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  // Extended key usages
  ekuEmailProtection: "1.3.6.1.5.5.7.3.4",
  ekuDocumentSigning: "1.3.6.1.5.5.7.3.36",
  ekuC2PAClaimSigning: "1.3.6.1.4.1.62558.2.1",
} as const;

// ===== PER-APP SWAP-POINT: leaf-certificate subject DN =====
//
// Fixed subject DN written into every issued leaf. A fork should set its own
// organization name + CN here; the defaults below are RealReel's. Sourced from
// env (`LEAF_SUBJECT_ORG`, `LEAF_SUBJECT_OU`, `LEAF_SUBJECT_CN`) when present so
// a forker can override per-deployment without editing code, falling back to
// the RealReel values so the test suite and the standard deploy run with no env
// set. User identity is never embedded — the (user_id, public_key) binding
// lives in user_signing_keys — so any externally-published cert stays
// privacy-respecting. Note the leaf's *issuer* DN (the "...Issuing CA" string
// the verifier surfaces as `signature_info.issuer`) comes from the
// intermediate cert, NOT from this subject; the verifier's trust-list
// `issuerMatch` keys off that issuer string, so a fork that rebrands here must
// also re-issue its CA hierarchy and update the trust-list metadata.
//
// pkijs's `RelativeDistinguishedNames.toSchema()` serializes the entire
// `typesAndValues` array into a SINGLE multi-valued RDN (one SET containing
// every attribute). RFC 5280 §4.1.2.4 allows multi-valued RDNs, but every
// mature X.509 toolchain (openssl, swift-certificates, BouncyCastle) emits
// one attribute per RDN by default — the canonical form. We match the
// canonical form by overriding `toSchema` on the instance, so downstream
// PKIX validators that only exercise the common path don't trip on shape.
function realReelLeafSubject(): pkijs.RelativeDistinguishedNames {
  // Source-of-truth table — one row per attribute, in the order they appear
  // in the DN. Both the pkijs typesAndValues array (for programmatic reads
  // of `cert.subject`) and the overridden toSchema (for serialization) are
  // derived from this so the two stay in sync.
  const attrs: ReadonlyArray<{
    type: string;
    value: string;
    stringClass: typeof asn1js.PrintableString | typeof asn1js.Utf8String;
  }> = [
    { type: OID.countryName, value: Deno.env.get("LEAF_SUBJECT_COUNTRY") ?? "US", stringClass: asn1js.PrintableString },
    { type: OID.organizationName, value: Deno.env.get("LEAF_SUBJECT_ORG") ?? "RealReel", stringClass: asn1js.Utf8String },
    { type: OID.organizationalUnitName, value: Deno.env.get("LEAF_SUBJECT_OU") ?? "Production", stringClass: asn1js.Utf8String },
    { type: OID.commonName, value: Deno.env.get("LEAF_SUBJECT_CN") ?? "RealReel-Device-Key", stringClass: asn1js.Utf8String },
  ];

  const dn = new pkijs.RelativeDistinguishedNames({
    typesAndValues: attrs.map((a) =>
      new pkijs.AttributeTypeAndValue({
        type: a.type,
        value: new a.stringClass({ value: a.value }),
      })
    ),
  });

  // Emit `SEQUENCE { SET { Attr }, SET { Attr }, ... }` instead of pkijs's
  // default `SEQUENCE { SET { Attr, Attr, ... } }`. Rebuilt on every call so
  // asn1js objects are never re-consumed across multiple TBS encodings.
  (dn as unknown as { toSchema: () => asn1js.Sequence }).toSchema = () =>
    new asn1js.Sequence({
      value: attrs.map((a) =>
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: a.type }),
                new a.stringClass({ value: a.value }),
              ],
            }),
          ],
        })
      ),
    });

  return dn;
}

export interface LeafTemplate {
  csr: pkijs.CertificationRequest;
  intermediate: pkijs.Certificate;
  validityDays: number; // see register-signing-key LEAF_VALIDITY_DAYS
  serialNumber: Uint8Array; // typically 20 random bytes
}

// Build a fully-populated leaf Certificate object ready to be TBS-encoded,
// hashed, signed by KMS, and finalized. The server determines all naming and
// extensions; the CSR contributes only the SPKI.
//
// Ownership contract: this aliases (does not deep-clone) the CSR's
// `subjectPublicKeyInfo` and the intermediate's `subject` into the returned
// Certificate, so callers must not mutate those source objects between
// buildLeafCertificate and finalizeLeafPEM (the change would bleed into the
// leaf). Callers issue one leaf per request and discard both inputs
// immediately, so this is documented rather than defensively cloned.
//
// Async because SubjectKeyIdentifier is SHA-1 over the leaf's public key bits
// (RFC 5280 §4.2.1.2 method 1), and crypto.subtle.digest is async.
export async function buildLeafCertificate(
  template: LeafTemplate,
): Promise<pkijs.Certificate> {
  if (template.validityDays <= 0) {
    throw new AttestationError(
      "LEAF_BUILD_FAILED",
      `validityDays must be positive, got ${template.validityDays}`,
    );
  }
  if (template.serialNumber.length === 0 || template.serialNumber.length > 20) {
    throw new AttestationError(
      "LEAF_BUILD_FAILED",
      `serialNumber must be 1..20 bytes, got ${template.serialNumber.length}`,
    );
  }

  const cert = new pkijs.Certificate();
  cert.version = 2; // v3

  // Mask the high bit to keep the INTEGER positive; X.509 requires
  // non-negative serial numbers.
  const serialCopy = new Uint8Array(template.serialNumber);
  serialCopy[0] = serialCopy[0] & 0x7f;
  cert.serialNumber = new asn1js.Integer({
    valueHex: serialCopy.buffer.slice(
      serialCopy.byteOffset,
      serialCopy.byteOffset + serialCopy.byteLength,
    ),
  });

  cert.issuer = template.intermediate.subject;
  cert.subject = realReelLeafSubject();

  const now = new Date();
  // Trim sub-second precision; UTCTime has 1-second resolution and pkijs's
  // round-tripping can drift on the millisecond field otherwise.
  now.setMilliseconds(0);
  // Backdate notBefore by 5 minutes for clock-skew tolerance: the cert is
  // KMS-issued (NTP-synced) and immediately handed to a device that may be
  // slightly behind, so without this the FIRST sign after enrollment can fail
  // "certificate not yet valid" (c2pa-rs surfaces it as "certificate invalid").
  const notBefore = new Date(now.getTime() - 5 * 60_000);
  const notAfter = new Date(now.getTime() + template.validityDays * 86_400_000);
  cert.notBefore = new pkijs.Time({ type: 0, value: notBefore });
  cert.notAfter = new pkijs.Time({ type: 0, value: notAfter });

  cert.subjectPublicKeyInfo = template.csr.subjectPublicKeyInfo;

  const sigAlg = new pkijs.AlgorithmIdentifier({
    algorithmId: OID.ecdsaWithSHA256,
  });
  // X.509 requires the AlgorithmIdentifier inside the TBS (`signature`) and
  // outside the TBS (`signatureAlgorithm`) to match byte-for-byte. Verifiers
  // reject mismatches.
  cert.signature = sigAlg;
  cert.signatureAlgorithm = sigAlg;

  cert.extensions = [];

  // basicConstraints CA:FALSE — critical. pkijs.Extension's `extnValue` accepts
  // the raw DER bytes of the inner extension structure and wraps them into the
  // outer OCTET STRING itself.
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.basicConstraints,
      critical: true,
      extnValue: new pkijs.BasicConstraints({ cA: false }).toSchema().toBER(
        false,
      ),
    }),
  );

  // keyUsage: digitalSignature only (bit 0), critical. c2pa-rs's claim-signing
  // validator requires digitalSignature; adding nonRepudiation made c2pa-rs
  // reject the cert as "invalid" during signing.
  // BIT STRING bits are MSB-first: 0b10000000 = 0x80, with 7 unused trailing bits.
  const kuBytes = new Uint8Array([0x80]);
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.keyUsage,
      critical: true,
      extnValue: new asn1js.BitString({
        valueHex: kuBytes.buffer,
        unusedBits: 7,
      }).toBER(false),
    }),
  );

  // extKeyUsage: emailProtection + documentSigning (for c2pa-rs
  // iter_organization compatibility) + c2pa-kp-claimSigning (the C2PA-specific
  // EKU; future-proofs the Trust List path).
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.extKeyUsage,
      critical: false,
      extnValue: new pkijs.ExtKeyUsage({
        keyPurposes: [
          OID.ekuEmailProtection,
          OID.ekuDocumentSigning,
          OID.ekuC2PAClaimSigning,
        ],
      }).toSchema().toBER(false),
    }),
  );

  // SubjectKeyIdentifier: SHA-1 of the leaf's public key bits (RFC 5280
  // §4.2.1.2 method 1). Strict PKIX path-builders (webpki-style, which c2pa-rs
  // uses) want this on every end-entity cert.
  const pubKeyBits = extractSubjectPublicKeyBytes(cert);
  const skiHash = await crypto.subtle.digest(
    "SHA-1",
    pubKeyBits as BufferSource,
  );
  const skiBytes = new Uint8Array(skiHash);
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.subjectKeyIdentifier,
      critical: false,
      extnValue: new asn1js.OctetString({
        valueHex: skiBytes.buffer.slice(
          skiBytes.byteOffset,
          skiBytes.byteOffset + skiBytes.byteLength,
        ) as ArrayBuffer,
      }).toBER(false),
    }),
  );

  // AuthorityKeyIdentifier: copies the intermediate's SubjectKeyIdentifier
  // into the leaf so path-builders can deterministically link leaf→issuer.
  // Encoded as `SEQUENCE { [0] IMPLICIT OctetString }` per RFC 5280 §4.2.1.1
  // — only keyIdentifier is populated (authorityCertIssuer +
  // authorityCertSerialNumber are optional and omitted).
  //
  // A RealReel intermediate carries an SKI per standard CA hygiene; one
  // without it indicates config drift (wrong PEM / malformed intermediate).
  // Fail closed rather than emit a leaf missing AKI — such leaves still chain
  // via DN matching but strict path-builders may reject them.
  const interSki = readSubjectKeyIdentifier(template.intermediate);
  if (!interSki) {
    throw new AttestationError(
      "INTERMEDIATE_MISSING_SKI",
      "Intermediate certificate has no SubjectKeyIdentifier extension; cannot construct leaf AKI",
    );
  }
  const akiSeq = new asn1js.Sequence({
    value: [
      new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 0 }, // context-specific [0]
        valueHex: interSki.buffer.slice(
          interSki.byteOffset,
          interSki.byteOffset + interSki.byteLength,
        ) as ArrayBuffer,
      }),
    ],
  });
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.authorityKeyIdentifier,
      critical: false,
      extnValue: akiSeq.toBER(false),
    }),
  );

  return cert;
}

// Extract the keyIdentifier bytes from a cert's SubjectKeyIdentifier
// extension. Returns null if the cert has no SKI extension. The SKI extnValue
// is an OctetString-wrapped OctetString; we unwrap both layers.
function readSubjectKeyIdentifier(cert: pkijs.Certificate): Uint8Array | null {
  const ext = cert.extensions?.find(
    (e: pkijs.Extension) => e.extnID === OID.subjectKeyIdentifier,
  );
  if (!ext) return null;
  // pkijs's Extension stashes the extnValue's raw DER bytes here.
  const innerDer =
    ((ext.extnValue.valueBlock as unknown) as { valueHexView?: Uint8Array })
      .valueHexView;
  if (!innerDer || innerDer.byteLength === 0) return null;
  const ab = innerDer.buffer.slice(
    innerDer.byteOffset,
    innerDer.byteOffset + innerDer.byteLength,
  );
  const parsed = asn1js.fromBER(ab as ArrayBuffer);
  if (parsed.offset === -1) return null;
  const result =
    ((parsed.result.valueBlock as unknown) as { valueHexView?: Uint8Array })
      .valueHexView;
  if (!result) return null;
  return new Uint8Array(result);
}

// DER-encode the leaf's TBSCertificate ready for SHA-256 hashing.
//
// The TBS bytes produced here MUST byte-equal what finalizeLeafPEM re-encodes
// inside the outer Certificate envelope — verifiers reject any
// TBS-vs-signature mismatch. Both call sites go through pkijs's
// `Certificate.encodeTBS()`: here directly, and inside finalizeLeafPEM via
// `leaf.toSchema(true)` (the `true` forces re-encoding from fields rather than
// reading a `tbsView` cache). A full-round-trip test pins this determinism, so
// a pkijs/asn1js upgrade that reorders any TBS field breaks first.
export function encodeTBS(leaf: pkijs.Certificate): Uint8Array {
  const seq = leaf.encodeTBS();
  const ab = seq.toBER(false);
  return new Uint8Array(ab);
}

// Combine the leaf's fields (re-emits the TBS via pkijs's encodeTBS) with the
// externally-produced signature into a finished X.509 cert, returned as PEM.
// The `signatureDer` argument is the raw bytes Cloud KMS returns for
// `ec-sign-p256-sha256` — a DER `Sequence { r INTEGER, s INTEGER }` — which
// is exactly what X.509 signatureValue carries inside its BIT STRING wrapper.
//
// `toSchema(true)` is intentional: pkijs's default (`false`) reads from a
// `tbsView` byte cache that we don't populate, and falls back to a broken
// schema-template path when the cache is empty. The `true` flag forces a
// fresh re-encode through `Certificate.encodeTBS()`.
export function finalizeLeafPEM(
  leaf: pkijs.Certificate,
  signatureDer: Uint8Array,
): string {
  // Copy into a fresh ArrayBuffer so asn1js owns the buffer independent of
  // any subarray slicing in the caller's signatureDer.
  const sigBuf = new ArrayBuffer(signatureDer.byteLength);
  new Uint8Array(sigBuf).set(signatureDer);
  leaf.signatureValue = new asn1js.BitString({ valueHex: sigBuf });

  const certAb = leaf.toSchema(true).toBER(false);
  return derToCertPem(new Uint8Array(certAb));
}

function derToCertPem(der: Uint8Array): string {
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN CERTIFICATE-----\n${
    lines.join("\n")
  }\n-----END CERTIFICATE-----\n`;
}

// --- Chain verification against the RealReel root ----------------------

// Validate that `chainPem` (leaf-first; leaf + intermediate) terminates at the
// supplied RealReel root.
export async function verifyChainToRealReelRoot(
  chainPem: string,
  rootPem: string,
): Promise<void> {
  const certBlocks = chainPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  if (!certBlocks || certBlocks.length === 0) {
    throw new AttestationError(
      "CHAIN_PARSE_FAILED",
      "No CERTIFICATE blocks found in chain PEM",
    );
  }
  const chain: pkijs.Certificate[] = [];
  for (const block of certBlocks) {
    try {
      chain.push(parseCertFromPem(block));
    } catch (e) {
      throw new AttestationError(
        "CHAIN_PARSE_FAILED",
        `Could not parse cert in chain: ${(e as Error).message}`,
      );
    }
  }

  let root: pkijs.Certificate;
  try {
    root = parseCertFromPem(rootPem);
  } catch (e) {
    throw new AttestationError(
      "CHAIN_PARSE_FAILED",
      `Could not parse RealReel root PEM: ${(e as Error).message}`,
    );
  }

  await verifyChainToTrustedRoots(chain, [root]);
}

// --- Leaf issuance orchestrator ----------------------------------------

// Pluggable signer: takes the SHA-256 digest of the leaf's TBSCertificate and
// returns the DER ECDSA signature (SEQUENCE { r INTEGER, s INTEGER }) — the
// exact shape Cloud KMS's `ec-sign-p256-sha256` returns and the exact shape
// X.509 `signatureValue` carries. Pluggable so tests can substitute
// `crypto.subtle.sign` + `p1363ToDer` without hitting real KMS.
export type LeafTbsSigner = (digest: Uint8Array) => Promise<Uint8Array>;

export interface IssueLeafChainOpts {
  // PEM of the RealReel intermediate cert. Its subject is copied into the
  // leaf's issuer; its bytes are appended after the leaf in the returned
  // chain. Caller supplies this from env (REALREEL_INTERMEDIATE_CERT_PEM).
  intermediatePem: string;
  validityDays: number;
  signer: LeafTbsSigner;
}

/**
 * Issued leaf chain + the certificate's serial number, in both raw and
 * canonical-decimal forms.
 *
 * - `pem`: `leaf + intermediate` joined with a newline. Persisted to
 *   `user_signing_keys.leaf_cert_pem` and returned to the client.
 * - `serialDecimal`: the leaf's serial as a positive base-10 integer
 *   string. Matches the form c2pa-rs / c2pa-node expose via
 *   `signature_info.cert_serial_number`, so it's directly comparable
 *   to the verifier's lookup key without conversion.
 * - `serialBytes`: the raw 20-byte minted serial. Surfaced for tests
 *   and observability; production callers should use `serialDecimal`.
 * - `notAfter`: the leaf's expiry Date, read off the issued cert.
 *   Persisted to `user_signing_keys.expires_at` so the verifier's
 *   chain-validity check and the Devices screen's "Expires in X days"
 *   surface share one authoritative value.
 */
export interface IssuedLeafChain {
  pem: string;
  serialDecimal: string;
  serialBytes: Uint8Array;
  notAfter: Date;
}

// One-shot issuance: parses the intermediate, mints a 20-byte serial, builds
// the leaf, hashes the TBS, asks the signer to sign it, finalizes the leaf
// PEM, and returns `leaf + intermediate` joined with a newline plus the serial
// in canonical-decimal form (the verifier lookup keys off cert_serial_number).
//
// Caller owns the CSR (must have already verified its signature + SPKI match
// against the attested public key — this helper does NOT re-check either).
export async function issueLeafChainFromCSR(
  csr: pkijs.CertificationRequest,
  opts: IssueLeafChainOpts,
): Promise<IssuedLeafChain> {
  let intermediate: pkijs.Certificate;
  try {
    intermediate = parseCertFromPem(opts.intermediatePem);
  } catch (e) {
    throw new AttestationError(
      "INTERMEDIATE_PARSE_FAILED",
      `Could not parse RealReel intermediate PEM: ${(e as Error).message}`,
    );
  }

  const serialNumber = new Uint8Array(20);
  crypto.getRandomValues(serialNumber);

  const leaf = await buildLeafCertificate({
    csr,
    intermediate,
    validityDays: opts.validityDays,
    serialNumber,
  });

  const tbs = encodeTBS(leaf);
  const digest = await sha256(tbs);
  const signatureDer = await opts.signer(digest);
  const leafPem = finalizeLeafPEM(leaf, signatureDer);

  // Normalize: ensure intermediate has its own trailing newline so concatenation
  // produces a clean two-block chain regardless of how the source PEM was
  // stored (env vars sometimes lose trailing newlines).
  const intermediatePem = opts.intermediatePem.endsWith("\n")
    ? opts.intermediatePem
    : opts.intermediatePem + "\n";

  // Derive the canonical-decimal form of the serial. buildLeafCertificate
  // clears the first byte's high bit for X.509-positive encoding
  // (`serialCopy[0] & 0x7f`); we mirror that here so the returned value
  // matches what got written into the cert, and matches c2pa-node's
  // signature_info.cert_serial_number byte-for-byte.
  const canonicalSerial = new Uint8Array(serialNumber);
  canonicalSerial[0] = canonicalSerial[0] & 0x7f;
  const serialDecimal = bytesToBigIntDecimal(canonicalSerial);

  // Read notAfter off the issued cert rather than recomputing
  // `now + validityDays * 86_400_000` — buildLeafCertificate is the source
  // of truth (it does the same math + clock-skew backdating of notBefore),
  // and re-deriving here would silently drift if its policy ever changed.
  const notAfter = leaf.notAfter.value;

  return {
    pem: leafPem + intermediatePem,
    serialDecimal,
    serialBytes: canonicalSerial,
    notAfter,
  };
}

// Convert a big-endian unsigned byte array to its canonical-decimal
// string. Matches the form X.509 tools (openssl, c2pa-rs) use to
// display cert serial numbers.
function bytesToBigIntDecimal(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex).toString(10);
}

// Re-export pkijs types for the consumers (apple.ts / android.ts).
export type { Certificate, CertificationRequest } from "npm:pkijs@3.2.4";
export { asn1js, pkijs };
