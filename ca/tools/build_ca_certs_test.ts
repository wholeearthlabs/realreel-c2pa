// Tests for the ceremony cert builder. A local WebCrypto P-384 key stands in
// for the KMS root so the full build→sign→finalize→self-verify path runs
// hermetically; profile-shape assertions parse the finished PEMs with the
// same helpers the verifier stack uses.

import {
  buildCaCert,
  encodeCertTBS,
  finalizeCertPem,
  lintProfile,
  PROFILES,
  selfVerify,
} from "./build-ca-certs.ts";
import {
  asn1js,
  findExtensionByOid,
  parseCertFromPem,
  pkijs,
  verifyChainToTrustedRoots,
} from "../_shared/attestation/pki.ts";

const OID_BC = "2.5.29.19";
const OID_KU = "2.5.29.15";
const OID_EKU = "2.5.29.37";
const OID_POLICIES = "2.5.29.32";
const OID_AIA = "1.3.6.1.5.5.7.1.1";
const OID_NOCHECK = "1.3.6.1.5.5.7.48.1.5";
const OID_SKI = "2.5.29.14";
const OID_AKI = "2.5.29.35";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

function ext(c: pkijs.Certificate, oid: string): pkijs.Extension | undefined {
  return c.extensions?.find((e) => e.extnID === oid);
}

// Decode a KeyUsage extension into its BIT STRING bytes + unusedBits.
function decodeKu(
  c: pkijs.Certificate,
): { bytes: Uint8Array; unusedBits: number } {
  const inner = findExtensionByOid(c, OID_KU)!;
  const parsed = asn1js.fromBER(inner.buffer as ArrayBuffer)
    .result as asn1js.BitString;
  return {
    bytes: new Uint8Array(parsed.valueBlock.valueHexView),
    unusedBits: parsed.valueBlock.unusedBits,
  };
}

// Asserts the CP-mandated extension criticalities on any of the three certs.
function assertCriticalities(c: pkijs.Certificate, label: string) {
  assert(ext(c, OID_BC)?.critical === true, `${label}: BC must be critical`);
  assert(ext(c, OID_KU)?.critical === true, `${label}: KU must be critical`);
  for (const [oid, name] of [
    [OID_EKU, "EKU"],
    [OID_POLICIES, "certificatePolicies"],
    [OID_AIA, "AIA"],
    [OID_SKI, "SKI"],
    [OID_AKI, "AKI"],
    [OID_NOCHECK, "ocsp-nocheck"],
  ] as const) {
    const e = ext(c, oid);
    if (e) assert(!e.critical, `${label}: ${name} must be non-critical`);
  }
}

// P1363 (r||s) → DER SEQUENCE{r,s} with minimal positive INTEGERs.
function p1363ToDer(sig: Uint8Array): Uint8Array {
  const half = sig.length / 2;
  const int = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) {
      const padded = new Uint8Array(v.length + 1);
      padded.set(v, 1);
      v = padded;
    }
    return new asn1js.Integer({
      valueHex: v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength),
    });
  };
  return new Uint8Array(
    new asn1js.Sequence({
      value: [int(sig.slice(0, half)), int(sig.slice(half))],
    }).toBER(false),
  );
}

interface TestCa {
  rootPem: string;
  rootCert: pkijs.Certificate;
  rootSpkiDer: Uint8Array;
  signTbs: (tbs: Uint8Array) => Promise<Uint8Array>;
  spkiOf: (keys: CryptoKeyPair) => Promise<Uint8Array>;
}

async function makeTestCa(rootSerial?: Uint8Array): Promise<TestCa> {
  const rootKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  );
  const spkiOf = async (keys: CryptoKeyPair) =>
    new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
  const signTbs = async (tbs: Uint8Array) =>
    p1363ToDer(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-384" },
          rootKeys.privateKey,
          tbs.slice().buffer as ArrayBuffer,
        ),
      ),
    );

  const rootSpkiDer = await spkiOf(rootKeys);
  const serial = rootSerial ?? new Uint8Array(20).fill(7);
  const cert = await buildCaCert({
    profile: PROFILES.root,
    subjectSpkiDer: rootSpkiDer,
    serialNumber: serial,
    now: new Date("2026-07-21T12:00:00Z"),
  });
  const tbs = encodeCertTBS(cert);
  const rootPem = finalizeCertPem(cert, await signTbs(tbs));
  await selfVerify(rootPem, tbs, rootSpkiDer, rootSpkiDer);
  return {
    rootPem,
    rootCert: parseCertFromPem(rootPem),
    rootSpkiDer,
    signTbs,
    spkiOf,
  };
}

Deno.test("root profile: self-signed, P-384, GeneralizedTime past 2049, SKI==AKI, no AIA, KU bits", async () => {
  const ca = await makeTestCa();
  const c = ca.rootCert;

  assert(c.subject.isEqual(c.issuer), "root must be self-signed");
  assert(c.notAfter.value.getUTCFullYear() >= 2050, "25y root crosses 2050");
  assert(c.notAfter.type === 1, "notAfter must be GeneralizedTime (type 1)");
  assert(c.notBefore.type === 0, "notBefore in 2026 stays UTCTime");

  const days = (c.notAfter.value.getTime() - c.notBefore.value.getTime()) /
    86_400_000;
  assert(days === 9131, `root validity must be 9131d, got ${days}`);

  const bc = new pkijs.BasicConstraints({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_BC)!.buffer as ArrayBuffer,
    ).result,
  });
  assert(bc.cA === true && bc.pathLenConstraint === 1, "root BC CA:TRUE pathlen 1");

  assertCriticalities(c, "root");
  const ku = decodeKu(c);
  assert(
    ku.bytes.length === 1 && ku.bytes[0] === 0x06 && ku.unusedBits === 1,
    `root KU must be keyCertSign|cRLSign (0x06/1), got 0x${
      ku.bytes[0].toString(16)
    }/${ku.unusedBits}`,
  );

  assert(findExtensionByOid(c, OID_EKU) === null, "root must have no EKU");
  assert(findExtensionByOid(c, OID_AIA) === null, "root MUST NOT carry AIA");

  const ski = findExtensionByOid(c, OID_SKI)!;
  const aki = findExtensionByOid(c, OID_AKI)!;
  const skiHex = [...ski].map((b) => b.toString(16).padStart(2, "0")).join("");
  const akiHex = [...aki].map((b) => b.toString(16).padStart(2, "0")).join("");
  assert(akiHex.includes(skiHex.slice(4)), "root AKI must embed its own SKI");

  const serialBytes = new Uint8Array(c.serialNumber.valueBlock.valueHexView);
  assert(serialBytes.length <= 20 && (serialBytes[0] & 0x80) === 0, "positive ≤20-octet serial");
});

Deno.test("serial normalization: high-bit and zero leading bytes yield minimal positive DER", async () => {
  for (const first of [0x80, 0x00, 0xff]) {
    const serial = new Uint8Array(20).fill(0x22);
    serial[0] = first;
    const ca = await makeTestCa(serial);
    const bytes = new Uint8Array(
      ca.rootCert.serialNumber.valueBlock.valueHexView,
    );
    assert(bytes.length === 20, "serial keeps its 20 octets");
    assert(bytes[0] !== 0x00, "no leading zero byte (non-minimal DER)");
    assert((bytes[0] & 0x80) === 0, "high bit clear (positive INTEGER)");
  }
});

Deno.test("ica profile: chains to root, EKU trio, C2PA policy OID, AIA with OCSP + DER caIssuers, pathlen 0, 1825d, KU bits", async () => {
  const ca = await makeTestCa();
  const icaKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  );
  const icaSpki = await ca.spkiOf(icaKeys);
  const cert = await buildCaCert({
    profile: PROFILES.ica,
    subjectSpkiDer: icaSpki,
    issuerCert: ca.rootCert,
    serialNumber: crypto.getRandomValues(new Uint8Array(20)),
    now: new Date("2026-07-21T12:00:00Z"),
  });
  const tbs = encodeCertTBS(cert);
  const pem = finalizeCertPem(cert, await ca.signTbs(tbs));
  await selfVerify(pem, tbs, ca.rootSpkiDer, icaSpki);

  const c = parseCertFromPem(pem);
  await verifyChainToTrustedRoots([c], [ca.rootCert]);

  const days = (c.notAfter.value.getTime() - c.notBefore.value.getTime()) /
    86_400_000;
  assert(days === 1825, `ica validity must be 1825d (cap 1827), got ${days}`);

  const bc = new pkijs.BasicConstraints({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_BC)!.buffer as ArrayBuffer,
    ).result,
  });
  assert(bc.cA === true && bc.pathLenConstraint === 0, "ica BC CA:TRUE pathlen 0");

  assertCriticalities(c, "ica");
  const ku = decodeKu(c);
  assert(
    ku.bytes.length === 1 && ku.bytes[0] === 0x06 && ku.unusedBits === 1,
    "ica KU must be keyCertSign|cRLSign (0x06/1)",
  );

  const eku = new pkijs.ExtKeyUsage({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_EKU)!.buffer as ArrayBuffer,
    ).result,
  });
  for (
    const oid of [
      "1.3.6.1.4.1.62558.2.1",
      "1.3.6.1.5.5.7.3.36",
      "1.3.6.1.5.5.7.3.4",
    ]
  ) {
    assert(eku.keyPurposes.includes(oid), `ica EKU must contain ${oid}`);
  }

  const policies = new pkijs.CertificatePolicies({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_POLICIES)!.buffer as ArrayBuffer,
    ).result,
  });
  assert(
    policies.certificatePolicies.some((p) =>
      p.policyIdentifier === "1.3.6.1.4.1.62558.1.1"
    ),
    "ica must carry the C2PA certificate policy OID",
  );

  const aia = new pkijs.InfoAccess({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_AIA)!.buffer as ArrayBuffer,
    ).result,
  });
  const methods = aia.accessDescriptions.map((d) => d.accessMethod);
  assert(methods.includes("1.3.6.1.5.5.7.48.1"), "AIA must include id-ad-ocsp");
  assert(methods.includes("1.3.6.1.5.5.7.48.2"), "AIA should include caIssuers");
  const urls = aia.accessDescriptions.map((d) => d.accessLocation.value);
  assert(urls.includes("http://ocsp.realreel.xyz"), "OCSP URL");
  assert(
    urls.includes("http://pki.realreel.xyz/realreel-c2pa-root.cer"),
    "caIssuers must point at the DER (.cer) resource per RFC 5280 §4.2.2.1",
  );
});

Deno.test("ocsp profile: chains to root, EKU exactly OCSPSigning, nocheck present, CA:FALSE, KU digitalSignature, 366d", async () => {
  const ca = await makeTestCa();
  const ocspKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const ocspSpki = await ca.spkiOf(ocspKeys);
  const cert = await buildCaCert({
    profile: PROFILES.ocsp,
    subjectSpkiDer: ocspSpki,
    issuerCert: ca.rootCert,
    serialNumber: crypto.getRandomValues(new Uint8Array(20)),
    now: new Date("2026-07-21T12:00:00Z"),
  });
  const tbs = encodeCertTBS(cert);
  const pem = finalizeCertPem(cert, await ca.signTbs(tbs));
  await selfVerify(pem, tbs, ca.rootSpkiDer, ocspSpki);

  const c = parseCertFromPem(pem);
  await verifyChainToTrustedRoots([c], [ca.rootCert]);

  const days = (c.notAfter.value.getTime() - c.notBefore.value.getTime()) /
    86_400_000;
  assert(days === 366, `responder validity must be 366d, got ${days}`);

  const bc = new pkijs.BasicConstraints({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_BC)!.buffer as ArrayBuffer,
    ).result,
  });
  assert(bc.cA === false, "responder must be CA:FALSE");

  assertCriticalities(c, "ocsp");
  const ku = decodeKu(c);
  assert(
    ku.bytes.length === 1 && ku.bytes[0] === 0x80 && ku.unusedBits === 7,
    "responder KU must be digitalSignature (0x80/7)",
  );

  const eku = new pkijs.ExtKeyUsage({
    schema: asn1js.fromBER(
      findExtensionByOid(c, OID_EKU)!.buffer as ArrayBuffer,
    ).result,
  });
  assert(
    eku.keyPurposes.length === 1 &&
      eku.keyPurposes[0] === "1.3.6.1.5.5.7.3.9",
    "EKU must be exactly id-kp-OCSPSigning",
  );

  assert(findExtensionByOid(c, OID_NOCHECK) !== null, "ocsp-nocheck present");
  assert(findExtensionByOid(c, OID_AIA) === null, "responder MUST NOT carry AIA");
});

Deno.test("PROFILES pin: literal values match the runbook Appendix A table", () => {
  const r = PROFILES.root;
  assert(r.cn === "RealReel C2PA Root CA", "root CN");
  assert(r.kmsKey === "realreel-root", "root KMS key");
  assert(r.validityDays === 9131, "root 9131d");
  assert(r.basicConstraints.pathLen === 1, "root pathlen 1");
  assert(r.eku === null && r.aia === null && r.certificatePolicies === null, "root minimal extensions");

  const i = PROFILES.ica;
  assert(i.cn === "RealReel Claim Signing CA", "ica CN");
  assert(i.kmsKey === "realreel-claim-ica", "ica KMS key");
  assert(i.validityDays === 1825, "ica 1825d");
  assert(i.basicConstraints.pathLen === 0, "ica pathlen 0");
  assert(
    JSON.stringify(i.eku) ===
      JSON.stringify([
        "1.3.6.1.4.1.62558.2.1",
        "1.3.6.1.5.5.7.3.36",
        "1.3.6.1.5.5.7.3.4",
      ]),
    "ica EKU trio",
  );
  assert(
    JSON.stringify(i.certificatePolicies) ===
      JSON.stringify(["1.3.6.1.4.1.62558.1.1"]),
    "ica policy OID",
  );
  assert(i.aia?.ocspUrl === "http://ocsp.realreel.xyz", "ica OCSP URL");
  assert(
    i.aia?.caIssuersUrl === "http://pki.realreel.xyz/realreel-c2pa-root.cer",
    "ica caIssuers DER URL",
  );

  const o = PROFILES.ocsp;
  assert(o.cn === "RealReel OCSP Responder 1", "ocsp CN");
  assert(o.kmsKey === "realreel-ocsp-root", "ocsp KMS key");
  assert(o.validityDays === 366, "ocsp 366d");
  assert(o.ocspNoCheck === true, "ocsp nocheck");
  assert(
    JSON.stringify(o.eku) === JSON.stringify(["1.3.6.1.5.5.7.3.9"]),
    "ocsp EKU",
  );
});

Deno.test("lint: runs inside buildCaCert and rejects a >1827d issuing CA", async () => {
  const bad = { ...PROFILES.ica, validityDays: 1900 };
  let directThrew = false;
  try {
    lintProfile("ica", bad);
  } catch {
    directThrew = true;
  }
  assert(directThrew, "lintProfile must reject >1827d issuing CA");

  const ca = await makeTestCa();
  let buildThrew = false;
  try {
    await buildCaCert({
      profile: bad,
      subjectSpkiDer: ca.rootSpkiDer,
      issuerCert: ca.rootCert,
      serialNumber: new Uint8Array(20).fill(1),
      now: new Date("2026-07-21T12:00:00Z"),
    });
  } catch {
    buildThrew = true;
  }
  assert(buildThrew, "buildCaCert must lint (CN-matched) profiles itself");
});

Deno.test("lint: rejects root pathLen 3 and CA-flagged responder", () => {
  for (
    const [name, bad] of [
      ["root", { ...PROFILES.root, basicConstraints: { cA: true, pathLen: 3 } }],
      ["ocsp", { ...PROFILES.ocsp, basicConstraints: { cA: true } }],
    ] as const
  ) {
    let threw = false;
    try {
      lintProfile(name, bad);
    } catch {
      threw = true;
    }
    assert(threw, `lint must reject bad ${name} profile`);
  }
});

Deno.test("selfVerify: rejects a TBS mismatch and a subject-SPKI mismatch", async () => {
  const ca = await makeTestCa();

  const tampered = encodeCertTBS(ca.rootCert);
  tampered[tampered.length - 1] ^= 0xff;
  let tbsThrew = false;
  try {
    await selfVerify(ca.rootPem, tampered, ca.rootSpkiDer, ca.rootSpkiDer);
  } catch {
    tbsThrew = true;
  }
  assert(tbsThrew, "selfVerify must reject a TBS mismatch");

  const otherKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-384" },
    true,
    ["sign", "verify"],
  );
  const otherSpki = await ca.spkiOf(otherKeys);
  let spkiThrew = false;
  try {
    await selfVerify(
      ca.rootPem,
      encodeCertTBS(ca.rootCert),
      ca.rootSpkiDer,
      otherSpki,
    );
  } catch {
    spkiThrew = true;
  }
  assert(
    spkiThrew,
    "selfVerify must reject a cert whose key differs from the KMS-fetched SPKI",
  );
});
