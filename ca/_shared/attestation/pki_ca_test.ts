// Tests for the CA-issuance helpers in pki.ts:
//   - parseCSRFromPem / verifyCSRSignature / extractCSRSpkiDer
//   - buildLeafCertificate / encodeTBS / finalizeLeafPEM (round-trip)
//   - verifyChainToRealReelRoot (happy + tampered)
//
// Run with:
//   deno test --allow-read ca/_shared/attestation/pki_ca_test.ts
//
// KMS round-trip is intentionally NOT tested here. Real-network coverage
// happens in the smoke test against the live intermediate key.

import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "https://deno.land/std@0.221.0/assert/mod.ts";
import {
  asn1js,
  AttestationError,
  buildLeafCertificate,
  bytesToBase64,
  ctEqual,
  encodeTBS,
  extractCSRSpkiDer,
  extractSpkiDer,
  extractSubjectPublicKeyBytes,
  findExtensionByOid,
  finalizeLeafPEM,
  issueLeafChainFromCSR,
  parseCertFromPem,
  parseCSRFromPem,
  pemToDer,
  pkijs,
  sha256,
  verifyChainToRealReelRoot,
  verifyCSRSignature,
} from "./pki.ts";

const CSR_FIXTURE_PATH = new URL(
  "./__fixtures__/sample_csr.pem",
  import.meta.url,
);

// --- Helpers ----------------------------------------------------------

// Convert IEEE P1363 (r||s, 64 bytes for P-256) — what crypto.subtle.sign
// returns for ECDSA — into the DER `SEQUENCE { r INTEGER, s INTEGER }` form
// that X.509 signatureValue expects. KMS already returns DER in production,
// so this conversion is test-only.
//
// Canonical INTEGER encoding rules we must honor (~75% of P-256 signatures
// hit one of these branches per component):
//   1. Strip leading 0x00 bytes — but keep at least one byte so the value
//      is never zero-length.
//   2. If the high bit of the resulting first byte is set, prepend a 0x00.
//      Otherwise DER decoders read the INTEGER as negative (two's complement),
//      which silently corrupts the signature.
function p1363ToDer(sig: Uint8Array): Uint8Array {
  if (sig.length !== 64) {
    throw new Error(`expected 64-byte P1363 signature, got ${sig.length}`);
  }
  return new Uint8Array(
    new asn1js.Sequence({
      value: [
        new asn1js.Integer({
          valueHex: canonicalIntegerBytes(sig.slice(0, 32)),
        }),
        new asn1js.Integer({
          valueHex: canonicalIntegerBytes(sig.slice(32, 64)),
        }),
      ],
    }).toBER(false),
  );
}

function canonicalIntegerBytes(raw: Uint8Array): ArrayBuffer {
  let start = 0;
  while (start < raw.length - 1 && raw[start] === 0) start++;
  const trimmed = raw.subarray(start);
  if (trimmed[0] & 0x80) {
    const padded = new Uint8Array(trimmed.length + 1);
    padded.set(trimmed, 1);
    return padded.buffer;
  }
  // Return a fresh ArrayBuffer slice to avoid asn1js holding a reference into
  // the caller's signature buffer.
  const out = new Uint8Array(trimmed.length);
  out.set(trimmed);
  return out.buffer;
}

function rdn(
  pairs: ReadonlyArray<readonly [string, string]>,
): pkijs.RelativeDistinguishedNames {
  return new pkijs.RelativeDistinguishedNames({
    typesAndValues: pairs.map(([type, value]) =>
      new pkijs.AttributeTypeAndValue({
        type,
        value: new asn1js.Utf8String({ value }),
      })
    ),
  });
}

interface TestCA {
  cert: pkijs.Certificate;
  privateKey: CryptoKey;
}

// Build a self-signed root or an intermediate signed by a parent. Tests need
// these to stand in for the offline RealReel root + KMS intermediate without
// touching real PKI.
async function buildTestCA(
  commonName: string,
  parent?: TestCA,
): Promise<TestCA> {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );

  const cert = new pkijs.Certificate();
  cert.version = 2;
  const serial = new Uint8Array(8);
  crypto.getRandomValues(serial);
  serial[0] = serial[0] & 0x7f;
  cert.serialNumber = new asn1js.Integer({
    valueHex: serial.buffer.slice(0, 8),
  });

  const dn = rdn([
    ["2.5.4.6", "US"],
    ["2.5.4.10", "RealReel-Test"],
    ["2.5.4.3", commonName],
  ]);
  cert.subject = dn;
  cert.issuer = parent ? parent.cert.subject : dn;

  const now = new Date();
  now.setMilliseconds(0);
  // 1-year test cert; the leaf inherits its 5y from production defaults.
  const notAfter = new Date(now.getTime() + 365 * 86_400_000);
  cert.notBefore = new pkijs.Time({ type: 0, value: now });
  cert.notAfter = new pkijs.Time({ type: 0, value: notAfter });

  await cert.subjectPublicKeyInfo.importKey(kp.publicKey);

  // SubjectKeyIdentifier: SHA-1 of the cert's public key bits (RFC 5280
  // §4.2.1.2 method 1). Required by the leaf-side AKI construction in
  // buildLeafCertificate, which fails closed if the intermediate has no SKI.
  // Production intermediates (Phase A ceremony output) carry SKI per CA
  // hygiene; the test harness must match that posture or AKI coverage is zero.
  const pubKeyBits = extractSubjectPublicKeyBytes(cert);
  const skiHash = await crypto.subtle.digest(
    "SHA-1",
    pubKeyBits as BufferSource,
  );
  const skiBytes = new Uint8Array(skiHash);

  cert.extensions = [
    new pkijs.Extension({
      extnID: "2.5.29.19", // basicConstraints
      critical: true,
      extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(
        false,
      ),
    }),
    new pkijs.Extension({
      extnID: "2.5.29.15", // keyUsage: keyCertSign + cRLSign (bits 5 and 6)
      critical: true,
      extnValue: new asn1js.BitString({
        valueHex: new Uint8Array([0x06]).buffer,
        unusedBits: 1,
      }).toBER(false),
    }),
    new pkijs.Extension({
      extnID: "2.5.29.14", // SubjectKeyIdentifier
      critical: false,
      extnValue: new asn1js.OctetString({
        valueHex: skiBytes.buffer.slice(
          skiBytes.byteOffset,
          skiBytes.byteOffset + skiBytes.byteLength,
        ) as ArrayBuffer,
      }).toBER(false),
    }),
  ];

  const signingKey = parent ? parent.privateKey : kp.privateKey;
  await cert.sign(signingKey, "SHA-256");

  return { cert, privateKey: kp.privateKey };
}

// `cert.toSchema()` defaults to encodeFlag=false, which reads from the cert's
// `tbsView` cache. This works on test CAs because `await cert.sign(...)`
// inside buildTestCA populates tbsView with the signed bytes. Don't "fix"
// this to toSchema(true) — finalizeLeafPEM uses (true) for the production
// path where we explicitly avoid the cache and re-encode via encodeTBS, but
// the test-side intermediate is already signed and re-encoding here would
// produce a fresh TBS whose signature wouldn't verify.
function certToPem(cert: pkijs.Certificate): string {
  const der = new Uint8Array(cert.toSchema().toBER(false));
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN CERTIFICATE-----\n${
    lines.join("\n")
  }\n-----END CERTIFICATE-----\n`;
}

async function loadCSRFixture(): Promise<string> {
  return await Deno.readTextFile(CSR_FIXTURE_PATH);
}

// --- CSR parse / verify / SPKI tests -----------------------------------

Deno.test("parseCSRFromPem — happy path on sample fixture", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);
  assertEquals(csr.version, 0); // PKCS#10 v1 encodes as INTEGER 0
});

Deno.test("verifyCSRSignature — accepts well-formed sample CSR", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);
  await verifyCSRSignature(csr); // no throw == pass
});

Deno.test("verifyCSRSignature — rejects tampered signature", async () => {
  const pem = await loadCSRFixture();
  const der = pemToDer(
    pem
      .replace(/CERTIFICATE REQUEST/g, "CERTIFICATE"), // pemToDer matches CERTIFICATE markers
  );
  // Flip the last byte (always inside the signature region of a PKCS#10).
  der[der.length - 1] ^= 0xff;
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  const tampered = `-----BEGIN CERTIFICATE REQUEST-----\n${
    lines.join("\n")
  }\n-----END CERTIFICATE REQUEST-----\n`;

  const csr = parseCSRFromPem(tampered);
  await assertRejects(
    () => verifyCSRSignature(csr),
    AttestationError,
    "CSR",
  );
});

Deno.test("parseCSRFromPem — rejects garbage PEM", () => {
  let threw = false;
  try {
    parseCSRFromPem(
      "-----BEGIN CERTIFICATE REQUEST-----\nbm90IGFzbjE=\n-----END CERTIFICATE REQUEST-----",
    );
  } catch (e) {
    threw = true;
    if (!(e instanceof AttestationError)) {
      throw new Error(`expected AttestationError, got ${e}`);
    }
    assertStringIncludes(e.code, "CSR_PARSE_FAILED");
  }
  assertEquals(threw, true);
});

Deno.test("p1363ToDer — canonical-encodes components with high bit set", () => {
  // r has high bit set in byte 0; s has high bit set in byte 0; both should
  // gain a 0x00 prefix in DER. Round-trip the result and confirm asn1js
  // decodes the INTEGERs back to the original 32-byte values (not their
  // two's-complement negatives).
  const r = new Uint8Array(32).fill(0xaa); // 0xAA = 0b10101010, high bit set
  const s = new Uint8Array(32).fill(0xff); // also high bit set
  const sig = new Uint8Array(64);
  sig.set(r, 0);
  sig.set(s, 32);

  const der = p1363ToDer(sig);
  const parsed = asn1js.fromBER(der.buffer.slice(0, der.length) as ArrayBuffer);
  if (parsed.offset === -1) throw new Error("could not re-parse DER");
  const seq = parsed.result as unknown as { valueBlock: { value: unknown[] } };
  // deno-lint-ignore no-explicit-any
  const intRView = (seq.valueBlock.value[0] as any).valueBlock
    .valueHexView as Uint8Array;
  // deno-lint-ignore no-explicit-any
  const intSView = (seq.valueBlock.value[1] as any).valueBlock
    .valueHexView as Uint8Array;

  // Canonical encoding prepends 0x00 for both → 33 bytes each.
  assertEquals(intRView.length, 33);
  assertEquals(intSView.length, 33);
  assertEquals(intRView[0], 0x00);
  assertEquals(intSView[0], 0x00);
  // The remaining 32 bytes match the original r / s.
  assertEquals(intRView.subarray(1).every((b) => b === 0xaa), true);
  assertEquals(intSView.subarray(1).every((b) => b === 0xff), true);
});

Deno.test("p1363ToDer — does not pad components with clear high bit", () => {
  // r and s both have high bit clear → no padding, 32 bytes each.
  const r = new Uint8Array(32).fill(0x42);
  const s = new Uint8Array(32).fill(0x10);
  const sig = new Uint8Array(64);
  sig.set(r, 0);
  sig.set(s, 32);

  const der = p1363ToDer(sig);
  const parsed = asn1js.fromBER(der.buffer.slice(0, der.length) as ArrayBuffer);
  if (parsed.offset === -1) throw new Error("could not re-parse DER");
  const seq = parsed.result as unknown as { valueBlock: { value: unknown[] } };
  // deno-lint-ignore no-explicit-any
  const intRView = (seq.valueBlock.value[0] as any).valueBlock
    .valueHexView as Uint8Array;
  // deno-lint-ignore no-explicit-any
  const intSView = (seq.valueBlock.value[1] as any).valueBlock
    .valueHexView as Uint8Array;
  assertEquals(intRView.length, 32);
  assertEquals(intSView.length, 32);
});

Deno.test("extractCSRSpkiDer — matches openssl-derived SPKI shape", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);
  const spki = extractCSRSpkiDer(csr);
  // P-256 SPKI is 91 bytes (algorithm-id + uncompressed point).
  assertEquals(spki.length, 91);
  // First byte is SEQUENCE.
  assertEquals(spki[0], 0x30);
});

// --- Leaf issuance round-trip ------------------------------------------

Deno.test("buildLeafCertificate / encodeTBS / finalizeLeafPEM — full round-trip verifies", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);

  const root = await buildTestCA("Test Root CA");
  const intermediate = await buildTestCA("Test Issuing CA", root);

  const serial = new Uint8Array(20);
  crypto.getRandomValues(serial);

  const leaf = await buildLeafCertificate({
    csr,
    intermediate: intermediate.cert,
    validityDays: 180,
    serialNumber: serial,
  });

  const tbs = encodeTBS(leaf);
  const digest = await sha256(tbs);

  // Sign the digest with the intermediate's key. crypto.subtle.sign with
  // ECDSA hashes internally — we already have the digest, so feed it the
  // pre-hashed TBS via the "raw" trick: actually subtle.sign doesn't support
  // pre-hashed input, so we sign the TBS bytes themselves with hash=SHA-256.
  // The outcome is byte-identical: SHA-256(tbs) then ECDSA-sign.
  const sigP1363 = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      intermediate.privateKey,
      tbs as BufferSource,
    ),
  );
  // Sanity: confirm digest matches what subtle.sign would compute, just so
  // the comment above isn't lying. (Cheap check; the actual signature
  // verifies below via the chain engine.)
  assertEquals(digest.length, 32);

  const sigDer = p1363ToDer(sigP1363);
  const leafPEM = finalizeLeafPEM(leaf, sigDer);

  // Re-parse the finalized leaf and check core fields.
  const leafParsed = parseCertFromPem(leafPEM);

  // Subject CN is the server-determined "RealReel-Device-Key".
  const cnAttr = leafParsed.subject.typesAndValues.find(
    (tv: pkijs.AttributeTypeAndValue) => tv.type === "2.5.4.3",
  );
  assertEquals(cnAttr?.value.valueBlock.value, "RealReel-Device-Key");

  // Issuer matches intermediate's subject.
  const intIssuerCN = intermediate.cert.subject.typesAndValues.find(
    (tv: pkijs.AttributeTypeAndValue) => tv.type === "2.5.4.3",
  );
  const leafIssuerCN = leafParsed.issuer.typesAndValues.find(
    (tv: pkijs.AttributeTypeAndValue) => tv.type === "2.5.4.3",
  );
  assertEquals(
    leafIssuerCN?.value.valueBlock.value,
    intIssuerCN?.value.valueBlock.value,
  );

  // SPKI in finalized leaf matches CSR's SPKI byte-for-byte.
  const leafSpki = extractSpkiDer(leafParsed);
  const csrSpki = extractCSRSpkiDer(csr);
  assertEquals(ctEqual(leafSpki, csrSpki), true);

  // Validity window: 180 days (the shortened leaf lifetime).
  const nb = leafParsed.notBefore.value.getTime();
  const na = leafParsed.notAfter.value.getTime();
  const days = (na - nb) / 86_400_000;
  assertEquals(Math.round(days), 180);

  // Required extensions present.
  const extOids = (leafParsed.extensions ?? []).map((e: pkijs.Extension) =>
    e.extnID
  );
  assertEquals(extOids.includes("2.5.29.19"), true); // basicConstraints
  assertEquals(extOids.includes("2.5.29.15"), true); // keyUsage
  assertEquals(extOids.includes("2.5.29.37"), true); // extKeyUsage
  assertEquals(extOids.includes("2.5.29.14"), true); // subjectKeyIdentifier
  assertEquals(extOids.includes("2.5.29.35"), true); // authorityKeyIdentifier

  // AKI's keyIdentifier bytes must byte-equal the intermediate's SKI value —
  // this is the structural link strict PKIX path-builders use. Walk both
  // extensions' raw DER to read the OctetString contents.
  const intSkiRaw = findExtensionByOid(intermediate.cert, "2.5.29.14");
  if (!intSkiRaw) throw new Error("test intermediate is missing SKI");
  const intSkiAsn = asn1js.fromBER(
    intSkiRaw.buffer.slice(
      intSkiRaw.byteOffset,
      intSkiRaw.byteOffset + intSkiRaw.byteLength,
    ) as ArrayBuffer,
  );
  const intSkiBytes = new Uint8Array(
    // deno-lint-ignore no-explicit-any
    (intSkiAsn.result.valueBlock as any).valueHexView,
  );

  const leafAkiRaw = findExtensionByOid(leafParsed, "2.5.29.35");
  if (!leafAkiRaw) throw new Error("issued leaf is missing AKI");
  // AKI wraps a SEQUENCE { [0] IMPLICIT keyIdentifier }; the OctetString
  // bytes are inside the [0] primitive's valueBlock.
  const leafAkiAsn = asn1js.fromBER(
    leafAkiRaw.buffer.slice(
      leafAkiRaw.byteOffset,
      leafAkiRaw.byteOffset + leafAkiRaw.byteLength,
    ) as ArrayBuffer,
  );
  // deno-lint-ignore no-explicit-any
  const akiSeq = (leafAkiAsn.result.valueBlock as any).value;
  // deno-lint-ignore no-explicit-any
  const leafAkiKeyId = new Uint8Array((akiSeq[0].valueBlock as any).valueHexView);
  assertEquals(ctEqual(intSkiBytes, leafAkiKeyId), true);

  // Full chain validates leaf → intermediate → root via the existing engine.
  const chainPem = leafPEM + certToPem(intermediate.cert);
  const rootPem = certToPem(root.cert);
  await verifyChainToRealReelRoot(chainPem, rootPem);
});

Deno.test("buildLeafCertificate — rejects non-positive validityDays", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);
  const root = await buildTestCA("Test Root CA");
  const intermediate = await buildTestCA("Test Issuing CA", root);

  let threw = false;
  try {
    await buildLeafCertificate({
      csr,
      intermediate: intermediate.cert,
      validityDays: 0,
      serialNumber: new Uint8Array([1, 2, 3, 4]),
    });
  } catch (e) {
    threw = true;
    if (!(e instanceof AttestationError)) {
      throw new Error(`expected AttestationError, got ${e}`);
    }
  }
  assertEquals(threw, true);
});

// --- Chain verification ------------------------------------------------

Deno.test("verifyChainToRealReelRoot — rejects empty PEM", async () => {
  await assertRejects(
    () => verifyChainToRealReelRoot("no certs here", "garbage"),
    AttestationError,
    "No CERTIFICATE blocks found",
  );
});

Deno.test("verifyChainToRealReelRoot — rejects chain not anchored to root", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);

  const realRoot = await buildTestCA("Test Root CA");
  const intermediate = await buildTestCA("Test Issuing CA", realRoot);

  // Different, unrelated root the verifier knows.
  const otherRoot = await buildTestCA("Unrelated Root CA");

  const leaf = await buildLeafCertificate({
    csr,
    intermediate: intermediate.cert,
    validityDays: 180,
    serialNumber: new Uint8Array(20),
  });
  const tbs = encodeTBS(leaf);
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      intermediate.privateKey,
      tbs as BufferSource,
    ),
  );
  const leafPEM = finalizeLeafPEM(leaf, p1363ToDer(sig));

  const chainPem = leafPEM + certToPem(intermediate.cert);
  const otherRootPem = certToPem(otherRoot.cert);

  await assertRejects(
    () => verifyChainToRealReelRoot(chainPem, otherRootPem),
    Error, // pkijs's chain engine throws its own Error, not AttestationError
  );
});

// --- issueLeafChainFromCSR (leaf-chain issuance orchestrator) ----------
//
// End-to-end cryptographic validity is covered by the
// `buildLeafCertificate / encodeTBS / finalizeLeafPEM` round-trip test
// above. These tests target the orchestration boundary the edge function
// relies on: signer injection (KMS sub) and leaf+intermediate ordering.

Deno.test(
  "issueLeafChainFromCSR — emits leaf-first, intermediate-second; calls signer with 32-byte digest",
  async () => {
    const pem = await loadCSRFixture();
    const csr = parseCSRFromPem(pem);
    const root = await buildTestCA("Test Root CA");
    const intermediate = await buildTestCA("Test Issuing CA", root);
    const intermediatePem = certToPem(intermediate.cert);

    let observedDigestLen = -1;
    const signer = async (digest: Uint8Array): Promise<Uint8Array> => {
      observedDigestLen = digest.length;
      // Syntactically-valid DER ECDSA SEQUENCE { r=1, s=1 }. Cryptographic
      // validity is irrelevant here — we're asserting shape only.
      return new Uint8Array(
        new asn1js.Sequence({
          value: [
            new asn1js.Integer({ valueHex: new Uint8Array([0x01]).buffer }),
            new asn1js.Integer({ valueHex: new Uint8Array([0x01]).buffer }),
          ],
        }).toBER(false),
      );
    };

    const issued = await issueLeafChainFromCSR(csr, {
      intermediatePem,
      validityDays: 180,
      signer,
    });

    const blocks = issued.pem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    );
    if (!blocks) throw new Error("no cert blocks in chain");
    assertEquals(blocks.length, 2);

    const leafParsed = parseCertFromPem(blocks[0]);
    const intParsed = parseCertFromPem(blocks[1]);

    assertEquals(
      ctEqual(extractSpkiDer(leafParsed), extractCSRSpkiDer(csr)),
      true,
    );
    assertEquals(
      ctEqual(extractSpkiDer(intParsed), extractSpkiDer(intermediate.cert)),
      true,
    );
    assertEquals(observedDigestLen, 32);

    // The returned serialDecimal must match the
    // serial embedded in the leaf cert. The verifier looks up by this
    // value — drift here would silently break revocation. The leaf's
    // parsed serial is a BER-encoded integer; the comparison is
    // value-equivalence on the canonical-decimal form.
    const leafSerialBytes = new Uint8Array(
      leafParsed.serialNumber.valueBlock.valueHexView,
    );
    let leafSerialHex = "";
    for (let i = 0; i < leafSerialBytes.length; i++) {
      leafSerialHex += leafSerialBytes[i].toString(16).padStart(2, "0");
    }
    const leafSerialDecimal = BigInt("0x" + leafSerialHex).toString(10);
    assertEquals(issued.serialDecimal, leafSerialDecimal);
    // And the serial is positive (high bit cleared per X.509 INTEGER).
    if (BigInt(issued.serialDecimal) <= 0n) {
      throw new Error("serialDecimal must be positive");
    }
  },
);

Deno.test(
  "issueLeafChainFromCSR — propagates signer errors as-is (no wrapping)",
  async () => {
    const pem = await loadCSRFixture();
    const csr = parseCSRFromPem(pem);
    const root = await buildTestCA("Test Root CA");
    const intermediate = await buildTestCA("Test Issuing CA", root);

    const original = new Error("kms down");
    let caught: unknown;
    try {
      await issueLeafChainFromCSR(csr, {
        intermediatePem: certToPem(intermediate.cert),
        validityDays: 180,
        signer: () => {
          throw original;
        },
      });
    } catch (e) {
      caught = e;
    }
    assertEquals(caught, original);
  },
);

Deno.test(
  "buildLeafCertificate — subject DN emits one attribute per RDN (canonical, not multi-valued)",
  async () => {
    const pem = await loadCSRFixture();
    const csr = parseCSRFromPem(pem);
    const root = await buildTestCA("Test Root CA");
    const intermediate = await buildTestCA("Test Issuing CA", root);

    const leaf = await buildLeafCertificate({
      csr,
      intermediate: intermediate.cert,
      validityDays: 180,
      serialNumber: new Uint8Array(20),
    });

    // Pre-round-trip: the override on leaf.subject.toSchema() should emit
    // SEQUENCE { SET, SET, SET, SET } where each SET contains exactly one
    // AttributeTypeAndValue — NOT pkijs's default single multi-valued SET.
    const subjectSchema = leaf.subject.toSchema() as unknown as {
      valueBlock: { value: Array<{ valueBlock: { value: unknown[] } }> };
    };
    const rdns = subjectSchema.valueBlock.value;
    assertEquals(rdns.length, 4); // C, O, OU, CN — four separate RDNs
    for (const rdn of rdns) {
      assertEquals(
        rdn.valueBlock.value.length,
        1,
        "each RDN must contain exactly one AttributeTypeAndValue",
      );
    }

    // Post-round-trip: walk the leaf's serialized DER directly via asn1js
    // (NOT through pkijs's Certificate parser — pkijs flattens RDN groupings
    // into typesAndValues at parse time and would re-emit a single
    // multi-valued SET on re-serialization, masking the structure under test).
    // TBSCertificate layout per RFC 5280 §4.1: SEQUENCE { [0] version,
    // serialNumber, signature, issuer, validity, subject, ... }. Subject is
    // at index 5 when version is present.
    const placeholderSig = new Uint8Array(
      new asn1js.Sequence({
        value: [
          new asn1js.Integer({ valueHex: new Uint8Array([0x01]).buffer }),
          new asn1js.Integer({ valueHex: new Uint8Array([0x01]).buffer }),
        ],
      }).toBER(false),
    );
    const leafPem = finalizeLeafPEM(leaf, placeholderSig);
    const leafDer = pemToDer(leafPem);
    const parsedCert = asn1js.fromBER(
      leafDer.buffer.slice(
        leafDer.byteOffset,
        leafDer.byteOffset + leafDer.byteLength,
      ) as ArrayBuffer,
    );
    if (parsedCert.offset === -1) {
      throw new Error("could not parse finalized leaf DER");
    }
    // deno-lint-ignore no-explicit-any
    const certSeq = (parsedCert.result as any).valueBlock.value as unknown[];
    // deno-lint-ignore no-explicit-any
    const tbsSeq = (certSeq[0] as any).valueBlock.value as unknown[];
    // deno-lint-ignore no-explicit-any
    const subjectAfterRoundTrip = (tbsSeq[5] as any).valueBlock.value as Array<
      { valueBlock: { value: unknown[] } }
    >;
    assertEquals(
      subjectAfterRoundTrip.length,
      4,
      "subject must have 4 RDNs after DER round-trip",
    );
    for (const rdn of subjectAfterRoundTrip) {
      assertEquals(
        rdn.valueBlock.value.length,
        1,
        "each RDN must remain single-valued after DER round-trip",
      );
    }
  },
);

Deno.test(
  "issueLeafChainFromCSR — rejects unparseable intermediate PEM",
  async () => {
    const pem = await loadCSRFixture();
    const csr = parseCSRFromPem(pem);
    await assertRejects(
      () =>
        issueLeafChainFromCSR(csr, {
          intermediatePem: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
          validityDays: 180,
          signer: async () => new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
        }),
      AttestationError,
      "intermediate",
    );
  },
);

Deno.test("verifyChainToRealReelRoot — rejects tampered intermediate signature", async () => {
  const pem = await loadCSRFixture();
  const csr = parseCSRFromPem(pem);

  const root = await buildTestCA("Test Root CA");
  const intermediate = await buildTestCA("Test Issuing CA", root);

  const leaf = await buildLeafCertificate({
    csr,
    intermediate: intermediate.cert,
    validityDays: 180,
    serialNumber: new Uint8Array(20),
  });
  const tbs = encodeTBS(leaf);
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      intermediate.privateKey,
      tbs as BufferSource,
    ),
  );
  const leafPEM = finalizeLeafPEM(leaf, p1363ToDer(sig));

  // Tamper with the intermediate's DER bytes (flip a byte deep in the
  // signature region) and re-PEM. The re-parsed cert is structurally valid
  // but its self-signature against the root no longer verifies.
  const intDer = new Uint8Array(intermediate.cert.toSchema().toBER(false));
  intDer[intDer.length - 5] ^= 0xff;
  const b64 = bytesToBase64(intDer);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  const tamperedIntPem = `-----BEGIN CERTIFICATE-----\n${
    lines.join("\n")
  }\n-----END CERTIFICATE-----\n`;

  const chainPem = leafPEM + tamperedIntPem;
  const rootPem = certToPem(root.cert);

  await assertRejects(
    () => verifyChainToRealReelRoot(chainPem, rootPem),
    Error,
  );
});
