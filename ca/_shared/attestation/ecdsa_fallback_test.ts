// Tests for the ECDSA curve/hash fallback in pki.ts.
//
// Supabase Edge Runtime's WebCrypto throws `Not implemented` for ECDSA verify
// when the hash isn't the curve's natural pairing. Apple's App Attest credCert
// is P-384-signed with SHA-256, so the leaf→intermediate link hits that gap.
// Deno CLI implements those pairs, so these tests install a scoped patch that
// makes crypto.subtle.verify reject them the way the edge runtime does.
//
// Run: cd ca && deno test --allow-read --allow-env _shared/attestation/ecdsa_fallback_test.ts

import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.221.0/assert/mod.ts";
import {
  asn1js,
  base64ToBytes,
  parseCertFromDer,
  parseCertFromPem,
  pkijs,
  verifyChainToTrustedRoots,
} from "./pki.ts";
import { APPLE_APPATTEST_ROOT_PEM } from "./roots.ts";

const NATURAL_PAIRING: Record<string, string> = {
  "P-256": "SHA-256",
  "P-384": "SHA-384",
  "P-521": "SHA-512",
};

const realVerify = crypto.subtle.verify.bind(crypto.subtle);

// Makes crypto.subtle.verify behave like the edge runtime's. Scoped rather than
// installed at module load: `deno test` shares one isolate across test files, so
// a leaked patch would surface in a later file as a baffling chain failure.
// pki.ts's engine resolves `.verify` off the subtle object per call, so patching
// the property after that module loads still takes effect.
function simulateEdgeRuntimeGap() {
  let rejectedPairs = 0;
  // deno-lint-ignore no-explicit-any
  (crypto.subtle as any).verify = (
    // deno-lint-ignore no-explicit-any
    algorithm: any,
    key: CryptoKey,
    signature: BufferSource,
    data: BufferSource,
  ) => {
    // deno-lint-ignore no-explicit-any
    const keyAlg = key.algorithm as any;
    if (keyAlg?.name === "ECDSA") {
      const hash = typeof algorithm === "string"
        ? algorithm
        : algorithm?.hash?.name ?? algorithm?.hash;
      if (NATURAL_PAIRING[keyAlg.namedCurve] !== hash) {
        rejectedPairs++;
        throw new Error("Not implemented");
      }
    }
    return realVerify(algorithm, key, signature, data);
  };
  return {
    rejectedPairs: () => rejectedPairs,
    // deno-lint-ignore no-explicit-any
    restore: () => ((crypto.subtle as any).verify = realVerify),
  };
}

async function withEdgeRuntimeGap<T>(
  fn: (gap: ReturnType<typeof simulateEdgeRuntimeGap>) => Promise<T>,
): Promise<T> {
  const gap = simulateEdgeRuntimeGap();
  try {
    return await fn(gap);
  } finally {
    gap.restore();
  }
}

// A real Apple App Attest chain: [credCert (P-256 key, signed SHA-256 by the
// P-384 CA), Apple App Attestation CA 1]. Captured from a dev-signed build on
// 2026-07-08; the credCert is valid ~3 days, hence the pinned validation date.
const APPLE_X5C = [
  "MIID3TCCA2KgAwIBAgIGAZ9IpNaMMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI2MDcwODIwNDk1MFoXDTI2MDcxMTIwNDk1MFowgZExSTBHBgNVBAMMQDFjODI3NDAwOTI5ZmZkOTRmMTg3YTcxZGFmNWY5Y2NlYTRlZDI4YmQ1NTk0YTRlZWNiMzEyY2E3N2M1OTA1YjYxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp0c9CJJCNWYRhvcOBz0MldGUG+LQKk5dzNC1703zM0uZPHJ9ZSjyi/u5A8Xoc745s/2U8b4cfPrFKs+lF3C7wKOCAeUwggHhMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgTwMBQGA1UdJQQNMAsGCSqGSIb3Y2QEGDB9BgkqhkiG92NkCAUEcDBupAMCAQq/iTADAgEAv4kxAwIBAL+JMgMCAQC/iTMDAgEAv4k0IQQfN1JQSFlZNjZVNi5jb20ucmVhbHJlZWwuYXBwLmRldr+JNgMCAQS/iTcDAgEAv4k5AwIBAL+JOgMCAQC/iTsDAgEAqgMCAQAwgZwGCSqGSIb3Y2QIBwSBjjCBi7+KeAYEBDI2LjW/iFADAgEAv4p5CQQHMS4wLjIyM7+KewcEBTIzRjc3v4p8BgQEMjYuNb+KfQYEBDI2LjW/in4DAgEAv4sKDwQNMjMuNi43Ny4wLjAsML+LCw8EDTIzLjYuNzcuMC4wLDC/iwwPBA0yMy42Ljc3LjAuMCwwv4gCCgQIaXBob25lb3MwMwYJKoZIhvdjZAgCBCYwJKEiBCBcuc+AqQ9zUC7BfyqA5kdr0zQCVF1wd/JLoctSwifqOzBYBgkqhkiG92NkCAYESzBJo0cERTBDDAIxMTA9MAoMA29rZKEDAQH/MAkMAm9hoQMBAf8wCwwEb3NnbqEDAQH/MAsMBG9kZWyhAwEB/zAKDANvY2uhAwEB/zAKBggqhkjOPQQDAgNpADBmAjEA+im5HLrobxIOPTgeAebtPRJCEKYhd0bK2TPJ4+HieYLRJl7eKqq3GVz+3jAGlO2dAjEAuE52drtf8/eY+BwVmJ1LTayePv5Vv/3IjceVUSmGl1WhS76nsgFzlwHIi70JCnbS",
  "MIICQzCCAcigAwIBAgIQCbrF4bxAGtnUU5W8OBoIVDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM5NTVaFw0zMDAzMTMwMDAwMDBaME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAErls3oHdNebI1j0Dn0fImJvHCX+8XgC3qs4JqWYdP+NKtFSV4mqJmBBkSSLY8uWcGnpjTY71eNw+/oI4ynoBzqYXndG6jWaL2bynbMq9FXiEWWNVnr54mfrJhTcIaZs6Zo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFKyREFMzvb5oQf+nDKnl+url5YqhMB0GA1UdDgQWBBQ+410cBBmpybQx+IR01uHhV3LjmzAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaQAwZgIxALu+iI1zjQUCz7z9Zm0JV1A1vNaHLD+EMEkmKe3R+RToeZkcmui1rvjTqFQz97YNBgIxAKs47dDMge0ApFLDukT5k2NlU/7MKX8utN+fXr5aSsq2mVxLgg35BDhveAe7WJQ5tw==",
];
const CHAIN_VALIDATION_TIME = new Date("2026-07-09T20:49:50Z");

function appleRoot() {
  return parseCertFromPem(APPLE_APPATTEST_ROOT_PEM);
}

function chainFrom(leaf: Uint8Array) {
  return [
    parseCertFromDer(leaf),
    parseCertFromDer(base64ToBytes(APPLE_X5C[1])),
  ];
}

// Guards the tests below against passing vacuously: if this stops throwing, the
// patch no longer simulates the edge runtime and the chain test proves nothing.
Deno.test("ECDSA fallback — the simulated edge-runtime gap is in effect", async () => {
  await withEdgeRuntimeGap(async (gap) => {
    const intermediate = parseCertFromDer(base64ToBytes(APPLE_X5C[1]));
    const key = await crypto.subtle.importKey(
      "spki",
      intermediate.subjectPublicKeyInfo.toSchema().toBER(false),
      { name: "ECDSA", namedCurve: "P-384" },
      false,
      ["verify"],
    );
    let message = "";
    try {
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        new Uint8Array(96),
        new Uint8Array(32),
      );
    } catch (e) {
      message = (e as Error).message;
    }
    assertEquals(message, "Not implemented");
    assertEquals(gap.rejectedPairs(), 1);
  });
});

Deno.test("ECDSA fallback — P-384/SHA-256 chain validates when WebCrypto can't", async () => {
  // Without EcdsaFallbackCryptoEngine this throws "No valid certificate paths
  // found", the exact production symptom the fallback fixes.
  await withEdgeRuntimeGap(() =>
    verifyChainToTrustedRoots(
      chainFrom(base64ToBytes(APPLE_X5C[0])),
      [appleRoot()],
      CHAIN_VALIDATION_TIME,
    )
  );
});

// The fallback must be a real cryptographic verification, not a bypass. These
// assert the leaf→intermediate verify directly rather than through
// verifyChainToTrustedRoots: a chain-level assertRejects would also pass with
// the fallback deleted, because path-building then fails for its own reason.
async function verifyLeafAgainstIntermediate(
  leaf: Uint8Array,
): Promise<boolean> {
  const [cert, intermediate] = chainFrom(leaf);
  return await withEdgeRuntimeGap(() => cert.verify(intermediate));
}

Deno.test("ECDSA fallback — verifies an untampered leaf against its issuer", async () => {
  assertEquals(
    await verifyLeafAgainstIntermediate(base64ToBytes(APPLE_X5C[0])),
    true,
  );
});

Deno.test("ECDSA fallback — returns false for a tampered signature", async () => {
  const leaf = base64ToBytes(APPLE_X5C[0]);
  leaf[leaf.length - 1] ^= 0x01; // last byte lives in the ECDSA signature's `s`
  assertEquals(await verifyLeafAgainstIntermediate(leaf), false);
});

Deno.test("ECDSA fallback — returns false for a tampered TBS body", async () => {
  const leaf = base64ToBytes(APPLE_X5C[0]);
  leaf[120] ^= 0x01; // inside the signed TBSCertificate
  assertEquals(await verifyLeafAgainstIntermediate(leaf), false);
});

// Builds a self-signed P-256 cert whose signature uses `hash`, so we can assert
// which signature algorithms the fallback is willing to verify.
async function selfSignedCert(hash: string): Promise<pkijs.Certificate> {
  const keys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;

  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: 1 });
  for (const dn of [cert.issuer, cert.subject]) {
    dn.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: "2.5.4.3",
        value: new asn1js.PrintableString({ value: "ecdsa-fallback-test" }),
      }),
    );
  }
  cert.notBefore = new pkijs.Time({ type: 0, value: new Date("2020-01-01") });
  cert.notAfter = new pkijs.Time({ type: 0, value: new Date("2040-01-01") });
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(keys.privateKey, hash);
  return cert;
}

// SHA-1 is a mismatched pair for P-256, so it would route to the fallback if it
// were listed in ECDSA_SIG_HASH_BY_OID. It must not be: the fallback exists to
// restore verification the runtime can't do, never to widen the set of
// signature algorithms this trust boundary accepts.
Deno.test("ECDSA fallback — refuses ecdsa-with-SHA1 rather than verifying it", async () => {
  const cert = await selfSignedCert("SHA-1");
  assertEquals(cert.signatureAlgorithm.algorithmId, "1.2.840.10045.4.1");
  await withEdgeRuntimeGap(async (gap) => {
    // Falls through to WebCrypto, which rejects the pair — so enrollment fails
    // closed exactly as it did before the fallback existed.
    await assertRejects(() => cert.verify(), Error, "Not implemented");
    assertEquals(gap.rejectedPairs(), 1);
  });
});

// Contrast case: a natural pair still verifies through WebCrypto untouched.
Deno.test("ECDSA fallback — leaves natural curve/hash pairs on WebCrypto", async () => {
  const cert = await selfSignedCert("SHA-256");
  await withEdgeRuntimeGap(async (gap) => {
    assertEquals(await cert.verify(), true);
    assertEquals(gap.rejectedPairs(), 0);
  });
});

// pkijs's CMS/OCSP callers pass `shaAlgorithm` explicitly, which skips the
// signature-OID table. The hash allowlist must still apply on that path, or
// SHA-1 gets back in through the side door.
Deno.test("ECDSA fallback — an explicit shaAlgorithm cannot smuggle in SHA-1", async () => {
  const cert = await selfSignedCert("SHA-1");
  await withEdgeRuntimeGap(async () => {
    await assertRejects(
      () =>
        fallbackEngine().verifyWithPublicKey(
          cert.tbsView,
          cert.signatureValue,
          cert.subjectPublicKeyInfo,
          cert.signatureAlgorithm,
          "SHA-1",
        ),
      Error,
      "Not implemented",
    );
  });
});

// deno-lint-ignore no-explicit-any
function fallbackEngine(): any {
  return pkijs.getEngine().crypto;
}

// --- Parity with WebCrypto ----------------------------------------------
//
// The fallback must accept exactly what the WebCrypto path accepts: the same
// signature encodings, key encodings, and algorithm sanity checks.

Deno.test("ECDSA fallback — covers non-Apple mismatched pairs (P-256/SHA-384)", async () => {
  const cert = await selfSignedCert("SHA-384");
  await withEdgeRuntimeGap(async (gap) => {
    assertEquals(await cert.verify(), true);
    assertEquals(gap.rejectedPairs(), 0);
    cert.tbsView[20] ^= 0x01;
    assertEquals(await cert.verify(), false);
  });
});

Deno.test("ECDSA fallback — accepts BER long-form signature lengths like WebCrypto", async () => {
  const [leaf, intermediate] = chainFrom(base64ToBytes(APPLE_X5C[0]));
  const sig = leaf.signatureValue.valueBlock.valueHexView;
  assertEquals(sig[0], 0x30);
  // Re-encode the SEQUENCE length in (non-minimal) long form; noble's strict
  // Signature.fromDER rejects this, asn1js accepts it on both engine paths.
  const longForm = new Uint8Array([0x30, 0x81, ...sig.slice(1)]);
  await withEdgeRuntimeGap(async () => {
    assertEquals(
      await fallbackEngine().verifyWithPublicKey(
        leaf.tbsView,
        new asn1js.BitString({ valueHex: longForm.buffer }),
        intermediate.subjectPublicKeyInfo,
        leaf.signatureAlgorithm,
      ),
      true,
    );
  });
});

Deno.test("ECDSA fallback — rejects compressed public keys like WebCrypto import", async () => {
  const [leaf, intermediate] = chainFrom(base64ToBytes(APPLE_X5C[0]));
  const spki = intermediate.subjectPublicKeyInfo;
  const pub = spki.subjectPublicKey.valueBlock.valueHexView;
  // Same P-384 key, compressed to 0x02/0x03 || X — a valid noble encoding
  // that WebCrypto's SPKI import refuses.
  const compressed = new Uint8Array([
    0x02 | (pub[pub.length - 1] & 1),
    ...pub.slice(1, 49),
  ]);
  spki.subjectPublicKey = new asn1js.BitString({ valueHex: compressed.buffer });
  assertEquals(
    await fallbackEngine().verifyWithPublicKey(
      leaf.tbsView,
      leaf.signatureValue,
      spki,
      leaf.signatureAlgorithm,
    ),
    false,
  );
});

Deno.test("ECDSA fallback — declines a declared RSA-PSS algorithm over an EC key", async () => {
  const [leaf, intermediate] = chainFrom(base64ToBytes(APPLE_X5C[0]));
  // Must fall through to WebCrypto, which fails the RSA-PSS import of an EC
  // key — not re-interpret the mislabeled structure as ECDSA and verify it.
  await assertRejects(() =>
    fallbackEngine().verifyWithPublicKey(
      leaf.tbsView,
      leaf.signatureValue,
      intermediate.subjectPublicKeyInfo,
      new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.10" }),
      "SHA-256",
    )
  );
});

Deno.test("ECDSA fallback — declines non-OID ECDSA public key parameters", async () => {
  const [leaf, intermediate] = chainFrom(base64ToBytes(APPLE_X5C[0]));
  const spki = intermediate.subjectPublicKeyInfo;
  spki.algorithm.algorithmParams = new asn1js.PrintableString({
    value: "1.3.132.0.34",
  });
  await assertRejects(() =>
    fallbackEngine().verifyWithPublicKey(
      leaf.tbsView,
      leaf.signatureValue,
      spki,
      leaf.signatureAlgorithm,
    )
  );
});
