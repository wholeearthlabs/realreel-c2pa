// Builder/self-verify tests: sign with an ephemeral P-256 key (KMS is CLI-only
// and injected), then check the produced DER parses as a proper RFC 6960
// response, survives verifyOcspResponseDer, and round-trips through the router
// against a real openssl-generated request. The encoder itself was also
// validated externally: openssl `ocsp -respin` reports "Response verify OK"
// for its output against a scratch CA hierarchy.
//
//   deno test --allow-read ocsp/
import { p256 } from "@noble/curves/nist.js";
import {
  buildOcspResponseDer,
  OUT_FILE_BY_HASH_OID,
  verifyOcspResponseDer,
} from "./build-ocsp-responses.ts";
import { handleRequest } from "./router.ts";
import {
  bytesEqual,
  KV_KEY_BY_HASH_OID,
  OID_SHA1,
  OID_SHA256,
  toArrayBuffer,
} from "./ocsp.ts";

const dir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
const rootPem = await Deno.readTextFile(new URL("realreel-c2pa-root.pem", dir));
const icaPem = await Deno.readTextFile(
  new URL("realreel-claim-signing-ca.pem", dir),
);
const responderPem = await Deno.readTextFile(
  new URL("realreel-ocsp-responder-1.pem", dir),
);

const priv = p256.utils.randomPrivateKey();
const pub = p256.getPublicKey(priv, false); // uncompressed point, like an SPKI's key bits
const signTbs = async (tbs: Uint8Array): Promise<Uint8Array> => {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(tbs)),
  );
  return p256.sign(digest, priv).toDERRawBytes();
};

const NOW = new Date("2026-07-24T12:00:00Z");
const base = {
  rootPem,
  icaPem,
  responderPem,
  status: "good" as const,
  now: NOW,
  validityDays: 7,
  signTbs,
};

function assert(cond: unknown, msg: string): void {
  if (!cond) throw new Error(msg);
}
async function assertRejects(
  fn: () => Promise<unknown>,
  label: string,
): Promise<void> {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error(`${label}: expected a verification failure`);
}

Deno.test("good responses build and self-verify for both CertID hash algorithms", async () => {
  for (const hashOid of [OID_SHA1, OID_SHA256]) {
    const der = await buildOcspResponseDer({ ...base, hashOid });
    const verified = await verifyOcspResponseDer(der, {
      rootPem,
      icaPem,
      hashOid,
      status: "good",
      now: NOW,
      signerKeyBits: pub,
      expectEmbeddedCertPem: responderPem,
    });
    assert(
      verified.signerCn === "RealReel OCSP Responder 1",
      `signer CN (${verified.signerCn})`,
    );
    assert(
      verified.thisUpdate.getTime() === NOW.getTime(),
      "thisUpdate == now",
    );
    assert(
      verified.nextUpdate.getTime() - verified.thisUpdate.getTime() ===
        7 * 86_400_000,
      "validity window is 7 days",
    );
  }
});

Deno.test("verification is pinned to the CertID hash algorithm", async () => {
  const der = await buildOcspResponseDer({ ...base, hashOid: OID_SHA1 });
  await assertRejects(
    () =>
      verifyOcspResponseDer(der, {
        rootPem,
        icaPem,
        hashOid: OID_SHA256,
        status: "good",
        now: NOW,
        signerKeyBits: pub,
      }),
    "sha1 response verified as sha256",
  );
});

Deno.test("a tampered response fails signature verification", async () => {
  const der = await buildOcspResponseDer({ ...base, hashOid: OID_SHA1 });
  const tampered = new Uint8Array(der);
  // Flip a bit inside tbsResponseData (producedAt lives ~60 bytes in).
  tampered[60] ^= 0x01;
  await assertRejects(
    () =>
      verifyOcspResponseDer(tampered, {
        rootPem,
        icaPem,
        hashOid: OID_SHA1,
        status: "good",
        now: NOW,
        signerKeyBits: pub,
      }),
    "tampered response",
  );
});

Deno.test("embedded-cert pinning catches the wrong certificate", async () => {
  const der = await buildOcspResponseDer({ ...base, hashOid: OID_SHA1 });
  await assertRejects(
    () =>
      verifyOcspResponseDer(der, {
        rootPem,
        icaPem,
        hashOid: OID_SHA1,
        status: "good",
        now: NOW,
        signerKeyBits: pub,
        expectEmbeddedCertPem: icaPem, // not the responder
      }),
    "wrong embedded cert",
  );
});

Deno.test("revoked responses encode and verify; a good-expecting check rejects them", async () => {
  const der = await buildOcspResponseDer({
    ...base,
    hashOid: OID_SHA1,
    status: "revoked",
    revocationTime: new Date("2026-07-20T00:00:00Z"),
    revocationReason: 1, // keyCompromise
  });
  await verifyOcspResponseDer(der, {
    rootPem,
    icaPem,
    hashOid: OID_SHA1,
    status: "revoked",
    now: NOW,
    signerKeyBits: pub,
  });
  await assertRejects(
    () =>
      verifyOcspResponseDer(der, {
        rootPem,
        icaPem,
        hashOid: OID_SHA1,
        status: "good",
        now: NOW,
        signerKeyBits: pub,
      }),
    "revoked response verified as good",
  );
});

Deno.test("a non-integer or out-of-range revocation reason is refused at build time", async () => {
  // NaN would encode as a zero-length ENUMERATED that openssl rejects as
  // illegal DER — the builder must refuse rather than emit it.
  for (const revocationReason of [Number.NaN, 1.5, -1, 11]) {
    await assertRejects(
      () =>
        buildOcspResponseDer({
          ...base,
          hashOid: OID_SHA1,
          status: "revoked",
          revocationTime: new Date("2026-07-20T00:00:00Z"),
          revocationReason,
        }),
      `reason ${revocationReason} accepted`,
    );
  }
});

Deno.test("an expired response fails self-verification", async () => {
  const der = await buildOcspResponseDer({ ...base, hashOid: OID_SHA1 });
  await assertRejects(
    () =>
      verifyOcspResponseDer(der, {
        rootPem,
        icaPem,
        hashOid: OID_SHA1,
        status: "good",
        now: new Date(NOW.getTime() + 8 * 86_400_000), // past nextUpdate
        signerKeyBits: pub,
      }),
    "expired response",
  );
});

Deno.test("built responses round-trip through the router for an openssl request", async () => {
  // The same openssl-generated request bytes router_test.ts pins.
  const REQ_SHA1_HEX =
    "305530533051304f304d300906052b0e03021a050004149ab24e11e0c1f6d783bfdb1881f706af6954838e0414a1a57fee084567cf67b2810dcceae42fe3e6c20d0214095796d6d429759614860de66811df37549c4b8c";
  const reqDer = new Uint8Array(REQ_SHA1_HEX.length / 2);
  for (let i = 0; i < reqDer.length; i++) {
    reqDer[i] = parseInt(REQ_SHA1_HEX.slice(2 * i, 2 * i + 2), 16);
  }

  const responseDer = await buildOcspResponseDer({
    ...base,
    hashOid: OID_SHA1,
  });
  const store = {
    get: (key: string) =>
      Promise.resolve(
        key === KV_KEY_BY_HASH_OID[OID_SHA1]
          ? toArrayBuffer(responseDer)
          : null,
      ),
  };
  const res = await handleRequest(
    new Request("http://ocsp.realreel.xyz/", {
      method: "POST",
      body: toArrayBuffer(reqDer),
    }),
    { rootPem, icaPem },
    store,
  );
  assert(res.status === 200, "status");
  assert(
    res.headers.get("content-type") === "application/ocsp-response",
    "content-type",
  );
  const served = new Uint8Array(await res.arrayBuffer());
  assert(
    bytesEqual(served, responseDer),
    "served bytes are the pre-signed response",
  );
});

Deno.test("output filenames mirror the KV keys", () => {
  assert(
    OUT_FILE_BY_HASH_OID[OID_SHA1] === "response-sha1.der",
    "sha1 filename",
  );
  assert(
    OUT_FILE_BY_HASH_OID[OID_SHA256] === "response-sha256.der",
    "sha256 filename",
  );
});
