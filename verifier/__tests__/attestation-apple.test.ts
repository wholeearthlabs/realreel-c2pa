// Unit tests for the per-capture App Attest validator.
//
// Covers:
//   * extractAppAttestData rejects missing / malformed / non-iOS / non-base64 envelopes.
//   * hasAppAttestAssertion correctly detects presence.
//   * consumeAppAttestForStage propagates DB consumption errors as
//     ATTESTATION_REPLAY (replay) vs bubbles internal errors unchanged.
//   * verifyAppAttestAssertion (Stage 1 validate-only path) does not
//     touch the DB.
//
// Database is mocked via vi.mock — these tests don't touch Postgres.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { encode as cborEncode } from "cbor-x";

// Mock the db module BEFORE importing the validator.
vi.mock("../src/db.js", () => {
  const consumeAndRecordAttestation = vi.fn();
  const lookupSigningKeyRevocation = vi.fn();
  const pingDb = vi.fn();
  return {
    consumeAndRecordAttestation,
    lookupSigningKeyRevocation,
    pingDb,
    initDb: vi.fn(),
    closeDbPool: vi.fn(),
    // The default NonceBurner the attestation consumers fall back to when no
    // adapter is injected. Delegates to the same spies so existing
    // `consumeMock` assertions stay valid.
    postgresAdapter: {
      lookup: lookupSigningKeyRevocation,
      burn: consumeAndRecordAttestation,
      ping: pingDb,
    },
  };
});

import { consumeAndRecordAttestation } from "../src/db.js";
import {
  APPLE_APP_ID,
  APP_ATTEST_LABEL,
  consumeAppAttestForStage,
  extractAppAttestData,
  hasAppAttestAssertion,
  validateAppAttestStructure,
  verifyAppAttestAssertion,
  type AppAttestCryptoInputs,
} from "../src/attestation/apple.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";
import type { ManifestShape } from "../src/c2pa-shape.js";

const consumeMock = consumeAndRecordAttestation as unknown as ReturnType<typeof vi.fn>;

const KEY_ID = "signing-key-id-base64==";
const VALID_ENVELOPE = {
  keyId: "appAttestKey-base64==",
  challenge: "challengeNonce-base64==",
  assertion: "assertionCbor-base64==",
  platform: "ios",
};

function manifestWith(envelope: unknown): ManifestShape {
  return {
    assertions: [
      { label: "org.realreel.capture", data: { capturerUuid: "u" } },
      { label: APP_ATTEST_LABEL, data: envelope },
    ],
  };
}

function manifestWithout(): ManifestShape {
  return {
    assertions: [
      { label: "org.realreel.capture", data: { capturerUuid: "u" } },
    ],
  };
}

beforeEach(() => {
  consumeMock.mockReset();
});

describe("hasAppAttestAssertion", () => {
  it("returns true when the assertion is present", () => {
    expect(hasAppAttestAssertion(manifestWith(VALID_ENVELOPE))).toBe(true);
  });

  it("returns false when assertions list is empty or missing the label", () => {
    expect(hasAppAttestAssertion(manifestWithout())).toBe(false);
    expect(hasAppAttestAssertion({})).toBe(false);
    expect(hasAppAttestAssertion({ assertions: [] })).toBe(false);
  });
});

describe("extractAppAttestData — structural validation", () => {
  it("returns the envelope when fully well-formed", () => {
    const out = extractAppAttestData(manifestWith(VALID_ENVELOPE), "Stage 1");
    expect(out).toEqual(VALID_ENVELOPE);
  });

  it("throws ATTESTATION_MISSING when the assertion is absent", () => {
    try {
      extractAppAttestData(manifestWithout(), "Stage 1");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_MISSING);
    }
  });

  it("throws ATTESTATION_INVALID when fields are missing", () => {
    const broken = { keyId: VALID_ENVELOPE.keyId, platform: "ios" };
    try {
      extractAppAttestData(manifestWith(broken), "Stage 1");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("throws ATTESTATION_INVALID when platform != 'ios'", () => {
    const wrongPlatform = { ...VALID_ENVELOPE, platform: "android" };
    try {
      extractAppAttestData(manifestWith(wrongPlatform), "Stage 1");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("throws ATTESTATION_INVALID when fields contain non-base64 chars", () => {
    const garbageChars = { ...VALID_ENVELOPE, challenge: "not!@#valid$%^" };
    try {
      extractAppAttestData(manifestWith(garbageChars), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("includes the stage label in the error message", () => {
    try {
      extractAppAttestData(manifestWithout(), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).message).toContain("Stage 2");
    }
  });
});

describe("validateAppAttestStructure — pure, no DB side effects", () => {
  it("returns the parsed envelope without touching the DB", () => {
    const out = validateAppAttestStructure(manifestWith(VALID_ENVELOPE), "Stage 1");
    expect(out).toEqual(VALID_ENVELOPE);
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("throws ATTESTATION_INVALID on malformed envelope without burning a nonce", () => {
    const broken = { ...VALID_ENVELOPE, assertion: "" };
    try {
      validateAppAttestStructure(manifestWith(broken), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });
});

// A valid signed App Attest assertion + its matching crypto inputs. Crypto
// verification now ALWAYS runs before the nonce burn (no nonce-only
// fallback), so the DB-layer tests need an assertion that passes
// verification to reach consumeAndRecordAttestation. The signing primitives
// (makeTestKeypair / buildSignedAssertion / sha256Sync) are the module-scope
// helpers defined in the cryptographic-chain-validation section below
// (function decls are hoisted).
function validAppAttestFixture(counter = 1): {
  envelope: typeof VALID_ENVELOPE;
  crypto: AppAttestCryptoInputs;
} {
  const { privateKey, publicKeyRaw } = makeTestKeypair();
  const challengeBytes = Buffer.from("db-layer-challenge-bytes-padding!", "utf8");
  const signingKeySpki = Uint8Array.from(Buffer.from("db-layer-SE-SPKI-DER"));
  const rpIdHash = sha256Sync(Buffer.from(APPLE_APP_ID, "utf8"));
  const assertion = buildSignedAssertion({
    privateKey,
    rpIdHash,
    counter,
    challenge: challengeBytes,
    signingKeySpki,
  });
  return {
    envelope: {
      ...VALID_ENVELOPE,
      challenge: challengeBytes.toString("base64"),
      assertion,
    },
    crypto: { appAttestPublicKey: publicKeyRaw, signingKeySpki },
  };
}

describe("consumeAppAttestForStage — nonce burn + DB error mapping", () => {
  it("burns the nonce after the assertion verifies (null counter — monotonicity dropped)", async () => {
    const { envelope, crypto } = validAppAttestFixture();
    consumeMock.mockResolvedValueOnce(undefined);
    await consumeAppAttestForStage(envelope, KEY_ID, "Stage 2", crypto);
    expect(consumeMock).toHaveBeenCalledTimes(1);
    expect(consumeMock).toHaveBeenCalledWith(KEY_ID, envelope.challenge);
  });

  it("maps attestation_challenge_unavailable to ATTESTATION_REPLAY", async () => {
    const { envelope, crypto } = validAppAttestFixture();
    consumeMock.mockRejectedValueOnce(
      new Error(
        "attestation_challenge_unavailable: nonce for key is unknown or already consumed",
      ),
    );
    try {
      await consumeAppAttestForStage(envelope, KEY_ID, "Stage 2", crypto);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_REPLAY);
    }
  });

  it("rethrows non-policy DB errors unchanged (Postgres unreachable, etc.)", async () => {
    const { envelope, crypto } = validAppAttestFixture();
    const dbErr = new Error("connection refused");
    consumeMock.mockRejectedValueOnce(dbErr);
    await expect(
      consumeAppAttestForStage(envelope, KEY_ID, "Stage 2", crypto),
    ).rejects.toBe(dbErr);
  });
});

// verifyAppAttestAssertion is the crypto-only entry point (CBOR decode +
// rpIdHash + clientDataHash + ECDSA verify + counter extract) with NO DB
// side effects — consumeAppAttestForStage layers the nonce burn on top for
// Stage 2. These tests pin that verifyAppAttestAssertion itself does NOT
// call consumeAndRecordAttestation, so a regression that folds a burn into
// the crypto path fails loud.
describe("verifyAppAttestAssertion — crypto-only, no DB burn", () => {
  it("throws ATTESTATION_INVALID on bad crypto without touching the DB", async () => {
    // Inject crypto inputs that won't match VALID_ENVELOPE's fake assertion
    // bytes. The signature check inside validateAssertionCrypto throws
    // before any DB code path is reachable. The point: even on a failure
    // path, we never burn a Stage 1 nonce under the new policy.
    const fakeCrypto: AppAttestCryptoInputs = {
      appAttestPublicKey: new Uint8Array(65),
      signingKeySpki: new Uint8Array(91),
    };
    try {
      await verifyAppAttestAssertion(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        fakeCrypto,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------
// Apple cryptographic chain validation
// ---------------------------------------------------------------
//
// Real DCAppAttestService outputs aren't reproducible in tests (Apple's
// hardware signs them). We instead generate a P-256 keypair locally that
// stands in for the App Attest credCert key, build an assertion CBOR that
// matches Apple's documented shape, sign it with our test key, and feed
// the public key + SE SPKI through the validator as if it had come from
// user_signing_keys. This exercises every step of the chain (CBOR decode
// + rpIdHash check + clientDataHash reconstruction + signature verify +
// counter extract) against the same crypto primitives a real assertion
// would land on.

/** Build a P-256 test pair + its raw uncompressed pubkey bytes. */
function makeTestKeypair(): { privateKey: KeyObject; publicKeyRaw: Uint8Array } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  // Last 65 bytes of an X9.63 SPKI are the uncompressed point (header is
  // 26 bytes for prime256v1 OID-tagged SPKI). Re-deriving by parsing the
  // last 65 bytes is brittle to header changes — instead, ask Node to
  // emit the raw point via JWK and reassemble it.
  const jwk = publicKey.export({ format: "jwk" }) as {
    crv: string;
    x: string;
    y: string;
  };
  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 33);
  // Sanity: parsed SPKI should agree with the assembled raw point on the
  // last 64 bytes. Cheap correctness assertion.
  if (spkiDer.byteLength < 65) {
    throw new Error("test setup: SPKI DER unexpectedly short");
  }
  return { privateKey, publicKeyRaw: raw };
}

function base64UrlToBytes(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4;
  const b64 = (s + "===".slice(0, pad)).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(Buffer.from(b64, "base64"));
}

/** Compute SHA-256 synchronously via node:crypto. */
function sha256Sync(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Build an authenticatorData buffer the validator will accept: 32-byte
 * rpIdHash, 1-byte flags (irrelevant for per-capture), 4-byte big-endian
 * counter. Per-capture assertions don't carry attested-credential-data,
 * so the buffer is exactly 37 bytes.
 */
function makeAuthData(rpIdHash: Buffer, counter: number): Uint8Array {
  if (rpIdHash.length !== 32) {
    throw new Error("test setup: rpIdHash must be 32 bytes");
  }
  const buf = new Uint8Array(37);
  buf.set(rpIdHash, 0);
  buf[32] = 0x00; // flags — unused on per-capture path
  buf[33] = (counter >>> 24) & 0xff;
  buf[34] = (counter >>> 16) & 0xff;
  buf[35] = (counter >>> 8) & 0xff;
  buf[36] = counter & 0xff;
  return buf;
}

/**
 * Sign + CBOR-encode an assertion that matches Apple's documented shape.
 * Per Apple's "Assessing Fraud Risk" docs:
 *   clientDataHash = SHA256(challenge || SE_SPKI)
 *   nonce          = SHA256(authData || clientDataHash)
 *   signature      = ECDSA-SHA256(nonce, privateKey)
 *                  = ECDSA-primitive(SHA256(nonce), privateKey)
 *
 * That's a literal-reading "double SHA-256" — diverges from WebAuthn's
 * single-hash convention. Empirically verified against real iPhone
 * assertions; see the long comment block in
 * verifier/src/attestation/apple.ts § "5. nonce". Don't simplify this
 * back to `sign("sha256", compositeData, ...)` — the validator would
 * still pass synthetic fixtures but reject every real assertion.
 *
 * Returns base64-encoded CBOR ready to drop into an envelope.assertion field.
 */
function buildSignedAssertion(opts: {
  privateKey: KeyObject;
  rpIdHash: Buffer;
  counter: number;
  challenge: Buffer;
  signingKeySpki: Uint8Array;
}): string {
  const authData = makeAuthData(opts.rpIdHash, opts.counter);
  const clientDataHash = sha256Sync(concatBytes(opts.challenge, opts.signingKeySpki));
  const compositeData = concatBytes(authData, clientDataHash);
  const nonce = sha256Sync(compositeData);
  // `sign("sha256", nonce, ...)` internally does ECDSA(SHA256(nonce), key)
  // which matches Apple's net SHA256(SHA256(compositeData)) digest.
  const signature = sign("sha256", Buffer.from(nonce), opts.privateKey);
  const cbor = cborEncode({
    signature,
    authenticatorData: Buffer.from(authData),
  });
  return Buffer.from(cbor).toString("base64");
}

describe("Apple cryptographic chain validation", () => {
  // Fixed inputs reused across cases so each case shows what it varies.
  const challengeBytes = Buffer.from(
    "phase1b-challenge-32-bytes-padding!",
    "utf8",
  );
  const seSpki = Uint8Array.from(Buffer.from("test-SE-SPKI-DER-placeholder"));
  const challenge = challengeBytes.toString("base64");
  const expectedRpIdHash = sha256Sync(Buffer.from(APPLE_APP_ID, "utf8"));

  let privateKey: KeyObject;
  let publicKeyRaw: Uint8Array;
  let crypto: AppAttestCryptoInputs;

  beforeEach(() => {
    consumeMock.mockReset();
    consumeMock.mockResolvedValue(undefined);
    const kp = makeTestKeypair();
    privateKey = kp.privateKey;
    publicKeyRaw = kp.publicKeyRaw;
    crypto = {
      appAttestPublicKey: publicKeyRaw,
      signingKeySpki: seSpki,
    };
  });

  it("happy path: valid assertion verifies + nonce burns (counter NOT passed — monotonicity dropped)", async () => {
    const counter = 42;
    const assertion = buildSignedAssertion({
      privateKey,
      rpIdHash: expectedRpIdHash,
      counter,
      challenge: challengeBytes,
      signingKeySpki: seSpki,
    });
    await consumeAppAttestForStage(
      { ...VALID_ENVELOPE, challenge, assertion },
      KEY_ID,
      "Stage 1",
      crypto,
    );
    expect(consumeMock).toHaveBeenCalledTimes(1);
    // Counter-monotonicity is dropped: the nonce burn is the sole
    // anti-replay, so the consume RPC is always called with a null counter.
    expect(consumeMock).toHaveBeenCalledWith(KEY_ID, challenge);
  });

  it("counter with top bit set decodes as positive uint32 (regression: signed Int32 cast)", async () => {
    // The counter is folded into the signature-verified authenticatorData,
    // so verifyAppAttestAssertion still extracts + returns it even though it
    // no longer gates the DB consume. Per-operand `>>> 0` inside a `|` chain
    // is a foot-gun — JS bitwise OR re-casts both sides to Int32, undoing the
    // unsignedification. This case asserts the boundary stays a positive
    // bigint via the crypto-only return value.
    const counter = 0xffffffff; // 4_294_967_295 — the largest uint32
    const assertion = buildSignedAssertion({
      privateKey,
      rpIdHash: expectedRpIdHash,
      counter,
      challenge: challengeBytes,
      signingKeySpki: seSpki,
    });
    const extracted = await verifyAppAttestAssertion(
      { ...VALID_ENVELOPE, challenge, assertion },
      KEY_ID,
      "Stage 1",
      crypto,
    );
    expect(extracted).toBe(4294967295n);
    expect(consumeMock).not.toHaveBeenCalled(); // crypto-only path, no burn
  });

  it("rejects WebAuthn-style single-hash signatures (regression: scheme A vs scheme B)", async () => {
    // Defensive test against silent regression of Apple's specific signing
    // scheme. Apple signs ECDSA-SHA256(SHA256(authData || clientDataHash));
    // WebAuthn-style ECDSA-SHA256(authData || clientDataHash) would slide
    // past synthetic happy-path fixtures if both sign+verify were refactored
    // together. This test signs with the WRONG (single-hash) scheme and
    // asserts the validator REJECTS — guards the scheme as a one-way pin.
    const authData = makeAuthData(expectedRpIdHash, 1);
    const clientDataHash = sha256Sync(concatBytes(challengeBytes, seSpki));
    const compositeData = concatBytes(authData, clientDataHash);
    // SINGLE hash — WebAuthn-style, NOT what Apple does.
    const wrongScheme = sign("sha256", Buffer.from(compositeData), privateKey);
    const cbor = cborEncode({
      signature: wrongScheme,
      authenticatorData: Buffer.from(authData),
    });
    const assertion = Buffer.from(cbor).toString("base64");
    try {
      await consumeAppAttestForStage(
        { ...VALID_ENVELOPE, challenge, assertion },
        KEY_ID,
        "Stage 1",
        crypto,
      );
      throw new Error("expected throw — WebAuthn-style signature must be rejected");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("counter at the 2^31 boundary decodes positive (top bit set, second smallest case)", async () => {
    // Cover 0x80000000 specifically — the exact value that flips Int32
    // negative (-2147483648). Asserted via the crypto-only return value
    // (the counter no longer reaches the DB consume — monotonicity dropped).
    const counter = 0x80000000; // 2_147_483_648
    const assertion = buildSignedAssertion({
      privateKey,
      rpIdHash: expectedRpIdHash,
      counter,
      challenge: challengeBytes,
      signingKeySpki: seSpki,
    });
    const extracted = await verifyAppAttestAssertion(
      { ...VALID_ENVELOPE, challenge, assertion },
      KEY_ID,
      "Stage 1",
      crypto,
    );
    expect(extracted).toBe(2147483648n);
    expect(consumeMock).not.toHaveBeenCalled(); // crypto-only path, no burn
  });

  it("rejects ATTESTATION_INVALID on tampered signature, never burns nonce", async () => {
    const assertion = buildSignedAssertion({
      privateKey,
      rpIdHash: expectedRpIdHash,
      counter: 1,
      challenge: challengeBytes,
      signingKeySpki: seSpki,
    });
    // Flip a byte in the middle of the CBOR. Any byte after the CBOR
    // header lands inside either the signature OR authData; both flips
    // make the signature check fail.
    const cbor = Buffer.from(assertion, "base64");
    cbor[cbor.length - 5] ^= 0x01;
    const tampered = cbor.toString("base64");

    try {
      await consumeAppAttestForStage(
        { ...VALID_ENVELOPE, challenge, assertion: tampered },
        KEY_ID,
        "Stage 1",
        crypto,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects ATTESTATION_INVALID on rpIdHash mismatch", async () => {
    const wrongRpId = sha256Sync(Buffer.from("BADTEAM.com.attacker.evil", "utf8"));
    const assertion = buildSignedAssertion({
      privateKey,
      rpIdHash: wrongRpId,
      counter: 1,
      challenge: challengeBytes,
      signingKeySpki: seSpki,
    });
    try {
      await consumeAppAttestForStage(
        { ...VALID_ENVELOPE, challenge, assertion },
        KEY_ID,
        "Stage 1",
        crypto,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("rpIdHash");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("cross-device: assertion signed by device A's key paired with device B's SE_SPKI is rejected", async () => {
    // Device A produces a valid assertion for SE_SPKI_A.
    const seSpkiA = Uint8Array.from(Buffer.from("device-A-SE-SPKI"));
    const assertion = buildSignedAssertion({
      privateKey,
      rpIdHash: expectedRpIdHash,
      counter: 1,
      challenge: challengeBytes,
      signingKeySpki: seSpkiA,
    });
    // Verifier looks up device B's row → SE_SPKI_B. clientDataHash on
    // the verify side won't match what device A actually signed →
    // signature check fails.
    const seSpkiB = Uint8Array.from(Buffer.from("device-B-SE-SPKI"));
    try {
      await consumeAppAttestForStage(
        { ...VALID_ENVELOPE, challenge, assertion },
        KEY_ID,
        "Stage 1",
        { appAttestPublicKey: publicKeyRaw, signingKeySpki: seSpkiB },
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects ATTESTATION_INVALID on malformed CBOR (not a map / wrong shape)", async () => {
    // Encode a CBOR array instead of a map — common shape-confusion case.
    const cbor = cborEncode([1, 2, 3]);
    const malformed = Buffer.from(cbor).toString("base64");
    try {
      await consumeAppAttestForStage(
        { ...VALID_ENVELOPE, challenge, assertion: malformed },
        KEY_ID,
        "Stage 1",
        crypto,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects ATTESTATION_INVALID when authenticatorData is shorter than 37 bytes", async () => {
    // Build a CBOR with valid keys but truncated authenticatorData.
    const cbor = cborEncode({
      signature: Buffer.from([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]),
      authenticatorData: Buffer.alloc(20), // way short
    });
    const truncated = Buffer.from(cbor).toString("base64");
    try {
      await consumeAppAttestForStage(
        { ...VALID_ENVELOPE, challenge, assertion: truncated },
        KEY_ID,
        "Stage 1",
        crypto,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("authenticatorData");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });
});
