// Unit tests for the per-capture Play Integrity validator (Android).
//
// Covers (mirrors attestation-apple.test.ts where structurally analogous):
//   * validatePlayIntegrityStructure rejects missing / malformed /
//     non-android / non-JWS envelopes.
//   * hasPlayIntegrityAssertion correctly detects presence.
//   * decodeIntegrityToken — happy path (decoded payload), 4xx → INVALID,
//     5xx → VERIFIER_UNAVAILABLE, network error → VERIFIER_UNAVAILABLE.
//   * enforceVerdicts — package-name mismatch, app-recognition-not-recognized,
//     device-integrity-missing, stale timestamp all → ATTESTATION_INVALID.
//   * consumePlayIntegrityForStage:
//       - happy path validates verdicts + burns nonce.
//       - lenient-degraded (no config) burns nonce only, skips decode.
//       - DB replay error → ATTESTATION_REPLAY.
//       - DB non-policy error bubbles up.
//
// Database, fetch, and GoogleAuth are all mocked via vi.mock — these
// tests don't touch Postgres or the network.

import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  afterEach,
} from "vitest";

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

// Mock google-auth-library — its GoogleAuth constructor reaches for
// Application Default Credentials at the filesystem / metadata server,
// which we want neither to happen nor to delay test startup.
vi.mock("google-auth-library", () => {
  const getAccessToken = vi.fn().mockResolvedValue("test-access-token");
  return {
    GoogleAuth: vi.fn().mockImplementation(() => ({
      getAccessToken,
    })),
  };
});

import { consumeAndRecordAttestation } from "../src/db.js";
import {
  PLAY_INTEGRITY_LABEL,
  consumePlayIntegrityForStage,
  hasPlayIntegrityAssertion,
  validatePlayIntegrityStructure,
  __resetAuthClientForTests,
} from "../src/attestation/play_integrity.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";
import type { PlayIntegrityConfig } from "../src/config.js";
import type { ManifestShape } from "../src/c2pa-shape.js";

const consumeMock = consumeAndRecordAttestation as unknown as ReturnType<typeof vi.fn>;

const KEY_ID = "signing-key-id-base64==";
// Empirically-validated shape: Standard Integrity API tokens are
// opaque single-segment base64url-alphabet strings (no dot separators
// in observed output as of 2026-05-18). Length is in the 500–3000
// range; this fixture is 400 chars of base64url-safe filler that
// clears the structural validator's MIN_TOKEN_LENGTH=300 bound with
// headroom. We mock the Google decode endpoint so the actual content
// is never cryptographically validated here — the structural check
// just needs a plausible-looking opaque token string.
const VALID_TOKEN =
  "A".repeat(400);
const VALID_ENVELOPE = {
  challenge: "challenge-base64==",
  token: VALID_TOKEN,
  platform: "android",
};

const CONFIG: PlayIntegrityConfig = {
  packageName: "com.realreel.app",
  cloudProjectNumber: "123456789",
};

// Build a minimal-but-realistic decoded payload Google would return for a
// healthy device with a freshly-issued token.
//
// `deviceAttributes` is nested INSIDE `deviceIntegrity` to match Google's
// real token shape:
//   deviceIntegrity: { deviceRecognitionVerdict: [...],
//                      deviceAttributes: { sdkVersion: 33 } }
// (https://developer.android.com/google/play/integrity/verdicts). The
// `deviceIntegrity` override below merges so a test can tweak either
// `deviceRecognitionVerdict` or `deviceAttributes` without clobbering the
// other; pass `deviceIntegrity` directly to replace the whole subtree.
function freshDecodedPayload(overrides: Record<string, unknown> = {}) {
  const { deviceIntegrity: deviceIntegrityOverride, ...rest } = overrides;
  const deviceIntegrity = {
    // A STRONG device reports the full ladder of met levels; the gate
    // requires MEETS_STRONG_INTEGRITY.
    deviceRecognitionVerdict: [
      "MEETS_BASIC_INTEGRITY",
      "MEETS_DEVICE_INTEGRITY",
      "MEETS_STRONG_INTEGRITY",
    ],
    // Default to a current Android version so existing test cases pass
    // the Android-12-carve-out gate. Tests that exercise the gate
    // override deviceAttributes (or deviceIntegrity) explicitly.
    deviceAttributes: {
      sdkVersion: 34, // Android 14
    },
    ...(deviceIntegrityOverride as Record<string, unknown> | undefined),
  };
  return {
    tokenPayloadExternal: {
      requestDetails: {
        requestPackageName: "com.realreel.app",
        timestampMillis: String(Date.now()),
        requestHash: "abc",
      },
      appIntegrity: {
        appRecognitionVerdict: "PLAY_RECOGNIZED",
        packageName: "com.realreel.app",
        versionCode: "1",
      },
      deviceIntegrity,
      ...rest,
    },
  };
}

function manifestWith(envelope: unknown): ManifestShape {
  return {
    assertions: [
      { label: "org.realreel.capture", data: { capturerUuid: "u" } },
      { label: PLAY_INTEGRITY_LABEL, data: envelope },
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

function mockFetchOk(body: unknown) {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response) as typeof fetch;
}

function mockFetchError(status: number, body = "boom") {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: false,
    status,
    text: async () => body,
    json: async () => ({ error: body }),
  } as unknown as Response) as typeof fetch;
}

function mockFetchNetworkError() {
  globalThis.fetch = vi
    .fn()
    .mockRejectedValue(new Error("ECONNRESET")) as typeof fetch;
}

const originalFetch = globalThis.fetch;

beforeEach(() => {
  consumeMock.mockReset();
  __resetAuthClientForTests();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("hasPlayIntegrityAssertion", () => {
  it("returns true when the assertion is present", () => {
    expect(hasPlayIntegrityAssertion(manifestWith(VALID_ENVELOPE))).toBe(true);
  });

  it("returns false when assertions list is empty or missing the label", () => {
    expect(hasPlayIntegrityAssertion(manifestWithout())).toBe(false);
    expect(hasPlayIntegrityAssertion({})).toBe(false);
    expect(hasPlayIntegrityAssertion({ assertions: [] })).toBe(false);
  });
});

describe("validatePlayIntegrityStructure", () => {
  it("returns the envelope when fully well-formed", () => {
    const out = validatePlayIntegrityStructure(
      manifestWith(VALID_ENVELOPE),
      "Stage 1",
    );
    expect(out).toEqual(VALID_ENVELOPE);
  });

  it("throws ATTESTATION_MISSING when the assertion is absent", () => {
    try {
      validatePlayIntegrityStructure(manifestWithout(), "Stage 1");
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(VerifyError);
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_MISSING);
    }
  });

  it("throws ATTESTATION_INVALID when fields are missing", () => {
    const broken = { token: VALID_TOKEN, platform: "android" };
    try {
      validatePlayIntegrityStructure(manifestWith(broken), "Stage 1");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("throws ATTESTATION_INVALID when platform != 'android'", () => {
    const wrongPlatform = { ...VALID_ENVELOPE, platform: "ios" };
    try {
      validatePlayIntegrityStructure(manifestWith(wrongPlatform), "Stage 1");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("throws ATTESTATION_INVALID when token is empty", () => {
    const empty = { ...VALID_ENVELOPE, token: "" };
    try {
      validatePlayIntegrityStructure(manifestWith(empty), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("throws ATTESTATION_INVALID when token is implausibly short", () => {
    // Below MIN_TOKEN_LENGTH. Real Standard Integrity tokens run
    // 500+ chars; a 10-char string is "definitely not a token."
    const tooShort = { ...VALID_ENVELOPE, token: "tinytoken." };
    try {
      validatePlayIntegrityStructure(manifestWith(tooShort), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("throws ATTESTATION_INVALID when token contains disallowed characters", () => {
    // base64url alphabet is [A-Za-z0-9_.-]. Spaces, `+`, `/`, padding
    // `=`, and Unicode are all rejected as "definitely not a Google-
    // emitted token."
    const garbage = {
      ...VALID_ENVELOPE,
      token: "valid_chars".repeat(20) + " spaces+slash/=padding",
    };
    try {
      validatePlayIntegrityStructure(manifestWith(garbage), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("accepts an opaque single-segment token (the actual Standard API shape)", () => {
    // Regression guard for the 2026-05-18 fix: the validator used to
    // require `split(".").length === 3` (JWS compact assumption);
    // every real Android upload failed because Standard API
    // tokens are opaque single-segment strings. This test asserts
    // that an opaque non-empty plausible-length token passes
    // structural validation — leaving the actual format authority
    // with Google's decodeIntegrityToken API.
    const opaqueToken = { ...VALID_ENVELOPE, token: "ABC123_-".repeat(50) };
    const out = validatePlayIntegrityStructure(manifestWith(opaqueToken), "Stage 2");
    expect(out.token).toBe(opaqueToken.token);
  });

  it("throws ATTESTATION_INVALID when challenge contains non-base64 chars", () => {
    const garbage = { ...VALID_ENVELOPE, challenge: "not!@#valid$%^" };
    try {
      validatePlayIntegrityStructure(manifestWith(garbage), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
  });

  it("includes the stage label in the error message", () => {
    try {
      validatePlayIntegrityStructure(manifestWithout(), "Stage 2");
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).message).toContain("Stage 2");
    }
  });
});

describe("consumePlayIntegrityForStage — happy path", () => {
  it("decodes, validates verdicts, burns nonce", async () => {
    mockFetchOk(freshDecodedPayload());
    consumeMock.mockResolvedValueOnce(undefined);
    await consumePlayIntegrityForStage(
      VALID_ENVELOPE,
      KEY_ID,
      "Stage 1",
      CONFIG,
    );
    expect(consumeMock).toHaveBeenCalledWith(KEY_ID, VALID_ENVELOPE.challenge);
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  });

  it("posts to the package-specific decode URL with Bearer auth", async () => {
    mockFetchOk(freshDecodedPayload());
    consumeMock.mockResolvedValueOnce(undefined);
    await consumePlayIntegrityForStage(
      VALID_ENVELOPE,
      KEY_ID,
      "Stage 1",
      CONFIG,
    );
    const fetchMock = globalThis.fetch as unknown as ReturnType<typeof vi.fn>;
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe(
      "https://playintegrity.googleapis.com/v1/com.realreel.app:decodeIntegrityToken",
    );
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe("Bearer test-access-token");
    expect(JSON.parse(init.body)).toEqual({ integrity_token: VALID_TOKEN });
  });
});

describe("consumePlayIntegrityForStage — lenient (no config)", () => {
  it("burns the nonce but skips Google decode entirely", async () => {
    // No fetch mock — if decode were called we'd get a TypeError on the
    // unmocked global.
    consumeMock.mockResolvedValueOnce(undefined);
    await consumePlayIntegrityForStage(
      VALID_ENVELOPE,
      KEY_ID,
      "Stage 1",
      undefined,
    );
    expect(consumeMock).toHaveBeenCalledTimes(1);
  });
});

describe("consumePlayIntegrityForStage — verdict enforcement", () => {
  it("rejects mismatched requestPackageName as ATTESTATION_INVALID", async () => {
    mockFetchOk(
      freshDecodedPayload({
        requestDetails: {
          requestPackageName: "com.attacker.app",
          timestampMillis: String(Date.now()),
        },
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("requestPackageName mismatch");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects UNRECOGNIZED_VERSION as ATTESTATION_INVALID", async () => {
    mockFetchOk(
      freshDecodedPayload({
        appIntegrity: { appRecognitionVerdict: "UNRECOGNIZED_VERSION" },
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("appRecognitionVerdict");
    }
  });

  it("rejects when MEETS_STRONG_INTEGRITY is missing (only BASIC present)", async () => {
    mockFetchOk(
      freshDecodedPayload({
        deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_BASIC_INTEGRITY"] },
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("MEETS_STRONG_INTEGRITY");
    }
  });

  it("rejects MEETS_DEVICE_INTEGRITY without MEETS_STRONG_INTEGRITY", async () => {
    // A device that clears DEVICE integrity but not STRONG (hardware-backed)
    // is rejected — the verifier requires STRONG. Guards against a regression
    // back to the looser DEVICE gate.
    mockFetchOk(
      freshDecodedPayload({
        deviceIntegrity: {
          deviceRecognitionVerdict: [
            "MEETS_BASIC_INTEGRITY",
            "MEETS_DEVICE_INTEGRITY",
          ],
        },
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 2",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("MEETS_STRONG_INTEGRITY");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("accepts STRONG when sdkVersion == 33 (Android 13, the minimum)", async () => {
    mockFetchOk(
      freshDecodedPayload({
        deviceIntegrity: { deviceAttributes: { sdkVersion: 33 } },
      }),
    );
    await expect(
      consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 2",
        CONFIG,
      ),
    ).resolves.toBeUndefined();
  });

  it("rejects STRONG when sdkVersion < 33 (Android 12 carve-out: STRONG carries no patch-currency signal)", async () => {
    mockFetchOk(
      freshDecodedPayload({
        deviceIntegrity: { deviceAttributes: { sdkVersion: 32 } }, // Android 12
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 2",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("sdkVersion 32");
      expect((e as VerifyError).message).toContain("minimum 33");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects fail-closed when sdkVersion missing (Play Console Optional device labels not enabled)", async () => {
    mockFetchOk(
      freshDecodedPayload({
        deviceIntegrity: { deviceAttributes: {} }, // sdkVersion absent
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 2",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("sdkVersion missing");
      expect((e as VerifyError).message).toContain("Optional device labels");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects fail-closed when deviceAttributes entirely absent", async () => {
    // Delete deviceAttributes from inside deviceIntegrity — the default
    // fixture nests { sdkVersion: 34 } there (matching Google's real shape);
    // this checks the missing-deviceAttributes branch of the gate.
    const payload = freshDecodedPayload();
    delete payload.tokenPayloadExternal.deviceIntegrity.deviceAttributes;
    mockFetchOk(payload);
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 2",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("sdkVersion missing");
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("rejects tokens older than the freshness window", async () => {
    const old = Date.now() - 60 * 60 * 1000; // 1 hour ago, window is 30 min
    mockFetchOk(
      freshDecodedPayload({
        requestDetails: {
          requestPackageName: "com.realreel.app",
          timestampMillis: String(old),
        },
      }),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 2",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
      expect((e as VerifyError).message).toContain("too old");
    }
  });
});

describe("consumePlayIntegrityForStage — decode HTTP errors", () => {
  it("maps Google 400 (bad token) to ATTESTATION_INVALID", async () => {
    mockFetchError(400, "Invalid integrity_token");
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_INVALID);
    }
    expect(consumeMock).not.toHaveBeenCalled();
  });

  it("maps Google 500 to VERIFIER_UNAVAILABLE (retryable)", async () => {
    mockFetchError(500, "Server error");
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
    }
  });

  it("maps auth-side 401 to VERIFIER_UNAVAILABLE (our config bug)", async () => {
    mockFetchError(401, "Unauthorized");
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
    }
  });

  it("maps network errors to VERIFIER_UNAVAILABLE", async () => {
    mockFetchNetworkError();
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
    }
  });

  it("maps decode-timeout (AbortSignal.timeout) to VERIFIER_UNAVAILABLE with a timeout-tagged message", async () => {
    // Simulate what AbortSignal.timeout produces: a DOMException with
    // name "TimeoutError" when the fetch is aborted. Node 22's fetch
    // throws this exact shape, so we mimic it directly.
    const timeoutErr = new Error("The operation was aborted due to timeout");
    (timeoutErr as { name?: string }).name = "TimeoutError";
    globalThis.fetch = vi
      .fn()
      .mockRejectedValue(timeoutErr) as typeof fetch;
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
      // Tag matters: makes a Google-side timeout distinguishable from a
      // generic network error in Sentry / log grep without re-parsing
      // the underlying exception. If this breaks, the error mapping
      // regressed.
      expect((e as VerifyError).message).toContain("timeout");
    }
  });
});

describe("consumePlayIntegrityForStage — DB integration", () => {
  it("maps attestation_challenge_unavailable to ATTESTATION_REPLAY", async () => {
    mockFetchOk(freshDecodedPayload());
    consumeMock.mockRejectedValueOnce(
      new Error(
        "attestation_challenge_unavailable: nonce for key is unknown or already consumed",
      ),
    );
    try {
      await consumePlayIntegrityForStage(
        VALID_ENVELOPE,
        KEY_ID,
        "Stage 1",
        CONFIG,
      );
      throw new Error("expected throw");
    } catch (e) {
      expect((e as VerifyError).code).toBe(VerifyErrorCode.ATTESTATION_REPLAY);
    }
  });

  it("rethrows non-policy DB errors unchanged", async () => {
    mockFetchOk(freshDecodedPayload());
    const dbErr = new Error("connection refused");
    consumeMock.mockRejectedValueOnce(dbErr);
    await expect(
      consumePlayIntegrityForStage(VALID_ENVELOPE, KEY_ID, "Stage 1", CONFIG),
    ).rejects.toBe(dbErr);
  });
});
