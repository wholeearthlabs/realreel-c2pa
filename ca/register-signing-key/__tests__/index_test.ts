// Unit tests for register-signing-key.
//
// register-signing-key is the highest-trust edge function in the branch:
// it validates a hardware-attestation chain + CSR, asks Cloud KMS to
// sign a leaf cert with the RealReel intermediate, and persists the
// resulting row. A regression that loosened any of the input checks
// would let a tampered client enroll a key it doesn't actually possess.
//
// The reviewer's H13 specifically named:
//   1. CSR↔SPKI binding — the constant-time check that the attested
//      hardware pubkey matches the CSR's SPKI. Without this, an attacker
//      could POST attested-pubkey-A alongside CSR-carrying-pubkey-B and
//      the mismatch would only surface later at verifier time.
//   2. Malformed CSR — parse / signature / format failures.
//   3. Env-var boot — REALREEL_INTERMEDIATE_CERT_PEM unset.
//
// This file pins those three plus the natural edge-function surface
// (auth, AAL2, rate limit, body validation, enrollment-challenge burn,
// attestation rejection, KMS misconfig, persistence errors, happy path)
// for end-to-end coverage of the handler's orchestration. The underlying
// crypto primitives (Apple + Android attestation, PKI, KMS REST) are
// covered by their own dedicated test files.

import {
  assertEquals,
  assertExists,
  assertObjectMatch,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  buildCachedIntermediateCheck,
  handleRegister,
  type RegisterDeps,
} from "../index.ts";
import {
  buildRequest,
  fakeAuthUser,
  makeMockSupabaseClient,
  readJsonResponse,
  testUserId,
} from "../../_shared/test-harness/edge-test.ts";
import { AttestationError } from "../../_shared/attestation/pki.ts";

// ---------- Fixtures + helpers ---------------------------------------

const VALID_INTERMEDIATE_PEM =
  "-----BEGIN CERTIFICATE-----\nMOCKED-INTERMEDIATE-CERT-PEM\n-----END CERTIFICATE-----";

const VALID_CSR_PEM =
  "-----BEGIN CERTIFICATE REQUEST-----\nMOCKED-CSR\n-----END CERTIFICATE REQUEST-----";

// A 65-byte X9.63 uncompressed P-256 pubkey shape. The exact bytes
// don't matter for any test since attestation + CSR validators are
// mocked — we just need *some* bytes that the handler can SHA-256 to
// produce a key_id.
const FAKE_SE_PUBKEY_BYTES = new Uint8Array(65);
FAKE_SE_PUBKEY_BYTES[0] = 0x04;
for (let i = 1; i < 65; i++) FAKE_SE_PUBKEY_BYTES[i] = (i * 7) & 0xff;
const FAKE_SE_PUBKEY_B64 = btoa(String.fromCharCode(...FAKE_SE_PUBKEY_BYTES));

// Distinct second pubkey for the CSR↔SPKI mismatch case. The handler's
// constant-time comparison treats this as "different bytes" → reject.
const ATTACKER_SE_PUBKEY_BYTES = new Uint8Array(65);
ATTACKER_SE_PUBKEY_BYTES[0] = 0x04;
for (let i = 1; i < 65; i++) ATTACKER_SE_PUBKEY_BYTES[i] = (i * 11) & 0xff;

// Apple attestation blob — opaque bytes. Mocked validator just returns
// `{ credCertPublicKey }`; the bytes themselves are never decoded in tests.
const FAKE_APPLE_ATTESTATION_BYTES = new Uint8Array([0xa1, 0xa2, 0xa3]);
const FAKE_APPLE_ATTESTATION_B64 = btoa(
  String.fromCharCode(...FAKE_APPLE_ATTESTATION_BYTES),
);

// Android attestation is a JSON-stringified array of base64 cert DER.
// Mocked validator only checks shape.
const FAKE_ANDROID_ATTESTATION_JSON = JSON.stringify([
  "leaf-cert-b64",
  "intermediate-cert-b64",
]);

// Valid challenge bytes (32 random — content doesn't matter, just shape).
const VALID_CHALLENGE_BYTES = new Uint8Array(32);
for (let i = 0; i < 32; i++) VALID_CHALLENGE_BYTES[i] = i;
const VALID_CHALLENGE_B64 = btoa(String.fromCharCode(...VALID_CHALLENGE_BYTES));

interface BuildBodyOverrides {
  publicKey?: string;
  platform?: string;
  attestation?: string;
  keyId?: string;
  keyVersion?: string;
  challenge?: string;
  csr?: string;
  deviceLabel?: string;
  // Pass `null` or a string explicitly to override; omit to leave the
  // body's supersedeKeyId field absent entirely (initial-enrollment path).
  supersedeKeyId?: string | null;
}

function buildIosBody(overrides: BuildBodyOverrides = {}): unknown {
  return {
    publicKey: FAKE_SE_PUBKEY_B64,
    platform: "ios",
    attestation: FAKE_APPLE_ATTESTATION_B64,
    keyId: "fake-apple-attest-key-id",
    keyVersion: "4",
    challenge: VALID_CHALLENGE_B64,
    csr: VALID_CSR_PEM,
    deviceLabel: "iOS 18.2",
    ...overrides,
  };
}

function buildAndroidBody(overrides: BuildBodyOverrides = {}): unknown {
  return {
    publicKey: FAKE_SE_PUBKEY_B64,
    platform: "android-strongbox",
    attestation: FAKE_ANDROID_ATTESTATION_JSON,
    keyId: "realreel-signing-android-key-alias",
    keyVersion: "4",
    challenge: VALID_CHALLENGE_B64,
    csr: VALID_CSR_PEM,
    deviceLabel: "Android 15",
    ...overrides,
  };
}

/**
 * Build a RegisterDeps with sensible happy-path stubs. Tests override
 * individual fields to drive specific failure modes. Modeled on the
 * RevokeDeps builder pattern from revoke-signing-key/__tests__.
 */
function buildDeps(opts: {
  userId?: string;
  intermediatePem?: string;
  rateLimit?: { ok: true } | { ok: false; retryAfter: number };
  aalReject?: Response | null;
  // ---- CSR/attestation/KMS overrides for failure-mode tests ----
  parseCSRFromPemImpl?: RegisterDeps["parseCSRFromPem"];
  verifyCSRSignatureImpl?: RegisterDeps["verifyCSRSignature"];
  csrSpkiBytes?: Uint8Array;
  validateAppleAttestationImpl?: RegisterDeps["validateAppleAttestation"];
  validateAndroidAttestationImpl?: RegisterDeps["validateAndroidAttestation"];
  loadKmsCredentialsImpl?: RegisterDeps["loadKmsCredentials"];
  kmsSignDigestImpl?: RegisterDeps["kmsSignDigest"];
  ensureIntermediateImpl?: RegisterDeps["ensureIntermediateMatchesKms"];
  issueLeafChainImpl?: RegisterDeps["issueLeafChainFromCSR"];
  // ---- Burn RPC + INSERT RPC results ----
  burnResult?: { data: unknown; error: unknown };
  insertResult?: { data: unknown; error: unknown };
} = {}): {
  deps: RegisterDeps;
  mockClient: ReturnType<typeof makeMockSupabaseClient>;
} {
  const mockClient = makeMockSupabaseClient();
  // Queue: first call is the burn RPC, second is the INSERT RPC.
  mockClient.queueResults([
    opts.burnResult ?? { data: "4", error: null }, // burn → returns key_version
    opts.insertResult ?? { data: null, error: null }, // INSERT → no error
  ]);

  // Happy-path CSR pubkey defaults to MATCHING the body's publicKey
  // (so the binding check passes). Tests override csrSpkiBytes to
  // drive the mismatch case.
  const csrSpki = opts.csrSpkiBytes ?? FAKE_SE_PUBKEY_BYTES;

  const deps: RegisterDeps = {
    getUserFromAuthHeader: () =>
      Promise.resolve(
        fakeAuthUser({ id: opts.userId ?? testUserId("alice") }),
      ),
    requireAal2IfMfaEnrolled: () =>
      Promise.resolve(opts.aalReject ?? null),
    enforceRateLimit: () =>
      Promise.resolve(opts.rateLimit ?? { ok: true }),
    makeServiceRoleClient: () => mockClient.client,
    validateAppleAttestation:
      opts.validateAppleAttestationImpl ??
      (() => Promise.resolve({ credCertPublicKey: new Uint8Array(65) })),
    validateAndroidAttestation:
      opts.validateAndroidAttestationImpl ??
      // Default happy-path stub: returns a recent osPatchLevel so the
      // patch-gate decision in register-signing-key/index.ts:Android-
      // branch always accepts. Individual tests override
      // validateAndroidAttestationImpl to drive specific failure modes.
      (() => Promise.resolve({ osPatchLevel: 209901 })),
    parseCSRFromPem:
      opts.parseCSRFromPemImpl ??
      // deno-lint-ignore no-explicit-any
      (((_pem: string) => ({ __mockCsr: true })) as any),
    verifyCSRSignature:
      opts.verifyCSRSignatureImpl ?? (() => Promise.resolve()),
    extractCSRSpkiDer: () => csrSpki,
    issueLeafChainFromCSR:
      opts.issueLeafChainImpl ??
      (() =>
        Promise.resolve({
          pem: "-----BEGIN CERTIFICATE-----\nMOCKED-LEAF-CHAIN\n-----END CERTIFICATE-----",
          serialDecimal: "12345678",
          serialBytes: new Uint8Array([1, 2, 3, 4]),
          notAfter: new Date("2031-01-01T00:00:00Z"),
        })),
    loadKmsCredentials:
      opts.loadKmsCredentialsImpl ??
      // deno-lint-ignore no-explicit-any
      (() => Promise.resolve({} as any)),
    kmsSignDigest:
      opts.kmsSignDigestImpl ?? (() => Promise.resolve(new Uint8Array(64))),
    getIntermediatePem: () =>
      opts.intermediatePem ?? VALID_INTERMEDIATE_PEM,
    ensureIntermediateMatchesKms:
      opts.ensureIntermediateImpl ?? (() => Promise.resolve()),
  };
  return { deps, mockClient };
}

// =====================================================================
// Method + preflight
// =====================================================================

Deno.test("register-signing-key — GET → 405", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({ method: "GET" }),
    deps,
  );
  assertEquals(res.status, 405);
});

Deno.test("register-signing-key — OPTIONS preflight → 200 with CORS headers", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    new Request("http://localhost/test", {
      method: "OPTIONS",
      headers: { origin: "https://example.com" },
    }),
    deps,
  );
  assertEquals(res.status, 200);
  // Pin the CORS headers explicitly — a regression that returns 200
  // but drops Access-Control-Allow-Origin would silently break browser
  // clients without failing the status check.
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
  assertEquals(
    res.headers.get("Access-Control-Allow-Headers"),
    "authorization, x-client-info, apikey, content-type",
  );
});

// =====================================================================
// Env-var boot (H13: REALREEL_INTERMEDIATE_CERT_PEM unset)
// =====================================================================

Deno.test("register-signing-key — REALREEL_INTERMEDIATE_CERT_PEM empty → 500 Server misconfiguration (auth never reached)", async () => {
  // The handler must fail-fast at 500 before reading the JWT or body
  // when the intermediate PEM env is unset — otherwise the CSR pipeline
  // would run, attestation would validate, KMS would be called, and
  // only at issueLeafChainFromCSR's intermediatePem parse would the
  // misconfig surface. Failing fast keeps the surface tight.
  //
  // Pin the "auth never reached" invariant explicitly: an
  // assertion-throwing auth dep that the handler should never call.
  let authCalled = false;
  const { deps } = buildDeps({ intermediatePem: "" });
  const guardedDeps: RegisterDeps = {
    ...deps,
    getUserFromAuthHeader: () => {
      authCalled = true;
      throw new Error("auth should not be called when intermediate PEM is empty");
    },
  };

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    guardedDeps,
  );

  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 500);
  assertEquals(body.error, "Server misconfiguration");
  assertEquals(authCalled, false);
});

// =====================================================================
// Auth + AAL2 + rate limit
// =====================================================================

Deno.test("register-signing-key — missing JWT → 401", async () => {
  const { deps } = buildDeps();
  // Override the auth function to return null (no user resolved).
  const noAuthDeps: RegisterDeps = {
    ...deps,
    getUserFromAuthHeader: () => Promise.resolve(null),
  };

  const res = await handleRegister(
    buildRequest({ body: buildIosBody() }),
    noAuthDeps,
  );
  assertEquals(res.status, 401);
});

Deno.test("register-signing-key — AAL2 reject returned verbatim", async () => {
  // requireAal2IfMfaEnrolled returns a non-null Response → handler
  // surfaces it unchanged. The exact status/body comes from auth.ts;
  // here we assert pass-through.
  const aalReject = new Response(
    JSON.stringify({ error: "AAL2 required" }),
    { status: 403, headers: { "content-type": "application/json" } },
  );
  const { deps } = buildDeps({ aalReject });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  assertEquals(res.status, 403);
});

Deno.test("register-signing-key — rate limited → 429 with Retry-After", async () => {
  const { deps } = buildDeps({
    rateLimit: { ok: false, retryAfter: 1234 },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  assertEquals(res.status, 429);
  assertEquals(res.headers.get("Retry-After"), "1234");
});

// =====================================================================
// Body validation
// =====================================================================

Deno.test("register-signing-key — invalid JSON body → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    new Request("http://localhost/test", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": "Bearer x",
      },
      body: "{not-valid-json",
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid JSON body");
});

Deno.test("register-signing-key — missing publicKey → 400 Missing or malformed fields", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildIosBody({ publicKey: undefined }),
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Missing or malformed fields");
});

Deno.test("register-signing-key — invalid platform → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildIosBody({ platform: "windows-tpm" }),
    }),
    deps,
  );
  assertEquals(res.status, 400);
});

Deno.test("register-signing-key — oversized deviceLabel → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      // MAX_DEVICE_LABEL_CHARS = 64.
      body: buildIosBody({ deviceLabel: "x".repeat(65) }),
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Malformed deviceLabel");
});

Deno.test("register-signing-key — oversized CSR → 413", async () => {
  const { deps } = buildDeps();
  // MAX_CSR_PEM_CHARS = 2 * 1024.
  const oversized = "-".repeat(3000);
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildIosBody({ csr: oversized }),
    }),
    deps,
  );
  assertEquals(res.status, 413);
});

Deno.test("register-signing-key — CSR without BEGIN CERTIFICATE REQUEST → 400 Malformed csr", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildIosBody({
        csr: "-----BEGIN NEW CERTIFICATE REQUEST-----\nx\n-----END NEW CERTIFICATE REQUEST-----",
      }),
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Malformed csr");
});

// =====================================================================
// Enrollment challenge burn
// =====================================================================

Deno.test("register-signing-key — burn RPC reports unavailable → 400 Challenge expired or already used", async () => {
  const { deps } = buildDeps({
    burnResult: {
      data: null,
      error: {
        code: "P0001",
        message: "enrollment_challenge_unavailable: challenge unknown",
      },
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Challenge expired or already used");
});

Deno.test("register-signing-key — unexpected burn RPC error → 500 Server error", async () => {
  // A non-P0001 error code is a server bug; surface as 500.
  const { deps } = buildDeps({
    burnResult: {
      data: null,
      error: { code: "57P03", message: "cannot connect now" },
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 500);
  assertEquals(body.error, "Server error");
});

Deno.test("register-signing-key — burned key_version mismatches client claim → 400", async () => {
  // The RPC's scalar return is the key_version recorded at issue time.
  // Client claims v4 in the body but the burned row was issued for v5
  // → defense-in-depth reject.
  const { deps } = buildDeps({
    burnResult: { data: "5", error: null },
  });

  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildIosBody({ keyVersion: "4" }),
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Challenge / keyVersion mismatch");
});

// =====================================================================
// Base64 decode failures
// =====================================================================

Deno.test("register-signing-key — non-base64 publicKey → 400 Invalid attestation", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildIosBody({ publicKey: "!!!not-valid-base64!!!" }),
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid attestation");
});

// =====================================================================
// CSR validation (H13 — load-bearing)
// =====================================================================

Deno.test("register-signing-key — CSR parse failure → 400 Malformed csr", async () => {
  const { deps } = buildDeps({
    parseCSRFromPemImpl: () => {
      throw new Error("ASN.1 decode failed");
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Malformed csr");
});

Deno.test("register-signing-key — CSR signature verify failure → 400 Invalid csr signature", async () => {
  const { deps } = buildDeps({
    verifyCSRSignatureImpl: () => {
      throw new Error("ECDSA verify failed");
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid csr signature");
});

Deno.test(
  "register-signing-key — CSR SPKI != attested pubkey → 400 (load-bearing H13 binding check)",
  async () => {
    // The security-critical assertion: if the client posts attested
    // pubkey-A but a CSR carrying pubkey-B, the handler MUST reject.
    // Without this check, an attacker could chain a legitimate
    // attestation (proving they own SOME hardware key) to a CSR for
    // a key they actually possess off-device, then later impersonate
    // the attested device.
    const { deps } = buildDeps({
      csrSpkiBytes: ATTACKER_SE_PUBKEY_BYTES, // != FAKE_SE_PUBKEY_BYTES
    });

    const res = await handleRegister(
      buildRequest({
        bearer: "alice-jwt",
        body: buildIosBody({ publicKey: FAKE_SE_PUBKEY_B64 }),
      }),
      deps,
    );
    const { status, body } = await readJsonResponse<{ error: string }>(res);
    assertEquals(status, 400);
    assertEquals(body.error, "CSR public key does not match attested key");
  },
);

// =====================================================================
// Attestation validation
// =====================================================================

Deno.test("register-signing-key — iOS attestation rejected → 400 Invalid attestation", async () => {
  const { deps } = buildDeps({
    validateAppleAttestationImpl: () => {
      throw new AttestationError(
        "ATTESTATION_INVALID",
        "fmt is not apple-appattest",
      );
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid attestation");
});

Deno.test("register-signing-key — Android attestation rejected → 400", async () => {
  const { deps } = buildDeps({
    validateAndroidAttestationImpl: () => {
      throw new AttestationError("CHAIN_INVALID", "cert chain validation failed");
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildAndroidBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid attestation");
});

Deno.test("register-signing-key — Android attestation non-JSON → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildAndroidBody({ attestation: "not-json{" }),
    }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid attestation");
});

Deno.test("register-signing-key — Android attestation non-array → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleRegister(
    buildRequest({
      bearer: "alice-jwt",
      body: buildAndroidBody({
        attestation: JSON.stringify({ not: "an-array" }),
      }),
    }),
    deps,
  );
  assertEquals(res.status, 400);
});

// ---------- Android enrollment patch-gate --------------
//
// register-signing-key threads ANDROID_MIN_PATCH_LOOKBACK_MONTHS into the
// android validator and lets the validator's own osPatchLevel comparison
// throw ATTESTATION_STALE_PATCH. The handler then returns a distinct
// 400 with a `code: "ATTESTATION_STALE_PATCH"` field so the client can
// render an actionable "device security patches out of date" message.
// All other AttestationError codes stay generic ("Invalid attestation")
// so we don't leak which check failed to attackers tweaking inputs.

Deno.test("register-signing-key — Android patch-gate: fresh patch level → 200", async () => {
  let receivedMinPatch: number | undefined;
  const { deps } = buildDeps({
    validateAndroidAttestationImpl: (opts) => {
      // Capture the threshold the handler passes through. This pins the
      // wiring contract: when the validator decides to enforce the
      // gate, it sees a numeric YYYYMM threshold from the handler.
      receivedMinPatch = opts.minOsPatchLevel;
      return Promise.resolve({ osPatchLevel: 209901 });
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildAndroidBody() }),
    deps,
  );
  assertEquals(res.status, 200);
  assertExists(receivedMinPatch);
  // YYYYMM bounds — anything in this range is a sane rolling-window
  // threshold derived from "now - 12 months". A tighter bound is
  // calendar-dependent; we only need to pin that the handler isn't
  // passing through undefined or a degenerate value.
  if (receivedMinPatch < 200001 || receivedMinPatch > 210012) {
    throw new Error(`unexpected minOsPatchLevel ${receivedMinPatch}`);
  }
});

Deno.test("register-signing-key — Android patch-gate: stale patch level → 400 ATTESTATION_STALE_PATCH", async () => {
  const { deps } = buildDeps({
    validateAndroidAttestationImpl: (opts) => {
      // Simulate a device whose osPatchLevel is older than the threshold
      // the handler passes through. The real validator raises this
      // exact AttestationError; here we throw it directly to pin the
      // handler's surfacing behavior (status + body shape).
      const threshold = opts.minOsPatchLevel!;
      return Promise.reject(
        new AttestationError(
          "ATTESTATION_STALE_PATCH",
          `device osPatchLevel 202001 < required ${threshold} (YYYYMM)`,
        ),
      );
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildAndroidBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<
    { error: string; code?: string }
  >(res);
  assertEquals(status, 400);
  // Distinct UX-actionable payload — the client uses `code` to render
  // "your device is out of date" rather than the generic "device
  // attestation failed" copy.
  assertEquals(body.code, "ATTESTATION_STALE_PATCH");
  assertEquals(body.error, "Device security patch level out of date");
});

Deno.test("register-signing-key — Android patch-gate: missing osPatchLevel field → 400 ATTESTATION_STALE_PATCH", async () => {
  // A leaf cert without a TAG_OS_PATCH_LEVEL is treated as "older than
  // any threshold" (fail closed). The validator surfaces this as the
  // same AttestationError code, so the handler's UX path is the same.
  const { deps } = buildDeps({
    validateAndroidAttestationImpl: () =>
      Promise.reject(
        new AttestationError(
          "ATTESTATION_STALE_PATCH",
          "leaf cert has no osPatchLevel; cannot prove patch-gate",
        ),
      ),
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildAndroidBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<
    { error: string; code?: string }
  >(res);
  assertEquals(status, 400);
  assertEquals(body.code, "ATTESTATION_STALE_PATCH");
});

Deno.test("register-signing-key — Android: generic AttestationError stays masked (no code leak)", async () => {
  // CHAIN_INVALID and friends must NOT leak through `code`. Only
  // ATTESTATION_STALE_PATCH gets the special UX treatment.
  const { deps } = buildDeps({
    validateAndroidAttestationImpl: () => {
      throw new AttestationError("CHAIN_INVALID", "cert chain validation failed");
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildAndroidBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<
    { error: string; code?: string }
  >(res);
  assertEquals(status, 400);
  assertEquals(body.error, "Invalid attestation");
  // Belt-and-suspenders: a future regression that added `code` to the
  // generic branch would silently broaden the attacker's view of which
  // check failed. Assert absence.
  assertEquals(body.code, undefined);
});

// =====================================================================
// KMS + leaf issuance (failure paths)
// =====================================================================

Deno.test("register-signing-key — ensureIntermediateMatchesKms throws (algorithm mismatch) → 500 Issuance failed", async () => {
  const { deps } = buildDeps({
    ensureIntermediateImpl: () =>
      Promise.reject(
        new AttestationError(
          "KMS_ALGORITHM_MISMATCH",
          "Cloud KMS algorithm is RSA_SIGN_PSS_2048_SHA256, expected EC_SIGN_P256_SHA256",
        ),
      ),
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 500);
  assertEquals(body.error, "Issuance failed");
});

Deno.test("register-signing-key — ensureIntermediateMatchesKms throws (SPKI mismatch) → 500", async () => {
  const { deps } = buildDeps({
    ensureIntermediateImpl: () =>
      Promise.reject(
        new AttestationError(
          "KMS_INTERMEDIATE_MISMATCH",
          "REALREEL_INTERMEDIATE_CERT_PEM does not match Cloud KMS public key",
        ),
      ),
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  assertEquals(res.status, 500);
});

Deno.test("register-signing-key — issueLeafChainFromCSR throws → 500 Issuance failed", async () => {
  const { deps } = buildDeps({
    issueLeafChainImpl: () => Promise.reject(new Error("KMS sign network failure")),
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  assertEquals(res.status, 500);
});

// =====================================================================
// Persistence
// =====================================================================

Deno.test("register-signing-key — INSERT RPC returns unique_violation (23505) → 409 Key already registered", async () => {
  const { deps } = buildDeps({
    insertResult: {
      data: null,
      error: { code: "23505", message: "duplicate key" },
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 409);
  assertEquals(body.error, "Key already registered");
});

Deno.test("register-signing-key — INSERT RPC returns generic error → 500 Persist failed", async () => {
  const { deps } = buildDeps({
    insertResult: {
      data: null,
      error: { code: "42501", message: "permission denied" },
    },
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(status, 500);
  assertEquals(body.error, "Persist failed");
});

// =====================================================================
// Happy paths
// =====================================================================

Deno.test("register-signing-key — iOS happy path → 200 with leafChainPEM + keyId", async () => {
  // Sentinel-style App Attest credCert public key: tagged bytes so the
  // RPC-arg assertion below catches a regression that hardcoded a
  // constant instead of forwarding the validator's return value.
  const SENTINEL_APP_ATTEST_PUBKEY = new Uint8Array(65);
  SENTINEL_APP_ATTEST_PUBKEY[0] = 0x04;
  for (let i = 1; i < 65; i++) SENTINEL_APP_ATTEST_PUBKEY[i] = 0xa0 | (i & 0x0f);
  const expectedHex = "\\x" +
    Array.from(SENTINEL_APP_ATTEST_PUBKEY)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

  const { deps, mockClient } = buildDeps({
    validateAppleAttestationImpl: () =>
      Promise.resolve({ credCertPublicKey: SENTINEL_APP_ATTEST_PUBKEY }),
  });

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
    deps,
  );
  const { status, body } = await readJsonResponse<{
    ok: boolean;
    leafChainPEM: string;
    keyId: string;
  }>(res);
  assertEquals(status, 200);
  assertEquals(body.ok, true);
  assertExists(body.leafChainPEM);
  assertExists(body.keyId);

  // Two RPC calls happened in order: burn, then INSERT.
  assertEquals(mockClient.calls.length, 2);
  assertEquals(mockClient.calls[0].table, "rpc:consume_enrollment_challenge");
  assertEquals(mockClient.calls[1].table, "rpc:register_user_signing_key");

  // The INSERT RPC's args contain the iOS-only app_attest_public_key as
  // a non-null hex literal that matches what validateAppleAttestation
  // returned. A regression that hardcoded a constant pubkey (or pulled
  // it from the wrong field) would mismatch the sentinel and fail here.
  const insertArgs = mockClient.calls[1].values as Record<string, unknown>;
  assertEquals(insertArgs.p_platform, "ios");
  assertEquals(insertArgs.p_app_attest_public_key, expectedHex);
});

Deno.test("register-signing-key — Android happy path → 200 with leafChainPEM, app_attest_public_key NULL", async () => {
  const { deps, mockClient } = buildDeps();

  const res = await handleRegister(
    buildRequest({ bearer: "alice-jwt", body: buildAndroidBody() }),
    deps,
  );
  assertEquals(res.status, 200);

  // Android rows persist app_attest_public_key = NULL by design (no
  // App Attest equivalent on Android — Play Integrity uses different
  // primitives that don't surface a per-key pubkey).
  const insertArgs = mockClient.calls[1].values as Record<string, unknown>;
  assertEquals(insertArgs.p_platform, "android-strongbox");
  assertEquals(insertArgs.p_app_attest_public_key, null);
});

Deno.test(
  "register-signing-key — happy path passes burn RPC the correct (challenge, user_id) args",
  async () => {
    // Defense-in-depth: confirm the burn is keyed by the user from the
    // JWT, not by anything client-supplied. This test pins the wiring.
    const { deps, mockClient } = buildDeps({ userId: testUserId("alice") });

    await handleRegister(
      buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
      deps,
    );

    const burnCall = mockClient.calls[0];
    assertEquals(burnCall.op, "rpc");
    assertObjectMatch(burnCall.values as Record<string, unknown>, {
      p_challenge: VALID_CHALLENGE_B64,
      p_user_id: testUserId("alice"),
    });
  },
);

// =====================================================================
// buildCachedIntermediateCheck — internal helper isolation
// =====================================================================
//
// Verifies the cache contract documented on the helper: a successful
// check resolves once and subsequent calls return the same promise
// (no re-fetching KMS); a failing check clears the cache so the next
// call retries. Tests the helper directly rather than through
// handleRegister so the cache state is observable.

Deno.test("buildCachedIntermediateCheck — caches success across calls", async () => {
  let kmsCalls = 0;
  const check = buildCachedIntermediateCheck({
    // deno-lint-ignore no-explicit-any
    kmsGetPublicKey: () => {
      kmsCalls++;
      return Promise.resolve({
        spki: new Uint8Array([1, 2, 3]),
        algorithm: "EC_SIGN_P256_SHA256",
      });
    },
    // deno-lint-ignore no-explicit-any
    parseCertFromPem: (() => ({ __mock: true })) as any,
    extractSpkiDer: () => new Uint8Array([1, 2, 3]),
  });

  // deno-lint-ignore no-explicit-any
  await check({} as any, "intermediate-pem");
  // deno-lint-ignore no-explicit-any
  await check({} as any, "intermediate-pem");
  // deno-lint-ignore no-explicit-any
  await check({} as any, "intermediate-pem");

  assertEquals(kmsCalls, 1); // cached after first call
});

Deno.test("buildCachedIntermediateCheck — clears cache on KMS algorithm mismatch", async () => {
  let kmsCalls = 0;
  const check = buildCachedIntermediateCheck({
    kmsGetPublicKey: () => {
      kmsCalls++;
      return Promise.resolve({
        spki: new Uint8Array([1, 2, 3]),
        algorithm: "RSA_SIGN_PSS_2048_SHA256", // wrong algorithm
      });
    },
    // deno-lint-ignore no-explicit-any
    parseCertFromPem: (() => ({ __mock: true })) as any,
    extractSpkiDer: () => new Uint8Array([1, 2, 3]),
  });

  // deno-lint-ignore no-explicit-any
  await assertRejects(() => check({} as any, "intermediate-pem"), AttestationError);
  // deno-lint-ignore no-explicit-any
  await assertRejects(() => check({} as any, "intermediate-pem"), AttestationError);

  // Both calls hit KMS — the failing call clears the cache so a
  // subsequent fix-and-retry doesn't need a process restart.
  assertEquals(kmsCalls, 2);
});

Deno.test("buildCachedIntermediateCheck — clears cache on SPKI mismatch", async () => {
  let kmsCalls = 0;
  const check = buildCachedIntermediateCheck({
    kmsGetPublicKey: () => {
      kmsCalls++;
      return Promise.resolve({
        spki: new Uint8Array([1, 2, 3]),
        algorithm: "EC_SIGN_P256_SHA256",
      });
    },
    // deno-lint-ignore no-explicit-any
    parseCertFromPem: (() => ({ __mock: true })) as any,
    extractSpkiDer: () => new Uint8Array([9, 9, 9]), // != KMS spki
  });

  // deno-lint-ignore no-explicit-any
  await assertRejects(() => check({} as any, "intermediate-pem"), AttestationError);
  // deno-lint-ignore no-explicit-any
  await assertRejects(() => check({} as any, "intermediate-pem"), AttestationError);
  assertEquals(kmsCalls, 2);
});

// =====================================================================
// supersedeKeyId — re-enroll plumbing
// =====================================================================
//
// The Devices screen and the future auto-rotate-near-expiry flow pass
// the prior canonical key_id so the RPC sets superseded_at on the prior
// row in the same transaction as the INSERT. These tests pin:
//   - validation (length bound, empty-string reject, null is accepted as
//     a no-supersede signal),
//   - happy-path forwarding into p_supersede_key_id,
//   - the omit-on-undefined contract (initial enrollment must NOT set
//     p_supersede_key_id, lest the RPC interpret a stale local value).
//
// The RPC's cross-user guard + 0-row RAISE NOTICE are exercised in the
// migration's SQL — not unit-tested here (the mocked RPC client doesn't
// run the function body).

Deno.test(
  "register-signing-key — empty-string supersedeKeyId → 400 Malformed",
  async () => {
    const { deps } = buildDeps();
    const res = await handleRegister(
      buildRequest({
        bearer: "alice-jwt",
        body: buildIosBody({ supersedeKeyId: "" }),
      }),
      deps,
    );
    const { status, body } = await readJsonResponse<{ error: string }>(res);
    assertEquals(status, 400);
    assertEquals(body.error, "Malformed supersedeKeyId");
  },
);

Deno.test(
  "register-signing-key — oversized supersedeKeyId → 400 Malformed",
  async () => {
    const { deps } = buildDeps();
    const oversized = "a".repeat(129); // MAX_SIGNING_KEY_ID_CHARS = 128
    const res = await handleRegister(
      buildRequest({
        bearer: "alice-jwt",
        body: buildIosBody({ supersedeKeyId: oversized }),
      }),
      deps,
    );
    const { status, body } = await readJsonResponse<{ error: string }>(res);
    assertEquals(status, 400);
    assertEquals(body.error, "Malformed supersedeKeyId");
  },
);

Deno.test(
  "register-signing-key — supersedeKeyId forwarded into RPC p_supersede_key_id",
  async () => {
    const { deps, mockClient } = buildDeps();
    const SENTINEL_OLD_KEY_ID = "sha256-of-prior-spki-base64====";

    const res = await handleRegister(
      buildRequest({
        bearer: "alice-jwt",
        body: buildIosBody({ supersedeKeyId: SENTINEL_OLD_KEY_ID }),
      }),
      deps,
    );
    assertEquals(res.status, 200);

    // The INSERT RPC's args should carry the supersede key_id verbatim;
    // the RPC itself (in plpgsql) does the user_id-guarded UPDATE.
    const insertArgs = mockClient.calls[1].values as Record<string, unknown>;
    assertEquals(insertArgs.p_supersede_key_id, SENTINEL_OLD_KEY_ID);
  },
);

Deno.test(
  "register-signing-key — initial enrollment (no supersedeKeyId) → RPC receives null",
  async () => {
    const { deps, mockClient } = buildDeps();

    const res = await handleRegister(
      buildRequest({ bearer: "alice-jwt", body: buildIosBody() }),
      deps,
    );
    assertEquals(res.status, 200);

    // Initial-enrollment path: the body omits supersedeKeyId entirely.
    // The edge function should pass NULL to the RPC so the plpgsql
    // "IF p_supersede_key_id IS NOT NULL" guard short-circuits and no
    // UPDATE is attempted. A regression that forwarded a stale local
    // value (e.g., reading from a previous request's variable) would
    // surface here.
    const insertArgs = mockClient.calls[1].values as Record<string, unknown>;
    assertEquals(insertArgs.p_supersede_key_id, null);
  },
);

Deno.test(
  "register-signing-key — explicit null supersedeKeyId behaves like undefined",
  async () => {
    const { deps, mockClient } = buildDeps();

    const res = await handleRegister(
      buildRequest({
        bearer: "alice-jwt",
        body: buildIosBody({ supersedeKeyId: null }),
      }),
      deps,
    );
    assertEquals(res.status, 200);
    const insertArgs = mockClient.calls[1].values as Record<string, unknown>;
    assertEquals(insertArgs.p_supersede_key_id, null);
  },
);
