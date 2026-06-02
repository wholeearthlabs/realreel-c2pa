// Actions-allowlist + structural policy enforcement.
//
// Tests the policy layered on top of c2pa-rs's cryptographic checks:
//   - RealReel Stage 1 (parent): no ingredients, only c2pa.created.
//   - RealReel Stage 2 (active): exactly one parentOf ingredient,
//     actions ⊆ upload allowlist.
//
// One real-world test: the user's Google-Photos-edited Pixel JPEG
// (pixel-edited.jpg) gets rejected end-to-end. The rest are synthetic
// manifests against verifyRealReel directly so each rejection path is
// exercised in isolation.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

vi.mock("../src/db.js", () => {
  const lookupSigningKeyRevocation = vi.fn();
  // attestationRequired test cases happy-path through the nonce burn, so
  // the policy tests need the consume RPC mocked. The non-attestation
  // tests reset this between cases via beforeEach.
  const consumeAndRecordAttestation = vi.fn().mockResolvedValue(undefined);
  const pingDb = vi.fn();
  return {
    lookupSigningKeyRevocation,
    consumeAndRecordAttestation,
    pingDb,
    initDb: vi.fn(),
    closeDbPool: vi.fn(),
    // The default VerifierDatastore the profile / attestation consumers fall
    // back to when no adapter is injected. Delegates to the same spies so the
    // existing `vi.mocked(lookupSigningKeyRevocation)` assertions stay valid.
    postgresAdapter: {
      lookup: lookupSigningKeyRevocation,
      burn: consumeAndRecordAttestation,
      ping: pingDb,
    },
  };
});

import { verify } from "../src/verify.js";
import { verifyRealReel } from "../src/profiles/realreel.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { lookupSigningKeyRevocation } from "../src/db.js";
import { VerifyErrorCode } from "../src/errors.js";

const trustSourcesPath = resolve(import.meta.dirname, "../trust-sources.yaml");
const trustConfig = await loadTrustConfig(trustSourcesPath);

const FIXTURE_USER_ID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
const STAGE_1_SERIAL = "1111111111";
const STAGE_2_SERIAL = "2222222222";

beforeEach(() => {
  vi.mocked(lookupSigningKeyRevocation).mockReset();
});

// ---------------------------------------------------------------
// Real fixture: Google-Photos-edited Pixel JPEG
// ---------------------------------------------------------------

describe("Defense-layer smoke test — real edited Pixel JPEG", () => {
  // This is a SMOKE test for the multi-layer defense, not a test of
  // the policy code path in isolation. The Google-Photos-edited JPEG
  // has THREE possible rejection layers, in order of which fires first:
  //
  //   1. UNTRUSTED_ISSUER — the active manifest is signed under
  //      issuer "Google LLC" but common_name "Google Photos" (a
  //      separate Google C2PA program from Pixel). The dispatcher's
  //      commonNameMatch pin on the Pixel entry — "Pixel Camera" —
  //      refuses to route Google Photos manifests to the Pixel
  //      profile. This is the H6 fix's exact purpose: stop misrouting
  //      sibling Google programs through Pixel.
  //   2. MANIFEST_MALFORMED — if the dispatcher somehow accepted it,
  //      c2pa-rs's own `assertion.ingredient.malformed` validation
  //      would catch Google Photos' incomplete v3 ingredient assertion.
  //   3. SIGNATURE_INVALID — if both of the above somehow softened,
  //      our profile policy (ingredients-empty for the wrap-parent path)
  //      would catch it.
  //
  // Today layer 1 fires (post-H6). Pre-H6 it was layer 2. If Google ever
  // adds a "Google Photos" entry to TRUSTED_ISSUERS, this test's first
  // bucket goes away and layer 2 takes over again. All three are correct
  // rejections — the test asserts ANY of them, not a specific one.
  //
  // The realreel policy path itself is exercised by the synthetic
  // RealReel tests below — those drive ManifestStoreShape values directly
  // into verifyRealReel, bypassing c2pa-rs's validation. They carry the
  // load for actual policy coverage.
  it("rejects end-to-end with code from one of three defense layers", async () => {
    const editedBytes = await readFile(
      resolve(import.meta.dirname, "fixtures/pixel-edited.jpg"),
    );
    let caught: unknown;
    try {
      await verify({
        assetBytes: editedBytes,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_USER_ID,
        trustConfig,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeDefined();
    const code = (caught as { code?: string })?.code;
    // Log which layer fired — useful for future diagnostic when this
    // test eventually changes behavior.
    console.log(
      `[defense-layer-smoke] real edited Pixel rejected via ${code} layer`,
    );
    expect([
      VerifyErrorCode.UNTRUSTED_ISSUER, // dispatcher CN pin (current, post-H6)
      VerifyErrorCode.MANIFEST_MALFORMED, // c2pa-rs validation (pre-H6 / fallback)
      VerifyErrorCode.SIGNATURE_INVALID, // our policy (if both above soften)
    ]).toContain(code);
  });
});

// ---------------------------------------------------------------
// Synthetic RealReel Stage 1 policy
// ---------------------------------------------------------------

type StageAttestation =
  | { kind: "app_attest"; data?: Record<string, string> }
  | { kind: "play_integrity"; data?: Record<string, string> };

const DEFAULT_APP_ATTEST_DATA = {
  keyId: "appAttestKey-base64==",
  challenge: "challengeNonce-base64==",
  assertion: "assertionCbor-base64==",
  platform: "ios",
};

const DEFAULT_PLAY_INTEGRITY_DATA = {
  challenge: "challengeNonce-base64==",
  // 400-char opaque base64url-alphabet filler that clears the
  // structural validator's MIN_TOKEN_LENGTH=300 bound. Standard
  // Integrity API tokens are opaque single-segment strings (no dot
  // separators in observed output); see attestation-play-integrity.test.ts
  // VALID_TOKEN for the empirical pinning + 2026-05-18 fix history.
  token: "A".repeat(400),
  platform: "android",
};

function makeRealReelStore(opts: {
  stage1?: {
    ingredients?: Array<{ active_manifest?: string; relationship?: string }>;
    actions?: string[];
    attestation?: StageAttestation | null;
  };
  stage2?: {
    ingredients?: Array<{ active_manifest?: string; relationship?: string }>;
    actions?: string[];
    attestation?: StageAttestation | null;
  };
}): unknown {
  // Defaults match the canonical RealReel manifest shape (verified
  // against __tests__/fixtures/realreel-uploaded.jpg, Pixel 10 capture):
  //   Stage 1: [c2pa.created]
  //   Stage 2: [c2pa.opened, c2pa.resized, c2pa.transcoded]
  // Tests override either array to exercise rejection paths.
  const stage1Actions = opts.stage1?.actions ?? ["c2pa.created"];
  const stage2Actions = opts.stage2?.actions ?? [
    "c2pa.opened",
    "c2pa.resized",
    "c2pa.transcoded",
  ];
  const stage2Ingredients = opts.stage2?.ingredients ?? [
    { active_manifest: "urn:test:stage1", relationship: "parentOf" },
  ];
  const stage1Assertions: Array<{ label: string; data: unknown }> = [
    {
      label: "c2pa.actions.v2",
      data: { actions: stage1Actions.map((action) => ({ action })) },
    },
  ];
  appendAttestationAssertion(stage1Assertions, opts.stage1?.attestation);

  const stage2Assertions: Array<{ label: string; data: unknown }> = [
    {
      label: "c2pa.actions.v2",
      data: { actions: stage2Actions.map((action) => ({ action })) },
    },
  ];
  appendAttestationAssertion(stage2Assertions, opts.stage2?.attestation);

  return {
    active_manifest: "urn:test:stage2",
    manifests: {
      "urn:test:stage1": {
        signature_info: { cert_serial_number: STAGE_1_SERIAL },
        ingredients: opts.stage1?.ingredients ?? [],
        assertions: stage1Assertions,
      },
      "urn:test:stage2": {
        signature_info: { cert_serial_number: STAGE_2_SERIAL },
        ingredients: stage2Ingredients,
        assertions: stage2Assertions,
      },
    },
    validation_status: [],
  };
}

function appendAttestationAssertion(
  target: Array<{ label: string; data: unknown }>,
  attestation: StageAttestation | null | undefined,
): void {
  if (!attestation) return;
  if (attestation.kind === "app_attest") {
    target.push({
      label: "org.realreel.app_attest",
      data: attestation.data ?? DEFAULT_APP_ATTEST_DATA,
    });
  } else {
    target.push({
      label: "org.realreel.play_integrity",
      data: attestation.data ?? DEFAULT_PLAY_INTEGRITY_DATA,
    });
  }
}

function stubBothKeysValid(): void {
  vi.mocked(lookupSigningKeyRevocation)
    .mockResolvedValueOnce({
      // Same key_id on both stages — the policy tests are not about
      // the capturer-uploader bind, so we use the production-shape
      // case (one hardware key per device, signs both stages).
      key_id: "device-hw-key",
      user_id: FIXTURE_USER_ID,
      revoked_at: null,
      cert_serial_number: STAGE_1_SERIAL,
      platform: "ios",
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    })
    .mockResolvedValueOnce({
      key_id: "device-hw-key",
      user_id: FIXTURE_USER_ID,
      revoked_at: null,
      cert_serial_number: STAGE_2_SERIAL,
      platform: "ios",
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    });
}

describe("Policy — RealReel Stage 1 (parent / capture)", () => {
  it("baseline: clean Stage 1 + Stage 2 passes", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({});
    const result = await verifyRealReel(store, "realreel");
    expect(result.validation_state).toBe("trusted");
  });

  it("rejects: Stage 1 has ingredients (claims to be derived)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage1: {
        ingredients: [
          { active_manifest: "urn:test:ancestor", relationship: "parentOf" },
        ],
      },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("Stage 1 must be a fresh capture"),
    });
  });

  it("rejects: Stage 1 has a disallowed action (c2pa.adjustedColor)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage1: { actions: ["c2pa.created", "c2pa.adjustedColor"] },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("c2pa.adjustedColor"),
    });
  });

  it("rejects: Stage 1 has a different disallowed action (c2pa.filtered)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage1: { actions: ["c2pa.filtered"] },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
    });
  });

  it("rejects: Stage 1 contains AI-generation action", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage1: { actions: ["c2pa.ai_generated"] },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
    });
  });
});

describe("Policy — RealReel Stage 2 (active / upload)", () => {
  it("rejects: Stage 2 has zero ingredients (looks like a single-stage)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({ stage2: { ingredients: [] } });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("Stage 2 must have exactly one ingredient"),
    });
  });

  it("rejects: Stage 2 has two ingredients (composite or extra derivation)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage2: {
        ingredients: [
          { active_manifest: "urn:test:stage1", relationship: "parentOf" },
          { active_manifest: "urn:test:extra", relationship: "componentOf" },
        ],
      },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("exactly one ingredient"),
    });
  });

  it("rejects: Stage 2 ingredient relationship is componentOf, not parentOf", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage2: {
        ingredients: [
          { active_manifest: "urn:test:stage1", relationship: "componentOf" },
        ],
      },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("'parentOf'"),
    });
  });

  it("rejects: Stage 2 ingredient relationship is missing entirely", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage2: {
        ingredients: [
          { active_manifest: "urn:test:stage1" }, // no relationship
        ],
      },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
    });
  });

  it("rejects: Stage 2 has disallowed action (c2pa.adjustedColor)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage2: { actions: ["c2pa.opened", "c2pa.adjustedColor"] },
    });
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("c2pa.adjustedColor"),
    });
  });

  it("accepts: Stage 2 with the canonical upload actions (c2pa.opened, c2pa.resized, c2pa.transcoded)", async () => {
    stubBothKeysValid();
    const store = makeRealReelStore({
      stage2: { actions: ["c2pa.opened", "c2pa.resized", "c2pa.transcoded"] },
    });
    const result = await verifyRealReel(store, "realreel");
    expect(result.validation_state).toBe("trusted");
  });

  // ---- Roundtrip: every Stage2Action variant must be accepted ----
  //
  // Tripwire for drift between the verifier's allowlist and the JS
  // bridge's Stage2Action union (native/index.ts). If
  // someone adds a new variant to Stage2Action without updating
  // REALREEL_UPLOAD_ALLOWED_ACTIONS, this test fails — and the same
  // failure surfaces in CI before any user upload hits the verifier.
  //
  // The list is maintained alongside Stage2Action by hand (verifier
  // is intentionally self-contained — no cross-package import). When
  // you add a new Stage2Action variant, add the action name here AND
  // to REALREEL_UPLOAD_ALLOWED_ACTIONS.
  describe("Roundtrip: every Stage2Action variant accepted", () => {
    const STAGE2_USER_ACTIONS = [
      "c2pa.rotated",
      "c2pa.resized",
      "c2pa.transcoded",
      "c2pa.cropped",
      "c2pa.trimmed",
      "c2pa.redacted",
    ];

    for (const action of STAGE2_USER_ACTIONS) {
      it(`accepts Stage 2 with action ${action} (plus auto-injected c2pa.opened)`, async () => {
        stubBothKeysValid();
        const store = makeRealReelStore({
          stage2: { actions: ["c2pa.opened", action] },
        });
        const result = await verifyRealReel(store, "realreel");
        expect(result.validation_state).toBe("trusted");
      });
    }
  });
});

// ---------------------------------------------------------------
// Stage-2 upload-time attestation: require-mode + per-platform routing
// ---------------------------------------------------------------
//
// attestationRequired=true is the production posture: the Stage 2
// signing-key platform determines which envelope is mandatory. Missing
// the platform-matched envelope → ATTESTATION_MISSING. Cross-platform
// envelope/key combinations always reject (regardless of mode) since
// they're never produced by a correctly built client. (Stage 1 carries
// no device-health attestation — enrollment-only trust.)

function stubBothKeysWithPlatform(
  stage1Platform: string,
  stage2Platform: string,
): void {
  vi.mocked(lookupSigningKeyRevocation)
    .mockResolvedValueOnce({
      // Same key_id on both stages — the policy tests are not about
      // the capturer-uploader bind, so we use the production-shape
      // case (one hardware key per device, signs both stages).
      key_id: "device-hw-key",
      user_id: FIXTURE_USER_ID,
      revoked_at: null,
      cert_serial_number: STAGE_1_SERIAL,
      platform: stage1Platform,
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    })
    .mockResolvedValueOnce({
      key_id: "device-hw-key",
      user_id: FIXTURE_USER_ID,
      revoked_at: null,
      cert_serial_number: STAGE_2_SERIAL,
      platform: stage2Platform,
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    });
}

describe("Policy — attestationRequired strict mode", () => {
  it("rejects iOS app_attest in required mode when the enrollment-stored pubkey is missing (fail-closed)", async () => {
    // The verifier MUST verify the App Attest assertion against the
    // enrollment-stored credCert pubkey. stubBothKeysWithPlatform sets both
    // pubkey columns null (a legacy pre-credCert iOS row), so cryptoInputsForRow
    // returns null — and we reject rather than fall back to the nonce-only
    // path that would bypass the stored-pubkey check (the warn-and-pass
    // fallback was removed entirely). Reaching ATTESTATION_INVALID (not
    // ATTESTATION_MISSING) also proves dispatch routed to the app_attest branch.
    stubBothKeysWithPlatform("ios", "ios");
    const store = makeRealReelStore({
      stage1: { attestation: { kind: "app_attest" } },
      stage2: { attestation: { kind: "app_attest" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({ code: VerifyErrorCode.ATTESTATION_INVALID });
  });

  it("rejects iOS app_attest with a missing stored pubkey even in LENIENT mode (no nonce-only fallback)", async () => {
    // The missing-pubkey reject is NOT gated on attestationRequired: App
    // Attest verification is local ECDSA, so the warn-and-pass fallback was
    // removed for both modes. A present app_attest envelope is dispatched +
    // verified even in lenient dev (leniency only tolerates an ABSENT
    // envelope), so a null-pubkey row rejects here too.
    stubBothKeysWithPlatform("ios", "ios");
    const store = makeRealReelStore({
      stage2: { attestation: { kind: "app_attest" } },
    });
    // attestationRequired omitted → lenient (false).
    await expect(
      verifyRealReel(store, "realreel"),
    ).rejects.toMatchObject({ code: VerifyErrorCode.ATTESTATION_INVALID });
  });

  it("accepts android manifest carrying play_integrity on Stage 2", async () => {
    stubBothKeysWithPlatform("android-strongbox", "android-strongbox");
    const store = makeRealReelStore({
      stage2: { attestation: { kind: "play_integrity" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).resolves.toBeDefined();
  });

  it("rejects iOS-signed manifest missing app_attest on Stage 2 as ATTESTATION_MISSING", async () => {
    stubBothKeysWithPlatform("ios", "ios");
    const store = makeRealReelStore({
      // Stage 1 lenient even in strict mode — Stage 2 carries the
      // load-bearing require check.
      stage1: { attestation: { kind: "app_attest" } },
      stage2: {},
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_MISSING,
    });
  });

  it("rejects android-signed manifest missing play_integrity on Stage 2 as ATTESTATION_MISSING", async () => {
    stubBothKeysWithPlatform("android-strongbox", "android-strongbox");
    const store = makeRealReelStore({
      stage1: { attestation: { kind: "play_integrity" } },
      stage2: {},
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_MISSING,
    });
  });

  it("accepts a manifest with no Stage 1 envelope (enrollment-only — Stage 1 ignored)", async () => {
    // Stage 1 device-health was dropped (enrollment-only trust): a native
    // capture with no app_attest/play_integrity on Stage 1 is fine. The
    // load-bearing require check is Stage 2's attestation, present here. Uses
    // Android so the required-mode happy path doesn't need a stored App
    // Attest pubkey (Play Integrity has no stored-pubkey equivalent); the
    // iOS missing-pubkey path is covered by the fail-closed test above.
    stubBothKeysWithPlatform("android-strongbox", "android-strongbox");
    const store = makeRealReelStore({
      stage1: {},
      stage2: { attestation: { kind: "play_integrity" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).resolves.toBeDefined();
  });

  it("rejects unknown platform as ATTESTATION_INVALID (defensive)", async () => {
    stubBothKeysWithPlatform("future-platform", "future-platform");
    const store = makeRealReelStore({
      stage1: { attestation: { kind: "app_attest" } },
      stage2: { attestation: { kind: "app_attest" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_INVALID,
    });
  });

  it("rejects when iOS-platform key carries play_integrity (cross-platform mismatch)", async () => {
    stubBothKeysWithPlatform("ios", "ios");
    const store = makeRealReelStore({
      stage1: { attestation: { kind: "play_integrity" } },
      stage2: { attestation: { kind: "play_integrity" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_INVALID,
    });
  });

  it("rejects when android-platform key carries app_attest (cross-platform mismatch)", async () => {
    stubBothKeysWithPlatform("android-strongbox", "android-strongbox");
    const store = makeRealReelStore({
      stage1: { attestation: { kind: "app_attest" } },
      stage2: { attestation: { kind: "app_attest" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_INVALID,
    });
  });

  it("rejects when Stage 2 carries BOTH envelopes (manifest stuffing)", async () => {
    stubBothKeysWithPlatform("ios", "ios");
    // Manually construct a store with both attestation assertions on Stage 2
    // — the makeRealReelStore helper takes one or the other, so we shadow it
    // here with a direct object literal. resolveStageEnvelope rejects a
    // stage carrying both before any nonce is burned.
    const store = {
      active_manifest: "urn:test:stage2",
      manifests: {
        "urn:test:stage1": {
          signature_info: { cert_serial_number: STAGE_1_SERIAL },
          ingredients: [],
          assertions: [
            { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } },
          ],
        },
        "urn:test:stage2": {
          signature_info: { cert_serial_number: STAGE_2_SERIAL },
          ingredients: [{ active_manifest: "urn:test:stage1", relationship: "parentOf" }],
          assertions: [
            {
              label: "c2pa.actions.v2",
              data: { actions: [{ action: "c2pa.opened" }, { action: "c2pa.resized" }] },
            },
            { label: "org.realreel.app_attest", data: DEFAULT_APP_ATTEST_DATA },
            { label: "org.realreel.play_integrity", data: DEFAULT_PLAY_INTEGRITY_DATA },
          ],
        },
      },
      validation_status: [],
    };
    await expect(
      verifyRealReel(store, "realreel", undefined, true),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_INVALID,
    });
  });

  // Lenient-mode (attestationRequired=false or omitted) regression guard:
  // missing envelope must continue to pass. This is what local dev relies
  // on so the verifier boots and accepts unattested manifests without
  // requiring real Google credentials.

  it("lenient mode (default): missing envelope is tolerated", async () => {
    stubBothKeysWithPlatform("ios", "ios");
    const store = makeRealReelStore({ stage1: {}, stage2: {} });
    // attestationRequired argument omitted → defaults to false.
    await expect(
      verifyRealReel(store, "realreel"),
    ).resolves.toBeDefined();
  });

  it("lenient mode: cross-platform mismatch STILL rejected (mode-independent)", async () => {
    // The cross-platform check runs regardless of attestationRequired —
    // an inconsistent shape is always a sign of a misrouted token or
    // tampered build, never a normal-but-degraded state.
    stubBothKeysWithPlatform("ios", "ios");
    const store = makeRealReelStore({
      stage1: { attestation: { kind: "play_integrity" } },
      stage2: { attestation: { kind: "play_integrity" } },
    });
    await expect(
      verifyRealReel(store, "realreel", undefined, false),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.ATTESTATION_INVALID,
    });
  });
});

// ---------------------------------------------------------------
// Interposed timestamp Update Manifest walk-through
// ---------------------------------------------------------------
//
// A once-offline capture that's later TSA-drained gets an Update Manifest
// interposed between Stage-2 (upload) and Stage-1 (capture):
//   active(Stage-2) → parentOf → Update → parentOf → Stage-1 (capture)
// The Update Manifest carries a c2pa.time-stamp assertion over Stage-1's
// signature. verifyRealReel must walk PAST it to run the Stage-1 gates on the
// real capture (not on the Update Manifest, which would fail the fresh-capture
// rule). These synthetic stores drive that walk directly; the c2pa-rs-level
// timestamp-trust validation is covered on-device against a real drained
// fixture (see "Trusted timestamps and offline verifiability" in
// TRUST_ARCHITECTURE.md).

const UPDATE_SERIAL = "3333333333";

/** Build a drained-chain store: Stage-2 → Update → Stage-1. Knobs let each
 *  test break exactly one link. */
function makeDrainedStore(opts?: {
  /** Actions on the interposed Update Manifest. Default [c2pa.opened] — the
   *  real on-device shape: c2pa-rs auto-injects c2pa.opened when it
   *  incorporates the Stage-1 parent (confirmed 2026-05-28). */
  updateActions?: string[];
  /** Whether the Update Manifest carries the c2pa.time-stamp assertion.
   *  Default true (that's what marks it as an interposed Update Manifest). */
  updateHasTimestamp?: boolean;
  /** Where the Update Manifest's parentOf points. Default the real capture;
   *  override to a missing label to exercise the dangling-ref path. */
  updateParentLabel?: string;
  /** Ingredients on the true capture. Default [] (a fresh capture). */
  captureIngredients?: Array<{ active_manifest?: string; relationship?: string }>;
  /** Actions on the true capture. Default [c2pa.created]. */
  captureActions?: string[];
}): unknown {
  const updateAssertions: Array<{ label: string; data: unknown }> = [
    {
      label: "c2pa.actions.v2",
      data: {
        actions: (opts?.updateActions ?? ["c2pa.opened"]).map((action) => ({ action })),
      },
    },
  ];
  if (opts?.updateHasTimestamp ?? true) {
    updateAssertions.push({
      label: "c2pa.time-stamp",
      // HashMap<manifest_urn, token_b64> — keyed by the stamped Stage-1.
      data: { "urn:test:stage1": "ZmFrZS10c2EtdG9rZW4=" },
    });
  }

  return {
    active_manifest: "urn:test:stage2",
    manifests: {
      "urn:test:stage1": {
        signature_info: { cert_serial_number: STAGE_1_SERIAL },
        ingredients: opts?.captureIngredients ?? [],
        assertions: [
          {
            label: "c2pa.actions.v2",
            data: {
              actions: (opts?.captureActions ?? ["c2pa.created"]).map((action) => ({
                action,
              })),
            },
          },
        ],
      },
      "urn:test:update": {
        signature_info: { cert_serial_number: UPDATE_SERIAL },
        ingredients: [
          {
            active_manifest: opts?.updateParentLabel ?? "urn:test:stage1",
            relationship: "parentOf",
          },
        ],
        assertions: updateAssertions,
      },
      "urn:test:stage2": {
        signature_info: { cert_serial_number: STAGE_2_SERIAL },
        ingredients: [
          { active_manifest: "urn:test:update", relationship: "parentOf" },
        ],
        assertions: [
          {
            label: "c2pa.actions.v2",
            data: {
              actions: ["c2pa.opened", "c2pa.resized"].map((action) => ({ action })),
            },
          },
        ],
      },
    },
    validation_status: [],
  };
}

describe("Policy — TSA Update Manifest walk-through", () => {
  it("happy path: a drained Stage-2 → Update → Stage-1 chain verifies trusted", async () => {
    // Only the capture + Stage-2 keys are looked up (the walk is purely
    // structural — the Update Manifest gets no DB lookup), in that order.
    stubBothKeysValid();
    const store = makeDrainedStore();
    const result = await verifyRealReel(store, "realreel");
    expect(result.validation_state).toBe("trusted");
    // The Update Manifest is preserved in the sanitized store (the UI walks it).
    expect(result.manifests["urn:test:update"]).toBeDefined();
  });

  it("does NOT walk past a genuine edited parent (no timestamp) — rejects it as the capture", async () => {
    // The inverse of the happy path: Stage-2's parent is a real EDITED manifest
    // (parentOf ingredient + c2pa.resized, NO c2pa.time-stamp) — e.g. a
    // downloaded-then-re-uploaded asset, or an external editor's re-sign. It
    // must NOT be mistaken for an interposed timestamp Update Manifest and
    // walked past; it IS the (illegitimate) Stage-1 and must be rejected. The
    // fresh-capture gate fires on it (it has an ingredient) → SIGNATURE_INVALID.
    const store = makeDrainedStore({
      updateHasTimestamp: false, // ← no c2pa.time-stamp → not an Update Manifest
      updateActions: ["c2pa.opened", "c2pa.resized"], // a real edit
    });
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("fresh capture"),
    });
  });

  it("runs the fresh-capture gate on the TRUE capture, not the Update Manifest", async () => {
    // The capture below the Update Manifest is itself derived (has an
    // ingredient) → it's not a fresh capture → reject. Proves the Stage-1
    // gate is redirected through the walk rather than hitting the Update
    // Manifest (which legitimately HAS an ingredient).
    const store = makeDrainedStore({
      captureIngredients: [
        { active_manifest: "urn:test:ancestor", relationship: "parentOf" },
      ],
    });
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("fresh capture"),
    });
  });

  it("runs the capture action allowlist on the TRUE capture", async () => {
    const store = makeDrainedStore({ captureActions: ["c2pa.created", "c2pa.resized"] });
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("Stage 1"),
    });
  });

  it("applies the Stage-1 revocation denylist to the TRUE capture key", async () => {
    // First (and only) lookup is the capture serial — return it revoked.
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValueOnce({
      key_id: "device-hw-key",
      user_id: FIXTURE_USER_ID,
      revoked_at: "2026-05-01T00:00:00.000Z",
      cert_serial_number: STAGE_1_SERIAL,
      platform: "ios",
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    });
    const store = makeDrainedStore();
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.KEY_REVOKED,
    });
  });

  it("allows the auto-injected c2pa.opened on the Update Manifest", async () => {
    // The real on-device shape — c2pa-rs injects c2pa.opened when it
    // incorporates the parent. Must NOT trip the Update-Manifest allowlist.
    stubBothKeysValid();
    const store = makeDrainedStore({ updateActions: ["c2pa.opened"] });
    const result = await verifyRealReel(store, "realreel");
    expect(result.validation_state).toBe("trusted");
  });

  it("rejects an Update Manifest carrying an editorial action (no edit smuggling)", async () => {
    // Realistic shape: c2pa.opened (allowed) PLUS a smuggled edit (rejected).
    const store = makeDrainedStore({ updateActions: ["c2pa.opened", "c2pa.resized"] });
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("Update Manifest"),
    });
  });

  it("rejects when the Update Manifest's parent ingredient is dangling", async () => {
    const store = makeDrainedStore({ updateParentLabel: "urn:test:does-not-exist" });
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.MANIFEST_MALFORMED,
    });
  });

  it("rejects a chain of interposed Update Manifests deeper than the cap", async () => {
    // Build active → u1 → u2 → ... → u6 → stage1, each uN an Update Manifest.
    const manifests: Record<string, unknown> = {
      "urn:test:stage1": {
        signature_info: { cert_serial_number: STAGE_1_SERIAL },
        ingredients: [],
        assertions: [
          { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } },
        ],
      },
    };
    const DEPTH = 6;
    for (let i = DEPTH; i >= 1; i--) {
      const child = i === DEPTH ? "urn:test:stage1" : `urn:test:u${i + 1}`;
      manifests[`urn:test:u${i}`] = {
        signature_info: { cert_serial_number: `u${i}` },
        ingredients: [{ active_manifest: child, relationship: "parentOf" }],
        assertions: [
          { label: "c2pa.actions.v2", data: { actions: [] } },
          { label: "c2pa.time-stamp", data: { [child]: "ZmFrZQ==" } },
        ],
      };
    }
    manifests["urn:test:stage2"] = {
      signature_info: { cert_serial_number: STAGE_2_SERIAL },
      ingredients: [{ active_manifest: "urn:test:u1", relationship: "parentOf" }],
      assertions: [
        { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.opened" }] } },
      ],
    };
    const store = {
      active_manifest: "urn:test:stage2",
      manifests,
      validation_status: [],
    };
    await expect(verifyRealReel(store, "realreel")).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringContaining("depth"),
    });
  });
});
