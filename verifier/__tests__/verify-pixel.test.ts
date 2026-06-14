// Force-wrap test: a raw single-stage Pixel capture uploaded directly is
// REJECTED at ingestion. After the attestation-simplification refactor the
// verifier has ONE ingestion profile (realreel) and requires every upload's
// ACTIVE manifest to be RealReel-signed (a RealReel Stage 2). A bare Pixel
// file has a Google-issued active manifest and no Stage 2, so it's refused.
//
// The Pixel ROOT stays in the trust bundle — it's still needed to validate
// a Pixel *parent* wrapped in a RealReel Stage 2 (see
// verify-realreel-wrap.test.ts). What changed is only that a Pixel-active
// manifest is no longer an accepted ingestion shape.
//
// Fixture: __tests__/fixtures/pixel-og.jpg — Pixel 10 capture (2026-05-12,
// ~5.2 MB), single-stage manifest, trust-rooted at the Google C2PA Root CA
// G3 in trust-sources/pixel/root.pem.
//
// Mocks: lookupSigningKeyRevocation. Force-wrap rejects before the realreel
// profile runs, so the mock stays in default-not-called state. We assert that.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

vi.mock("../src/db.js", () => {
  const lookupSigningKeyRevocation = vi.fn();
  // consumeAndRecordAttestation is stubbed as a no-op resolve. It
  // exists only so the regression-guard test below ("RealReel fixture
  // still routes to realreel profile") doesn't crash on a missing
  // mock when its android-Play-Integrity envelope reaches the
  // nonce-burn path. This test file guards ROUTING (force-wrap
  // rejection of raw single-stage Pixel + cross-routing fallthrough),
  // not Play Integrity verdict semantics — nonce-burn validity is
  // exercised in verify-realreel.test.ts where it matters. Do NOT
  // add assertions on this mock here; treating it as a real burn-path
  // would require the realreel-test's setup machinery.
  const consumeAndRecordAttestation = vi.fn().mockResolvedValue(undefined);
  const pingDb = vi.fn();
  return {
    lookupSigningKeyRevocation,
    consumeAndRecordAttestation,
    pingDb,
    initDb: vi.fn(),
    closeDbPool: vi.fn(),
    // The default VerifierDatastore the profile / attestation consumers fall
    // back to when no adapter is injected. Delegates to the same spies.
    postgresAdapter: {
      lookup: lookupSigningKeyRevocation,
      burn: consumeAndRecordAttestation,
      ping: pingDb,
    },
  };
});

import { verify } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { lookupSigningKeyRevocation } from "../src/db.js";
import { VerifyErrorCode } from "../src/errors.js";

const fixturePath = resolve(
  import.meta.dirname,
  "fixtures/pixel-og.jpg",
);
const trustSourcesPath = resolve(import.meta.dirname, "../trust-sources.yaml");

const fixtureBytes = await readFile(fixturePath);
const trustConfig = await loadTrustConfig(trustSourcesPath);

// The Pixel fixture's expectedUserId is irrelevant — the file is rejected
// before any user_id binding. Pass anything; it gets ignored.
const EXPECTED_USER = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";

beforeEach(() => {
  vi.mocked(lookupSigningKeyRevocation).mockReset();
});

describe("verify() force-wrap — raw single-stage Pixel rejected", () => {
  it("rejects a raw Pixel-captured JPEG with UNTRUSTED_ISSUER (force-wrap)", async () => {
    // The active manifest is Google-signed (issuer "Google LLC",
    // common_name "Pixel Camera"); force-wrap requires a RealReel Stage 2.
    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: EXPECTED_USER,
        trustConfig,
        declaredLocation: "precise",
      }),
    ).rejects.toMatchObject({ code: VerifyErrorCode.UNTRUSTED_ISSUER });
  });

  it("does NOT call lookupSigningKeyRevocation (rejected before profile dispatch)", async () => {
    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: EXPECTED_USER,
        trustConfig,
        declaredLocation: "precise",
      }),
    ).rejects.toBeDefined();
    // Force-wrap fires in verify.ts before the realreel profile runs, so the
    // Stage-2 signing-key lookup is never reached.
    expect(vi.mocked(lookupSigningKeyRevocation)).not.toHaveBeenCalled();
  });

  it("rejects with MANIFEST_MALFORMED for non-C2PA bytes", async () => {
    const garbage = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0]);
    await expect(
      verify({
        assetBytes: garbage,
        mimeType: "image/jpeg",
        expectedUserId: EXPECTED_USER,
        trustConfig,
        declaredLocation: "precise",
      }),
    ).rejects.toMatchObject({ code: VerifyErrorCode.MANIFEST_MALFORMED });
  });
});

describe("Cross-source routing — realreel still accepted", () => {
  it("RealReel fixture still routes to realreel profile (regression guard)", async () => {
    // Ensures the force-wrap gate didn't change how a genuine RealReel
    // two-stage file ingests. Mock lookupSigningKeyRevocation since the
    // realreel profile uses it for Stage 2.
    const realreelBytes = await readFile(
      resolve(import.meta.dirname, "fixtures/realreel-uploaded.jpg"),
    );
    const FIXTURE_CERT_SERIAL =
      "363929595041533803483005728970001726554859632395";
    const FIXTURE_CAPTURER_UUID = "a73f9e58-7323-4fd6-970e-59fb0b4d2ea4";
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue({
      key_id: "stub",
      user_id: FIXTURE_CAPTURER_UUID,
      revoked_at: null,
      cert_serial_number: FIXTURE_CERT_SERIAL,
      platform: "android",
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    });

    const result = await verify({
      assetBytes: realreelBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
      declaredLocation: "precise",
    });
    expect(result.sanitizedManifest.trust_source).toBe("realreel");
  });
});
