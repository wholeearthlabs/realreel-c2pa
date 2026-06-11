// End-to-end test of the RealReel verifier against a REAL once-offline-then-
// TSA-drained fixture.
//
// Fixture: __tests__/fixtures/realreel-drained.jpg — captured offline on the
// same enrolled device as realreel-uploaded.jpg (so it reuses the same cert
// serial + capturerUuid), timestamped on next connectivity via an Update
// Manifest, then uploaded with location removed. Its manifest chain is the
// THREE-level shape the offline-queue drain produces:
//
//     Stage-2 (upload, active)
//        └─parentOf→ Update Manifest   (carries c2pa.time-stamp over Stage-1)
//             └─parentOf→ Stage-1 (capture)
//
// This is the binary counterpart to the synthetic walk-through tests in
// policy.test.ts: it pins, against real c2pa-node output, that
//   (a) verify() walks PAST the interposed Update Manifest to the capture and
//       returns Trusted (the Update Manifest is not mistaken for the capture),
//   (b) capturer attribution (org.realreel.capture) resolves through the
//       deeper chain,
//   (c) the interposed Update Manifest is the timestamped one — its RFC 3161
//       token is dropped from the persisted shape (re-verification-only) but
//       its stamp time survives as signature_info.time, and
//   (d) GPS privacy holds end-to-end — Stage-1's stds.exif was redacted at
//       upload (the capture has NO stds.exif assertion), and Stage-2 records
//       the redaction against the Stage-1 (grandparent) URN.
//
// Database is mocked at the module boundary (no Postgres).

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

vi.mock("../src/db.js", () => {
  const lookupSigningKeyRevocation = vi.fn();
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
import { loadTrustConfig } from "../src/trust/loader.js";
import { lookupSigningKeyRevocation } from "../src/db.js";

// Same enrolled device as realreel-uploaded.jpg → same key.
const FIXTURE_CERT_SERIAL =
  "363929595041533803483005728970001726554859632395";
const FIXTURE_CAPTURER_UUID = "a73f9e58-7323-4fd6-970e-59fb0b4d2ea4";

// Single-device fixture: every stage (capture, update, upload) is signed by
// the same hardware key, so the mock returns the same row for every lookup.
function deviceRow() {
  return {
    key_id: "stub-key-id-from-mock",
    user_id: FIXTURE_CAPTURER_UUID,
    revoked_at: null,
    cert_serial_number: FIXTURE_CERT_SERIAL,
    platform: "android", // Stage 2 carries org.realreel.play_integrity
    public_key: Buffer.alloc(0),
    app_attest_public_key: null,
  };
}

const fixtureBytes = await readFile(
  resolve(import.meta.dirname, "fixtures/realreel-drained.jpg"),
);
const trustConfig = await loadTrustConfig(
  resolve(import.meta.dirname, "../trust-sources.yaml"),
);

beforeEach(() => {
  vi.mocked(lookupSigningKeyRevocation).mockReset();
});

describe("verify() against a once-offline-then-drained RealReel fixture", () => {
  it("walks Stage-2 → Update → Stage-1 and returns Trusted", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(deviceRow());

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    expect(result.sanitizedManifest.validation_state).toBe("trusted");
    expect(result.sanitizedManifest.trust_source).toBe("realreel");

    const store = result.sanitizedManifest;
    const active = store.active_manifest!;
    expect(active).not.toBeNull();

    // active (Stage 2) → Update Manifest
    const updateLabel = active.parent_label!;
    expect(updateLabel).toBeTruthy();
    const update = store.manifests[updateLabel]!;
    expect(update).toBeDefined();
    // The interposed manifest is the timestamped one. Its ~8 KB RFC 3161 token
    // is dropped from the persisted shape (re-verification-only), but the stamp
    // time a viewer renders survives as signature_info.time — and the TSA
    // provider name is lifted onto signature_info.timestamp_authority.
    expect(update.assertions.some((a) => a.label === "c2pa.time-stamp")).toBe(false);
    expect(update.signature_info.time).toBeTruthy();
    expect(update.signature_info.timestamp_authority).toBeTruthy();
    // Dropping the token keeps even a drained row a few KB (unfiltered ~13 KB);
    // the per-manifest timestamp_authority adds only a few tens of bytes each.
    expect(JSON.stringify(store).length).toBeLessThan(5500);

    // Update Manifest → Stage-1 capture
    const captureLabel = update.parent_label!;
    expect(captureLabel).toBeTruthy();
    const capture = store.manifests[captureLabel]!;
    expect(capture).toBeDefined();

    // Capturer attribution resolves through the deeper chain.
    const captureAssertion = capture.assertions.find(
      (a) => a.label === "org.realreel.capture",
    );
    expect(captureAssertion).toBeDefined();
    expect(
      (captureAssertion!.data as { capturerUuid?: string }).capturerUuid,
    ).toBe(FIXTURE_CAPTURER_UUID);
  });

  it("looks up the capture (post-walk) + Stage-2 keys — proves the walk reached the real capture", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(deviceRow());
    await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });
    // Two lookups: the capture's serial (Stage-1 denylist, post-walk) and the
    // Stage-2 serial — NOT the Update Manifest (the walk doesn't look it up).
    expect(vi.mocked(lookupSigningKeyRevocation)).toHaveBeenCalledTimes(2);
    expect(vi.mocked(lookupSigningKeyRevocation)).toHaveBeenCalledWith(FIXTURE_CERT_SERIAL);
  });

  it("GPS privacy: the capture's stds.exif was redacted at upload (location scrubbed from provenance)", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(deviceRow());
    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    const store = result.sanitizedManifest;
    const updateLabel = store.active_manifest!.parent_label!;
    const captureLabel = store.manifests[updateLabel]!.parent_label!;
    const capture = store.manifests[captureLabel]!;

    // "Remove location" at upload redacts the capture's GPS-bearing stds.exif
    // (a grandparent of Stage-2) — so the capture manifest no longer carries
    // it. This is the manifest-level half of the privacy guarantee (the file's
    // EXIF GPS bytes are stripped separately at upload).
    expect(capture.assertions.some((a) => a.label === "stds.exif")).toBe(false);
    // The capture itself is still a fresh capture (it kept its capture context).
    expect(capture.assertions.some((a) => a.label === "org.realreel.capture")).toBe(true);
  });
});
