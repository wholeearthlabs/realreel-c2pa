// End-to-end test of the RealReel verification pipeline against a real
// fixture captured + uploaded by the RealReel mobile app.
//
// Fixture: __tests__/fixtures/realreel-uploaded.jpg — Pixel 10, captured
// 2026-05-28, two-stage signed (capture + upload), trust-rooted at the
// RealReel CA root in trust-sources/realreel/root.pem. Stage 2 carries
// an RFC 3161 sigTst2 token (DigiCert TSA).
//
// Pipeline exercised:
//   1. loadTrustConfig — reads trust-sources.yaml + the realreel root.pem.
//   2. verify() — Reader.fromAsset with our trust anchors.
//   3. identifyTrustSource — matches signature_info.issuer "RealReel"
//      against @realreel/c2pa-trust-core's TRUSTED_ISSUERS[id=realreel]
//      issuerMatch substring; force-wrap accepts it (active = RealReel).
//   4. verifyRealReel — extracts cert_serial_number from Stage 2, looks
//      up via mocked lookupSigningKeyRevocation, enforces Stage-2
//      revocation + user_id binding. Stage 1 = structural checks only
//      (enrollment-only trust; no per-capture device-health).
//   5. sanitizeManifestStore — strips signature bytes, retains
//      assertions + parent_label.
//
// Database is mocked via vitest's vi.mock() at the module boundary —
// the test does not connect to Postgres.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

// Mock the db module BEFORE importing the modules that depend on it.
// Tests inject the result via `mockResolvedValue`.
//
// `consumeAndRecordAttestation` is no-op-mocked because a Stage 2 envelope
// (if the fixture carries one) reaches the consume path.
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
import { VerifyErrorCode } from "../src/errors.js";

// Fixture metadata — derived from manifest inspection of the file:
//   subject=RealReel-Device-Key, issuer=RealReel Issuing CA
//   cert serial (decimal) = 363929595041533803483005728970001726554859632395
//   Stage 1's capturerUuid assertion: a73f9e58-7323-4fd6-970e-59fb0b4d2ea4
const FIXTURE_CERT_SERIAL =
  "363929595041533803483005728970001726554859632395";
const FIXTURE_CAPTURER_UUID = "a73f9e58-7323-4fd6-970e-59fb0b4d2ea4";

// The mocked lookupSigningKeyRevocation always returns the SAME row
// regardless of input — single-device fixture, Stage 2 keys the lookup.
function defaultRevocationRow(opts: {
  revoked?: boolean;
  userId?: string;
  platform?: string;
} = {}) {
  return {
    key_id: "stub-key-id-from-mock",
    user_id: opts.userId ?? FIXTURE_CAPTURER_UUID,
    revoked_at: opts.revoked ? "2026-05-28T12:00:00.000Z" : null,
    cert_serial_number: FIXTURE_CERT_SERIAL,
    // The committed fixture (realreel-uploaded.jpg) was captured on a
    // Pixel 10; its signing-key platform is 'android'. Tests that want
    // to assert cross-platform behavior override via opts.platform.
    platform: opts.platform ?? "android",
    public_key: Buffer.alloc(0),
    app_attest_public_key: null,
  };
}

const fixturePath = resolve(
  import.meta.dirname,
  "fixtures/realreel-uploaded.jpg",
);
const trustSourcesPath = resolve(import.meta.dirname, "../trust-sources.yaml");

const fixtureBytes = await readFile(fixturePath);
const trustConfig = await loadTrustConfig(trustSourcesPath);

beforeEach(() => {
  vi.mocked(lookupSigningKeyRevocation).mockReset();
});

describe("verify() end-to-end against real RealReel fixture", () => {
  it("happy path: accepts a valid RealReel-signed JPEG", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(defaultRevocationRow());

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    expect(result.sanitizedManifest.validation_state).toBe("trusted");
    expect(result.sanitizedManifest.trust_source).toBe("realreel");

    // The active manifest is Stage 2 (the upload); its parent_label
    // points at Stage 1 (the capture). This is the canonical
    // two-stage shape.
    expect(result.sanitizedManifest.active_manifest).not.toBeNull();
    expect(result.sanitizedManifest.active_manifest?.parent_label).toBeTruthy();

    // Stage 1 manifest carries the org.realreel.capture assertion with
    // the capturerUuid. The capturer-UUID UI overlay reads this.
    const stage1Label = result.sanitizedManifest.active_manifest!.parent_label!;
    const stage1 = result.sanitizedManifest.manifests[stage1Label];
    expect(stage1).toBeDefined();
    const captureAssertion = stage1.assertions.find(
      (a) => a.label === "org.realreel.capture",
    );
    expect(captureAssertion).toBeDefined();
    expect(
      (captureAssertion!.data as { capturerUuid?: string }).capturerUuid,
    ).toBe(FIXTURE_CAPTURER_UUID);

    // This online capture's Stage-1 parent carries its OWN sigTst2,
    // so the sanitized parent exposes a TSA genTime (captures that timestamp
    // only the upload leave this null). Confirms the verifier accepts — and our TSA trust pool
    // validates — a timestamp on the Stage-1 manifest, not just Stage 2. The
    // overall validation_state asserted above stays 'trusted', so the parent's
    // timestamp validates cleanly under verifyTimestampTrust.
    expect(stage1.signature_info.time).toBeTruthy();
  });

  it("surfaces the signer common_name + signing alg on both stages", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(defaultRevocationRow());

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    // The enrichment a manifest viewer reads: the leaf cert's common_name
    // (friendlier than the issuer DN) and the signing algorithm, kept for
    // every manifest in the store. Pinned against the real fixture's certs.
    const active = result.sanitizedManifest.active_manifest!;
    expect(active.signature_info.common_name).toBe("RealReel-Device-Key");
    expect(active.signature_info.alg).toBe("Es256");

    const stage1 = result.sanitizedManifest.manifests[active.parent_label!];
    expect(stage1!.signature_info.common_name).toBe("RealReel-Device-Key");
    expect(stage1!.signature_info.alg).toBe("Es256");
  });

  it("lifts the TSA provider name onto both stages' signature_info.timestamp_authority", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(defaultRevocationRow());

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    // Both stages of this fixture carry a DigiCert sigTst2 (capture at
    // 19:46:30, upload at 19:46:41). The provider name survives only in
    // c2pa-rs's validation_results explanation strings — sanitize lifts it out
    // (extractTsaByLabel) per manifest so a viewer can show "Timestamped by …".
    const TSA = "DigiCert SHA256 RSA4096 Timestamp Responder 2025 1";
    const active = result.sanitizedManifest.active_manifest!;
    expect(active.signature_info.timestamp_authority).toBe(TSA);

    const stage1 = result.sanitizedManifest.manifests[active.parent_label!];
    expect(stage1!.signature_info.timestamp_authority).toBe(TSA);
  });

  it("drops re-verification-only assertions and keeps the row a few KB", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(defaultRevocationRow());

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    const labels = Object.values(result.sanitizedManifest.manifests).flatMap(
      (m) => m.assertions.map((a) => a.label),
    );
    // Consumed-at-ingest / re-verification material is stripped...
    expect(labels.some((l) => l.startsWith("c2pa.hash."))).toBe(false);
    expect(labels).not.toContain("org.realreel.play_integrity");
    // ...while the provenance a viewer renders is kept: signed EXIF, the
    // actions log, the capture UUID.
    expect(labels).toContain("stds.exif");
    expect(labels).toContain("org.realreel.capture");
    // Real-row size pin: the kept shape is a few KB, and this ceiling also
    // trips if the drop ever regresses (unfiltered this fixture is ~5.5 KB).
    expect(JSON.stringify(result.sanitizedManifest).length).toBeLessThan(5000);
  });

  it("looks up BOTH stages' cert serials (Stage 1 for the revocation denylist, Stage 2 for the full gate)", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(defaultRevocationRow());

    await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });

    // Dual-stage revocation: Stage 1 is now consulted for the
    // revocation denylist (revoked_at only — its user_id is never bound, so
    // cross-user capture stays allowed), and Stage 2 for the full lookup +
    // gates. In this single-device native fixture both stages are signed by
    // the same enrolled key, so both lookups use the same cert serial.
    expect(vi.mocked(lookupSigningKeyRevocation)).toHaveBeenCalledTimes(2);
    expect(vi.mocked(lookupSigningKeyRevocation)).toHaveBeenCalledWith(FIXTURE_CERT_SERIAL);
  });
});

describe("verify() end-to-end against real RealReel fixture (cont.)", () => {
  it("rejects with KEY_NOT_FOUND when the cert_serial_number isn't enrolled", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(null);

    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_CAPTURER_UUID,
        trustConfig,
      }),
    ).rejects.toMatchObject({ code: VerifyErrorCode.KEY_NOT_FOUND });
  });

  it("rejects with KEY_REVOKED when the Stage 2 upload key is revoked", async () => {
    // Order-based mock: the realreel profile looks Stage 1 up first, then
    // Stage 2. Stage 1 is clean here; Stage 2 is revoked.
    vi.mocked(lookupSigningKeyRevocation)
      .mockResolvedValueOnce(defaultRevocationRow())
      .mockResolvedValue(defaultRevocationRow({ revoked: true }));

    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_CAPTURER_UUID,
        trustConfig,
      }),
    ).rejects.toMatchObject({ code: VerifyErrorCode.KEY_REVOKED });
  });

  it("rejects with KEY_REVOKED when the Stage 1 capture key is revoked (denylist)", async () => {
    // The laundering-oracle kill switch: a revoked CAPTURE key
    // rejects the upload even though the Stage 2 upload key is clean. Stage 1
    // is looked up first, so the first queued row is the revoked capture key.
    vi.mocked(lookupSigningKeyRevocation)
      .mockResolvedValueOnce(defaultRevocationRow({ revoked: true }))
      .mockResolvedValue(defaultRevocationRow());

    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_CAPTURER_UUID,
        trustConfig,
      }),
    ).rejects.toMatchObject({ code: VerifyErrorCode.KEY_REVOKED });
  });

  it("accepts when the Stage 1 capture key is not enrolled (denylist skips not-found) — pins skip + lookup order", async () => {
    // The ONLY native test that exercises the Stage-1 not-found-is-skip
    // branch, and it doubles as an ordering pin. Stage 1 is looked up FIRST
    // and misses the registry → the denylist skips it (not-found is not a
    // rejection). Stage 2 is looked up SECOND and returns a valid key →
    // trusted. If the two lookups were ever reordered, Stage 2 would receive
    // the null and throw KEY_NOT_FOUND instead of accepting, failing this
    // test. (The stage-specific revoked tests above can't catch a reorder:
    // both throw KEY_REVOKED regardless of which stage saw the revoked row,
    // since the native fixture's two stages share one cert serial.)
    vi.mocked(lookupSigningKeyRevocation)
      .mockResolvedValueOnce(null)
      .mockResolvedValue(defaultRevocationRow());

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
    });
    expect(result.sanitizedManifest.validation_state).toBe("trusted");
  });

  it("accepts even when Stage 2's key belongs to a different user_id than the JWT (verifier is user-anonymous)", async () => {
    // The user_id == JWT binding was dropped. The Stage 2 key's
    // recorded owner differing from expectedUserId is no longer a rejection
    // — Stage-2 attestation already forces own-key signing, and the
    // verifier stays anonymous to the uploader.
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(
      defaultRevocationRow({ userId: "00000000-0000-0000-0000-000000000001" }),
    );

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID, // differs from the row's user_id
      trustConfig,
    });
    expect(result.sanitizedManifest.validation_state).toBe("trusted");
  });

  it("accepts a cross-user capture (Stage 1 looked up for revocation only, user_id never bound)", async () => {
    // Bob captured (Stage 1); Sara uploads the photo (Stage 2, her valid
    // key). The capturer==uploader bind is gone. Stage 1 IS
    // looked up now — but only for the revocation denylist (revoked_at);
    // Bob's user_id is never compared to Sara's, so the cross-user flow is
    // preserved.
    const saraId = FIXTURE_CAPTURER_UUID;
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(
      defaultRevocationRow({ userId: saraId }), // valid, non-revoked
    );

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: saraId,
      trustConfig,
    });
    expect(result.sanitizedManifest.validation_state).toBe("trusted");
    // Both stages consulted: Stage 1 (revocation denylist) + Stage 2 (gate).
    expect(vi.mocked(lookupSigningKeyRevocation)).toHaveBeenCalledTimes(2);
  });

  it("accepts a post-reinstall capture signed by the user's now-dormant old key", async () => {
    // One user, two enrollments. K1 captured the photo while healthy; the
    // user later reinstalled and re-enrolled as K2 (Stage 2). Stage 1 is
    // never looked up, so re-uploading your own older capture works.
    const aliceId = FIXTURE_CAPTURER_UUID;
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(
      defaultRevocationRow({ userId: aliceId }), // K2, valid
    );

    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: aliceId,
      trustConfig,
    });
    expect(result.sanitizedManifest.validation_state).toBe("trusted");
  });

  it("rejects MANIFEST_MALFORMED when bytes are not a C2PA-signed asset", async () => {
    const garbage = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0]); // JPEG SOI + nothing else
    await expect(
      verify({
        assetBytes: garbage,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_CAPTURER_UUID,
        trustConfig,
      }),
    ).rejects.toMatchObject({ code: VerifyErrorCode.MANIFEST_MALFORMED });
  });

});

describe("verify() — TSA-trust state surfaces in top-level validation_results", () => {
  // Regression guard for what makes sigTst2 validation actually
  // load-bearing. c2pa-node v0.5.5 surfaces TSA chain-trust state at
  // `reader.json().validation_results.activeManifest` (top-level on
  // ManifestStore, NOT nested per-manifest):
  //   - success contains `timeStamp.trusted` when the TSA chain
  //     validates against trustAnchorsBundle.
  //   - informational contains `timeStamp.untrusted` when the chain
  //     can't be rooted.
  // The asymmetry is what tells us tsaRoots are doing real work — and
  // is the surface the cert-validity gates read to enforce as-of-TSA-time cert validity.
  //
  // verify() doesn't expose validation_results directly (sanitize drops
  // it after deriving validation_state), so this test goes around verify
  // and calls Reader.fromAsset itself with the same settings shape
  // verify.ts uses.

  it("emits timeStamp.trusted in success when TSA roots are loaded; timeStamp.untrusted in informational when stripped", async () => {
    const [{ Reader, createTrustSettings, settingsToJson }] = await Promise.all([
      import("@contentauth/c2pa-node"),
    ]);

    async function timestampCodes(bundle: string) {
      const settings = settingsToJson({
        ...createTrustSettings({
          verifyTrustList: false,
          trustAnchors: bundle,
        }),
        verify: { verifyTimestampTrust: true },
      });
      const reader = await Reader.fromAsset(
        { buffer: fixtureBytes, mimeType: "image/jpeg" },
        settings,
      );
      const result = reader!.json();
      const parsed: { validation_results?: { activeManifest?: {
        success?: Array<{ code: string }>;
        informational?: Array<{ code: string }>;
        failure?: Array<{ code: string }>;
      } } } = typeof result === "string" ? JSON.parse(result) : result;
      const am = parsed.validation_results?.activeManifest;
      const codes = (bucket: "success" | "informational" | "failure") =>
        (am?.[bucket] ?? [])
          .map((i) => i.code)
          .filter((c) => c.toLowerCase().includes("timestamp"));
      return {
        success: codes("success"),
        informational: codes("informational"),
        failure: codes("failure"),
      };
    }

    // WITH the full trust pool (signer roots + TSA roots): chain validates.
    const withTsa = await timestampCodes(trustConfig.trustAnchorsBundle);
    expect(withTsa.success).toContain("timeStamp.trusted");
    expect(withTsa.success).toContain("timeStamp.validated");
    expect(withTsa.informational).not.toContain("timeStamp.untrusted");
    expect(withTsa.failure).toEqual([]);

    // WITHOUT TSA roots (signer roots only): chain can't be rooted →
    // c2pa-rs surfaces `timeStamp.untrusted` in informational and drops
    // `timeStamp.trusted` from success. Confirms our vendored
    // `c2pa-tsa/` + `c2pa-tsa-fallback/` PEMs are what carry the trust.
    const signerOnly = trustConfig.sources.map((s) => s.rootCertPem.trim()).join("\n");
    const withoutTsa = await timestampCodes(signerOnly);
    expect(withoutTsa.success).not.toContain("timeStamp.trusted");
    expect(withoutTsa.success).toContain("timeStamp.validated"); // hash binding still validates
    expect(withoutTsa.informational).toContain("timeStamp.untrusted");
  });
});

describe("verify() — time-bound cert-validity gates (wire-up)", () => {
  // Unit-level gate behavior lives in cert-validity.test.ts. These
  // tests confirm verify() actually invokes the gates against the real
  // fixture — i.e. validation_results is read BEFORE sanitize drops
  // it, the clock arg threads through, and the cert-lifetime arg
  // threads through. The fixture is the Android
  // realreel-uploaded.jpg used above; the active (Stage-2)
  // signature_info.time = 2026-05-28T19:46:41+00:00 and BOTH stages
  // carry a trusted DigiCert sigTst2 stamp (Stage-1 parent at 19:46:30).

  beforeEach(() => {
    vi.mocked(lookupSigningKeyRevocation).mockResolvedValue(defaultRevocationRow());
  });

  it("Gate 1 fires when TSA roots are stripped from the trust pool (sigTst2 chain untrusted)", async () => {
    // Same trick the TSA-trust regression test uses: rebuild the
    // trustAnchorsBundle from signer roots only, dropping the TSA
    // roots. c2pa-rs then emits timeStamp.untrusted in informational,
    // which the untrusted-TSA-chain gate rejects as SIGNATURE_INVALID.
    const signerOnly = trustConfig.sources
      .map((s) => s.rootCertPem.trim())
      .join("\n");
    const noTsaTrust = { ...trustConfig, trustAnchorsBundle: signerOnly };

    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_CAPTURER_UUID,
        trustConfig: noTsaTrust,
      }),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringMatching(/untrusted chain/),
    });
  });

  it("Gate 2 fires when clock is set before the fixture's signature time (future-dated)", async () => {
    // Inject a clock dated well before the fixture's
    // 2026-05-28T19:46:41 signature time. The clock-skew tolerance is
    // 5 minutes; nearly two hours earlier easily trips it.
    await expect(
      verify({
        assetBytes: fixtureBytes,
        mimeType: "image/jpeg",
        expectedUserId: FIXTURE_CAPTURER_UUID,
        trustConfig,
        clock: { now: () => new Date("2026-05-28T18:00:00Z") },
      }),
    ).rejects.toMatchObject({
      code: VerifyErrorCode.SIGNATURE_INVALID,
      detail: expect.stringMatching(/in the future/),
    });
  });

  it("passes with a deliberately tiny certLifetimeMs because TSA is trusted (Gate 3 skipped)", async () => {
    // A trusted TSA stamp lifts the required-TSA gate entirely. The
    // fixture has a trusted DigiCert sigTst2, so even a 1ms cert
    // lifetime ceiling should NOT cause rejection.
    //
    // Inject a fixed clock ~30 minutes past the fixture's
    // signature_info.time (2026-05-28T19:46:41Z) so Gate 2 (future-
    // dated, with 5-min skew tolerance) passes deterministically. Without
    // the injection this test would silently couple "Gate 3 skipped" to
    // "real now happens to be past the fixture's signature time" — true
    // today but a brittle assumption to bake into a regression test.
    const result = await verify({
      assetBytes: fixtureBytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_CAPTURER_UUID,
      trustConfig,
      clock: { now: () => new Date("2026-05-28T20:16:00Z") },
      certLifetimeMs: 1,
    });
    expect(result.sanitizedManifest.validation_state).toBe("trusted");
  });
});
