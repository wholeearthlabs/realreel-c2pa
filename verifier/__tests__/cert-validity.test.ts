// Unit tests for the time-bound cert-validity gates.
//
// These exercise the pure functions in src/cert-validity.ts against
// synthetic ManifestStoreShape / ManifestShape inputs — no fixture
// binaries, no c2pa-node Reader. The verify() wire-up is exercised by
// verify-realreel.test.ts's cert-validity wire-up section against the real
// realreel-uploaded.jpg fixture.

import { describe, it, expect } from "vitest";
import {
  readTsaState,
  readSignatureTime,
  checkCertValidityTimeBounds,
  CLOCK_SKEW_TOLERANCE_MS,
  DEFAULT_CERT_LIFETIME_MS,
  type Clock,
  type TsaState,
} from "../src/cert-validity.js";
import type {
  ManifestStoreShape,
  ManifestShape,
} from "../src/c2pa-shape.js";
import { VerifyErrorCode } from "../src/errors.js";

// ----- Fixed clock helper -----

function clockAt(iso: string): Clock {
  const t = new Date(iso);
  return { now: () => t };
}

// ----- Synthetic ManifestStoreShape builder -----

interface BuildStoreOpts {
  tsaSuccess?: string[];
  tsaInformational?: string[];
  tsaFailure?: string[];
}

/**
 * Build a minimal ManifestStoreShape with whatever timestamp codes the
 * test wants in validation_results.activeManifest. The c2pa-node v0.5.5
 * structural pinning that matters here: validation_results lives at the
 * top of the store, NOT nested per-manifest. See verify.ts trustSettings
 * comment block + the "TSA-trust state surfaces" regression test.
 */
function buildStore(opts: BuildStoreOpts = {}): ManifestStoreShape {
  return {
    active_manifest: "synthetic",
    manifests: { synthetic: { label: "synthetic", signature_info: {} } },
    validation_status: [],
    ...({
      validation_results: {
        activeManifest: {
          success: (opts.tsaSuccess ?? []).map((code) => ({ code })),
          informational: (opts.tsaInformational ?? []).map((code) => ({ code })),
          failure: (opts.tsaFailure ?? []).map((code) => ({ code })),
        },
      },
    } as Record<string, unknown>),
  };
}

function buildActive(opts: { time?: string | null } = {}): ManifestShape {
  const sig: { time?: string } = {};
  if (typeof opts.time === "string") sig.time = opts.time;
  return { label: "synthetic", signature_info: sig };
}

// ----- readTsaState -----

describe("readTsaState", () => {
  it("reports trusted=true when timeStamp.trusted appears in success", () => {
    const store = buildStore({
      tsaSuccess: ["timeStamp.trusted", "timeStamp.validated"],
    });
    expect(readTsaState(store)).toEqual({ hasStamp: true, trusted: true });
  });

  it("reports hasStamp=true, trusted=false when timeStamp.untrusted is in informational", () => {
    // The sigTst2-trust surface: c2pa-rs emits timeStamp.untrusted in
    // informational when sigTst2 is present but its chain can't be
    // rooted (revoked or wrong-root TSA cert). The untrusted-TSA-chain
    // gate rejects.
    const store = buildStore({
      tsaSuccess: ["timeStamp.validated"], // digest binding independent of chain trust
      tsaInformational: ["timeStamp.untrusted"],
    });
    expect(readTsaState(store)).toEqual({ hasStamp: true, trusted: false });
  });

  it("reports hasStamp=false, trusted=false when no timeStamp.* codes appear", () => {
    // Manifest without a sigTst2 timestamp, or any asset without one.
    const store = buildStore({ tsaSuccess: ["signingCredential.trusted"] });
    expect(readTsaState(store)).toEqual({ hasStamp: false, trusted: false });
  });

  it("handles missing validation_results entirely", () => {
    const store: ManifestStoreShape = {
      active_manifest: "synthetic",
      manifests: {},
      validation_status: [],
    };
    expect(readTsaState(store)).toEqual({ hasStamp: false, trusted: false });
  });
});

// ----- readSignatureTime -----

describe("readSignatureTime", () => {
  it("parses an ISO-8601 timestamp from signature_info.time", () => {
    const active = buildActive({ time: "2026-05-28T16:31:37+00:00" });
    expect(readSignatureTime(active)?.toISOString()).toBe(
      "2026-05-28T16:31:37.000Z",
    );
  });

  it("returns null when signature_info.time is absent (wrap fixture, untimestamped manifests)", () => {
    expect(readSignatureTime(buildActive())).toBeNull();
  });

  it("returns null on an unparseable timestamp", () => {
    const active = buildActive({ time: "not-a-date" });
    expect(readSignatureTime(active)).toBeNull();
  });
});

// ----- checkCertValidityTimeBounds — Gate 1 (trusted-TSA-when-present) -----

describe("checkCertValidityTimeBounds — Gate 1 (trusted-TSA-when-present)", () => {
  const baseArgs = {
    active: buildActive({ time: "2026-05-28T16:31:37+00:00" }),
    clock: clockAt("2026-05-28T17:00:00Z"),
    certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
  };

  it("rejects SIGNATURE_INVALID when sigTst2 is present but untrusted", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        ...baseArgs,
        tsaState: { hasStamp: true, trusted: false },
      }),
    ).toThrowError(/untrusted chain/);
  });

  it("accepts when sigTst2 is present and trusted", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        ...baseArgs,
        tsaState: { hasStamp: true, trusted: true },
      }),
    ).not.toThrow();
  });

  it("accepts when no sigTst2 is present (untimestamped manifest)", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        ...baseArgs,
        tsaState: { hasStamp: false, trusted: false },
      }),
    ).not.toThrow();
  });

  it("error carries SIGNATURE_INVALID code (not CERT_EXPIRED)", () => {
    try {
      checkCertValidityTimeBounds({
        ...baseArgs,
        tsaState: { hasStamp: true, trusted: false },
      });
      expect.unreachable("expected throw");
    } catch (e) {
      // Untrusted TSA chain is a signature-attached-resource problem,
      // not a cert-validity problem — pin the code so Sentry routing
      // stays stable.
      expect((e as { code: string }).code).toBe(VerifyErrorCode.SIGNATURE_INVALID);
    }
  });
});

// ----- checkCertValidityTimeBounds — Gate 2 (future-dated) -----

describe("checkCertValidityTimeBounds — Gate 2 (future-dated signature)", () => {
  const trustedState: TsaState = { hasStamp: true, trusted: true };

  it("rejects SIGNATURE_INVALID when signature_info.time is far in the future", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2027-01-01T00:00:00Z" }),
        tsaState: trustedState,
        clock: clockAt("2026-05-28T17:00:00Z"),
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      }),
    ).toThrowError(/in the future/);
  });

  it("accepts when signature time is within the clock-skew tolerance ahead of now", () => {
    // A CI run a few seconds before a fresh fixture's signature_time
    // shouldn't trip — RFC 3161 implementations conventionally allow
    // ±5 minutes for clock skew.
    const now = new Date("2026-05-28T17:00:00Z");
    const within = new Date(now.getTime() + CLOCK_SKEW_TOLERANCE_MS - 1_000);
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive({ time: within.toISOString() }),
        tsaState: trustedState,
        clock: { now: () => now },
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      }),
    ).not.toThrow();
  });

  it("rejects when signature time is past the clock-skew tolerance", () => {
    const now = new Date("2026-05-28T17:00:00Z");
    const beyond = new Date(now.getTime() + CLOCK_SKEW_TOLERANCE_MS + 1_000);
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive({ time: beyond.toISOString() }),
        tsaState: trustedState,
        clock: { now: () => now },
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      }),
    ).toThrowError(/in the future/);
  });

  it("skips Gate 2 when signature_info.time is absent (gate has nothing to bound)", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive(),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-05-28T17:00:00Z"),
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      }),
    ).not.toThrow();
  });
});

// ----- checkCertValidityTimeBounds — Gate 3 (required-TSA for old assets) -----

describe("checkCertValidityTimeBounds — Gate 3 (required-TSA for old assets)", () => {
  // 6mo in ms — useful for testing under the planned shorter-lifetime
  // CA cutover without rebuilding the rest of the harness.
  const SIX_MONTHS_MS = 6 * 30 * 24 * 60 * 60 * 1000;

  it("rejects CERT_EXPIRED when signature is older than certLifetimeMs and no trusted TSA", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2026-01-01T00:00:00Z" }),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-12-01T00:00:00Z"), // 11 months later
        certLifetimeMs: SIX_MONTHS_MS,
      }),
    ).toThrowError(/older than the cert-lifetime ceiling/);
  });

  it("accepts when signature is within certLifetimeMs and no trusted TSA", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2026-05-01T00:00:00Z" }),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-05-28T00:00:00Z"), // < 6mo later
        certLifetimeMs: SIX_MONTHS_MS,
      }),
    ).not.toThrow();
  });

  it("accepts when trusted TSA is present even if signature is older than certLifetimeMs", () => {
    // The whole point of TSA: prove the signature existed before cert
    // expiry. A trusted timestamp lifts the required-TSA gate entirely.
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2020-01-01T00:00:00Z" }), // 6 years old
        tsaState: { hasStamp: true, trusted: true },
        clock: clockAt("2026-05-28T00:00:00Z"),
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      }),
    ).not.toThrow();
  });

  it("accepts when signature_info.time is absent (legacy untimestamped assets)", () => {
    // c2pa-rs leaves signature_info.time out when neither sigTst2 nor a
    // claim-internal time is present. The committed wrap-mode fixture
    // (pixel-uploaded.jpg) hits this path because it carries no sigTst2;
    // RealReel signs — including wrap-mode — always embed
    // sigTst2 in production, so a real wrap-mode upload reaches Gate 3
    // with a trusted TSA and is skipped via the !trusted branch instead.
    // We accept here and lean on c2pa-rs's cert-chain check against
    // `now`. The required-TSA gate only adds protection when the manifest
    // itself CLAIMS to be older than cert lifetime.
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive(),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-05-28T00:00:00Z"),
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      }),
    ).not.toThrow();
  });

  it("CERT_EXPIRED error message includes age and limit in days for triage", () => {
    try {
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2026-01-01T00:00:00Z" }),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-08-01T00:00:00Z"), // ~7 months later
        certLifetimeMs: SIX_MONTHS_MS,
      });
      expect.unreachable("expected throw");
    } catch (e) {
      const detail = (e as { detail?: string }).detail ?? "";
      // ~212 days > ~180 days. Exact value depends on month lengths;
      // assert the day-comparison wording is present rather than fixed
      // numbers — keeps the test robust across a leap year.
      expect(detail).toMatch(/\d+ days > \d+ days/);
      expect((e as { code: string }).code).toBe(VerifyErrorCode.CERT_EXPIRED);
    }
  });
});

// ----- Interaction between gates -----

describe("checkCertValidityTimeBounds — gate ordering", () => {
  it("Gate 1 (untrusted TSA) fires before Gate 3 (old asset)", () => {
    // An old, untrusted-TSA asset is rejected for the untrusted-TSA
    // reason, NOT the age reason. The Sentry tag should reflect what
    // actually broke (SIGNATURE_INVALID, not CERT_EXPIRED).
    try {
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2020-01-01T00:00:00Z" }),
        tsaState: { hasStamp: true, trusted: false },
        clock: clockAt("2026-05-28T00:00:00Z"),
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      });
      expect.unreachable("expected throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(VerifyErrorCode.SIGNATURE_INVALID);
    }
  });

  it("Gate 2 (future-dated) fires before Gate 3 (old asset) — irrelevant in practice but pins ordering", () => {
    // A future-dated signature with no TSA hits Gate 2 first.
    try {
      checkCertValidityTimeBounds({
        active: buildActive({ time: "2030-01-01T00:00:00Z" }),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-05-28T00:00:00Z"),
        certLifetimeMs: DEFAULT_CERT_LIFETIME_MS,
      });
      expect.unreachable("expected throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(VerifyErrorCode.SIGNATURE_INVALID);
    }
  });
});
