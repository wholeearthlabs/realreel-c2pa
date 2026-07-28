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
  checkLedgerTimeBounds,
  CLOCK_SKEW_TOLERANCE_MS,
  ISSUANCE_TOLERANCE_MS,
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
      }),
    ).toThrowError(/in the future/);
  });

  it("skips Gate 2 when signature_info.time is absent (gate has nothing to bound)", () => {
    expect(() =>
      checkCertValidityTimeBounds({
        active: buildActive(),
        tsaState: { hasStamp: false, trusted: false },
        clock: clockAt("2026-05-28T17:00:00Z"),
      }),
    ).not.toThrow();
  });
});

// ----- checkLedgerTimeBounds — Gate 3 (ledger-backed validity window) -----

describe("checkLedgerTimeBounds — Gate 3 (ledger-backed validity window)", () => {
  const NO_TSA: TsaState = { hasStamp: false, trusted: false };
  const TRUSTED_TSA: TsaState = { hasStamp: true, trusted: true };
  const ISSUED_AT = "2026-05-01T00:00:00.000Z";
  const EXPIRES_AT = "2026-10-28T00:00:00.000Z"; // 180d leaf

  function ledgerArgs(over: {
    time?: string | null;
    tsaState?: TsaState;
    issuedAt?: string;
    expiresAt?: string;
  } = {}) {
    return {
      active: buildActive({
        time: over.time === undefined ? "2026-05-28T16:31:37+00:00" : over.time,
      }),
      tsaState: over.tsaState ?? NO_TSA,
      issuedAt: over.issuedAt ?? ISSUED_AT,
      expiresAt: over.expiresAt ?? EXPIRES_AT,
    };
  }

  it("accepts a signature time inside the ledger window", () => {
    expect(() => checkLedgerTimeBounds(ledgerArgs())).not.toThrow();
  });

  it("rejects SIGNATURE_INVALID when the signature predates ledger issuance (time-warp)", () => {
    try {
      checkLedgerTimeBounds(ledgerArgs({ time: "2026-04-30T00:00:00Z" }));
      expect.unreachable("expected throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(VerifyErrorCode.SIGNATURE_INVALID);
      expect((e as { detail?: string }).detail).toMatch(/predates/);
    }
  });

  it("time-warp rejects even with a trusted TSA — a genuine pre-issuance timestamp is damning", () => {
    expect(() =>
      checkLedgerTimeBounds(
        ledgerArgs({ time: "2026-04-30T00:00:00Z", tsaState: TRUSTED_TSA }),
      ),
    ).toThrowError(/predates/);
  });

  it("tolerates the CA notBefore backdate + clock skew just before issuance", () => {
    // ISSUANCE_TOLERANCE_MS covers the 5-min notBefore backdate plus 5-min
    // device skew: a first signature moments after enrollment may carry a
    // time slightly before the ledger write.
    const justInside = new Date(
      new Date(ISSUED_AT).getTime() - ISSUANCE_TOLERANCE_MS + 1_000,
    ).toISOString();
    expect(() => checkLedgerTimeBounds(ledgerArgs({ time: justInside }))).not.toThrow();
    const justOutside = new Date(
      new Date(ISSUED_AT).getTime() - ISSUANCE_TOLERANCE_MS - 1_000,
    ).toISOString();
    expect(() => checkLedgerTimeBounds(ledgerArgs({ time: justOutside }))).toThrowError(
      /predates/,
    );
  });

  it("rejects CERT_EXPIRED when the signature postdates ledger expiry with no trusted TSA", () => {
    try {
      checkLedgerTimeBounds(ledgerArgs({ time: "2026-11-15T00:00:00Z" }));
      expect.unreachable("expected throw");
    } catch (e) {
      expect((e as { code: string }).code).toBe(VerifyErrorCode.CERT_EXPIRED);
      expect((e as { detail?: string }).detail).toMatch(/ledger expiry/);
    }
  });

  it("a trusted TSA lifts the post-expiry bound (C2PA §15.7 governs instead)", () => {
    expect(() =>
      checkLedgerTimeBounds(
        ledgerArgs({ time: "2026-11-15T00:00:00Z", tsaState: TRUSTED_TSA }),
      ),
    ).not.toThrow();
  });

  it("accepts when signature_info.time is absent (legacy untimestamped assets)", () => {
    // No time claim = nothing to bound; c2pa-rs's cert-chain check against
    // now remains binding. Production RealReel signs always embed sigTst2.
    expect(() => checkLedgerTimeBounds(ledgerArgs({ time: null }))).not.toThrow();
  });

  it("fails closed on unparseable ledger timestamps", () => {
    // NaN comparisons would silently disable both bounds — a broken custom
    // adapter must reject, not pass-open.
    expect(() =>
      checkLedgerTimeBounds(ledgerArgs({ issuedAt: "not-a-date" })),
    ).toThrowError(/unparseable/);
    expect(() =>
      checkLedgerTimeBounds(ledgerArgs({ expiresAt: "" })),
    ).toThrowError(/unparseable/);
  });

  it("supports the 90-day AL2 window as-is (per-leaf, no constant)", () => {
    // The gate reads whatever window the ledger recorded — a 90-day AL2
    // leaf needs no verifier-side configuration.
    const al2 = {
      issuedAt: "2026-08-01T00:00:00.000Z",
      expiresAt: "2026-10-30T00:00:00.000Z",
    };
    expect(() =>
      checkLedgerTimeBounds(ledgerArgs({ ...al2, time: "2026-09-15T00:00:00Z" })),
    ).not.toThrow();
    expect(() =>
      checkLedgerTimeBounds(ledgerArgs({ ...al2, time: "2026-11-05T00:00:00Z" })),
    ).toThrowError(/ledger expiry/);
  });
});
