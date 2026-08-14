// Time-bound cert-validity gates layered on top of c2pa-rs.
//
// c2pa-node (pinned on 0.5.5, re-verified on 0.8.0) does NOT surface
// cert.notBefore/notAfter (only
// signature_info.{issuer, common_name, cert_serial_number, time, alg}) —
// but for the RealReel-signed ACTIVE manifest we don't need the chain:
// the issued_certificates ledger records every leaf's actual validity
// window, keyed by the same cert_serial_number the Reader surfaces.
//
//   Gate 1 — Trusted-TSA-when-present (checkCertValidityTimeBounds). If
//   sigTst2 is embedded, the TSA cert chain MUST root to our TSA trust
//   pool. Catches revoked / compromised / untrusted TSA operators.
//
//   Gate 2 — Future-dated signature (checkCertValidityTimeBounds).
//   signature_info.time MUST NOT exceed `now` (with a small clock-skew
//   tolerance).
//
//   Gate 3 — Ledger-backed validity window (checkLedgerTimeBounds; runs
//   in the realreel profile after the Stage-2 ledger row is fetched, so
//   structural checks still precede any DB read). The claimed signing
//   time must not predate the leaf's ledger issuance (time-warp — a
//   trusted TSA time before issuance is just as damning) and, without a
//   trusted TSA, must not postdate its ledger expiry. Replaces the old
//   flat 180-day age ceiling that had to be hand-synced with the CA's
//   leaf validity — per-AL lifetimes (90d AL2 / 180d AL1) made a single
//   constant wrong by construction.

import { VerifyError, VerifyErrorCode } from "./errors.js";
import type {
  ManifestStoreShape,
  ManifestShape,
} from "./c2pa-shape.js";

/**
 * Trust state of any embedded sigTst2 timestamp on the active manifest.
 * Derived from c2pa-rs's `validation_results.activeManifest` codes,
 * which surface TSA chain-trust at the top level (NOT nested
 * per-manifest):
 *   - success contains `timeStamp.trusted` when the TSA chain validates
 *     against `trustAnchorsBundle`.
 *   - informational contains `timeStamp.untrusted` when the chain can't
 *     be rooted.
 *   - `timeStamp.validated` (digest binding correct) lives in success
 *     in both cases — independent of chain trust.
 */
export interface TsaState {
  /** True if a sigTst2 token is present (any `timeStamp.*` code appears
   * in success / informational / failure). */
  hasStamp: boolean;
  /** True iff `timeStamp.trusted` appears in success — chain validated
   * to our TSA trust pool. */
  trusted: boolean;
}

const TIMESTAMP_CODE_PREFIX = "timeStamp.";
const TIMESTAMP_TRUSTED_CODE = "timeStamp.trusted";

/**
 * Read TSA trust verdict from the c2pa-node Reader output. Pure
 * function over the raw ManifestStore shape; MUST be called BEFORE
 * sanitize.ts drops the validation_results field.
 */
export function readTsaState(store: ManifestStoreShape): TsaState {
  // The narrowed ManifestStoreShape doesn't model validation_results — it's
  // c2pa-rs runtime output the rest of the verifier doesn't touch. Cast through.
  const vr = (
    store as ManifestStoreShape & {
      validation_results?: {
        activeManifest?: {
          success?: Array<{ code: string }>;
          informational?: Array<{ code: string }>;
          failure?: Array<{ code: string }>;
        };
      };
    }
  ).validation_results?.activeManifest;

  const success = vr?.success ?? [];
  const informational = vr?.informational ?? [];
  const failure = vr?.failure ?? [];

  const allCodes = [...success, ...informational, ...failure].map(
    (c) => c.code,
  );
  const hasStamp = allCodes.some((c) => c.startsWith(TIMESTAMP_CODE_PREFIX));
  const trusted = success.some((c) => c.code === TIMESTAMP_TRUSTED_CODE);

  return { hasStamp, trusted };
}

/**
 * Parse signature_info.time from the active manifest. C2PA surfaces
 * this as an ISO-8601 string (e.g. `"2026-05-28T16:31:37+00:00"`). When
 * sigTst2 is present, c2pa-rs populates it from the TSA token's
 * `genTime`; without sigTst2 it's the claim's internal signature time.
 *
 * Returns null when the field is missing or unparseable. Legacy manifests
 * (no sigTst2, no claim-internal time) hit this; Gate 3 then treats the
 * asset as legacy-acceptable and defers to c2pa-rs's cert-chain check
 * against `now`.
 */
export function readSignatureTime(active: ManifestShape): Date | null {
  const t = active.signature_info?.time;
  if (typeof t !== "string") return null;
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Clock-skew tolerance for Gate 2. Capture devices' wall clocks drift;
 * 5 minutes is conventional (RFC 3161 implementations use similar
 * bounds). Without tolerance, a CI run mere seconds before a fresh
 * fixture's signature time would flag it as future-dated.
 */
export const CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000;

/** Clock indirection so tests can inject a fixed `now`. */
export interface Clock {
  now(): Date;
}

/** Production clock — real wall-clock. */
export const SYSTEM_CLOCK: Clock = { now: () => new Date() };

export interface CertValidityArgs {
  active: ManifestShape;
  tsaState: TsaState;
  clock: Clock;
}

/**
 * Run the two DB-free time-bound gates on the active manifest. Throws
 * VerifyError on the first failed gate; returns void on accept. Gate 3
 * (the ledger-backed validity window) is checkLedgerTimeBounds below,
 * called from the realreel profile once the Stage-2 ledger row is in hand.
 *
 * NOT implemented:
 *   - `claim_time > TSA.genTime` distinct from genTime — c2pa-rs populates
 *     signature_info.time from the TSA token when sigTst2 is present, so the
 *     two collapse.
 *   - As-of-TSA-time cert-validity override of c2pa-rs's expired signal — we
 *     trust c2pa-rs's C2PA §15.7 implementation under
 *     verifyTimestampTrust:true.
 *
 * Backdating inside the cert validity window remains an accepted residual.
 */
export function checkCertValidityTimeBounds(args: CertValidityArgs): void {
  const { active, tsaState, clock } = args;
  const now = clock.now();

  // Gate 1 — Trusted-TSA-when-present.
  if (tsaState.hasStamp && !tsaState.trusted) {
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      "embedded sigTst2 token has an untrusted chain — TSA cert chain " +
        "did not root to any configured TSA trust anchor",
    );
  }

  const signatureTime = readSignatureTime(active);

  // Gate 2 — Future-dated. With a small clock-skew tolerance so a CI
  // run a few seconds before a fresh fixture's signature time doesn't
  // trip. An absent signature time skips this AND the ledger gate — an
  // untimestamped legacy asset has no time claim to bound.
  if (
    signatureTime !== null &&
    signatureTime.getTime() > now.getTime() + CLOCK_SKEW_TOLERANCE_MS
  ) {
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      `signature_info.time (${signatureTime.toISOString()}) is in the ` +
        `future relative to now (${now.toISOString()})`,
    );
  }
}

/**
 * Tolerance for the time-warp bound: the CA backdates notBefore 5 minutes
 * for device clock skew, and issued_at is the ledger's own write time, so a
 * legitimate first-signature can slightly precede it. 5-min backdate +
 * 5-min skew.
 */
export const ISSUANCE_TOLERANCE_MS = 10 * 60 * 1000;

export interface LedgerTimeBoundsArgs {
  active: ManifestShape;
  tsaState: TsaState;
  /** issued_at / expires_at from the Stage-2 leaf's issued_certificates
   * ledger row, as the ISO strings the lookup projects. */
  issuedAt: string;
  expiresAt: string;
}

/**
 * Gate 3 — bound the claimed signing time by the Stage-2 leaf's ACTUAL
 * validity window, as recorded in the issued_certificates ledger at
 * issuance. Runs in the realreel profile right after the Stage-2 row
 * gates (so structural checks still precede any DB read).
 *
 * Missing signature_info.time = legacy untimestamped asset: accept and
 * lean on c2pa-rs's cert-chain check against `now` — with no time claim
 * there is nothing to bound. Production RealReel signs always embed
 * sigTst2, so real uploads reach this gate with a trusted TSA time.
 */
export function checkLedgerTimeBounds(args: LedgerTimeBoundsArgs): void {
  const { active, tsaState } = args;

  const issuedAt = new Date(args.issuedAt);
  const expiresAt = new Date(args.expiresAt);
  if (Number.isNaN(issuedAt.getTime()) || Number.isNaN(expiresAt.getTime())) {
    // Fail closed: an adapter projecting unparseable timestamps would
    // otherwise disable both bounds (NaN comparisons are false).
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      `ledger row carries unparseable validity timestamps ` +
        `(issued_at='${args.issuedAt}', expires_at='${args.expiresAt}')`,
    );
  }

  const signatureTime = readSignatureTime(active);
  if (signatureTime === null) return;

  // Time-warp: the signature claims to predate the leaf's issuance. A
  // trusted TSA makes this MORE damning, not less — a genuine timestamp
  // from before we minted the cert can't be explained by clock skew.
  if (signatureTime.getTime() < issuedAt.getTime() - ISSUANCE_TOLERANCE_MS) {
    throw new VerifyError(
      VerifyErrorCode.SIGNATURE_INVALID,
      `signature_info.time (${signatureTime.toISOString()}) predates the ` +
        `signing cert's ledger issuance (${issuedAt.toISOString()})`,
    );
  }

  // Post-expiry claim without a trusted TSA: we cannot establish the cert
  // was valid at the claimed signing time. With a trusted TSA, c2pa-rs's
  // C2PA §15.7 handling already judged validity as of the stamped time.
  if (
    !tsaState.trusted &&
    signatureTime.getTime() > expiresAt.getTime() + CLOCK_SKEW_TOLERANCE_MS
  ) {
    throw new VerifyError(
      VerifyErrorCode.CERT_EXPIRED,
      `signature_info.time (${signatureTime.toISOString()}) is after the ` +
        `signing cert's ledger expiry (${expiresAt.toISOString()}) and ` +
        `carries no trusted TSA stamp`,
    );
  }
}
