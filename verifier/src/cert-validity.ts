// Time-bound cert-validity gates layered on top of c2pa-rs.
//
// c2pa-node v0.5.5 does NOT surface cert.notBefore/notAfter (only
// signature_info.{issuer, common_name, cert_serial_number, time, alg}), so
// gates that need those (e.g. `claim_time < cert.notBefore`) would require
// manual JUMBF → COSE → x5chain parsing and are skipped. Backdating inside
// the cert validity window is therefore an accepted residual.
//
// What we DO enforce, from existing Reader output:
//
//   Gate 1 — Trusted-TSA-when-present. If sigTst2 is embedded, the TSA cert
//   chain MUST root to our TSA trust pool. Catches revoked / compromised /
//   untrusted TSA operators.
//
//   Gate 2 — Future-dated signature. signature_info.time MUST NOT exceed
//   `now` (with a small clock-skew tolerance).
//
//   Gate 3 — TSA required for old assets. Without a trusted TSA stamp, the
//   signature must not be older than DEFAULT_CERT_LIFETIME_MS. Inside that
//   window c2pa-rs's signingCredential.expired check (against now) is
//   binding; past it we can't establish the cert was valid at signing
//   without a timestamp.
//
// The cert-lifetime ceiling is a flat code constant (DEFAULT_CERT_LIFETIME_MS
// below), NOT env-overridable, kept in sync with the CA's LEAF_VALIDITY_DAYS
// by hand — there is no programmatic drift check (we don't read cert.notAfter
// from the manifest).

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
  const t = (active.signature_info as { time?: string } | undefined)?.time;
  if (typeof t !== "string") return null;
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Default cert-lifetime ceiling for Gate 3 (180 days). MUST stay in sync
 * with the CA's LEAF_VALIDITY_DAYS
 * (ca/register-signing-key/index.ts) — there's no
 * programmatic drift check, and it is NOT env-overridable.
 *
 * A flat constant rather than a per-cert lookup because c2pa-node doesn't
 * surface cert.notBefore/notAfter. The gate's only role is to require a TSA
 * stamp on truly old assets, not to do precise cert-validity math, so a leaf
 * signed under a different lifetime still being measured against this
 * constant is acceptable.
 */
export const DEFAULT_CERT_LIFETIME_MS = 180 * 24 * 60 * 60 * 1000;

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
  /** Cert-lifetime ceiling for Gate 3 (ms). */
  certLifetimeMs: number;
}

/**
 * Run the three time-bound gates on the active manifest. Throws VerifyError
 * on the first failed gate; returns void on accept.
 *
 * NOT implemented:
 *   - `claim_time < cert.notBefore` (issuer time-warp) — needs
 *     cert.notBefore, which c2pa-node doesn't expose.
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
  const { active, tsaState, clock, certLifetimeMs } = args;
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
  // trip. Skip when signature time is absent — Gate 3 handles that
  // case for the no-trusted-TSA branch.
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

  // Gate 3 — TSA required for old assets. Only meaningful when no trusted
  // TSA stamp is present AND the manifest carries a signature time. Inside
  // the cert-lifetime window c2pa-rs's own signingCredential.expired check
  // (against now) is sufficient.
  //
  // Missing signature_info.time + no trusted TSA = legacy asset. Production
  // RealReel signs always embed sigTst2 (the app's TSA client with its
  // TSA fallback), so they reach this gate with a TSA and Gate 3 is skipped via the
  // !trusted branch. We accept and lean on c2pa-rs's cert-chain check (which
  // already ran against now, surfaced via validation_status →
  // classifyStrictValidationStatus). The required-TSA gate only adds
  // protection when the manifest itself CLAIMS to be older than cert
  // lifetime; with no time claim there's nothing to validate against.
  if (!tsaState.trusted && signatureTime !== null) {
    const age = now.getTime() - signatureTime.getTime();
    if (age > certLifetimeMs) {
      const ageDays = Math.floor(age / 86_400_000);
      const limitDays = Math.floor(certLifetimeMs / 86_400_000);
      throw new VerifyError(
        VerifyErrorCode.CERT_EXPIRED,
        `signature is older than the cert-lifetime ceiling ` +
          `(${ageDays} days > ${limitDays} days) and carries no trusted ` +
          `TSA stamp — cannot verify the cert was valid at signing time`,
      );
    }
  }
}
