// ===== PER-APP SWAP-POINT: published app identity used by attestation =====
//
// A fork MUST replace these with its own app identity. They are NOT secrets —
// they're public app identifiers visible to anyone who downloads the published
// binary or inspects the App Store / Play Store listing:
//
//   * APPLE_TEAM_ID is embedded in every code-signed iOS app
//     (`codesign -d -vv RealReel.app` reveals it).
//   * APPLE_BUNDLE_ID and ANDROID_PACKAGE_NAME appear in the App Store /
//     Play Store listings and in every IPA's Info.plist / APK's manifest.
//
// Sourced from env when present so a forker can override per-deployment without
// editing code; the defaults below are RealReel's, so the test suite and the
// standard deploy run with no env set. These MUST stay in lockstep with the
// verifier-side copy in `verifier/src/attestation/apple.ts` (the verifier is a
// separate Node project and can't import this Deno code). Changing them
// invalidates every already-enrolled key whose attestation bound the old
// identity — there is no migration path.
//
// The ONE runtime exception is a local-dev relaxation (`resolveDevAttestation`
// below): a local `make dev` stack may accept the `<package>.dev` bundle id —
// the local debug / dev-client build — so it can enroll and upload against your
// own machine. It is hard-gated: honored ONLY with an explicit opt-in AND a
// SUPABASE_URL whose host is a recognized LOCAL one; if the opt-in is set
// against any non-local URL (a hosted project OR a custom domain) it throws.
// Production is unaffected (uses the canonical pins) and fails CLOSED on
// misconfiguration.
//
// Sources of truth elsewhere (RealReel app repo):
//   * APPLE_BUNDLE_ID:    app.config.ts ios.bundleIdentifier
//   * APPLE_TEAM_ID:      ios/RealReel.xcodeproj/project.pbxproj DEVELOPMENT_TEAM
//   * ANDROID_PACKAGE_NAME: app.config.ts android.package

export const APPLE_TEAM_ID = Deno.env.get("APPLE_TEAM_ID") ?? "7RPHYY66U6";

/** Resolved app-identity pins for the active environment. */
export interface DevAttestationPins {
  appleBundleId: string;
  androidPackageName: string;
  /** Whether to require the production App Attest AAGUID. False only on a gated
   *  local stack, so a dev-signed build (development env) can enroll. */
  requireProductionAppAttest: boolean;
}

// Hosts the local `make dev` stack injects into an edge function's SUPABASE_URL.
// The Supabase CLI uses the docker-internal `http://kong:8000`; the rest cover
// alternate local setups. This is a POSITIVE allowlist, deliberately NOT "any
// URL lacking supabase.co": a Supabase CUSTOM DOMAIN carries no
// `supabase.co` token, so a denylist would read it as local and fail OPEN.
const LOCAL_SUPABASE_HOST =
  /^https?:\/\/(?:127\.0\.0\.1|localhost|kong|host\.docker\.internal)(?::\d+)?(?:\/|$)/i;

/**
 * Resolve the app-identity pins, applying the local-dev attestation relaxation
 * (see the header note) when — and ONLY when — BOTH hold:
 *   1. ALLOW_DEV_BUILD_ATTESTATION=true (explicit opt-in), and
 *   2. SUPABASE_URL's host is a recognized LOCAL one (positive match above).
 * If the opt-in is set against any non-local URL (a hosted project, a custom
 * domain, or an unset/odd URL) we THROW — production fails CLOSED rather than
 * relaxing off-local. Takes `env` as a parameter (mirrors auth.ts) so the gate
 * is directly unit-testable.
 *
 * The relaxed identity is the canonical one with a `.dev` suffix — the
 * convention the RealReel dev-client build uses; a fork's dev build should
 * follow the same `<package>.dev` shape (or skip the opt-in entirely).
 */
export function resolveDevAttestation(
  env: (name: string) => string | undefined = (n) => Deno.env.get(n),
): DevAttestationPins {
  const appleBase = env("APPLE_BUNDLE_ID") ?? "com.realreel.app";
  const androidBase = env("ANDROID_PACKAGE_NAME") ?? "com.realreel.app";
  const optIn = env("ALLOW_DEV_BUILD_ATTESTATION") === "true";
  const supabaseUrl = env("SUPABASE_URL") ?? "";
  const isLocal = LOCAL_SUPABASE_HOST.test(supabaseUrl);
  if (optIn && !isLocal) {
    throw new Error(
      "ALLOW_DEV_BUILD_ATTESTATION is set but SUPABASE_URL is not a recognized " +
        `local stack (${supabaseUrl || "(unset)"}). This flag relaxes device ` +
        "attestation and is for `make dev` only — refusing off-local.",
    );
  }
  const relax = optIn && isLocal;
  return {
    appleBundleId: relax ? `${appleBase}.dev` : appleBase,
    androidPackageName: relax ? `${androidBase}.dev` : androidBase,
    requireProductionAppAttest: !relax,
  };
}

const _pins = resolveDevAttestation();

// Canonical app identifiers — the secure default everywhere, and the only
// values production ever uses. The local-dev gate swaps in the `.dev` variants.
export const APPLE_BUNDLE_ID = _pins.appleBundleId;

// Apple App Attest's rpIdHash is SHA-256(<TeamID>.<BundleID>). NOT just the
// bundle identifier — that was a 30-minute debugging session. Don't change.
export const APPLE_APP_ID = `${APPLE_TEAM_ID}.${APPLE_BUNDLE_ID}`;

export const ANDROID_PACKAGE_NAME = _pins.androidPackageName;

// Whether to require the production App Attest environment AAGUID. Set false
// only if you intentionally want to accept attestations from Xcode-debug
// builds running against Apple's development attestation server. Production
// builds (TestFlight, App Store) always use the production AAGUID even with
// REQUIRE_PRODUCTION_APPATTEST = true. The local-dev gate drops it to false so a
// dev-signed build (development App Attest environment) can enroll locally.
export const REQUIRE_PRODUCTION_APPATTEST = _pins.requireProductionAppAttest;

// Maximum length for a user_signing_keys.key_id passed in an edge-function
// request body (revoke-signing-key, register-signing-key supersedeKeyId).
// The server-issued canonical key_id is SHA-256(SE_SPKI) → base64 = 44 chars;
// 128 leaves ~3× margin without enabling large-body abuse vectors. Lifted
// into _shared so a future change to the canonical form propagates to both
// edge functions without drift.
export const MAX_SIGNING_KEY_ID_CHARS = 128;

// Android enrollment patch-gate.
//
// At register-signing-key, reject Android attestations whose leaf-cert
// osPatchLevel is older than (now - ANDROID_MIN_PATCH_LOOKBACK_MONTHS). A
// rolling window self-adjusts and matches Google's "12-month security
// bulletin coverage" SLA for OEMs.
//
// osPatchLevel is a Keymaster `INTEGER` encoded as YYYYMM (e.g. 202501 =
// January 2025), stored in the AuthorizationList of the leaf's Android Key
// Attestation extension. Some legacy / non-conformant builds emit YYYYMMDD —
// the validator normalizes to YYYYMM before comparison.
//
// iOS has no equivalent patch signal (the App Attest assertion carries no OS
// version), so iOS enrollment has no patch-gate.
//
// A config CONSTANT, not env — rotation is a code edit + redeploy (same as
// APPLE_TEAM_ID), which is intentional friction so a misclick can't unblock
// stale firmware.
export const ANDROID_MIN_PATCH_LOOKBACK_MONTHS = 12;
