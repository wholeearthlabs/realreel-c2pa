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
// Sources of truth elsewhere in the repo:
//   * APPLE_BUNDLE_ID:    app.config.ts ios.bundleIdentifier
//   * APPLE_TEAM_ID:      ios/RealReel.xcodeproj/project.pbxproj DEVELOPMENT_TEAM
//   * ANDROID_PACKAGE_NAME: app.config.ts android.package

export const APPLE_TEAM_ID = Deno.env.get("APPLE_TEAM_ID") ?? "7RPHYY66U6";
export const APPLE_BUNDLE_ID = Deno.env.get("APPLE_BUNDLE_ID") ?? "com.realreel.app";

// Apple App Attest's rpIdHash is SHA-256(<TeamID>.<BundleID>). NOT just the
// bundle identifier — that was a 30-minute debugging session. Don't change.
export const APPLE_APP_ID = `${APPLE_TEAM_ID}.${APPLE_BUNDLE_ID}`;

export const ANDROID_PACKAGE_NAME =
  Deno.env.get("ANDROID_PACKAGE_NAME") ?? "com.realreel.app";

// Whether to require the production App Attest environment AAGUID. Set false
// only if you intentionally want to accept attestations from Xcode-debug
// builds running against Apple's development attestation server. Production
// builds (TestFlight, App Store) always use the production AAGUID even with
// REQUIRE_PRODUCTION_APPATTEST = true.
export const REQUIRE_PRODUCTION_APPATTEST = true;

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
