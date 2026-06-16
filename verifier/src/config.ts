// Centralized env-var parsing. Validated at startup so the process
// fails fast on misconfiguration rather than crashing on the first
// request.

import { DEFAULT_CERT_LIFETIME_MS } from "./cert-validity.js";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return v;
}

function compileHostRegex(pattern: string): RegExp {
  try {
    return new RegExp(pattern);
  } catch (e) {
    throw new Error(
      `Invalid ASSET_STORAGE_HOST_REGEX: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

const DEFAULT_MAX_ASSET_MIB = 50;
// Sanity ceiling — above this a fat-fingered value would OOM the instance.
const MAX_ASSET_MIB_CEILING = 512;

function parseMaxAssetBytes(raw: string | undefined): number {
  if (!raw?.trim()) return DEFAULT_MAX_ASSET_MIB * 1024 * 1024;
  const mib = Number(raw);
  if (!Number.isFinite(mib) || mib <= 0 || mib > MAX_ASSET_MIB_CEILING) {
    throw new Error(
      `Invalid MAX_ASSET_MIB: ${raw} (must be a positive number of MiB ≤ ${MAX_ASSET_MIB_CEILING})`,
    );
  }
  return Math.floor(mib * 1024 * 1024);
}

function parseHostAllowlist(raw: string | undefined): Set<string> {
  if (!raw || raw.trim().length === 0) {
    throw new Error(
      "Missing required env var: ASSET_STORAGE_HOST_ALLOWLIST (comma-separated hosts; see config.ts)",
    );
  }
  const hosts = raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter((h) => h.length > 0);
  if (hosts.length === 0) {
    throw new Error(
      "ASSET_STORAGE_HOST_ALLOWLIST parsed to zero hosts — refusing to start with no allowlisted hosts",
    );
  }
  return new Set(hosts);
}

export interface Config {
  /** TCP port to bind Fastify to. Cloud Run sets PORT=8080. */
  port: number;

  /** Absolute path to trust-sources.yaml. Default: ./trust-sources.yaml. */
  trustSourcesPath: string;

  /** Bearer secret the edge function shares with us. Must be a non-empty
   * string; timing-safe compared in the onRequest hook. */
  sharedSecret: string;

  /** Postgres connection string for verifier_readonly. Targets PgBouncer
   * (port 6543) in production for transaction-mode pooling. */
  databaseUrl: string;

  /** RegExp the signedUrl must match before we fetch it. First layer
   * of SSRF defense — even with bearer auth, we never fetch URLs that
   * aren't asset-storage signed-URL shapes (typically Supabase Storage). */
  assetStorageHostRegex: RegExp;

  /** Explicit host allowlist checked AFTER the regex passes. Strips
   * userinfo and other URL quirks via `new URL(...).host`, then
   * Set.has() — no string-substring matching, no false positives. The
   * regex catches gross shape problems; this set is the authoritative
   * "may fetch from this host" decision. */
  assetStorageHostAllowlist: Set<string>;

  /** Max asset size (bytes) the verifier will fetch + buffer for a /verify
   *  call; content-length is checked against it before the body is read.
   *  Env-overridable via `MAX_ASSET_MIB` (MiB), default 50. Keep >= the app
   *  `media` bucket's file_size_limit, else legit uploads in the gap band are
   *  rejected here as oversize. */
  maxAssetBytes: number;

  /** Optional Sentry DSN. If unset, Sentry init is skipped (local dev). */
  sentryDsn: string | undefined;

  /** Production vs dev — controls logger format and Sentry init. */
  isProduction: boolean;

  /** Android Play Integrity verifier config. When ANY field is set, both
   *  `packageName` and `cloudProjectNumber` must be set together — partial
   *  config is a misconfiguration and loadConfig() throws. When all unset,
   *  the verifier accepts Android manifests carrying the assertion
   *  structurally but skips the JWS decode (lenient-degraded). */
  playIntegrity: PlayIntegrityConfig | undefined;

  /** Cert-lifetime ceiling (ms) for the required-TSA gate. When
   *  `now - signature_info.time` exceeds this AND no trusted sigTst2 stamp is
   *  embedded, the verifier rejects with CERT_EXPIRED — past this age we
   *  can't establish the leaf cert was valid at signing without a timestamp.
   *
   *  Always `DEFAULT_CERT_LIFETIME_MS` (180d). This constant and the CA's
   *  LEAF_VALIDITY_DAYS MUST stay in sync; there's no programmatic drift
   *  check (the verifier doesn't parse cert.notAfter from the x5chain). */
  certLifetimeMs: number;

  /** Strict require-presence of Stage 2 upload-time attestation per
   *  signing key's platform. When true:
   *    - iOS-platform signing keys (`user_signing_keys.platform = 'ios'`)
   *      MUST carry `org.realreel.app_attest` on Stage 2.
   *    - Android-platform keys (`android-strongbox` or `android-tee`)
   *      MUST carry `org.realreel.play_integrity` on Stage 2 AND
   *      playIntegrity config above must be set so we can validate it.
   *  When false (default), the lenient gate applies: validate-if-present,
   *  accept-if-absent.
   *
   *  Local dev verifier leaves this unset → lenient. Production sets it
   *  to "true" → strict per-platform requirements. Setting this with
   *  playIntegrity unset is a startup error (you can't require an envelope
   *  you can't decode). */
  attestationRequired: boolean;
}

export interface PlayIntegrityConfig {
  /** Android package name issued the token (`com.realreel.app` in prod).
   *  Cross-checked against tokenPayloadExternal.requestDetails.requestPackageName
   *  by the verifier — mismatch is a tampered or misrouted token. */
  packageName: string;
  /** Google Cloud project number that issues Play Integrity tokens for
   *  this build. Used as the path segment in the decodeIntegrityToken
   *  URL: `https://playintegrity.googleapis.com/v1/<packageName>:decodeIntegrityToken`.
   *  Must match the value the Android module passes to
   *  StandardIntegrityManager at token-request time. */
  cloudProjectNumber: string;
}

export function loadConfig(): Config {
  const isProduction = process.env.NODE_ENV === "production";

  const portRaw = process.env.PORT ?? "8080";
  const port = parseInt(portRaw, 10);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid PORT: ${portRaw} (must be a positive integer ≤ 65535)`);
  }

  const playIntegrity = loadPlayIntegrityConfig();
  const attestationRequired = parseAttestationRequired(playIntegrity, isProduction);
  // Not env-overridable: lives in one place so it can't drift from the CA's
  // LEAF_VALIDITY_DAYS.
  const certLifetimeMs = DEFAULT_CERT_LIFETIME_MS;

  return {
    port,
    trustSourcesPath: process.env.TRUST_SOURCES_PATH ?? "./trust-sources.yaml",
    sharedSecret: requireEnv("VERIFIER_SHARED_SECRET"),
    databaseUrl: requireEnv("DATABASE_URL"),
    assetStorageHostRegex: compileHostRegex(
      requireEnv("ASSET_STORAGE_HOST_REGEX"),
    ),
    assetStorageHostAllowlist: parseHostAllowlist(
      process.env.ASSET_STORAGE_HOST_ALLOWLIST,
    ),
    maxAssetBytes: parseMaxAssetBytes(process.env.MAX_ASSET_MIB),
    sentryDsn: process.env.SENTRY_DSN,
    isProduction,
    playIntegrity,
    attestationRequired,
    certLifetimeMs,
  };
}

function parseAttestationRequired(
  playIntegrity: PlayIntegrityConfig | undefined,
  isProduction: boolean,
): boolean {
  const raw = process.env.ATTESTATION_REQUIRED;
  // Fail CLOSED on ambiguity in production. ATTESTATION_REQUIRED is the
  // single most safety-critical setting: when lenient, the verifier accepts
  // uploads carrying NO attestation. An unset or typo'd value used to fall
  // through to lenient silently — so a forgotten env var or a shell typo
  // ("ATTESTAION_REQUIRED", "True", "1") would boot production wide open.
  // In production we therefore demand the literal "true" or "false"
  // explicitly; anything else throws at startup so the operator must make a
  // conscious choice. Non-production keeps the lenient-by-default behavior
  // (local dev / the Makefile target leave it unset on purpose).
  if (isProduction && raw !== "true" && raw !== "false") {
    throw new Error(
      `ATTESTATION_REQUIRED must be explicitly "true" or "false" in production ` +
        `(got ${raw === undefined ? "(unset)" : `'${raw}'`}). This is the ` +
        `single most safety-critical verifier setting: when lenient the ` +
        `verifier accepts uploads with no attestation, so production must ` +
        `fail closed on an ambiguous value rather than silently default to ` +
        `lenient. Set ATTESTATION_REQUIRED=true for strict per-platform ` +
        `enforcement, or =false to deliberately accept the lenient gate.`,
    );
  }
  // Only the literal "true" enables strict mode; anything else (including an
  // empty string from `export ATTESTATION_REQUIRED=`, or a deliberate
  // "false") is permissive.
  if (raw !== "true") return false;
  // Strict mode requires the Play Integrity decode path so we can validate
  // Android Stage 2 tokens; without it every Android upload would be
  // rejected. Surface the config bug at startup rather than at request time.
  if (!playIntegrity) {
    throw new Error(
      "ATTESTATION_REQUIRED=true but Play Integrity config is unset. " +
        "Set PLAY_INTEGRITY_PACKAGE_NAME and PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER " +
        "together with ATTESTATION_REQUIRED, or leave all three unset for " +
        "dev / lenient mode.",
    );
  }
  return true;
}

function loadPlayIntegrityConfig(): PlayIntegrityConfig | undefined {
  const pkg = process.env.PLAY_INTEGRITY_PACKAGE_NAME;
  const proj = process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER;
  if (!pkg && !proj) return undefined;
  if (!pkg || !proj) {
    throw new Error(
      "Play Integrity config partially set: both PLAY_INTEGRITY_PACKAGE_NAME and " +
        "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER must be set together (or neither). " +
        "With neither set, the verifier accepts Android manifests leniently " +
        "(structural envelope only, no JWS decode).",
    );
  }
  return { packageName: pkg, cloudProjectNumber: proj };
}
