// Tests for the verifier startup config matrix.
//
// The verifier deliberately fails fast at startup on inconsistent
// env-var combinations (PLAY_INTEGRITY_* partial set, ATTESTATION_REQUIRED
// without playIntegrity creds, etc.) rather than crashing on the first
// /verify request. Without these tests, a future regression that
// loosened the validation would silently let production boot in a
// broken state where every Android upload fails ATTESTATION_MISSING.
//
// See verifier/DEPLOY.md § "What each combination means" for the matrix.

import { describe, it, expect, beforeEach, afterEach } from "vitest";

import { loadConfig } from "../src/config.js";
import { DEFAULT_CERT_LIFETIME_MS } from "../src/cert-validity.js";

// Snapshot the env vars we mutate so each test starts from a clean
// process.env. Restoring after each test avoids cross-test pollution
// when vitest runs files in shared workers.
const TOUCHED_ENV_VARS = [
  "NODE_ENV",
  "PORT",
  "VERIFIER_SHARED_SECRET",
  "DATABASE_URL",
  "ASSET_STORAGE_HOST_REGEX",
  "ASSET_STORAGE_HOST_ALLOWLIST",
  "SENTRY_DSN",
  "TRUST_SOURCES_PATH",
  "PLAY_INTEGRITY_PACKAGE_NAME",
  "PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
  "ATTESTATION_REQUIRED",
  "MAX_ASSET_MIB",
] as const;

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = {};
  for (const k of TOUCHED_ENV_VARS) savedEnv[k] = process.env[k];
  // Wipe everything we touch — each test sets exactly what it needs.
  for (const k of TOUCHED_ENV_VARS) delete process.env[k];
});

afterEach(() => {
  for (const k of TOUCHED_ENV_VARS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

/** The minimum env set every loadConfig() call needs to get past the
 *  required-env checks before reaching the matrix branch under test. */
function withMinimumValidEnv(): void {
  process.env.VERIFIER_SHARED_SECRET = "dev-shared-secret-not-for-prod";
  process.env.DATABASE_URL = "postgresql://x:y@127.0.0.1:54322/postgres";
  process.env.ASSET_STORAGE_HOST_REGEX =
    "^https?://(127\\.0\\.0\\.1|localhost):54321/storage/v1/object/sign/";
  process.env.ASSET_STORAGE_HOST_ALLOWLIST = "127.0.0.1:54321";
}

// ---------------------------------------------------------------
// Play Integrity + ATTESTATION_REQUIRED matrix
// ---------------------------------------------------------------

describe("loadConfig — Play Integrity + ATTESTATION_REQUIRED matrix", () => {
  it("local-dev posture: neither playIntegrity nor ATTESTATION_REQUIRED set → both undefined/false", () => {
    withMinimumValidEnv();
    const config = loadConfig();
    expect(config.playIntegrity).toBeUndefined();
    expect(config.attestationRequired).toBe(false);
  });

  it("production posture: playIntegrity + ATTESTATION_REQUIRED=true → strict mode", () => {
    withMinimumValidEnv();
    process.env.PLAY_INTEGRITY_PACKAGE_NAME = "com.realreel.app";
    process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER = "874158087818";
    process.env.ATTESTATION_REQUIRED = "true";
    const config = loadConfig();
    expect(config.playIntegrity).toEqual({
      packageName: "com.realreel.app",
      cloudProjectNumber: "874158087818",
    });
    expect(config.attestationRequired).toBe(true);
  });

  it("lenient-decode: playIntegrity set but ATTESTATION_REQUIRED unset → decode runs, presence not enforced", () => {
    // Useful for testing Google's decode + verdict enforcement against
    // real credentials without locking out unattested uploads.
    withMinimumValidEnv();
    process.env.PLAY_INTEGRITY_PACKAGE_NAME = "com.realreel.app";
    process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER = "874158087818";
    const config = loadConfig();
    expect(config.playIntegrity).toEqual({
      packageName: "com.realreel.app",
      cloudProjectNumber: "874158087818",
    });
    expect(config.attestationRequired).toBe(false);
  });

  // ----- partial Play Integrity config: refuse to start -----

  it("startup error: PLAY_INTEGRITY_PACKAGE_NAME set, CLOUD_PROJECT_NUMBER unset", () => {
    withMinimumValidEnv();
    process.env.PLAY_INTEGRITY_PACKAGE_NAME = "com.realreel.app";
    expect(() => loadConfig()).toThrow(/Play Integrity config partially set/);
  });

  it("startup error: PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER set, PACKAGE_NAME unset", () => {
    withMinimumValidEnv();
    process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER = "874158087818";
    expect(() => loadConfig()).toThrow(/Play Integrity config partially set/);
  });

  // ----- ATTESTATION_REQUIRED=true requires playIntegrity creds -----

  it("startup error: ATTESTATION_REQUIRED=true without any Play Integrity config", () => {
    withMinimumValidEnv();
    process.env.ATTESTATION_REQUIRED = "true";
    expect(() => loadConfig()).toThrow(
      /ATTESTATION_REQUIRED=true but Play Integrity config is unset/,
    );
  });

  it("startup error: ATTESTATION_REQUIRED=true with partial playIntegrity (package only)", () => {
    // The partial-playIntegrity throw fires first, before
    // parseAttestationRequired's consistency check. The error
    // message should still surface the playIntegrity problem so the
    // operator fixes it before re-running with ATTESTATION_REQUIRED.
    withMinimumValidEnv();
    process.env.PLAY_INTEGRITY_PACKAGE_NAME = "com.realreel.app";
    process.env.ATTESTATION_REQUIRED = "true";
    expect(() => loadConfig()).toThrow(/Play Integrity config partially set/);
  });

  // ----- ATTESTATION_REQUIRED truthy-vs-literal-true -----

  it("ATTESTATION_REQUIRED=1 is treated as off (only literal 'true' enables strict)", () => {
    // Documented convention: defends against shell assignments where
    // the variable is non-empty but not literally "true". A future
    // regression that loosened this to truthy coercion would silently
    // accept misconfig.
    withMinimumValidEnv();
    process.env.ATTESTATION_REQUIRED = "1";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(false);
  });

  it("ATTESTATION_REQUIRED=yes is treated as off", () => {
    withMinimumValidEnv();
    process.env.ATTESTATION_REQUIRED = "yes";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(false);
  });

  it("ATTESTATION_REQUIRED='' (empty string) is treated as off", () => {
    // `export ATTESTATION_REQUIRED=` in a shell leaves the variable
    // defined but empty — must not be misread as truthy.
    withMinimumValidEnv();
    process.env.ATTESTATION_REQUIRED = "";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(false);
  });

  it("ATTESTATION_REQUIRED=false is treated as off", () => {
    withMinimumValidEnv();
    process.env.ATTESTATION_REQUIRED = "false";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(false);
  });
});

// ---------------------------------------------------------------
// ATTESTATION_REQUIRED — fail-closed-on-ambiguity in production
// ---------------------------------------------------------------
//
// In production this is the single most safety-critical setting: when
// lenient, the verifier accepts uploads carrying no attestation. So prod
// must NOT silently fall through to lenient on an unset/typo'd value — it
// throws at startup, forcing an explicit "true" or "false".

describe("loadConfig — ATTESTATION_REQUIRED fail-closed in production", () => {
  it("throws when ATTESTATION_REQUIRED is unset in production (fail closed on ambiguity)", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "production";
    // ATTESTATION_REQUIRED intentionally unset.
    expect(() => loadConfig()).toThrow(
      /ATTESTATION_REQUIRED must be explicitly "true" or "false" in production/,
    );
  });

  it("throws when ATTESTATION_REQUIRED is an ambiguous value in production (e.g. '1')", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "production";
    process.env.ATTESTATION_REQUIRED = "1";
    expect(() => loadConfig()).toThrow(
      /ATTESTATION_REQUIRED must be explicitly "true" or "false" in production/,
    );
  });

  it("throws when ATTESTATION_REQUIRED is empty string in production", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "production";
    process.env.ATTESTATION_REQUIRED = "";
    expect(() => loadConfig()).toThrow(
      /ATTESTATION_REQUIRED must be explicitly "true" or "false" in production/,
    );
  });

  it("accepts explicit ATTESTATION_REQUIRED=false in production (lenient by choice)", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "production";
    process.env.ATTESTATION_REQUIRED = "false";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(false);
    expect(config.isProduction).toBe(true);
  });

  it("accepts explicit ATTESTATION_REQUIRED=true in production (with Play Integrity creds)", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "production";
    process.env.PLAY_INTEGRITY_PACKAGE_NAME = "com.realreel.app";
    process.env.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER = "874158087818";
    process.env.ATTESTATION_REQUIRED = "true";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(true);
    expect(config.isProduction).toBe(true);
  });

  it("does NOT require explicit ATTESTATION_REQUIRED outside production (lenient-by-default)", () => {
    // Non-production keeps today's behavior: unset → lenient, no throw.
    withMinimumValidEnv();
    process.env.NODE_ENV = "development";
    const config = loadConfig();
    expect(config.attestationRequired).toBe(false);
    expect(config.isProduction).toBe(false);
  });
});

// ---------------------------------------------------------------
// Required-env enforcement
// ---------------------------------------------------------------

describe("loadConfig — required env vars", () => {
  it("throws when VERIFIER_SHARED_SECRET is missing", () => {
    withMinimumValidEnv();
    delete process.env.VERIFIER_SHARED_SECRET;
    expect(() => loadConfig()).toThrow(/VERIFIER_SHARED_SECRET/);
  });

  it("throws when DATABASE_URL is missing", () => {
    withMinimumValidEnv();
    delete process.env.DATABASE_URL;
    expect(() => loadConfig()).toThrow(/DATABASE_URL/);
  });

  it("throws when ASSET_STORAGE_HOST_REGEX is missing", () => {
    withMinimumValidEnv();
    delete process.env.ASSET_STORAGE_HOST_REGEX;
    expect(() => loadConfig()).toThrow(/ASSET_STORAGE_HOST_REGEX/);
  });

  it("throws when ASSET_STORAGE_HOST_ALLOWLIST is missing", () => {
    withMinimumValidEnv();
    delete process.env.ASSET_STORAGE_HOST_ALLOWLIST;
    expect(() => loadConfig()).toThrow(/ASSET_STORAGE_HOST_ALLOWLIST/);
  });

  it("throws when ASSET_STORAGE_HOST_ALLOWLIST parses to zero hosts", () => {
    // ", , ,  " parses to all-empty tokens → filtered out → zero
    // hosts → refuse to start. Without this guard, the verifier
    // would launch with an empty allowlist that rejects every
    // signed URL, which is broken but not obviously broken.
    withMinimumValidEnv();
    process.env.ASSET_STORAGE_HOST_ALLOWLIST = ", , ,  ";
    expect(() => loadConfig()).toThrow(/parsed to zero hosts/);
  });
});

// ---------------------------------------------------------------
// Port validation
// ---------------------------------------------------------------

describe("loadConfig — PORT validation", () => {
  it("defaults PORT to 8080 when unset", () => {
    withMinimumValidEnv();
    const config = loadConfig();
    expect(config.port).toBe(8080);
  });

  it("accepts PORT=8787 (the make verifier-dev default)", () => {
    withMinimumValidEnv();
    process.env.PORT = "8787";
    const config = loadConfig();
    expect(config.port).toBe(8787);
  });

  it("throws on non-numeric PORT", () => {
    withMinimumValidEnv();
    process.env.PORT = "not-a-number";
    expect(() => loadConfig()).toThrow(/Invalid PORT/);
  });

  it("throws on PORT=0", () => {
    withMinimumValidEnv();
    process.env.PORT = "0";
    expect(() => loadConfig()).toThrow(/Invalid PORT/);
  });

  it("throws on PORT > 65535", () => {
    withMinimumValidEnv();
    process.env.PORT = "65536";
    expect(() => loadConfig()).toThrow(/Invalid PORT/);
  });
});

// ---------------------------------------------------------------
// HOST_REGEX validation
// ---------------------------------------------------------------

describe("loadConfig — HOST_REGEX validation", () => {
  it("throws on an invalid regex", () => {
    withMinimumValidEnv();
    // Unclosed character class — RegExp constructor throws.
    process.env.ASSET_STORAGE_HOST_REGEX = "[unclosed";
    expect(() => loadConfig()).toThrow(/Invalid ASSET_STORAGE_HOST_REGEX/);
  });
});

// ---------------------------------------------------------------
// HOST_ALLOWLIST parsing
// ---------------------------------------------------------------

describe("loadConfig — HOST_ALLOWLIST parsing", () => {
  it("lowercases all hosts", () => {
    withMinimumValidEnv();
    process.env.ASSET_STORAGE_HOST_ALLOWLIST =
      "MyProject.SUPABASE.co, DEV.realreel.xyz";
    const config = loadConfig();
    expect(config.assetStorageHostAllowlist.has("myproject.supabase.co")).toBe(true);
    expect(config.assetStorageHostAllowlist.has("dev.realreel.xyz")).toBe(true);
    expect(config.assetStorageHostAllowlist.has("MyProject.SUPABASE.co")).toBe(false);
  });

  it("trims whitespace and drops empty tokens", () => {
    withMinimumValidEnv();
    process.env.ASSET_STORAGE_HOST_ALLOWLIST =
      "  a.example.com  , ,b.example.com,  ";
    const config = loadConfig();
    expect(config.assetStorageHostAllowlist.size).toBe(2);
    expect(config.assetStorageHostAllowlist.has("a.example.com")).toBe(true);
    expect(config.assetStorageHostAllowlist.has("b.example.com")).toBe(true);
  });
});

// ---------------------------------------------------------------
// isProduction flag
// ---------------------------------------------------------------

// ---------------------------------------------------------------
// certLifetimeMs — required-TSA gate ceiling (code constant, no env)
// ---------------------------------------------------------------

describe("loadConfig — certLifetimeMs", () => {
  it("is the DEFAULT_CERT_LIFETIME_MS constant (180 days)", () => {
    // Not env-overridable: the ceiling MUST track the CA's
    // LEAF_VALIDITY_DAYS (180 days after the 5y → 180d shortening), so it
    // lives in exactly one code constant. Pinning the literal catches an
    // accidental drift.
    withMinimumValidEnv();
    const config = loadConfig();
    expect(config.certLifetimeMs).toBe(DEFAULT_CERT_LIFETIME_MS);
    expect(config.certLifetimeMs).toBe(180 * 24 * 60 * 60 * 1000);
  });
});

// ---------------------------------------------------------------
// maxAssetBytes — fetch/buffer ceiling (env MAX_ASSET_MIB)
// ---------------------------------------------------------------

describe("loadConfig — maxAssetBytes / MAX_ASSET_MIB", () => {
  it("defaults to 50 MiB when MAX_ASSET_MIB unset", () => {
    withMinimumValidEnv();
    const config = loadConfig();
    expect(config.maxAssetBytes).toBe(50 * 1024 * 1024);
  });

  it("honors an explicit MAX_ASSET_MIB override", () => {
    withMinimumValidEnv();
    process.env.MAX_ASSET_MIB = "120";
    const config = loadConfig();
    expect(config.maxAssetBytes).toBe(120 * 1024 * 1024);
  });

  it("treats an empty MAX_ASSET_MIB as unset → default", () => {
    withMinimumValidEnv();
    process.env.MAX_ASSET_MIB = "";
    const config = loadConfig();
    expect(config.maxAssetBytes).toBe(50 * 1024 * 1024);
  });

  it("throws on a non-numeric MAX_ASSET_MIB", () => {
    withMinimumValidEnv();
    process.env.MAX_ASSET_MIB = "not-a-number";
    expect(() => loadConfig()).toThrow(/Invalid MAX_ASSET_MIB/);
  });

  it("throws on MAX_ASSET_MIB=0", () => {
    withMinimumValidEnv();
    process.env.MAX_ASSET_MIB = "0";
    expect(() => loadConfig()).toThrow(/Invalid MAX_ASSET_MIB/);
  });

  it("throws on a negative MAX_ASSET_MIB", () => {
    withMinimumValidEnv();
    process.env.MAX_ASSET_MIB = "-10";
    expect(() => loadConfig()).toThrow(/Invalid MAX_ASSET_MIB/);
  });

  it("throws above the sanity ceiling (OOM foot-gun guard)", () => {
    withMinimumValidEnv();
    process.env.MAX_ASSET_MIB = "100000";
    expect(() => loadConfig()).toThrow(/Invalid MAX_ASSET_MIB/);
  });
});

describe("loadConfig — isProduction flag", () => {
  it("isProduction === false when NODE_ENV unset", () => {
    withMinimumValidEnv();
    const config = loadConfig();
    expect(config.isProduction).toBe(false);
  });

  it("isProduction === true when NODE_ENV=production", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "production";
    // Production fails closed on an ambiguous ATTESTATION_REQUIRED, so set it
    // explicitly here (this test only cares about the isProduction flag).
    process.env.ATTESTATION_REQUIRED = "false";
    const config = loadConfig();
    expect(config.isProduction).toBe(true);
  });

  it("isProduction === false when NODE_ENV=development", () => {
    withMinimumValidEnv();
    process.env.NODE_ENV = "development";
    const config = loadConfig();
    expect(config.isProduction).toBe(false);
  });
});
