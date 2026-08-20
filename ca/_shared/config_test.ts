// Tests for the local-dev attestation gate (resolveDevAttestation in config.ts).
// The gate relaxes the bundle-id pins ONLY with an explicit opt-in AND a
// recognized LOCAL SUPABASE_URL; every other opt-in context throws (fail-closed).
// resolveDevAttestation takes its `env` as a parameter so these cases are pure
// function calls — no process-env mutation or module-cache busting.
//
// Run: deno test --allow-env --allow-read <path to this file>, from the
// directory holding the deno config.

import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.221.0/assert/mod.ts";
import { resolveDevAttestation } from "./config.ts";

// Build an `env` accessor from a fixed map.
const envFrom = (m: Record<string, string | undefined>) => (n: string) => m[n];

const CANONICAL_APPLE = "com.realreel.app";
const DEV_APPLE = "com.realreel.app.dev";

Deno.test("resolveDevAttestation — canonical pins when opt-in is unset, regardless of URL", () => {
  for (
    const url of [
      "http://kong:8000",
      "https://ulntxdbdhhoolbkszhsh.supabase.co",
      "https://api.realreel.app",
      "",
    ]
  ) {
    const p = resolveDevAttestation(envFrom({ SUPABASE_URL: url }));
    assertEquals(p.appleBundleId, CANONICAL_APPLE, `url=${url}`);
    assertEquals(p.androidPackageName, CANONICAL_APPLE, `url=${url}`);
    assertEquals(p.requireProductionAppAttest, true, `url=${url}`);
  }
});

Deno.test("resolveDevAttestation — relaxes to .dev on a recognized local stack with opt-in", () => {
  for (
    const url of [
      "http://kong:8000",
      "http://127.0.0.1:54321",
      "http://localhost:54321",
      "http://host.docker.internal:54321",
    ]
  ) {
    const p = resolveDevAttestation(
      envFrom({ ALLOW_DEV_BUILD_ATTESTATION: "true", SUPABASE_URL: url }),
    );
    assertEquals(p.appleBundleId, DEV_APPLE, `url=${url}`);
    assertEquals(p.androidPackageName, DEV_APPLE, `url=${url}`);
    assertEquals(p.requireProductionAppAttest, false, `url=${url}`);
  }
});

Deno.test("resolveDevAttestation — fork env overrides feed both the canonical and .dev identities", () => {
  // The PER-APP SWAP-POINT env overrides must compose with the dev gate: a
  // fork's base identity gets the same `.dev` suffix convention.
  const base = {
    APPLE_BUNDLE_ID: "com.example.fork",
    ANDROID_PACKAGE_NAME: "com.example.forkdroid",
  };
  const canonical = resolveDevAttestation(envFrom({ ...base }));
  assertEquals(canonical.appleBundleId, "com.example.fork");
  assertEquals(canonical.androidPackageName, "com.example.forkdroid");
  const relaxed = resolveDevAttestation(
    envFrom({
      ...base,
      ALLOW_DEV_BUILD_ATTESTATION: "true",
      SUPABASE_URL: "http://kong:8000",
    }),
  );
  assertEquals(relaxed.appleBundleId, "com.example.fork.dev");
  assertEquals(relaxed.androidPackageName, "com.example.forkdroid.dev");
});

Deno.test("resolveDevAttestation — THROWS when the env base id already ends in .dev", () => {
  // Other components use the same variable names for the fully-resolved id
  // (e.g. a verifier deployment sets APPLE_BUNDLE_ID=com.realreel.app.dev);
  // copying that value here would double the suffix. Must fail loud, in
  // every mode — not silently pin `<base>.dev.dev`.
  for (
    const env of [
      { APPLE_BUNDLE_ID: "com.realreel.app.dev" },
      { ANDROID_PACKAGE_NAME: "com.realreel.app.dev" },
    ]
  ) {
    assertThrows(() => resolveDevAttestation(envFrom(env)), Error, "BASE");
    assertThrows(
      () =>
        resolveDevAttestation(
          envFrom({
            ...env,
            ALLOW_DEV_BUILD_ATTESTATION: "true",
            SUPABASE_URL: "http://kong:8000",
          }),
        ),
      Error,
      "BASE",
    );
  }
});

Deno.test("resolveDevAttestation — THROWS when opt-in is set against a hosted *.supabase.co project", () => {
  assertThrows(
    () =>
      resolveDevAttestation(
        envFrom({
          ALLOW_DEV_BUILD_ATTESTATION: "true",
          SUPABASE_URL: "https://ulntxdbdhhoolbkszhsh.supabase.co",
        }),
      ),
    Error,
    "not a recognized",
  );
});

Deno.test("resolveDevAttestation — THROWS against a custom domain (closes the denylist fail-open)", () => {
  // A Supabase custom domain carries no `supabase.co` token, so a substring
  // denylist would wrongly read it as local. Positive host matching treats it
  // as non-local → throws (production fails closed even on a custom domain).
  assertThrows(
    () =>
      resolveDevAttestation(
        envFrom({
          ALLOW_DEV_BUILD_ATTESTATION: "true",
          SUPABASE_URL: "https://api.realreel.app",
        }),
      ),
    Error,
    "not a recognized",
  );
});

Deno.test("resolveDevAttestation — THROWS on opt-in with unset SUPABASE_URL", () => {
  assertThrows(
    () =>
      resolveDevAttestation(envFrom({ ALLOW_DEV_BUILD_ATTESTATION: "true" })),
    Error,
  );
});

Deno.test("resolveDevAttestation — host spoofing (kong.evil.com) is NOT treated as local", () => {
  assertThrows(
    () =>
      resolveDevAttestation(
        envFrom({
          ALLOW_DEV_BUILD_ATTESTATION: "true",
          SUPABASE_URL: "http://kong.evil.com:8000",
        }),
      ),
    Error,
  );
});

Deno.test("resolveDevAttestation — opt-in must be exactly 'true' (not '1'/'TRUE')", () => {
  for (const v of ["1", "TRUE", "yes", ""]) {
    const p = resolveDevAttestation(
      envFrom({
        ALLOW_DEV_BUILD_ATTESTATION: v,
        SUPABASE_URL: "http://kong:8000",
      }),
    );
    assertEquals(p.appleBundleId, CANONICAL_APPLE, `optIn=${v}`);
  }
});
