// Sentry wiring for Supabase edge functions (Deno runtime).
//
// Used by the verify-and-create-media edge function. Other edge functions
// (register-signing-key, revoke-signing-key, ...) can opt in incrementally.
//
// **Lazy-loaded** so importing this module doesn't pull in the Sentry
// SDK over the network during tests. Tests never call initSentry() and
// captureMessage/captureException fall back to console.warn (visible
// in Deno test output) with no network access required. Production
// edge functions call initSentry() at startup; the real SDK is
// dynamically imported there.
//
// Why Sentry vs console.log:
//   We emit structured tags (`verify_reject`,
//   `orphan_cleanup_failed`, `toctou_detected`, `ssrf_attempt`) with
//   facets like code/source/stage. Cloud Logging can parse JSON, but
//   its filter UX is much weaker than Sentry's tag search for
//   incident triage.
//
// Env vars:
//   SENTRY_DSN_EDGE — Supabase function secret. Distinct from the
//     mobile app's DSN unless we explicitly share; v1 recommendation
//     is shared so oncall sees both surfaces in one inbox.
//   SUPABASE_ENV    — 'production' | 'staging' | 'development'.

export interface SentryEventContext {
  level?: "fatal" | "error" | "warning" | "info" | "debug";
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
}

export interface SentryLike {
  captureMessage(message: string, context?: SentryEventContext): void;
  captureException(err: unknown, context?: SentryEventContext): void;
}

// Default implementation: log to console with a 'sentry-fallback'
// prefix so the structured-event semantics survive in Cloud Logging
// even without a Sentry DSN.
const consoleFallback: SentryLike = {
  captureMessage(message, context) {
    const payload = { message, ...context };
    console.warn(`[sentry-fallback] ${JSON.stringify(payload)}`);
  },
  captureException(err, context) {
    const message = err instanceof Error ? err.message : String(err);
    const stack = err instanceof Error ? err.stack : undefined;
    const payload = { message, stack, ...context };
    console.error(`[sentry-fallback] ${JSON.stringify(payload)}`);
  },
};

let impl: SentryLike = consoleFallback;
let initialized = false;

/**
 * Initialize Sentry. Idempotent — safe to call from multiple edge
 * function entrypoints; only the first call has effect. Returns the
 * shared instance.
 *
 * If SENTRY_DSN_EDGE is unset, stays on the consoleFallback. Avoids
 * the network-import cost when running locally without a DSN.
 */
export async function initSentry(): Promise<void> {
  if (initialized) return;
  initialized = true;

  const dsn = Deno.env.get("SENTRY_DSN_EDGE");
  if (!dsn) return; // fallback stays in place

  try {
    // Dynamic import keeps the SDK out of the test bundle. The URL
    // pins a Sentry SDK build that works under Deno; bump in the same
    // commit that bumps @sentry/node in verifier/.
    const Sentry = await import(
      "https://esm.sh/@sentry/deno@8.55.0?bundle"
    );
    Sentry.init({
      dsn,
      environment: Deno.env.get("SUPABASE_ENV") ?? "unknown",
      tracesSampleRate: 0, // events only — no perf traces at this scope
    });
    impl = {
      captureMessage: (msg, ctx) => Sentry.captureMessage(msg, ctx ?? {}),
      captureException: (err, ctx) => Sentry.captureException(err, ctx ?? {}),
    };
  } catch (e) {
    // Loader failure shouldn't take the edge function down. Stay on
    // consoleFallback and log the load failure for ops.
    console.error(
      `[sentry-fallback] Sentry SDK failed to load: ${e instanceof Error ? e.message : String(e)} — staying on console fallback`,
    );
  }
}

/**
 * The canonical Sentry surface inside edge functions. Always returns
 * the current impl (live-swaps from consoleFallback to the real SDK
 * after initSentry succeeds).
 */
export const Sentry: SentryLike = {
  captureMessage: (m, c) => impl.captureMessage(m, c),
  captureException: (e, c) => impl.captureException(e, c),
};
