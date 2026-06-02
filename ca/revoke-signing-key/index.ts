// Revokes a single user_signing_keys row for the authed user. JWT-required;
// conditional AAL2 gate matches register-signing-key. Soft-DELETE via
// UPDATE-set-revoked_at; idempotent (revoking an already-revoked or missing
// row is 200 OK — the user's mental model is "make sure this device's key
// isn't enrolled," not "I'm asserting current state").
//
// Cross-user revoke is structurally impossible: the WHERE clause is
// (user_id = jwt.user_id AND key_id = body.keyId AND revoked_at IS NULL),
// so an attacker posting their own JWT with someone else's keyId gets a
// successful 200 with zero rows updated and learns nothing about the
// victim's keys.
//
// Soft-DELETE (not hard-DELETE): the verifier's lookup_signing_key_revocation
// function checks `revoked_at IS NULL` on both Stage 1 and Stage 2 signing
// keys. Preserves an audit trail ("when was this key revoked?") and leaves
// room for a future RFC-3161-aware predicate (`revoked_at IS NULL OR
// revoked_at > tsa_timestamp` — same column, more lenient check).

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { handlePreflight, jsonResponse } from "../_shared/cors.ts";
import {
  type AuthUser,
  getUserFromAuthHeader,
  makeServiceRoleClient,
  requireAal2IfMfaEnrolled,
} from "../_shared/auth.ts";
import { enforceRateLimit } from "../_shared/rate_limit.ts";
import { MAX_SIGNING_KEY_ID_CHARS } from "../_shared/config.ts";

// Tight per-user limits. Enrollment is rare; revocation is rarer.
const RATE_LIMIT_WINDOWS = [
  { windowSec: 3600, max: 20 },   // 20 revocations / hour
  { windowSec: 86400, max: 60 },  // 60 revocations / day
] as const;

interface RevokeBody {
  keyId?: string;
}

/**
 * Test-injection seams. Production passes the real implementations via
 * `defaultDeps`; tests override each to assert behavior without booting
 * Supabase. A single deps object avoids positional-argument refactors as new
 * injections are added.
 */
export interface RevokeDeps {
  getUserFromAuthHeader: typeof getUserFromAuthHeader;
  requireAal2IfMfaEnrolled: typeof requireAal2IfMfaEnrolled;
  enforceRateLimit: typeof enforceRateLimit;
  makeServiceRoleClient: typeof makeServiceRoleClient;
  now: () => Date;
}

export const defaultDeps: RevokeDeps = {
  getUserFromAuthHeader,
  requireAal2IfMfaEnrolled,
  enforceRateLimit,
  makeServiceRoleClient,
  now: () => new Date(),
};

/**
 * Request handler — pure function of (Request, deps) → Promise<Response>.
 * Imported by index_test.ts; production path wraps this in serve().
 */
export async function handleRevoke(
  req: Request,
  deps: RevokeDeps = defaultDeps,
): Promise<Response> {
  const preflight = handlePreflight(req);
  if (preflight) return preflight;

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, { status: 405 });
  }

  const user: AuthUser | null = await deps.getUserFromAuthHeader(req);
  if (!user) {
    return jsonResponse({ error: "Unauthorized" }, { status: 401 });
  }

  // Conditional AAL2 gate. If the user has MFA enrolled, the session must
  // be at AAL2. Mirrors register-signing-key: defends against a phished
  // AAL1 session being used to nuke the victim's device enrollments.
  const aalReject = await deps.requireAal2IfMfaEnrolled(user);
  if (aalReject) return aalReject;

  const rl = await deps.enforceRateLimit(
    "revoke-signing-key",
    user.id,
    RATE_LIMIT_WINDOWS,
  );
  if (!rl.ok) {
    return jsonResponse(
      { error: "Rate limit exceeded" },
      {
        status: 429,
        extraHeaders: { "Retry-After": String(rl.retryAfter) },
      },
    );
  }

  let body: RevokeBody;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { keyId } = body;
  if (
    typeof keyId !== "string" ||
    keyId.length === 0 ||
    keyId.length > MAX_SIGNING_KEY_ID_CHARS
  ) {
    return jsonResponse(
      { error: "Missing or malformed keyId" },
      { status: 400 },
    );
  }

  const supabase = deps.makeServiceRoleClient();
  // Soft-DELETE via UPDATE. `revoked_at IS NULL` guard makes the UPDATE
  // idempotent: revoking an already-revoked key is a 0-row UPDATE (200 OK),
  // not a re-stamp of revoked_at to a later timestamp.
  const { error } = await supabase
    .from("user_signing_keys")
    .update({ revoked_at: deps.now().toISOString() })
    .eq("user_id", user.id)
    .eq("key_id", keyId)
    .is("revoked_at", null);

  if (error) {
    console.error("[revoke-signing-key] UPDATE failed:", error);
    return jsonResponse({ error: "Revoke failed" }, { status: 500 });
  }

  console.log(
    `[revoke-signing-key] revoked user=${user.id} key_id=${keyId.slice(0, 12)}…`,
  );
  return jsonResponse({ ok: true });
}

// Only start the HTTP server when this module is run directly; tests import
// handleRevoke and would otherwise trip Deno.listen() at module load.
if (import.meta.main) {
  serve((req: Request) => handleRevoke(req));
}
