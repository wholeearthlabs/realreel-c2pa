// Issues a single-use enrollment challenge for the calling user.
//
// Flow:
//   1. JWT-required (default verify_jwt = true).
//   2. Service-role call to issue_enrollment_challenge RPC, which
//      generates a 32-byte random challenge server-side, INSERTs a
//      row into enrollment_challenges (consumed_at NULL,
//      expires_at = now() + 5 min), and returns the pair.
//   3. Return { challenge, expiresAt, keyVersion } to the client.
//
// The client passes `challenge` to PhotoAttest.generateAndAttestKey,
// then includes (challenge, keyVersion) in its register-signing-key
// request body. register-signing-key calls consume_enrollment_challenge
// which atomically burns the row (UPDATE WHERE consumed_at IS NULL AND
// expires_at > now()), so replays / cross-session reuse / forged-challenge
// attempts all fail at the SQL layer.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { handlePreflight, jsonResponse } from "../_shared/cors.ts";
import { getUserFromAuthHeader, makeServiceRoleClient } from "../_shared/auth.ts";
import { enforceRateLimit } from "../_shared/rate_limit.ts";

const DEFAULT_KEY_VERSION = "4";

// Per-user mint rate limits. Tighter than register-signing-key's because
// minting is cheaper than registering and the only legitimate consumer is
// the enrollment flow (one challenge per enrollment attempt). Mirrors the
// shape used by register-signing-key so a buggy retry loop or a stolen-JWT
// spammer can't accumulate unbounded enrollment_challenges rows for one
// user_id before consumed_at GC catches up.
const RATE_LIMIT_WINDOWS = [
  { windowSec: 3600, max: 10 },     // 10 challenges / hour
  { windowSec: 86400, max: 30 },    // 30 challenges / day
] as const;

serve(async (req: Request) => {
  const preflight = handlePreflight(req);
  if (preflight) return preflight;

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, { status: 405 });
  }

  const user = await getUserFromAuthHeader(req);
  if (!user) {
    return jsonResponse({ error: "Unauthorized" }, { status: 401 });
  }

  // Per-user rate limit: caps write-amplification into enrollment_challenges
  // from an authenticated misbehaving client. Legitimate enrollments mint at
  // most a handful of challenges (one per device install per user).
  const rl = await enforceRateLimit(
    "get-attestation-challenge",
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

  let keyVersion = DEFAULT_KEY_VERSION;
  try {
    const body = await req.json().catch(() => ({}));
    if (typeof body?.keyVersion === "string" && body.keyVersion) {
      keyVersion = body.keyVersion;
    }
  } catch {
    // Empty body is fine; defaults apply.
  }

  const supabase = makeServiceRoleClient();
  const { data, error } = await supabase
    .rpc("issue_enrollment_challenge", {
      p_user_id: user.id,
      p_key_version: keyVersion,
    })
    .single();

  if (error || !data) {
    console.error("[get-attestation-challenge] issue RPC failed:", error);
    return jsonResponse({ error: "Server error" }, { status: 500 });
  }

  const row = data as { challenge: string; expires_at: string };
  return jsonResponse({
    challenge: row.challenge,
    expiresAt: row.expires_at,
    keyVersion,
  });
});
