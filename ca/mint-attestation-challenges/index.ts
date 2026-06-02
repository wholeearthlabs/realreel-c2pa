// Mints a batch of single-use attestation challenges for a hardware signing key.
//
// Each challenge is a server-issued nonce that the client binds into a
// per-capture App Attest assertion (iOS) or Play Integrity token (Android) at
// signing time. The verifier (at upload) atomically marks the challenge as
// consumed in the same DB transaction that accepts the manifest, so replays
// fail closed.
//
// Flow:
//   1. JWT-required (default verify_jwt = true).
//   2. Validate body: { keyId, count? }.
//   3. Service-role .rpc('mint_attestation_challenges', …). The SECURITY DEFINER
//      function verifies keyId is owned by the JWT user and not revoked
//      (defense-in-depth check beyond what we already do here).
//   4. Return { challenges: string[] } — nonces only. The DB row carries the
//      key binding + issued_at; the client only needs the nonce to redeem.
//
// Used in two modes by the client:
//   * Capture path (offline-capable): batched ~100, cached in AsyncStorage,
//     consumed one per capture. Challenges are NOT secrets — they're public
//     nonces; the security boundary is verifier-side single-use enforcement
//     plus platform attestation, not filesystem secrecy.
//   * Upload path (online): single-shot count=1 fetch right before Stage-2
//     sign, so the upload-time attestation binds to a fresh challenge.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { handlePreflight, jsonResponse } from "../_shared/cors.ts";
import {
  type AuthUser,
  getUserFromAuthHeader,
  makeServiceRoleClient,
} from "../_shared/auth.ts";

const DEFAULT_COUNT = 100;
const MAX_COUNT = 200;
const MAX_BODY_BYTES = 256;

interface MintBody {
  keyId?: string;
  count?: number;
}

/**
 * Test-injection seams. Same pattern as revoke-signing-key. Production
 * passes the real implementations via `defaultDeps`; tests override each
 * to assert behavior without booting Supabase.
 */
export interface MintChallengesDeps {
  getUserFromAuthHeader: typeof getUserFromAuthHeader;
  makeServiceRoleClient: typeof makeServiceRoleClient;
}

export const defaultDeps: MintChallengesDeps = {
  getUserFromAuthHeader,
  makeServiceRoleClient,
};

export async function handleMintChallenges(
  req: Request,
  deps: MintChallengesDeps = defaultDeps,
): Promise<Response> {
  const preflight = handlePreflight(req);
  if (preflight) return preflight;

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, { status: 405 });
  }

  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: "Payload too large" }, { status: 413 });
  }

  const user: AuthUser | null = await deps.getUserFromAuthHeader(req);
  if (!user) {
    return jsonResponse({ error: "Unauthorized" }, { status: 401 });
  }

  let body: MintBody;
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ error: "Invalid JSON body" }, { status: 400 });
  }

  const keyId = typeof body?.keyId === "string" ? body.keyId : "";
  if (!keyId) {
    return jsonResponse({ error: "keyId is required" }, { status: 400 });
  }

  const rawCount = body?.count;
  const count = typeof rawCount === "number" && Number.isFinite(rawCount)
    ? Math.floor(rawCount)
    : DEFAULT_COUNT;
  if (count < 1 || count > MAX_COUNT) {
    return jsonResponse(
      { error: `count must be between 1 and ${MAX_COUNT}` },
      { status: 400 },
    );
  }

  const supabase = deps.makeServiceRoleClient();

  const { data, error } = await supabase.rpc("mint_attestation_challenges", {
    p_key_id: keyId,
    p_user_id: user.id,
    p_count: count,
  });

  if (error) {
    // The RPC raises 42501 (insufficient_privilege) for ownership/revocation
    // failures and 22023 (invalid_parameter_value) for bad counts. We've
    // already validated count above, but keep the mapping for completeness.
    if (error.code === "42501") {
      return jsonResponse(
        { error: "keyId not owned by user or revoked" },
        { status: 403 },
      );
    }
    if (error.code === "22023") {
      return jsonResponse({ error: error.message }, { status: 400 });
    }
    console.error("[mint-attestation-challenges] rpc error", error);
    return jsonResponse({ error: "Failed to mint challenges" }, { status: 500 });
  }

  if (!Array.isArray(data)) {
    console.error("[mint-attestation-challenges] unexpected rpc result", data);
    return jsonResponse({ error: "Failed to mint challenges" }, { status: 500 });
  }

  const challenges = data
    .map((row: { nonce?: string }) => row?.nonce)
    .filter((n): n is string => typeof n === "string" && n.length > 0);

  return jsonResponse({ challenges });
}

// Only start the HTTP server when this module is run directly; tests import
// handleMintChallenges and would otherwise trip Deno.listen() at module load.
if (import.meta.main) {
  serve((req: Request) => handleMintChallenges(req));
}
