// Auth helpers extracted from the get-watermark-token pattern.
//
// Supabase auto-injects SUPABASE_SECRET_KEYS as a JSON map (keyed by signing-key
// alias) once a project has migrated to the new API-keys system. Older projects
// still use the legacy SUPABASE_SERVICE_ROLE_KEY env var. resolveServiceKey
// supports both so we don't have to care which mode the project is in.

import {
  createClient,
  type SupabaseClient,
} from "https://esm.sh/@supabase/supabase-js@2";
import { jsonResponse } from "./cors.ts";

export interface AuthUser {
  id: string;
  email?: string;
  // AAL claim from the JWT. 'aal1' = password-only session; 'aal2' = MFA factor
  // verified in this session. Used by requireAal2IfMfaEnrolled.
  aal: "aal1" | "aal2";
  // The Supabase client scoped to this user's JWT. Reused by helpers like
  // requireAal2IfMfaEnrolled so we don't build a fresh client per call.
  client: SupabaseClient;
}

export function resolveServiceKey(): string {
  const json = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (json) {
    try {
      const map = JSON.parse(json) as Record<string, string>;
      const key = map["default"] ?? Object.values(map)[0];
      if (key) return key;
    } catch {
      // Fall through to legacy.
    }
  }
  return Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || "";
}

export function getSupabaseUrl(): string {
  return Deno.env.get("SUPABASE_URL") || "";
}

export function makeServiceRoleClient(): SupabaseClient {
  return createClient(getSupabaseUrl(), resolveServiceKey());
}

// Returns a Supabase client scoped to the calling user's JWT. RLS evaluates
// against `auth.uid()` from that JWT; SECURITY DEFINER functions called via
// .rpc() see the user as the caller. Returns null if no JWT is present.
//
// Cached on the AuthUser to avoid building a fresh client every time a helper
// (getUserFromAuthHeader, requireAal2IfMfaEnrolled, …) needs one.
export function userScopedClient(req: Request): SupabaseClient | null {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const jwt = authHeader.slice("Bearer ".length).trim();
  if (!jwt) return null;
  return createClient(
    getSupabaseUrl(),
    Deno.env.get("SUPABASE_ANON_KEY") || "",
    { global: { headers: { Authorization: `Bearer ${jwt}` } } },
  );
}

// Decodes the payload (middle segment) of a JWT without verifying its
// signature. Safe here because Supabase's verify_jwt = true gate has already
// validated the signature before our handler runs; we only need to read claims.
function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const seg = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = seg.padEnd(Math.ceil(seg.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

// Resolves the calling user via the Authorization: Bearer <jwt> header.
// Returns null if no header is present, the JWT is invalid, or the user is
// not found. Caller should respond with 401 in that case.
//
// For functions configured with verify_jwt = true (the default), Supabase has
// already validated the JWT signature and rejected requests with bad tokens
// before we run. We still call getUser() to resolve the user_id from the token.
export async function getUserFromAuthHeader(
  req: Request,
): Promise<AuthUser | null> {
  const client = userScopedClient(req);
  if (!client) return null;

  const jwt = (req.headers.get("Authorization") ?? "")
    .replace(/^Bearer\s+/i, "")
    .trim();

  const { data, error } = await client.auth.getUser(jwt);
  if (error || !data?.user) return null;

  const payload = decodeJwtPayload(jwt);
  const aalClaim = payload?.aal;
  const aal: AuthUser["aal"] = aalClaim === "aal2" ? "aal2" : "aal1";

  return {
    id: data.user.id,
    email: data.user.email ?? undefined,
    aal,
    client,
  };
}

// Conditional AAL2 gate matching the codebase's existing RLS policies (see
// migrations/20260419175728_fix_mfa_policy_permission_denied.sql):
//
//   * If the user has NOT enrolled MFA → pass through at AAL1. No factor prompt.
//   * If the user HAS enrolled MFA and the current session is AAL2 → pass.
//   * If the user HAS enrolled MFA but the session is AAL1 → 403.
//
// Returns null on pass, or a Response (the caller early-returns it) on reject.
export async function requireAal2IfMfaEnrolled(
  user: AuthUser,
): Promise<Response | null> {
  if (user.aal === "aal2") return null;

  // User is at AAL1 — check whether they've enrolled MFA. The
  // user_has_verified_mfa() SECURITY DEFINER function is defined in
  // migrations/20260419175728_fix_mfa_policy_permission_denied.sql and granted
  // to `authenticated`. Uses the JWT-scoped client cached on AuthUser so we
  // don't build a second client per request.
  const { data, error } = await user.client.rpc("user_has_verified_mfa");
  if (error) {
    console.error("[auth] user_has_verified_mfa RPC failed:", error);
    return jsonResponse(
      { error: "Could not verify MFA state" },
      { status: 500 },
    );
  }

  if (data === true) {
    return jsonResponse(
      { error: "AAL2 required for this action" },
      { status: 403 },
    );
  }

  return null;
}
