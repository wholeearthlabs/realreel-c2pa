// Reusable Deno-KV rate limiter for edge functions.
//
// Pattern follows get-watermark-token's inline implementation: multiple sliding
// windows, atomic check-and-set on each bucket, fail-open on KV outages.
//
// Usage:
//   const limit = await enforceRateLimit(
//     "register-signing-key",          // prefix scopes the buckets per-function
//     user.id,                          // identity key (per-user here, per-IP for anon endpoints)
//     [
//       { windowSec: 3600, max: 5 },
//       { windowSec: 86400, max: 20 },
//     ],
//   );
//   if (!limit.ok) {
//     return jsonResponse(
//       { error: "Rate limit exceeded" },
//       { status: 429, extraHeaders: { "Retry-After": String(limit.retryAfter) } },
//     );
//   }

export interface RateLimitWindow {
  windowSec: number;
  max: number;
}

export type RateLimitResult =
  | { ok: true }
  | { ok: false; retryAfter: number };

// Increment one bucket atomically using check-and-set, retrying on contention.
// Returns true if we incremented, false if we were over the limit.
async function bumpBucket(
  kv: Deno.Kv,
  key: Deno.KvKey,
  max: number,
  ttlMs: number,
): Promise<boolean> {
  for (let attempt = 0; attempt < 4; attempt++) {
    const entry = await kv.get<Deno.KvU64>(key);
    const current = entry.value?.value ?? 0n;
    if (current >= BigInt(max)) return false;
    const result = await kv.atomic()
      .check(entry)
      .set(key, new Deno.KvU64(current + 1n), { expireIn: ttlMs })
      .commit();
    if (result.ok) return true;
  }
  // Contention exhausted retries — fail closed for this bucket.
  return false;
}

export async function enforceRateLimit(
  prefix: string,
  identityKey: string,
  windows: ReadonlyArray<RateLimitWindow>,
): Promise<RateLimitResult> {
  let kv: Deno.Kv;
  try {
    kv = await Deno.openKv();
  } catch (err) {
    // KV unavailable — fail open. Logging the failure makes ops aware that
    // the rate limit silently isn't being enforced.
    console.warn(`[${prefix}] rate-limit KV unavailable, failing open:`, err);
    return { ok: true };
  }

  const now = Math.floor(Date.now() / 1000);
  for (const { windowSec, max } of windows) {
    const bucket = Math.floor(now / windowSec);
    const key: Deno.KvKey = [prefix, identityKey, windowSec, bucket];
    const ok = await bumpBucket(kv, key, max, (windowSec + 5) * 1000);
    if (!ok) {
      return { ok: false, retryAfter: windowSec - (now % windowSec) };
    }
  }
  return { ok: true };
}
