// Fastify entrypoint for the RealReel C2PA verifier.
//
// Request flow for POST /verify:
//   onRequest hook (BEFORE body parse):
//     - Bearer-token auth via timing-safe Buffer compare against
//       VERIFIER_SHARED_SECRET. Reject 401 if missing/wrong. Doing this
//       in onRequest (not preHandler) means an unauthenticated attacker
//       spends zero CPU on JSON parse, even at the 64 KB body cap.
//   /verify handler:
//     - Parse body { signedUrl, expectedUserId, expectedEtag,
//       expectedContentLength, mimeType }.
//     - Validate signedUrl against ASSET_STORAGE_HOST_REGEX (Layer 2
//       SSRF defense). Reject 400 + Sentry-tag ssrf_attempt if off-host.
//     - GET signedUrl with `redirect: 'error'` + `If-Match: <etag>`.
//       If 412 → TOCTOU detected. If non-2xx → STORAGE_FETCH_FAILED.
//     - Confirm content-length matches expectedContentLength and the
//       full stream stays under MAX_ASSET_BYTES.
//     - Call verify({ assetBytes, ... }). Throws VerifyError on rejection.
//     - On success: respond 200 + { verdict: 'ok', sanitizedManifest }.
//   errorHandler:
//     - VerifyError → 422 + { verdict: 'reject', errorCode, detail? }.
//     - Anything else → 500 + Sentry.captureException + { errorCode: 'VERIFIER_UNAVAILABLE' }.
//
// Health probes:
//   GET /healthz       — liveness. Returns 200 unconditionally as long
//                        as Fastify is serving. Used by Cloud Run
//                        liveness probe and load-balancer health.
//   GET /healthz/ready — readiness. Round-trips
//                        lookup_signing_key_revocation against a
//                        sentinel that returns zero rows. 200 if the
//                        DB pool, role grants, and function signature
//                        are all healthy; 503 otherwise. Wired as the
//                        Cloud Run startup probe so a misconfigured
//                        instance never starts serving /verify.
//
// buildServer({ config, trustConfig }) is exported so vitest can use
// fastify.inject() without triggering loadConfig() / initDb() /
// loadTrustConfig() side effects at module load.

import Fastify, { type FastifyInstance } from "fastify";
import { timingSafeEqual } from "node:crypto";
import { loadConfig, type Config } from "./config.js";
import { initObservability, Sentry } from "./observability.js";
import { initDb, pingDb } from "./db.js";
import { loadTrustConfig } from "./trust/loader.js";
import type { TrustConfig } from "./trust/types.js";
import { verify } from "./verify.js";
import { VerifyError, VerifyErrorCode } from "./errors.js";

// 50 MB ceiling on the asset we'll fetch + load into memory.
//
// NOT a streaming cap in the strict sense: response.arrayBuffer() below
// buffers the whole body before we check the byte count. Today this is
// safe because (a) Supabase Storage returns honest content-length and
// we early-reject on mismatch, and (b) the host-allowlist limits where
// we'll fetch from. If the allowlist ever loosens, swap to a chunked
// reader with early-abort to make this truly streaming.
const MAX_ASSET_BYTES = 50 * 1024 * 1024;
const SIGNED_URL_FETCH_TIMEOUT_MS = 15_000;

interface VerifyRequestBody {
  signedUrl: string;
  expectedUserId: string;
  expectedEtag: string;
  expectedContentLength: number;
  mimeType: string;
}

/**
 * Build the Fastify instance with all routes + hooks wired up. Pure —
 * no module-level singletons, no listen(). Vitest uses this directly
 * with fastify.inject() so tests don't need to bind a port or trigger
 * loadConfig() / initDb() / loadTrustConfig() side effects.
 *
 * Production boot calls initDb() before fastify.listen() (see module
 * bottom). Tests vi.mock("./db.js", ...) — initDb is a no-op there
 * and pingDb / lookupSigningKeyRevocation are spies — so tests do
 * NOT need to call initDb themselves.
 */
export function buildServer(opts: {
  config: Config;
  trustConfig: TrustConfig;
}): FastifyInstance {
  const { config, trustConfig } = opts;

  const fastify = Fastify({
    // Production: default JSON logger (Cloud Logging parses it natively).
    // Dev: pino-pretty for readable local output. pino-pretty MUST NOT
    // be used in production — extra CPU + non-JSON breaks Cloud Logging
    // field extraction.
    logger: config.isProduction
      ? true
      : { transport: { target: "pino-pretty" } },
    bodyLimit: 64 * 1024,   // JSON request body cap
  });

  // The "both env vars or neither" gate in loadConfig() catches half-config,
  // but not "forgot both" — which boots cleanly in lenient-degraded mode
  // where Android manifests carry the play_integrity assertion and the nonce
  // burns but Google's JWS signature is NEVER verified. Harmless in dev, a
  // silent attestation regression in production, so warn loudly at startup.
  if (config.isProduction && !config.playIntegrity) {
    fastify.log.warn(
      {
        category: "play-integrity",
        mode: "lenient",
      },
      "PRODUCTION verifier running in Play Integrity LENIENT mode — " +
        "PLAY_INTEGRITY_PACKAGE_NAME and PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER " +
        "are unset; Android JWS decode is DISABLED, nonce burn only. " +
        "Set both env vars to enable full verdict enforcement.",
    );
  }

  registerRoutes(fastify, config, trustConfig);
  return fastify;
}

function registerRoutes(
  fastify: FastifyInstance,
  config: Config,
  trustConfig: TrustConfig,
): void {
  // ----- Layer 1: bearer-token auth (onRequest, before body parse) -----
  fastify.addHook("onRequest", async (req, reply) => {
    if (req.url !== "/verify") return;

    const auth = req.headers.authorization ?? "";
    const expected = `Bearer ${config.sharedSecret}`;
    // Convert to Buffers FIRST, then compare byte-lengths. String length
    // is UTF-16 code-units; Buffer length is bytes. A multibyte string
    // could string-match expected.length while differing in byte-length
    // and trigger ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH inside
    // timingSafeEqual — which surfaces as a 500 + Sentry noise, not a
    // 401. The Buffer-first ordering avoids that vector.
    const authBuf = Buffer.from(auth);
    const expectedBuf = Buffer.from(expected);
    if (authBuf.length !== expectedBuf.length) {
      return reply.status(401).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.UNAUTHORIZED,
      });
    }
    if (!timingSafeEqual(authBuf, expectedBuf)) {
      return reply.status(401).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.UNAUTHORIZED,
      });
    }
  });

  // ----- Liveness -----
  fastify.get("/healthz", async () => ({ ok: true }));

  // ----- Readiness -----
  //
  // 503 (not 500) on failure: Cloud Run treats 503 as "retry me" and
  // 5xx-non-503 as "broken, restart me." DB-unreachable is recoverable
  // (pooler hiccup, transient network), so 503 is the right signal.
  //
  // No Sentry capture here. Cloud Run polls this every few seconds;
  // any real outage would drown Sentry in duplicates. Surface failures
  // via Cloud Run's own probe-failure metric.
  fastify.get("/healthz/ready", async (_req, reply) => {
    try {
      await pingDb();
      return reply.status(200).send({ ok: true, db: "ok" });
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e);
      return reply.status(503).send({ ok: false, db: "unreachable", detail });
    }
  });

  // ----- Main verify route -----
  fastify.post("/verify", async (req, reply) => {
    const body = req.body as VerifyRequestBody | undefined;
    if (
      !body ||
      typeof body.signedUrl !== "string" ||
      typeof body.expectedUserId !== "string" ||
      typeof body.expectedEtag !== "string" ||
      typeof body.expectedContentLength !== "number" ||
      typeof body.mimeType !== "string"
    ) {
      reply.status(400).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.MANIFEST_MALFORMED,
        detail: "missing or malformed request body fields",
      });
      return;
    }

    const { signedUrl, expectedUserId, expectedEtag, expectedContentLength, mimeType } = body;

    // ----- Layer 2: SSRF defense, two-step -----
    //
    // Step 2a: regex shape match. Cheap; rejects obvious garbage and
    // wrong-scheme URLs before we burn cycles on URL parsing.
    if (!config.assetStorageHostRegex.test(signedUrl)) {
      Sentry.captureMessage("ssrf_attempt", {
        level: "error",
        tags: { signedUrlHost: bestEffortHost(signedUrl), stage: "regex" },
      });
      return reply.status(400).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
      });
    }

    // Step 2b: parse and check `URL.host` against the explicit allowlist.
    // `new URL(...).host` strips userinfo automatically, so this defeats
    // tricks like `https://abc.supabase.co@attacker.com/...` that a
    // permissive regex could let through. Authoritative — no substring
    // matching.
    let parsedHost: string;
    try {
      parsedHost = new URL(signedUrl).host.toLowerCase();
    } catch {
      Sentry.captureMessage("ssrf_attempt", {
        level: "error",
        tags: { signedUrlHost: "(unparseable)", stage: "url_parse" },
      });
      return reply.status(400).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
      });
    }
    if (!config.assetStorageHostAllowlist.has(parsedHost)) {
      Sentry.captureMessage("ssrf_attempt", {
        level: "error",
        tags: { signedUrlHost: parsedHost, stage: "allowlist" },
      });
      return reply.status(400).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
      });
    }

    // ----- Fetch the asset -----
    // redirect: 'error' — Supabase Storage signed URLs don't redirect; a
    // 30x here is an SSRF signal, refuse.
    // If-Match: <etag> — TOCTOU defense. Storage returns 412 if the
    // underlying object was overwritten between the edge function's HEAD
    // and our GET.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), SIGNED_URL_FETCH_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetch(signedUrl, {
        redirect: "error",
        headers: { "If-Match": expectedEtag },
        signal: controller.signal,
      });
    } catch (e) {
      clearTimeout(timeoutId);
      Sentry.captureException(e, { tags: { stage: "storage_fetch" } });
      reply.status(502).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
      });
      return;
    }
    clearTimeout(timeoutId);

    if (response.status === 412) {
      Sentry.captureMessage("toctou_detected", { level: "warning" });
      reply.status(422).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
        detail: "object changed between signing and fetch (If-Match failed)",
      });
      return;
    }
    if (!response.ok) {
      reply.status(502).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
        detail: `storage GET returned ${response.status}`,
      });
      return;
    }

    // Stream size sanity. content-length-vs-expected catches truncation /
    // tampering; the >MAX_ASSET_BYTES guard caps memory pressure from a
    // hostile signed URL claiming a small length and streaming forever.
    const contentLengthHeader = response.headers.get("content-length");
    const contentLength = contentLengthHeader ? Number(contentLengthHeader) : NaN;
    if (
      !Number.isFinite(contentLength) ||
      contentLength !== expectedContentLength ||
      contentLength > MAX_ASSET_BYTES
    ) {
      reply.status(422).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
        detail: `content-length mismatch or oversize (got ${contentLength}, expected ${expectedContentLength})`,
      });
      return;
    }
    const assetBytes = Buffer.from(await response.arrayBuffer());
    if (assetBytes.byteLength !== contentLength) {
      reply.status(422).send({
        verdict: "reject",
        errorCode: VerifyErrorCode.STORAGE_FETCH_FAILED,
        detail: "streamed bytes differ from content-length header",
      });
      return;
    }

    // ----- Run the verify pipeline -----
    const result = await verify({
      assetBytes,
      mimeType,
      expectedUserId,
      trustConfig,
      playIntegrityConfig: config.playIntegrity,
      attestationRequired: config.attestationRequired,
      certLifetimeMs: config.certLifetimeMs,
    });

    reply.status(200).send({
      verdict: "ok",
      sanitizedManifest: result.sanitizedManifest,
      // Server-derived displayed metadata (see VerifyResult.derived).
      derived: result.derived,
    });
  });

  // ----- Error handler -----
  fastify.setErrorHandler((err, _req, reply) => {
    if (err instanceof VerifyError) {
      // Capture every VerifyError to Sentry with structured tags.
      // Level routing: VERIFIER_UNAVAILABLE (our side or Google's API down) is
      // an ops concern → warning; other codes are user-side rejections
      // (revoked key, missing attestation, replay) → info so they don't page
      // on routine activity but stay queryable by rate-based alerts. category
      // is set only when the throw-site bound one, so platform-specific alerts
      // don't false-positive on cross-platform errors.
      try {
        Sentry.captureMessage(`verify_error.${err.code}`, {
          level: err.code === VerifyErrorCode.VERIFIER_UNAVAILABLE
            ? "warning"
            : "info",
          tags: {
            error_code: err.code,
            ...(err.category ? { category: err.category } : {}),
          },
          extra: err.detail ? { detail: err.detail } : undefined,
        });
      } catch {
        // Sentry SDK fault should never break the response path —
        // telemetry is best-effort.
      }
      // Mirror the Sentry tags to the local Fastify log so dev environments
      // without a Sentry DSN can still see WHICH VerifyError fired. Without
      // this, the 422 line is opaque locally.
      reply.log.warn(
        { errorCode: err.code, detail: err.detail, category: err.category },
        "verify rejected",
      );
      reply.status(422).send({
        verdict: "reject",
        errorCode: err.code,
        detail: err.detail,
      });
      return;
    }
    Sentry.captureException(err);
    reply.log.error(err);
    reply.status(500).send({
      verdict: "reject",
      errorCode: VerifyErrorCode.VERIFIER_UNAVAILABLE,
    });
  });
}

// Best-effort host extraction for Sentry tagging on rejected URLs. The
// URL is by definition malformed-or-hostile here, so `new URL()` may
// throw — fall back to a regex extract, then to a literal sentinel.
function bestEffortHost(rawUrl: string): string {
  try {
    return new URL(rawUrl).host;
  } catch {
    const match = rawUrl.match(/^[a-z]+:\/\/([^/]+)/i);
    if (match) return match[1]!;
    return "(unparseable)";
  }
}

// ----- Module-level boot -----
//
// Two boot conditions cover the two real environments:
//   - NODE_ENV === 'production' — the Dockerfile sets this explicitly, so a
//     container boots even if a stray VITEST leaked into the deploy env.
//   - NODE_ENV unset AND VITEST unset — `node dist/server.js` in dev. Tests
//     set VITEST so they skip both conditions.
const NODE_ENV = process.env.NODE_ENV;
if (NODE_ENV === "production" || (NODE_ENV === undefined && !process.env.VITEST)) {
  const config = loadConfig();
  initObservability(config);
  initDb(config.databaseUrl);
  const trustConfig = await loadTrustConfig(config.trustSourcesPath, config);
  const fastify = buildServer({ config, trustConfig });
  await fastify.listen({ port: config.port, host: "0.0.0.0" });
}
