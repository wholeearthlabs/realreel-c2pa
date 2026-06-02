// Readiness probe (GET /healthz/ready).
//
// /healthz/ready round-trips lookup_signing_key_revocation via pingDb()
// to assert (a) the DB pool can reach Postgres, (b) verifier_readonly
// has EXECUTE on the function, (c) the function signature still matches.
// Failure returns 503 so Cloud Run treats it as "retry me" rather than
// "broken, restart me."
//
// We hoist a vi.mock of ../src/db.js BEFORE importing buildServer so
// the server.ts side-effects (initDb) become no-ops and pingDb is a
// mocked spy. Same pattern as policy.test.ts:18.

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../src/db.js", () => ({
  initDb: vi.fn(),
  closeDbPool: vi.fn(),
  pingDb: vi.fn(),
  lookupSigningKeyRevocation: vi.fn(),
}));

import { buildServer } from "../src/server.js";
import { pingDb } from "../src/db.js";
import type { Config } from "../src/config.js";
import type { TrustConfig } from "../src/trust/types.js";

// Minimal config — buildServer only touches sharedSecret / isProduction /
// regex / allowlist on the actual request paths, and /healthz/ready
// touches none of them. The pretty-logger transport is disabled by
// isProduction:true so vitest doesn't try to spawn pino-pretty.
const config: Config = {
  port: 0,
  trustSourcesPath: "(unused)",
  sharedSecret: "test-secret",
  databaseUrl: "(unused)",
  assetStorageHostRegex: /^https:\/\//,
  assetStorageHostAllowlist: new Set(["abc.supabase.co"]),
  sentryDsn: undefined,
  isProduction: true,
  playIntegrity: undefined,
  attestationRequired: false,
};

// Empty trust config — readiness doesn't touch it. Cast through unknown
// because the full TrustConfig surface is irrelevant here.
const trustConfig = {} as unknown as TrustConfig;

beforeEach(() => {
  vi.mocked(pingDb).mockReset();
});

describe("GET /healthz (liveness)", () => {
  // Regression guard: the buildServer() refactor moved /healthz inside
  // registerRoutes — a typo in the route string would silently break
  // liveness probes. This case asserts the path + body shape that
  // Cloud Run's liveness probe expects.
  it("returns 200 + ok:true unconditionally (no DB roundtrip)", async () => {
    const fastify = buildServer({ config, trustConfig });
    try {
      const res = await fastify.inject({ method: "GET", url: "/healthz" });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ ok: true });
      // Liveness must NOT touch the DB — that's what readiness is for.
      expect(vi.mocked(pingDb)).not.toHaveBeenCalled();
    } finally {
      await fastify.close();
    }
  });
});

describe("GET /healthz/ready", () => {
  it("returns 200 + ok:true when pingDb resolves", async () => {
    vi.mocked(pingDb).mockResolvedValue(undefined);

    const fastify = buildServer({ config, trustConfig });
    try {
      const res = await fastify.inject({
        method: "GET",
        url: "/healthz/ready",
      });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ ok: true, db: "ok" });
      expect(vi.mocked(pingDb)).toHaveBeenCalledTimes(1);
    } finally {
      await fastify.close();
    }
  });

  it("returns 503 + ok:false when pingDb rejects", async () => {
    vi.mocked(pingDb).mockRejectedValue(
      new Error("connect ECONNREFUSED 127.0.0.1:5432"),
    );

    const fastify = buildServer({ config, trustConfig });
    try {
      const res = await fastify.inject({
        method: "GET",
        url: "/healthz/ready",
      });
      expect(res.statusCode).toBe(503);
      const body = res.json();
      expect(body.ok).toBe(false);
      expect(body.db).toBe("unreachable");
      // The pg error message should propagate into `detail` so operators
      // can distinguish permission-denied from connection-refused without
      // shelling onto the box.
      expect(body.detail).toContain("ECONNREFUSED");
    } finally {
      await fastify.close();
    }
  });
});
