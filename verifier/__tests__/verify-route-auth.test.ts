// Bearer auth on POST /verify: every request that routes to the handler needs
// the shared secret, whatever its query string or path encoding.

import { describe, it, expect, vi } from "vitest";

vi.mock("../src/db.js", () => ({
  initDb: vi.fn(),
  closeDbPool: vi.fn(),
  pingDb: vi.fn(),
  lookupSigningKeyRevocation: vi.fn(),
}));

import { buildServer } from "../src/server.js";
import { VerifyErrorCode } from "../src/errors.js";
import type { Config } from "../src/config.js";
import type { TrustConfig } from "../src/trust/types.js";

const config: Config = {
  port: 0,
  trustSourcesPath: "(unused)",
  sharedSecret: "test-secret",
  databaseUrl: "(unused)",
  assetStorageHostRegex: /^https:\/\//,
  assetStorageHostAllowlist: new Set(["abc.supabase.co"]),
  maxAssetBytes: 50 * 1024 * 1024,
  sentryDsn: undefined,
  isProduction: true,
  playIntegrity: undefined,
  attestationRequired: false,
  networkRevocation: false,
};
const trustConfig = { ocspHosts: [] } as unknown as TrustConfig;

async function send(url: string, authorization?: string, method: "GET" | "POST" = "POST") {
  const fastify = buildServer({ config, trustConfig });
  try {
    return await fastify.inject({
      method,
      url,
      headers: authorization ? { authorization } : {},
      ...(method === "POST" ? { payload: {} } : {}),
    });
  } finally {
    await fastify.close();
  }
}

describe("POST /verify bearer auth", () => {
  it.each([
    "/verify",
    "/verify?",
    "/verify?x=1",
    "/verify?signedUrl=x&x=1",
    "/%76erify",
    "/verif%79",
  ])(
    "rejects %s without the secret",
    async (url) => {
      const res = await send(url);
      expect(res.statusCode).toBe(401);
      expect(res.json()).toMatchObject({ errorCode: VerifyErrorCode.UNAUTHORIZED });
    },
  );

  it("rejects a wrong secret with a query string", async () => {
    const res = await send("/verify?x=1", "Bearer wrong-secret");
    expect(res.statusCode).toBe(401);
  });

  it("lets the right secret through to body validation", async () => {
    const res = await send("/verify?x=1", "Bearer test-secret");
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ errorCode: VerifyErrorCode.MANIFEST_MALFORMED });
  });

  it("leaves the health probe open", async () => {
    const res = await send("/healthz", undefined, "GET");
    expect(res.statusCode).toBe(200);
  });
});
