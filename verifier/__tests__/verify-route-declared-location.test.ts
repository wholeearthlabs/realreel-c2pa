// POST /verify request-shape validation for the declaredLocation field.
//
// declaredLocation is a REQUIRED body field (strict, no tolerant fallback):
// the body-validation block rejects a request that omits it or sends a value
// outside {none, general, precise} with 400 before any fetch / verify happens.
// A request reaching this point has already passed the bearer-auth onRequest
// hook, so each case sends `Authorization: Bearer test-secret`.
//
// Same buildServer + fastify.inject + vi.mock("../src/db.js") harness as
// healthz-ready.test.ts — these cases never reach the DB or verify().

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
  // Permissive regex + a single-host allowlist: a valid-but-off-allowlist URL
  // proves a request that PASSES body validation falls through to the SSRF
  // layer (distinct errorCode), so we can assert a valid level is accepted.
  assetStorageHostRegex: /^https:\/\//,
  assetStorageHostAllowlist: new Set(["abc.supabase.co"]),
  sentryDsn: undefined,
  isProduction: true,
  playIntegrity: undefined,
  attestationRequired: false,
  certLifetimeMs: 1000,
};
const trustConfig = {} as unknown as TrustConfig;

// A body valid in every field EXCEPT declaredLocation, which each case sets.
function bodyWith(declaredLocation: unknown) {
  return {
    signedUrl: "https://abc.supabase.co/object/sign/media/x.jpg",
    expectedUserId: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
    expectedEtag: "etag-123",
    expectedContentLength: 1024,
    mimeType: "image/jpeg",
    ...(declaredLocation === undefined ? {} : { declaredLocation }),
  };
}

async function postVerify(body: unknown) {
  const fastify = buildServer({ config, trustConfig });
  try {
    return await fastify.inject({
      method: "POST",
      url: "/verify",
      headers: { authorization: "Bearer test-secret" },
      payload: body as Record<string, unknown>,
    });
  } finally {
    await fastify.close();
  }
}

describe("POST /verify — declaredLocation strict validation", () => {
  it("rejects 400 when declaredLocation is absent", async () => {
    const res = await postVerify(bodyWith(undefined));
    expect(res.statusCode).toBe(400);
    expect(res.json().errorCode).toBe(VerifyErrorCode.MANIFEST_MALFORMED);
  });

  it("rejects 400 when declaredLocation is an unrecognized value", async () => {
    const res = await postVerify(bodyWith("banana"));
    expect(res.statusCode).toBe(400);
    expect(res.json().errorCode).toBe(VerifyErrorCode.MANIFEST_MALFORMED);
  });

  for (const level of ["none", "general", "precise"] as const) {
    it(`accepts the body shape for declaredLocation='${level}' (falls through to the SSRF layer, not a body-shape 400)`, async () => {
      // Off-allowlist host → the SSRF layer returns 400 STORAGE_FETCH_FAILED.
      // The distinct errorCode (not MANIFEST_MALFORMED) proves the body passed
      // the declaredLocation gate and reached the next layer.
      const res = await postVerify({
        ...bodyWith(level),
        signedUrl: "https://not-in-allowlist.example.com/x.jpg",
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().errorCode).toBe(VerifyErrorCode.STORAGE_FETCH_FAILED);
    });
  }
});
