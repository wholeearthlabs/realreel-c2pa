// Unit tests for mint-attestation-challenges.
//
// The endpoint is the trust-list entrypoint for per-capture attestation
// challenges. Tests assert: (a) auth + validation gates, (b) the RPC
// receives the right shape (load-bearing for the SECURITY DEFINER's
// ownership check), (c) RPC error codes map to the right HTTP statuses,
// and (d) the response contains only nonces — the DB carries the rest.

import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { defaultDeps, handleMintChallenges, type MintChallengesDeps } from "../index.ts";
import {
  buildRequest,
  fakeAuthUser,
  makeBaseDeps,
  makeMockSupabaseClient,
  readJsonResponse,
  testUserId,
} from "../../_shared/test-harness/edge-test.ts";

function buildDeps(opts: {
  userId?: string;
  client?: ReturnType<typeof makeMockSupabaseClient>;
  noUser?: boolean;
} = {}): { deps: MintChallengesDeps; mockClient: ReturnType<typeof makeMockSupabaseClient> } {
  const mockClient = opts.client ?? makeMockSupabaseClient();
  const base = makeBaseDeps({
    user: opts.noUser
      ? null
      : fakeAuthUser({ id: opts.userId ?? testUserId("alice") }),
    client: mockClient.client,
  });
  const deps: MintChallengesDeps = {
    getUserFromAuthHeader: base.getUserFromAuthHeader,
    makeServiceRoleClient: base.makeServiceRoleClient,
  };
  return { deps, mockClient };
}

const KEY_ID = "test-key-id-base64==";

Deno.test("mint-attestation-challenges — happy path returns nonces and burns nothing", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({
    data: [
      { nonce: "nonce-a", issued_at: "2026-05-14T20:00:00Z" },
      { nonce: "nonce-b", issued_at: "2026-05-14T20:00:00Z" },
      { nonce: "nonce-c", issued_at: "2026-05-14T20:00:00Z" },
    ],
    error: null,
  });

  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 3 } }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ challenges: string[] }>(res);
  assertEquals(status, 200);
  assertEquals(body.challenges, ["nonce-a", "nonce-b", "nonce-c"]);

  // The RPC must be called with the JWT user's id (not a body-supplied one)
  // — load-bearing for the ownership check inside the SECURITY DEFINER fn.
  assertEquals(mockClient.calls.length, 1);
  const call = mockClient.calls[0];
  assertEquals(call.table, "rpc:mint_attestation_challenges");
  assertEquals(call.op, "rpc");
  assertEquals(call.values, {
    p_key_id: KEY_ID,
    p_user_id: testUserId("alice"),
    p_count: 3,
  });
});

Deno.test("mint-attestation-challenges — default count is applied when count is omitted", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({
    data: Array.from({ length: 100 }, (_, i) => ({
      nonce: `n${i}`,
      issued_at: "2026-05-14T20:00:00Z",
    })),
    error: null,
  });

  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID } }),
    deps,
  );
  assertEquals(res.status, 200);
  assertEquals(mockClient.calls[0].values, {
    p_key_id: KEY_ID,
    p_user_id: testUserId("alice"),
    p_count: 100,
  });
});

Deno.test("mint-attestation-challenges — missing Authorization → 401", async () => {
  const { deps, mockClient } = buildDeps({ noUser: true });
  const res = await handleMintChallenges(
    buildRequest({ body: { keyId: KEY_ID } }),
    deps,
  );
  assertEquals(res.status, 401);
  // Must not have hit the DB.
  assertEquals(mockClient.calls.length, 0);
});

Deno.test("mint-attestation-challenges — non-POST method → 405", async () => {
  const { deps } = buildDeps();
  const res = await handleMintChallenges(
    buildRequest({ method: "GET", bearer: "ignored" }),
    deps,
  );
  assertEquals(res.status, 405);
});

Deno.test("mint-attestation-challenges — malformed JSON body → 400", async () => {
  const { deps } = buildDeps();
  // Hand-craft a request with a body that isn't valid JSON.
  const req = new Request("http://localhost/test", {
    method: "POST",
    headers: { "content-type": "application/json", "authorization": "Bearer x" },
    body: "{not-json",
  });
  const res = await handleMintChallenges(req, deps);
  assertEquals(res.status, 400);
});

Deno.test("mint-attestation-challenges — missing keyId → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { count: 50 } }),
    deps,
  );
  assertEquals(res.status, 400);
  const { body } = await readJsonResponse<{ error: string }>(res);
  assertEquals(body.error, "keyId is required");
});

Deno.test("mint-attestation-challenges — count < 1 → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 0 } }),
    deps,
  );
  assertEquals(res.status, 400);
});

Deno.test("mint-attestation-challenges — count > 200 → 400", async () => {
  const { deps } = buildDeps();
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 201 } }),
    deps,
  );
  assertEquals(res.status, 400);
});

Deno.test("mint-attestation-challenges — RPC 42501 (key not owned/revoked) → 403", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({
    data: null,
    error: {
      code: "42501",
      message: "mint_attestation_challenges: key_id not owned by user or revoked",
    },
  });
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 5 } }),
    deps,
  );
  assertEquals(res.status, 403);
});

Deno.test("mint-attestation-challenges — RPC 22023 (bad count) → 400", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({
    data: null,
    error: {
      code: "22023",
      message: "mint_attestation_challenges: count must be 1..200",
    },
  });
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 5 } }),
    deps,
  );
  assertEquals(res.status, 400);
});

Deno.test("mint-attestation-challenges — RPC unknown error → 500", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({
    data: null,
    error: { code: "XX000", message: "Postgres ate the request" },
  });
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 5 } }),
    deps,
  );
  assertEquals(res.status, 500);
});

Deno.test("mint-attestation-challenges — RPC returns non-array → 500", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({ data: { unexpected: "shape" }, error: null });
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 5 } }),
    deps,
  );
  assertEquals(res.status, 500);
});

Deno.test("mint-attestation-challenges — rows missing nonce are filtered out", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({
    data: [
      { nonce: "good-1", issued_at: "..." },
      { nonce: "", issued_at: "..." },         // empty — filtered
      { issued_at: "..." },                     // missing — filtered
      { nonce: "good-2", issued_at: "..." },
    ],
    error: null,
  });
  const res = await handleMintChallenges(
    buildRequest({ bearer: "ignored", body: { keyId: KEY_ID, count: 4 } }),
    deps,
  );
  const { status, body } = await readJsonResponse<{ challenges: string[] }>(res);
  assertEquals(status, 200);
  assertEquals(body.challenges, ["good-1", "good-2"]);
});

Deno.test("mint-attestation-challenges — defaultDeps export is wired correctly", () => {
  // Defensive check: production deps must include both injection seams. If
  // someone refactors and forgets to add one to defaultDeps, every production
  // request would NPE at the handler — this catches it at test time.
  assertEquals(typeof defaultDeps.getUserFromAuthHeader, "function");
  assertEquals(typeof defaultDeps.makeServiceRoleClient, "function");
});
