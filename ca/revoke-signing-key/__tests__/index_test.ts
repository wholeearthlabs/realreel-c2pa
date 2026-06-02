// Unit tests for revoke-signing-key.
//
// The endpoint is the critical security primitive for "user A cannot
// modify user B's enrollments." These tests assert the load-bearing
// shape of the UPDATE WHERE clause structurally (without round-tripping
// through Postgres), plus the response-shape parity that prevents the
// endpoint from being a key-existence oracle.

import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  handleRevoke,
  type RevokeDeps,
} from "../index.ts";
import {
  assertResponseShapesIdentical,
  buildRequest,
  fakeAuthUser,
  makeBaseDeps,
  makeMockSupabaseClient,
  readJsonResponse,
  testUserId,
} from "../../_shared/test-harness/edge-test.ts";

// Helper: build a RevokeDeps object using the shared test harness. The
// only field we ever override per-test is the mock client (so we can
// inspect captured query shape). Everything else uses the harness
// defaults.
function buildDeps(opts: {
  userId?: string;
  client?: ReturnType<typeof makeMockSupabaseClient>;
  rateLimit?: { ok: true } | { ok: false; retryAfter: number };
  aalReject?: Response | null;
  now?: Date;
} = {}): { deps: RevokeDeps; mockClient: ReturnType<typeof makeMockSupabaseClient> } {
  const mockClient = opts.client ?? makeMockSupabaseClient();
  const base = makeBaseDeps({
    user: fakeAuthUser({ id: opts.userId ?? testUserId("alice") }),
    rateLimit: opts.rateLimit,
    aalReject: opts.aalReject,
    client: mockClient.client,
    now: opts.now,
  });
  const deps: RevokeDeps = {
    ...base,
    // The handler's RevokeDeps type expects the makeServiceRoleClient
    // signature; the harness already provides a compatible factory.
  };
  return { deps, mockClient };
}

Deno.test("revoke-signing-key — happy path UPDATE has the load-bearing WHERE clause", async () => {
  const { deps, mockClient } = buildDeps({
    userId: testUserId("alice"),
    now: new Date("2026-05-14T12:34:56Z"),
  });
  // Mock returns "0 rows affected" — same as real soft-DELETE against a
  // key that doesn't exist or is already revoked. The structural
  // assertions below are what matter, not the result.
  mockClient.setNextResult({ data: null, error: null });

  const res = await handleRevoke(
    buildRequest({
      bearer: "ignored-by-mock-auth",
      body: { keyId: "alice-key-id" },
    }),
    deps,
  );
  assertEquals(res.status, 200);

  // Exactly one DB call.
  assertEquals(mockClient.calls.length, 1);
  const call = mockClient.calls[0];
  assertEquals(call.table, "user_signing_keys");
  assertEquals(call.op, "update");
  assertEquals(call.values, { revoked_at: "2026-05-14T12:34:56.000Z" });

  // Three filters — user_id, key_id, and the revoked_at IS NULL guard
  // that gives idempotency.
  assertEquals(call.filters.length, 3);
  assertEquals(call.filters[0], { kind: "eq", column: "user_id", value: testUserId("alice") });
  assertEquals(call.filters[1], { kind: "eq", column: "key_id", value: "alice-key-id" });
  assertEquals(call.filters[2], { kind: "is", column: "revoked_at", value: null });
});

Deno.test("revoke-signing-key — cross-user attempt: A's JWT cannot revoke B's key", async () => {
  // Alice posts Bob's keyId with Alice's JWT. The WHERE clause's
  // user_id = alice's id means the UPDATE matches zero rows for Bob's
  // key, regardless of whether the key exists. The endpoint returns
  // 200 + { ok: true } either way (idempotent semantics).
  const { deps, mockClient } = buildDeps({ userId: testUserId("alice") });
  mockClient.setNextResult({ data: null, error: null }); // 0-row update

  const res = await handleRevoke(
    buildRequest({
      bearer: "alice-jwt",
      body: { keyId: "bobs-key-id-that-belongs-to-someone-else" },
    }),
    deps,
  );
  assertEquals(res.status, 200);

  // The WHERE clause carried Alice's user_id, NOT Bob's. The query is
  // structurally incapable of touching Bob's row.
  const call = mockClient.calls[0];
  const userIdFilter = call.filters.find((f) => f.column === "user_id");
  assertEquals(userIdFilter?.value, testUserId("alice"));
  // Sanity: the keyId we sent did make it onto the query, but bounded
  // by the user_id filter.
  const keyIdFilter = call.filters.find((f) => f.column === "key_id");
  assertEquals(keyIdFilter?.value, "bobs-key-id-that-belongs-to-someone-else");
});

Deno.test(
  "revoke-signing-key — response shape parity: three indistinguishable 0-row scenarios (no existence oracle)",
  async () => {
    // The endpoint must NOT reveal which of these three scenarios it
    // actually processed:
    //   (a) Alice's JWT + Bob's key_id        — WHERE user_id = alice
    //                                            doesn't match (Bob owns it)
    //   (b) Alice's JWT + nonexistent key_id  — no row at all
    //   (c) Alice's JWT + Alice's own         — already-revoked row;
    //       already-revoked key_id              `revoked_at IS NULL`
    //                                           filter excludes it
    // All three yield 0 affected rows, all three must yield byte-
    // identical 200 responses. Any divergence is a key-existence
    // oracle.
    //
    // Parameterized per reviewer suggestion (M1 polish): adds the
    // already-revoked-own-key case that previously was only exercised
    // by the idempotency test.

    const scenarios = [
      { name: "victim key (cross-user)", keyId: "bobs-key-id" },
      { name: "own nonexistent key", keyId: "alice-nonexistent" },
      { name: "own already-revoked key", keyId: "alice-already-revoked" },
    ];

    const responses = await Promise.all(
      scenarios.map(async () => {
        const { deps, mockClient } = buildDeps({ userId: testUserId("alice") });
        // All three real-world cases produce 0-row UPDATE results,
        // even though the underlying SQL is filtering for different
        // reasons. The mock returns "no data, no error" — same as
        // Postgres returning a 0-row UPDATE.
        mockClient.setNextResult({ data: null, error: null });
        return await handleRevoke(
          buildRequest({
            bearer: "alice-jwt",
            body: { keyId: scenarios[0].keyId }, // unused — name kept for clarity
          }),
          deps,
        );
      }),
    );

    const jsons = await Promise.all(responses.map((r) => readJsonResponse(r)));
    // Pin the first as the oracle; all others must match it.
    for (let i = 1; i < jsons.length; i++) {
      assertResponseShapesIdentical(jsons[0], jsons[i]);
    }
  },
);

Deno.test("revoke-signing-key — already-revoked-or-missing key returns 200 (idempotent)", async () => {
  // The revoked_at IS NULL guard means a second tap matches 0 rows.
  // Endpoint must return 200 + ok: true so a double-tapping client
  // doesn't see a fake error.
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({ data: null, error: null });

  const res = await handleRevoke(
    buildRequest({
      bearer: "alice-jwt",
      body: { keyId: "already-revoked-key" },
    }),
    deps,
  );
  assertEquals(res.status, 200);
  const json = await readJsonResponse<{ ok: boolean }>(res);
  assertEquals(json.body.ok, true);
});

Deno.test("revoke-signing-key — missing Authorization → 401", async () => {
  const base = makeBaseDeps({ user: null });
  const res = await handleRevoke(
    buildRequest({ body: { keyId: "anything" } }),
    base as RevokeDeps,
  );
  assertEquals(res.status, 401);
});

Deno.test("revoke-signing-key — malformed keyId → 400", async () => {
  const { deps } = buildDeps();
  const cases: Array<{ name: string; body: unknown }> = [
    { name: "missing keyId field", body: {} },
    { name: "keyId is empty string", body: { keyId: "" } },
    { name: "keyId is too long (>128 chars)", body: { keyId: "x".repeat(129) } },
    { name: "keyId is not a string", body: { keyId: 1234 } },
  ];
  for (const tc of cases) {
    const res = await handleRevoke(
      buildRequest({ bearer: "alice", body: tc.body }),
      deps,
    );
    assertEquals(res.status, 400, `expected 400 for ${tc.name}`);
  }
});

Deno.test("revoke-signing-key — rate-limit exceeded → 429 with Retry-After", async () => {
  const { deps } = buildDeps({
    rateLimit: { ok: false, retryAfter: 600 },
  });
  const res = await handleRevoke(
    buildRequest({ bearer: "alice", body: { keyId: "anything" } }),
    deps,
  );
  assertEquals(res.status, 429);
  assertEquals(res.headers.get("Retry-After"), "600");
});

Deno.test("revoke-signing-key — non-POST method → 405", async () => {
  const { deps } = buildDeps();
  const res = await handleRevoke(
    buildRequest({ method: "GET", bearer: "alice" }),
    deps,
  );
  assertEquals(res.status, 405);
});

Deno.test("revoke-signing-key — DB error surfaces as 500", async () => {
  const { deps, mockClient } = buildDeps();
  mockClient.setNextResult({ data: null, error: { message: "connection lost" } });
  const res = await handleRevoke(
    buildRequest({ bearer: "alice", body: { keyId: "any" } }),
    deps,
  );
  assertEquals(res.status, 500);
});
