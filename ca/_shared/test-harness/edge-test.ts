// Shared test harness for Supabase edge functions.
//
// Goals:
//   1. Let edge-function tests run as pure Deno unit tests — no `supabase
//      start` required, no network. The handler is invoked directly with a
//      fake Request and mocked dependency object.
//   2. Centralize the structural assertions every edge-function test wants:
//      JWT-missing → 401, AAL2-required → AAL2 code, rate-limit → 429,
//      malformed body → 400.
//   3. Provide a tiny mock-Supabase-client factory so tests can assert the
//      load-bearing security shape (e.g. `eq("user_id", jwt.sub)` made it
//      onto the query) without parsing actual SQL.
//
// **Not for integration tests against a running local Supabase.** Those
// can live alongside this file later if a feature warrants them, but the
// M1 + verify-and-create-media test suites are pure unit tests against
// the handler.

import type { SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";
import type { AuthUser } from "../auth.ts";

// ---------- Test users ---------------------------------------------

// Canonical 8-4-4-4-12 hex shape — same regex shape the
// verify-and-create-media storagePath check applies. Memorable but
// real.
const TEST_USERS = {
  alice: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
  bob:   "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
} as const;

export function testUserId(name: keyof typeof TEST_USERS): string {
  return TEST_USERS[name];
}

/** Build a minimal AuthUser for handler tests. Doesn't carry a real
 * JWT — the handler only reads .id and .aal directly. */
export function fakeAuthUser(
  overrides: Partial<AuthUser> & Pick<AuthUser, "id">,
): AuthUser {
  return {
    aal: "aal2",
    client: makeMockSupabaseClient() as unknown as SupabaseClient,
    ...overrides,
  } as AuthUser;
}

// ---------- Request builder ----------------------------------------

export function buildRequest(opts: {
  method?: string;
  url?: string;
  bearer?: string;
  body?: unknown;
  headers?: Record<string, string>;
}): Request {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...opts.headers,
  };
  if (opts.bearer) headers["authorization"] = `Bearer ${opts.bearer}`;
  return new Request(opts.url ?? "http://localhost/test", {
    method: opts.method ?? "POST",
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

// ---------- Mock Supabase client -----------------------------------

/**
 * Captured details of every `.from(table).<op>(...)` chain invocation,
 * so a test can assert "the WHERE clause carried user_id = $jwtUserId"
 * structurally without parsing SQL.
 */
export interface MockSupabaseCall {
  table: string;
  op: "select" | "insert" | "update" | "delete" | "upsert" | "rpc";
  values?: unknown;
  upsertOptions?: unknown;
  filters: Array<
    | { kind: "eq"; column: string; value: unknown }
    | { kind: "is"; column: string; value: unknown }
    | { kind: "in"; column: string; value: unknown }
  >;
}

/** Captured call to admin.storage.from(bucket).remove(paths). Tests
 * assert which bucket and which paths the handler removed. */
export interface MockStorageRemoveCall {
  bucket: string;
  paths: string[];
}

export interface MockSupabaseClient {
  client: SupabaseClient;
  calls: MockSupabaseCall[];
  /** Captured admin.storage.from(bucket).remove(paths) invocations.
   * Push-on-call; tests inspect to assert delete shape. */
  storageRemoveCalls: MockStorageRemoveCall[];
  /** Override the result returned by the next executable operation.
   * Replaces any queued sequence. */
  setNextResult(result: { data?: unknown; error?: unknown }): void;
  /** Queue a sequence of results, consumed one per .then() resolution.
   * Useful for tests that drive multiple DB ops in a single handler
   * call (e.g. upsert then select on ON CONFLICT). After the queue is
   * exhausted, falls back to `{ data: null, error: null }`. */
  queueResults(results: Array<{ data?: unknown; error?: unknown }>): void;
  /** Override the result returned by the next .storage.from().remove().
   * Default is `{ data: [], error: null }` (success, zero rows removed —
   * tests that don't care can ignore). */
  setNextStorageRemoveResult(result: { data?: unknown; error?: unknown }): void;
}

export function makeMockSupabaseClient(): MockSupabaseClient {
  const calls: MockSupabaseCall[] = [];
  const storageRemoveCalls: MockStorageRemoveCall[] = [];
  let nextResult: { data?: unknown; error?: unknown } = {
    data: null,
    error: null,
  };
  let resultQueue: Array<{ data?: unknown; error?: unknown }> = [];
  let nextStorageRemoveResult: { data?: unknown; error?: unknown } = {
    data: [],
    error: null,
  };

  function consumeResult(): { data: unknown; error: unknown } {
    let r: { data?: unknown; error?: unknown };
    if (resultQueue.length > 0) {
      r = resultQueue.shift()!;
    } else {
      r = nextResult;
      nextResult = { data: null, error: null };
    }
    return { data: r.data ?? null, error: r.error ?? null };
  }

  // deno-lint-ignore no-explicit-any
  type Chain = any;
  function makeChain(call: MockSupabaseCall): Chain {
    // The chain is a Proxy-style object that returns itself for filter
    // ops (eq, is, in, …) and a thenable for the final await. Captures
    // all filter calls into `call.filters` for inspection. Loose
    // typing here is intentional — this is test plumbing, not
    // production code; tight typing fights more than it helps because
    // postgres-js / supabase-js builder chains carry generic state we
    // don't replicate.
    const chain: Chain = {
      eq: (column: string, value: unknown) => {
        call.filters.push({ kind: "eq", column, value });
        return chain;
      },
      is: (column: string, value: unknown) => {
        call.filters.push({ kind: "is", column, value });
        return chain;
      },
      in: (column: string, value: unknown) => {
        call.filters.push({ kind: "in", column, value });
        return chain;
      },
      select: () => chain,
      single: () => chain,
      maybeSingle: () => chain,
      then: (
        resolve: (v: { data: unknown; error: unknown }) => unknown,
      ) => {
        return Promise.resolve(consumeResult()).then(resolve);
      },
    };
    return chain;
  }

  const client = {
    from(table: string) {
      return {
        select() {
          const call: MockSupabaseCall = { table, op: "select", filters: [] };
          calls.push(call);
          return makeChain(call);
        },
        insert(values: unknown) {
          const call: MockSupabaseCall = { table, op: "insert", values, filters: [] };
          calls.push(call);
          return makeChain(call);
        },
        update(values: unknown) {
          const call: MockSupabaseCall = { table, op: "update", values, filters: [] };
          calls.push(call);
          return makeChain(call);
        },
        delete() {
          const call: MockSupabaseCall = { table, op: "delete", filters: [] };
          calls.push(call);
          return makeChain(call);
        },
        upsert(values: unknown, upsertOptions?: unknown) {
          const call: MockSupabaseCall = {
            table,
            op: "upsert",
            values,
            upsertOptions,
            filters: [],
          };
          calls.push(call);
          return makeChain(call);
        },
      };
    },
    // .rpc(name, args) — consumed by the same nextResult / resultQueue
    // pipeline as .from() ops. `table` is set to `rpc:<name>` so test
    // assertions can disambiguate from a regular .from() call.
    rpc(name: string, args?: unknown) {
      const call: MockSupabaseCall = {
        table: `rpc:${name}`,
        op: "rpc",
        values: args,
        filters: [],
      };
      calls.push(call);
      return makeChain(call);
    },
    // Optional: storage mock. .remove() captures (bucket, paths) into
    // storageRemoveCalls so tests can assert delete shape; the result is
    // independently configurable via setNextStorageRemoveResult.
    storage: {
      from(bucket: string) {
        return {
          createSignedUrl: async (
            _path: string,
            _ttl: number,
          ): Promise<{ data: { signedUrl: string } | null; error: unknown }> => ({
            data: { signedUrl: "https://mock-signed-url.example.invalid/x" },
            error: null,
          }),
          info: async (
            _path: string,
          ): Promise<{ data: { eTag: string; size: number } | null; error: unknown }> => ({
            data: { eTag: '"mock-etag"', size: 1024 },
            error: null,
          }),
          remove: async (
            paths: string[],
          ): Promise<{ data: unknown; error: unknown }> => {
            storageRemoveCalls.push({ bucket, paths: [...paths] });
            const r = nextStorageRemoveResult;
            nextStorageRemoveResult = { data: [], error: null };
            return { data: r.data ?? [], error: r.error ?? null };
          },
          getPublicUrl: (path: string): { data: { publicUrl: string } } => ({
            data: {
              publicUrl:
                "https://mock-public-url.example.invalid/storage/v1/object/public/media/" +
                path,
            },
          }),
        };
      },
    },
  } as unknown as SupabaseClient;

  return {
    client,
    calls,
    storageRemoveCalls,
    setNextResult(result) {
      nextResult = result;
      resultQueue = [];
    },
    queueResults(results) {
      resultQueue = [...results];
    },
    setNextStorageRemoveResult(result) {
      nextStorageRemoveResult = result;
    },
  };
}

// ---------- Default test dependency object -------------------------

/**
 * Build a default deps object covering the four standard edge-function
 * boundaries (auth, AAL2, rate-limit, service-role client) plus a deterministic
 * `now()`. Tests override specific fields as needed.
 *
 * Generic over a specific deps shape because each edge function declares
 * its own RevokeDeps / VerifyDeps interface; the harness produces a
 * compatible default and tests cast on the way out.
 */
export interface BaseDeps {
  getUserFromAuthHeader: (req: Request) => Promise<AuthUser | null>;
  requireAal2IfMfaEnrolled: (user: AuthUser) => Promise<Response | null>;
  enforceRateLimit: (
    surface: string,
    userId: string,
    windows: ReadonlyArray<{ windowSec: number; max: number }>,
  ) => Promise<{ ok: true } | { ok: false; retryAfter: number }>;
  makeServiceRoleClient: () => SupabaseClient;
  now: () => Date;
}

export function makeBaseDeps(opts: {
  user?: AuthUser | null;
  aalReject?: Response | null;
  rateLimit?: { ok: true } | { ok: false; retryAfter: number };
  client?: SupabaseClient;
  now?: Date;
}): BaseDeps {
  return {
    getUserFromAuthHeader: async () => opts.user ?? null,
    requireAal2IfMfaEnrolled: async () => opts.aalReject ?? null,
    enforceRateLimit: async () => opts.rateLimit ?? { ok: true },
    makeServiceRoleClient: () =>
      opts.client ?? (makeMockSupabaseClient().client),
    now: () => opts.now ?? new Date("2026-05-14T12:00:00Z"),
  };
}

// ---------- Response helpers ---------------------------------------

export async function readJsonResponse<T = unknown>(
  res: Response,
): Promise<{ status: number; body: T }> {
  const body = res.headers.get("content-type")?.includes("json")
    ? await res.json()
    : await res.text();
  return { status: res.status, body: body as T };
}

/**
 * Strict response-shape parity check. Asserts two responses are
 * indistinguishable to the caller (same status, same body keys, same body
 * values). Load-bearing for any endpoint that must not leak the existence
 * of a resource via response variation.
 */
export function assertResponseShapesIdentical(
  a: { status: number; body: unknown },
  b: { status: number; body: unknown },
): void {
  if (a.status !== b.status) {
    throw new Error(
      `Response status differs: ${a.status} vs ${b.status} — endpoint MAY be an existence oracle`,
    );
  }
  const aJson = JSON.stringify(a.body);
  const bJson = JSON.stringify(b.body);
  if (aJson !== bJson) {
    throw new Error(
      `Response body differs:\n  a: ${aJson}\n  b: ${bJson}\n` +
        `endpoint MAY be an existence oracle`,
    );
  }
}
