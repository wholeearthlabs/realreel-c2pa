// Tests for the Google attestation revocation list: serial normalization,
// list parsing, and the loader's cache/fallback policy. No network — the
// loader takes an injected fetch.

import { assertEquals, assertRejects, assertThrows } from "std/assert/mod.ts";
import {
  ANDROID_ATTESTATION_STATUS_URL,
  buildAndroidRevocationLoader,
  certSerialHex,
  parseAndroidRevocationList,
  serialHex,
} from "./android_revocation.ts";
import { base64ToBytes, parseCertFromDer } from "./pki.ts";

Deno.test("serialHex — lowercase hex, no leading zeros, DER 0x00 pad byte dropped", () => {
  assertEquals(serialHex(new Uint8Array([0x00, 0x92, 0x42])), "9242");
  assertEquals(serialHex(new Uint8Array([0x00, 0x00, 0x01])), "1");
  assertEquals(serialHex(new Uint8Array([0x0e, 0xfa])), "efa");
  assertEquals(serialHex(new Uint8Array([0xab, 0xcd])), "abcd");
  assertEquals(serialHex(new Uint8Array([0x01])), "1");
});

Deno.test("certSerialHex — real chain cert whose DER serial starts with a 0x00 byte", async () => {
  let fix: { attestation: string };
  try {
    fix = JSON.parse(
      await Deno.readTextFile(
        new URL("./__fixtures__/android_strongbox.json", import.meta.url),
      ),
    );
  } catch {
    return;
  }
  const chain = (JSON.parse(fix.attestation) as string[]).map((b) =>
    parseCertFromDer(base64ToBytes(b))
  );
  assertEquals(certSerialHex(chain[0]), "1");
  assertEquals(certSerialHex(chain[3]), "924250191903e3ba65320efd6a2085fb");
});

Deno.test("parseAndroidRevocationList — normalizes keys, keeps status + reason", () => {
  const list = parseAndroidRevocationList({
    entries: {
      "00ABCD": { status: "REVOKED", reason: "KEY_COMPROMISE" },
      "ef01": { status: "SUSPENDED" },
    },
  });
  assertEquals(list.size, 2);
  assertEquals(list.get("abcd"), {
    status: "REVOKED",
    reason: "KEY_COMPROMISE",
  });
  assertEquals(list.get("ef01"), { status: "SUSPENDED", reason: null });
});

Deno.test("parseAndroidRevocationList — rejects a body without an entries object", () => {
  assertThrows(() => parseAndroidRevocationList({}), Error, "entries");
  assertThrows(() => parseAndroidRevocationList(null), Error, "entries");
  assertThrows(() => parseAndroidRevocationList({ entries: "x" }), Error);
});

// --- loader ------------------------------------------------------------

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const ENTRIES = { abcd: { status: "REVOKED", reason: "KEY_COMPROMISE" } };

type Step = "ok" | "http500" | "network" | "garbage";

/** A fetch whose i-th call follows steps[i] (the last step repeats). */
function scriptedFetch(steps: Step[]) {
  const calls: Array<{ url: string; signal: AbortSignal | null | undefined }> =
    [];
  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(input), signal: init?.signal });
    const step = steps[Math.min(calls.length - 1, steps.length - 1)];
    switch (step) {
      case "network":
        return Promise.reject(new TypeError("dns failure"));
      case "http500":
        return Promise.resolve(new Response("boom", { status: 500 }));
      case "garbage":
        return Promise.resolve(new Response("not json", { status: 200 }));
      case "ok":
        return Promise.resolve(
          new Response(JSON.stringify({ entries: ENTRIES }), { status: 200 }),
        );
    }
  }) as typeof fetch;
  return { fetchImpl, calls };
}

function clock(start = "2026-09-23T00:00:00Z") {
  let t = new Date(start).getTime();
  return { now: () => new Date(t), advance: (ms: number) => (t += ms) };
}

Deno.test("loader — fetches the fixed URL with a timeout signal and caches for 24h", async () => {
  const { fetchImpl, calls } = scriptedFetch(["ok"]);
  const c = clock();
  const load = buildAndroidRevocationLoader({ fetch: fetchImpl, now: c.now });

  const list = await load();
  assertEquals(list.get("abcd")?.reason, "KEY_COMPROMISE");
  assertEquals(calls.length, 1);
  assertEquals(calls[0].url, ANDROID_ATTESTATION_STATUS_URL);
  assertEquals(calls[0].signal instanceof AbortSignal, true);

  c.advance(23 * HOUR);
  assertEquals(await load(), list);
  assertEquals(calls.length, 1);

  c.advance(2 * HOUR);
  await load();
  assertEquals(calls.length, 2);
});

Deno.test("loader — fetch failure with a cache under 7 days old serves the cache", async () => {
  const { fetchImpl, calls } = scriptedFetch(["ok", "network"]);
  const c = clock();
  const load = buildAndroidRevocationLoader({ fetch: fetchImpl, now: c.now });
  const first = await load();
  c.advance(6 * DAY);
  assertEquals(await load(), first);
  assertEquals(calls.length, 2);
});

Deno.test("loader — fetch failure with a cache over 7 days old throws", async () => {
  const { fetchImpl } = scriptedFetch(["ok", "http500"]);
  const c = clock();
  const load = buildAndroidRevocationLoader({ fetch: fetchImpl, now: c.now });
  await load();
  c.advance(8 * DAY);
  await assertRejects(load, Error, "unavailable");
});

Deno.test("loader — fetch failure with no cache throws, and a later fetch recovers", async () => {
  for (const failure of ["network", "http500", "garbage"] as Step[]) {
    const { fetchImpl, calls } = scriptedFetch([failure, "ok"]);
    const load = buildAndroidRevocationLoader({ fetch: fetchImpl });
    await assertRejects(load, Error, "unavailable");
    assertEquals((await load()).has("abcd"), true, failure);
    assertEquals(calls.length, 2, failure);
  }
});
