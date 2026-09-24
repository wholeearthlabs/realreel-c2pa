// Tests for the Google attestation revocation list: serial matching in both
// radices the list uses, list parsing, and the loader's cache/fallback policy.
// No network — the loader takes an injected fetch.

import { assertEquals, assertRejects, assertThrows } from "std/assert/mod.ts";
import {
  ANDROID_ATTESTATION_STATUS_URL,
  buildAndroidRevocationLoader,
  findRevoked,
  parseAndroidRevocationList,
  serialForms,
} from "./android_revocation.ts";
import { base64ToBytes, parseCertFromDer } from "./pki.ts";

async function loadJson(name: string): Promise<unknown | null> {
  try {
    return JSON.parse(
      await Deno.readTextFile(
        new URL(`./__fixtures__/${name}`, import.meta.url),
      ),
    );
  } catch {
    return null;
  }
}

Deno.test("serialForms — lowercase hex and decimal, no leading zeros, DER 0x00 pad dropped", () => {
  assertEquals(serialForms(new Uint8Array([0x00, 0x92, 0x42])), {
    hex: "9242",
    dec: "37442",
  });
  assertEquals(serialForms(new Uint8Array([0x00, 0x00, 0x01])), {
    hex: "1",
    dec: "1",
  });
  assertEquals(serialForms(new Uint8Array([0x0e, 0xfa])), {
    hex: "efa",
    dec: "3834",
  });
});

Deno.test("serialForms — real chain cert whose DER serial starts with a 0x00 byte", async () => {
  const fix = await loadJson("android_strongbox.json") as
    | { attestation: string }
    | null;
  if (!fix) return;
  const chain = (JSON.parse(fix.attestation) as string[]).map((b) =>
    parseCertFromDer(base64ToBytes(b))
  );
  const der = (i: number) =>
    new Uint8Array(chain[i].serialNumber.valueBlock.valueHexView);
  assertEquals(serialForms(der(0)).hex, "1");
  assertEquals(serialForms(der(3)).hex, "924250191903e3ba65320efd6a2085fb");
});

// Excerpt of the live list (2026-09-23): three 64-bit serials written in
// decimal, three 128-bit serials written in hex, one SOFTWARE_FLAW entry.
Deno.test("findRevoked — matches serials the list writes in decimal or in hex", async () => {
  const snapshot = await loadJson("android_attestation_status_excerpt.json");
  if (!snapshot) throw new Error("excerpt fixture missing");
  const list = parseAndroidRevocationList(snapshot);
  assertEquals(list.size, 7);

  const der = (hex: string) =>
    new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
  // 6681152659205225093 = 0x5cb838f1fe157a85: listed in decimal only.
  assertEquals(findRevoked(der("5cb838f1fe157a85"), list), {
    serial: "6681152659205225093",
    entry: { status: "REVOKED", reason: "KEY_COMPROMISE" },
  });
  // 9408173275444922801 = 0x82908bbf5437c9b1: top bit set, so DER pads it.
  assertEquals(
    findRevoked(der("0082908bbf5437c9b1"), list)?.serial,
    "9408173275444922801",
  );
  assertEquals(
    findRevoked(der("f277e2565b15fd0b"), list)?.entry.reason,
    "SOFTWARE_FLAW",
  );
  // Hex-listed serial.
  assertEquals(
    findRevoked(der("c35747a084470c3135aeefe2b8d40cd6"), list)?.serial,
    "c35747a084470c3135aeefe2b8d40cd6",
  );
  assertEquals(
    findRevoked(der("001f4363f4acefdf83ae59202b934cead9"), list)?.serial,
    "1f4363f4acefdf83ae59202b934cead9",
  );
  // Unlisted.
  assertEquals(findRevoked(der("5cb838f1fe157a86"), list), null);
  assertEquals(findRevoked(der("01"), list), null);
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

Deno.test("parseAndroidRevocationList — rejects empty, missing, array-shaped, or non-numeric-key lists", () => {
  assertThrows(() => parseAndroidRevocationList({}), Error, "entries");
  assertThrows(() => parseAndroidRevocationList(null), Error, "entries");
  assertThrows(() => parseAndroidRevocationList({ entries: "x" }), Error);
  assertThrows(
    () => parseAndroidRevocationList({ entries: [] }),
    Error,
    "entries",
  );
  assertThrows(
    () => parseAndroidRevocationList({ entries: {} }),
    Error,
    "empty",
  );
  assertThrows(
    () =>
      parseAndroidRevocationList({
        entries: { "0x1234": { status: "REVOKED" } },
      }),
    Error,
    "non-numeric",
  );
});

// --- loader ------------------------------------------------------------

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
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

Deno.test("loader — failed refresh serves the cache under 7 days old and backs off for 5 minutes", async () => {
  const { fetchImpl, calls } = scriptedFetch(["ok", "network", "ok"]);
  const c = clock();
  const load = buildAndroidRevocationLoader({ fetch: fetchImpl, now: c.now });
  const first = await load();
  c.advance(25 * HOUR);
  assertEquals(await load(), first); // refresh fails → stale copy
  assertEquals(calls.length, 2);
  c.advance(1 * MINUTE);
  assertEquals(await load(), first); // inside the back-off → no network
  assertEquals(calls.length, 2);
  c.advance(5 * MINUTE);
  await load(); // back-off over → refresh succeeds
  assertEquals(calls.length, 3);
  c.advance(6 * DAY);
  assertEquals(await load(), first); // still under 7 days after the refresh... no: fresh copy from call 3
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
