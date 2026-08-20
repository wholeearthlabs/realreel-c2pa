// Tests for the workflow-support commands: status precedence + validation,
// the wrangler.toml namespace extraction, the OCSP request builder (pinned
// byte-for-byte to what openssl produces), and the byte-equality live check.
//
//   deno test --allow-read ocsp/
import {
  namespaceIdFromWranglerToml,
  resolveStatus,
  verifyLive,
} from "./refresh-ops.ts";
import {
  buildOcspRequestDer,
  bytesEqual,
  bytesToBase64,
  certIdMatches,
  icaCertIdTargets,
  OID_SHA1,
  OID_SHA256,
  parseOcspRequestCertIds,
  toArrayBuffer,
} from "./ocsp.ts";

const dir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
const rootPem = await Deno.readTextFile(new URL("realreel-c2pa-root.pem", dir));
const icaPem = await Deno.readTextFile(
  new URL("realreel-claim-signing-ca.pem", dir),
);

// Same openssl-generated reference request router_test.ts pins.
const REQ_SHA1_HEX =
  "305530533051304f304d300906052b0e03021a050004149ab24e11e0c1f6d783bfdb1881f706af6954838e0414a1a57fee084567cf67b2810dcceae42fe3e6c20d0214095796d6d429759614860de66811df37549c4b8c";

function assert(cond: unknown, msg: string): void {
  if (!cond) throw new Error(msg);
}
function assertEq<T>(actual: T, expected: T, label: string): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}
async function assertRejects(
  fn: () => Promise<unknown>,
  label: string,
): Promise<void> {
  try {
    await fn();
  } catch {
    return;
  }
  throw new Error(`${label}: expected a failure`);
}
const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
};
const neverRead = () =>
  Promise.reject(new Error("readPersisted must not be called"));

Deno.test("explicit dispatch input wins without touching KV", async () => {
  const resolved = await resolveStatus({
    inputStatus: "revoked",
    inputTime: "2026-07-20T00:00:00Z",
    inputReason: "1",
    readPersisted: neverRead,
  });
  assertEq(resolved.status, "revoked", "status");
  assertEq(resolved.explicit, true, "explicit");
});

Deno.test("inherit reads the persisted record (HTTP 200)", async () => {
  const resolved = await resolveStatus({
    inputStatus: "inherit",
    inputTime: "",
    inputReason: "",
    readPersisted: () =>
      Promise.resolve({
        code: 200,
        body: JSON.stringify({
          status: "revoked",
          revocationTime: "2026-07-20T00:00:00Z",
          revocationReason: "1",
        }),
      }),
  });
  assertEq(resolved.status, "revoked", "status");
  assertEq(resolved.revocationTime, "2026-07-20T00:00:00Z", "time");
  assertEq(resolved.explicit, false, "explicit");
});

Deno.test("inherit with no persisted record (404) defaults to good", async () => {
  const resolved = await resolveStatus({
    inputStatus: "", // schedule events have no input at all
    inputTime: "",
    inputReason: "",
    readPersisted: () => Promise.resolve({ code: 404, body: "" }),
  });
  assertEq(resolved.status, "good", "status");
  assertEq(resolved.explicit, false, "explicit");
});

Deno.test("a KV read error is fatal, never a silent good", async () => {
  await assertRejects(
    () =>
      resolveStatus({
        inputStatus: "inherit",
        inputTime: "",
        inputReason: "",
        readPersisted: () => Promise.resolve({ code: 500, body: "boom" }),
      }),
    "HTTP 500 resolved",
  );
});

Deno.test("malformed persisted records are rejected", async () => {
  const inherit = (body: string) =>
    resolveStatus({
      inputStatus: "inherit",
      inputTime: "",
      inputReason: "",
      readPersisted: () => Promise.resolve({ code: 200, body }),
    });
  await assertRejects(() => inherit("not json"), "non-JSON body");
  await assertRejects(
    () => inherit(JSON.stringify({ status: "eaten" })),
    "unknown status",
  );
  // status=revoked persisted without a time must not re-sign silently
  await assertRejects(
    () => inherit(JSON.stringify({ status: "revoked" })),
    "revoked w/o time",
  );
  // Values become GitHub step outputs (line-based) and argv — newlines are an
  // injection attempt, not data.
  await assertRejects(
    () =>
      inherit(JSON.stringify({
        status: "revoked",
        revocationTime: "2026-07-20T00:00:00Z\nstatus=good",
      })),
    "newline in revocationTime",
  );
});

Deno.test("explicit revoked without a time is rejected", async () => {
  await assertRejects(
    () =>
      resolveStatus({
        inputStatus: "revoked",
        inputTime: "",
        inputReason: "",
        readPersisted: neverRead,
      }),
    "revoked w/o time",
  );
});

Deno.test("namespace id extraction matches the committed wrangler.toml", async () => {
  const toml = await Deno.readTextFile(
    new URL("wrangler.toml", import.meta.url),
  );
  assertEq(
    namespaceIdFromWranglerToml(toml),
    "544330752c3d4641a96ba2192cc2e9ab",
    "namespace id",
  );
});

Deno.test("buildOcspRequestDer reproduces openssl's request byte-for-byte (SHA-1)", async () => {
  const target = (await icaCertIdTargets(rootPem, icaPem)).find((t) =>
    t.hashOid === OID_SHA1
  )!;
  assert(
    bytesEqual(buildOcspRequestDer(target), hexToBytes(REQ_SHA1_HEX)),
    "request bytes",
  );
});

Deno.test("built SHA-256 requests round-trip through the request parser", async () => {
  const target = (await icaCertIdTargets(rootPem, icaPem)).find((t) =>
    t.hashOid === OID_SHA256
  )!;
  const parsed = parseOcspRequestCertIds(buildOcspRequestDer(target));
  assertEq(parsed.length, 1, "one CertID");
  assert(certIdMatches(parsed[0], target), "CertID round-trip");
});

Deno.test("verifyLive requires byte-identical bytes on BOTH transports, and retries", async () => {
  const expected = new TextEncoder().encode("published-response-bytes");
  const stale = new TextEncoder().encode("stale-response-bytes");
  const requestDer = hexToBytes(REQ_SHA1_HEX);
  let calls = 0;
  const sleeps: number[] = [];
  // Serves stale bytes for the first attempt (both transports), fresh after.
  const fetchFn = ((input: string | URL | Request) => {
    calls++;
    const url = String(input);
    assert(url.startsWith("http://ocsp.test"), `unexpected url ${url}`);
    const body = calls <= 2 ? stale : expected;
    if (!url.endsWith("ocsp.test")) {
      // GET form: path must be the url-encoded base64 request
      assert(
        url.endsWith(`/${encodeURIComponent(bytesToBase64(requestDer))}`),
        "GET path encodes the request",
      );
    }
    return Promise.resolve(
      new Response(toArrayBuffer(body), {
        headers: { "content-type": "application/ocsp-response" },
      }),
    );
  }) as typeof fetch;

  const attempt = await verifyLive({
    url: "http://ocsp.test",
    requestDer,
    expected,
    attempts: 3,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    fetchFn,
  });
  assertEq(attempt, 2, "succeeded on the second attempt");
  assertEq(sleeps.length, 1, "slept once between attempts");
});

Deno.test("verifyLive fails on a wrong content-type even with matching bytes", async () => {
  const expected = new TextEncoder().encode("published-response-bytes");
  const fetchFn = (() =>
    Promise.resolve(
      new Response(toArrayBuffer(expected), {
        headers: { "content-type": "text/html" }, // e.g. an interposed challenge page
      }),
    )) as typeof fetch;
  await assertRejects(
    () =>
      verifyLive({
        url: "http://ocsp.test",
        requestDer: hexToBytes(REQ_SHA1_HEX),
        expected,
        attempts: 2,
        sleep: () => Promise.resolve(),
        fetchFn,
      }),
    "content-type",
  );
});
