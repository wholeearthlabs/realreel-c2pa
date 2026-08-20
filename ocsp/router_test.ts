// Router tests: drive the OCSP router with request bytes produced by openssl
// (an independent RFC 6960 implementation) against the real ceremony certs, so
// CertID matching is pinned to what clients actually send — not to our own
// encoder. Response bytes come from a stubbed store; the signed-response
// round-trip lives in build_ocsp_responses_test.ts.
//
//   deno test --allow-read ocsp/
import { handleRequest, type ResponseStore } from "./router.ts";
import {
  buildOcspRequestDer,
  bytesEqual,
  leafIssuerTargets,
  OCSP_INTERNAL_ERROR,
  OCSP_MALFORMED_REQUEST,
  OCSP_UNAUTHORIZED,
  OID_SHA256,
  OID_SHA384,
  toArrayBuffer,
} from "./ocsp.ts";

const dir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
const rootPem = await Deno.readTextFile(new URL("realreel-c2pa-root.pem", dir));
const icaPem = await Deno.readTextFile(
  new URL("realreel-claim-signing-ca.pem", dir),
);
const assets = { rootPem, icaPem };

// OCSP requests generated with `openssl ocsp -issuer realreel-c2pa-root.pem
// -cert realreel-claim-signing-ca.pem -reqout …` (2026-07-24). The nonce
// variant omits -no_nonce; the sha256 variant adds -sha256.
const REQ_SHA1_HEX =
  "305530533051304f304d300906052b0e03021a050004149ab24e11e0c1f6d783bfdb1881f706af6954838e0414a1a57fee084567cf67b2810dcceae42fe3e6c20d0214095796d6d429759614860de66811df37549c4b8c";
const REQ_SHA256_HEX =
  "3071306f306d306b3069300d06096086480165030402010500042035441477d1d2f6d6dd791d5e72bd6487a5be7c989830e1d49a84210bf956a7820420f6260d59347c5714103f3c41a46c43ffb56fa6ade240bdc81e2a3b4a7b9e8e500214095796d6d429759614860de66811df37549c4b8c";
const REQ_SHA1_NONCE_HEX =
  "307a30783051304f304d300906052b0e03021a050004149ab24e11e0c1f6d783bfdb1881f706af6954838e0414a1a57fee084567cf67b2810dcceae42fe3e6c20d0214095796d6d429759614860de66811df37549c4b8ca2233021301f06092b06010505073001020412041071168477ef1b34ff8e6a3a57a374870d";
// Same issuer hashes, but the RESPONDER's serial (-cert realreel-ocsp-responder-1.pem):
const REQ_OTHER_SERIAL_HEX =
  "305530533051304f304d300906052b0e03021a050004149ab24e11e0c1f6d783bfdb1881f706af6954838e0414a1a57fee084567cf67b2810dcceae42fe3e6c20d021416cc4a07b80628ecc4e35fecb8820fa38dcbe1d5";
// ICA serial + root name hash, but the ICA's key hash (-issuer realreel-claim-signing-ca.pem):
const REQ_WRONG_KEYHASH_HEX =
  "305530533051304f304d300906052b0e03021a050004149ab24e11e0c1f6d783bfdb1881f706af6954838e04147e938ea9995567ea8b35772e3f144ded2c8fa8ce0214095796d6d429759614860de66811df37549c4b8c";

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

const SHA1_STUB = new TextEncoder().encode("pre-signed response (sha1 CertID)");
const SHA256_STUB = new TextEncoder().encode(
  "pre-signed response (sha256 CertID)",
);
const store: ResponseStore = {
  get: (key) =>
    Promise.resolve(
      key === "response:sha1"
        ? toArrayBuffer(SHA1_STUB)
        : key === "response:sha256"
        ? toArrayBuffer(SHA256_STUB)
        : null,
    ),
};
const emptyStore: ResponseStore = { get: () => Promise.resolve(null) };

function assert(cond: unknown, msg: string): void {
  if (!cond) throw new Error(msg);
}
function assertEq<T>(actual: T, expected: T, label: string): void {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}
function post(der: Uint8Array): Request {
  return new Request("http://ocsp.realreel.xyz/", {
    method: "POST",
    headers: { "content-type": "application/ocsp-request" },
    body: toArrayBuffer(der),
  });
}
function get(path: string): Request {
  return new Request(`http://ocsp.realreel.xyz${path}`);
}
async function expectOcsp(
  res: Response,
  body: Uint8Array,
  label: string,
): Promise<void> {
  assertEq(res.status, 200, `${label}: status`);
  assertEq(
    res.headers.get("content-type"),
    "application/ocsp-response",
    `${label}: content-type`,
  );
  assertEq(
    res.headers.get("access-control-allow-origin"),
    "*",
    `${label}: cors`,
  );
  const got = new Uint8Array(await res.arrayBuffer());
  assert(bytesEqual(got, body), `${label}: body bytes`);
}

Deno.test("POST with the openssl SHA-1 CertID serves the sha1 pre-signed response", async () => {
  const res = await handleRequest(
    post(hexToBytes(REQ_SHA1_HEX)),
    assets,
    store,
  );
  await expectOcsp(res, SHA1_STUB, "sha1");
  assertEq(
    res.headers.get("cache-control"),
    "public, max-age=3600",
    "cacheable",
  );
});

Deno.test("POST with the openssl SHA-256 CertID serves the sha256 pre-signed response", async () => {
  const res = await handleRequest(
    post(hexToBytes(REQ_SHA256_HEX)),
    assets,
    store,
  );
  await expectOcsp(res, SHA256_STUB, "sha256");
});

Deno.test("GET serves the request encoded base64 in the path (RFC 6960 A.1)", async () => {
  const b64 = bytesToB64(hexToBytes(REQ_SHA1_HEX));
  const res = await handleRequest(
    get(`/${encodeURIComponent(b64)}`),
    assets,
    store,
  );
  await expectOcsp(res, SHA1_STUB, "get-encoded");
  // Clients differ on percent-encoding '+', '/', '='; raw base64 must work too.
  const raw = await handleRequest(get(`/${b64}`), assets, store);
  await expectOcsp(raw, SHA1_STUB, "get-raw");
});

Deno.test("a request nonce is ignored, not fatal (RFC 5019 pre-signed operation)", async () => {
  const res = await handleRequest(
    post(hexToBytes(REQ_SHA1_NONCE_HEX)),
    assets,
    store,
  );
  await expectOcsp(res, SHA1_STUB, "nonce");
});

Deno.test("a different serial under the same issuer is unauthorized, never good", async () => {
  const res = await handleRequest(
    post(hexToBytes(REQ_OTHER_SERIAL_HEX)),
    assets,
    store,
  );
  await expectOcsp(res, OCSP_UNAUTHORIZED, "other-serial");
  assertEq(res.headers.get("cache-control"), "no-store", "uncacheable");
});

Deno.test("the ICA serial under a different issuer key is unauthorized", async () => {
  const res = await handleRequest(
    post(hexToBytes(REQ_WRONG_KEYHASH_HEX)),
    assets,
    store,
  );
  await expectOcsp(res, OCSP_UNAUTHORIZED, "wrong-keyhash");
});

Deno.test("a multi-cert request is unauthorized (pre-signed responses cover one CertID)", async () => {
  // Minimal DER SEQUENCE encoder, enough to rewrap the known single Request
  // TLV (the last 81 bytes of the openssl request) into a two-entry
  // requestList: OCSPRequest{ TBSRequest{ requestList{ req, req } } }.
  const derSeq = (...parts: Uint8Array[]): Uint8Array => {
    const len = parts.reduce((n, p) => n + p.length, 0);
    const header = len < 128 ? [0x30, len] : [0x30, 0x81, len];
    const out = new Uint8Array(header.length + len);
    out.set(header);
    let off = header.length;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  };
  const single = hexToBytes(REQ_SHA1_HEX).slice(-81); // the Request TLV (0x4f + 2)
  const doubled = derSeq(derSeq(derSeq(single, single)));
  const res = await handleRequest(post(doubled), assets, store);
  await expectOcsp(res, OCSP_UNAUTHORIZED, "multi-cert");
});

Deno.test("unparseable POST body is malformedRequest", async () => {
  const res = await handleRequest(
    post(new TextEncoder().encode("not ocsp")),
    assets,
    store,
  );
  await expectOcsp(res, OCSP_MALFORMED_REQUEST, "garbage");
});

Deno.test("empty POST body is malformedRequest", async () => {
  const res = await handleRequest(post(new Uint8Array(0)), assets, store);
  await expectOcsp(res, OCSP_MALFORMED_REQUEST, "empty");
});

Deno.test("an oversized POST body is malformedRequest", async () => {
  // Far past MAX_REQUEST_BYTES; a single-CertID request is ~100 bytes.
  const res = await handleRequest(
    post(new Uint8Array(64 * 1024)),
    assets,
    store,
  );
  await expectOcsp(res, OCSP_MALFORMED_REQUEST, "oversized");
});

Deno.test("undecodable GET path is malformedRequest", async () => {
  const res = await handleRequest(
    get("/definitely-not-base64!!!"),
    assets,
    store,
  );
  await expectOcsp(res, OCSP_MALFORMED_REQUEST, "bad-b64");
});

Deno.test("valid request against an unpopulated store is internalError", async () => {
  const res = await handleRequest(
    post(hexToBytes(REQ_SHA1_HEX)),
    assets,
    emptyStore,
  );
  await expectOcsp(res, OCSP_INTERNAL_ERROR, "empty-store");
});

Deno.test("index page on GET /", async () => {
  const res = await handleRequest(get("/"), assets, store);
  assertEq(res.status, 200, "status");
  assert(
    (res.headers.get("content-type") ?? "").startsWith("text/html"),
    "content-type",
  );
  assert((await res.text()).includes("OCSP"), "body");
});

Deno.test("PUT is rejected 405 with an Allow header", async () => {
  const res = await handleRequest(
    new Request("http://ocsp.realreel.xyz/", { method: "PUT", body: "x" }),
    assets,
    store,
  );
  assertEq(res.status, 405, "status");
  assert((res.headers.get("allow") ?? "").includes("POST"), "allow header");
});

// --- Leaf forwarding (LEAF_RESPONDER_ORIGIN configured) ---------------------

const LEAF_TARGETS = await leafIssuerTargets(icaPem);
// A CertID for an ICA-issued leaf: the ICA's issuer hashes with an arbitrary
// serial (the origin, not this router, decides whether the serial is known).
function leafRequest(hashOid: string): Uint8Array {
  const t = LEAF_TARGETS.find((x) => x.hashOid === hashOid)!;
  return buildOcspRequestDer({
    ...t,
    serialNumber: new Uint8Array([0x0a, 0x1b, 0x2c]),
  });
}
const LEAF_STUB = new TextEncoder().encode("origin-signed leaf response");
function stubForwarder(
  calls: Uint8Array[],
): (der: Uint8Array) => Promise<Response> {
  return (der) => {
    calls.push(der);
    return Promise.resolve(
      new Response(toArrayBuffer(LEAF_STUB), {
        headers: {
          "content-type": "application/ocsp-response",
          "cache-control": "public, max-age=300",
        },
      }),
    );
  };
}

Deno.test("a leaf CertID is relayed to the leaf responder verbatim, response + caching pass through", async () => {
  const calls: Uint8Array[] = [];
  const der = leafRequest(OID_SHA256);
  const res = await handleRequest(
    post(der),
    assets,
    store,
    stubForwarder(calls),
  );
  await expectOcsp(res, LEAF_STUB, "leaf-relay");
  assertEq(
    res.headers.get("cache-control"),
    "public, max-age=300",
    "origin cache-control",
  );
  assertEq(calls.length, 1, "forwarder calls");
  assert(bytesEqual(calls[0], der), "request DER relayed unmodified");
});

Deno.test("a SHA-384 leaf CertID is relayed (all four CertID hashes recognized)", async () => {
  const calls: Uint8Array[] = [];
  const res = await handleRequest(
    post(leafRequest(OID_SHA384)),
    assets,
    store,
    stubForwarder(calls),
  );
  await expectOcsp(res, LEAF_STUB, "leaf-sha384");
  assertEq(calls.length, 1, "forwarder calls");
});

Deno.test("origin content-type parameters / casing don't break the relay", async () => {
  const res = await handleRequest(
    post(leafRequest(OID_SHA256)),
    assets,
    store,
    () =>
      Promise.resolve(
        new Response(toArrayBuffer(LEAF_STUB), {
          headers: {
            "content-type": "Application/OCSP-Response; charset=binary",
          },
        }),
      ),
  );
  await expectOcsp(res, LEAF_STUB, "media-type-normalized");
});

Deno.test("HEAD leaf requests are not relayed (body would be discarded)", async () => {
  const calls: Uint8Array[] = [];
  const b64 = bytesToB64(leafRequest(OID_SHA256));
  const res = await handleRequest(
    new Request(`http://ocsp.realreel.xyz/${encodeURIComponent(b64)}`, {
      method: "HEAD",
    }),
    assets,
    store,
    stubForwarder(calls),
  );
  await expectOcsp(res, OCSP_UNAUTHORIZED, "head-not-relayed");
  assertEq(calls.length, 0, "forwarder untouched");
});

Deno.test("a leaf CertID with no forwarder configured is unauthorized (pre-cutover)", async () => {
  const res = await handleRequest(post(leafRequest(OID_SHA256)), assets, store);
  await expectOcsp(res, OCSP_UNAUTHORIZED, "leaf-no-forwarder");
});

Deno.test("a non-leaf CertID is never relayed even with a forwarder", async () => {
  const calls: Uint8Array[] = [];
  const res = await handleRequest(
    post(hexToBytes(REQ_WRONG_KEYHASH_HEX)),
    assets,
    store,
    stubForwarder(calls),
  );
  await expectOcsp(res, OCSP_UNAUTHORIZED, "foreign-not-relayed");
  assertEq(calls.length, 0, "forwarder untouched");
});

Deno.test("forwarder failure (throw / non-OCSP reply) is internalError, no-store", async () => {
  const thrown = await handleRequest(
    post(leafRequest(OID_SHA256)),
    assets,
    store,
    () => Promise.reject(new Error("origin down")),
  );
  await expectOcsp(thrown, OCSP_INTERNAL_ERROR, "origin-throw");
  assertEq(thrown.headers.get("cache-control"), "no-store", "uncacheable");

  const html = await handleRequest(
    post(leafRequest(OID_SHA256)),
    assets,
    store,
    () =>
      Promise.resolve(
        new Response("<html>404</html>", {
          status: 404,
          headers: { "content-type": "text/html" },
        }),
      ),
  );
  await expectOcsp(html, OCSP_INTERNAL_ERROR, "origin-not-ocsp");
});

Deno.test("OPTIONS preflight returns 204 with CORS incl. content-type header allowance", async () => {
  const res = await handleRequest(
    new Request("http://ocsp.realreel.xyz/", { method: "OPTIONS" }),
    assets,
    store,
  );
  assertEq(res.status, 204, "status");
  assertEq(res.headers.get("access-control-allow-origin"), "*", "cors");
  // application/ocsp-request is not CORS-safelisted; without this a browser
  // preflight rejects the POST.
  assert(
    (res.headers.get("access-control-allow-headers") ?? "").includes(
      "content-type",
    ),
    "allow-headers",
  );
});
