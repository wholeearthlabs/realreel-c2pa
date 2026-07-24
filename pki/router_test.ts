// Router tests: pin the served bytes to the known root/ICA certs and check every
// route, content-type, CORS, and the 404/405/OPTIONS paths, so a bad file or a
// routing regression fails here rather than at the live AIA URL.
//
//   deno test --allow-read pki/router_test.ts
import { handleRequest, pemToDer, sha256HexUpper } from "./router.ts";

const dir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
const rootPem = await Deno.readTextFile(new URL("realreel-c2pa-root.pem", dir));
const icaPem = await Deno.readTextFile(new URL("realreel-claim-signing-ca.pem", dir));
const assets = { rootPem, icaPem };

// The certs produced by the key ceremony (2026-07-24).
const ROOT_SHA256 = "5559383DDD6666EB38FF746D592C5F6686B1C3340F4FDD584076D32E60B5E858";
const ICA_SHA256 = "00F1EE5D117141F1092AC350EFC937396AE8FEC8FEF1A4BC9581B1B1A12D4669";

function assert(cond: unknown, msg: string): void {
  if (!cond) throw new Error(msg);
}
function assertEq<T>(actual: T, expected: T, label: string): void {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, got ${actual}`);
}
function req(path: string, method = "GET"): Request {
  return new Request(`https://pki.realreel.xyz${path}`, { method });
}

Deno.test("root .cer serves the exact root DER as application/pkix-cert with CORS", async () => {
  const res = await handleRequest(req("/realreel-c2pa-root.cer"), assets);
  assertEq(res.status, 200, "status");
  assertEq(res.headers.get("content-type"), "application/pkix-cert", "content-type");
  assertEq(res.headers.get("access-control-allow-origin"), "*", "cors");
  const der = new Uint8Array(await res.arrayBuffer());
  assertEq(der[0], 0x30, "DER SEQUENCE tag");
  assertEq(await sha256HexUpper(der), ROOT_SHA256, "served root DER fingerprint");
});

Deno.test("root .pem serves the PEM", async () => {
  const res = await handleRequest(req("/realreel-c2pa-root.pem"), assets);
  assertEq(res.status, 200, "status");
  assert((res.headers.get("content-type") ?? "").startsWith("application/x-pem-file"), "content-type");
  assert((await res.text()).includes("-----BEGIN CERTIFICATE-----"), "pem body");
});

Deno.test("ICA .cer serves the exact ICA DER", async () => {
  const res = await handleRequest(req("/realreel-claim-signing-ca.cer"), assets);
  assertEq(res.status, 200, "status");
  assertEq(res.headers.get("content-type"), "application/pkix-cert", "content-type");
  const der = new Uint8Array(await res.arrayBuffer());
  assertEq(await sha256HexUpper(der), ICA_SHA256, "served ICA DER fingerprint");
});

Deno.test("index page publishes the fingerprint derived from the served root", async () => {
  const res = await handleRequest(req("/"), assets);
  assertEq(res.status, 200, "status");
  assert((res.headers.get("content-type") ?? "").startsWith("text/html"), "content-type");
  assert((await res.text()).includes(ROOT_SHA256), "derived fingerprint present on page");
});

Deno.test("OPTIONS preflight returns 204 with CORS", async () => {
  const res = await handleRequest(req("/realreel-c2pa-root.cer", "OPTIONS"), assets);
  assertEq(res.status, 204, "status");
  assertEq(res.headers.get("access-control-allow-origin"), "*", "cors");
  assert((res.headers.get("access-control-allow-methods") ?? "").includes("GET"), "allow-methods");
});

Deno.test("POST is rejected 405 with an Allow header", async () => {
  const res = await handleRequest(req("/realreel-c2pa-root.cer", "POST"), assets);
  assertEq(res.status, 405, "status");
  assert((res.headers.get("allow") ?? "").includes("GET"), "allow header");
});

Deno.test("unknown path is 404 and still CORS-open", async () => {
  const res = await handleRequest(req("/nope"), assets);
  assertEq(res.status, 404, "status");
  assertEq(res.headers.get("access-control-allow-origin"), "*", "cors");
});

Deno.test("pemToDer produces a DER certificate", () => {
  const der = pemToDer(rootPem);
  assert(der.length > 0, "non-empty");
  assertEq(der[0], 0x30, "DER SEQUENCE tag");
});
