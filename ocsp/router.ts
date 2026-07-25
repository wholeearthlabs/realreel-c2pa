// Pure request router for the realreel-ocsp Worker. Cert PEMs and the
// pre-signed-response store are passed in (not imported) so this can be
// unit-tested without wrangler's module loaders; index.ts wires in the bundled
// PEMs and the KV binding. See README.md for the endpoint contract.
//
// The Worker never signs anything: a scheduled job pre-signs `good` responses
// for the ICA via Cloud KMS and publishes them to KV (see
// build-ocsp-responses.ts). This router only decides which bytes to serve:
//   - request's CertID names the ICA  → the pre-signed response (KV)
//   - any other CertID, or >1 request → unauthorized (unsigned, RFC 6960 §2.3)
//   - unparseable request             → malformedRequest
//   - KV empty (refresh never ran)    → internalError

import {
  certIdMatches,
  type CertIdValues,
  icaCertIdTargets,
  KV_KEY_BY_HASH_OID,
  OCSP_INTERNAL_ERROR,
  OCSP_MALFORMED_REQUEST,
  OCSP_UNAUTHORIZED,
  parseOcspRequestCertIds,
  toArrayBuffer,
} from "./ocsp.ts";

export interface CertAssets {
  rootPem: string;
  icaPem: string;
}

// The KV namespace, reduced to the one read the router needs.
export interface ResponseStore {
  get(key: string): Promise<ArrayBuffer | null>;
}

const ALLOW = "GET, POST, HEAD, OPTIONS";
const OCSP_CONTENT_TYPE = "application/ocsp-response";
// A pre-signed response is valid for days; letting edge caches hold it for an
// hour costs nothing and absorbs bursts. Error responses are never cached.
const CACHE_OK = "public, max-age=3600";
// OCSP requests for a single CertID are ~100 bytes; anything huge is not a
// request worth parsing.
const MAX_REQUEST_BYTES = 8192;

// CORS-open like pki.realreel.xyz: a public, read-only status endpoint may be
// queried by browser-based C2PA validators from any origin.
function headers(extra: Record<string, string>): Headers {
  const h = new Headers(extra);
  h.set("access-control-allow-origin", "*");
  return h;
}

function ocspBytes(bytes: Uint8Array, cache: string): Response {
  return new Response(toArrayBuffer(bytes), {
    headers: headers({ "content-type": OCSP_CONTENT_TYPE, "cache-control": cache }),
  });
}

// RFC 6960 A.1: GET {url}/{url-encoded base64 of the DER request}. Clients
// vary in how much they percent-encode ('+', '/', '='), so decode the path
// component first and let atob be the arbiter. Returns null when the path
// isn't decodable base64.
function decodeGetRequest(pathname: string): Uint8Array | null {
  try {
    const b64 = decodeURIComponent(pathname.replace(/^\/+/, ""));
    const bin = atob(b64);
    const der = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
    return der;
  } catch {
    return null;
  }
}

const indexHtml = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RealReel C2PA OCSP</title>
<style>body{font:15px/1.6 -apple-system,Arial,sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem;color:#111}code{background:#f4f4f4;padding:1px 5px;border-radius:3px;word-break:break-all}a{color:#2456c8}</style>
</head><body>
<h1>RealReel C2PA OCSP responder</h1>
<p>RFC 6960 OCSP endpoint for the RealReel C2PA Certification Authority, operated by Whole Earth Labs LLC. It answers status requests for the RealReel Claim Signing CA.</p>
<p>Send OCSP requests to this host over HTTP GET (base64 request in the path) or POST (<code>application/ocsp-request</code>).</p>
<p>CA certificates: <a href="https://pki.realreel.xyz/">pki.realreel.xyz</a></p>
</body></html>`;

// Computed once per isolate; the PEMs are compiled into the Worker bundle so
// the targets are constant for its lifetime.
const targetsCache = new WeakMap<CertAssets, Promise<CertIdValues[]>>();
function targets(assets: CertAssets): Promise<CertIdValues[]> {
  let cached = targetsCache.get(assets);
  if (!cached) {
    cached = icaCertIdTargets(assets.rootPem, assets.icaPem);
    targetsCache.set(assets, cached);
  }
  return cached;
}

export async function handleRequest(
  req: Request,
  assets: CertAssets,
  store: ResponseStore,
): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: headers({
        allow: ALLOW,
        "access-control-allow-methods": ALLOW,
        // POSTing application/ocsp-request is not CORS-safelisted, so browser
        // clients preflight with this header; without it the POST never happens.
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "86400",
      }),
    });
  }

  const { pathname } = new URL(req.url);

  let der: Uint8Array | null;
  if (req.method === "POST") {
    // Reject oversized requests on the declared length BEFORE buffering the
    // body; the post-read length check below still covers chunked uploads.
    if (Number(req.headers.get("content-length") ?? "0") > MAX_REQUEST_BYTES) {
      return ocspBytes(OCSP_MALFORMED_REQUEST, "no-store");
    }
    const body = new Uint8Array(await req.arrayBuffer());
    der = body.length > 0 ? body : null;
  } else if (req.method === "GET" || req.method === "HEAD") {
    if (pathname === "/") {
      return new Response(indexHtml, {
        headers: headers({ "content-type": "text/html; charset=utf-8", "cache-control": CACHE_OK }),
      });
    }
    der = decodeGetRequest(pathname);
  } else {
    return new Response("Method Not Allowed\n", {
      status: 405,
      headers: headers({ allow: ALLOW, "content-type": "text/plain; charset=utf-8" }),
    });
  }

  if (!der || der.length > MAX_REQUEST_BYTES) {
    return ocspBytes(OCSP_MALFORMED_REQUEST, "no-store");
  }

  let certIds: CertIdValues[];
  try {
    certIds = parseOcspRequestCertIds(der);
  } catch {
    return ocspBytes(OCSP_MALFORMED_REQUEST, "no-store");
  }

  // Pre-signed responses cover exactly one CertID, so a multi-cert request
  // can't be answered from this responder — unauthorized, same as a CertID
  // we are not authoritative for.
  if (certIds.length !== 1) {
    return ocspBytes(OCSP_UNAUTHORIZED, "no-store");
  }
  const match = (await targets(assets)).find((t) => certIdMatches(t, certIds[0]));
  if (!match) {
    return ocspBytes(OCSP_UNAUTHORIZED, "no-store");
  }

  const bytes = await store.get(KV_KEY_BY_HASH_OID[match.hashOid]);
  if (!bytes) {
    // The refresh job has never populated (or failed to repopulate) the store.
    return ocspBytes(OCSP_INTERNAL_ERROR, "no-store");
  }
  return new Response(bytes, {
    headers: headers({ "content-type": OCSP_CONTENT_TYPE, "cache-control": CACHE_OK }),
  });
}
