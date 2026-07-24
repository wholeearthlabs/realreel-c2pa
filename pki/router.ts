// Pure request router for the realreel-pki Worker. The cert bytes are passed in
// (not imported) so this can be unit-tested without wrangler's module loaders;
// index.ts wires in the bundled PEMs. See README.md for what the endpoint serves.

export interface CertAssets {
  rootPem: string;
  icaPem: string;
}

const CACHE = "public, max-age=3600";
const ALLOW = "GET, HEAD, OPTIONS";

// CORS-open on every response: a public, read-only cert repository must be
// fetchable by browser-based C2PA validators (c2pa-js) from any origin.
function headers(extra: Record<string, string>): Headers {
  const h = new Headers(extra);
  h.set("access-control-allow-origin", "*");
  return h;
}

export function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return der;
}

export async function sha256HexUpper(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function indexHtml(rootFingerprint: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RealReel C2PA PKI</title>
<style>body{font:15px/1.6 -apple-system,Arial,sans-serif;max-width:42rem;margin:3rem auto;padding:0 1rem;color:#111}code{background:#f4f4f4;padding:1px 5px;border-radius:3px;word-break:break-all}a{color:#2456c8}</style>
</head><body>
<h1>RealReel C2PA PKI</h1>
<p>Public certificate repository for the RealReel C2PA Certification Authority, operated by Whole Earth Labs LLC.</p>
<ul>
<li><a href="/realreel-c2pa-root.cer">realreel-c2pa-root.cer</a> / <a href="/realreel-c2pa-root.pem">.pem</a> &mdash; root CA (trust anchor)</li>
<li><a href="/realreel-claim-signing-ca.cer">realreel-claim-signing-ca.cer</a> / <a href="/realreel-claim-signing-ca.pem">.pem</a> &mdash; Claim Signing intermediate CA</li>
</ul>
<p>Root SHA-256: <code>${rootFingerprint}</code></p>
</body></html>`;
}

export async function handleRequest(req: Request, assets: CertAssets): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: headers({ allow: ALLOW, "access-control-allow-methods": ALLOW, "access-control-max-age": "86400" }),
    });
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method Not Allowed\n", {
      status: 405,
      headers: headers({ allow: ALLOW, "content-type": "text/plain; charset=utf-8" }),
    });
  }

  const { pathname } = new URL(req.url);
  switch (pathname) {
    case "/realreel-c2pa-root.cer":
      return new Response(pemToDer(assets.rootPem), {
        headers: headers({
          "content-type": "application/pkix-cert",
          "content-disposition": 'inline; filename="realreel-c2pa-root.cer"',
          "cache-control": CACHE,
        }),
      });
    case "/realreel-c2pa-root.pem":
      return new Response(assets.rootPem, {
        headers: headers({ "content-type": "application/x-pem-file; charset=utf-8", "cache-control": CACHE }),
      });
    case "/realreel-claim-signing-ca.cer":
      return new Response(pemToDer(assets.icaPem), {
        headers: headers({
          "content-type": "application/pkix-cert",
          "content-disposition": 'inline; filename="realreel-claim-signing-ca.cer"',
          "cache-control": CACHE,
        }),
      });
    case "/realreel-claim-signing-ca.pem":
      return new Response(assets.icaPem, {
        headers: headers({ "content-type": "application/x-pem-file; charset=utf-8", "cache-control": CACHE }),
      });
    case "/": {
      const fingerprint = await sha256HexUpper(pemToDer(assets.rootPem));
      return new Response(indexHtml(fingerprint), {
        headers: headers({ "content-type": "text/html; charset=utf-8", "cache-control": CACHE }),
      });
    }
    default:
      return new Response("Not found\n", {
        status: 404,
        headers: headers({ "content-type": "text/plain; charset=utf-8" }),
      });
  }
}
