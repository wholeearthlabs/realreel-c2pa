// HTTP entry point for the leaf-status OCSP responder — a small Cloud Run
// service beside the verifier (see README.md for deploy + how requests reach
// it from ocsp.realreel.xyz). Wires the pure core in responder.ts to:
//
//   * the issued_certificates ledger (lookup_signing_key_revocation, read
//     with the verifier's read-only DATABASE_URL), and
//   * Cloud KMS signing with the realreel-ocsp-ica responder key — ambient
//     Cloud Run service-account identity via the metadata server, or
//     GCP_KMS_SA_JSON locally (same envs/shape as the CA edge functions).
//
// Env:
//   DATABASE_URL                 required — verifier_readonly connection
//   GCP_KMS_KEY_RESOURCE         required — projects/…/cryptoKeys/realreel-ocsp-ica/cryptoKeyVersions/1
//   GCP_KMS_SA_JSON              optional — local/off-GCP auth (else metadata server)
//   OCSP_LEAF_VALIDITY_HOURS     optional — thisUpdate→nextUpdate window (default 24;
//                                kept short so a revocation propagates well inside
//                                the CP's 72-hour clock even through caches)
//   PORT                         Cloud Run standard (default 8080)

import { kmsSignDigest, loadKmsCredentials } from "../ca/_shared/kms.ts";
import type { KmsCredentials } from "../ca/_shared/kms.ts";
import {
  leafIssuerTargets,
  OCSP_INTERNAL_ERROR,
  OCSP_MALFORMED_REQUEST,
  respond,
} from "./responder.ts";
import type {
  LeafStatus,
  ResponderDeps,
  ResponseCache,
  SignTbs,
} from "./responder.ts";
import postgres from "postgres";

const MAX_REQUEST_BYTES = 8192; // matches the ICA-status Worker's cap
const CACHE_MAX_AGE_SECONDS = 300;

// --- config + startup ------------------------------------------------------

function requiredEnv(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`${name} is required`);
  return v;
}

const databaseUrl = requiredEnv("DATABASE_URL");
const kmsKeyResource = requiredEnv("GCP_KMS_KEY_RESOURCE");

const validityHours = Number(Deno.env.get("OCSP_LEAF_VALIDITY_HOURS") ?? "24");
if (!Number.isFinite(validityHours) || validityHours < 1 || validityHours > 72) {
  // >72 would let a cached "good" outlive the CP's 72-hour revocation clock.
  throw new Error(
    `OCSP_LEAF_VALIDITY_HOURS must be 1..72, got '${validityHours}'`,
  );
}

const certsDir = new URL("../verifier/trust-sources/realreel/", import.meta.url);
const icaPem = await Deno.readTextFile(
  new URL("realreel-claim-signing-ca.pem", certsDir),
);
const responderPem = await Deno.readTextFile(
  new URL("realreel-leaf-ocsp-responder-1.pem", certsDir),
);

// Fail fast on config drift: the responder cert must actually be ICA-issued,
// or every response we sign embeds a cert clients can't chain to the CertID's
// issuer. (Deeper checks — AKI/SKI, signature — were done at mint; this
// catches a wrong-PEM swap.)
{
  const { parseCert } = await import("../ocsp/ocsp.ts");
  const ica = parseCert(icaPem);
  const responder = parseCert(responderPem);
  const icaSubject = new Uint8Array(ica.subject.toSchema().toBER(false));
  const respIssuer = new Uint8Array(responder.issuer.toSchema().toBER(false));
  if (
    icaSubject.length !== respIssuer.length ||
    !icaSubject.every((b, i) => b === respIssuer[i])
  ) {
    throw new Error(
      "responder cert issuer DN != ICA subject DN — wrong PEM deployed",
    );
  }
}

const issuerTargets = await leafIssuerTargets(icaPem);

// --- ledger lookup ---------------------------------------------------------

const sql = postgres(databaseUrl, {
  prepare: false, // PgBouncer transaction-mode pooling (same as the verifier)
  max: 4,
  idle_timeout: 30,
  connect_timeout: 10,
});

async function lookupStatus(serialDecimal: string): Promise<LeafStatus> {
  const rows = await sql`
    SELECT revoked_at
      FROM public.lookup_signing_key_revocation(${serialDecimal})
  `;
  if (rows.length === 0) return { kind: "unknown" };
  const revokedAt = rows[0].revoked_at as Date | string | null;
  if (revokedAt == null) return { kind: "good" };
  return { kind: "revoked", revokedAt: new Date(revokedAt) };
}

// --- KMS signing -----------------------------------------------------------

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      data.buffer.slice(
        data.byteOffset,
        data.byteOffset + data.byteLength,
      ) as ArrayBuffer,
    ),
  );
}

// Metadata-server token, cached until shortly before expiry.
let metadataToken: { value: string; expiresAtMs: number } | null = null;
async function getMetadataToken(): Promise<string> {
  if (metadataToken && Date.now() < metadataToken.expiresAtMs - 60_000) {
    return metadataToken.value;
  }
  const resp = await fetch(
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    { headers: { "Metadata-Flavor": "Google" } },
  );
  if (!resp.ok) {
    throw new Error(`metadata token fetch failed: ${resp.status}`);
  }
  const json = await resp.json() as { access_token: string; expires_in: number };
  metadataToken = {
    value: json.access_token,
    expiresAtMs: Date.now() + json.expires_in * 1000,
  };
  return metadataToken.value;
}

async function kmsSignViaMetadata(digest: Uint8Array): Promise<Uint8Array> {
  const token = await getMetadataToken();
  let digestB64 = "";
  for (let i = 0; i < digest.length; i++) {
    digestB64 += String.fromCharCode(digest[i]);
  }
  digestB64 = btoa(digestB64);
  const resp = await fetch(
    `https://cloudkms.googleapis.com/v1/${kmsKeyResource}:asymmetricSign`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ digest: { sha256: digestB64 } }),
    },
  );
  if (!resp.ok) {
    throw new Error(`KMS asymmetricSign returned ${resp.status}`);
  }
  const json = await resp.json() as { signature?: string };
  if (!json.signature) throw new Error("KMS response missing signature");
  const bin = atob(json.signature);
  const sig = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) sig[i] = bin.charCodeAt(i);
  return sig;
}

function makeSignTbs(): SignTbs {
  if (Deno.env.get("GCP_KMS_SA_JSON")) {
    // Local / off-GCP: the CA edge functions' SA-JSON client, verbatim.
    let creds: Promise<KmsCredentials> | null = null;
    return async (tbs) => {
      creds ??= loadKmsCredentials();
      return kmsSignDigest(await sha256(tbs), await creds, "sha256");
    };
  }
  // Cloud Run: ambient service-account identity.
  return async (tbs) => kmsSignViaMetadata(await sha256(tbs));
}

// Per-CertID LRU of signed responses, TTL = the response's own validity
// window (a cached entry is never served past its nextUpdate; revocation
// propagation is unchanged — see ResponseCache in responder.ts). Bounds
// KMS/DB spend for repeat queries of issued serials; never-issued serials
// don't sign at all (responder.ts answers them unsigned unauthorized), so
// serial enumeration on this public endpoint costs only cheap lookups.
function makeLruCache(maxEntries: number, ttlMs: number): ResponseCache {
  const entries = new Map<string, { der: Uint8Array; expiresAtMs: number }>();
  return {
    get(key) {
      const e = entries.get(key);
      if (!e) return undefined;
      if (Date.now() >= e.expiresAtMs) {
        entries.delete(key);
        return undefined;
      }
      entries.delete(key); // re-insert to refresh LRU position
      entries.set(key, e);
      return e.der;
    },
    set(key, der) {
      if (entries.size >= maxEntries) {
        const oldest = entries.keys().next().value;
        if (oldest !== undefined) entries.delete(oldest);
      }
      entries.set(key, { der, expiresAtMs: Date.now() + ttlMs });
    },
  };
}

const validityMs = validityHours * 3_600_000;

const deps: ResponderDeps = {
  issuerTargets,
  responderPem,
  lookupStatus,
  signTbs: makeSignTbs(),
  now: () => new Date(),
  validityMs,
  cache: makeLruCache(8192, validityMs),
};

// --- HTTP ------------------------------------------------------------------

function ocspHttpResponse(der: Uint8Array, cacheable: boolean): Response {
  const body = der.buffer.slice(
    der.byteOffset,
    der.byteOffset + der.byteLength,
  ) as ArrayBuffer;
  return new Response(body, {
    status: 200, // OCSP-over-HTTP carries its own status inside the body
    headers: {
      "content-type": "application/ocsp-response",
      "cache-control": cacheable
        ? `public, max-age=${CACHE_MAX_AGE_SECONDS}`
        : "no-store",
    },
  });
}

async function readRequestDer(req: Request, url: URL): Promise<Uint8Array | null> {
  if (req.method === "POST") {
    const body = new Uint8Array(await req.arrayBuffer());
    return body.byteLength > 0 && body.byteLength <= MAX_REQUEST_BYTES
      ? body
      : null;
  }
  // RFC 6960 A.1 GET form: base64(DER), URL-encoded, as the path.
  const encoded = url.pathname.slice(1);
  if (!encoded || encoded.length > MAX_REQUEST_BYTES * 2) return null;
  try {
    const bin = atob(decodeURIComponent(encoded));
    const der = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
    return der.byteLength <= MAX_REQUEST_BYTES ? der : null;
  } catch {
    return null;
  }
}

const port = Number(Deno.env.get("PORT") ?? "8080");
Deno.serve({ port }, async (req) => {
  const url = new URL(req.url);

  if (req.method === "GET" && url.pathname === "/healthz") {
    return new Response("ok", { status: 200 });
  }
  if (req.method === "GET" && url.pathname === "/healthz/ready") {
    // Round-trips the real ledger function with a sentinel serial (returns
    // zero rows). Proves DB connectivity + grants without touching real data.
    try {
      await lookupStatus("0");
      return new Response("ready", { status: 200 });
    } catch (e) {
      console.error("[ocsp-leaf] readiness probe failed:", e);
      return new Response("db unavailable", { status: 503 });
    }
  }
  if (req.method !== "POST" && req.method !== "GET") {
    return new Response("method not allowed", { status: 405 });
  }

  const requestDer = await readRequestDer(req, url);
  if (requestDer === null) {
    return ocspHttpResponse(OCSP_MALFORMED_REQUEST, false);
  }

  try {
    const { der, signed } = await respond(requestDer, deps);
    return ocspHttpResponse(der, signed);
  } catch (e) {
    // Ledger or KMS failure — never a client problem. Log and answer with
    // the unsigned internalError form (RFC 6960 §4.2.1).
    console.error("[ocsp-leaf] internal error:", e);
    return ocspHttpResponse(OCSP_INTERNAL_ERROR, false);
  }
});
