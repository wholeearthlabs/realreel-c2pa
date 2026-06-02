// Cloud KMS REST client — signing operations only.
//
// Used by `register-signing-key` to issue the per-device leaf cert via the
// RealReel intermediate key that lives inside Cloud KMS. The intermediate
// key's private half never leaves KMS; this module only ever asks KMS to sign
// a SHA-256 digest of a TBSCertificate we built locally.
//
// Auth flow:
//   1. Load service account JSON from GCP_KMS_SA_JSON.
//   2. Import the SA's RSA private key into WebCrypto.
//   3. Mint a short-lived RS256 JWT asserting we want a token scoped to
//      cloudkms.googleapis.com.
//   4. Exchange the JWT at oauth2.googleapis.com/token for a Bearer token.
//   5. Cache the Bearer token in-process until ~60s before expiry.
//   6. POST to cloudkms.googleapis.com/v1/{resource}:asymmetricSign.
//
// All fetches are restricted to oauth2.googleapis.com and cloudkms.googleapis.com.
// Deploy with `--allow-net=oauth2.googleapis.com,cloudkms.googleapis.com --allow-env`.

if (typeof Deno === "undefined") {
  throw new Error(
    "ca/_shared/kms.ts is Deno-only. Do not import from React Native or other non-Deno runtimes.",
  );
}

export class KmsError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "KmsError";
    this.code = code;
  }
}

// --- Service account credentials --------------------------------------

// Shape of GCP service account JSON keys. Only the fields we actually use are
// declared; the JSON object has many more (`project_id`, `auth_uri`, etc.).
interface ServiceAccountJSON {
  client_email: string;
  private_key: string; // PKCS#8 PEM with PEM headers
  private_key_id?: string;
}

export interface KmsCredentials {
  // Full versioned resource path:
  //   projects/.../locations/.../keyRings/.../cryptoKeys/.../cryptoKeyVersions/N
  resource: string;
  saClientEmail: string;
  saPrivateKey: CryptoKey;
  saPrivateKeyId?: string;
}

// Parse a PKCS#8 PEM block (BEGIN/END PRIVATE KEY) into raw DER bytes.
// Distinct from pki.ts's pemToDer which targets CERTIFICATE blocks.
function pkcs8PemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(stripped);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Read GCP_KMS_KEY_RESOURCE and GCP_KMS_SA_JSON from the environment, import
// the SA RSA key into WebCrypto, and return a ready-to-use credentials handle.
// Throws KmsError if either env var is missing or malformed.
export async function loadKmsCredentials(): Promise<KmsCredentials> {
  const resource = Deno.env.get("GCP_KMS_KEY_RESOURCE");
  if (!resource) {
    throw new KmsError("ENV_MISSING", "GCP_KMS_KEY_RESOURCE is not set");
  }
  const saJsonRaw = Deno.env.get("GCP_KMS_SA_JSON");
  if (!saJsonRaw) {
    throw new KmsError("ENV_MISSING", "GCP_KMS_SA_JSON is not set");
  }

  let sa: ServiceAccountJSON;
  try {
    sa = JSON.parse(saJsonRaw) as ServiceAccountJSON;
  } catch (e) {
    throw new KmsError(
      "SA_PARSE_FAILED",
      `GCP_KMS_SA_JSON is not valid JSON: ${(e as Error).message}`,
    );
  }
  if (!sa.client_email || !sa.private_key) {
    throw new KmsError(
      "SA_PARSE_FAILED",
      "GCP_KMS_SA_JSON is missing client_email or private_key",
    );
  }

  let saPrivateKey: CryptoKey;
  try {
    const der = pkcs8PemToDer(sa.private_key);
    saPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      der as BufferSource,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch (e) {
    throw new KmsError(
      "SA_KEY_IMPORT_FAILED",
      `Failed to import SA private key: ${(e as Error).message}`,
    );
  }

  return {
    resource,
    saClientEmail: sa.client_email,
    saPrivateKey,
    saPrivateKeyId: sa.private_key_id,
  };
}

// --- JWT mint ----------------------------------------------------------

// base64url-encode bytes (no padding).
function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlEncodeString(s: string): string {
  return b64urlEncode(new TextEncoder().encode(s));
}

// Build and sign an RS256 JWT asserting the service account wants a token
// scoped to cloudkms.googleapis.com. Audience is oauth2.googleapis.com/token
// per Google's "JWT Bearer" flow.
async function mintJwtAssertion(creds: KmsCredentials): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header: Record<string, string> = { alg: "RS256", typ: "JWT" };
  if (creds.saPrivateKeyId) header.kid = creds.saPrivateKeyId;
  const payload = {
    iss: creds.saClientEmail,
    scope: "https://www.googleapis.com/auth/cloudkms",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const signingInput = `${b64urlEncodeString(JSON.stringify(header))}.${
    b64urlEncodeString(JSON.stringify(payload))
  }`;
  const sigBuf = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    creds.saPrivateKey,
    new TextEncoder().encode(signingInput) as BufferSource,
  );
  return `${signingInput}.${b64urlEncode(new Uint8Array(sigBuf))}`;
}

// --- Access token cache ------------------------------------------------

interface CachedToken {
  value: string;
  expiresAt: number; // epoch seconds; we evict 60s before this
  // Tied to the credentials we used to mint it; rotating SA invalidates cache.
  credsKey: string;
}

let cachedToken: CachedToken | null = null;

function credsCacheKey(creds: KmsCredentials): string {
  // Distinguishing on client_email is sufficient — same SA, same scope, same
  // cached token. Resource string is intentionally excluded; one token can
  // sign across multiple keys for the same SA.
  return creds.saClientEmail;
}

async function getAccessToken(creds: KmsCredentials): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const key = credsCacheKey(creds);
  if (
    cachedToken && cachedToken.credsKey === key &&
    cachedToken.expiresAt - 60 > nowSec
  ) {
    return cachedToken.value;
  }

  const assertion = await mintJwtAssertion(creds);
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
  });

  let resp: Response;
  try {
    resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
    });
  } catch (e) {
    throw new KmsError(
      "TOKEN_FETCH_FAILED",
      `Failed to reach oauth2.googleapis.com: ${(e as Error).message}`,
    );
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error("[kms] token exchange failed", resp.status, text);
    throw new KmsError(
      "TOKEN_EXCHANGE_FAILED",
      `OAuth token exchange returned ${resp.status}`,
    );
  }

  let json: { access_token?: string; expires_in?: number };
  try {
    json = await resp.json();
  } catch (e) {
    throw new KmsError(
      "TOKEN_PARSE_FAILED",
      `OAuth response was not JSON: ${(e as Error).message}`,
    );
  }
  if (!json.access_token || typeof json.expires_in !== "number") {
    throw new KmsError(
      "TOKEN_PARSE_FAILED",
      "OAuth response missing access_token or expires_in",
    );
  }

  cachedToken = {
    value: json.access_token,
    expiresAt: nowSec + json.expires_in,
    credsKey: key,
  };
  return cachedToken.value;
}

// --- KMS asymmetricSign ------------------------------------------------

// Sign a SHA-256 digest with the intermediate CA key in Cloud KMS. Returns the
// raw signature bytes exactly as KMS returns them — for `ec-sign-p256-sha256`
// this is a DER-encoded `SEQUENCE { r INTEGER, s INTEGER }`, which is the same
// encoding X.509 expects in `signatureValue`. No P1363→DER conversion needed.
//
// The caller is responsible for SHA-256-hashing the TBSCertificate bytes
// before calling.
export async function kmsSignDigest(
  digest: Uint8Array,
  creds: KmsCredentials,
): Promise<Uint8Array> {
  if (digest.length !== 32) {
    throw new KmsError(
      "BAD_DIGEST",
      `kmsSignDigest expects a 32-byte SHA-256 digest, got ${digest.length} bytes`,
    );
  }
  const token = await getAccessToken(creds);
  const url =
    `https://cloudkms.googleapis.com/v1/${creds.resource}:asymmetricSign`;

  // Base64-encode the digest (standard base64, not URL-safe — KMS accepts both,
  // but standard is documented).
  let digestB64 = "";
  for (let i = 0; i < digest.length; i++) {
    digestB64 += String.fromCharCode(digest[i]);
  }
  digestB64 = btoa(digestB64);

  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ digest: { sha256: digestB64 } }),
    });
  } catch (e) {
    throw new KmsError(
      "SIGN_FETCH_FAILED",
      `Failed to reach cloudkms.googleapis.com: ${(e as Error).message}`,
    );
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error("[kms] asymmetricSign failed", resp.status, text);
    throw new KmsError(
      "SIGN_FAILED",
      `Cloud KMS asymmetricSign returned ${resp.status}`,
    );
  }

  let json: { signature?: string };
  try {
    json = await resp.json();
  } catch (e) {
    throw new KmsError(
      "SIGN_PARSE_FAILED",
      `Cloud KMS response was not JSON: ${(e as Error).message}`,
    );
  }
  if (!json.signature) {
    throw new KmsError(
      "SIGN_PARSE_FAILED",
      "Cloud KMS response missing signature",
    );
  }

  const sigBin = atob(json.signature);
  const sig = new Uint8Array(sigBin.length);
  for (let i = 0; i < sigBin.length; i++) sig[i] = sigBin.charCodeAt(i);
  return sig;
}

// --- KMS getPublicKey -------------------------------------------------

// Expected algorithm enum string from Cloud KMS for the RealReel intermediate.
// See https://cloud.google.com/kms/docs/algorithms — `EC_SIGN_P256_SHA256`
// signs with ECDSA P-256 and SHA-256, which matches the `ecdsaWithSHA256`
// AlgorithmIdentifier pki.ts hardcodes in the TBSCertificate handed to KMS.
//
// If GCP_KMS_KEY_RESOURCE is ever pointed at an RSA, P-384, or other-curve
// key without simultaneously updating pki.ts, every leaf we issue would
// declare `signatureAlgorithm = ecdsaWithSHA256` while carrying a
// different signature — leaves would fail to verify against their own
// declared algorithm, and devices would be unable to capture until the
// config drift is fixed. The constant + check below catch the misconfig
// at the first cold-start KMS call rather than at first sign-then-verify.
export const KMS_EXPECTED_ALGORITHM = "EC_SIGN_P256_SHA256";

export interface KmsPublicKey {
  // DER-encoded SubjectPublicKeyInfo bytes (raw, no PEM wrapper). Same shape
  // as `extractSpkiDer(cert)` from pki.ts so callers can constant-time-compare
  // directly.
  spki: Uint8Array;
  // Cloud KMS algorithm enum string (e.g. `EC_SIGN_P256_SHA256`). Verified
  // against KMS_EXPECTED_ALGORITHM by callers as part of the cold-start
  // consistency check.
  algorithm: string;
}

// Fetch the public key + algorithm for the configured KMS resource. Used by
// register-signing-key to verify REALREEL_INTERMEDIATE_CERT_PEM and the
// KMS-resident intermediate key are in sync (a rotation drift would otherwise
// produce leaves whose signatures don't verify against their declared
// issuer — recoverable but operationally expensive). The algorithm field
// closes a parallel drift hazard where the KMS key is rotated to a
// different signing algorithm than the TBS certificate template assumes.
//
// KMS returns the public key as a PEM-wrapped SPKI (`-----BEGIN PUBLIC KEY-----`)
// alongside an `algorithm` enum. We strip the PEM wrapper and surface
// both fields. Free per Google's KMS pricing.
export async function kmsGetPublicKey(
  creds: KmsCredentials,
): Promise<KmsPublicKey> {
  const token = await getAccessToken(creds);
  const url = `https://cloudkms.googleapis.com/v1/${creds.resource}/publicKey`;

  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "GET",
      headers: { "authorization": `Bearer ${token}` },
    });
  } catch (e) {
    throw new KmsError(
      "PUBLIC_KEY_FETCH_FAILED",
      `Failed to reach cloudkms.googleapis.com: ${(e as Error).message}`,
    );
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    console.error("[kms] getPublicKey failed", resp.status, text);
    throw new KmsError(
      "PUBLIC_KEY_FAILED",
      `Cloud KMS getPublicKey returned ${resp.status}`,
    );
  }

  let json: { pem?: string; algorithm?: string };
  try {
    json = await resp.json();
  } catch (e) {
    throw new KmsError(
      "PUBLIC_KEY_PARSE_FAILED",
      `Cloud KMS response was not JSON: ${(e as Error).message}`,
    );
  }
  if (!json.pem) {
    throw new KmsError(
      "PUBLIC_KEY_PARSE_FAILED",
      "Cloud KMS getPublicKey response missing pem field",
    );
  }
  if (!json.algorithm) {
    throw new KmsError(
      "PUBLIC_KEY_PARSE_FAILED",
      "Cloud KMS getPublicKey response missing algorithm field",
    );
  }

  // Explicit marker check before strip — upgrades a malformed-response
  // failure mode from a generic atob InvalidCharacterError to a typed
  // KmsError, so future KMS response-format regressions surface clearly in
  // logs. KMS has emitted SubjectPublicKeyInfo as `BEGIN PUBLIC KEY` across
  // the v1 API; any other shape is "we don't recognize this", not "we trust
  // it and try to decode the body anyway."
  if (!json.pem.includes("-----BEGIN PUBLIC KEY-----")) {
    throw new KmsError(
      "PUBLIC_KEY_FORMAT_INVALID",
      "Cloud KMS pem field missing BEGIN PUBLIC KEY marker",
    );
  }

  const stripped = json.pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(stripped);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return { spki: der, algorithm: json.algorithm };
}
