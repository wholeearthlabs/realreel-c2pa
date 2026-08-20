// Shared OCSP (RFC 6960) primitives for the realreel-ocsp Worker and its
// response-refresh tool. Everything here is pure and WebCrypto-based so it runs
// identically in the Workers runtime, Deno (tests + refresh tool), and Node.
//
// The single certificate this responder is authoritative for is the RealReel
// Claim Signing CA (the ICA), whose issuer is the RealReel C2PA Root CA. A
// client's CertID names that pair as: hash(ICA's issuer Name DER) +
// hash(root's subjectPublicKey bits) + the ICA serial (RFC 6960 §4.1.1).

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";

export const OID_SHA1 = "1.3.14.3.2.26";
export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
export const OID_SHA384 = "2.16.840.1.101.3.4.2.2";
export const OID_SHA512 = "2.16.840.1.101.3.4.2.3";
export const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
export const OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";

// KV keys the refresh tool writes and the Worker reads, one pre-signed
// response per CertID hash algorithm a client may use. SHA-1 is what nearly
// every OCSP client sends (openssl, c2pa-rs — and RFC 5019 §2.1.1 mandates it
// for lightweight clients); SHA-256 is covered for the rest. A SHA-384/512
// ICA CertID answers `unauthorized` — an accepted gap: no known client sends
// one, and closing it means pre-signing two more responses in the daily
// refresh, not a Worker change. (Leaf CertIDs cover all four hashes because
// the live leaf responder signs per request — see LEAF_WEBCRYPTO_BY_HASH_OID.)
export const KV_KEY_BY_HASH_OID: Record<string, string> = {
  [OID_SHA1]: "response:sha1",
  [OID_SHA256]: "response:sha256",
};

const WEBCRYPTO_ALG_BY_OID: Record<string, string> = {
  [OID_SHA1]: "SHA-1",
  [OID_SHA256]: "SHA-256",
};

// An OCSPResponse with a non-successful responseStatus carries no
// responseBytes (RFC 6960 §4.2.1) and therefore needs no signature — it
// encodes as five constant bytes: SEQUENCE { ENUMERATED status }.
function errorResponse(status: number): Uint8Array {
  return new Uint8Array([0x30, 0x03, 0x0a, 0x01, status]);
}
export const OCSP_MALFORMED_REQUEST = errorResponse(1);
export const OCSP_INTERNAL_ERROR = errorResponse(2);
export const OCSP_UNAUTHORIZED = errorResponse(6);

// --- Byte / cert helpers --------------------------------------------------

export function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

export function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return der;
}

export function parseCert(pem: string): pkijs.Certificate {
  const asn1 = asn1js.fromBER(toArrayBuffer(pemToDer(pem)));
  if (asn1.offset === -1) throw new Error("failed to parse certificate PEM as DER");
  return new pkijs.Certificate({ schema: asn1.result });
}

// OCTET STRING / INTEGER / BIT STRING content bytes, with the same
// valueHexView → valueHex fallback the ca/ tooling uses.
export function blockBytes(node: unknown): Uint8Array {
  const vb = (node as { valueBlock?: unknown }).valueBlock as {
    valueHexView?: Uint8Array;
    valueHex?: ArrayBuffer;
  };
  if (vb?.valueHexView) return new Uint8Array(vb.valueHexView);
  if (vb?.valueHex) return new Uint8Array(vb.valueHex);
  throw new Error("cannot extract ASN.1 value bytes");
}

export function subjectPublicKeyBits(cert: pkijs.Certificate): Uint8Array {
  return blockBytes(cert.subjectPublicKeyInfo.subjectPublicKey);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function digest(webcryptoAlg: string, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(webcryptoAlg, toArrayBuffer(data)));
}

// --- CertID values --------------------------------------------------------

export interface CertIdValues {
  hashOid: string;
  issuerNameHash: Uint8Array;
  issuerKeyHash: Uint8Array;
  serialNumber: Uint8Array;
}

// The CertID values a client asking about the ICA will send, for each
// supported hash algorithm. Derived at runtime from the same trust-source
// PEMs the verifier ships, so they can never drift from the deployed certs.
// `async` is deliberate despite the body having no `await`: router.ts memoizes
// the returned promise without awaiting it, so a PEM-parse failure has to
// surface as a rejected (and cached) promise, not a synchronous throw at the
// memo site.
// deno-lint-ignore require-await
export async function icaCertIdTargets(rootPem: string, icaPem: string): Promise<CertIdValues[]> {
  const root = parseCert(rootPem);
  const ica = parseCert(icaPem);
  const issuerNameDer = new Uint8Array(ica.issuer.toSchema().toBER(false));
  const rootKeyBits = subjectPublicKeyBits(root);
  const serialNumber = blockBytes(ica.serialNumber);
  return Promise.all(
    Object.keys(KV_KEY_BY_HASH_OID).map(async (hashOid) => ({
      hashOid,
      issuerNameHash: await digest(WEBCRYPTO_ALG_BY_OID[hashOid], issuerNameDer),
      issuerKeyHash: await digest(WEBCRYPTO_ALG_BY_OID[hashOid], rootKeyBits),
      serialNumber,
    })),
  );
}

export function certIdMatches(a: CertIdValues, b: CertIdValues): boolean {
  return (
    a.hashOid === b.hashOid &&
    bytesEqual(a.issuerNameHash, b.issuerNameHash) &&
    bytesEqual(a.issuerKeyHash, b.issuerKeyHash) &&
    bytesEqual(a.serialNumber, b.serialNumber)
  );
}

// --- Leaf CertIDs (issuer = the ICA) ---------------------------------------

// The issuer half of every leaf CertID: hashes of the ICA's subject DN and
// subjectPublicKey bits (RFC 6960 §4.1.1 — a leaf's OCSP request names its
// ISSUER, which for RealReel leaves is always the Claim Signing ICA). Used by
// the live leaf-status responder (../ocsp-leaf/) to gate lookups, and by the
// Worker to decide which requests to relay to it.
export interface IssuerHashes {
  hashOid: string;
  issuerNameHash: Uint8Array;
  issuerKeyHash: Uint8Array;
}

// All four RFC 6960-permitted CertID hash algorithms: a client may hash the
// issuer with any of them (SHA-384 is the natural pairing for a SHA-384
// hierarchy), and a matching target only ever asserts authority over OUR ICA.
// Distinct from KV_KEY_BY_HASH_OID, which enumerates only the pre-signed
// ICA-status responses the refresh job publishes.
const LEAF_WEBCRYPTO_BY_HASH_OID: Record<string, string> = {
  [OID_SHA1]: "SHA-1",
  [OID_SHA256]: "SHA-256",
  [OID_SHA384]: "SHA-384",
  [OID_SHA512]: "SHA-512",
};

// `async` is deliberate despite the body having no `await`: router.ts memoizes
// the returned promise without awaiting it, so a PEM-parse failure has to
// surface as a rejected (and cached) promise, not a synchronous throw at the
// memo site.
// deno-lint-ignore require-await
export async function leafIssuerTargets(icaPem: string): Promise<IssuerHashes[]> {
  const ica = parseCert(icaPem);
  const nameDer = new Uint8Array(ica.subject.toSchema().toBER(false));
  const keyBits = subjectPublicKeyBits(ica);
  return Promise.all(
    Object.entries(LEAF_WEBCRYPTO_BY_HASH_OID).map(async ([hashOid, alg]) => ({
      hashOid,
      issuerNameHash: await digest(alg, nameDer),
      issuerKeyHash: await digest(alg, keyBits),
    })),
  );
}

export function issuerMatches(
  targets: IssuerHashes[],
  certId: CertIdValues,
): boolean {
  return targets.some(
    (t) =>
      t.hashOid === certId.hashOid &&
      bytesEqual(t.issuerNameHash, certId.issuerNameHash) &&
      bytesEqual(t.issuerKeyHash, certId.issuerKeyHash),
  );
}

// --- CertID / request construction ----------------------------------------

export function certIdToPkijs(t: CertIdValues): pkijs.CertID {
  return new pkijs.CertID({
    hashAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: t.hashOid,
      algorithmParams: new asn1js.Null(),
    }),
    issuerNameHash: new asn1js.OctetString({ valueHex: toArrayBuffer(t.issuerNameHash) }),
    issuerKeyHash: new asn1js.OctetString({ valueHex: toArrayBuffer(t.issuerKeyHash) }),
    serialNumber: new asn1js.Integer({ valueHex: toArrayBuffer(t.serialNumber) }),
  });
}

// Minimal OCSPRequest DER for one CertID (no version, requestor, extensions
// or nonce) — the same shape `openssl ocsp -no_nonce` produces. Used by the
// refresh tooling's live-endpoint check.
export function buildOcspRequestDer(t: CertIdValues): Uint8Array {
  const request = new asn1js.Sequence({ value: [certIdToPkijs(t).toSchema()] });
  const requestList = new asn1js.Sequence({ value: [request] });
  const tbsRequest = new asn1js.Sequence({ value: [requestList] });
  const ocspRequest = new asn1js.Sequence({ value: [tbsRequest] });
  return new Uint8Array(ocspRequest.toBER(false));
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// --- Request parsing ------------------------------------------------------

export function certIdValues(certId: pkijs.CertID): CertIdValues {
  return {
    hashOid: certId.hashAlgorithm.algorithmId,
    issuerNameHash: blockBytes(certId.issuerNameHash),
    issuerKeyHash: blockBytes(certId.issuerKeyHash),
    serialNumber: blockBytes(certId.serialNumber),
  };
}

// Parses a DER OCSPRequest and returns the CertID values of every Request in
// its requestList. Throws on anything that doesn't parse as an OCSPRequest.
// Request extensions (e.g. a nonce) are deliberately ignored: pre-signed
// responses cannot echo a nonce, per RFC 5019 operating practice.
export function parseOcspRequestCertIds(der: Uint8Array): CertIdValues[] {
  const request = pkijs.OCSPRequest.fromBER(toArrayBuffer(der));
  return request.tbsRequest.requestList.map((r) => certIdValues(r.reqCert));
}
