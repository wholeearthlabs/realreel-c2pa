// Pure core of the LEAF-status OCSP responder (RFC 6960), the dynamic
// sibling of the pre-signed ICA-status Worker in ../ocsp/. Leaf status is
// high-cardinality (one serial per enrolled device key) and changes with
// revocations, so responses are built and KMS-signed per request instead of
// pre-signed into KV — see ../ocsp/README.md's "leaf status" note and the
// deployment shape in ./README.md.
//
// This module is pure: request parsing, issuer matching, status → DER
// response building, with the ledger lookup and the KMS signature injected.
// main.ts wires the real ones; tests inject ephemeral keys + fixed clocks.
//
// Status semantics (source of record: the app-side issued_certificates
// ledger, read through lookup_signing_key_revocation):
//   row with revoked_at NULL     → good
//   row with revoked_at set      → revoked (revocationTime = revoked_at)
//   no row (never issued by us)  → unknown
// Superseded and expired leaves stay "good" — supersession is an app-fleet
// concept, and expiry is judged from the certificate itself by clients.

import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
  bytesEqual,
  certIdToPkijs,
  OCSP_MALFORMED_REQUEST,
  OCSP_UNAUTHORIZED,
  OID_ECDSA_WITH_SHA256,
  OID_OCSP_BASIC,
  OID_SHA1,
  OID_SHA256,
  parseCert,
  parseOcspRequestCertIds,
  subjectPublicKeyBits,
  toArrayBuffer,
} from "../ocsp/ocsp.ts";
import type { CertIdValues } from "../ocsp/ocsp.ts";

export type SignTbs = (tbs: Uint8Array) => Promise<Uint8Array>;

export type LeafStatus =
  | { kind: "good" }
  | { kind: "revoked"; revokedAt: Date }
  | { kind: "unknown" };

// The issuer half of every leaf CertID: hashes of the ICA's subject DN and
// subjectPublicKey bits (RFC 6960 §4.1.1 — a leaf's OCSP request names its
// ISSUER, which for RealReel leaves is always the Claim Signing ICA).
export interface IssuerHashes {
  hashOid: string;
  issuerNameHash: Uint8Array;
  issuerKeyHash: Uint8Array;
}

// All four RFC 6960-permitted CertID hash algorithms: a client may hash the
// issuer with any of them (SHA-384 is the natural pairing for a SHA-384
// hierarchy), and a matching target only ever asserts authority over OUR ICA.
const OID_SHA384 = "2.16.840.1.101.3.4.2.2";
const OID_SHA512 = "2.16.840.1.101.3.4.2.3";
const WEBCRYPTO_BY_HASH_OID: Record<string, string> = {
  [OID_SHA1]: "SHA-1",
  [OID_SHA256]: "SHA-256",
  [OID_SHA384]: "SHA-384",
  [OID_SHA512]: "SHA-512",
};

export async function leafIssuerTargets(icaPem: string): Promise<IssuerHashes[]> {
  const ica = parseCert(icaPem);
  const nameDer = new Uint8Array(ica.subject.toSchema().toBER(false));
  const keyBits = subjectPublicKeyBits(ica);
  return Promise.all(
    Object.entries(WEBCRYPTO_BY_HASH_OID).map(async ([hashOid, alg]) => ({
      hashOid,
      issuerNameHash: new Uint8Array(
        await crypto.subtle.digest(alg, toArrayBuffer(nameDer)),
      ),
      issuerKeyHash: new Uint8Array(
        await crypto.subtle.digest(alg, toArrayBuffer(keyBits)),
      ),
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

/** OCSP-request serial bytes → the canonical-decimal string the ledger keys
 * on (a DER INTEGER's optional 0x00 high-bit pad doesn't change the value). */
export function serialToDecimal(serial: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < serial.length; i++) {
    hex += serial[i].toString(16).padStart(2, "0");
  }
  return hex.length ? BigInt("0x" + hex).toString(10) : "0";
}

function certStatusSchema(
  status: LeafStatus,
): asn1js.Primitive | asn1js.Constructed {
  switch (status.kind) {
    case "good":
      // good ::= [0] IMPLICIT NULL
      return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 0 } });
    case "revoked":
      // revoked ::= [1] IMPLICIT RevokedInfo { revocationTime }. The ledger's
      // revoked_reason is free operator text, not a CRLReason enum — omitted.
      // Whole seconds: revoked_at is a timestamptz with sub-second precision,
      // and DER GeneralizedTime must be fraction-free (strict parsers reject).
      return new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [
          new asn1js.GeneralizedTime({
            valueDate: new Date(
              Math.floor(status.revokedAt.getTime() / 1000) * 1000,
            ),
          }),
        ],
      });
    case "unknown":
      // unknown ::= [2] IMPLICIT UnknownInfo (NULL)
      return new asn1js.Primitive({ idBlock: { tagClass: 3, tagNumber: 2 } });
  }
}

export interface BuildLeafResponseOpts {
  /** Echoed back verbatim (by value) from the client's request. */
  certId: CertIdValues;
  status: LeafStatus;
  responderPem: string;
  now: Date;
  /** thisUpdate → nextUpdate window. Short: revocation must propagate inside
   * the CP's 72-hour clock even through caches that hold until nextUpdate. */
  validityMs: number;
  signTbs: SignTbs;
}

// Same assembly as the ICA responder's buildOcspResponseDer, with two
// deliberate differences that keep this a separate function rather than a
// parameter soup: the CertID comes from the client (echoed), and "unknown"
// is a valid status (the ICA responder never says unknown — a CertID it
// doesn't recognize is unauthorized instead).
export async function buildLeafOcspResponseDer(
  opts: BuildLeafResponseOpts,
): Promise<Uint8Array> {
  const responder = parseCert(opts.responderPem);

  const now = new Date(opts.now.getTime());
  now.setMilliseconds(0); // whole seconds: keeps GeneralizedTime fraction-free
  const nextUpdate = new Date(now.getTime() + opts.validityMs);

  const single = new pkijs.SingleResponse({
    certID: certIdToPkijs(opts.certId),
    certStatus: certStatusSchema(opts.status),
    thisUpdate: now,
    nextUpdate,
  });

  // responderID byKey: SHA-1 of the responder's subjectPublicKey bits
  // (RFC 6960 §4.2.1 KeyHash) — same choice as the ICA responder.
  const responderKeyHash = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-1",
      toArrayBuffer(subjectPublicKeyBits(responder)),
    ),
  );

  // No responseExtensions — deliberately no request-nonce echo (RFC 6960
  // SHOULD): RFC 5019 forbids nonces in cacheable responses, the pre-signed
  // ICA sibling can't echo either, and per-CertID caching is the KMS/DB
  // abuse bound. Replay within thisUpdate→nextUpdate is what the validity
  // window already permits.
  const responseData = new pkijs.ResponseData({
    responderID: new asn1js.OctetString({
      valueHex: toArrayBuffer(responderKeyHash),
    }),
    producedAt: now,
    responses: [single],
  });
  const tbs = new Uint8Array(responseData.toSchema(true).toBER(false));
  responseData.tbsView = tbs; // BasicOCSPResponse.toSchema() serializes tbsView

  const signature = await opts.signTbs(tbs);

  const basic = new pkijs.BasicOCSPResponse({
    tbsResponseData: responseData,
    signatureAlgorithm: new pkijs.AlgorithmIdentifier({
      algorithmId: OID_ECDSA_WITH_SHA256,
    }),
    signature: new asn1js.BitString({ valueHex: toArrayBuffer(signature) }),
    certs: [responder],
  });

  const response = new pkijs.OCSPResponse({
    responseStatus: new asn1js.Enumerated({ value: 0 }), // successful
    responseBytes: new pkijs.ResponseBytes({
      responseType: OID_OCSP_BASIC,
      response: new asn1js.OctetString({
        valueHex: basic.toSchema().toBER(false),
      }),
    }),
  });
  return new Uint8Array(response.toSchema().toBER(false));
}

/** Optional per-CertID cache of SIGNED responses. A cached response is
 * served for at most its own thisUpdate→nextUpdate window, so revocation
 * propagation is unchanged — external caches already hold that long. The
 * point is abuse economics: without it, every serial-enumeration request
 * costs a KMS signature + a ledger query. */
export interface ResponseCache {
  get(key: string): Uint8Array | undefined;
  set(key: string, der: Uint8Array): void;
}

function certIdCacheKey(certId: CertIdValues): string {
  const hex = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${certId.hashOid}:${hex(certId.issuerNameHash)}:${
    hex(certId.issuerKeyHash)
  }:${hex(certId.serialNumber)}`;
}

export interface ResponderDeps {
  issuerTargets: IssuerHashes[];
  responderPem: string;
  /** Ledger lookup by canonical-decimal serial. */
  lookupStatus: (serialDecimal: string) => Promise<LeafStatus>;
  signTbs: SignTbs;
  now: () => Date;
  validityMs: number;
  cache?: ResponseCache;
}

export interface RespondResult {
  der: Uint8Array;
  /** True for a signed (successful) response — cacheable; false for the
   * 5-byte unsigned error forms, which must never be cached. */
  signed: boolean;
}

/**
 * Full request → response pipeline. Never throws for client-shaped problems
 * (malformed / not-ours → unsigned error responses); ledger or KMS failures
 * DO throw so the HTTP layer can return internalError + log.
 */
export async function respond(
  requestDer: Uint8Array,
  deps: ResponderDeps,
): Promise<RespondResult> {
  let certIds: CertIdValues[];
  try {
    certIds = parseOcspRequestCertIds(requestDer);
  } catch {
    return { der: OCSP_MALFORMED_REQUEST, signed: false };
  }
  // One CertID per request, like the ICA responder: batched requests are
  // rare in the wild and refusing them keeps the signing path single-status.
  if (certIds.length !== 1) {
    return { der: OCSP_UNAUTHORIZED, signed: false };
  }
  const certId = certIds[0];
  if (!issuerMatches(deps.issuerTargets, certId)) {
    // Asking about a cert we didn't issue under a different issuer —
    // this responder is not authoritative for it.
    return { der: OCSP_UNAUTHORIZED, signed: false };
  }

  const cacheKey = certIdCacheKey(certId);
  const cached = deps.cache?.get(cacheKey);
  if (cached) return { der: cached, signed: true };

  const status = await deps.lookupStatus(serialToDecimal(certId.serialNumber));
  const der = await buildLeafOcspResponseDer({
    certId,
    status,
    responderPem: deps.responderPem,
    now: deps.now(),
    validityMs: deps.validityMs,
    signTbs: deps.signTbs,
  });
  deps.cache?.set(cacheKey, der);
  return { der, signed: true };
}

// Re-export for main.ts / tests so they don't reach into ../ocsp directly.
export {
  blockBytes,
  OCSP_INTERNAL_ERROR,
  OCSP_MALFORMED_REQUEST,
  OCSP_UNAUTHORIZED,
} from "../ocsp/ocsp.ts";
