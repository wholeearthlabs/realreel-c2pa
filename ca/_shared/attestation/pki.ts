// X.509 / ASN.1 helpers built on pkijs. Used by both the iOS App Attest
// validator and the Android KeyStore attestation validator, for cert parsing
// and chain validation. (CBOR decoding for App Attest lives in apple.ts.)

// deno-lint-ignore-file no-explicit-any
import * as pkijs from "npm:pkijs@3.2.4";
import * as asn1js from "npm:asn1js@3.0.5";
import { p256, p384, p521 } from "npm:@noble/curves@1.9.7/nist.js";

// Defensive: this module mutates `globalThis.process` to work around a pkijs +
// Supabase-Edge-Runtime quirk (see below). That mutation is only safe in Deno;
// in Node, it would clobber the real EventEmitter `process` global. The
// _shared/attestation/ directory is structurally Edge-only, but a runtime
// guard makes accidental imports from non-Deno code (e.g. React Native) fail
// loudly instead of corrupting global state.
if (typeof Deno === "undefined") {
  throw new Error(
    "_shared/attestation/pki.ts is Deno-only. Do not import from React Native or other non-Deno runtimes.",
  );
}

// --- ECDSA curve/hash fallback -----------------------------------------
//
// Supabase Edge Runtime's WebCrypto only implements ECDSA verify for the
// "natural" curve/hash pairing (P-256+SHA-256, P-384+SHA-384, P-521+SHA-512);
// anything else throws `Not implemented`. Apple's App Attest credCert is signed
// by the P-384 "Apple App Attestation CA 1" key using SHA-256, so the
// leaf→intermediate link hits that gap. pkijs's `findIssuer` swallows the throw
// and drops the issuer candidate, surfacing only as the misleading
// "No valid certificate paths found". Deno CLI implements the mismatched pairs,
// so this reproduces on the edge runtime alone (ecdsa_fallback_test.ts
// simulates it). Verify those pairs with @noble/curves instead.
//
// The fallback must accept exactly what the WebCrypto path accepts — neither
// laxer (this is the attestation trust boundary) nor stricter (a link must not
// verify or fail depending on which engine path handled it). Retire it once
// the edge runtime's `crypto.subtle.verify` stops throwing on mismatched pairs.

// All curve×SHA-2 cross pairings, not just Apple's P-384+SHA-256: a narrower
// table would make CI (Deno CLI verifies all pairs natively) silently diverge
// from the edge runtime again.
const EC_CURVE_BY_OID: Record<string, { curve: any; naturalHash: string }> = {
  "1.2.840.10045.3.1.7": { curve: p256, naturalHash: "SHA-256" }, // secp256r1
  "1.3.132.0.34": { curve: p384, naturalHash: "SHA-384" }, // secp384r1
  "1.3.132.0.35": { curve: p521, naturalHash: "SHA-512" }, // secp521r1
};

// Deliberately omits ecdsa-with-SHA1 and -SHA224: the fallback must not widen
// the set of signature algorithms this trust boundary accepts. WebCrypto here
// rejects both, and a hash absent from this table keeps that rejection.
const ECDSA_SIG_HASH_BY_OID: Record<string, string> = {
  "1.2.840.10045.4.3.2": "SHA-256",
  "1.2.840.10045.4.3.3": "SHA-384",
  "1.2.840.10045.4.3.4": "SHA-512",
};

// Applied to the caller-supplied `shaAlgorithm` too, which otherwise reaches
// the fallback without passing the OID table above.
const FALLBACK_HASHES = new Set(Object.values(ECDSA_SIG_HASH_BY_OID));

const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_RSA_PSS = "1.2.840.113549.1.1.10";

// Returns the noble curve + hash name when this verification is an ECDSA
// signature whose hash is not the curve's natural pairing, else null.
function ecdsaFallbackParams(
  publicKeyInfo: any,
  signatureAlgorithm: any,
  shaAlgorithm?: string,
): { curve: any; hash: string } | null {
  if (publicKeyInfo?.algorithm?.algorithmId !== OID_EC_PUBLIC_KEY) return null;

  // pkijs keys the import off a declared RSA-PSS OID (only that one) and fails
  // for an EC key; decline rather than re-interpret the mislabel as ECDSA.
  if (signatureAlgorithm?.algorithmId === OID_RSA_PSS) return null;

  // pkijs rejects namedCurve params that aren't an OBJECT IDENTIFIER; a
  // mistyped node must keep failing closed, not string-match to a curve.
  const params = publicKeyInfo.algorithm.algorithmParams;
  if (!(params instanceof asn1js.ObjectIdentifier)) return null;
  const entry = EC_CURVE_BY_OID[params.valueBlock.toString()];
  if (!entry) return null;

  const hash = shaAlgorithm ??
    ECDSA_SIG_HASH_BY_OID[signatureAlgorithm?.algorithmId];
  if (!hash || !FALLBACK_HASHES.has(hash)) return null;
  if (hash === entry.naturalHash) return null; // WebCrypto handles this pair

  return { curve: entry.curve, hash };
}

// Parse an X.509 ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`) into a
// noble Signature, or null if unparseable/out-of-range. Uses the same lenient
// asn1js parser as the WebCrypto path — noble's strict-DER Signature.fromDER
// would reject BER-ish encodings that natural-pair links accept.
function ecdsaSigFromBer(curve: any, sigDer: Uint8Array): any | null {
  const asn1 = asn1js.fromBER(
    sigDer.buffer.slice(
      sigDer.byteOffset,
      sigDer.byteOffset + sigDer.byteLength,
    ) as ArrayBuffer,
  );
  if (asn1.offset === -1 || !(asn1.result instanceof asn1js.Sequence)) {
    return null;
  }
  const parts = (asn1.result.valueBlock as any).value;
  if (
    parts?.length !== 2 ||
    !(parts[0] instanceof asn1js.Integer) ||
    !(parts[1] instanceof asn1js.Integer)
  ) {
    return null;
  }
  try {
    return new curve.Signature(
      bytesToBigInt(parts[0].valueBlock.valueHexView),
      bytesToBigInt(parts[1].valueBlock.valueHexView),
    );
  } catch {
    return null; // r or s out of range for the curve
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = "0";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return BigInt("0x" + hex);
}

class EcdsaFallbackCryptoEngine extends pkijs.CryptoEngine {
  override async verifyWithPublicKey(
    data: any,
    signature: any,
    publicKeyInfo: any,
    signatureAlgorithm: any,
    shaAlgorithm?: string,
  ): Promise<boolean> {
    const fallback = ecdsaFallbackParams(
      publicKeyInfo,
      signatureAlgorithm,
      shaAlgorithm,
    );
    if (!fallback) {
      try {
        return await super.verifyWithPublicKey(
          data,
          signature,
          publicKeyInfo,
          signatureAlgorithm,
          shaAlgorithm as any,
        );
      } catch (e) {
        // pkijs swallows engine throws into "No valid certificate paths
        // found"; name the algorithm WebCrypto couldn't handle first so the
        // next runtime gap is a one-line diagnosis.
        console.warn(
          `[pki] WebCrypto verify threw for sigAlg=${signatureAlgorithm?.algorithmId} ` +
            `keyAlg=${publicKeyInfo?.algorithm?.algorithmId}` +
            (shaAlgorithm ? ` sha=${shaAlgorithm}` : "") +
            `: ${(e as Error).message}`,
        );
        throw e;
      }
    }

    // WebCrypto's SPKI import accepts only the uncompressed point
    // (0x04 || X || Y); noble would also decompress 0x02/0x03. Enforce the
    // same shape so both paths accept identical key encodings.
    const publicKey = publicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
    if (publicKey?.[0] !== 0x04) return false;

    const sig = ecdsaSigFromBer(
      fallback.curve,
      signature.valueBlock.valueHexView,
    );
    if (sig === null) return false; // malformed signature: "does not verify"

    const digest = new Uint8Array(
      await crypto.subtle.digest(fallback.hash, data),
    );

    try {
      // lowS:false — X.509 signers may emit high-S values, and WebCrypto
      // accepts them; rejecting here would fail valid certificates.
      return fallback.curve.verify(sig, digest, publicKey, { lowS: false });
    } catch (e) {
      // Inputs are vetted above, so this is an off-curve key or an
      // infrastructure failure (e.g. a noble API change). Log before failing
      // closed so an outage can't masquerade as "does not verify".
      console.warn(
        `[pki] ECDSA fallback verify threw (curve+${fallback.hash}): ${
          (e as Error).message
        }`,
      );
      return false;
    }
  }
}

// pkijs needs a CryptoEngine registered before any cert signature work.
//
// Why this is awkward in Supabase Edge Runtime:
//   pkijs's setEngine() detects "Node" by checking that `process` exists with
//   a `pid` property and `window` is undefined. It then stashes the engine on
//   `globalThis[process.pid].pkijs.engine`. Supabase polyfills `process` but
//   exposes `pid` as `undefined`, so pkijs ends up doing
//   `globalThis["undefined"] = {}` — and the `"undefined"` property of the
//   Window-class global is non-writable, so the assignment throws.
//
// Fix: patch `process.pid` to a real string key BEFORE calling setEngine, and
// pre-create the stash slot with a plain mutable object. pkijs then writes
// `engine` into our pre-populated stash and getEngine() reads it back.
{
  const g = globalThis as Record<string, unknown>;
  const stashKey = "__pkijs_deno_stash";

  // Pre-populate the slot pkijs will look for. This must be a plain mutable
  // object — pkijs writes `slot.pkijs.engine = ...` later.
  g[stashKey] = { pkijs: {} };

  // Override ONLY `process.pid`, not the whole process object: Supabase's
  // `process` polyfill is an EventEmitter that later code reads (process.on,
  // process.env), so replacing it would break those. Direct assignment fails
  // because `pid` is a getter; Object.defineProperty installs a real data
  // property, with a wholesale-replacement fallback if it's non-configurable.
  const proc = g.process as { pid?: unknown } | undefined;
  if (proc) {
    try {
      Object.defineProperty(proc, "pid", {
        value: stashKey,
        writable: true,
        configurable: true,
      });
    } catch {
      // Non-configurable somehow — fall back to the heavier shim.
      g.process = { pid: stashKey };
    }
  } else {
    // No `process` polyfill at all — provide a minimal one.
    g.process = { pid: stashKey };
  }

  pkijs.setEngine(
    "deno-webcrypto",
    new EcdsaFallbackCryptoEngine({
      name: "deno-webcrypto",
      crypto: globalThis.crypto,
      subtle: globalThis.crypto.subtle,
    }),
  );
}

// --- PEM/DER conversions -----------------------------------------------

export function pemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(stripped);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// --- Certificate parsing -----------------------------------------------

export function parseCertFromDer(der: Uint8Array): pkijs.Certificate {
  const ab = der.buffer.slice(
    der.byteOffset,
    der.byteOffset + der.byteLength,
  ) as ArrayBuffer;
  const asn1 = asn1js.fromBER(ab);
  if (asn1.offset === -1) {
    throw new Error("failed to parse DER as ASN.1");
  }
  return new pkijs.Certificate({ schema: asn1.result });
}

export function parseCertFromPem(pem: string): pkijs.Certificate {
  return parseCertFromDer(pemToDer(pem));
}

// --- Chain verification ------------------------------------------------

// Verifies that `chain[0]` (leaf) chains up through `chain[1..]` (intermediates)
// to one of the provided trusted roots. Throws on failure with a concrete reason.
//
// Notes:
//   * pkijs's CertificateChainValidationEngine handles signature verification at
//     each link, validity-period checks, and basic constraints.
//   * The chain array is leaf-first (matching how Apple's x5c and Android's
//     keystore cert chain are both ordered).
//   * We pass `findIssuer` undefined → pkijs builds the chain from the supplied
//     certs and trusted roots automatically.
//   * `validationTime` overrides "now" for the validity-window checks.
//     TEST-ONLY: committed fixtures carry short-lived RKP intermediates that
//     expire weeks after capture, so fixture tests pin this to the capture
//     date. Production callers must omit it.
export async function verifyChainToTrustedRoots(
  chain: pkijs.Certificate[],
  trustedRoots: pkijs.Certificate[],
  validationTime?: Date,
): Promise<void> {
  if (chain.length === 0) throw new Error("empty cert chain");
  if (trustedRoots.length === 0) throw new Error("no trusted roots configured");

  // Drop a device-presented self-signed root before validating: Android RKP
  // chains append the Google root, but the trust anchor must come from our
  // pinned store. Under root rotation (Google re-issues the same subject+key
  // with a fresh window) a device still ships the OLD expired copy, which would
  // date-fail the path if left in. Safe to drop: it was never in trustedCerts,
  // and every leaf→intermediate link is still checked against the pinned anchor.
  const presented = [...chain];
  const top = presented[presented.length - 1];
  if (presented.length > 1 && isSelfSigned(top)) {
    presented.pop();
  }

  // The engine validates certs[LAST] and builds upward, so it needs target-last
  // order — reverse our leaf-first input. Passing leaf-first made it treat the
  // presented ROOT as the target, so only the top link was ever verified and a
  // forged leaf sailed through.
  const engine = new pkijs.CertificateChainValidationEngine({
    certs: presented.reverse(),
    trustedCerts: [...trustedRoots],
    ...(validationTime ? { checkDate: validationTime } : {}),
  });

  const result = await engine.verify();
  if (!result.result) {
    throw new Error(
      `chain validation failed: ${result.resultMessage || "unknown"}`,
    );
  }
}

// Self-signed = issuer DN equals subject DN. A name-only (not cryptographic)
// test, enough to spot a root the device appended so we can drop it.
function isSelfSigned(cert: pkijs.Certificate): boolean {
  return cert.issuer.isEqual(cert.subject);
}

// Compact one-line description of a parsed chain for rejection logs — one
// segment per cert: subject, issuer, cert serial (hex), validity window.
// Attestation certs carry no user PII, so this is safe to log; it's what lets
// an operator identify an unknown device hierarchy from the edge-function log
// alone (e.g. an OEM root we haven't pinned).
export function describeCertChain(chain: pkijs.Certificate[]): string {
  return chain
    .map((cert, i) => {
      // Runs inside the CHAIN_INVALID error path, so it must never throw on a
      // malformed-but-parseable cert (e.g. an out-of-range date) and escalate a
      // clean 400 rejection into an uncaught 500.
      try {
        const serial = hex(
          new Uint8Array(cert.serialNumber.valueBlock.valueHexView),
        );
        return `[${i}] subj="${rdnToString(cert.subject)}" issuer="${
          rdnToString(cert.issuer)
        }" serial=${serial} valid=${isoDay(cert.notBefore.value)}..${
          isoDay(cert.notAfter.value)
        }`;
      } catch {
        return `[${i}] <undescribable cert>`;
      }
    })
    .join(" | ");
}

// YYYY-MM-DD, or "invalid" for a date pkijs couldn't parse — toISOString()
// throws RangeError on an Invalid Date.
function isoDay(d: Date): string {
  const t = d?.getTime?.();
  return typeof t === "number" && Number.isFinite(t)
    ? d.toISOString().slice(0, 10)
    : "invalid";
}

// OID → short attribute names for the DN types that actually appear in
// attestation chains; anything else falls back to the dotted OID.
const DN_OID_NAMES: Record<string, string> = {
  "2.5.4.3": "CN",
  "2.5.4.5": "SERIALNUMBER",
  "2.5.4.6": "C",
  "2.5.4.10": "O",
  "2.5.4.11": "OU",
};

function rdnToString(rdn: pkijs.RelativeDistinguishedNames): string {
  return rdn.typesAndValues
    .map((tv) => {
      const name = DN_OID_NAMES[tv.type] ?? tv.type;
      return `${name}=${sanitizeDnValue(tv.value.valueBlock.value)}`;
    })
    .join(",");
}

// DN values come from the device-presented cert and land in an operator log
// line, so strip anything a log viewer might render as a line break — C0
// controls, DEL, the C1 block (incl. NEL U+0085), and the Unicode line/
// paragraph separators — and cap the length so a giant CN can't flood a line.
function sanitizeDnValue(value: unknown): string {
  let out = "";
  for (const ch of String(value)) {
    const c = ch.codePointAt(0)!;
    const isBreak = c <= 0x1f || c === 0x7f || (c >= 0x80 && c <= 0x9f) ||
      c === 0x2028 || c === 0x2029;
    if (!isBreak) out += ch;
    if (out.length >= 128) break;
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

// --- Extension lookup --------------------------------------------------

// Returns the raw extnValue (DER bytes) of the extension with the given OID,
// or null if no such extension is present.
export function findExtensionByOid(
  cert: pkijs.Certificate,
  oid: string,
): Uint8Array | null {
  const exts = cert.extensions ?? [];
  for (const ext of exts) {
    if (ext.extnID === oid) {
      // ext.extnValue is an asn1js OctetString; valueBlock.valueHex is the raw
      // bytes of the OCTET STRING contents.
      const hex = (ext.extnValue.valueBlock as any).valueHexView as
        | Uint8Array
        | undefined;
      if (hex) return new Uint8Array(hex);
      // Older pkijs versions: fall back to valueHex (ArrayBuffer).
      const ab = (ext.extnValue.valueBlock as any).valueHex as
        | ArrayBuffer
        | undefined;
      if (ab) return new Uint8Array(ab);
      return null;
    }
  }
  return null;
}

// --- Public key extraction --------------------------------------------

// Returns the DER-encoded SubjectPublicKeyInfo of the certificate's public key.
// This is the format we store in user_signing_keys.public_key for the SE key,
// so the caller can constant-time-compare.
export function extractSpkiDer(cert: pkijs.Certificate): Uint8Array {
  const ber = cert.subjectPublicKeyInfo.toSchema().toBER(false);
  return new Uint8Array(ber);
}

// Returns just the raw subjectPublicKey bits (no SPKI envelope) — useful for
// hashing where Apple's spec says "SHA-256 over the public key bytes" without
// further qualification (App Attest credCert keyId derivation).
export function extractSubjectPublicKeyBytes(
  cert: pkijs.Certificate,
): Uint8Array {
  const bv = cert.subjectPublicKeyInfo.subjectPublicKey;
  const hex = (bv.valueBlock as any).valueHexView as Uint8Array | undefined;
  if (hex) return new Uint8Array(hex);
  const ab = (bv.valueBlock as any).valueHex as ArrayBuffer | undefined;
  if (ab) return new Uint8Array(ab);
  throw new Error("could not extract subject public key bytes");
}

// --- Hashing + comparison ----------------------------------------------

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(buf);
}

export async function sha384(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-384", data as BufferSource);
  return new Uint8Array(buf);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// Constant-time byte comparison. Returns true iff equal.
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Errors ------------------------------------------------------------

export class AttestationError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "AttestationError";
    this.code = code;
  }
}

// --- CSR (PKCS#10) parsing & verification ------------------------------
//
// CSR handling lives here (not in a separate `csr.ts`) because it shares the
// same pkijs CryptoEngine setup that the cert helpers above already depend on.
// Splitting would force a second engine-init block or a cross-file import that
// risks ordering bugs.

export function csrPemToDer(pem: string): Uint8Array {
  const stripped = pem
    .replace(/-----BEGIN CERTIFICATE REQUEST-----/g, "")
    .replace(/-----END CERTIFICATE REQUEST-----/g, "")
    .replace(/-----BEGIN NEW CERTIFICATE REQUEST-----/g, "")
    .replace(/-----END NEW CERTIFICATE REQUEST-----/g, "")
    .replace(/\s+/g, "");
  return base64ToBytes(stripped);
}

export function parseCSRFromPem(pem: string): pkijs.CertificationRequest {
  const der = csrPemToDer(pem);
  const ab = der.buffer.slice(
    der.byteOffset,
    der.byteOffset + der.byteLength,
  ) as ArrayBuffer;
  const asn1 = asn1js.fromBER(ab);
  if (asn1.offset === -1) {
    throw new AttestationError(
      "CSR_PARSE_FAILED",
      "Could not parse PEM as PKCS#10 ASN.1",
    );
  }
  try {
    return new pkijs.CertificationRequest({ schema: asn1.result });
  } catch (e) {
    throw new AttestationError(
      "CSR_PARSE_FAILED",
      `Not a valid CertificationRequest: ${(e as Error).message}`,
    );
  }
}

// Cryptographically verify the CSR's self-signature, which proves the requester
// possesses the private key for the subject SPKI. This is the C2PA-relevant
// possession proof; we then constant-time-compare the SPKI against the attested
// SE/StrongBox key separately in register-signing-key.
export async function verifyCSRSignature(
  csr: pkijs.CertificationRequest,
): Promise<void> {
  let ok = false;
  try {
    ok = await csr.verify();
  } catch (e) {
    throw new AttestationError(
      "CSR_SIG_INVALID",
      `CSR signature verification threw: ${(e as Error).message}`,
    );
  }
  if (!ok) {
    throw new AttestationError(
      "CSR_SIG_INVALID",
      "CSR self-signature did not verify",
    );
  }
}

// DER-encoded SubjectPublicKeyInfo from a CSR. Same shape as
// extractSpkiDer(cert), so the caller can constant-time-compare against the
// attested public key without conversion.
export function extractCSRSpkiDer(
  csr: pkijs.CertificationRequest,
): Uint8Array {
  const ber = csr.subjectPublicKeyInfo.toSchema().toBER(false);
  return new Uint8Array(ber);
}

// --- Leaf cert construction (CA issuance) ------------------------------

// Standard X.509 OIDs we set/inspect repeatedly. Named locally rather than
// imported from pkijs (pkijs doesn't export a comprehensive OID dictionary).
const OID = {
  // RDN attributes
  countryName: "2.5.4.6",
  organizationName: "2.5.4.10",
  organizationalUnitName: "2.5.4.11",
  commonName: "2.5.4.3",
  // Extensions
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectKeyIdentifier: "2.5.29.14",
  authorityKeyIdentifier: "2.5.29.35",
  certificatePolicies: "2.5.29.32",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  // AIA access methods
  adOcsp: "1.3.6.1.5.5.7.48.1",
  adCaIssuers: "1.3.6.1.5.5.7.48.2",
  // Signature algorithms
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  ecdsaWithSHA384: "1.2.840.10045.4.3.3",
  // Extended key usages
  ekuEmailProtection: "1.3.6.1.5.5.7.3.4",
  ekuDocumentSigning: "1.3.6.1.5.5.7.3.36",
  ekuC2PAClaimSigning: "1.3.6.1.4.1.62558.2.1",
  // C2PA conformance-program OIDs (CP §7.1.2; 62558 is C2PA's IANA PEN)
  c2paCertPolicy: "1.3.6.1.4.1.62558.1.1",
  c2paAssuranceLevel: "1.3.6.1.4.1.62558.3",
  c2paAssuranceLevel1: "1.3.6.1.4.1.62558.3.10",
  c2paAssuranceLevel2: "1.3.6.1.4.1.62558.3.20",
  c2paCplRecord: "1.3.6.1.4.1.62558.4",
} as const;

// --- Hierarchy selection (v1 legacy / v2 conformant) --------------------
//
// The CA can issue against two hierarchies:
//   v1 — the legacy pre-conformance hierarchy (P-256 ICA, SHA-256 chain,
//        `CN=RealReel-Device-Key` leaves, no CP §7.1.2 extensions). Default,
//        and what production runs until the cutover gate clears.
//   v2 — the conformant hierarchy (P-384 root+ICA signing with SHA-384,
//        per-platform CPL-registered DNs, nonRepudiation KU, and the CP-required
//        certificatePolicies / AIA / c2pa-al / c2pa-cpl-record extensions).
// Selected by the CA_HIERARCHY env var so the production flip is a config
// change (env + GCP_KMS_KEY_RESOURCE + REALREEL_INTERMEDIATE_CERT_PEM swapped
// together), not a deploy. GUARDRAIL: do not set v2 in production until the
// real CPL record UUIDs exist and the root is on the C2PA Trust List —
// v2 leaves embed the UUID and are non-conformant with a placeholder.

export type CaHierarchy = "v1" | "v2";

export function caHierarchy(): CaHierarchy {
  const v = Deno.env.get("CA_HIERARCHY") ?? "v1";
  if (v !== "v1" && v !== "v2") {
    throw new AttestationError(
      "CA_CONFIG_INVALID",
      `CA_HIERARCHY must be "v1" or "v2", got "${v}"`,
    );
  }
  return v;
}

/** Platform group for leaf issuance. Collapses the enrollment platforms
 * (`ios` / `android-strongbox` / `android-tee`) to the two CPL records. */
export type LeafPlatform = "ios" | "android";

/** C2PA conformance-program assurance level (CP §3.2.3): AL2 requires the
 * full dynamic-evidence table and caps validity at 90 days; AL1 caps at
 * 366 days. RealReel issues iOS at AL1 and Android at AL2-with-AL1-fallback. */
export type AssuranceLevel = "AL1" | "AL2";

// v2 issuance parameters. Resolved from env once per request by
// resolveV2LeafOptions and carried explicitly, so buildLeafCertificate stays a
// pure function of its template (tests construct these directly).
export interface V2LeafOptions {
  platform: LeafPlatform;
  assuranceLevel: AssuranceLevel;
  /** 36-char CPL record UUID embedded in c2pa-cpl-record (CP §7.1.2). */
  cplRecordUuid: string;
  /** HTTP URL of the leaf-status OCSP responder (AIA id-ad-ocsp). */
  ocspUrl: string;
  /** HTTP URL of the DER-encoded ICA cert (AIA id-ad-caIssuers). RFC 5280
   * §4.2.2.1: caIssuers points at certs issued TO this cert's issuer — for a
   * leaf that's the Claim ICA, not the root. */
  caIssuersUrl: string;
}

const UUID_36 =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Resolve the v2 issuance parameters from env. The CPL record UUID is
 * per-platform (C2PA issues one CPL record per registered product DN) and has
 * NO default — v2 issuance without a configured UUID must fail closed rather
 * than mint a leaf missing its CPL binding. Dark testing sets a placeholder
 * UUID explicitly in the local env.
 */
export function resolveV2LeafOptions(
  platform: LeafPlatform,
  assuranceLevel: AssuranceLevel,
): V2LeafOptions {
  const uuidEnv = platform === "ios"
    ? "LEAF_CPL_RECORD_UUID_IOS"
    : "LEAF_CPL_RECORD_UUID_ANDROID";
  const cplRecordUuid = Deno.env.get(uuidEnv) ?? "";
  if (!UUID_36.test(cplRecordUuid)) {
    throw new AttestationError(
      "CA_CONFIG_INVALID",
      `${uuidEnv} must hold the 36-char CPL record UUID for CA_HIERARCHY=v2 ` +
        "issuance (unset or malformed)",
    );
  }
  return {
    platform,
    assuranceLevel,
    cplRecordUuid,
    ocspUrl: Deno.env.get("LEAF_AIA_OCSP_URL") ?? "http://ocsp.realreel.xyz",
    caIssuersUrl: Deno.env.get("LEAF_AIA_CA_ISSUERS_URL") ??
      "http://pki.realreel.xyz/realreel-claim-signing-ca.cer",
  };
}

// ===== PER-APP SWAP-POINT: leaf-certificate subject DN =====
//
// Fixed subject DN written into every issued leaf. A fork should set its own
// organization name + CN here; the defaults below are RealReel's. Sourced from
// env when present so a forker can override per-deployment without editing
// code, falling back to the RealReel values so the test suite and the standard
// deploy run with no env set.
//
// The two hierarchies read DISJOINT env vars, because a v2 DN must byte-match
// the DN registered in the C2PA CPL record and must not silently inherit any
// v1 override:
//   v1: LEAF_SUBJECT_COUNTRY, LEAF_SUBJECT_ORG, LEAF_SUBJECT_OU, LEAF_SUBJECT_CN
//   v2: LEAF_SUBJECT_COUNTRY_V2, LEAF_SUBJECT_ORG_V2,
//       LEAF_SUBJECT_CN_IOS / LEAF_SUBJECT_CN_ANDROID  (no OU)
// A fork running v2 MUST set its own v2 DN vars AND the AIA URLs
// (LEAF_AIA_OCSP_URL, LEAF_AIA_CA_ISSUERS_URL) — the AIA defaults point at
// RealReel's responder/PKI hosts, which answer `unknown` for a fork's serials.
//
// User identity is never embedded — the (user_id, public_key) binding
// lives in user_signing_keys — so any externally-published cert stays
// privacy-respecting. Note the leaf's *issuer* DN (the "...Issuing CA" string
// the verifier surfaces as `signature_info.issuer`) comes from the
// intermediate cert, NOT from this subject; the verifier's trust-list
// `issuerMatch` keys off that issuer string, so a fork that rebrands here must
// also re-issue its CA hierarchy and update the trust-list metadata.
//
// pkijs's `RelativeDistinguishedNames.toSchema()` serializes the entire
// `typesAndValues` array into a SINGLE multi-valued RDN (one SET containing
// every attribute). RFC 5280 §4.1.2.4 allows multi-valued RDNs, but every
// mature X.509 toolchain (openssl, swift-certificates, BouncyCastle) emits
// one attribute per RDN by default — the canonical form. We match the
// canonical form by overriding `toSchema` on the instance, so downstream
// PKIX validators that only exercise the common path don't trip on shape.
function realReelLeafSubject(
  v2?: V2LeafOptions,
): pkijs.RelativeDistinguishedNames {
  // Source-of-truth table — one row per attribute, in the order they appear
  // in the DN. Both the pkijs typesAndValues array (for programmatic reads
  // of `cert.subject`) and the overridden toSchema (for serialization) are
  // derived from this so the two stay in sync.
  //
  // v2 emits the CPL-registered DN: exactly C, O, and a per-platform CN
  // (CP §7.1.2 requires C/O/CN and the DN must byte-match the CPL record —
  // no OU). v1 keeps the legacy four-attribute DN.
  const attrs: ReadonlyArray<{
    type: string;
    value: string;
    stringClass: typeof asn1js.PrintableString | typeof asn1js.Utf8String;
  }> = v2
    ? [
      {
        type: OID.countryName,
        value: Deno.env.get("LEAF_SUBJECT_COUNTRY_V2") ?? "US",
        stringClass: asn1js.PrintableString,
      },
      {
        type: OID.organizationName,
        value: Deno.env.get("LEAF_SUBJECT_ORG_V2") ?? "Whole Earth Labs LLC",
        stringClass: asn1js.Utf8String,
      },
      {
        type: OID.commonName,
        value: v2.platform === "ios"
          ? (Deno.env.get("LEAF_SUBJECT_CN_IOS") ?? "RealReel iOS")
          : (Deno.env.get("LEAF_SUBJECT_CN_ANDROID") ?? "RealReel Android"),
        stringClass: asn1js.Utf8String,
      },
    ]
    : [
      {
        type: OID.countryName,
        value: Deno.env.get("LEAF_SUBJECT_COUNTRY") ?? "US",
        stringClass: asn1js.PrintableString,
      },
      {
        type: OID.organizationName,
        value: Deno.env.get("LEAF_SUBJECT_ORG") ?? "RealReel",
        stringClass: asn1js.Utf8String,
      },
      {
        type: OID.organizationalUnitName,
        value: Deno.env.get("LEAF_SUBJECT_OU") ?? "Production",
        stringClass: asn1js.Utf8String,
      },
      {
        type: OID.commonName,
        value: Deno.env.get("LEAF_SUBJECT_CN") ?? "RealReel-Device-Key",
        stringClass: asn1js.Utf8String,
      },
    ];

  const dn = new pkijs.RelativeDistinguishedNames({
    typesAndValues: attrs.map((a) =>
      new pkijs.AttributeTypeAndValue({
        type: a.type,
        value: new a.stringClass({ value: a.value }),
      })
    ),
  });

  // Emit `SEQUENCE { SET { Attr }, SET { Attr }, ... }` instead of pkijs's
  // default `SEQUENCE { SET { Attr, Attr, ... } }`. Rebuilt on every call so
  // asn1js objects are never re-consumed across multiple TBS encodings.
  (dn as unknown as { toSchema: () => asn1js.Sequence }).toSchema = () =>
    new asn1js.Sequence({
      value: attrs.map((a) =>
        new asn1js.Set({
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.ObjectIdentifier({ value: a.type }),
                new a.stringClass({ value: a.value }),
              ],
            }),
          ],
        })
      ),
    });

  return dn;
}

export interface LeafTemplate {
  csr: pkijs.CertificationRequest;
  intermediate: pkijs.Certificate;
  validityDays: number; // see register-signing-key leafValidityDays()
  serialNumber: Uint8Array; // typically 20 random bytes
  // Present iff issuing against the v2 (conformant) hierarchy: selects the
  // per-platform DN, SHA-384 signature declaration, nonRepudiation KU, and
  // the CP §7.1.2 extensions. Absent → legacy v1 shape.
  v2?: V2LeafOptions;
}

// Build a fully-populated leaf Certificate object ready to be TBS-encoded,
// hashed, signed by KMS, and finalized. The server determines all naming and
// extensions; the CSR contributes only the SPKI.
//
// Ownership contract: this aliases (does not deep-clone) the CSR's
// `subjectPublicKeyInfo` and the intermediate's `subject` into the returned
// Certificate, so callers must not mutate those source objects between
// buildLeafCertificate and finalizeLeafPEM (the change would bleed into the
// leaf). Callers issue one leaf per request and discard both inputs
// immediately, so this is documented rather than defensively cloned.
//
// Async because SubjectKeyIdentifier is SHA-1 over the leaf's public key bits
// (RFC 5280 §4.2.1.2 method 1), and crypto.subtle.digest is async.
export async function buildLeafCertificate(
  template: LeafTemplate,
): Promise<pkijs.Certificate> {
  if (template.validityDays <= 0) {
    throw new AttestationError(
      "LEAF_BUILD_FAILED",
      `validityDays must be positive, got ${template.validityDays}`,
    );
  }
  if (template.serialNumber.length === 0 || template.serialNumber.length > 20) {
    throw new AttestationError(
      "LEAF_BUILD_FAILED",
      `serialNumber must be 1..20 bytes, got ${template.serialNumber.length}`,
    );
  }

  const cert = new pkijs.Certificate();
  cert.version = 2; // v3

  // Mask the high bit to keep the INTEGER positive (X.509 requires
  // non-negative serials), then force byte0 nonzero: asn1js emits valueHex
  // verbatim, and a leading 0x00 followed by a byte <0x80 is non-minimal DER
  // that strict parsers (openssl) reject as a bad INTEGER. Without the bump,
  // ~1/256 issued certs were malformed. Mirrored in issueLeafChainFromCSR's
  // canonicalSerial derivation — keep the two transforms identical.
  const serialCopy = new Uint8Array(template.serialNumber);
  serialCopy[0] = serialCopy[0] & 0x7f;
  if (serialCopy[0] === 0x00) serialCopy[0] = 0x01;
  cert.serialNumber = new asn1js.Integer({
    valueHex: serialCopy.buffer.slice(
      serialCopy.byteOffset,
      serialCopy.byteOffset + serialCopy.byteLength,
    ),
  });

  cert.issuer = template.intermediate.subject;
  cert.subject = realReelLeafSubject(template.v2);

  const now = new Date();
  // Trim sub-second precision; UTCTime has 1-second resolution and pkijs's
  // round-tripping can drift on the millisecond field otherwise.
  now.setMilliseconds(0);
  // Backdate notBefore by 5 minutes for clock-skew tolerance: the cert is
  // KMS-issued (NTP-synced) and immediately handed to a device that may be
  // slightly behind, so without this the FIRST sign after enrollment can fail
  // "certificate not yet valid" (c2pa-rs surfaces it as "certificate invalid").
  const notBefore = new Date(now.getTime() - 5 * 60_000);
  // Anchor to notBefore (not now) and pull in one second: RFC 5280 counts the
  // validity period inclusively, so anchoring to now would add the 5-minute
  // backdate on top of validityDays — over the CP cap when validityDays sits
  // exactly at one (90d AL2 / 366d AL1).
  const notAfter = new Date(
    notBefore.getTime() + template.validityDays * 86_400_000 - 1_000,
  );
  cert.notBefore = new pkijs.Time({ type: 0, value: notBefore });
  cert.notAfter = new pkijs.Time({ type: 0, value: notAfter });

  cert.subjectPublicKeyInfo = template.csr.subjectPublicKeyInfo;

  // v2 chains sign with the P-384 ICA (KMS ec-sign-p384-sha384) →
  // ecdsa-with-SHA384; v1 with the P-256 intermediate → ecdsa-with-SHA256.
  // The leaf KEY stays P-256 either way (mixed-curve chains are CP-allowed
  // and validate in c2pa-rs). Must agree with the digest issueLeafChainFromCSR
  // hashes and the KMS key algorithm — kms.ts's expected-algorithm gate pins
  // that at cold start.
  const sigAlg = new pkijs.AlgorithmIdentifier({
    algorithmId: template.v2 ? OID.ecdsaWithSHA384 : OID.ecdsaWithSHA256,
  });
  // X.509 requires the AlgorithmIdentifier inside the TBS (`signature`) and
  // outside the TBS (`signatureAlgorithm`) to match byte-for-byte. Verifiers
  // reject mismatches.
  cert.signature = sigAlg;
  cert.signatureAlgorithm = sigAlg;

  cert.extensions = [];

  // basicConstraints CA:FALSE — critical. pkijs.Extension's `extnValue` accepts
  // the raw DER bytes of the inner extension structure and wraps them into the
  // outer OCTET STRING itself.
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.basicConstraints,
      critical: true,
      extnValue: new pkijs.BasicConstraints({ cA: false }).toSchema().toBER(
        false,
      ),
    }),
  );

  // keyUsage, critical. BIT STRING bits are MSB-first: digitalSignature is
  // bit 0, nonRepudiation bit 1. v2 sets both (0b11000000 = 0xC0, 6 unused
  // bits) — CP §7.1.2 requires digitalSignature + nonRepudiation, and current
  // c2pa-rs accepts the pair (re-tested 2026-07-27 against c2patool 0.26.60;
  // an earlier rejection blamed on c2pa-rs was a KU unusedBits encoding bug
  // on our side). v1 stays digitalSignature-only (0x80, 7 unused) so the
  // fielded legacy shape doesn't shift.
  const kuBytes = new Uint8Array([template.v2 ? 0xc0 : 0x80]);
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.keyUsage,
      critical: true,
      extnValue: new asn1js.BitString({
        valueHex: kuBytes.buffer,
        unusedBits: template.v2 ? 6 : 7,
      }).toBER(false),
    }),
  );

  // extKeyUsage: emailProtection + documentSigning (for c2pa-rs
  // iter_organization compatibility) + c2pa-kp-claimSigning (the C2PA-specific
  // EKU; future-proofs the Trust List path).
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.extKeyUsage,
      critical: false,
      extnValue: new pkijs.ExtKeyUsage({
        keyPurposes: [
          OID.ekuEmailProtection,
          OID.ekuDocumentSigning,
          OID.ekuC2PAClaimSigning,
        ],
      }).toSchema().toBER(false),
    }),
  );

  // SubjectKeyIdentifier: SHA-1 of the leaf's public key bits (RFC 5280
  // §4.2.1.2 method 1). Strict PKIX path-builders (webpki-style, which c2pa-rs
  // uses) want this on every end-entity cert.
  const pubKeyBits = extractSubjectPublicKeyBytes(cert);
  const skiHash = await crypto.subtle.digest(
    "SHA-1",
    pubKeyBits as BufferSource,
  );
  const skiBytes = new Uint8Array(skiHash);
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.subjectKeyIdentifier,
      critical: false,
      extnValue: new asn1js.OctetString({
        valueHex: skiBytes.buffer.slice(
          skiBytes.byteOffset,
          skiBytes.byteOffset + skiBytes.byteLength,
        ) as ArrayBuffer,
      }).toBER(false),
    }),
  );

  // AuthorityKeyIdentifier: copies the intermediate's SubjectKeyIdentifier
  // into the leaf so path-builders can deterministically link leaf→issuer.
  // Encoded as `SEQUENCE { [0] IMPLICIT OctetString }` per RFC 5280 §4.2.1.1
  // — only keyIdentifier is populated (authorityCertIssuer +
  // authorityCertSerialNumber are optional and omitted).
  //
  // A RealReel intermediate carries an SKI per standard CA hygiene; one
  // without it indicates config drift (wrong PEM / malformed intermediate).
  // Fail closed rather than emit a leaf missing AKI — such leaves still chain
  // via DN matching but strict path-builders may reject them.
  const interSki = readSubjectKeyIdentifier(template.intermediate);
  if (!interSki) {
    throw new AttestationError(
      "INTERMEDIATE_MISSING_SKI",
      "Intermediate certificate has no SubjectKeyIdentifier extension; cannot construct leaf AKI",
    );
  }
  const akiSeq = new asn1js.Sequence({
    value: [
      new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 0 }, // context-specific [0]
        valueHex: interSki.buffer.slice(
          interSki.byteOffset,
          interSki.byteOffset + interSki.byteLength,
        ) as ArrayBuffer,
      }),
    ],
  });
  cert.extensions.push(
    new pkijs.Extension({
      extnID: OID.authorityKeyIdentifier,
      critical: false,
      extnValue: akiSeq.toBER(false),
    }),
  );

  // CP §7.1.2 leaf extensions, v2 only. All four are non-critical.
  if (template.v2) {
    // certificatePolicies: the c2pa-certificate-policy OID, no qualifiers.
    cert.extensions.push(
      new pkijs.Extension({
        extnID: OID.certificatePolicies,
        critical: false,
        extnValue: new pkijs.CertificatePolicies({
          certificatePolicies: [
            new pkijs.PolicyInformation({
              policyIdentifier: OID.c2paCertPolicy,
            }),
          ],
        }).toSchema().toBER(false),
      }),
    );

    // AIA: OCSP (MUST) + caIssuers (SHOULD), both plain-HTTP URIs per
    // OCSP/AIA convention. GeneralName type 6 = uniformResourceIdentifier.
    cert.extensions.push(
      new pkijs.Extension({
        extnID: OID.authorityInfoAccess,
        critical: false,
        extnValue: new pkijs.InfoAccess({
          accessDescriptions: [
            new pkijs.AccessDescription({
              accessMethod: OID.adOcsp,
              accessLocation: new pkijs.GeneralName({
                type: 6,
                value: template.v2.ocspUrl,
              }),
            }),
            new pkijs.AccessDescription({
              accessMethod: OID.adCaIssuers,
              accessLocation: new pkijs.GeneralName({
                type: 6,
                value: template.v2.caIssuersUrl,
              }),
            }),
          ],
        }).toSchema().toBER(false),
      }),
    );

    // c2pa-al: the granted assurance level, encoded as a bare OBJECT
    // IDENTIFIER (…3.10 = AL1, …3.20 = AL2).
    cert.extensions.push(
      new pkijs.Extension({
        extnID: OID.c2paAssuranceLevel,
        critical: false,
        extnValue: new asn1js.ObjectIdentifier({
          value: template.v2.assuranceLevel === "AL2"
            ? OID.c2paAssuranceLevel2
            : OID.c2paAssuranceLevel1,
        }).toBER(false),
      }),
    );

    // c2pa-cpl-record: UTF8String (SIZE 36) carrying the CPL record UUID.
    // resolveV2LeafOptions validated the shape; re-assert here so a caller
    // constructing V2LeafOptions directly can't mint a malformed record.
    if (!UUID_36.test(template.v2.cplRecordUuid)) {
      throw new AttestationError(
        "LEAF_BUILD_FAILED",
        "v2 cplRecordUuid is not a 36-char UUID",
      );
    }
    cert.extensions.push(
      new pkijs.Extension({
        extnID: OID.c2paCplRecord,
        critical: false,
        extnValue: new asn1js.Utf8String({
          value: template.v2.cplRecordUuid,
        }).toBER(false),
      }),
    );
  }

  return cert;
}

// Extract the keyIdentifier bytes from a cert's SubjectKeyIdentifier
// extension. Returns null if the cert has no SKI extension. The SKI extnValue
// is an OctetString-wrapped OctetString; we unwrap both layers.
function readSubjectKeyIdentifier(cert: pkijs.Certificate): Uint8Array | null {
  const ext = cert.extensions?.find(
    (e: pkijs.Extension) => e.extnID === OID.subjectKeyIdentifier,
  );
  if (!ext) return null;
  // pkijs's Extension stashes the extnValue's raw DER bytes here.
  const innerDer =
    ((ext.extnValue.valueBlock as unknown) as { valueHexView?: Uint8Array })
      .valueHexView;
  if (!innerDer || innerDer.byteLength === 0) return null;
  const ab = innerDer.buffer.slice(
    innerDer.byteOffset,
    innerDer.byteOffset + innerDer.byteLength,
  );
  const parsed = asn1js.fromBER(ab as ArrayBuffer);
  if (parsed.offset === -1) return null;
  const result =
    ((parsed.result.valueBlock as unknown) as { valueHexView?: Uint8Array })
      .valueHexView;
  if (!result) return null;
  return new Uint8Array(result);
}

// DER-encode the leaf's TBSCertificate ready for SHA-256 hashing.
//
// The TBS bytes produced here MUST byte-equal what finalizeLeafPEM re-encodes
// inside the outer Certificate envelope — verifiers reject any
// TBS-vs-signature mismatch. Both call sites go through pkijs's
// `Certificate.encodeTBS()`: here directly, and inside finalizeLeafPEM via
// `leaf.toSchema(true)` (the `true` forces re-encoding from fields rather than
// reading a `tbsView` cache). A full-round-trip test pins this determinism, so
// a pkijs/asn1js upgrade that reorders any TBS field breaks first.
export function encodeTBS(leaf: pkijs.Certificate): Uint8Array {
  const seq = leaf.encodeTBS();
  const ab = seq.toBER(false);
  return new Uint8Array(ab);
}

// Combine the leaf's fields (re-emits the TBS via pkijs's encodeTBS) with the
// externally-produced signature into a finished X.509 cert, returned as PEM.
// The `signatureDer` argument is the raw bytes Cloud KMS returns for
// `ec-sign-p256-sha256` — a DER `Sequence { r INTEGER, s INTEGER }` — which
// is exactly what X.509 signatureValue carries inside its BIT STRING wrapper.
//
// `toSchema(true)` is intentional: pkijs's default (`false`) reads from a
// `tbsView` byte cache that we don't populate, and falls back to a broken
// schema-template path when the cache is empty. The `true` flag forces a
// fresh re-encode through `Certificate.encodeTBS()`.
export function finalizeLeafPEM(
  leaf: pkijs.Certificate,
  signatureDer: Uint8Array,
): string {
  // Copy into a fresh ArrayBuffer so asn1js owns the buffer independent of
  // any subarray slicing in the caller's signatureDer.
  const sigBuf = new ArrayBuffer(signatureDer.byteLength);
  new Uint8Array(sigBuf).set(signatureDer);
  leaf.signatureValue = new asn1js.BitString({ valueHex: sigBuf });

  const certAb = leaf.toSchema(true).toBER(false);
  return derToCertPem(new Uint8Array(certAb));
}

function derToCertPem(der: Uint8Array): string {
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN CERTIFICATE-----\n${
    lines.join("\n")
  }\n-----END CERTIFICATE-----\n`;
}

// --- Chain verification against the RealReel root ----------------------

// Validate that `chainPem` (leaf-first; leaf + intermediate) terminates at the
// supplied RealReel root.
export async function verifyChainToRealReelRoot(
  chainPem: string,
  rootPem: string,
): Promise<void> {
  const certBlocks = chainPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  );
  if (!certBlocks || certBlocks.length === 0) {
    throw new AttestationError(
      "CHAIN_PARSE_FAILED",
      "No CERTIFICATE blocks found in chain PEM",
    );
  }
  const chain: pkijs.Certificate[] = [];
  for (const block of certBlocks) {
    try {
      chain.push(parseCertFromPem(block));
    } catch (e) {
      throw new AttestationError(
        "CHAIN_PARSE_FAILED",
        `Could not parse cert in chain: ${(e as Error).message}`,
      );
    }
  }

  let root: pkijs.Certificate;
  try {
    root = parseCertFromPem(rootPem);
  } catch (e) {
    throw new AttestationError(
      "CHAIN_PARSE_FAILED",
      `Could not parse RealReel root PEM: ${(e as Error).message}`,
    );
  }

  await verifyChainToTrustedRoots(chain, [root]);
}

// --- Leaf issuance orchestrator ----------------------------------------

// Pluggable signer: takes the digest of the leaf's TBSCertificate — SHA-256
// under v1, SHA-384 under v2, matching the declared signatureAlgorithm — and
// returns the DER ECDSA signature (SEQUENCE { r INTEGER, s INTEGER }): the
// exact shape Cloud KMS's `ec-sign-*` returns and the exact shape X.509
// `signatureValue` carries. Pluggable so tests can substitute
// `crypto.subtle.sign` + `p1363ToDer` without hitting real KMS.
export type LeafTbsSigner = (digest: Uint8Array) => Promise<Uint8Array>;

export interface IssueLeafChainOpts {
  // PEM of the RealReel intermediate cert. Its subject is copied into the
  // leaf's issuer; its bytes are appended after the leaf in the returned
  // chain. Caller supplies this from env (REALREEL_INTERMEDIATE_CERT_PEM).
  intermediatePem: string;
  validityDays: number;
  signer: LeafTbsSigner;
  // Present iff issuing against the v2 hierarchy (see LeafTemplate.v2).
  // Also switches the TBS digest handed to `signer` to SHA-384.
  v2?: V2LeafOptions;
}

/**
 * Issued leaf chain + the certificate's serial number, in both raw and
 * canonical-decimal forms.
 *
 * - `pem`: `leaf + intermediate` joined with a newline. Persisted to
 *   `user_signing_keys.leaf_cert_pem` and returned to the client.
 * - `serialDecimal`: the leaf's serial as a positive base-10 integer
 *   string. Matches the form c2pa-rs / c2pa-node expose via
 *   `signature_info.cert_serial_number`, so it's directly comparable
 *   to the verifier's lookup key without conversion.
 * - `serialBytes`: the raw 20-byte minted serial. Surfaced for tests
 *   and observability; production callers should use `serialDecimal`.
 * - `notAfter`: the leaf's expiry Date, read off the issued cert.
 *   Persisted to `user_signing_keys.expires_at` so the verifier's
 *   chain-validity check and the Devices screen's "Expires in X days"
 *   surface share one authoritative value.
 */
export interface IssuedLeafChain {
  pem: string;
  serialDecimal: string;
  serialBytes: Uint8Array;
  notAfter: Date;
}

// One-shot issuance: parses the intermediate, mints a 20-byte serial, builds
// the leaf, hashes the TBS, asks the signer to sign it, finalizes the leaf
// PEM, and returns `leaf + intermediate` joined with a newline plus the serial
// in canonical-decimal form (the verifier lookup keys off cert_serial_number).
//
// Caller owns the CSR (must have already verified its signature + SPKI match
// against the attested public key — this helper does NOT re-check either).
export async function issueLeafChainFromCSR(
  csr: pkijs.CertificationRequest,
  opts: IssueLeafChainOpts,
): Promise<IssuedLeafChain> {
  let intermediate: pkijs.Certificate;
  try {
    intermediate = parseCertFromPem(opts.intermediatePem);
  } catch (e) {
    throw new AttestationError(
      "INTERMEDIATE_PARSE_FAILED",
      `Could not parse RealReel intermediate PEM: ${(e as Error).message}`,
    );
  }

  const serialNumber = new Uint8Array(20);
  crypto.getRandomValues(serialNumber);

  const leaf = await buildLeafCertificate({
    csr,
    intermediate,
    validityDays: opts.validityDays,
    serialNumber,
    v2: opts.v2,
  });

  const tbs = encodeTBS(leaf);
  const digest = opts.v2 ? await sha384(tbs) : await sha256(tbs);
  const signatureDer = await opts.signer(digest);
  const leafPem = finalizeLeafPEM(leaf, signatureDer);

  // Normalize: ensure intermediate has its own trailing newline so concatenation
  // produces a clean two-block chain regardless of how the source PEM was
  // stored (env vars sometimes lose trailing newlines).
  const intermediatePem = opts.intermediatePem.endsWith("\n")
    ? opts.intermediatePem
    : opts.intermediatePem + "\n";

  // Derive the canonical-decimal form of the serial. buildLeafCertificate
  // clears the first byte's high bit for X.509-positive encoding and bumps a
  // zero byte0 to 0x01 for DER-minimal encoding; we mirror both transforms
  // here so the returned value matches what got written into the cert, and
  // matches c2pa-node's signature_info.cert_serial_number byte-for-byte.
  const canonicalSerial = new Uint8Array(serialNumber);
  canonicalSerial[0] = canonicalSerial[0] & 0x7f;
  if (canonicalSerial[0] === 0x00) canonicalSerial[0] = 0x01;
  const serialDecimal = bytesToBigIntDecimal(canonicalSerial);

  // Read notAfter off the issued cert rather than recomputing
  // `now + validityDays * 86_400_000` — buildLeafCertificate is the source
  // of truth (it does the same math + clock-skew backdating of notBefore),
  // and re-deriving here would silently drift if its policy ever changed.
  const notAfter = leaf.notAfter.value;

  return {
    pem: leafPem + intermediatePem,
    serialDecimal,
    serialBytes: canonicalSerial,
    notAfter,
  };
}

// Convert a big-endian unsigned byte array to its canonical-decimal
// string. Matches the form X.509 tools (openssl, c2pa-rs) use to
// display cert serial numbers.
function bytesToBigIntDecimal(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex).toString(10);
}

// Re-export pkijs types for the consumers (apple.ts / android.ts).
export type { Certificate, CertificationRequest } from "npm:pkijs@3.2.4";
export { asn1js, pkijs };
