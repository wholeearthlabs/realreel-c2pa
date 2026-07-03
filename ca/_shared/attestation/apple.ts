// Apple App Attest validation.
//
// Implements the steps from "Validating Apps That Connect to Your Server":
//   https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
//
// Each step in validateAppleAttestation() maps directly to the numbered step
// in Apple's spec — keep them aligned for ease of audit.

// deno-lint-ignore-file no-explicit-any
import * as cbor from "npm:cbor-x@1.5.9";
import {
  AttestationError,
  bytesToBase64,
  concat,
  ctEqual,
  describeCertChain,
  extractSubjectPublicKeyBytes,
  findExtensionByOid,
  parseCertFromDer,
  parseCertFromPem,
  sha256,
  verifyChainToTrustedRoots,
} from "./pki.ts";
import type { Certificate } from "./pki.ts";
import { APPLE_APPATTEST_ROOT_PEM } from "./roots.ts";
import { asn1js } from "./pki.ts";

// Lazy-init the parsed root cert; PEM parsing is non-trivial work to do per
// request and the value is constant for the lifetime of the process.
let _appleRoot: Certificate | null = null;
function appleRoot(): Certificate {
  if (!_appleRoot) _appleRoot = parseCertFromPem(APPLE_APPATTEST_ROOT_PEM);
  return _appleRoot;
}

// OIDs from Apple's spec.
const OID_APPLE_APPATTEST_NONCE = "1.2.840.113635.100.8.2";

// Production AAGUID is the ASCII bytes "appattest" + 7 NUL bytes (16 total).
// Development AAGUID is "appattestdevelop" exactly (16 ASCII bytes).
const AAGUID_PRODUCTION = new Uint8Array([
  0x61,
  0x70,
  0x70,
  0x61,
  0x74,
  0x74,
  0x65,
  0x73,
  0x74,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
  0x00,
]);
const AAGUID_DEVELOPMENT = new Uint8Array([
  0x61,
  0x70,
  0x70,
  0x61,
  0x74,
  0x74,
  0x65,
  0x73,
  0x74,
  0x64,
  0x65,
  0x76,
  0x65,
  0x6c,
  0x6f,
  0x70,
]);

export interface ValidateAppleAttestationOpts {
  // Raw bytes of the App Attest CBOR object (i.e. base64-decoded `attestation`
  // string from the client).
  attestation: Uint8Array;
  // Server-issued challenge bytes (raw, not base64).
  challenge: Uint8Array;
  // base64 keyId returned by the client (= base64 of SHA-256 over the credCert
  // public key per Apple's spec).
  keyId: string;
  // SPKI DER bytes of the SE signing key the client wants to register. The
  // attestation binds this to the App Attest key via clientDataHash.
  sePublicKey: Uint8Array;
  // Our App ID — formatted as "<TeamID>.<BundleID>" per Apple's spec. The
  // rpIdHash field of authData is SHA-256 of this concatenated string. NOT
  // just the bundle identifier.
  appId: string;
  // If true, reject the development environment AAGUID. Set true in prod.
  requireProduction: boolean;
  // TEST-ONLY override for the chain validity-window checks (fixture certs
  // age out). See verifyChainToTrustedRoots. Production omits.
  validationTime?: Date;
}

interface AuthData {
  rpIdHash: Uint8Array;
  flags: number;
  counter: number;
  aaguid: Uint8Array;
  credentialId: Uint8Array;
  credentialPublicKey: Uint8Array;
}

/**
 * The verifier needs the credCert's public key to check Apple's ECDSA
 * signature on each upload-time assertion. We extract it here at enrollment
 * time and surface it to the caller, which persists it on
 * user_signing_keys.app_attest_public_key.
 *
 * Apple's spec hashes the bare BIT STRING contents (X9.63 0x04||X||Y for EC
 * keys), so the bytes returned here are the same form
 * extractSubjectPublicKeyBytes produces for the keyId comparison in Step 4.
 */
export interface ValidateAppleAttestationResult {
  credCertPublicKey: Uint8Array;
}

// Throws AttestationError on any spec violation. Resolves with the credCert
// public-key bytes on success.
export async function validateAppleAttestation(
  opts: ValidateAppleAttestationOpts,
): Promise<ValidateAppleAttestationResult> {
  // === Step 0: decode CBOR ===
  let obj: any;
  try {
    obj = cbor.decode(opts.attestation);
  } catch (e) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      `cbor decode failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (typeof obj !== "object" || obj === null) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      "attestation root is not an object",
    );
  }

  if (obj.fmt !== "apple-appattest") {
    throw new AttestationError(
      "WRONG_FORMAT",
      `expected fmt=apple-appattest, got ${String(obj.fmt)}`,
    );
  }

  const attStmt = obj.attStmt;
  const authData: Uint8Array = obj.authData instanceof Uint8Array
    ? obj.authData
    : new Uint8Array(obj.authData ?? []);
  if (!authData.length) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      "missing authData",
    );
  }
  if (!attStmt || !Array.isArray(attStmt.x5c) || attStmt.x5c.length < 2) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      "missing or short x5c",
    );
  }

  // === Step 1: parse + verify cert chain to Apple root ===
  const chainBytes: Uint8Array[] = attStmt.x5c.map((c: any) =>
    c instanceof Uint8Array ? c : new Uint8Array(c)
  );
  let chain: ReturnType<typeof parseCertFromDer>[];
  try {
    chain = chainBytes.map(parseCertFromDer);
  } catch (e) {
    throw new AttestationError(
      "CERT_PARSE_FAILED",
      e instanceof Error ? e.message : String(e),
    );
  }
  await verifyChainToTrustedRoots(chain, [appleRoot()], opts.validationTime)
    .catch((e) => {
      throw new AttestationError(
        "CHAIN_INVALID",
        `${e instanceof Error ? e.message : String(e)}; presented chain: ${
          describeCertChain(chain)
        }`,
      );
    });

  const credCert = chain[0];

  // === Step 2: reconstruct nonce = SHA-256(authData || clientDataHash) ===
  // where clientDataHash = SHA-256(challenge || sePublicKey)
  const clientDataHash = await sha256(concat(opts.challenge, opts.sePublicKey));
  const expectedNonce = await sha256(concat(authData, clientDataHash));

  // === Step 3: extract Apple-specific nonce extension from credCert ===
  // The extension is OID 1.2.840.113635.100.8.2 and its value is an OCTET
  // STRING wrapping a SEQUENCE containing a context-tagged [1] OCTET STRING
  // of the nonce.
  const extBytes = findExtensionByOid(credCert, OID_APPLE_APPATTEST_NONCE);
  if (!extBytes) {
    throw new AttestationError(
      "NONCE_EXTENSION_MISSING",
      "credCert does not have the Apple App Attest nonce extension",
    );
  }
  const embeddedNonce = parseAppleNonceExtension(extBytes);
  if (!ctEqual(embeddedNonce, expectedNonce)) {
    throw new AttestationError(
      "NONCE_MISMATCH",
      "embedded nonce does not match SHA-256(authData || clientDataHash)",
    );
  }

  // === Step 4: keyId === base64(SHA-256(credCert subject public key bytes)) ===
  // Note: Apple's spec hashes the bare BIT STRING contents (X9.63 0x04||X||Y
  // for EC keys), NOT the full SubjectPublicKeyInfo. This intentionally
  // differs from android.ts's leaf-cert public-key check, which compares the
  // full SPKI DER. Don't try to "unify" them — each matches its respective
  // platform's spec.
  const credPubKeyRaw = extractSubjectPublicKeyBytes(credCert);
  const credPubKeyHash = await sha256(credPubKeyRaw);
  if (bytesToBase64(credPubKeyHash) !== opts.keyId) {
    throw new AttestationError(
      "KEY_ID_MISMATCH",
      "keyId does not match SHA-256 of credCert public key",
    );
  }

  // === Step 5: parse authData fields ===
  const ad = parseAuthData(authData);

  // === Step 6: rpIdHash === SHA-256(appId) where appId = "<TeamID>.<BundleID>" ===
  const expectedRpIdHash = await sha256(
    new TextEncoder().encode(opts.appId),
  );
  if (!ctEqual(ad.rpIdHash, expectedRpIdHash)) {
    throw new AttestationError(
      "RP_ID_MISMATCH",
      "rpIdHash does not match SHA-256 of appId",
    );
  }

  // === Step 7: counter === 0 (initial attestation) ===
  if (ad.counter !== 0) {
    throw new AttestationError(
      "COUNTER_NONZERO",
      `expected counter=0, got ${ad.counter}`,
    );
  }

  // === Step 8: AAGUID is production (or dev, if !requireProduction) ===
  const isProduction = ctEqual(ad.aaguid, AAGUID_PRODUCTION);
  const isDevelopment = ctEqual(ad.aaguid, AAGUID_DEVELOPMENT);
  if (!isProduction && !isDevelopment) {
    throw new AttestationError(
      "AAGUID_UNKNOWN",
      "aaguid is neither 'appattest' nor 'appattestdevelop'",
    );
  }
  if (opts.requireProduction && !isProduction) {
    throw new AttestationError(
      "AAGUID_NOT_PRODUCTION",
      "production-mode required, but attestation has development aaguid",
    );
  }

  // === Step 9: credentialId === keyId ===
  if (bytesToBase64(ad.credentialId) !== opts.keyId) {
    throw new AttestationError(
      "CREDENTIAL_ID_MISMATCH",
      "credentialId in authData does not match keyId",
    );
  }

  // All checks passed. Return credCert's X9.63 uncompressed pubkey (extracted
  // in Step 4) so the caller can persist it for upload-time signature checks.
  return { credCertPublicKey: credPubKeyRaw };
}

// Parses the value of the Apple App Attest nonce extension. Per Apple's
// "Validating Apps That Connect to Your Server", the extnValue is:
//
//   SEQUENCE {
//     [1] EXPLICIT OCTET STRING nonce  -- 32 bytes
//   }
//
// pkijs already strips the outer X.509 OCTET-STRING wrapper around extnValue,
// so the bytes we receive start at the inner SEQUENCE. We walk the structure
// deterministically (rather than "find any 32-byte OCTET STRING") so a
// malformed extension can't steer the parser.
function parseAppleNonceExtension(extValue: Uint8Array): Uint8Array {
  const ab = extValue.buffer.slice(
    extValue.byteOffset,
    extValue.byteOffset + extValue.byteLength,
  ) as ArrayBuffer;
  const outer = asn1js.fromBER(ab);
  if (outer.offset === -1) {
    throw new AttestationError(
      "NONCE_EXTENSION_INVALID",
      "could not ASN.1-decode the nonce extension",
    );
  }

  // Outer must be a universal SEQUENCE (tagClass=1, tagNumber=16).
  const seq = outer.result as any;
  if (seq?.idBlock?.tagClass !== 1 || seq?.idBlock?.tagNumber !== 16) {
    throw new AttestationError(
      "NONCE_EXTENSION_INVALID",
      "expected outer SEQUENCE in nonce extension",
    );
  }

  // Inside the SEQUENCE, find the [1] context-tagged element (tagClass=3,
  // tagNumber=1). EXPLICIT tagging means its single child is the OCTET STRING.
  const seqChildren = seq.valueBlock?.value as any[] | undefined;
  if (!Array.isArray(seqChildren)) {
    throw new AttestationError(
      "NONCE_EXTENSION_INVALID",
      "nonce SEQUENCE has no children",
    );
  }
  const tagged = seqChildren.find((c) =>
    c?.idBlock?.tagClass === 3 && c?.idBlock?.tagNumber === 1
  );
  if (!tagged) {
    throw new AttestationError(
      "NONCE_EXTENSION_INVALID",
      "missing [1] EXPLICIT element in nonce SEQUENCE",
    );
  }

  // EXPLICIT tagging in pkijs lands the inner OCTET STRING as a child of the
  // tagged constructed node.
  const inner = tagged.valueBlock?.value as any[] | undefined;
  const octet = Array.isArray(inner) ? inner[0] : tagged;
  if (octet?.idBlock?.tagClass !== 1 || octet?.idBlock?.tagNumber !== 4) {
    throw new AttestationError(
      "NONCE_EXTENSION_INVALID",
      "expected OCTET STRING inside [1] tag",
    );
  }

  const hexView = octet.valueBlock?.valueHexView as Uint8Array | undefined;
  const hexAb = octet.valueBlock?.valueHex as ArrayBuffer | undefined;
  const bytes = hexView
    ? new Uint8Array(hexView)
    : hexAb
    ? new Uint8Array(hexAb)
    : null;
  if (!bytes || bytes.length !== 32) {
    throw new AttestationError(
      "NONCE_EXTENSION_INVALID",
      `nonce OCTET STRING is ${bytes?.length ?? "missing"} bytes; expected 32`,
    );
  }
  return bytes;
}

// Parses the WebAuthn-style authData byte layout used by App Attest:
//   rpIdHash:           32 bytes
//   flags:               1 byte
//   counter:             4 bytes (big-endian uint32)
//   aaguid:             16 bytes
//   credentialIdLength:  2 bytes (big-endian uint16)
//   credentialId:       <credentialIdLength> bytes
//   credentialPublicKey: COSE key (CBOR-encoded; rest of buffer)
function parseAuthData(authData: Uint8Array): AuthData {
  if (authData.length < 37) {
    throw new AttestationError("AUTH_DATA_TRUNCATED", "authData < 37 bytes");
  }
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const counter = (authData[33] << 24) |
    (authData[34] << 16) |
    (authData[35] << 8) |
    authData[36];

  // Attested credential data section starts at byte 37 when flag bit 6 (AT) is set.
  if (!(flags & 0x40)) {
    throw new AttestationError(
      "AUTH_DATA_NO_ATTESTED_CRED",
      "AT flag not set in authData",
    );
  }
  if (authData.length < 55) {
    throw new AttestationError(
      "AUTH_DATA_TRUNCATED",
      "authData truncated before credential data",
    );
  }
  const aaguid = authData.slice(37, 53);
  const credIdLen = (authData[53] << 8) | authData[54];
  if (authData.length < 55 + credIdLen) {
    throw new AttestationError(
      "AUTH_DATA_TRUNCATED",
      "authData truncated within credentialId",
    );
  }
  const credentialId = authData.slice(55, 55 + credIdLen);
  const credentialPublicKey = authData.slice(55 + credIdLen);

  return {
    rpIdHash,
    flags,
    counter: counter >>> 0,
    aaguid,
    credentialId,
    credentialPublicKey,
  };
}
