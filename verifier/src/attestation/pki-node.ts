// Crypto primitives for the Node-side Stage-2 App Attest validator.
//
// Independent of ca/_shared/attestation/pki.ts, which is
// Deno-only (pkijs + asn1js). The verifier runs in Node 22 / Cloud Run and
// uses node:crypto instead. Only the Stage-2 validator's primitives live
// here — it never re-parses the cert chain (full ASN.1 parsing stays on the
// enrollment side); it consumes the pre-extracted App Attest public key the
// enrollment validator stored in user_signing_keys.app_attest_public_key.

import { Buffer } from "node:buffer";
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import { webcrypto } from "node:crypto";

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await webcrypto.subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time byte comparison. Returns true iff equal. */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Build a node:crypto KeyObject for an X9.63 uncompressed P-256 public
 * key. Apple's App Attest credCert exposes its public key as a 65-byte
 * uncompressed point (0x04 || X(32) || Y(32)), which we extract once at
 * enrollment time and persist in user_signing_keys.app_attest_public_key.
 *
 * Node has no `format: "raw"` import in createPublicKey, so we route the
 * raw bytes through JWK (the only built-in import that accepts an
 * uncompressed-point representation without an SPKI envelope).
 *
 * Throws if the input isn't a valid P-256 uncompressed point.
 */
export function importP256RawPubkey(raw: Uint8Array): KeyObject {
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error(
      `expected 65-byte uncompressed P-256 point (0x04 || X || Y); got ${raw.length} bytes, leading byte 0x${(raw[0] ?? 0).toString(16)}`,
    );
  }
  const x = raw.subarray(1, 33);
  const y = raw.subarray(33, 65);
  return createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: base64UrlNoPad(x),
      y: base64UrlNoPad(y),
    },
    format: "jwk",
  });
}

/**
 * Verify an ECDSA-P256-SHA256 signature in DER form (`SEQUENCE { r, s }`).
 * The Apple App Attest assertion's "signature" CBOR field is exactly this
 * encoding. Returns true on success, false on mismatch.
 *
 * Note: node:crypto.verify accepts the DER encoding directly when the
 * `dsaEncoding` option is omitted (the default is `'der'` for EC keys).
 * Throwing exceptions from .verify() bubble up — invalid SPKI / bad DER
 * surface as Error, distinct from a clean false-return mismatch.
 */
export function verifyEcdsaP256Sha256(
  data: Uint8Array,
  signatureDer: Uint8Array,
  pubkey: KeyObject,
): boolean {
  return verify(
    "sha256",
    Buffer.from(data),
    pubkey,
    Buffer.from(signatureDer),
  );
}

function base64UrlNoPad(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}
