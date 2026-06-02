// Tests for validateAppleAttestation. Real fixtures live in __fixtures__/.
// Each test loads a fixture, calls the validator, asserts expected outcome.
//
// Run with:
//   make test-ca
// or directly:
//   deno test --allow-read --allow-env ca/_shared/attestation/apple_test.ts
//
// Fixture format: a JSON file with the exact shape of register-signing-key's
// request body (publicKey, platform, attestation, keyId, challenge, ...).

import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.221.0/assert/mod.ts";
import { validateAppleAttestation } from "./apple.ts";
import { AttestationError } from "./pki.ts";
import { APPLE_APP_ID } from "../config.ts";

const FIXTURE_PATH = new URL(
  "./__fixtures__/ios_production.json",
  import.meta.url,
);

interface Fixture {
  publicKey: string; // base64 SPKI
  platform: "ios";
  attestation: string; // base64 CBOR
  keyId: string;
  challenge: string; // base64
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function loadFixture(): Promise<Fixture | null> {
  try {
    const text = await Deno.readTextFile(FIXTURE_PATH);
    return JSON.parse(text) as Fixture;
  } catch {
    return null;
  }
}

Deno.test("Apple attestation — happy path", async () => {
  const fix = await loadFixture();
  if (!fix) {
    console.warn(
      "skipping: ios_production.json fixture not present. Capture one via the dev smoke screen.",
    );
    return;
  }
  await validateAppleAttestation({
    attestation: base64ToBytes(fix.attestation),
    challenge: base64ToBytes(fix.challenge),
    keyId: fix.keyId,
    sePublicKey: base64ToBytes(fix.publicKey),
    appId: APPLE_APP_ID,
    requireProduction: true,
  });
});

Deno.test("Apple attestation — rejects wrong challenge", async () => {
  const fix = await loadFixture();
  if (!fix) return;
  const wrongChallenge = new Uint8Array(32);
  crypto.getRandomValues(wrongChallenge);
  await assertRejects(
    () =>
      validateAppleAttestation({
        attestation: base64ToBytes(fix.attestation),
        challenge: wrongChallenge,
        keyId: fix.keyId,
        sePublicKey: base64ToBytes(fix.publicKey),
        appId: APPLE_APP_ID,
        requireProduction: true,
      }),
    AttestationError,
  );
});

Deno.test("Apple attestation — rejects tampered attestation bytes", async () => {
  const fix = await loadFixture();
  if (!fix) return;
  const att = base64ToBytes(fix.attestation);
  // Flip many bytes scattered through the CBOR. A single byte flip can land
  // in an unvalidated field (e.g. attStmt.receipt) and slip through; flipping
  // every 200th byte across the whole blob guarantees one lands inside x5c
  // or authData and one of our spec-step checks (cert chain, nonce, keyId,
  // rpIdHash, credentialId) catches it.
  for (let i = 100; i < att.length; i += 200) att[i] ^= 0xff;
  await assertRejects(
    () =>
      validateAppleAttestation({
        attestation: att,
        challenge: base64ToBytes(fix.challenge),
        keyId: fix.keyId,
        sePublicKey: base64ToBytes(fix.publicKey),
        appId: APPLE_APP_ID,
        requireProduction: true,
      }),
    AttestationError,
  );
});

Deno.test("Apple attestation — rejects wrong public key", async () => {
  const fix = await loadFixture();
  if (!fix) return;
  const wrongKey = new Uint8Array(base64ToBytes(fix.publicKey));
  wrongKey[wrongKey.length - 1] ^= 0x01;
  await assertRejects(
    () =>
      validateAppleAttestation({
        attestation: base64ToBytes(fix.attestation),
        challenge: base64ToBytes(fix.challenge),
        keyId: fix.keyId,
        sePublicKey: wrongKey,
        appId: APPLE_APP_ID,
        requireProduction: true,
      }),
    AttestationError,
  );
});

Deno.test("Apple attestation — rejects wrong appId", async () => {
  const fix = await loadFixture();
  if (!fix) return;
  await assertRejects(
    () =>
      validateAppleAttestation({
        attestation: base64ToBytes(fix.attestation),
        challenge: base64ToBytes(fix.challenge),
        keyId: fix.keyId,
        sePublicKey: base64ToBytes(fix.publicKey),
        appId: "ATTACKER123.com.attacker.app",
        requireProduction: true,
      }),
    AttestationError,
  );
});

Deno.test("Apple attestation — rejects wrong keyId", async () => {
  const fix = await loadFixture();
  if (!fix) return;
  await assertRejects(
    () =>
      validateAppleAttestation({
        attestation: base64ToBytes(fix.attestation),
        challenge: base64ToBytes(fix.challenge),
        keyId: fix.keyId + "x",
        sePublicKey: base64ToBytes(fix.publicKey),
        appId: APPLE_APP_ID,
        requireProduction: true,
      }),
    AttestationError,
  );
});

// Sanity check: assert constants line up. Doesn't need a fixture.
Deno.test("Apple attestation — constants", () => {
  assertEquals(APPLE_APP_ID.includes("."), true);
});
