// Tests for validateAndroidAttestation. Real fixtures live in __fixtures__/.
// One fixture per security level — fixtures are captured from real-device
// enrollment runs.
//
// Run with:
//   make test-ca
// or directly:
//   deno test --allow-read --allow-env ca/_shared/attestation/android_test.ts

import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.221.0/assert/mod.ts";
import {
  enforcePatchGate,
  extractOsPatchLevel,
  selectOsPatchLevel,
  validateAndroidAttestation,
} from "./android.ts";
import { AttestationError, asn1js } from "./pki.ts";
import { ANDROID_PACKAGE_NAME } from "../config.ts";

interface Fixture {
  publicKey: string;
  platform: "android-strongbox" | "android-tee";
  attestation: string; // JSON string of base64-encoded DER cert chain
  keyId: string;
  challenge: string;
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function loadFixture(name: string): Promise<Fixture | null> {
  try {
    const url = new URL(`./__fixtures__/${name}.json`, import.meta.url);
    const text = await Deno.readTextFile(url);
    return JSON.parse(text) as Fixture;
  } catch {
    return null;
  }
}

function expectedSecurityLevel(p: Fixture["platform"]) {
  return p === "android-strongbox" ? "strongbox" : "tee";
}

for (const name of ["android_strongbox", "android_tee"] as const) {
  Deno.test(`Android attestation (${name}) — happy path`, async () => {
    const fix = await loadFixture(name);
    if (!fix) {
      console.warn(`skipping: ${name}.json fixture not present.`);
      return;
    }
    await validateAndroidAttestation({
      certChainBase64: JSON.parse(fix.attestation),
      challenge: base64ToBytes(fix.challenge),
      sePublicKey: base64ToBytes(fix.publicKey),
      packageName: ANDROID_PACKAGE_NAME,
      expectedSecurityLevel: expectedSecurityLevel(fix.platform),
    });
  });

  Deno.test(`Android attestation (${name}) — rejects wrong challenge`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    const wrongChallenge = new Uint8Array(32);
    crypto.getRandomValues(wrongChallenge);
    await assertRejects(
      () =>
        validateAndroidAttestation({
          certChainBase64: JSON.parse(fix.attestation),
          challenge: wrongChallenge,
          sePublicKey: base64ToBytes(fix.publicKey),
          packageName: ANDROID_PACKAGE_NAME,
          expectedSecurityLevel: expectedSecurityLevel(fix.platform),
        }),
      AttestationError,
    );
  });

  Deno.test(`Android attestation (${name}) — rejects wrong public key`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    const wrongKey = base64ToBytes(fix.publicKey);
    wrongKey[wrongKey.length - 1] ^= 0x01;
    await assertRejects(
      () =>
        validateAndroidAttestation({
          certChainBase64: JSON.parse(fix.attestation),
          challenge: base64ToBytes(fix.challenge),
          sePublicKey: wrongKey,
          packageName: ANDROID_PACKAGE_NAME,
          expectedSecurityLevel: expectedSecurityLevel(fix.platform),
        }),
      AttestationError,
    );
  });

  Deno.test(`Android attestation (${name}) — rejects wrong package`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    await assertRejects(
      () =>
        validateAndroidAttestation({
          certChainBase64: JSON.parse(fix.attestation),
          challenge: base64ToBytes(fix.challenge),
          sePublicKey: base64ToBytes(fix.publicKey),
          packageName: "com.attacker.app",
          expectedSecurityLevel: expectedSecurityLevel(fix.platform),
        }),
      AttestationError,
    );
  });

  Deno.test(`Android attestation (${name}) — rejects mismatched security level`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    // Claim the OTHER level than what the fixture actually has.
    const lying = fix.platform === "android-strongbox" ? "tee" : "strongbox";
    if (lying === "tee") {
      // Wrong direction — TEE-claim against StrongBox cert is permitted (TEE
      // is a strict subset of StrongBox security). So flip and try claiming
      // StrongBox against TEE — that should fail.
      // (We only reach this branch from the strongbox fixture, so the test
      // here covers downgrade-claim, which is intentionally allowed.)
      return;
    }
    await assertRejects(
      () =>
        validateAndroidAttestation({
          certChainBase64: JSON.parse(fix.attestation),
          challenge: base64ToBytes(fix.challenge),
          sePublicKey: base64ToBytes(fix.publicKey),
          packageName: ANDROID_PACKAGE_NAME,
          expectedSecurityLevel: lying,
        }),
      AttestationError,
    );
  });

  Deno.test(`Android attestation (${name}) — rejects tampered cert byte`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    const chain = JSON.parse(fix.attestation) as string[];
    // Tamper the first byte of the leaf cert's base64.
    const leafBytes = base64ToBytes(chain[0]);
    leafBytes[Math.floor(leafBytes.length / 2)] ^= 0xff;
    chain[0] = btoa(String.fromCharCode(...leafBytes));
    await assertRejects(
      () =>
        validateAndroidAttestation({
          certChainBase64: chain,
          challenge: base64ToBytes(fix.challenge),
          sePublicKey: base64ToBytes(fix.publicKey),
          packageName: ANDROID_PACKAGE_NAME,
          expectedSecurityLevel: expectedSecurityLevel(fix.platform),
        }),
      AttestationError,
    );
  });
}

Deno.test("Android attestation — constants", () => {
  assertEquals(typeof ANDROID_PACKAGE_NAME, "string");
});

// =====================================================================
// extractOsPatchLevel — enrollment patch-gate parse + normalize
//
// Directly test the AuthorizationList field walker so the gate's
// comparison branch isn't only exercised through the register-signing-key
// stub.
//
// Two wire encodings tested — see extractOsPatchLevel doc-comment:
//   - EXPLICIT (constructed): real KeyMint shape. [706] wraps a Universal
//     INTEGER child. This is the production path that historically slipped
//     past the unit tests, then broke every Android enrollment when the
//     patch-gate landed.
//   - IMPLICIT (primitive): fallback for any future KeyMint that adopts
//     it. Bytes sit directly in the [706] primitive's value block.
//
// The fixture-based validateAndroidAttestation tests above can't reach
// this — fixtures pre-date the patch-gate so we backfilled by adding the
// "real-fixture leaf carries a parseable osPatchLevel" test below.
// =====================================================================

/** Build a minimal pkijs-shaped AuthorizationList containing exactly one
 *  [706] field encoded in the EXPLICIT (constructed) shape that real
 *  KeyMint devices emit: a Constructed context-tagged wrapper around a
 *  Universal INTEGER child. */
function makeAuthListWithPatchLevel(intBytes: number[]): unknown {
  const innerInt = new asn1js.Integer({
    valueHex: new Uint8Array(intBytes).buffer,
  });
  return new asn1js.Sequence({
    value: [
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 706 },
        value: [innerInt],
      }),
    ],
  });
}

/** Build the IMPLICIT (primitive) fallback shape — the original docs-
 *  described wire form. Kept as a separate helper so the fallback branch
 *  in extractOsPatchLevel stays covered. */
function makeAuthListWithPatchLevelImplicit(intBytes: number[]): unknown {
  return new asn1js.Sequence({
    value: [
      new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 706 },
        valueHex: new Uint8Array(intBytes).buffer,
      }),
    ],
  });
}

Deno.test(
  "extractOsPatchLevel — parses YYYYMM (3-byte INTEGER, no leading zero)",
  () => {
    // 202501 (Jan 2025) = 0x031705 = [0x03, 0x17, 0x05]
    const authList = makeAuthListWithPatchLevel([0x03, 0x17, 0x05]);
    assertEquals(extractOsPatchLevel(authList), 202501);
  },
);

Deno.test(
  "extractOsPatchLevel — normalizes YYYYMMDD → YYYYMM (4-byte INTEGER)",
  () => {
    // 20250115 (Jan 15, 2025) = 0x0134FE03 = [0x01, 0x34, 0xFE, 0x03].
    // After YYYYMMDD→YYYYMM normalization: 202501.
    const authList = makeAuthListWithPatchLevel([0x01, 0x34, 0xfe, 0x03]);
    assertEquals(extractOsPatchLevel(authList), 202501);
  },
);

Deno.test(
  "extractOsPatchLevel — out-of-range value (pre-2000) returns null",
  () => {
    // 100001 (Oct 100 AD) — below the [200001, 210012] sanity bound. Returns
    // null so the caller fail-closes treating the field as missing.
    // 100001 = 0x186A1 = [0x01, 0x86, 0xA1]
    const authList = makeAuthListWithPatchLevel([0x01, 0x86, 0xa1]);
    assertEquals(extractOsPatchLevel(authList), null);
  },
);

Deno.test(
  "extractOsPatchLevel — out-of-range value (post-2100) returns null",
  () => {
    // 210101 (Jan 2101) — above the [200001, 210012] sanity bound. Same
    // null-fail behavior as the pre-2000 case. A far-future value also
    // surfaces as "missing" so the caller's fail-closed branch rejects.
    // 210101 = 0x33515 = [0x03, 0x35, 0x15]
    const authList = makeAuthListWithPatchLevel([0x03, 0x35, 0x15]);
    assertEquals(extractOsPatchLevel(authList), null);
  },
);

Deno.test(
  "extractOsPatchLevel — missing [706] tag returns null",
  () => {
    // AuthorizationList containing only some other field — exercises the
    // "no match found" branch of the for-loop.
    const authList = new asn1js.Sequence({
      value: [
        new asn1js.Primitive({
          idBlock: { tagClass: 3, tagNumber: 999 },
          valueHex: new Uint8Array([0x01]).buffer,
        }),
      ],
    });
    assertEquals(extractOsPatchLevel(authList), null);
  },
);

Deno.test(
  "extractOsPatchLevel — null authList returns null (defensive)",
  () => {
    assertEquals(extractOsPatchLevel(null), null);
    assertEquals(extractOsPatchLevel(undefined), null);
  },
);

Deno.test(
  "extractOsPatchLevel — IMPLICIT (primitive) fallback shape still parses",
  () => {
    // Regression guard for the forward-compat fallback branch: any future
    // KeyMint version that emits [706] as an IMPLICIT primitive (raw
    // INTEGER bytes directly in the context-tagged value block) must
    // still parse. EXPLICIT-constructed is the only shape observed in the
    // field today, but the fallback exists so a one-off KeyMint variant
    // doesn't take down enrollment until we ship a fix.
    const authList = makeAuthListWithPatchLevelImplicit([0x03, 0x17, 0x05]);
    assertEquals(extractOsPatchLevel(authList), 202501);
  },
);

Deno.test(
  "validateAndroidAttestation — real fixture leaf carries parseable osPatchLevel (patch-gate regression)",
  async () => {
    // Regression guard for the patch-gate-rejected-every-real-Android-
    // enrollment bug. The synthetic extractOsPatchLevel tests above
    // can't catch a shape mismatch between our parser and what pkijs
    // returns from a real DER — they construct nodes that may not
    // reproduce the EXPLICIT-constructed wire form.
    //
    // Routes through the public validator entry point (not a private
    // walker re-implemented in the test) so the next KeyMint variant
    // exercises the exact production path. minOsPatchLevel = 200001
    // is a floor below any conceivable real patch level: if
    // extractOsPatchLevel returns the real value the gate passes
    // trivially; if a future regression returns null again the
    // null-fail-closed branch throws ATTESTATION_STALE_PATCH and the
    // test fails — same behavior as the bug we just shipped a fix for.
    const fix = await loadFixture("android_strongbox");
    if (!fix) return; // fixture absent → not a regression
    await validateAndroidAttestation({
      certChainBase64: JSON.parse(fix.attestation),
      challenge: base64ToBytes(fix.challenge),
      sePublicKey: base64ToBytes(fix.publicKey),
      packageName: ANDROID_PACKAGE_NAME,
      expectedSecurityLevel: "strongbox",
      minOsPatchLevel: 200001,
    });
  },
);

// =====================================================================
// validateAndroidAttestation — patch-gate branch
//
// One end-to-end check that the threshold comparison + fail-closed null
// branch actually fire from the public validator entry point. Fixtures
// don't carry osPatchLevel, so we exercise the gate by checking the
// helper directly above; here we just pin that minOsPatchLevel survives
// the option-passing without crashing the validator on missing fixtures.
// (Real chain rejection is unreachable without a fixture; this test
// guards against a TypeScript-only regression that dropped the option.)
// =====================================================================

// =====================================================================
// selectOsPatchLevel — hardware-vs-software preference convention
// =====================================================================

Deno.test(
  "selectOsPatchLevel — prefers hardwareEnforced when both lists carry the tag",
  () => {
    // hardware=202501, software=202301. KeyMint v3+ mandates the tag in
    // hardwareEnforced; the preference order pins that we use that value
    // even when softwareEnforced also has one (e.g. a transition-era
    // device emitting both).
    const hardware = makeAuthListWithPatchLevel([0x03, 0x17, 0x05]); // 202501
    const software = makeAuthListWithPatchLevel([0x03, 0x16, 0x6d]); // 202301
    assertEquals(selectOsPatchLevel(hardware, software), 202501);
  },
);

Deno.test(
  "selectOsPatchLevel — falls back to softwareEnforced when hardware is absent",
  () => {
    // Older Keymaster v2 attestations carry the tag only in
    // softwareEnforced. We MUST still find it there, otherwise
    // legacy-fleet devices would all hit the null-fail-closed branch.
    const emptyHardware = new asn1js.Sequence({ value: [] });
    const software = makeAuthListWithPatchLevel([0x03, 0x17, 0x05]);
    assertEquals(selectOsPatchLevel(emptyHardware, software), 202501);
  },
);

Deno.test(
  "selectOsPatchLevel — returns null when neither list carries the tag",
  () => {
    const emptyHardware = new asn1js.Sequence({ value: [] });
    const emptySoftware = new asn1js.Sequence({ value: [] });
    assertEquals(selectOsPatchLevel(emptyHardware, emptySoftware), null);
  },
);

Deno.test(
  "selectOsPatchLevel — out-of-range hardware value falls through to valid software value",
  () => {
    // A malformed leaf could carry an out-of-range value in
    // hardwareEnforced (extractOsPatchLevel returns null on values
    // outside [200001, 210012]) while softwareEnforced has a
    // well-formed legacy entry. The ?? fallback must walk past the
    // null and pick up the software value. Without this, a
    // transition-era device with a corrupt hardware tag would
    // false-reject even though its legacy entry meets the threshold.
    // 999999 = 0xF423F = [0x0F, 0x42, 0x3F] — above the 210012 ceiling.
    const corruptHardware = makeAuthListWithPatchLevel([0x0f, 0x42, 0x3f]);
    const validSoftware = makeAuthListWithPatchLevel([0x03, 0x17, 0x05]); // 202501
    assertEquals(selectOsPatchLevel(corruptHardware, validSoftware), 202501);
  },
);

// =====================================================================
// enforcePatchGate — threshold comparison + null-fail-closed
//
// Pins the comparison rule that validateAndroidAttestation delegates to.
// Round-1 review caught that the threshold logic was only stub-tested
// at the handler level; this exercises it directly.
// =====================================================================

Deno.test("enforcePatchGate — undefined threshold passes through (iOS path)", () => {
  // iOS validators omit minOsPatchLevel entirely — the gate must no-op.
  // This is the only path that doesn't reject when osPatchLevel is null.
  enforcePatchGate(null, undefined);
  enforcePatchGate(202501, undefined);
});

Deno.test("enforcePatchGate — strict < accepts the boundary case", () => {
  // osPatchLevel === minOsPatchLevel must NOT throw. A future tightening
  // to `<=` would shift the gate by one month and break this test —
  // intentional canary. A device patched exactly minOsPatchLevel months
  // ago (boundary case) is ACCEPTED.
  enforcePatchGate(202505, 202505);
});

Deno.test("enforcePatchGate — one month below threshold rejects", () => {
  assertThrows(
    () => enforcePatchGate(202504, 202505),
    AttestationError,
    "osPatchLevel 202504 < required 202505",
  );
});

Deno.test("enforcePatchGate — null osPatchLevel with threshold set fails closed", () => {
  // Missing TAG_OS_PATCH_LEVEL on a leaf where the operator asked for
  // a gate → reject. The validator can't prove the device meets the
  // threshold, so refusing to enroll is the only safe answer.
  assertThrows(
    () => enforcePatchGate(null, 202505),
    AttestationError,
    "leaf cert has no osPatchLevel",
  );
});

Deno.test(
  "validateAndroidAttestation — accepts minOsPatchLevel opt without fixture",
  async () => {
    // Validator throws ATTESTATION_DECODE_FAILED on the empty/short chain
    // BEFORE reaching the patch-gate; assert that. The point of this test
    // is that adding the option doesn't shift behavior on the pre-gate
    // failure modes — a regression that broke the option's plumbing
    // would surface as a TypeScript error or a different code here.
    await assertRejects(
      () =>
        validateAndroidAttestation({
          certChainBase64: [],
          challenge: new Uint8Array(32),
          sePublicKey: new Uint8Array(65),
          packageName: ANDROID_PACKAGE_NAME,
          expectedSecurityLevel: "strongbox",
          minOsPatchLevel: 202505,
        }),
      AttestationError,
      "expected cert chain",
    );
  },
);
