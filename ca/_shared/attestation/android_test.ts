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
  assertStringIncludes,
  assertThrows,
} from "std/assert/mod.ts";
import {
  type Al2EvidenceOpts,
  enforceAl2Evidence,
  extractAttestationApplicationId,
  extractDayPatchLevel,
  extractOsPatchLevel,
  extractRootOfTrust,
  type KeyDescription,
  readTaggedInt,
  readTaggedIntSet,
  validateAndroidAttestation,
  type ValidateAndroidAttestationOpts,
} from "./android.ts";
import type { AndroidRevocationList } from "./android_revocation.ts";
import { asn1js, AttestationError } from "./pki.ts";
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

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
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

// RKP-provisioned chains carry ~2-week batch certs (the committed strongbox
// fixture's batch cert is valid 2026-04-30..2026-05-13), so the fixture ages
// out of its own validity window almost immediately. Pin validation to a
// moment inside the capture window; production callers validate at "now"
// against the freshly provisioned chain the device presents at enrollment.
const FIXTURE_VALIDATION_TIME = new Date("2026-05-05T12:00:00Z");

// The committed strongbox fixture's attestationApplicationId signing digest.
const FIXTURE_SIGNING_CERT_SHA256 = hexToBytes(
  "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c",
);
// Serials from the same chain in the revocation list's form (lowercase hex,
// no leading zeros). The intermediate's DER content octets start with 0x00.
const FIXTURE_LEAF_SERIAL = "1";
const FIXTURE_INTERMEDIATE_SERIAL = "924250191903e3ba65320efd6a2085fb";

const NO_REVOCATIONS: AndroidRevocationList = new Map();

function fixtureOpts(
  fix: Fixture,
  over: Partial<ValidateAndroidAttestationOpts> = {},
): ValidateAndroidAttestationOpts {
  return {
    certChainBase64: JSON.parse(fix.attestation),
    validationTime: FIXTURE_VALIDATION_TIME,
    challenge: base64ToBytes(fix.challenge),
    sePublicKey: base64ToBytes(fix.publicKey),
    packageName: ANDROID_PACKAGE_NAME,
    expectedSecurityLevel: expectedSecurityLevel(fix.platform),
    signingCertSha256Digests: [FIXTURE_SIGNING_CERT_SHA256],
    revokedSerials: NO_REVOCATIONS,
    ...over,
  };
}

for (const name of ["android_strongbox", "android_tee"] as const) {
  Deno.test(`Android attestation (${name}) — happy path`, async () => {
    const fix = await loadFixture(name);
    if (!fix) {
      console.warn(`skipping: ${name}.json fixture not present.`);
      return;
    }
    await validateAndroidAttestation(fixtureOpts(fix));
  });

  Deno.test(`Android attestation (${name}) — rejects wrong challenge`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    const wrongChallenge = new Uint8Array(32);
    crypto.getRandomValues(wrongChallenge);
    await assertRejects(
      () =>
        validateAndroidAttestation(
          fixtureOpts(fix, { challenge: wrongChallenge }),
        ),
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
        validateAndroidAttestation(fixtureOpts(fix, { sePublicKey: wrongKey })),
      AttestationError,
    );
  });

  Deno.test(`Android attestation (${name}) — rejects wrong package`, async () => {
    const fix = await loadFixture(name);
    if (!fix) return;
    await assertRejects(
      () =>
        validateAndroidAttestation(
          fixtureOpts(fix, { packageName: "com.attacker.app" }),
        ),
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
        validateAndroidAttestation(
          fixtureOpts(fix, { expectedSecurityLevel: lying }),
        ),
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
        validateAndroidAttestation(
          fixtureOpts(fix, { certChainBase64: chain }),
        ),
      AttestationError,
    );
  });
}

Deno.test(
  "Android attestation — rejects leaf with forged signature (chain-order regression)",
  async () => {
    // Regression guard for the pkijs ordering bug: the engine treats
    // certs[LAST] as the validation target, so passing the chain leaf-first
    // meant only the top link was ever signature-checked — a leaf with a
    // garbage signature but an intact TBS (correct challenge, package name,
    // and attacker-chosen public key) grafted onto a real device's
    // intermediates enrolled successfully. Corrupt ONLY the trailing
    // signature bytes so every post-chain validation step still passes;
    // link-by-link chain verification is the only check that can reject it.
    const fix = await loadFixture("android_strongbox");
    if (!fix) return;
    const chain = JSON.parse(fix.attestation) as string[];
    const leaf = base64ToBytes(chain[0]);
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    // signatureValue BIT STRING } — the signature is the last field, so
    // flipping the final byte corrupts it without touching the TBS.
    leaf[leaf.length - 1] ^= 0xff;
    chain[0] = btoa(String.fromCharCode(...leaf));
    const err = await assertRejects(
      () =>
        validateAndroidAttestation(
          fixtureOpts(fix, { certChainBase64: chain }),
        ),
      AttestationError,
    );
    assertEquals((err as AttestationError).code, "CHAIN_INVALID");
  },
);

Deno.test("Android attestation — constants", () => {
  assertEquals(typeof ANDROID_PACKAGE_NAME, "string");
});

// =====================================================================
// validateAndroidAttestation — A.3.1 rows and the revocation list against
// the real strongbox chain. Patch-currency rows can't be aged out here
// (the chain's own validity window is two weeks); enforceAl2Evidence covers
// them below with synthetic KeyDescriptions.
// =====================================================================

Deno.test("validateAndroidAttestation — rejects a signing-cert digest that isn't registered", async () => {
  const fix = await loadFixture("android_strongbox");
  if (!fix) return;
  const err = await assertRejects(
    () =>
      validateAndroidAttestation(
        fixtureOpts(fix, {
          signingCertSha256Digests: [new Uint8Array(32).fill(0xbb)],
        }),
      ),
    AttestationError,
  );
  assertEquals(err.code, "AL2_EVIDENCE_FAILED");
  assertStringIncludes(err.message, "AL2_APP_SIGNING_CERT_MISMATCH");
});

Deno.test("validateAndroidAttestation — rejects with no registered signing-cert digests", async () => {
  const fix = await loadFixture("android_strongbox");
  if (!fix) return;
  const err = await assertRejects(
    () =>
      validateAndroidAttestation(
        fixtureOpts(fix, { signingCertSha256Digests: [] }),
      ),
    AttestationError,
  );
  assertEquals(err.code, "AL2_EVIDENCE_FAILED");
});

Deno.test("validateAndroidAttestation — app version floor: at the floor passes, above it rejects", async () => {
  const fix = await loadFixture("android_strongbox");
  if (!fix) return;
  // The fixture attests versionCode 1.
  await validateAndroidAttestation(fixtureOpts(fix, { minAppVersionCode: 1 }));
  const err = await assertRejects(
    () =>
      validateAndroidAttestation(fixtureOpts(fix, { minAppVersionCode: 2 })),
    AttestationError,
  );
  assertEquals(err.code, "AL2_EVIDENCE_FAILED");
  assertStringIncludes(err.message, "AL2_APP_VERSION_BELOW_FLOOR");
});

Deno.test("validateAndroidAttestation — rejects a leaf serial on Google's revocation list", async () => {
  const fix = await loadFixture("android_strongbox");
  if (!fix) return;
  const err = await assertRejects(
    () =>
      validateAndroidAttestation(
        fixtureOpts(fix, {
          revokedSerials: new Map([
            [FIXTURE_LEAF_SERIAL, {
              status: "REVOKED",
              reason: "KEY_COMPROMISE",
            }],
          ]),
        }),
      ),
    AttestationError,
  );
  assertEquals(err.code, "ATTESTATION_CERT_REVOKED");
  assertStringIncludes(err.message, `serial ${FIXTURE_LEAF_SERIAL} `);
  assertStringIncludes(err.message, "REVOKED/KEY_COMPROMISE");
});

Deno.test("validateAndroidAttestation — rejects an intermediate serial on the list, whatever its status", async () => {
  const fix = await loadFixture("android_strongbox");
  if (!fix) return;
  const err = await assertRejects(
    () =>
      validateAndroidAttestation(
        fixtureOpts(fix, {
          revokedSerials: new Map([
            [FIXTURE_INTERMEDIATE_SERIAL, {
              status: "SUSPENDED",
              reason: null,
            }],
          ]),
        }),
      ),
    AttestationError,
  );
  assertEquals(err.code, "ATTESTATION_CERT_REVOKED");
  assertStringIncludes(err.message, FIXTURE_INTERMEDIATE_SERIAL);
});

Deno.test("validateAndroidAttestation — a chain absent from a populated list passes", async () => {
  const fix = await loadFixture("android_strongbox");
  if (!fix) return;
  await validateAndroidAttestation(
    fixtureOpts(fix, {
      revokedSerials: new Map([
        ["deadbeef", { status: "REVOKED", reason: "KEY_COMPROMISE" }],
        // The leaf's serial with a leading zero would be a different key.
        ["01", { status: "REVOKED", reason: "KEY_COMPROMISE" }],
      ]),
    }),
  );
});

// =====================================================================
// extractOsPatchLevel — parse + normalize of the [706] field.
//
// Two wire encodings tested — see extractOsPatchLevel doc-comment:
//   - EXPLICIT (constructed): real KeyMint shape. [706] wraps a Universal
//     INTEGER child. This is the production path that historically slipped
//     past the unit tests, then broke every Android enrollment when the
//     patch-gate landed.
//   - IMPLICIT (primitive): fallback for any future KeyMint that adopts
//     it. Bytes sit directly in the [706] primitive's value block.
//
// The fixture happy path above covers the real DER: a parser regression
// that returned null would fail the os patch row and reject it.
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
    // null so the os patch row fails treating the field as missing.
    // 100001 = 0x186A1 = [0x01, 0x86, 0xA1]
    const authList = makeAuthListWithPatchLevel([0x01, 0x86, 0xa1]);
    assertEquals(extractOsPatchLevel(authList), null);
  },
);

Deno.test(
  "extractOsPatchLevel — out-of-range value (post-2100) returns null",
  () => {
    // 210101 (Jan 2101) — above the [200001, 210012] sanity bound. Same
    // null-fail behavior as the pre-2000 case.
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

// =====================================================================
// enforceAl2Evidence (CP Appendix A.3.1) — every row, the exact window
// boundaries, and the failure-code mapping, on synthetic KeyDescriptions.
// =====================================================================

const AL2_NOW = new Date("2026-07-27T00:00:00Z");
const DIGEST_A = new Uint8Array(32).fill(0xaa);
const DIGEST_B = new Uint8Array(32).fill(0xbb);
const ROWS_PREFIX = "A.3.1 rows failed: ";

/** A KeyDescription that passes every AL2 row at AL2_NOW. Tests mutate one
 * field at a time and assert the exact failure. */
function passingDesc(over: Partial<KeyDescription> = {}): KeyDescription {
  return {
    attestationVersion: 300,
    attestationSecurityLevel: 2,
    keymasterVersion: 300,
    keymasterSecurityLevel: 2,
    attestationChallenge: new Uint8Array(),
    appPackages: [{ name: ANDROID_PACKAGE_NAME, version: 42 }],
    appSigningCertDigests: [DIGEST_A],
    purposes: [2], // SIGN
    algorithm: 3, // EC
    keySize: 256,
    digests: [4], // SHA-2-256
    ecCurve: 1, // P_256
    origin: 0, // GENERATED
    rootOfTrust: { deviceLocked: true, verifiedBootState: 0 },
    osPatchLevel: 202607,
    vendorPatchLevel: 20260701,
    bootPatchLevel: 20260701,
    ...over,
  };
}

const AL2_OPTS: Al2EvidenceOpts = {
  signingCertSha256Digests: [DIGEST_A],
  minAppVersionCode: 40,
  now: AL2_NOW,
  packageName: ANDROID_PACKAGE_NAME,
};

function al2Error(
  over: Partial<KeyDescription>,
  opts: Al2EvidenceOpts = AL2_OPTS,
): AttestationError {
  return assertThrows(
    () => enforceAl2Evidence(passingDesc(over), opts),
    AttestationError,
  );
}

Deno.test("enforceAl2Evidence — full table passes", () => {
  enforceAl2Evidence(passingDesc(), AL2_OPTS);
});

Deno.test("enforceAl2Evidence — signing-cert row", () => {
  // No registered digests → the row can't pass.
  assertEquals(
    al2Error({}, { ...AL2_OPTS, signingCertSha256Digests: [] }).message,
    ROWS_PREFIX + "AL2_APP_SIGNING_CERT_MISMATCH",
  );
  // Attested digest doesn't match any registered one.
  const err = al2Error({ appSigningCertDigests: [DIGEST_B] });
  assertEquals(err.code, "AL2_EVIDENCE_FAILED");
  assertEquals(err.message, ROWS_PREFIX + "AL2_APP_SIGNING_CERT_MISMATCH");
  // Any-of-several registered digests matching is enough.
  enforceAl2Evidence(passingDesc(), {
    ...AL2_OPTS,
    signingCertSha256Digests: [DIGEST_B, DIGEST_A],
  });
});

Deno.test("enforceAl2Evidence — app version floor", () => {
  assertEquals(
    al2Error({ appPackages: [{ name: ANDROID_PACKAGE_NAME, version: 39 }] })
      .message,
    ROWS_PREFIX + "AL2_APP_VERSION_BELOW_FLOOR",
  );
  // Version missing from the attestation → same failure (can't prove floor).
  assertEquals(
    al2Error({ appPackages: [{ name: ANDROID_PACKAGE_NAME, version: null }] })
      .message,
    ROWS_PREFIX + "AL2_APP_VERSION_BELOW_FLOOR",
  );
  // No floor configured → version not checked.
  enforceAl2Evidence(
    passingDesc({
      appPackages: [{ name: ANDROID_PACKAGE_NAME, version: null }],
    }),
    { ...AL2_OPTS, minAppVersionCode: undefined },
  );
});

Deno.test("enforceAl2Evidence — key-parameter rows reject individually (null = fail)", () => {
  const cases: Array<[Partial<KeyDescription>, string]> = [
    [{ purposes: [0] }, "AL2_KEY_PURPOSE"],
    [{ purposes: null }, "AL2_KEY_PURPOSE"],
    [{ algorithm: 1 }, "AL2_KEY_ALGORITHM"],
    [{ algorithm: null }, "AL2_KEY_ALGORITHM"],
    [{ keySize: 384 }, "AL2_KEY_SIZE"],
    [{ digests: [2] }, "AL2_KEY_DIGEST"],
    [{ digests: null }, "AL2_KEY_DIGEST"],
    [{ ecCurve: 2 }, "AL2_KEY_CURVE"],
    [{ origin: 2 }, "AL2_KEY_ORIGIN"],
    [{ origin: null }, "AL2_KEY_ORIGIN"],
  ];
  for (const [over, row] of cases) {
    const err = al2Error(over);
    assertEquals(err.code, "AL2_EVIDENCE_FAILED", JSON.stringify(over));
    assertEquals(err.message, ROWS_PREFIX + row, JSON.stringify(over));
  }
});

Deno.test("enforceAl2Evidence — rootOfTrust rows", () => {
  assertEquals(
    al2Error({ rootOfTrust: null }).message,
    ROWS_PREFIX + "AL2_ROOT_OF_TRUST_MISSING",
  );
  assertEquals(
    al2Error({ rootOfTrust: { deviceLocked: false, verifiedBootState: 0 } })
      .message,
    ROWS_PREFIX + "AL2_DEVICE_NOT_LOCKED",
  );
  assertEquals(
    al2Error({ rootOfTrust: { deviceLocked: true, verifiedBootState: 2 } })
      .message,
    ROWS_PREFIX + "AL2_VERIFIED_BOOT_NOT_VERIFIED",
  );
});

Deno.test("enforceAl2Evidence — patch-currency rows and their exact boundaries", () => {
  // os window per the A.3.1 worked example: CSR month + 3 back. At
  // 2026-07-27 that's 202604..202607 inclusive.
  enforceAl2Evidence(passingDesc({ osPatchLevel: 202604 }), AL2_OPTS);
  assertEquals(
    al2Error({ osPatchLevel: 202603 }).message,
    ROWS_PREFIX + "AL2_OS_PATCH_STALE",
  );
  assertEquals(
    al2Error({ osPatchLevel: null }).message,
    ROWS_PREFIX + "AL2_OS_PATCH_STALE",
  );
  assertEquals(
    al2Error({ osPatchLevel: 202608 }).message,
    ROWS_PREFIX + "AL2_OS_PATCH_FUTURE",
  );
  // vendor/boot ≤ 90 days and not future: window at 2026-07-27 is
  // 20260428..20260727.
  enforceAl2Evidence(passingDesc({ vendorPatchLevel: 20260428 }), AL2_OPTS);
  assertEquals(
    al2Error({ vendorPatchLevel: 20260427 }).message,
    ROWS_PREFIX + "AL2_VENDOR_PATCH_STALE",
  );
  assertEquals(
    al2Error({ vendorPatchLevel: 20260728 }).message,
    ROWS_PREFIX + "AL2_VENDOR_PATCH_FUTURE",
  );
  assertEquals(
    al2Error({ bootPatchLevel: null }).message,
    ROWS_PREFIX + "AL2_BOOT_PATCH_STALE",
  );
  assertEquals(
    al2Error({ bootPatchLevel: 20260728 }).message,
    ROWS_PREFIX + "AL2_BOOT_PATCH_FUTURE",
  );
});

Deno.test("enforceAl2Evidence — only stale patch rows → ATTESTATION_STALE_PATCH", () => {
  for (
    const over of [
      { osPatchLevel: 202603 },
      { vendorPatchLevel: 20260427 },
      { bootPatchLevel: null },
      {
        osPatchLevel: null,
        vendorPatchLevel: 20260101,
        bootPatchLevel: 20260101,
      },
    ]
  ) {
    assertEquals(
      al2Error(over).code,
      "ATTESTATION_STALE_PATCH",
      JSON.stringify(over),
    );
  }
});

Deno.test("enforceAl2Evidence — future-dated or mixed failures stay generic", () => {
  assertEquals(al2Error({ osPatchLevel: 202608 }).code, "AL2_EVIDENCE_FAILED");
  assertEquals(
    al2Error({ osPatchLevel: 202603, vendorPatchLevel: 20260728 }).code,
    "AL2_EVIDENCE_FAILED",
  );
  const mixed = al2Error({
    rootOfTrust: { deviceLocked: false, verifiedBootState: 0 },
    osPatchLevel: 202603,
  });
  assertEquals(mixed.code, "AL2_EVIDENCE_FAILED");
  assertEquals(
    mixed.message,
    ROWS_PREFIX + "AL2_DEVICE_NOT_LOCKED,AL2_OS_PATCH_STALE",
  );
});

Deno.test("enforceAl2Evidence — every failed row is named, in table order", () => {
  const err = al2Error(
    {
      rootOfTrust: { deviceLocked: false, verifiedBootState: 2 },
      vendorPatchLevel: null,
    },
    { ...AL2_OPTS, signingCertSha256Digests: [] },
  );
  assertEquals(err.code, "AL2_EVIDENCE_FAILED");
  assertEquals(
    err.message,
    ROWS_PREFIX +
      "AL2_APP_SIGNING_CERT_MISMATCH,AL2_DEVICE_NOT_LOCKED,AL2_VERIFIED_BOOT_NOT_VERIFIED,AL2_VENDOR_PATCH_STALE",
  );
});

// --- The AuthorizationList readers (synthetic wire shapes) --------------

Deno.test("readTaggedInt / readTaggedIntSet — EXPLICIT and IMPLICIT shapes", () => {
  const list = new asn1js.Sequence({
    value: [
      // [1] EXPLICIT SET OF INTEGER {2}
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 1 },
        value: [
          new asn1js.Set({
            value: [
              new asn1js.Integer({ valueHex: new Uint8Array([2]).buffer }),
            ],
          }),
        ],
      }),
      // [3] EXPLICIT INTEGER 256
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 3 },
        value: [
          new asn1js.Integer({ valueHex: new Uint8Array([0x01, 0x00]).buffer }),
        ],
      }),
      // [702] IMPLICIT INTEGER 0 (fallback shape)
      new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 702 },
        valueHex: new Uint8Array([0]).buffer,
      }),
    ],
  });
  assertEquals(readTaggedIntSet(list, 1), [2]);
  assertEquals(readTaggedInt(list, 3), 256);
  assertEquals(readTaggedInt(list, 702), 0);
  assertEquals(readTaggedInt(list, 10), null); // absent tag
  assertEquals(readTaggedIntSet(list, 5), null); // absent tag
});

Deno.test("extractRootOfTrust — parses deviceLocked + verifiedBootState", () => {
  const rot = (locked: boolean, state: number) =>
    new asn1js.Sequence({
      value: [
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 704 },
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.OctetString({ valueHex: new Uint8Array(32).buffer }),
                new asn1js.Boolean({ value: locked }),
                new asn1js.Enumerated({ value: state }),
                new asn1js.OctetString({ valueHex: new Uint8Array(32).buffer }),
              ],
            }),
          ],
        }),
      ],
    });
  assertEquals(extractRootOfTrust(rot(true, 0)), {
    deviceLocked: true,
    verifiedBootState: 0,
  });
  assertEquals(extractRootOfTrust(rot(false, 2)), {
    deviceLocked: false,
    verifiedBootState: 2,
  });
  assertEquals(extractRootOfTrust(new asn1js.Sequence({ value: [] })), null);
});

Deno.test("extractDayPatchLevel — YYYYMMDD passthrough, YYYYMM→YYYYMM01, bounds", () => {
  const mk = (bytes: number[]) =>
    new asn1js.Sequence({
      value: [
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 718 },
          value: [
            new asn1js.Integer({ valueHex: new Uint8Array(bytes).buffer }),
          ],
        }),
      ],
    });
  // 20260701 = 0x01 0x35 0x27 0x5D
  assertEquals(
    extractDayPatchLevel(mk([0x01, 0x35, 0x27, 0x5d]), 718),
    20260701,
  );
  // 202607 = 0x03 0x17 0x6F → normalized to 20260701
  assertEquals(extractDayPatchLevel(mk([0x03, 0x17, 0x6f]), 718), 20260701);
  // Absent tag / garbage value → null
  assertEquals(extractDayPatchLevel(mk([0x01]), 719), null);
  assertEquals(extractDayPatchLevel(mk([0x01]), 718), null);
});

Deno.test("extractAttestationApplicationId — packages with versions + signature digests", () => {
  const inner = new asn1js.Sequence({
    value: [
      new asn1js.Set({
        value: [
          new asn1js.Sequence({
            value: [
              new asn1js.OctetString({
                valueHex: new TextEncoder().encode("com.realreel.app")
                  .buffer as ArrayBuffer,
              }),
              new asn1js.Integer({ valueHex: new Uint8Array([42]).buffer }),
            ],
          }),
        ],
      }),
      new asn1js.Set({
        value: [
          new asn1js.OctetString({ valueHex: DIGEST_A.slice().buffer }),
        ],
      }),
    ],
  });
  const authList = new asn1js.Sequence({
    value: [
      new asn1js.Constructed({
        idBlock: { tagClass: 3, tagNumber: 709 },
        value: [
          new asn1js.OctetString({ valueHex: inner.toBER(false) }),
        ],
      }),
    ],
  });
  const aid = extractAttestationApplicationId(authList);
  assertEquals(aid?.packages, [{ name: "com.realreel.app", version: 42 }]);
  assertEquals(aid?.signatureDigests.length, 1);
  assertEquals(aid?.signatureDigests[0], DIGEST_A);
});
