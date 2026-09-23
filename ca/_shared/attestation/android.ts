// Android KeyStore attestation validation.
//
// Implements the steps from "Verifying Hardware-backed Key Pairs":
//   https://source.android.com/docs/security/features/keystore/attestation
// plus the C2PA Certificate Policy Appendix A.3.1 evidence table, which every
// Android enrollment must pass in full: RealReel issues Android at AL2 only.
//
// The leaf certificate of an attested key chain carries a custom extension
// whose value is a `KeyDescription` ASN.1 SEQUENCE; parseKeyDescription pulls
// the fields the checks below read.

// deno-lint-ignore-file no-explicit-any
import {
  asn1js,
  AttestationError,
  base64ToBytes,
  ctEqual,
  describeCertChain,
  extractSpkiDer,
  findExtensionByOid,
  parseCertFromDer,
  parseCertFromPem,
  verifyChainToTrustedRoots,
} from "./pki.ts";
import type { Certificate } from "./pki.ts";
import { GOOGLE_HW_ATTESTATION_ROOT_PEMS } from "./roots.ts";
import {
  type AndroidRevocationList,
  certSerialHex,
} from "./android_revocation.ts";

// Two OIDs in active use across the Android device population:
//   * 1.3.6.1.4.1.11129.2.1.17 — Keymaster v1+ through KeyMint v2 (the vast
//     majority of devices in the field today).
//   * 1.3.6.1.4.1.11129.2.1.30 — KeyMint v3+ (Android 14+ on newer devices,
//     rolling out gradually). The KeyDescription structure is the same; only
//     the extension OID changed.
//
// We try the v3 OID first (forward-compat preference for newer devices) and
// fall back to the legacy OID. If a future KeyMint version introduces yet
// another OID, the validator will fail with KEY_DESCRIPTION_MISSING — that's
// the signal to add it here.
const OID_ANDROID_KEY_DESCRIPTION_V300 = "1.3.6.1.4.1.11129.2.1.30";
const OID_ANDROID_KEY_DESCRIPTION_LEGACY = "1.3.6.1.4.1.11129.2.1.17";

// SecurityLevel enum from Android KeyStore (KeyDescription.attestationSecurityLevel).
//   0 = Software, 1 = TrustedEnvironment (TEE), 2 = StrongBox
const SECURITY_LEVEL_SOFTWARE = 0;
const SECURITY_LEVEL_TEE = 1;
const SECURITY_LEVEL_STRONG_BOX = 2;

// KeyMint AuthorizationList enum values consumed by the AL2 evidence table
// (CP Appendix A.3.1). Source: hardware/interfaces/security/keymint aidl.
const KM_PURPOSE_SIGN = 2;
const KM_ALGORITHM_EC = 3;
const KM_DIGEST_SHA_2_256 = 4;
const KM_EC_CURVE_P_256 = 1;
const KM_ORIGIN_GENERATED = 0;
const VERIFIED_BOOT_STATE_VERIFIED = 0;

// Lazy-init the parsed Google roots.
let _googleRoots: Certificate[] | null = null;
function googleRoots(): Certificate[] {
  if (!_googleRoots) {
    _googleRoots = GOOGLE_HW_ATTESTATION_ROOT_PEMS.map(parseCertFromPem);
  }
  return _googleRoots;
}

export type ExpectedSecurityLevel = "strongbox" | "tee";

export interface ValidateAndroidAttestationOpts {
  // Cert chain as base64-encoded DER strings (leaf-first), matching what the
  // native module returns (JSON.stringify of an array).
  certChainBase64: string[];
  // Server-issued challenge bytes (raw, not base64) — must match the
  // attestationChallenge embedded in the leaf cert.
  challenge: Uint8Array;
  // SPKI DER bytes of the SE signing key the client claims. Must match the
  // public key in the leaf cert exactly.
  sePublicKey: Uint8Array;
  // Our app package name (com.realreel.app; or com.realreel.app.dev on a gated
  // local-dev stack — see _shared/config.ts). Passed in, not hardcoded here.
  packageName: string;
  // SHA-256 digests of the app's registered signing certificate(s) — the
  // Play App Signing cert in prod, the debug keystore cert on a local stack.
  // The leaf must carry one of them; an empty list rejects every chain.
  signingCertSha256Digests: Uint8Array[];
  // Optional versionCode floor for the registered package (the Gen Agmt §4.2
  // mandated-change lever). Unset ⇒ version not checked.
  minAppVersionCode?: number;
  // Google's attestation revocation list (android_revocation.ts). Any listed
  // serial anywhere in the chain rejects.
  revokedSerials: AndroidRevocationList;
  // What the client claimed about hardware backing. Cross-checks against the
  // attestationSecurityLevel in the cert: 'strongbox' requires SECURITY_LEVEL_STRONG_BOX,
  // 'tee' requires SECURITY_LEVEL_TEE or higher.
  expectedSecurityLevel: ExpectedSecurityLevel;
  // Evaluation time for the chain validity window and the patch-currency
  // rows. Tests pin it inside a fixture's window; production omits it.
  validationTime?: Date;
}

export interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;

  // --- A.3.1 evidence fields. null when the leaf doesn't carry the tag or
  // encodes it in an unsupported shape; enforceAl2Evidence fails that row.

  // attestationApplicationId [709]: package entries + the SET of SHA-256
  // signing-cert digests.
  appPackages: Array<{ name: string; version: number | null }>;
  appSigningCertDigests: Uint8Array[];
  // Key parameters, hardwareEnforced ONLY — a software-enforced key param
  // proves nothing about the key the hardware actually holds.
  purposes: number[] | null; // [1] SET OF INTEGER
  algorithm: number | null; // [2]
  keySize: number | null; // [3]
  digests: number[] | null; // [5] SET OF INTEGER
  ecCurve: number | null; // [10]
  origin: number | null; // [702]
  // rootOfTrust [704], hardwareEnforced ONLY.
  rootOfTrust: { deviceLocked: boolean; verifiedBootState: number } | null;
  // TAG_OS_PATCH_LEVEL [706], hardwareEnforced ONLY, YYYYMM (a YYYYMMDD wire
  // value is normalized to YYYYMM).
  osPatchLevel: number | null;
  // TAG_VENDOR_PATCH_LEVEL [718] / TAG_BOOT_PATCH_LEVEL [719], hardwareEnforced
  // ONLY, YYYYMMDD (a YYYYMM wire value is normalized to YYYYMM01).
  vendorPatchLevel: number | null;
  bootPatchLevel: number | null;
}

// Throws AttestationError on any failure. Every check is a hard reject.
export async function validateAndroidAttestation(
  opts: ValidateAndroidAttestationOpts,
): Promise<void> {
  if (!Array.isArray(opts.certChainBase64) || opts.certChainBase64.length < 2) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      "expected cert chain of length >= 2",
    );
  }
  const now = opts.validationTime ?? new Date();

  // === Step 1: parse cert chain (DER bytes) ===
  let chain: Certificate[];
  try {
    chain = opts.certChainBase64
      .map((b64) => base64ToBytes(b64))
      .map(parseCertFromDer);
  } catch (e) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      `cert parse failed: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  // === Step 2: verify chain to one of Google's hardware attestation roots ===
  // On failure, append a per-cert summary of what the device presented —
  // that's the only way to identify an unpinned hierarchy (new Google root,
  // OEM quirk, truncated chain) from the edge-function log, since a rejected
  // chain is never persisted.
  await verifyChainToTrustedRoots(chain, googleRoots(), now)
    .catch((e) => {
      throw new AttestationError(
        "CHAIN_INVALID",
        `${e instanceof Error ? e.message : String(e)}; presented chain: ${
          describeCertChain(chain)
        }`,
      );
    });

  // === Step 3: no cert in the chain is on Google's revocation list ===
  for (const cert of chain) {
    const serial = certSerialHex(cert);
    const entry = opts.revokedSerials.get(serial);
    if (entry) {
      throw new AttestationError(
        "ATTESTATION_CERT_REVOKED",
        `chain cert serial ${serial} is on Google's attestation revocation list: ${entry.status}` +
          (entry.reason ? `/${entry.reason}` : ""),
      );
    }
  }

  const leaf = chain[0];

  // === Step 4: find KeyDescription extension on leaf, parse it ===
  const ext = findExtensionByOid(leaf, OID_ANDROID_KEY_DESCRIPTION_V300) ??
    findExtensionByOid(leaf, OID_ANDROID_KEY_DESCRIPTION_LEGACY);
  if (!ext) {
    throw new AttestationError(
      "KEY_DESCRIPTION_MISSING",
      "leaf cert has no Android key attestation extension (tried v3 + legacy OIDs)",
    );
  }
  const desc = parseKeyDescription(ext);

  // === Step 5: attestationChallenge must match server-issued challenge ===
  if (!ctEqual(desc.attestationChallenge, opts.challenge)) {
    throw new AttestationError(
      "CHALLENGE_MISMATCH",
      "attestationChallenge in cert does not match server challenge",
    );
  }

  // === Step 6: security levels must be hardware-backed ===
  if (desc.attestationSecurityLevel === SECURITY_LEVEL_SOFTWARE) {
    throw new AttestationError(
      "SOFTWARE_ATTESTATION",
      "attestationSecurityLevel = SOFTWARE; reject",
    );
  }
  if (desc.keymasterSecurityLevel === SECURITY_LEVEL_SOFTWARE) {
    throw new AttestationError(
      "SOFTWARE_KEYMASTER",
      "keymasterSecurityLevel = SOFTWARE; reject",
    );
  }

  // === Step 7: cross-check claimed platform vs actual security level ===
  // Two distinct fields matter here:
  //   - attestationSecurityLevel:  WHERE the attestation record was signed
  //   - keymasterSecurityLevel:    WHERE the attested key actually lives
  // Some devices StrongBox-sign attestation records for TEE-resident keys.
  // Checking only attestationSecurityLevel would let a TEE-resident key pass
  // the strongbox branch — we'd believe the user's key was hardware-isolated
  // at StrongBox level when it's actually TEE. Enforce both fields.
  if (opts.expectedSecurityLevel === "strongbox") {
    if (desc.attestationSecurityLevel !== SECURITY_LEVEL_STRONG_BOX) {
      throw new AttestationError(
        "SECURITY_LEVEL_MISMATCH",
        "client claimed StrongBox but attestation record is at lower security level",
      );
    }
    if (desc.keymasterSecurityLevel !== SECURITY_LEVEL_STRONG_BOX) {
      throw new AttestationError(
        "SECURITY_LEVEL_MISMATCH",
        "client claimed StrongBox but the attested key resides in a lower security domain",
      );
    }
  } else {
    // 'tee' allows TEE or higher (StrongBox is fine too).
    if (
      desc.attestationSecurityLevel !== SECURITY_LEVEL_TEE &&
      desc.attestationSecurityLevel !== SECURITY_LEVEL_STRONG_BOX
    ) {
      throw new AttestationError(
        "SECURITY_LEVEL_MISMATCH",
        "client claimed TEE but cert shows software-only",
      );
    }
  }

  // === Step 8: leaf public key (SPKI DER) must match what client claims ===
  const leafSpki = extractSpkiDer(leaf);
  if (!ctEqual(leafSpki, opts.sePublicKey)) {
    throw new AttestationError(
      "PUBLIC_KEY_MISMATCH",
      "leaf cert public key does not match claimed sePublicKey",
    );
  }

  // === Step 9: packageName in attestationApplicationId must match ours ===
  if (!desc.appPackages.some((p) => p.name === opts.packageName)) {
    throw new AttestationError(
      "PACKAGE_NAME_MISMATCH",
      `package name "${opts.packageName}" not in attestation`,
    );
  }

  // === Step 10: the AL2 evidence table (CP Appendix A.3.1) ===
  enforceAl2Evidence(desc, {
    packageName: opts.packageName,
    signingCertSha256Digests: opts.signingCertSha256Digests,
    minAppVersionCode: opts.minAppVersionCode,
    now,
  });
}

// Parses the leaf cert's KeyDescription extension. The extension value is
// itself an OCTET STRING wrapping a SEQUENCE. The SEQUENCE has many fields;
// we only enforce the ones we care about and ignore the rest.
//
// Layout (per Google's spec, Keymaster v3+):
//   KeyDescription ::= SEQUENCE {
//     attestationVersion         INTEGER,
//     attestationSecurityLevel   ENUMERATED { 0=Software, 1=TEE, 2=StrongBox },
//     keymasterVersion           INTEGER,
//     keymasterSecurityLevel     ENUMERATED,
//     attestationChallenge       OCTET STRING,
//     uniqueId                   OCTET STRING,
//     softwareEnforced           AuthorizationList,
//     hardwareEnforced           AuthorizationList,
//   }
//
// AuthorizationList contains many OPTIONAL [tag] fields. We only look for the
// attestationApplicationId at tag [709], which is itself an OCTET STRING
// wrapping a SEQUENCE { SET OF SEQUENCE { OCTET STRING packageName, INTEGER version }, ... }.
function parseKeyDescription(extValue: Uint8Array): KeyDescription {
  const ab = extValue.buffer.slice(
    extValue.byteOffset,
    extValue.byteOffset + extValue.byteLength,
  ) as ArrayBuffer;
  const outer = asn1js.fromBER(ab);
  if (outer.offset === -1) {
    throw new AttestationError(
      "KEY_DESCRIPTION_INVALID",
      "could not ASN.1-decode KeyDescription",
    );
  }

  // The extension's extnValue is an OCTET STRING in standard X.509 — pkijs
  // already strips that when returning extnValue.valueBlock, but to be robust
  // we walk the tree looking for the outermost SEQUENCE.
  const seq = findFirstSequence(outer.result);
  if (!seq) {
    throw new AttestationError(
      "KEY_DESCRIPTION_INVALID",
      "no SEQUENCE found in KeyDescription extension",
    );
  }
  const fields: any[] = seq.valueBlock.value ?? [];

  if (fields.length < 8) {
    throw new AttestationError(
      "KEY_DESCRIPTION_INVALID",
      `KeyDescription has ${fields.length} fields, expected >= 8`,
    );
  }

  const attestationVersion = readInt(fields[0]);
  const attestationSecurityLevel = readEnum(fields[1]);
  const keymasterVersion = readInt(fields[2]);
  const keymasterSecurityLevel = readEnum(fields[3]);
  const attestationChallenge = readOctetString(fields[4]);
  // fields[5] = uniqueId — ignored
  // fields[6] = softwareEnforced AuthorizationList
  // fields[7] = hardwareEnforced AuthorizationList
  const softwareEnforced = fields[6];
  const hardwareEnforced = fields[7];

  // attestationApplicationId [709] lives in either softwareEnforced or
  // hardwareEnforced (typically softwareEnforced).
  const appId = extractAttestationApplicationId(softwareEnforced) ??
    extractAttestationApplicationId(hardwareEnforced);

  return {
    attestationVersion,
    attestationSecurityLevel,
    keymasterVersion,
    keymasterSecurityLevel,
    attestationChallenge,
    appPackages: appId?.packages ?? [],
    appSigningCertDigests: appId?.signatureDigests ?? [],
    // Every AL2 evidence field is read from hardwareEnforced ONLY (see the
    // KeyDescription field docs) — a softwareEnforced value is OS-asserted,
    // not secure-environment-asserted, and A.3.1 sources each row from
    // hardwareEnforced.
    purposes: readTaggedIntSet(hardwareEnforced, 1),
    algorithm: readTaggedInt(hardwareEnforced, 2),
    keySize: readTaggedInt(hardwareEnforced, 3),
    digests: readTaggedIntSet(hardwareEnforced, 5),
    ecCurve: readTaggedInt(hardwareEnforced, 10),
    origin: readTaggedInt(hardwareEnforced, 702),
    rootOfTrust: extractRootOfTrust(hardwareEnforced),
    osPatchLevel: extractOsPatchLevel(hardwareEnforced),
    vendorPatchLevel: extractDayPatchLevel(hardwareEnforced, 718),
    bootPatchLevel: extractDayPatchLevel(hardwareEnforced, 719),
  };
}

// --- ASN.1 walking helpers ---------------------------------------------

function findFirstSequence(node: any): any | null {
  if (node?.idBlock?.tagClass === 1 && node?.idBlock?.tagNumber === 16) {
    return node;
  }
  const children = node?.valueBlock?.value as any[] | undefined;
  if (Array.isArray(children)) {
    for (const c of children) {
      const found = findFirstSequence(c);
      if (found) return found;
    }
  }
  return null;
}

function readInt(node: any): number {
  if (!node) return 0;
  // pkijs Integer node: valueBlock.valueDec for small ints.
  const dec = node.valueBlock?.valueDec;
  if (typeof dec === "number") return dec;
  // Fall back to reading raw bytes.
  const hex = node.valueBlock?.valueHexView as Uint8Array | undefined;
  if (hex) {
    let v = 0;
    for (let i = 0; i < hex.length; i++) v = (v << 8) | hex[i];
    return v;
  }
  return 0;
}

function readEnum(node: any): number {
  return readInt(node);
}

function readOctetString(node: any): Uint8Array {
  if (!node) return new Uint8Array();
  const hex = node.valueBlock?.valueHexView as Uint8Array | undefined;
  if (hex) return new Uint8Array(hex);
  const ab = node.valueBlock?.valueHex as ArrayBuffer | undefined;
  if (ab) return new Uint8Array(ab);
  return new Uint8Array();
}

// Walks an AuthorizationList SEQUENCE looking for the [709] EXPLICIT tagged
// attestationApplicationId field. Its value is an OCTET STRING wrapping
//   SEQUENCE {
//     SET OF SEQUENCE { OCTET STRING packageName, INTEGER version },
//     SET OF OCTET STRING signatureDigests   -- SHA-256 of signing cert(s)
//   }
// Returns the parsed structure, or null if not found / unparseable.
export function extractAttestationApplicationId(
  authList: any,
): {
  packages: Array<{ name: string; version: number | null }>;
  signatureDigests: Uint8Array[];
} | null {
  const f = findTaggedField(authList, 709);
  if (!f) return null;

  // Inside [709] is an OCTET STRING; inside that is a SEQUENCE.
  const inner = f.valueBlock?.value as any[] | undefined;
  if (!inner || !inner.length) return null;

  const octetBytes = readOctetString(inner[0]);
  if (!octetBytes.length) return null;

  const ab = octetBytes.buffer.slice(
    octetBytes.byteOffset,
    octetBytes.byteOffset + octetBytes.byteLength,
  ) as ArrayBuffer;
  const decoded = asn1js.fromBER(ab);
  if (decoded.offset === -1) return null;

  const aidFields = (decoded.result as any).valueBlock?.value as
    | any[]
    | undefined;
  if (!aidFields || !aidFields.length) return null;

  // First field: SET OF SEQUENCE { OCTET STRING packageName, INTEGER version }.
  const pkgEntries = aidFields[0]?.valueBlock?.value as any[] | undefined;
  if (!pkgEntries) return null;

  const packages: Array<{ name: string; version: number | null }> = [];
  for (const entry of pkgEntries) {
    const entryFields = entry?.valueBlock?.value as any[] | undefined;
    if (!entryFields || !entryFields.length) continue;
    const nameBytes = readOctetString(entryFields[0]);
    if (!nameBytes.length) continue;
    const versionNode = entryFields[1];
    packages.push({
      name: new TextDecoder().decode(nameBytes),
      version: versionNode ? readInt(versionNode) : null,
    });
  }

  // Second field: SET OF OCTET STRING — SHA-256 digests of the APK signing
  // certificate(s). Absent on some legacy encodings → empty list (the
  // signing-cert row then fails).
  const signatureDigests: Uint8Array[] = [];
  const digestEntries = aidFields[1]?.valueBlock?.value as any[] | undefined;
  if (digestEntries) {
    for (const d of digestEntries) {
      const bytes = readOctetString(d);
      if (bytes.length) signatureDigests.push(bytes);
    }
  }

  return { packages, signatureDigests };
}

// --- Generic AuthorizationList tag readers ------------------------------
//
// Every scalar AuthorizationList field can appear in the same two wire
// shapes documented on extractOsPatchLevel (EXPLICIT constructed wrapper —
// what real KeyMint emits — or an IMPLICIT primitive). These helpers accept
// both, and return null for anything absent or malformed: AL2 rows treat
// null as a failed check (reject, never crash).

function findTaggedField(authList: any, tagNumber: number): any | null {
  if (!authList?.valueBlock?.value) return null;
  for (const f of authList.valueBlock.value as any[]) {
    if (f?.idBlock?.tagClass === 3 && f?.idBlock?.tagNumber === tagNumber) {
      return f;
    }
  }
  return null;
}

// Big-endian unsigned decode of an INTEGER-ish node's bytes; null if empty.
function readNodeUint(node: any): number | null {
  const hexView = node?.valueBlock?.valueHexView as Uint8Array | undefined;
  const raw = hexView && hexView.length
    ? new Uint8Array(hexView)
    : node?.valueBlock?.valueHex
    ? new Uint8Array(node.valueBlock.valueHex as ArrayBuffer)
    : null;
  if (!raw || !raw.length) return null;
  let value = 0;
  for (let i = 0; i < raw.length; i++) value = value * 256 + raw[i];
  return value;
}

/** Read a [tag] INTEGER from an AuthorizationList (both wire shapes). */
export function readTaggedInt(authList: any, tagNumber: number): number | null {
  const f = findTaggedField(authList, tagNumber);
  if (!f) return null;
  if (f.idBlock?.isConstructed === true) {
    const inner = (f.valueBlock?.value as any[] | undefined)?.[0];
    // Universal INTEGER (class 1, tag 2) or ENUMERATED (tag 10).
    const tc = inner?.idBlock?.tagClass;
    const tn = inner?.idBlock?.tagNumber;
    if (tc !== 1 || (tn !== 2 && tn !== 10)) return null;
    return readNodeUint(inner);
  }
  return readNodeUint(f);
}

/** Read a [tag] SET OF INTEGER from an AuthorizationList. */
export function readTaggedIntSet(
  authList: any,
  tagNumber: number,
): number[] | null {
  const f = findTaggedField(authList, tagNumber);
  if (!f) return null;
  let members: any[] | undefined;
  const children = f.valueBlock?.value as any[] | undefined;
  const first = children?.[0];
  if (first?.idBlock?.tagClass === 1 && first?.idBlock?.tagNumber === 17) {
    // EXPLICIT: [tag] wraps a Universal SET whose members are INTEGERs.
    members = first.valueBlock?.value as any[] | undefined;
  } else {
    // IMPLICIT: the INTEGER members sit directly under the context tag.
    members = children;
  }
  if (!members) return null;
  const out: number[] = [];
  for (const m of members) {
    const v = readNodeUint(m);
    if (v !== null) out.push(v);
  }
  return out;
}

/** Parse rootOfTrust [704]:
 *  SEQUENCE { OCTET STRING verifiedBootKey, BOOLEAN deviceLocked,
 *             ENUMERATED verifiedBootState, [OCTET STRING verifiedBootHash] } */
export function extractRootOfTrust(
  authList: any,
): { deviceLocked: boolean; verifiedBootState: number } | null {
  const f = findTaggedField(authList, 704);
  if (!f) return null;
  const seq = (f.valueBlock?.value as any[] | undefined)?.[0];
  const fields = seq?.valueBlock?.value as any[] | undefined;
  if (!fields || fields.length < 3) return null;
  const lockedNode = fields[1];
  const deviceLocked = lockedNode?.valueBlock?.value === true;
  const verifiedBootState = readNodeUint(fields[2]);
  if (verifiedBootState === null) return null;
  return { deviceLocked, verifiedBootState };
}

/** Read TAG_VENDOR_PATCH_LEVEL [718] / TAG_BOOT_PATCH_LEVEL [719] in
 * YYYYMMDD canonical form. A YYYYMM wire value is normalized to YYYYMM01
 * (day floored — conservative for a freshness gate). Out-of-range → null. */
export function extractDayPatchLevel(
  authList: any,
  tagNumber: number,
): number | null {
  let value = readTaggedInt(authList, tagNumber);
  if (value === null) return null;
  if (value < 1_000_000_0) value = value * 100 + 1; // YYYYMM → YYYYMM01
  if (value < 2000_01_01 || value > 2100_12_31) return null;
  return value;
}

// --- AL2 evidence table (CP Appendix A.3.1) ------------------------------

export interface Al2EvidenceOpts {
  packageName: string;
  signingCertSha256Digests: Uint8Array[];
  minAppVersionCode?: number;
  now: Date;
}

const PATCH_STALE_ROWS = new Set([
  "AL2_OS_PATCH_STALE",
  "AL2_VENDOR_PATCH_STALE",
  "AL2_BOOT_PATCH_STALE",
]);

function yyyymmFloor(now: Date, monthsBack: number): number {
  const d = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - monthsBack, 1),
  );
  return d.getUTCFullYear() * 100 + (d.getUTCMonth() + 1);
}

function yyyymmddFloor(now: Date, daysBack: number): number {
  const d = new Date(now.getTime() - daysBack * 86_400_000);
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 +
    d.getUTCDate();
}

/**
 * Enforce the AL2-only rows of CP Appendix A.3.1 against a parsed
 * KeyDescription. The base rows (hardware security level, challenge, SPKI
 * binding, package name) are checked by validateAndroidAttestation before
 * this runs. StrongBox is NOT required: A.3.1 accepts TrustedEnvironment or
 * StrongBox for both security levels.
 *
 * Every row is evaluated before throwing, so the rejection names every failed
 * row. The code is ATTESTATION_STALE_PATCH when only patch-currency rows
 * failed (the app renders "update your device" for that code) and
 * AL2_EVIDENCE_FAILED otherwise.
 */
export function enforceAl2Evidence(
  desc: KeyDescription,
  opts: Al2EvidenceOpts,
): void {
  const failures: string[] = [];

  // attestationApplicationID row: registered signing cert + version floor.
  if (
    !desc.appSigningCertDigests.some((got) =>
      opts.signingCertSha256Digests.some((want) => ctEqual(got, want))
    )
  ) {
    failures.push("AL2_APP_SIGNING_CERT_MISMATCH");
  }
  if (opts.minAppVersionCode !== undefined) {
    const versions = desc.appPackages
      .filter((p) => p.name === opts.packageName)
      .map((p) => p.version)
      .filter((v): v is number => v !== null);
    if (!versions.length || Math.max(...versions) < opts.minAppVersionCode) {
      failures.push("AL2_APP_VERSION_BELOW_FLOOR");
    }
  }

  // Key-parameter rows (hardwareEnforced only; null = row fails).
  if (!desc.purposes?.includes(KM_PURPOSE_SIGN)) {
    failures.push("AL2_KEY_PURPOSE");
  }
  if (desc.algorithm !== KM_ALGORITHM_EC) failures.push("AL2_KEY_ALGORITHM");
  if (desc.keySize !== 256) failures.push("AL2_KEY_SIZE");
  if (!desc.digests?.includes(KM_DIGEST_SHA_2_256)) {
    failures.push("AL2_KEY_DIGEST");
  }
  if (desc.ecCurve !== KM_EC_CURVE_P_256) failures.push("AL2_KEY_CURVE");
  if (desc.origin !== KM_ORIGIN_GENERATED) failures.push("AL2_KEY_ORIGIN");

  // rootOfTrust rows.
  if (!desc.rootOfTrust) {
    failures.push("AL2_ROOT_OF_TRUST_MISSING");
  } else {
    if (!desc.rootOfTrust.deviceLocked) failures.push("AL2_DEVICE_NOT_LOCKED");
    if (desc.rootOfTrust.verifiedBootState !== VERIFIED_BOOT_STATE_VERIFIED) {
      failures.push("AL2_VERIFIED_BOOT_NOT_VERIFIED");
    }
  }

  // Patch-currency rows. A.3.1's os window is the CSR month plus the three
  // before it ("for August 2026: 202608, 202607, 202606, or 202605") — a
  // floor of monthsBack=3, not 4. Vendor/boot are ≤ 90 days. All three rows
  // also say the value cannot be in the future.
  const monthNow = yyyymmFloor(opts.now, 0);
  if (
    desc.osPatchLevel === null ||
    desc.osPatchLevel < yyyymmFloor(opts.now, 3)
  ) {
    failures.push("AL2_OS_PATCH_STALE");
  } else if (desc.osPatchLevel > monthNow) {
    failures.push("AL2_OS_PATCH_FUTURE");
  }
  const dayFloor = yyyymmddFloor(opts.now, 90);
  const dayNow = yyyymmddFloor(opts.now, 0);
  if (desc.vendorPatchLevel === null || desc.vendorPatchLevel < dayFloor) {
    failures.push("AL2_VENDOR_PATCH_STALE");
  } else if (desc.vendorPatchLevel > dayNow) {
    failures.push("AL2_VENDOR_PATCH_FUTURE");
  }
  if (desc.bootPatchLevel === null || desc.bootPatchLevel < dayFloor) {
    failures.push("AL2_BOOT_PATCH_STALE");
  } else if (desc.bootPatchLevel > dayNow) {
    failures.push("AL2_BOOT_PATCH_FUTURE");
  }

  if (failures.length === 0) return;
  throw new AttestationError(
    failures.every((f) => PATCH_STALE_ROWS.has(f))
      ? "ATTESTATION_STALE_PATCH"
      : "AL2_EVIDENCE_FAILED",
    `A.3.1 rows failed: ${failures.join(",")}`,
  );
}

// Walks an AuthorizationList SEQUENCE looking for the [706] context-class
// INTEGER `osPatchLevel`. Spec says YYYYMM (e.g. 202501); some pre-2018
// Keymaster builds and a handful of OEMs emit YYYYMMDD, which we normalize
// back to YYYYMM. Returns null when the tag isn't present.
//
// Two wire encodings appear in the field for scalar AuthorizationList fields,
// both of which we accept:
//
//   * EXPLICIT (constructed): real KeyMint / Keymaster emits [706] as a
//     CONSTRUCTED context-class wrapper around a Universal INTEGER child (per
//     Google's keymaster ASN.1 schema). pkijs surfaces this as a node with
//     `idBlock.isConstructed = true` and the INTEGER bytes one level deeper
//     at `valueBlock.value[0]`. This is what real devices carry — handling
//     only the IMPLICIT shape parses [706] as null and fail-closes every real
//     enrollment.
//
//   * IMPLICIT (primitive): the INTEGER bytes sit directly in the
//     context-tagged primitive's value block. Not observed on a real device;
//     kept as a forward-compat fallback.
export function extractOsPatchLevel(authList: any): number | null {
  if (!authList?.valueBlock?.value) return null;
  const fields = authList.valueBlock.value as any[];

  for (const f of fields) {
    const tagClass = f?.idBlock?.tagClass;
    const tagNumber = f?.idBlock?.tagNumber;
    if (tagClass !== 3 || tagNumber !== 706) continue;

    // Branch explicitly on the wire encoding: pkijs exposes EXPLICIT
    // context-tagged values as Constructed nodes (the inner Universal INTEGER
    // is a child); IMPLICIT shows up as a Primitive whose value bytes ARE the
    // INTEGER bytes.
    const isExplicit = f?.idBlock?.isConstructed === true;
    let raw: Uint8Array | null = null;

    if (isExplicit) {
      // EXPLICIT (real KeyMint shape): [706] wraps a Universal INTEGER
      // child. Assert the child IS a Universal INTEGER before reading
      // its bytes — a future encoding that swaps in a different inner
      // type would otherwise read attacker-controlled bytes as an
      // integer. The sanity bound below catches downstream nonsense
      // values too, but defending at the type boundary is cheaper.
      const children = f.valueBlock?.value as any[] | undefined;
      const innerInt = children?.[0];
      const innerTagClass = innerInt?.idBlock?.tagClass;
      const innerTagNumber = innerInt?.idBlock?.tagNumber;
      // Universal class (1) + tag number 2 == ASN.1 INTEGER.
      if (innerTagClass !== 1 || innerTagNumber !== 2) return null;
      const innerHex = innerInt?.valueBlock?.valueHexView as
        | Uint8Array
        | undefined;
      if (innerHex && innerHex.length) {
        raw = new Uint8Array(innerHex);
      } else {
        const ab = innerInt?.valueBlock?.valueHex as ArrayBuffer | undefined;
        if (ab) raw = new Uint8Array(ab);
      }
    } else {
      // IMPLICIT (forward-compat fallback): bytes sit directly in the
      // [706] primitive's value block.
      const hexView = f.valueBlock?.valueHexView as Uint8Array | undefined;
      if (hexView && hexView.length) {
        raw = new Uint8Array(hexView);
      } else {
        const ab = f.valueBlock?.valueHex as ArrayBuffer | undefined;
        if (ab) raw = new Uint8Array(ab);
      }
    }

    if (!raw || !raw.length) return null;

    // Big-endian unsigned decode. osPatchLevel is at most YYYYMMDD ≈ 2^24,
    // well within the safe integer range; no BigInt needed. Multiplication
    // (rather than `<< 8 | byte`) avoids the JS bitwise-op Int32 cast and
    // the sign-bit footgun for malformed inputs whose top bit is set —
    // such inputs would still be sanity-bounded below, but the multiply
    // form makes that obvious at the call site.
    let value = 0;
    for (let i = 0; i < raw.length; i++) {
      value = value * 256 + raw[i];
    }

    // Normalize YYYYMMDD → YYYYMM. The Keymaster spec is "YYYYMM" but a
    // small fraction of pre-2018 devices emit the day component too;
    // dropping the trailing two digits gives the comparable form without
    // re-implementing date parsing here.
    if (value >= 1_000_000_0) {
      value = Math.floor(value / 100);
    }

    // Sanity bound: YYYYMM must fall in [2000_01, 2100_12]. Anything
    // outside is a malformed leaf. Returning null surfaces it as "no
    // patch-level field" → the os patch row fails.
    if (value < 200001 || value > 210012) return null;
    return value;
  }
  return null;
}
