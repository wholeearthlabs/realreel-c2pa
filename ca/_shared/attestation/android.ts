// Android KeyStore attestation validation.
//
// Implements the steps from "Verifying Hardware-backed Key Pairs":
//   https://source.android.com/docs/security/features/keystore/attestation
//
// The leaf certificate of an attested key chain carries a custom extension
// (OID 1.3.6.1.4.1.11129.2.1.17) whose value is a `KeyDescription` ASN.1
// SEQUENCE. We parse just the fields we need to enforce: attestation
// challenge, security level, and attestationApplicationId.packageName.

// deno-lint-ignore-file no-explicit-any
import {
  asn1js,
  AttestationError,
  base64ToBytes,
  ctEqual,
  extractSpkiDer,
  findExtensionByOid,
  parseCertFromDer,
  parseCertFromPem,
  verifyChainToTrustedRoots,
} from "./pki.ts";
import type { Certificate } from "./pki.ts";
import { GOOGLE_HW_ATTESTATION_ROOT_PEMS } from "./roots.ts";

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
  // Our app package name (com.realreel.app).
  packageName: string;
  // What the client claimed about hardware backing. Cross-checks against the
  // attestationSecurityLevel in the cert: 'strongbox' requires SECURITY_LEVEL_STRONG_BOX,
  // 'tee' requires SECURITY_LEVEL_TEE or higher.
  expectedSecurityLevel: ExpectedSecurityLevel;
  // Minimum acceptable osPatchLevel encoded as YYYYMM (e.g. 202501 for
  // January 2025). Reject if the chain's osPatchLevel < this value.
  // Optional so existing callers (verifier suite) keep building unchanged;
  // register-signing-key passes a computed rolling-window value.
  minOsPatchLevel?: number;
}

export interface ValidateAndroidAttestationResult {
  // OS patch level extracted from the leaf cert's AuthorizationList, YYYYMM
  // canonical form. May be null when the leaf carries no patch-level field
  // (older KeyMint versions, or fields encoded in an unsupported shape).
  // When minOsPatchLevel is supplied, a null osPatchLevel is treated as
  // "older than any threshold" and rejected — fail closed.
  osPatchLevel: number | null;
}

interface KeyDescription {
  attestationVersion: number;
  attestationSecurityLevel: number;
  keymasterVersion: number;
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;
  packageNames: string[];
  // Keymaster TAG_OS_PATCH_LEVEL (tag [706]) — typically YYYYMM, sometimes
  // YYYYMMDD on older builds. Normalized to YYYYMM in extractOsPatchLevel.
  // null when the AuthorizationList doesn't carry the tag.
  osPatchLevel: number | null;
}

// Throws AttestationError on any spec violation. Resolves with parsed
// extras on success (today: osPatchLevel; future: any AuthorizationList
// field the caller needs without re-parsing the chain).
export async function validateAndroidAttestation(
  opts: ValidateAndroidAttestationOpts,
): Promise<ValidateAndroidAttestationResult> {
  if (!Array.isArray(opts.certChainBase64) || opts.certChainBase64.length < 2) {
    throw new AttestationError(
      "ATTESTATION_DECODE_FAILED",
      "expected cert chain of length >= 2",
    );
  }

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
  await verifyChainToTrustedRoots(chain, googleRoots()).catch((e) => {
    throw new AttestationError(
      "CHAIN_INVALID",
      e instanceof Error ? e.message : String(e),
    );
  });

  const leaf = chain[0];

  // === Step 3: find KeyDescription extension on leaf, parse it ===
  const ext = findExtensionByOid(leaf, OID_ANDROID_KEY_DESCRIPTION_V300) ??
    findExtensionByOid(leaf, OID_ANDROID_KEY_DESCRIPTION_LEGACY);
  if (!ext) {
    throw new AttestationError(
      "KEY_DESCRIPTION_MISSING",
      "leaf cert has no Android key attestation extension (tried v3 + legacy OIDs)",
    );
  }
  const desc = parseKeyDescription(ext);

  // === Step 4: attestationChallenge must match server-issued challenge ===
  if (!ctEqual(desc.attestationChallenge, opts.challenge)) {
    throw new AttestationError(
      "CHALLENGE_MISMATCH",
      "attestationChallenge in cert does not match server challenge",
    );
  }

  // === Step 5: security levels must be hardware-backed ===
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

  // === Step 6: cross-check claimed platform vs actual security level ===
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

  // === Step 7: leaf public key (SPKI DER) must match what client claims ===
  const leafSpki = extractSpkiDer(leaf);
  if (!ctEqual(leafSpki, opts.sePublicKey)) {
    throw new AttestationError(
      "PUBLIC_KEY_MISMATCH",
      "leaf cert public key does not match claimed sePublicKey",
    );
  }

  // === Step 8: packageName in attestationApplicationId must match ours ===
  if (!desc.packageNames.includes(opts.packageName)) {
    throw new AttestationError(
      "PACKAGE_NAME_MISMATCH",
      `package name "${opts.packageName}" not in attestation`,
    );
  }

  // === Step 9: enrollment patch-gate ===
  // Reject Android attestations whose leaf-cert osPatchLevel is older than the
  // supplied threshold. iOS has no equivalent signal; the caller skips this
  // by omitting minOsPatchLevel.
  enforcePatchGate(desc.osPatchLevel, opts.minOsPatchLevel);

  // === Step 10 (deferred): check Google's revocation list ===
  // Fetch https://android.googleapis.com/attestation/status (with a cache) and
  // reject any revoked cert serial in the chain. Rare in practice for
  // unrevoked devices.

  return { osPatchLevel: desc.osPatchLevel };
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

  // packageNames live inside attestationApplicationId at tag [709] in either
  // softwareEnforced or hardwareEnforced (typically softwareEnforced).
  const packageNames = extractPackageNames(softwareEnforced) ??
    extractPackageNames(hardwareEnforced) ?? [];

  const osPatchLevel = selectOsPatchLevel(hardwareEnforced, softwareEnforced);

  return {
    attestationVersion,
    attestationSecurityLevel,
    keymasterVersion,
    keymasterSecurityLevel,
    attestationChallenge,
    packageNames,
    osPatchLevel,
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
// attestationApplicationId field. Its value is an OCTET STRING wrapping a
// SEQUENCE { SET OF SEQUENCE { OCTET STRING packageName, INTEGER version }, ... }.
// Returns the list of packageName strings, or null if not found.
function extractPackageNames(authList: any): string[] | null {
  if (!authList?.valueBlock?.value) return null;
  const fields = authList.valueBlock.value as any[];

  for (const f of fields) {
    // Looking for [709] EXPLICIT — context-class (3), tag number 709.
    const tagClass = f?.idBlock?.tagClass;
    const tagNumber = f?.idBlock?.tagNumber;
    if (tagClass !== 3 || tagNumber !== 709) continue;

    // Inside [709] is an OCTET STRING; inside that is a SEQUENCE.
    const inner = f.valueBlock?.value as any[] | undefined;
    if (!inner || !inner.length) return null;

    const octetNode = inner[0];
    const octetBytes = readOctetString(octetNode);
    if (!octetBytes.length) return null;

    const ab = octetBytes.buffer.slice(
      octetBytes.byteOffset,
      octetBytes.byteOffset + octetBytes.byteLength,
    ) as ArrayBuffer;
    const decoded = asn1js.fromBER(ab);
    if (decoded.offset === -1) return null;

    const aidSeq = decoded.result;
    const aidFields = (aidSeq as any).valueBlock?.value as any[] | undefined;
    if (!aidFields || !aidFields.length) return null;

    // First field is SET OF SEQUENCE { OCTET STRING packageName, INTEGER version }.
    const pkgSet = aidFields[0];
    const pkgEntries = pkgSet?.valueBlock?.value as any[] | undefined;
    if (!pkgEntries) return null;

    const names: string[] = [];
    for (const entry of pkgEntries) {
      const entryFields = entry?.valueBlock?.value as any[] | undefined;
      if (!entryFields || !entryFields.length) continue;
      const nameBytes = readOctetString(entryFields[0]);
      if (nameBytes.length) {
        names.push(new TextDecoder().decode(nameBytes));
      }
    }
    return names;
  }
  return null;
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
      const innerHex = innerInt?.valueBlock?.valueHexView as Uint8Array | undefined;
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
    // outside is a malformed leaf (or a far-future date that the rolling-
    // window check would reject anyway). Returning null surfaces it as
    // "no patch-level field" → the caller's fail-closed branch rejects.
    if (value < 200001 || value > 210012) return null;
    return value;
  }
  return null;
}

/**
 * Pick the leaf cert's osPatchLevel given both AuthorizationList halves.
 *
 * KeyMint v3+ MANDATES that TAG_OS_PATCH_LEVEL ([706]) live in the
 * hardwareEnforced list, but older Keymaster v2 attestations carry it only in
 * softwareEnforced. Both lists sit inside the same signed leaf, so
 * prefer-hardware-first is about KeyMint version compatibility, not a per-list
 * trust tier. Returns null when neither list carries the field (the caller's
 * fail-closed branch then rejects).
 */
export function selectOsPatchLevel(
  hardwareEnforced: unknown,
  softwareEnforced: unknown,
): number | null {
  return extractOsPatchLevel(hardwareEnforced) ??
    extractOsPatchLevel(softwareEnforced);
}

/**
 * Apply the enrollment patch-gate threshold rule. Throws
 * AttestationError('ATTESTATION_STALE_PATCH') iff a threshold is supplied AND
 * the device fails it. Two failure modes:
 *
 *   - osPatchLevel is null (no [706] tag): fail closed — a malformed /
 *     pre-Keymaster-v3 leaf can't prove the device meets the gate.
 *   - osPatchLevel < minOsPatchLevel: strict less-than (a device patched
 *     exactly at the threshold is ACCEPTED).
 *
 * Resolves when no threshold is supplied (the iOS path omits minOsPatchLevel,
 * since App Attest carries no OS patch signal) or when the device passes.
 */
export function enforcePatchGate(
  osPatchLevel: number | null,
  minOsPatchLevel: number | undefined,
): void {
  if (minOsPatchLevel === undefined) return;
  if (osPatchLevel === null) {
    throw new AttestationError(
      "ATTESTATION_STALE_PATCH",
      "leaf cert has no osPatchLevel (AuthorizationList tag [706]); cannot prove device meets the enrollment patch-gate",
    );
  }
  if (osPatchLevel < minOsPatchLevel) {
    throw new AttestationError(
      "ATTESTATION_STALE_PATCH",
      `device osPatchLevel ${osPatchLevel} < required ${minOsPatchLevel} (YYYYMM)`,
    );
  }
}
