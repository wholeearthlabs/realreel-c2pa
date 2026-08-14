// Main verify orchestrator. Called by the /verify route handler in
// server.ts AFTER auth + SSRF + If-Match guards have passed.
//
//   1. Hand the asset bytes to c2pa-node's Reader.fromAsset() with our
//      curated trust_anchors bundle (verify_trust_list: false).
//   2. Reader returns null if no C2PA provenance is embedded → reject
//      as MANIFEST_MALFORMED.
//   3. Identify the trust source from the active manifest's
//      signature_info.issuer.
//   4. Force-wrap: the active manifest MUST be RealReel-signed. A
//      foreign-issuer active manifest (a raw single-stage Pixel capture
//      uploaded directly) is rejected — every upload must carry a
//      RealReel Stage 2. There is ONE ingestion profile (realreel).
//   5. Run the realreel profile; it returns the sanitized manifest store,
//      which the orchestrator passes back to the caller.

import {
  Reader,
  createTrustSettings,
  settingsToJson,
} from "@contentauth/c2pa-node";
import { VerifyError, VerifyErrorCode } from "./errors.js";
import type { PlayIntegrityConfig } from "./config.js";
import type { TrustConfig } from "./trust/types.js";
import { makeTrustSourceResolver } from "./trust/dispatcher.js";
import { sniffContainer } from "./container-sniff.js";
import { verifyRealReel } from "./profiles/realreel.js";
import { postgresAdapter } from "./db.js";
import type { VerifierDatastore } from "./ports.js";
import type { SanitizedManifestStore } from "./sanitize.js";
import {
  type ManifestStoreShape,
  getActiveManifest,
} from "./c2pa-shape.js";
import {
  checkCertValidityTimeBounds,
  readTsaState,
  SYSTEM_CLOCK,
  type Clock,
} from "./cert-validity.js";
import { deriveMetadata, type DerivedMetadata } from "./derive-metadata.js";
import { enforceLocationPrivacy } from "./location-privacy.js";
import {
  ALLOWED_UPLOAD_MIME_TYPES,
  type LocationLevel,
} from "@realreel/c2pa-trust-core";
import { Sentry } from "./observability.js";

export interface VerifyArgs {
  assetBytes: Buffer;
  mimeType: string;
  /** The uploader's JWT subject. Part of the verifier's HTTP request
   *  contract (server.ts parses + forwards it), but it does NOT gate
   *  verification: the verifier is user-anonymous. Stage-2 attestation
   *  forces own-key signing; the enrollment-time user_id↔key_id link is the
   *  revocation handle, not an upload-time check. Retained for telemetry. */
  expectedUserId: string;
  /** The uploader's declared location choice, forwarded UNSIGNED from the
   *  request (server.ts validates it). Drives the location-privacy gate: a
   *  non-precise level forbids any GPS in the bytes or the signed assertion.
   *  Required — no default — so a caller can't silently skip the check. See
   *  location-privacy.ts. */
  declaredLocation: LocationLevel;
  trustConfig: TrustConfig;
  /** Optional Play Integrity config threaded through to the realreel profile
   *  for Android manifest validation. Lenient when undefined (profile accepts
   *  the structural envelope but skips the JWS decode); set in production via
   *  PLAY_INTEGRITY_PACKAGE_NAME + PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER. */
  playIntegrityConfig?: PlayIntegrityConfig;
  /** When true, the realreel profile requires Stage 2 upload-time attestation
   *  matching the signing-key platform (iOS → app_attest, Android →
   *  play_integrity). When false, the lenient gate applies:
   *  validate-if-present, accept-if-absent. Set from ATTESTATION_REQUIRED. */
  attestationRequired?: boolean;
  /** Optional clock for the time-bound cert-validity gates. Tests inject a
   *  fixed `now`; production defaults to SYSTEM_CLOCK. */
  clock?: Clock;
  /** Datastore adapter for the revocation lookup + attestation nonce burn
   *  (see src/ports.ts). Defaults to the Postgres-backed `postgresAdapter`;
   *  an OSS integrator injects their own VerifierDatastore here. */
  datastore?: VerifierDatastore;
}

export interface VerifyResult {
  sanitizedManifest: SanitizedManifestStore;
  /** Displayed metadata derived server-side from the verified upload — the
   *  single trust boundary for the values media.metadata / media.location /
   *  media.metadata_type hold. The edge function inserts exactly this, never a
   *  client-supplied field. See derive-metadata.ts. */
  derived: DerivedMetadata;
  /** Per-profile dedup key derived from the verified capture + signed upload
   *  extent. The edge function writes it to media.content_hash, whose
   *  UNIQUE(user_id, content_hash) index rejects a re-post to the same profile.
   *  See verifyRealReel / @realreel/c2pa-trust-core buildContentIdentity. */
  contentHash: string;
}

// c2pa settings for Reader.fromAsset. settingsToJson() converts our camelCase to
// c2pa-rs snake_case; without it the trustAnchors are silently ignored (every
// manifest then reports signingCredential.untrusted). verifyTimestampTrust pins
// the current c2pa-rs default.
//
// remoteManifestFetch + ocspFetch: false — the verifier makes NO outbound request
// during verification. c2pa-rs defaults remoteManifestFetch ON: an asset with no
// embedded manifest but a remote-manifest reference would make the Reader GET an
// attacker-chosen URL (SSRF). ocspFetch is off by default but pinned for the same
// reason. Both are lossless — RealReel ingests embedded manifests only and does
// revocation via the datastore, not OCSP.
export function buildVerifierSettings(trustConfig: TrustConfig): string {
  return settingsToJson({
    ...createTrustSettings({
      verifyTrustList: false,
      trustAnchors: trustConfig.trustAnchorsBundle,
    }),
    verify: {
      verifyTimestampTrust: true,
      remoteManifestFetch: false,
      ocspFetch: false,
    },
  });
}

export async function verify(args: VerifyArgs): Promise<VerifyResult> {
  const {
    assetBytes,
    mimeType,
    declaredLocation,
    trustConfig,
    playIntegrityConfig,
    attestationRequired = false,
    clock = SYSTEM_CLOCK,
    datastore = postgresAdapter,
  } = args;

  // Gate the client-supplied mimeType BEFORE it selects a c2pa-rs asset
  // handler. The edge function runs the same allowlist for a cheap 400;
  // this is the trust-boundary copy. JPEG-vs-ISOBMFF is the only handler
  // boundary to police: c2pa-rs serves every allowed ISOBMFF type
  // (mp4/mov/heic/heif) with the single BmffIO handler.
  const normalizedMime = mimeType.toLowerCase();
  if (!ALLOWED_UPLOAD_MIME_TYPES.has(normalizedMime)) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      `unsupported mimeType '${mimeType}'`,
    );
  }
  const expectedContainer =
    normalizedMime === "image/jpeg" ? "jpeg" : "isobmff";
  if (sniffContainer(assetBytes) !== expectedContainer) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      `asset bytes do not match declared mimeType '${mimeType}'`,
    );
  }

  const trustSettings = buildVerifierSettings(trustConfig);

  let reader: Reader | null;
  try {
    reader = await Reader.fromAsset(
      { buffer: assetBytes, mimeType: normalizedMime },
      trustSettings,
    );
  } catch (e) {
    // Reader throws on parse-level errors (truncated JUMBF, etc.).
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      e instanceof Error ? e.message : String(e),
    );
  }

  if (reader === null) {
    // No C2PA provenance embedded in the asset.
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "asset has no embedded C2PA provenance",
    );
  }

  // Serialize the manifest store to its plain-object form. The runtime
  // shape comes from @contentauth/c2pa-types' ManifestStore; we use
  // the narrow ManifestStoreShape from c2pa-shape.ts which captures
  // exactly what the verifier reads.
  const store = reader.json() as unknown as ManifestStoreShape;

  const issuer = readActiveIssuer(store);
  if (!issuer) {
    throw new VerifyError(
      VerifyErrorCode.MANIFEST_MALFORMED,
      "active manifest signature_info.issuer is missing",
    );
  }
  const commonName = readActiveCommonName(store);

  // One resolver for both manifests: the active lookup here, the parent
  // lookup inside verifyRealReel — so the two can't drift on matching rules.
  const resolveSource = makeTrustSourceResolver(trustConfig);
  const source = resolveSource(issuer, commonName);
  if (!source) {
    // c2pa-node validated the chain to one of our trust anchors, but the
    // issuer identity doesn't resolve to a configured source. Shouldn't
    // happen if the shared trust list, the verifier YAML, and the on-disk
    // PEMs are in sync — a "verifier misconfiguration" signal.
    throw new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      `issuer '${issuer}' does not match any configured trust source`,
    );
  }

  // Force-wrap: the ACTIVE manifest must be RealReel-signed. We dispatch on
  // verification_profile (not source.id) so a future transitional second
  // RealReel root for CA rotation — same profile, different id — still
  // ingests. A foreign-issuer active manifest (a raw single-stage Pixel
  // capture uploaded directly) is rejected here: the Pixel root stays in the
  // trust bundle ONLY to validate Pixel *parents* in wrap mode, never to
  // ingest a Pixel-active file. UNTRUSTED_ISSUER is the closest existing
  // code — the cert chain is trusted, but not as a RealReel Stage 2.
  if (source.profile !== "realreel") {
    throw new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      `active manifest issuer '${issuer}' (${source.name}) is not RealReel — ` +
        `every upload must carry a RealReel Stage 2 manifest (force-wrap); ` +
        `raw single-stage ${source.name} files are not accepted`,
    );
  }

  // Time-bound cert-validity gates 1+2: Trusted-TSA-when-present and
  // future-dated signature. Reads validation_results.activeManifest BEFORE
  // sanitize drops it. Active manifest is guaranteed present here —
  // readActiveIssuer above would have thrown otherwise. Gate 3 (the
  // ledger-backed validity window) runs inside verifyRealReel once the
  // Stage-2 ledger row is fetched, so tsaState is threaded through.
  const active = getActiveManifest(store)!;
  const tsaState = readTsaState(store);
  checkCertValidityTimeBounds({ active, tsaState, clock });

  const { sanitized, contentHash } = await verifyRealReel(
    store,
    source.id,
    resolveSource,
    playIntegrityConfig,
    attestationRequired,
    datastore,
    tsaState,
  );

  // Derive displayed metadata from the now-verified bytes + active manifest.
  // Runs only after every gate above passed, so the bytes are hash-bound and
  // the probe is sound. `active` is the Stage-2 RealReel manifest, which
  // carries c2pa.metadata (legacy stds.exif/stds.iptc for pre-cutover app
  // builds) even for a wrapped Pixel parent.
  const derived = await deriveMetadata({ assetBytes, mimeType: normalizedMime, active });

  // Location-privacy backstop (see location-privacy.ts): reject a declared-level
  // violation (non-precise upload carrying GPS) or a file-byte GPS leak; signal
  // the lesser reverse case without rejecting.
  const { displayLeak } = enforceLocationPrivacy(derived, declaredLocation);
  if (displayLeak) {
    try {
      Sentry.captureMessage("location_display_leak", {
        level: "warning",
        tags: { error_code: "LOCATION_DISPLAY_LEAK" },
      });
    } catch {
      // Telemetry is best-effort — never break the verify path.
    }
  }

  return { sanitizedManifest: sanitized, derived, contentHash };
}

// Resolve the active manifest's signature_info.issuer via the shared
// helper. See c2pa-shape.ts for the active_manifest-is-a-label rule.
function readActiveIssuer(store: ManifestStoreShape): string | null {
  return getActiveManifest(store)?.signature_info?.issuer ?? null;
}

// Resolve the active manifest's signature_info.common_name. Pinned by
// entries in TRUSTED_ISSUERS whose commonNameMatch is set (today: Pixel).
// May legitimately be absent on a manifest — identifyTrustSource treats
// null and undefined identically for the equality check.
function readActiveCommonName(store: ManifestStoreShape): string | null {
  return getActiveManifest(store)?.signature_info?.common_name ?? null;
}
