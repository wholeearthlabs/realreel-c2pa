import PhotoAttestModule from './PhotoAttestModule';

/**
 * Hardware-backed signing key + platform attestation.
 *
 * iOS: ECDSA P-256 keypair inside the Secure Enclave. Attestation via
 * `DCAppAttestService` returns a CBOR blob the server validates against
 * Apple's App Attest CA. The SE private key never leaves the chip.
 *
 * Android: ECDSA P-256 keypair inside AndroidKeyStore. StrongBox-backed when
 * available (Pixel 3+, Galaxy S20+, etc.), TEE fallback otherwise.
 * Attestation is the certificate chain returned by KeyStore — the leaf cert
 * carries the Key Attestation extension that the server validates against
 * Google's hardware attestation root.
 */

export type Platform = 'ios' | 'android-strongbox' | 'android-tee';

export interface GenerateKeyResult {
  /** Base64-encoded SubjectPublicKeyInfo (DER). Drop straight into `crypto.subtle.importKey('spki', ...)`. */
  publicKey: string;
  platform: Platform;
}

export interface AttestationResult {
  /**
   * iOS: base64-encoded App Attest object (CBOR).
   * Android: JSON string — array of base64-encoded DER certificates (root → ... → leaf).
   */
  attestation: string;
  /**
   * iOS: the App Attest key id (separate from the SE signing key); the server needs it to verify the attestation.
   * Android: echoes the keystore alias for symmetry.
   */
  keyId: string;
  platform: Platform;
}

export interface GenerateAndAttestKeyResult extends GenerateKeyResult {
  attestation: string;
  keyId: string;
}

/**
 * Error codes thrown by native. JS callers should branch on `error.code`
 * (Expo modules surface native errors as `Error` instances; the native side
 * sets the code via `Promise.reject(code, message, ...)` on Android and
 * `promise.reject(code, message)` on iOS).
 */
export type PhotoAttestErrorCode =
  | 'HARDWARE_UNAVAILABLE'
  | 'APP_ATTEST_UNAVAILABLE'
  | 'APP_ATTEST_FAILED'
  | 'KEY_NOT_FOUND'
  | 'KEY_ALREADY_EXISTS'
  | 'ATTESTATION_FAILED'
  | 'CERT_GENERATION_FAILED'
  | 'INVALID_CAPTURE_CONTEXT'
  | 'UNSUPPORTED_FORMAT'
  | 'C2PA_SIGN_FAILED'
  | 'CERT_KEY_MISMATCH'
  /** Stage 2 only: parent file's embedded JUMBF cannot be read (missing,
   *  corrupted, or no `active_manifest` field). Caller should not fall back
   *  to single-stage signing — that would lie about provenance. Surface a
   *  retry/recapture path to the user instead. */
  | 'STAGE1_PARENT_UNREADABLE'
  /** Android-only: Play Integrity Standard token request failed
   *  (prepareIntegrityToken or requestIntegrityToken returned a Google-side
   *  error — offline, Play services unavailable, project misconfigured, etc.).
   *  Capture-time the JS layer retries with backoff; persistent failure
   *  surfaces a "Play Integrity unavailable, try again later" toast. */
  | 'PLAY_INTEGRITY_FAILED'
  /** `overwriteMediaLibraryAsset`: the MediaLibrary asset id no longer resolves
   *  — the user deleted the queued capture from the gallery between enqueue and
   *  drain. The drain treats this as "dequeue and move on," never an error. */
  | 'ASSET_NOT_FOUND';

/**
 * Stage-2 (upload) iOS App Attest envelope (one arm of {@link AttestationEnvelope}).
 * Embedded into the upload C2PA manifest as the `org.realreel.app_attest`
 * assertion, hash-bound by COSE so a tampered runtime can't strip or swap it.
 *
 * The JS layer obtains the trio by:
 *   1. Fetching a fresh server-issued single-use challenge via
 *      the app's attestation-challenge cache.
 *   2. Reading the persisted App Attest keyId from enrollment via
 *      the app's enrollment client.
 *   3. Calling `PhotoAttest.generateCaptureAttestation(alias, keyId, challenge)`
 *      which returns the CBOR assertion bytes.
 */
export interface AppAttestEnvelope {
  /** Discriminator — distinguishes iOS App Attest from Android Play Integrity
   *  at the native bridge level. Both platforms ship the same bridge field
   *  name (`attestationEnvelope`); each native dispatches on this value. */
  platform: 'ios';
  /** The App Attest keyId (iOS) persisted at enrollment. */
  keyId: string;
  /** Server-issued single-use nonce (base64). Burned by the verifier on accept. */
  challenge: string;
  /** Base64 CBOR App Attest assertion bound to `SHA256(challenge || SE_SPKI)`. */
  assertion: string;
}

/**
 * Stage-2 (upload) Android Play Integrity envelope (other arm of {@link AttestationEnvelope}).
 * Embedded into the upload C2PA manifest as the `org.realreel.play_integrity`
 * assertion (parallel namespace to iOS's `org.realreel.app_attest`); the
 * verifier branches on assertion label to pick the platform validator.
 *
 * The JS layer obtains the pair by:
 *   1. Fetching a fresh server-issued single-use challenge via
 *      `fetchSingleChallenge` (upload is online by definition).
 *   2. Calling `PhotoAttest.generatePlayIntegrityToken(alias, challenge)`
 *      which returns the JWS token bytes Google signs with verdicts
 *      (PLAY_RECOGNIZED, MEETS_DEVICE_INTEGRITY) bound to
 *      `SHA256(challenge || SPKI)` via the `requestHash` field. The
 *      Google Cloud project number is a compile-time const inside the
 *      native module (not a JS-passed parameter).
 */
export interface PlayIntegrityEnvelope {
  /** Discriminator — see {@link AppAttestEnvelope.platform}. */
  platform: 'android';
  /** Server-issued single-use nonce (base64). Burned by the verifier on accept. */
  challenge: string;
  /** Play Integrity JWS token (compact serialization). Decoded by the verifier
   *  via Google's `decodeIntegrityToken` server API. */
  token: string;
}

/**
 * Discriminated union of platform-specific attestation envelopes. The bridge
 * sends the same field on both platforms and each native side dispatches by
 * inspecting the `platform` discriminator. Mismatched envelopes (an Android
 * envelope on iOS or vice versa) fail loud with INVALID_CAPTURE_CONTEXT
 * rather than silently being dropped.
 */
export type AttestationEnvelope = AppAttestEnvelope | PlayIntegrityEnvelope;

/**
 * Options the caller provides at capture time. Caller-supplied because the
 * cert chain is the CA-issued PEM returned by `register-signing-key` at
 * enrollment and stored in `user_signing_keys.leaf_cert_pem` server-side —
 * the same bytes must reach c2pa-rs at sign time so verifiers can chain it
 * up to the published RealReel root. Native fills in everything else
 * (device identity, app version, OS version, trust level) from values JS
 * cannot lie about.
 */
export interface SignC2PACaptureOptions {
  cameraFacing: 'front' | 'back';
  /**
   * The PEM cert chain returned by `register-signing-key` at enrollment
   * (server-issued: leaf signed by the KMS-resident RealReel intermediate,
   * followed by the intermediate itself; leaf-first). The leaf wraps the
   * hardware key for `alias`. Native rejects with CERT_KEY_MISMATCH if the
   * leaf cert's pubkey does not match the keystore key.
   */
  certChainPEM: string;
  /**
   * The signed-in user's UUID; written into `org.realreel.capture` for
   * display attribution (resolved to a username at render time via profile
   * lookup — the assertion itself only carries the UUID). NOT a security
   * claim: anyone with a stolen signed file can upload it, so this is not
   * enforced at upload time. The cryptographic claim of the assertion is
   * "this device signed this content"; the UUID is informational alongside.
   *
   * Native rejects with INVALID_CAPTURE_CONTEXT if empty. Verifiers walk
   * the parent chain to find this on Stage-2 manifests (per C2PA §15.11);
   * Stage-2 itself does not re-emit capture context.
   */
  capturerUuid: string;
  /**
   * Optional GPS coords from the JS layer (typically `Location.LocationObjectCoords`).
   *
   * When provided, native writes these directly into the `stds.exif` (photos)
   * or `stds.iptc` (videos) assertion in decimal-degree format with explicit
   * refs ("N"/"S"/"E"/"W"). When omitted (e.g. user denied location), native
   * skips emitting GPS in the assertion entirely.
   *
   * Source-of-truth split: this field populates the C2PA assertion. The file's
   * own EXIF GPS bytes are written separately by the caller (RealReel:
   * `injectRealReelExif` / `injectVideoMetadata` in the capture path). The two
   * paths are independent — neither depends on the other — so a broken EXIF
   * round-trip on either platform can't silently impoverish the assertion.
   *
   * Background (RealReel-specific): on Android, AndroidX `ExifInterface.latLong`
   * silently returns null after piexifjs writes well-formed GPS rationals,
   * which left Android manifests stripped of GPS while iOS (via ImageIO) was
   * fine. Decoupling the assertion from the readback removes that asymmetry.
   *
   * Non-finite values (NaN/±Infinity) for any field are silently skipped at
   * the native layer rather than throwing — capture should never hard-fail
   * because of an upstream Location-service quirk.
   */
  gps?: {
    /** Decimal degrees, signed (positive=N, negative=S). */
    latitude: number;
    /** Decimal degrees, signed (positive=E, negative=W). */
    longitude: number;
    /** Meters, signed (positive=above sea level, negative=below). Optional. */
    altitude?: number;
    /**
     * Unix epoch milliseconds. Photos (`stds.exif`): populates
     * `exif:GPSDateStamp` + `exif:GPSTimeStamp` in UTC. Videos (`stds.iptc`):
     * ignored — IPTC `LocationCreated` has no timestamp slot; capture time
     * lives in `dc:date`. Optional.
     */
    timestampMs?: number;
  };
  /**
   * Wall-clock capture time (Unix epoch milliseconds), typically `Date.now()`
   * passed by the JS layer at sign time.
   *
   * Used **only as a final fallback** for `dc:date` in the video assertion
   * (`stds.iptc`). Camera-supplied values are preserved as faithfully as the
   * platform API allows; this field never substitutes a different value when
   * the camera wrote one. Fallback chain:
   *
   *   1. File metadata atom — iOS `commonKey.creationDate` returns a typed
   *      `Date` which we serialize as ISO 8601 UTC (Apple gives no literal
   *      camera string to preserve); Android `METADATA_KEY_DATE` returns a
   *      string and is passed through verbatim. Behavior asymmetry is an
   *      artifact of platform API choices, not a deliberate parity decision.
   *   2. iOS only: `AVAsset.creationDate` (separate Apple API surface;
   *      sometimes catches what (1) misses). Same Date → ISO 8601 serialization.
   *   3. This field, formatted as ISO 8601 UTC.
   *
   * Photos have no analogue — they derive their creation timestamp from EXIF
   * (`exif:DateTimeOriginal`) which the device camera populates reliably.
   * Omitting this option is safe; native simply skips the fallback.
   */
  captureTimestampMs?: number;

  /**
   * RFC 3161 Time-Stamp Authority URL. Stage-1 (capture) analogue of
   * {@link SignC2PAUploadOptions.tsaUrl}. When set, c2pa-rs (via
   * c2pa-ios / c2pa-android) fetches a TSA token over the COSE signature
   * at sign time and embeds it in the COSE unprotected header (`sigTst2`),
   * anchoring the capture's "signed at" claim to a trusted external clock
   * so a Stage-1 manifest still verifies after its leaf cert expires.
   *
   * Unlike Stage 2 (always online), capture can happen offline. The JS
   * layer decides: online → pass a TSA URL; offline → omit. On a TSA
   * fetch failure when online, the JS orchestrator re-signs WITHOUT a
   * TSA and enqueues the asset for a later Update-Manifest stamp — a TSA
   * outage must never fail the capture itself (the bytes are already
   * hardware-signed; the timestamp is an archival add-on).
   *
   * Omitted / undefined → no TSA token embedded (the unstamped Stage-1 that the
   * queue drain later promotes via `c2pa.time-stamp`).
   */
  tsaUrl?: string;
}

export interface SignC2PACaptureResult {
  /**
   * Absolute path to the C2PA-signed media file under
   * `<appSupport>/c2pa-staging/<uuid>/realreel-<localtime>.<ext>`. Native owns
   * the directory lifecycle — Stage 2 deletes the dir after a successful
   * upload. There is no sidecar manifest: Stage 2 reads the parent ingredient
   * directly out of this file via c2pa-rs's Reader.
   */
  signedMediaPath: string;

  /**
   * The active manifest's URN (`active_manifest` from c2pa-rs's Reader), read
   * back from the freshly-signed file. The offline TSA queue records this so
   * the drain can build an Update Manifest whose `c2pa.time-stamp` assertion is
   * keyed by it.
   *
   * Empty string if the read-back failed — capture is NOT failed over an
   * unreadable URN (the bytes are already signed + saved), so callers must
   * treat `''` as "unknown" and re-derive it from the asset at drain time.
   */
  manifestId: string;
}

/**
 * Discriminated union of allowed Stage-2 action codes (for `signC2PAUpload`).
 *
 * Each entry maps to one C2PA action emitted in the `c2pa.actions.v2`
 * assertion. TypeScript enforces correct parameter shape per action at
 * compile time — typo'd action codes or wrong parameter names won't
 * type-check.
 *
 * `c2pa.opened` is intentionally absent from this union — c2pa-rs auto-injects
 * it when `BuilderIntent.Edit` is used with a `parentOf` ingredient (the
 * Stage-2 path). Callers list only the transformations they actually
 * performed.
 *
 * Add new action codes by extending this union. Keep parameter shapes
 * minimal — verifiers don't branch on parameter contents (the trust claim
 * is hash-bound), but consistent shape helps human readers + tooling.
 */
export type Stage2Action =
  | { action: 'c2pa.rotated';    parameters: { angle: 90 | 180 | 270 } }
  | { action: 'c2pa.resized';    parameters: { width: number; height: number } }
  | { action: 'c2pa.transcoded'; parameters?: { quality?: number; format?: string } }
  | { action: 'c2pa.cropped';    parameters: { x: number; y: number; width: number; height: number } }
  | { action: 'c2pa.trimmed';    parameters: { start: number; end: number } }
  /**
   * Redact an assertion from the parent (Stage 1). Native expands
   * `assertionLabel` to the full JUMBF URI using the parent's URN read
   * from the Stage-1 manifest:
   *   self#jumbf=/c2pa/<parent-urn>/c2pa.assertions/<assertionLabel>
   *
   * c2pa-rs physically zero-fills the redacted assertion's JUMBF Content
   * box (per C2PA §18.x), so the assertion's payload becomes unrecoverable
   * from the uploaded file.
   */
  | { action: 'c2pa.redacted';   parameters: { assertionLabel: string } };

export interface SignC2PAUploadOptions {
  /** Same as Stage 1 — the server-issued cert chain (leaf + RealReel intermediate) from enrollment. */
  certChainPEM: string;

  /**
   * Absolute path to the Stage-1 signed file (gallery copy) being treated
   * as the parent ingredient. Native opens it via c2pa-rs's `Reader`,
   * extracts the active manifest's URN, and embeds it as a `parentOf`
   * ingredient via `Builder.addIngredient` plus `BuilderIntent.Edit`.
   * c2pa-rs auto-injects `c2pa.opened` referring to the parent.
   *
   * If reading the parent's JUMBF fails (no manifest, corrupted bytes,
   * MediaLibrary mangled the file in transit), native throws
   * `STAGE1_PARENT_UNREADABLE`. Callers should surface a "couldn't prepare
   * upload, retry" error and fall back to a re-capture if needed; do not
   * single-stage-sign as a workaround (that would lie about provenance).
   */
  parentMediaPath: string;

  /**
   * Ordered list of transformations applied between Stage 1 and Stage 2.
   * Native emits as `c2pa.actions.v2` assertion, with c2pa-rs's auto-injected
   * `c2pa.opened` prepended. Each entry's parameter shape is enforced at
   * compile time via the discriminated union.
   *
   * For an empty list, the manifest's actions assertion contains only the
   * implicit `c2pa.opened` (i.e. "this is a re-sign of the parent with
   * no transformations beyond opening it").
   */
  actions: Stage2Action[];

  /** Same shape as Stage 1 — populates the assertion's GPS for the transformed file. */
  gps?: SignC2PACaptureOptions['gps'];
  /**
   * Wall-clock upload time (Unix epoch milliseconds). Distinct from Stage 1's
   * `captureTimestampMs` semantically — at Stage 2 this is "when we re-signed,"
   * not "when the user took the photo." Used **only as a final fallback** for
   * `dc:date` in the video assertion, identical fallback chain to Stage 1's
   * field (file metadata atom → AVAsset.creationDate iOS-only → this).
   *
   * In practice the transformed video typically inherits the parent's
   * `commonKey.creationDate` / `METADATA_KEY_DATE` through the upload
   * pipeline, so layer 1 wins and this field is unused. Provided for defense
   * in depth.
   *
   * Never overrides parent metadata. Photos derive `exif:DateTimeOriginal`
   * from EXIF directly, so this option is video-only in effect.
   */
  captureTimestampMs?: number;

  /**
   * Optional path to a JPEG/PNG to embed as the manifest's claim thumbnail
   * (`c2pa.thumbnail.claim`). Typically the user's selected video poster
   * frame from the upload UI. Skipped for photos (where the asset itself
   * IS the thumbnail).
   *
   * Distinct from the *ingredient* thumbnail (which represents the parent
   * Stage-1 asset and is auto-generated by c2pa-rs from the parent file
   * stream). The claim thumbnail represents this Stage-2 asset.
   */
  claimThumbnailPath?: string;

  /**
   * Per-upload platform attestation envelope. Stage 2 fetches a fresh
   * server-issued challenge (via the app's attestation-challenge cache)
   * right before signing — at upload
   * time we're online by definition, for the tightest possible replay
   * window. iOS embeds an App Attest assertion ({@link AppAttestEnvelope});
   * Android a Play Integrity token ({@link PlayIntegrityEnvelope}). The
   * verifier validates the envelope and burns its single-use nonce.
   * (Stage-1 capture no longer carries an attestation envelope.)
   */
  attestationEnvelope?: AttestationEnvelope;

  /**
   * RFC 3161 Time-Stamp Authority URL. When set, c2pa-rs (via c2pa-ios /
   * c2pa-android) fetches a TSA token over the COSE signature at sign
   * time and embeds it in the COSE unprotected header (`sigTst2`). The
   * verifier uses the TSA `genTime` instead of upload `now` when
   * validating cert validity — so a Stage 2 signed under a cert that
   * later expires still verifies, and the asset's "signed at" claim is
   * externally anchored rather than self-asserted.
   *
   * Stage 2 is always online (uploads require network), so the TSA
   * fetch is in-band. Native passes this through unchanged; the
   * underlying wrapper handles the HTTP round-trip and COSE assembly.
   * On TSA fetch failure (network error, 5xx, untrusted cert), the
   * whole sign fails with C2PA_SIGN_FAILED — JS callers handle
   * provider fallback (e.g. DigiCert → SSL.com) at the wrapper layer.
   *
   * Omitted / undefined → no TSA token embedded.
   */
  tsaUrl?: string;
}

export interface SignC2PAUploadResult {
  /**
   * Absolute path to the C2PA-signed Stage-2 file under
   * `<appSupport>/c2pa-staging/<uuid>/realreel-<localtime>.<ext>`. Distinct
   * staging dir from the parent's. The parent file in the gallery is never
   * touched. The caller's upload flow uploads this file to Storage, then
   * deletes the staging dir.
   */
  signedMediaPath: string;
}

export interface SignTimestampUpdateManifestOptions {
  /** Same server-issued cert chain (leaf + RealReel intermediate) from
   *  enrollment that Stage 1 / Stage 2 use. The Update Manifest is signed by
   *  the device's own hardware key (no separate timestamp-service cert). */
  certChainPEM: string;
  /**
   * Absolute path to the queued Stage-1 capture file (the gallery asset's
   * current bytes, resolved via `MediaLibrary.getAssetInfoAsync().localUri`).
   * Read as the Update Manifest's signing source: with `BuilderIntent.Update`,
   * c2pa-rs auto-incorporates the source asset's existing (Stage-1) manifest as
   * the parent — NO explicit `addIngredient` is needed (confirmed against
   * c2pa-rs `sdk/tests/timestamp_assertion.rs`).
   */
  parentMediaPath: string;
  /**
   * RFC 3161 TSA URL. With `auto_timestamp_assertion { enabled, fetch_scope:
   * "parent" }` loaded into c2pa settings AND a signer carrying this TSA URL,
   * c2pa-rs fetches a timestamp token over the PARENT's (Stage-1's) COSE
   * signature and bakes a `c2pa.time-stamp` assertion (keyed by the Stage-1
   * URN) into the Update Manifest. This is the offline-drain analogue of the
   * inline `sigTst2` an online capture embeds — same provider stack
   * (DigiCert → SSL.com), provider-fallback handled JS-side by the caller via
   * `withTsaFallback`. On TSA fetch failure the sign throws
   * `C2PA_SIGN_FAILED`; the caller retries the alternate provider then leaves
   * the entry queued for a later drain (the gallery asset is never mutated
   * until a stamp succeeds — see `overwriteMediaLibraryAsset`).
   */
  tsaUrl: string;
}

export interface SignTimestampUpdateManifestResult {
  /**
   * Absolute path to the stamped file under `<appSupport>/c2pa-staging/<uuid>/`
   * — the original Stage-1 content with the manifest store now carrying the
   * interposed Update Manifest (active) → Stage-1 (parentOf). The caller
   * overwrites the gallery asset with this via {@link overwriteMediaLibraryAsset},
   * then deletes the staging dir. The gallery asset is untouched until that
   * overwrite, so a failed sign never corrupts or drops the saved capture.
   */
  signedMediaPath: string;
  /**
   * The Update Manifest's URN (the active manifest of the stamped file), read
   * back via the existing `extractActiveManifestUrn` helper. Empty string if
   * the read-back failed (non-fatal — the stamp itself succeeded). Surfaced
   * for the drain's success event + diagnostics.
   */
  manifestId: string;
}

interface NativeModule {
  isHardwareSupported(): Promise<boolean>;
  isAppAttestAvailable(): Promise<boolean>;
  hasKey(alias: string): Promise<boolean>;
  deleteKey(alias: string): Promise<void>;
  generateKey(alias: string): Promise<GenerateKeyResult>;
  getPublicKey(alias: string): Promise<string>;
  getAttestation(alias: string, challengeBase64: string): Promise<AttestationResult>;
  generateAndAttestKey(
    alias: string,
    challengeBase64: string,
  ): Promise<GenerateAndAttestKeyResult>;
  generateCSR(alias: string): Promise<string>;
  generateCaptureAttestation(
    alias: string,
    appAttestKeyId: string,
    challengeBase64: string,
  ): Promise<{ assertion: string }>;
  /**
   * Android-only. Produces a Play Integrity Standard JWS token bound to
   * `SHA256(challenge || SPKI)` via the request's `requestHash` field.
   * No iOS implementation exists — JS callers branch on `Platform.OS`
   * before invoking, so this method is never called on iOS. (Calling it
   * on iOS would surface a "method not found" bridge error, not the
   * documented INVALID_CAPTURE_CONTEXT path.)
   *
   * The Google Cloud project number that issues these tokens is a compile-
   * time const inside the Android module (`CLOUD_PROJECT_NUMBER` in
   * PhotoAttestModule.kt), NOT a runtime parameter — the value is
   * app-identity-bound and never varies across environments. See the
   * const's comment block for the deploy steps. If the const is unset
   * (0L sentinel), this call throws INVALID_CAPTURE_CONTEXT, which the
   * JS retry layer treats as a permanent failure.
   */
  generatePlayIntegrityToken(
    alias: string,
    challengeBase64: string,
  ): Promise<{ token: string }>;
  /**
   * Bridged as a single options object (mirror of signC2PAUpload); both
   * platforms unpack from this map. Capture is a single-pass sign with no
   * embedded per-capture attestation (device trust is established at enrollment
   * + re-proven at Stage-2 upload).
   */
  signC2PACapture(options: {
    alias: string;
    mediaPath: string;
    cameraFacing: 'front' | 'back';
    certChainPEM: string;
    capturerUuid: string;
    gps: SignC2PACaptureOptions['gps'] | null;
    captureTimestampMs: number | null;
    tsaUrl: string | null;
  }): Promise<SignC2PACaptureResult>;
  /**
   * Bridged as a single options object — Expo modules' AsyncFunction lambda
   * caps at 8 typed params on Android and Stage 2 sits right at the cap.
   * Kept as a map (rather than reverting to positional) for the typed JS
   * options shape and to leave headroom if a deferred field (e.g.
   * uploaderUuid) is ever added. Both platforms unpack from this map in
   * their `AsyncFunction("signC2PAUpload")` handlers.
   */
  signC2PAUpload(options: {
    alias: string;
    parentMediaPath: string;
    transformedMediaPath: string;
    certChainPEM: string;
    actions: Stage2Action[];
    gps: SignC2PACaptureOptions['gps'] | null;
    captureTimestampMs: number | null;
    claimThumbnailPath: string | null;
    attestationEnvelope: AttestationEnvelope | null;
    tsaUrl: string | null;
  }): Promise<SignC2PAUploadResult>;
  /**
   * Offline-queue drain. Wraps a queued Stage-1 capture in a C2PA Update
   * Manifest carrying a `c2pa.time-stamp` over the Stage-1 COSE signature,
   * signed by the device's hardware key for `alias`. The TSA token is fetched
   * inside c2pa-rs (auto_timestamp_assertion + the signer's tsaUrl) — JS owns
   * only provider fallback + queue/triggers. Writes a stamped file to staging;
   * the caller overwrites the gallery asset with it.
   */
  signTimestampUpdateManifest(options: {
    alias: string;
    parentMediaPath: string;
    certChainPEM: string;
    tsaUrl: string;
  }): Promise<SignTimestampUpdateManifestResult>;
  /**
   * Overwrite an existing MediaLibrary asset's bytes in place with the file at
   * `sourcePath`. Used by the TSA drain to replace a queued Stage-1 capture
   * with its stamped (Update-Manifest) version so a later upload reads the
   * timestamped chain.
   *
   * Android: the app owns the MediaStore entry (it created it via
   * createAssetAsync), so `contentResolver.openOutputStream(uri, "wt")`
   * overwrites with no user prompt. iOS: PhotoKit's `PHContentEditingOutput`
   * edit flow inside `performChanges` — prompt-free for app-created assets;
   * the pre-stamp original stays revertable (it becomes a reversible edit, the
   * only Apple-sanctioned way to mutate a library asset).
   *
   * Rejects (without mutating the asset) with ASSET_NOT_FOUND if the id no
   * longer resolves (user deleted it from the gallery between enqueue and
   * drain) so the caller can dequeue it.
   */
  overwriteMediaLibraryAsset(options: {
    assetId: string;
    sourcePath: string;
  }): Promise<void>;
}

const native = PhotoAttestModule as NativeModule;

export const PhotoAttest = {
  /** True if the device exposes a hardware-backed keystore (Secure Enclave on iOS, AndroidKeyStore w/ EC + attestation on Android). */
  isHardwareSupported: () => native.isHardwareSupported(),

  /**
   * iOS: `DCAppAttestService.shared.isSupported`. False on the simulator and on iOS < 14.
   * Android: returns true when hardware attestation is available (API 24+).
   */
  isAppAttestAvailable: () => native.isAppAttestAvailable(),

  hasKey: (alias: string) => native.hasKey(alias),
  deleteKey: (alias: string) => native.deleteKey(alias),

  /**
   * Generate a P-256 keypair without attestation. Useful for iOS-only flows
   * (key rotation, re-attestation) where attestation is fetched separately.
   * On Android, prefer `generateAndAttestKey` — Android cannot retroactively
   * attach an attestation challenge to an existing key.
   */
  generateKey: (alias: string) => native.generateKey(alias),

  getPublicKey: (alias: string) => native.getPublicKey(alias),

  /**
   * Attest an existing key. iOS-only — Android throws ATTESTATION_FAILED
   * because Android attestation must be requested at key-generation time.
   */
  getAttestation: (alias: string, challengeBase64: string) =>
    native.getAttestation(alias, challengeBase64),

  /**
   * Generate a key and attest it in one call. Preferred path for first-time
   * enrollment on both platforms.
   */
  generateAndAttestKey: (alias: string, challengeBase64: string) =>
    native.generateAndAttestKey(alias, challengeBase64),

  /**
   * Mints a PKCS#10 CertificationRequest (PEM) carrying the hardware-backed
   * public key for `alias`, self-signed with the same key (proof-of-possession).
   *
   * Output: PEM block beginning `-----BEGIN CERTIFICATE REQUEST-----`.
   * Subject: standard 5-RDN structure (C / ST / O / OU / CN) sourced from the
   *   native modules' shared identity constants, with `CN=RealReel-CSR` as a
   *   debug-only marker — the RealReel CA edge function (`register-signing-key`)
   *   ignores the CSR subject entirely and writes its own server-determined DN
   *   at issuance.
   * Algorithm: ecdsa-with-SHA256 (P-256), matching the SE/StrongBox key.
   *
   * Usage: single-use. Mint, post to `register-signing-key` together with the
   * platform attestation, receive the CA-issued leaf chain (leaf + RealReel
   * intermediate) back, discard the CSR. The leaf chain (not the CSR) is what
   * gets cached locally and passed to `signC2PACapture` on every sign.
   */
  generateCSR: (alias: string) => native.generateCSR(alias),

  /**
   * Produce a Stage-2 (upload) platform attestation assertion bound to a
   * server-issued single-use challenge. The returned assertion is embedded
   * into the upload C2PA manifest as `org.realreel.app_attest` (iOS) so the
   * verifier can prove the signing event came from an unmodified RealReel
   * app on a hardware-attested device. (Capture no longer embeds attestation;
   * the name is retained for the existing native bridge entry point.)
   *
   * iOS: produces a CBOR-encoded `DCAppAttestService.generateAssertion`
   * blob. Local Secure-Enclave operation, no network required.
   * `clientDataHash = SHA256(challenge_bytes || SE_pubkey_SPKI_bytes)`.
   *
   * Android: rejects with APP_ATTEST_UNAVAILABLE. Android uses Play
   * Integrity via a separate native call (generatePlayIntegrityToken).
   */
  generateCaptureAttestation: (
    alias: string,
    appAttestKeyId: string,
    challengeBase64: string,
  ) => native.generateCaptureAttestation(alias, appAttestKeyId, challengeBase64),

  /**
   * Android-only Play Integrity counterpart of {@link generateCaptureAttestation}.
   * Throws on iOS (and rejects with APP_ATTEST_UNAVAILABLE on web). Bound to
   * `SHA256(challenge || SPKI)` via the request's `requestHash` field —
   * structurally parallel to iOS App Attest's `clientDataHash`. The Google
   * Cloud project number is a compile-time const in the Android module; see
   * the bridge interface above for the rationale.
   *
   * Per-call retry is the JS caller's responsibility; native makes a single
   * Play Integrity request and surfaces the failure code unchanged. See
   * `lib/perCaptureAttestation.ts` for the retry-with-backoff path.
   */
  generatePlayIntegrityToken: (
    alias: string,
    challengeBase64: string,
  ) => native.generatePlayIntegrityToken(alias, challengeBase64),

  /**
   * Stage 1 of two-stage C2PA signing. Hashes the captured media, builds a
   * C2PA manifest, and signs it with the hardware-backed key for `alias`.
   * The signed manifest is embedded directly into the output media file
   * (no sidecar). Stage 2 (`signC2PAUpload`) reads the parent ingredient from
   * this file at upload time.
   *
   * The cert chain (`options.certChainPEM`) MUST be the exact PEM the
   * `register-signing-key` edge function returned at enrollment (leaf +
   * RealReel intermediate), stored on the server in
   * `user_signing_keys.leaf_cert_pem`. Native compares the leaf cert's
   * pubkey against the keystore key's pubkey and throws CERT_KEY_MISMATCH
   * if they don't match (catches stale-cert bugs early).
   *
   * Manifest layout (lockstep across iOS/Android):
   *  - `c2pa.actions.v2`: single `c2pa.created` action with
   *    `digitalSourceType=digitalCapture` (set via Builder intent).
   *  - `stds.exif` (photos) / `stds.iptc` (videos): EXIF/QuickTime metadata
   *    extracted from the source file at sign time. Includes GPS if the
   *    user granted location permission and the camera wrote it.
   *  - `org.realreel.capture`: device identity (manufacturer, model, OS,
   *    app version, trust level) + cameraFacing + capturerUuid. This is
   *    the cross-platform single source of truth for "what device captured
   *    this" — Android MP4s often lack Make/Model in the file itself. The
   *    capturerUuid is `options.capturerUuid` (the signed-in user's id);
   *    Stage 2 does NOT re-emit this assertion, so the parent ingredient
   *    is the authoritative source for capturer attribution post-upload.
   *
   * Hash binding: `c2pa.hash.data` for images, `c2pa.hash.bmff` for videos —
   * c2pa-rs picks the right one based on the MIME type derived from the
   * file extension.
   *
   * @param alias  Hardware key alias (must already be enrolled).
   * @param mediaPath Absolute path to the captured photo/video on disk.
   *   Supported extensions: jpg, jpeg, heic, mp4, mov.
   * @param options See `SignC2PACaptureOptions`.
   * @returns `{ signedMediaPath }` — the path to the C2PA-signed file.
   *   Native owns the staging dir; do not move or rename. Call Stage 2
   *   on this exact path.
   */
  signC2PACapture: (
    alias: string,
    mediaPath: string,
    options: SignC2PACaptureOptions,
  ) => native.signC2PACapture({
    alias,
    mediaPath,
    cameraFacing: options.cameraFacing,
    certChainPEM: options.certChainPEM,
    capturerUuid: options.capturerUuid,
    gps: options.gps ?? null,
    captureTimestampMs: options.captureTimestampMs ?? null,
    tsaUrl: options.tsaUrl ?? null,
  }),

  /**
   * Stage 2 of two-stage C2PA signing. Re-signs a transformed asset, with the
   * Stage-1 file as a `parentOf` ingredient. Same hardware key signs both
   * stages — verifiers see an unbroken provenance chain from the original
   * capture through whatever transformations the upload flow applied (resize,
   * rotation, video trim, EXIF GPS redaction, etc.).
   *
   * c2pa-rs's `BuilderIntent.Edit` semantics handle the spec boilerplate:
   * the parent ingredient is auto-incorporated (with auto-generated thumbnail
   * + content hash) from the `parentMediaPath` stream, and `c2pa.opened`
   * is auto-prepended to the actions list. JS callers list only the
   * transformations they actually performed.
   *
   * Assertion shape (Stage 2): `c2pa.actions.v2` (the transformations) plus
   * a small `org.realreel.upload` carrying only the upload-stage processing
   * context — device identity, OS / app version, trust level of THIS sign.
   * Capture context (capturerUuid, cameraFacing, captureSource, capture-side
   * device fields) lives only in the parent ingredient's `org.realreel.capture`;
   * verifiers walk the parent chain per C2PA §10.3.2.2 + §15.11 rather than
   * expecting derived manifests to re-emit ancestor assertions. The split
   * also accommodates the future flow where the parent is a third-party
   * capture (Pixel / Leica) and only RealReel's upload-stage processing
   * belongs in this manifest.
   *
   * If the parent's embedded manifest can't be read, native throws
   * `STAGE1_PARENT_UNREADABLE` — do not fall back to single-stage signing
   * (that would lie about provenance). Surface a retry/recapture path to
   * the user instead.
   *
   * @param alias  Hardware key alias (must already be enrolled).
   * @param transformedMediaPath  Absolute path to the post-transform file
   *   ready to upload (the asset whose bytes will end up in Storage).
   * @param options  See `SignC2PAUploadOptions`. `options.parentMediaPath`
   *   points at the Stage-1 signed file from gallery.
   * @returns `{ signedMediaPath }` — path to the Stage-2 signed file in a
   *   new staging dir. Caller uploads this file then deletes the staging dir.
   */
  signC2PAUpload: (
    alias: string,
    transformedMediaPath: string,
    options: SignC2PAUploadOptions,
  ) => native.signC2PAUpload({
    alias,
    parentMediaPath: options.parentMediaPath,
    transformedMediaPath,
    certChainPEM: options.certChainPEM,
    actions: options.actions,
    gps: options.gps ?? null,
    captureTimestampMs: options.captureTimestampMs ?? null,
    claimThumbnailPath: options.claimThumbnailPath ?? null,
    attestationEnvelope: options.attestationEnvelope ?? null,
    tsaUrl: options.tsaUrl ?? null,
  }),

  /**
   * TSA drain: stamp a queued offline capture by wrapping it in a C2PA Update
   * Manifest that carries a trusted `c2pa.time-stamp` over the Stage-1
   * signature. The hardware key for `alias` signs; c2pa-rs fetches the
   * TSA token internally (auto_timestamp_assertion + the signer's tsaUrl). The
   * result is written to a staging dir — overwrite the gallery asset with it
   * via {@link overwriteMediaLibraryAsset}, then delete the staging dir.
   *
   * @param alias  Hardware key alias (the draining device's enrolled key).
   * @param options See {@link SignTimestampUpdateManifestOptions}.
   */
  signTimestampUpdateManifest: (
    alias: string,
    options: SignTimestampUpdateManifestOptions,
  ) => native.signTimestampUpdateManifest({
    alias,
    parentMediaPath: options.parentMediaPath,
    certChainPEM: options.certChainPEM,
    tsaUrl: options.tsaUrl,
  }),

  /**
   * Overwrite a MediaLibrary asset's bytes in place (TSA drain: replace a
   * queued capture with its stamped version). See the native bridge contract
   * for the per-platform mechanism (Android MediaStore stream; iOS PhotoKit
   * content-edit). Rejects with ASSET_NOT_FOUND if the asset was deleted from
   * the gallery since enqueue — the drain dequeues on that.
   */
  overwriteMediaLibraryAsset: (assetId: string, sourcePath: string) =>
    native.overwriteMediaLibraryAsset({ assetId, sourcePath }),
};

export default PhotoAttest;
