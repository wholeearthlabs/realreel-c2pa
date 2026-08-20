import PhotoAttestModule from './PhotoAttestModule';
import { normalizeMediaPath } from './mediaPath';

export { normalizeMediaPath };

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
 * sets the code via `CodedException(code, message, cause)` on Android and the
 * `PhotoAttestError` Exception subclass on iOS — never
 * `promise.reject(code, message)`, whose message expo-modules-core discards).
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
  /** `signC2PAUpload` / `signTimestampUpdateManifest`: the parent capture is
   *  unusable as an ingredient — file missing, or its embedded JUMBF is
   *  corrupted / has no `active_manifest`. Caller should not fall back to
   *  single-stage signing (that would lie about provenance); surface a
   *  retry/recapture path instead. */
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
  | 'ASSET_NOT_FOUND'
  /** `overwriteMediaLibraryAsset`: the write-back of the stamped bytes failed
   *  for a reason other than the asset being gone — missing staged source, no
   *  editing input (iOS limited Photos access), staging copy failure, no
   *  MediaStore write access (Android). Retryable. Never C2PA_SIGN_FAILED:
   *  signing already succeeded by the time the overwrite runs. */
  | 'MEDIA_OVERWRITE_FAILED'
  /** iOS-only, `overwriteMediaLibraryAsset`: PhotoKit validated and refused
   *  the content edit; the underlying error domain + code is in the message.
   *  `PHPhotosErrorDomain 3302` is `PHPhotosErrorInvalidResource` — resource
   *  validation failed, of which a non-upright (EXIF `Orientation` ≠ 1) render
   *  is the cause we have observed, not the only possible one. Retryable in
   *  principle; whether a given cause can ever succeed depends on the cause. */
  | 'MEDIA_OVERWRITE_REJECTED';

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
   * When provided, native writes these directly into the `c2pa.metadata`
   * assertion (C2PA 2.x §18.16, JSON-LD). Photos carry XMP GPSCoordinate
   * strings ("34,16.8548N" — hemisphere folded into the value; the separate
   * `exif:GPS*Ref` fields are not in the c2pa.metadata allowed-field list).
   * Videos nest signed decimal degrees inside `Iptc4xmpExt:LocationCreated`.
   * When omitted (e.g. user denied location), native skips emitting GPS in
   * the assertion entirely.
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
     * Unix epoch milliseconds. Photos: populates `exif:GPSDateStamp` +
     * `exif:GPSTimeStamp` in UTC. Videos: ignored — IPTC `LocationCreated`
     * has no timestamp slot; capture time lives in `dc:date`. Optional.
     */
    timestampMs?: number;
  };
  /**
   * Wall-clock capture time (Unix epoch milliseconds), typically `Date.now()`
   * passed by the JS layer at sign time.
   *
   * Used **only as a final fallback** for `dc:date` in the video metadata
   * assertion. Camera-supplied values are preserved as faithfully as the
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
 * `digitalSourceType` vocabulary an action may carry: the IPTC Digital Source
 * Type NewsCodes plus the C2PA-defined additions (spec 2.4 §18.15.4.4). The
 * template-literal type keeps the value inside those two namespaces at
 * compile time; native copies the string into the action verbatim.
 */
export type DigitalSourceTypeUri =
  | `http://cv.iptc.org/newscodes/digitalsourcetype/${string}`
  | `http://c2pa.org/digitalsourcetype/${string}`;

/** The IPTC value for a plain sensor capture — the fallback callers use when
 *  the parent's own `c2pa.created` action carries no digitalSourceType. */
export const DIGITAL_SOURCE_TYPE_DIGITAL_CAPTURE =
  'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' as const;

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
 * performed. Native stamps the assertion `allActionsIncluded: true`
 * (Conformance Program v0.2, mandatory), so the list a caller supplies is a
 * signed claim that NOTHING else was done to the asset — every mutation the
 * upload path makes must be declared here or be inherent to a declared action.
 *
 * `digitalSourceType`: the Program requires it on every pre-defined action in
 * a created assertion except a named exemption list. `c2pa.orientation` and
 * `c2pa.trimmed` are not exempt and carry it as a required field; the rest of
 * this union is exempt. Callers propagate the PARENT capture's own value (its
 * `c2pa.created` digitalSourceType — a Pixel is `computationalCapture`,
 * RealReel's camera `digitalCapture`) so the type describes the content being
 * acted on; DIGITAL_SOURCE_TYPE_DIGITAL_CAPTURE is the fallback for a parent
 * that declares none. Never on `c2pa.opened` (the Program prohibits it there;
 * c2pa-rs owns that action anyway).
 *
 * Add new action codes by extending this union. Keep parameter shapes
 * minimal — verifiers don't branch on parameter contents (the trust claim
 * is hash-bound), but consistent shape helps human readers + tooling.
 * Every variant must also be on trust-core's REALREEL_UPLOAD_ALLOWED_ACTIONS
 * or the verifier hard-rejects the upload.
 *
 * Parameter keys are entity-namespaced (`org.realreel.*`): C2PA 2.x
 * §18.15.4.7 requires any parameter key that isn't one of the spec's
 * pre-defined ones (`ingredients`, `redacted`, …) to carry a dot-separated
 * entity namespace, and the conformance checker rejects bare keys
 * (`validation:no_unrecognized_custom_action_parameters`). The one
 * exception is `assertionLabel` below: it is a signing-time instruction
 * consumed by native, never manifest content.
 */
export type Stage2Action =
  /**
   * User-requested rotation correction (spec 2.4 Table 8: "Changes to the
   * direction and position of content"). Emitted as `c2pa.rotated` before
   * photo-attest 0.6.0, which is not a pre-defined action in any spec version.
   */
  | {
      action: 'c2pa.orientation';
      digitalSourceType: DigitalSourceTypeUri;
      parameters: { 'org.realreel.angle': 90 | 180 | 270 };
    }
  /**
   * Downscale, aspect ratio preserved (spec 2.4's non-editorial refinement of
   * `c2pa.resized`). Parameters are the post-transform dimensions.
   */
  | {
      action: 'c2pa.resized.proportional';
      parameters: { 'org.realreel.width': number; 'org.realreel.height': number };
    }
  | { action: 'c2pa.transcoded'; parameters?: { 'org.realreel.quality'?: number; 'org.realreel.format'?: string } }
  /** Video trim. */
  | {
      action: 'c2pa.trimmed';
      digitalSourceType: DigitalSourceTypeUri;
      parameters: { 'org.realreel.start': number; 'org.realreel.end': number };
    }
  /**
   * File-level metadata the upload path removed from the asset (spec 2.4
   * Table 8: "Modifications to asset metadata or a metadata assertion but not
   * the asset's digital content") — as opposed to `c2pa.redacted`, the removal
   * of an assertion in the PARENT MANIFEST. Emitted whenever the published
   * file lacks metadata the parent carried: the EXIF GPS block a non-precise
   * location choice strips, EXIF tags / XMP namespaces / container keys a
   * re-encode did not carry over.
   *
   * `org.realreel.removed` names each item in the app's vocabulary
   * (`exif:GPSLatitude`, `tiff:Make`, `xmpns:<namespace-uri>`, `location`,
   * `mdta:<key>`, `udta:<key>`). Disclosure, not proof — a consumer trusting
   * the list is trusting this signature. Never emit with an empty list.
   */
  | {
      action: 'c2pa.edited.metadata';
      parameters: { 'org.realreel.removed': string[] };
    }
  /**
   * Redact an assertion from the parent (Stage 1). Native expands
   * `assertionLabel` to the full JUMBF URI using the parent's URN read
   * from the Stage-1 manifest:
   *   self#jumbf=/c2pa/<parent-urn>/c2pa.assertions/<assertionLabel>
   *
   * c2pa-rs physically zero-fills the redacted assertion's JUMBF Content
   * box (per C2PA §18.x), so the assertion's payload becomes unrecoverable
   * from the uploaded file.
   *
   * Redaction is location-only, so native also stamps the action with
   * `reason: "c2pa.PII.present"` and `description: "GPS"`; callers don't
   * supply these.
   *
   * Multiple c2pa.redacted entries are allowed — one per label. Both
   * platforms translate every entry into its own redaction URI + signed
   * action, so a dual-writing parent (c2pa.metadata + legacy stds.exif)
   * can have both assertions redacted in one signing pass.
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
   * If the parent can't be read — the file is missing, or its JUMBF has no
   * manifest / corrupted bytes / MediaLibrary mangled it in transit — native
   * throws `STAGE1_PARENT_UNREADABLE`. Callers should surface a "couldn't
   * prepare upload, retry" error and fall back to a re-capture if needed; do
   * not single-stage-sign as a workaround (that would lie about provenance).
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
   * Reverse-geocoded place label (e.g. "Phoenix, AZ") signed into the
   * `org.realreel.upload` assertion, for BOTH general and precise location
   * modes. The display reads this signed label rather than a client-supplied
   * field, so the shown location is bound to the verified upload. The client
   * geocodes on-device; we only sign the string. Omitted (none mode) → no
   * location is shown.
   */
  locationLabel?: string;

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

  /**
   * Concatenated PEM trust pool — content-source CA roots plus TSA roots —
   * that c2pa-rs consults when it validates the parent ingredient during
   * this sign. Pass `CLIENT_TRUST_ANCHORS_PEM` from
   * `@realreel/c2pa-trust-core/trust-anchors`: the generated client
   * projection of the pool the RealReel verifier loads at boot, so
   * sign-time ingredient validation asserts trust only for roots the
   * server trusts publicly.
   *
   * Why it matters: the validation outcome is RECORDED into the signed
   * `c2pa.ingredient.v3` assertion's `validationResults`. Without anchors
   * the generator permanently records `signingCredential.untrusted` /
   * `timeStamp.untrusted` for parents that are in fact trusted (RealReel
   * Stage-1 captures, wrap-mode Pixel parents) — a C2PA generator-
   * conformance failure: the CA and TSA Trust Lists must be consulted at
   * ingest. Trust FAILURES against the pool are still only recorded, never
   * thrown — an unrecognized parent degrades to recorded-untrusted rather
   * than blocking the sign, and so does a pool the native c2pa build
   * cannot load (the sign falls back to anchorless with a warning log).
   *
   * Downstream contract (since the verifier's parent-binding gate): the
   * recorded results split into two roles. Cert/TSA-trust entries stay
   * advisory — the verifier re-validates chains itself. The HARD-BINDING
   * entries are ENFORCED: the verifier requires the recorded
   * `assertion.dataHash.match` / `bmffHash.match` and rejects
   * `PARENT_BINDING_FAILED` on a recorded binding failure or an absent
   * record, because this sign-time record is the only artifact carrying
   * the parent-bytes verdict once upload transforms discard the original.
   * The sign itself still never throws on it.
   *
   * Pass it consistently (always or never within a process): iOS applies
   * settings process-globally with merge semantics, so anchors from an
   * earlier anchored sign can linger and color a later unanchored sign's
   * recorded results. RealReel's app always passes the bundle.
   *
   * Omitted / undefined → ingredient validation runs without trust
   * verification (no trust codes recorded; pre-cutover manifests recorded
   * untrusted certs here).
   */
  trustAnchorsPem?: string;
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
  /**
   * Same trust pool as {@link SignC2PAUploadOptions.trustAnchorsPem}, for the
   * parent (Stage-1) manifest this Update Manifest incorporates. Same
   * record-only semantics; omitted → anchorless validation.
   */
  trustAnchorsPem?: string;
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
    locationLabel: string | null;
    captureTimestampMs: number | null;
    claimThumbnailPath: string | null;
    attestationEnvelope: AttestationEnvelope | null;
    tsaUrl: string | null;
    trustAnchorsPem: string | null;
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
    trustAnchorsPem: string | null;
  }): Promise<SignTimestampUpdateManifestResult>;
  /**
   * Overwrite an existing MediaLibrary asset's bytes in place with the file at
   * `sourcePath`. Used by the TSA drain to replace a queued Stage-1 capture
   * with its stamped (Update-Manifest) version so a later upload reads the
   * timestamped chain.
   *
   * Android: the app owns the MediaStore entry (it created it via the
   * media-library `Asset.create`), so `contentResolver.openOutputStream(uri,
   * "wt")` overwrites with no user prompt. iOS: PhotoKit's
   * `PHContentEditingOutput` edit flow inside `performChanges` — prompt-free for
   * app-created assets; the pre-stamp original stays revertable (it becomes a
   * reversible edit, the only Apple-sanctioned way to mutate a library asset).
   *
   * `assetId` is an expo-media-library `Asset.id`: `ph://<localIdentifier>` on
   * iOS, a `content://` MediaStore uri on Android.
   *
   * Rejects (without mutating the asset) with ASSET_NOT_FOUND if the id no
   * longer resolves (user deleted it from the gallery between enqueue and
   * drain) so the caller can dequeue it, MEDIA_OVERWRITE_FAILED if the
   * write-back couldn't be set up, or (iOS) MEDIA_OVERWRITE_REJECTED if the
   * library refused the edit.
   */
  overwriteMediaLibraryAsset(options: {
    assetId: string;
    sourcePath: string;
  }): Promise<void>;
}

const native = PhotoAttestModule as NativeModule;

/**
 * Public API.
 *
 * Path parameters accept either a plain absolute filesystem path or a local
 * `file://` URI — pass an Expo `MediaLibrary` / `ImagePicker` / `Camera` /
 * `FileSystem` uri straight through; {@link normalizeMediaPath} converts it.
 */
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
   *    `digitalSourceType=digitalCapture` (set via Builder intent) and
   *    `allActionsIncluded: true` — the capture is signed exactly as the
   *    camera pipeline wrote it, so `c2pa.created` is the complete list.
   *  - `c2pa.metadata` (JSON-LD, C2PA 2.x §18.16): EXIF (photos) /
   *    QuickTime (videos) metadata extracted from the source file at sign
   *    time. Includes GPS if the user granted location permission and the
   *    camera wrote it.
   *  - `org.realreel.capture`: device identity (manufacturer, model, OS,
   *    app version, trust level) + capturerUuid. This is
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
   * Every assertion RealReel authors (actions, `c2pa.metadata`, the
   * `org.realreel.*` family) and every builder-generated one (ingredient,
   * thumbnails, time-stamp) is a CREATED assertion — attributed to the signer
   * (spec 2.4 §10.2.2; §18.15.2 requires the actions assertion there).
   * `claim_generator_info` carries `specVersion: "2.4.0"`.
   *
   * @param alias  Hardware key alias (must already be enrolled).
   * @param mediaPath Absolute path — or local `file://` URI — of the captured
   *   photo/video on disk. Supported extensions: jpg, jpeg, heic, mp4, mov.
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
    mediaPath: normalizeMediaPath(mediaPath),
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
   * Assertion shape (Stage 2): `c2pa.actions.v2` (the transformations, with
   * `allActionsIncluded: true` — see `Stage2Action`) plus
   * a small `org.realreel.upload` carrying only the upload-stage processing
   * context — device identity, OS / app version, trust level of THIS sign.
   * Capture context (capturerUuid, capture-side device fields) lives only in
   * the parent ingredient's `org.realreel.capture`;
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
   * @param transformedMediaPath  Absolute path — or local `file://` URI — of
   *   the post-transform file ready to upload (the asset whose bytes will end
   *   up in Storage).
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
    parentMediaPath: normalizeMediaPath(options.parentMediaPath),
    transformedMediaPath: normalizeMediaPath(transformedMediaPath),
    certChainPEM: options.certChainPEM,
    actions: options.actions,
    gps: options.gps ?? null,
    locationLabel: options.locationLabel ?? null,
    captureTimestampMs: options.captureTimestampMs ?? null,
    // `== null`, not truthiness: native hard-fails on an empty path by design,
    // and collapsing it to null here would silently drop the claim thumbnail.
    claimThumbnailPath: options.claimThumbnailPath == null
      ? null
      : normalizeMediaPath(options.claimThumbnailPath),
    attestationEnvelope: options.attestationEnvelope ?? null,
    tsaUrl: options.tsaUrl ?? null,
    trustAnchorsPem: options.trustAnchorsPem ?? null,
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
    parentMediaPath: normalizeMediaPath(options.parentMediaPath),
    certChainPEM: options.certChainPEM,
    tsaUrl: options.tsaUrl,
    trustAnchorsPem: options.trustAnchorsPem ?? null,
  }),

  /**
   * Overwrite a MediaLibrary asset's bytes in place (TSA drain: replace a
   * queued capture with its stamped version). See the native bridge contract
   * for the per-platform mechanism (Android MediaStore stream; iOS PhotoKit
   * content-edit). Rejects with ASSET_NOT_FOUND if the asset was deleted from
   * the gallery since enqueue — the drain dequeues on that — or with
   * MEDIA_OVERWRITE_FAILED / (iOS) MEDIA_OVERWRITE_REJECTED.
   */
  overwriteMediaLibraryAsset: (assetId: string, sourcePath: string) =>
    native.overwriteMediaLibraryAsset({
      assetId,
      sourcePath: normalizeMediaPath(sourcePath),
    }),
};

export default PhotoAttest;
