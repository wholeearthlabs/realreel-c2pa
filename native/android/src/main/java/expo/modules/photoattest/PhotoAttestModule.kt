package expo.modules.photoattest

import android.content.ContentUris
import android.content.pm.PackageManager
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.provider.MediaStore
// AndroidX (not platform) ExifInterface: see native/android/
// build.gradle for the dep declaration. The platform `android.media.ExifInterface`
// lacks TAG_LENS_MAKE / TAG_LENS_MODEL and the `latLong` Kotlin property.
import androidx.exifinterface.media.ExifInterface
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityToken
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.contentauth.c2pa.Builder
import org.contentauth.c2pa.BuilderIntent
import org.contentauth.c2pa.C2PASettings
import org.contentauth.c2pa.DigitalSourceType
import org.contentauth.c2pa.FileStream
import org.contentauth.c2pa.KeyStoreSigner
import org.contentauth.c2pa.Reader as C2PAReader
import org.contentauth.c2pa.Signer as C2PASigner
import org.contentauth.c2pa.SigningAlgorithm
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.io.StringWriter
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import java.util.Calendar
import java.util.Date
import java.util.UUID
import java.util.concurrent.TimeUnit

class PhotoAttestModule : Module() {
  private val keystore: KeyStore by lazy {
    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
  }

  // StandardIntegrityTokenProvider cache. Filled lazily on first
  // generatePlayIntegrityToken call. There's exactly one provider per
  // process because CLOUD_PROJECT_NUMBER is a compile-time const — no
  // need for a per-project map. Double-checked locking on the var below
  // gives the same exactly-once-init guarantee as ConcurrentHashMap's
  // computeIfAbsent with less ceremony.
  //
  // @Volatile is required: without it the JVM can re-order the
  // assignment such that another thread observes the var as non-null
  // but reads a partially-constructed object. With @Volatile the
  // write-then-read happens-before edge is preserved.
  @Volatile
  private var integrityProvider: StandardIntegrityTokenProvider? = null
  private val integrityProviderLock = Any()

  override fun definition() = ModuleDefinition {
    Name("PhotoAttest")

    AsyncFunction("isHardwareSupported") {
      // EC keys + key attestation in AndroidKeyStore landed in API 24 (Nougat).
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
    }

    AsyncFunction("isAppAttestAvailable") {
      // No App Attest on Android — we rely on KeyStore attestation, which
      // requires the same API 24+ floor.
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
    }

    AsyncFunction("hasKey") { alias: String ->
      keystore.containsAlias(alias)
    }

    AsyncFunction("deleteKey") { alias: String ->
      if (keystore.containsAlias(alias)) keystore.deleteEntry(alias)
    }

    AsyncFunction("generateKey") { alias: String ->
      val (platform, publicKey) = generateKeyInternal(alias, challenge = null)
      mapOf("publicKey" to publicKey, "platform" to platform)
    }

    AsyncFunction("getPublicKey") { alias: String ->
      val cert = keystore.getCertificate(alias)
        ?: throw CodedException("KEY_NOT_FOUND", "No key with alias '$alias'", null)
      Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
    }

    AsyncFunction("getAttestation") { _: String, _: String, promise: Promise ->
      // KeyStore attestation must be requested at key-generation time via
      // setAttestationChallenge — there's no API to retroactively attest an
      // existing key. Callers must use generateAndAttestKey on Android.
      promise.reject(
        "ATTESTATION_FAILED",
        "Android attestation must be requested at key generation. Use generateAndAttestKey.",
        null
      )
    }

    // Per-capture App Attest is iOS-only. Android's analogous primitive is
    // Play Integrity (Standard), exposed via generatePlayIntegrityToken below.
    // This stub keeps the bridge surface symmetric across platforms — JS
    // callers branch on platform before invoking, but the function existing on
    // both prevents accidental "method not found" errors from a mismatched build.
    AsyncFunction("generateCaptureAttestation") {
      _: String, _: String, _: String, promise: Promise ->
      promise.reject(
        "APP_ATTEST_UNAVAILABLE",
        "App Attest is iOS-only; on Android use generatePlayIntegrityToken",
        null
      )
    }

    // Per-capture Play Integrity token. Sister of iOS's generateCaptureAttestation.
    // Bound to `SHA256(challenge_bytes || spki_der_bytes)` via Play Integrity's
    // requestHash field — the same binding convention as iOS App Attest's
    // clientDataHash. The token JWS is signed by Google with verdicts
    // (PLAY_RECOGNIZED, MEETS_DEVICE_INTEGRITY). The verifier
    // (verifier/src/attestation/play_integrity.ts) decodes the JWS via Google's
    // decodeIntegrityToken server API, enforces verdicts, and burns the
    // challenge nonce single-use.
    //
    // The StandardIntegrityTokenProvider is prepared once per process (the
    // Google Cloud project number is a compile-time const, CLOUD_PROJECT_NUMBER)
    // and cached. Initial prepare can take ~1–2s on a cold device; subsequent
    // requestIntegrityToken calls are fast (~100–300ms typically).
    AsyncFunction("generatePlayIntegrityToken") {
      alias: String, challengeBase64: String, promise: Promise ->
      try {
        val token = generatePlayIntegrityTokenInternal(
          alias = alias,
          challengeBase64 = challengeBase64,
        )
        promise.resolve(mapOf("token" to token))
      } catch (e: CodedException) {
        promise.reject(e.code, e.message, e)
      } catch (e: Exception) {
        promise.reject("PLAY_INTEGRITY_FAILED", e.message ?: "Play Integrity token request failed", e)
      }
    }

    AsyncFunction("generateCSR") { alias: String ->
      generateCSRInternal(alias)
    }

    // Bridged as a single options map (mirror of signC2PAUpload). Capture is a
    // single-pass sign with no embedded per-capture attestation (device trust is
    // established at enrollment + re-proven at Stage-2 upload). Expo's
    // AsyncFunction dispatcher runs this off the main thread, so the C2PA sign
    // doesn't freeze the UI.
    AsyncFunction("signC2PACapture") { options: Map<String, Any?> ->
      val alias = options["alias"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'alias'", null)
      val mediaPath = options["mediaPath"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'mediaPath'", null)
      val certChainPEM = options["certChainPEM"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'certChainPEM'", null)
      val capturerUuid = options["capturerUuid"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'capturerUuid'", null)
      @Suppress("UNCHECKED_CAST")
      val gps = options["gps"] as? Map<String, Any?>
      val captureTimestampMs = (options["captureTimestampMs"] as? Number)?.toDouble()
      val tsaUrl = options["tsaUrl"] as? String
      signC2PACaptureInternal(
        alias, mediaPath, certChainPEM, capturerUuid, gps, captureTimestampMs, tsaUrl,
      )
    }

    // Bridged as a single options map — Expo modules' AsyncFunction lambda
    // overloads top out at 8 typed params and Stage 2 sits right at the cap.
    AsyncFunction("signC2PAUpload") { options: Map<String, Any?> ->
      val alias = options["alias"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'alias'", null)
      val parentMediaPath = options["parentMediaPath"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'parentMediaPath'", null)
      val transformedMediaPath = options["transformedMediaPath"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'transformedMediaPath'", null)
      val certChainPEM = options["certChainPEM"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'certChainPEM'", null)
      @Suppress("UNCHECKED_CAST")
      val actions = options["actions"] as? List<Map<String, Any?>> ?: emptyList()
      @Suppress("UNCHECKED_CAST")
      val gps = options["gps"] as? Map<String, Any?>
      val captureTimestampMs = (options["captureTimestampMs"] as? Number)?.toDouble()
      val claimThumbnailPath = options["claimThumbnailPath"] as? String
      @Suppress("UNCHECKED_CAST")
      val attestationEnvelope = options["attestationEnvelope"] as? Map<String, Any?>
      val tsaUrl = options["tsaUrl"] as? String
      signC2PAUploadInternal(
        alias, parentMediaPath, transformedMediaPath, certChainPEM,
        actions, gps, captureTimestampMs, claimThumbnailPath, attestationEnvelope, tsaUrl,
      )
    }

    // Stamp a queued offline capture via a c2pa.timestamp Update Manifest
    // (signed by the device hardware key; TSA token fetched inside c2pa-rs).
    // Writes a stamped file to staging; the caller overwrites the gallery asset
    // with it via overwriteMediaLibraryAsset.
    AsyncFunction("signTimestampUpdateManifest") { options: Map<String, Any?> ->
      val alias = options["alias"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'alias'", null)
      val parentMediaPath = options["parentMediaPath"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'parentMediaPath'", null)
      val certChainPEM = options["certChainPEM"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'certChainPEM'", null)
      val tsaUrl = options["tsaUrl"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'tsaUrl'", null)
      signTimestampUpdateManifestInternal(alias, parentMediaPath, certChainPEM, tsaUrl)
    }

    // Overwrite a gallery asset's bytes in place with a stamped file. The app
    // owns the MediaStore entry it created, so a "wt" output stream overwrites
    // with no user prompt. Rejects ASSET_NOT_FOUND if the asset was deleted from
    // the gallery since enqueue.
    AsyncFunction("overwriteMediaLibraryAsset") { options: Map<String, Any?> ->
      val assetId = options["assetId"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'assetId'", null)
      val sourcePath = options["sourcePath"] as? String
        ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "missing 'sourcePath'", null)
      overwriteMediaLibraryAssetInternal(assetId, sourcePath)
    }

    AsyncFunction("generateAndAttestKey") { alias: String, challengeBase64: String ->
      val challenge = Base64.decode(challengeBase64, Base64.DEFAULT)
      val (platform, publicKey) = generateKeyInternal(alias, challenge)
      val chain = keystore.getCertificateChain(alias)
        ?: throw CodedException("ATTESTATION_FAILED", "KeyStore returned no certificate chain for '$alias'", null)
      val attestation = JSONArray(
        chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
      ).toString()
      mapOf(
        "publicKey" to publicKey,
        "platform" to platform,
        "attestation" to attestation,
        "keyId" to alias,
      )
    }
  }

  private fun generateKeyInternal(alias: String, challenge: ByteArray?): Pair<String, String> {
    if (keystore.containsAlias(alias)) {
      throw CodedException("KEY_ALREADY_EXISTS", "Key with alias '$alias' already exists", null)
    }

    fun buildSpec(strongBox: Boolean): KeyGenParameterSpec {
      val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(false)
      if (challenge != null) {
        builder.setAttestationChallenge(challenge)
      }
      if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setIsStrongBoxBacked(true)
      }
      return builder.build()
    }

    val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)

    // Try StrongBox first on API 28+.
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      try {
        generator.initialize(buildSpec(strongBox = true))
        val keyPair = generator.generateKeyPair()
        return Pair(
          PLATFORM_STRONGBOX,
          Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP),
        )
      } catch (_: StrongBoxUnavailableException) {
        // fall through to TEE
      }
    }

    generator.initialize(buildSpec(strongBox = false))
    val keyPair = generator.generateKeyPair()
    return Pair(
      PLATFORM_TEE,
      Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP),
    )
  }

  // Mints a PKCS#10 CertificationRequest (PEM) carrying the StrongBox/TEE-backed
  // public key for `alias`, self-signed with the same key (proof-of-possession).
  // The RealReel CA edge function validates the self-signature + matches SPKI
  // against the attested key, then issues a CA-signed leaf cert. The CSR subject
  // is informational — the server overwrites it with its own DN at issuance, so
  // CN=RealReel-CSR (a debug marker) never appears in a published leaf.
  //
  // Signs via the AndroidKeyStoreContentSigner adapter, which bridges
  // BouncyCastle's ContentSigner contract to AndroidKeyStore's hardware-backed
  // Signature object.
  private fun generateCSRInternal(alias: String): String {
    val privateKey = keystore.getKey(alias, null) as? PrivateKey
      ?: throw CodedException("KEY_NOT_FOUND", "No key with alias '$alias'", null)
    val keystoreCert = keystore.getCertificate(alias)
      ?: throw CodedException("KEY_NOT_FOUND", "No key with alias '$alias'", null)
    val publicKey = keystoreCert.publicKey

    val subject = X500NameBuilder(BCStyle.INSTANCE)
      .addRDN(BCStyle.C, COUNTRY_NAME)
      .addRDN(BCStyle.ST, STATE_NAME)
      .addRDN(BCStyle.O, ORG_NAME)
      .addRDN(BCStyle.OU, ORG_UNIT_NAME)
      .addRDN(BCStyle.CN, "RealReel-CSR")
      .build()

    val csr = JcaPKCS10CertificationRequestBuilder(subject, publicKey)
      .build(AndroidKeyStoreContentSigner(privateKey))

    val sw = StringWriter()
    JcaPEMWriter(sw).use { it.writeObject(csr) }
    return sw.toString()
  }

  // C2PA Stage 1 (capture-time) signing — single-pass sign by the enrolled
  // hardware key, no embedded per-capture attestation. Device trust is
  // established once at enrollment (Google key attestation) and re-proven at
  // Stage-2 upload (Play Integrity).
  //
  // Sister implementation: native/ios/PhotoAttestModule.swift
  // (signC2PACaptureInternal is the canonical template). Manifest shape, action
  // codes, and assertion labels MUST stay in lockstep — the verifier treats
  // both platforms identically.
  private fun signC2PACaptureInternal(
    alias: String,
    mediaPath: String,
    certChainPEM: String,
    capturerUuid: String,
    gps: Map<String, Any?>?,
    captureTimestampMs: Double?,
    tsaUrl: String?,
  ): Map<String, String> {
    if (capturerUuid.isEmpty()) {
      throw CodedException(
        "INVALID_CAPTURE_CONTEXT",
        "capturerUuid must be non-empty",
        null,
      )
    }

    val sourceFile = File(mediaPath)
    val ext = sourceFile.extension.lowercase()
    val format = SUPPORTED_FORMATS[ext]
      ?: throw CodedException(
        "UNSUPPORTED_FORMAT",
        "Unsupported file extension '.$ext'. Supported: ${SUPPORTED_FORMATS.keys.sorted().joinToString(", ")}",
        null,
      )

    if (!sourceFile.exists()) {
      throw CodedException(
        "C2PA_SIGN_FAILED",
        "Source file does not exist: $mediaPath",
        null,
      )
    }

    // Defensive check: the cert chain we embed must wrap the SAME pubkey as
    // the hardware key we're about to sign with. Mismatch usually means the
    // caller passed a stale cert (e.g. cached from before a key rotation,
    // or wired to the wrong alias). Catching it here produces a clear error
    // instead of a silently-wrong manifest that the verifier rejects later
    // with an opaque message.
    assertCertChainMatchesKey(certChainPEM, alias)

    val mime = format.first
    val isVideo = format.second

    // Output: <filesDir>/c2pa-staging/<uuid>/media.<ext>. Native owns cleanup
    // (Stage 2 deletes the dir after a successful upload). On Android we use
    // app-internal files dir (filesDir) — appData equivalent of iOS App Support
    // since a native context is needed for cache/files paths and we don't have
    // one at module construction in the same way.
    val context = appContext.reactContext
      ?: throw CodedException("C2PA_SIGN_FAILED", "No app context available", null)
    val stagingDir = File(File(context.filesDir, "c2pa-staging"), UUID.randomUUID().toString())
    if (!stagingDir.mkdirs() && !stagingDir.isDirectory) {
      throw CodedException("C2PA_SIGN_FAILED", "Failed to create staging dir: $stagingDir", null)
    }
    // Gallery-friendly filename: `realreel-<localtime>.<ext>`. Local time
    // (not UTC) so users see the timestamp in their wall-clock zone, matching
    // every native camera app's convention (Pixel writes `PXL_YYYYMMDD_...`
    // in local time too). The UUID staging dir guarantees uniqueness
    // regardless of name collisions across rapid captures.
    val outputFileName = "realreel-${captureTimestamp()}.$ext"
    val destFile = File(stagingDir, outputFileName)

    try {
      // Single-pass sign: build the capture manifest and sign the original
      // bytes once with the enrolled key. No embedded per-capture attestation —
      // device trust is established at enrollment + re-proven at Stage-2 upload.
      val manifestJSON = buildCaptureManifestJSON(
        sourceFile = sourceFile,
        mime = mime,
        isVideo = isVideo,
        capturerUuid = capturerUuid,
        alias = alias,
        context = context,
        gps = gps,
        title = outputFileName,
        captureTimestampMs = captureTimestampMs,
      )
      signCaptureManifest(manifestJSON, sourceFile, destFile, mime, alias, certChainPEM, tsaUrl)
    } catch (e: CodedException) {
      // Clean up half-written staging dir so we don't leak empties on retry.
      // Preserve the coded error.
      stagingDir.deleteRecursively()
      throw e
    } catch (e: Exception) {
      stagingDir.deleteRecursively()
      throw CodedException("C2PA_SIGN_FAILED", e.message ?: "C2PA sign failed", e)
    }

    // Read back the active manifest's URN so the offline TSA queue can key a
    // future Update-Manifest stamp on this Stage-1 manifest. Done AFTER the sign
    // try/catch so a read-back failure never rolls back a
    // successfully-signed-and-written asset — the bytes are on disk regardless.
    // Empty string on any failure; JS treats `""` as "unknown" and re-derives
    // at drain time.
    val manifestId = readActiveManifestUrnQuietly(destFile, mime)

    return mapOf("signedMediaPath" to destFile.absolutePath, "manifestId" to manifestId)
  }

  // Open a Reader on a just-signed file and pull its active manifest URN,
  // swallowing all failures into "" — capture must never fail over an
  // unreadable read-back (see callers). Separate from extractActiveManifestUrn
  // (which throws STAGE1_PARENT_UNREADABLE for the parent-ingredient path).
  private fun readActiveManifestUrnQuietly(file: File, mime: String): String {
    var readStream: FileStream? = null
    var reader: C2PAReader? = null
    return try {
      readStream = FileStream(file, FileStream.Mode.READ)
      reader = C2PAReader.fromStream(mime, readStream)
      extractActiveManifestUrn(reader.json())
    } catch (e: Exception) {
      android.util.Log.w("PhotoAttest", "capture manifest URN read-back failed (non-fatal): ${e.message}")
      ""
    } finally {
      try { reader?.close() } catch (_: Exception) {}
      try { readStream?.close() } catch (_: Exception) {}
    }
  }

  // Sign a capture manifest into `destFile` with the hardware key for `alias`.
  // Disables c2pa-rs's post-sign verification (both trust-chain and structural
  // checks) — our leaf chains only to the RealReel CA, not a public CA, and the
  // verifier authenticates by chaining to the RealReel CA. Global setting,
  // idempotent.
  private fun signCaptureManifest(
    manifestJSON: String,
    sourceFile: File,
    destFile: File,
    mime: String,
    alias: String,
    certChainPEM: String,
    tsaUrl: String?,
  ) {
    C2PASigner.loadSettings(SIGN_SETTINGS_JSON, "json")

    var sourceStream: FileStream? = null
    var destStream: FileStream? = null
    var builder: Builder? = null
    try {
      builder = Builder.fromJson(manifestJSON)
      builder.setIntent(BuilderIntent.Create(DigitalSourceType.DIGITAL_CAPTURE))

      // TSA: when JS passes a tsaUrl (online capture), c2pa-android (via
      // c2pa-rs) fetches an RFC 3161 token over the COSE signature at sign time
      // and embeds it in the COSE unprotected header (sigTst2). Offline captures
      // pass null and stay unstamped — the JS layer enqueues them for a later
      // Update-Manifest stamp. On a TSA fetch failure the sign throws; the JS
      // orchestrator handles provider fallback and, if both fail, re-signs
      // without TSA + enqueues rather than failing the capture.
      //
      // Normalize the URL string: trim whitespace and treat empty as null.
      // Without this, an empty string would be handed to c2pa-rs as a literal ""
      // URL (a silent confusing failure). iOS does the equivalent normalization
      // so both platforms behave identically on bad input.
      val normalizedTsaUrl = tsaUrl?.trim()?.takeIf { it.isNotEmpty() }
      val signer = KeyStoreSigner.createSigner(
        algorithm = SigningAlgorithm.ES256,
        certificateChainPEM = certChainPEM,
        keyAlias = alias,
        tsaURL = normalizedTsaUrl,
      )

      sourceStream = FileStream(sourceFile, FileStream.Mode.READ)
      destStream = FileStream(destFile, FileStream.Mode.WRITE)

      builder.sign(
        format = mime,
        source = sourceStream,
        dest = destStream,
        signer = signer,
      )
    } finally {
      try { builder?.close() } catch (_: Exception) {}
      try { sourceStream?.close() } catch (_: Exception) {}
      try { destStream?.close() } catch (_: Exception) {}
    }
  }

  // TSA drain. Wrap a queued Stage-1 capture in a c2pa.timestamp Update Manifest
  // signed by the hardware key for `alias`. c2pa-rs does the heavy lifting: with
  // BuilderIntent.Update + the source asset carrying an existing manifest, it
  // auto-incorporates Stage-1 as the parent (NO explicit addIngredient — see
  // c2pa-rs sdk/tests/timestamp_assertion.rs), and with
  // UPDATE_MANIFEST_SETTINGS_JSON (auto_timestamp_assertion fetch_scope=parent)
  // + the signer's tsaURL it fetches an RFC 3161 token over the PARENT's COSE
  // signature and bakes the c2pa.timestamp assertion keyed by the Stage-1 URN.
  //
  // Output goes to a fresh staging dir; the gallery asset is NOT touched here
  // (the caller overwrites it via overwriteMediaLibraryAsset only after this
  // succeeds — so a TSA/sign failure never corrupts the saved capture).
  private fun signTimestampUpdateManifestInternal(
    alias: String,
    parentMediaPath: String,
    certChainPEM: String,
    tsaUrl: String,
  ): Map<String, String> {
    val parentFile = File(parentMediaPath)
    if (!parentFile.exists()) {
      throw CodedException("C2PA_SIGN_FAILED", "Parent file does not exist: $parentMediaPath", null)
    }
    val ext = parentFile.extension.lowercase()
    val format = SUPPORTED_FORMATS[ext]
      ?: throw CodedException("UNSUPPORTED_FORMAT", "Unsupported extension '.$ext'.", null)
    val mime = format.first

    assertCertChainMatchesKey(certChainPEM, alias)

    // Confirm the source carries a Stage-1 manifest — Update intent needs an
    // existing manifest to make the parent. Same hard-fail class as Stage 2.
    run {
      var probeReader: C2PAReader? = null
      var probeStream: FileStream? = null
      try {
        probeStream = FileStream(parentFile, FileStream.Mode.READ)
        probeReader = C2PAReader.fromStream(mime, probeStream)
        probeReader.json()
      } catch (e: Exception) {
        throw CodedException(
          "STAGE1_PARENT_UNREADABLE",
          "Failed to read Stage-1 manifest from $parentMediaPath: ${e.message}",
          e,
        )
      } finally {
        try { probeReader?.close() } catch (_: Exception) {}
        try { probeStream?.close() } catch (_: Exception) {}
      }
    }

    val context = appContext.reactContext
      ?: throw CodedException("C2PA_SIGN_FAILED", "No app context available", null)
    val outputFileName = "realreel-${captureTimestamp()}.$ext"

    val appName = "RealReel"
    val appVersion = try {
      context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0.0.0"
    } catch (_: Exception) {
      "0.0.0"
    }

    // Minimal Update Manifest definition — no assertions (c2pa-rs adds the
    // c2pa.timestamp itself) and no hard-binding (Update Manifests don't hash
    // content; the parent's binding stands).
    val manifestJSON = JSONObject().apply {
      put("claim_generator", "$appName/$appVersion")
      put(
        "claim_generator_info",
        JSONArray().put(JSONObject().apply {
          put("name", appName)
          put("version", appVersion)
        }),
      )
      put("title", outputFileName)
    }.toString()

    // TSA is REQUIRED here (the caller never drains without one). An empty URL
    // would silently produce an un-timestamped Update Manifest, defeating the
    // drain — fail loud instead.
    val normalizedTsaUrl = tsaUrl.trim().takeIf { it.isNotEmpty() }
      ?: throw CodedException("INVALID_CAPTURE_CONTEXT", "tsaUrl is empty", null)

    var stagingDir: File? = null
    var sourceStream: FileStream? = null
    var destStream: FileStream? = null
    var builder: Builder? = null
    var updateSettings: C2PASettings? = null
    val destPath: String = try {
      val dir = File(File(context.filesDir, "c2pa-staging"), UUID.randomUUID().toString())
      if (!dir.mkdirs() && !dir.isDirectory) {
        throw CodedException("C2PA_SIGN_FAILED", "Failed to create staging dir: $dir", null)
      }
      stagingDir = dir
      val destFile = File(dir, outputFileName)

      // CRITICAL: pass auto_timestamp_assertion settings EXPLICITLY to the
      // builder, NOT via the global C2PASigner.loadSettings(...) thread-local.
      // In c2pa-rs 0.79.5, Builder.maybe_add_timestamp reads `self.context()
      // .settings()` — the builder's OWN context — and a plain
      // Builder.fromJson(json) does NOT reliably inherit the global thread-local
      // settings across the Expo/JNI boundary (the global path silently left
      // auto_timestamp_assertion.enabled=false, so the c2pa.time-stamp assertion
      // was never produced — only the COSE sigTst2 on the Update Manifest's own
      // signature). The fromJson(json, settings) overload threads the settings
      // straight into the builder's context.
      updateSettings = C2PASettings.create().updateFromString(UPDATE_MANIFEST_SETTINGS_JSON, "json")

      builder = Builder.fromJson(manifestJSON, updateSettings)
      builder.setIntent(BuilderIntent.Update)

      val signer = KeyStoreSigner.createSigner(
        algorithm = SigningAlgorithm.ES256,
        certificateChainPEM = certChainPEM,
        keyAlias = alias,
        tsaURL = normalizedTsaUrl,
      )

      // Source = the Stage-1 file (its embedded manifest becomes the parent);
      // dest = the new stamped file with Stage-1 + the Update Manifest.
      sourceStream = FileStream(parentFile, FileStream.Mode.READ)
      destStream = FileStream(destFile, FileStream.Mode.WRITE)
      builder.sign(format = mime, source = sourceStream, dest = destStream, signer = signer)
      destFile.absolutePath
    } catch (e: CodedException) {
      stagingDir?.deleteRecursively()
      throw e
    } catch (e: Exception) {
      stagingDir?.deleteRecursively()
      throw CodedException("C2PA_SIGN_FAILED", e.message ?: "C2PA Update-Manifest sign failed", e)
    } finally {
      try { builder?.close() } catch (_: Exception) {}
      try { sourceStream?.close() } catch (_: Exception) {}
      try { destStream?.close() } catch (_: Exception) {}
      try { updateSettings?.close() } catch (_: Exception) {}
    }

    val manifestId = readActiveManifestUrnQuietly(File(destPath), mime)
    return mapOf("signedMediaPath" to destPath, "manifestId" to manifestId)
  }

  // TSA drain. Overwrite an app-created gallery asset's bytes in place with the
  // stamped file at `sourcePath`. The app owns the MediaStore entry it created
  // via `Asset.create`, so a "wt" (write+truncate) output stream overwrites
  // the bytes with no user prompt (scoped storage grants the owner write
  // access). Throws ASSET_NOT_FOUND if the entry is gone (deleted from the
  // gallery since enqueue) so the caller dequeues it.
  private fun overwriteMediaLibraryAssetInternal(assetId: String, sourcePath: String) {
    val source = File(sourcePath)
    if (!source.exists()) {
      throw CodedException("C2PA_SIGN_FAILED", "stamped source file does not exist: $sourcePath", null)
    }
    val context = appContext.reactContext
      ?: throw CodedException("C2PA_SIGN_FAILED", "No app context available", null)
    // expo-media-library's Asset.id is a MediaStore content:// uri; its last
    // path segment is the row id.
    val id = Uri.parse(assetId).lastPathSegment?.toLongOrNull()
      ?: throw CodedException("ASSET_NOT_FOUND", "MediaLibrary asset id is not resolvable: $assetId", null)
    // Files collection covers both images and videos, so we don't need to know
    // which from the id alone. "external" is the legacy external volume name,
    // available on all API levels (avoids the API-29 VOLUME_EXTERNAL constant).
    val uri = ContentUris.withAppendedId(MediaStore.Files.getContentUri("external"), id)

    try {
      context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
        source.inputStream().use { it.copyTo(out) }
      } ?: throw CodedException(
        "ASSET_NOT_FOUND",
        "MediaStore returned no output stream for id $assetId (asset deleted?)",
        null,
      )
    } catch (e: CodedException) {
      throw e
    } catch (e: java.io.FileNotFoundException) {
      // Entry no longer exists (deleted from gallery between enqueue and drain).
      throw CodedException("ASSET_NOT_FOUND", "MediaStore entry $assetId not found: ${e.message}", e)
    } catch (e: SecurityException) {
      // App doesn't own the entry — shouldn't happen for `Asset.create` assets.
      throw CodedException("C2PA_SIGN_FAILED", "No write access to MediaStore entry $assetId: ${e.message}", e)
    } catch (e: Exception) {
      throw CodedException("C2PA_SIGN_FAILED", "Failed to overwrite MediaStore entry $assetId: ${e.message}", e)
    }
  }

  // Stage 2. Re-signs a transformed asset with the Stage-1 file (gallery
  // copy) as a `parentOf` ingredient. c2pa-rs's BuilderIntent.Edit
  // semantics auto-incorporate the parent and auto-prepend `c2pa.opened`
  // to the actions list, so JS callers list only the transformations they
  // actually performed.
  //
  // Hard-fail policy: if the parent's embedded JUMBF can't be read,
  // STAGE1_PARENT_UNREADABLE is thrown. Callers must NOT fall back to
  // single-stage signing — that would lie about provenance.
  private fun signC2PAUploadInternal(
    alias: String,
    parentMediaPath: String,
    transformedMediaPath: String,
    certChainPEM: String,
    actions: List<Map<String, Any?>>,
    gps: Map<String, Any?>?,
    captureTimestampMs: Double?,
    claimThumbnailPath: String?,
    attestationEnvelope: Map<String, Any?>?,
    tsaUrl: String?,
  ): Map<String, String> {
    val parentFile = File(parentMediaPath)
    val transformedFile = File(transformedMediaPath)
    if (!parentFile.exists()) {
      throw CodedException(
        "C2PA_SIGN_FAILED",
        "Parent file does not exist: $parentMediaPath",
        null,
      )
    }
    if (!transformedFile.exists()) {
      throw CodedException(
        "C2PA_SIGN_FAILED",
        "Transformed file does not exist: $transformedMediaPath",
        null,
      )
    }

    val parentExt = parentFile.extension.lowercase()
    val transformedExt = transformedFile.extension.lowercase()
    val parentFormat = SUPPORTED_FORMATS[parentExt]
      ?: throw CodedException(
        "UNSUPPORTED_FORMAT",
        "Unsupported parent extension '.$parentExt'.",
        null,
      )
    val transformedFormat = SUPPORTED_FORMATS[transformedExt]
      ?: throw CodedException(
        "UNSUPPORTED_FORMAT",
        "Unsupported transformed extension '.$transformedExt'.",
        null,
      )
    val parentMime = parentFormat.first
    val transformedMime = transformedFormat.first
    val isVideo = transformedFormat.second

    assertCertChainMatchesKey(certChainPEM, alias)

    // Resolve the claim-thumbnail (mime, identifier) up-front. Hard-fail on
    // a missing-but-supplied path matches the wider hard-fail philosophy
    // (parent-unreadable etc.); silently skipping would let the manifest
    // reference a resource we never added.
    val claimThumbnailRef: Pair<String, String>? = if (claimThumbnailPath != null) {
      val thumbFile = File(claimThumbnailPath)
      if (!thumbFile.exists()) {
        throw CodedException(
          "C2PA_SIGN_FAILED",
          "Claim thumbnail file does not exist: $claimThumbnailPath",
          null,
        )
      }
      when (thumbFile.extension.lowercase()) {
        "jpg", "jpeg" -> "image/jpeg" to "claim_thumbnail.jpg"
        "png" -> "image/png" to "claim_thumbnail.png"
        else -> throw CodedException(
          "UNSUPPORTED_FORMAT",
          "Claim thumbnail must be JPEG or PNG (got '$claimThumbnailPath')",
          null,
        )
      }
    } else null

    // Read parent's embedded manifest. Hard-fail if absent/corrupted —
    // Stage 2 without a parent reference would lie about provenance.
    var parentReader: C2PAReader? = null
    var parentReadStream: FileStream? = null
    val parentManifestJSON: String = try {
      parentReadStream = FileStream(parentFile, FileStream.Mode.READ)
      parentReader = C2PAReader.fromStream(parentMime, parentReadStream)
      parentReader.json()
    } catch (e: Exception) {
      throw CodedException(
        "STAGE1_PARENT_UNREADABLE",
        "failed to read parent manifest from $parentMediaPath: ${e.message}",
        e,
      )
    } finally {
      try { parentReader?.close() } catch (_: Exception) {}
      try { parentReadStream?.close() } catch (_: Exception) {}
    }

    // The CAPTURE manifest's urn (walked past any interposed timestamp Update
    // Manifest) is the redaction target — see extractCaptureManifestUrn. On the
    // common never-offline path this equals the active-manifest urn.
    val captureURN = extractCaptureManifestUrn(parentManifestJSON)

    val context = appContext.reactContext
      ?: throw CodedException("C2PA_SIGN_FAILED", "No app context available", null)
    val outputFileName = "realreel-${captureTimestamp()}.$transformedExt"

    // Staging dir creation moved INTO the try/catch so any failure between
    // here and the final sign() rolls back the dir. Without this, a throw
    // from buildUploadManifestJSON or Builder.fromJson would leave an
    // empty staging dir behind on each retry.
    var stagingDir: File? = null
    var sourceStream: FileStream? = null
    var destStream: FileStream? = null
    var ingredientStream: FileStream? = null
    var thumbnailStream: FileStream? = null
    var builder: Builder? = null
    val signedMediaPath: String = try {
      val dir = File(File(context.filesDir, "c2pa-staging"), UUID.randomUUID().toString())
      if (!dir.mkdirs() && !dir.isDirectory) {
        throw CodedException("C2PA_SIGN_FAILED", "Failed to create staging dir: $dir", null)
      }
      stagingDir = dir
      val destFile = File(dir, outputFileName)

      val manifestJSON = buildUploadManifestJSON(
        transformedFile = transformedFile,
        transformedMime = transformedMime,
        isVideo = isVideo,
        alias = alias,
        context = context,
        gps = gps,
        captureTimestampMs = captureTimestampMs,
        title = outputFileName,
        actions = actions,
        redactionTargetUrn = captureURN,
        claimThumbnailRef = claimThumbnailRef,
        attestationEnvelope = attestationEnvelope,
      )

      // Same global verify-disabled settings as Stage 1 (auto-timestamp OFF).
      C2PASigner.loadSettings(SIGN_SETTINGS_JSON, "json")

      builder = Builder.fromJson(manifestJSON)
      builder.setIntent(BuilderIntent.Edit)

      // Add parent ingredient — c2pa-rs hashes the parent stream + auto-
      // generates the ingredient thumbnail. Minimal JSON: the rest is
      // populated by c2pa-rs from the stream contents.
      val parentIngredientJSON = JSONObject().apply {
        put("title", parentFile.name)
        put("format", parentMime)
        put("relationship", "parentOf")
      }.toString()
      ingredientStream = FileStream(parentFile, FileStream.Mode.READ)
      builder.addIngredient(parentIngredientJSON, parentMime, ingredientStream)

      // Optional claim thumbnail (user-selected video poster frame).
      // Photos: caller skips this; the asset itself IS the thumbnail.
      // File existence + format already validated above.
      if (claimThumbnailRef != null) {
        val (_, ident) = claimThumbnailRef
        thumbnailStream = FileStream(File(claimThumbnailPath!!), FileStream.Mode.READ)
        builder.addResource(ident, thumbnailStream)
      }

      // TSA: when JS passes a tsaUrl, c2pa-android (via c2pa-rs) fetches
      // an RFC 3161 token over the COSE signature at sign time and embeds
      // it in the COSE unprotected header (sigTst2). On TSA fetch failure
      // the whole sign throws — JS layer handles provider fallback
      // (DigiCert → SSL.com) at the wrapper level.
      //
      // Normalize the URL string: trim whitespace and treat empty as
      // null. Without this, passing an empty string would be handed to
      // c2pa-rs as a literal "" URL (silent confusing failure mode).
      // iOS does the equivalent normalization — match-keeps the two
      // platforms' behavior identical on bad input.
      val normalizedTsaUrl = tsaUrl?.trim()?.takeIf { it.isNotEmpty() }
      val signer = KeyStoreSigner.createSigner(
        algorithm = SigningAlgorithm.ES256,
        certificateChainPEM = certChainPEM,
        keyAlias = alias,
        tsaURL = normalizedTsaUrl,
      )

      sourceStream = FileStream(transformedFile, FileStream.Mode.READ)
      destStream = FileStream(destFile, FileStream.Mode.WRITE)

      builder.sign(
        format = transformedMime,
        source = sourceStream,
        dest = destStream,
        signer = signer,
      )

      destFile.absolutePath
    } catch (e: CodedException) {
      stagingDir?.deleteRecursively()
      throw e
    } catch (e: Exception) {
      stagingDir?.deleteRecursively()
      throw CodedException("C2PA_SIGN_FAILED", e.message ?: "C2PA sign failed", e)
    } finally {
      try { builder?.close() } catch (_: Exception) {}
      try { sourceStream?.close() } catch (_: Exception) {}
      try { destStream?.close() } catch (_: Exception) {}
      try { ingredientStream?.close() } catch (_: Exception) {}
      try { thumbnailStream?.close() } catch (_: Exception) {}
    }

    return mapOf("signedMediaPath" to signedMediaPath)
  }

  // Pull `active_manifest` (the parent's URN) out of c2pa-rs Reader's JSON.
  // Used for redaction URI expansion (`self#jumbf=/c2pa/<urn>/c2pa.assertions/<label>`).
  // Distinguishes JSON-parse failure from missing-field so debugging from
  // a STAGE1_PARENT_UNREADABLE error message points at the right cause.
  private fun extractActiveManifestUrn(readerJson: String): String {
    val parsed = try {
      JSONObject(readerJson)
    } catch (e: Exception) {
      throw CodedException(
        "STAGE1_PARENT_UNREADABLE",
        "failed to parse parent manifest JSON: ${e.message}",
        e,
      )
    }
    return parsed.optString("active_manifest").takeIf { it.isNotEmpty() }
      ?: throw CodedException(
        "STAGE1_PARENT_UNREADABLE",
        "parent has no 'active_manifest' field",
        null,
      )
  }

  // Walk past any interposed timestamp Update Manifest(s) in the parent's
  // manifest store to the real CAPTURE manifest's URN — the manifest that
  // actually carries the redactable assertions (stds.exif / stds.iptc /
  // org.realreel.capture). c2pa.redacted URIs must target THIS urn, not the
  // immediate-parent urn: for a once-offline-then-TSA-drained parent the active
  // manifest is the Update Manifest (carries a `c2pa.time-stamp` assertion + a
  // parentOf to the capture) and holds no GPS — redacting against it would miss
  // the capture's GPS and leak location. c2pa-rs permits redacting a grandparent
  // assertion through the chain (redaction.md). For a never-offline parent the
  // active manifest IS the capture, so this returns the same urn as
  // extractActiveManifestUrn (no behavior change on the common path).
  private fun extractCaptureManifestUrn(readerJson: String): String {
    val activeUrn = extractActiveManifestUrn(readerJson)
    val root = try { JSONObject(readerJson) } catch (_: Exception) { return activeUrn }
    val manifests = root.optJSONObject("manifests") ?: return activeUrn
    var cur = activeUrn
    var depth = 0
    // Cap matches the verifier + client gate (MAX_UPDATE_MANIFEST_DEPTH = 4);
    // fails open to the active urn, so it can never crash.
    while (depth < 4) {
      val m = manifests.optJSONObject(cur) ?: break
      val assertions = m.optJSONArray("assertions")
      var hasTimestamp = false
      if (assertions != null) {
        for (i in 0 until assertions.length()) {
          if (assertions.optJSONObject(i)?.optString("label") == "c2pa.time-stamp") {
            hasTimestamp = true; break
          }
        }
      }
      val ingredients = m.optJSONArray("ingredients")
      var parentLabel: String? = null
      if (ingredients != null) {
        for (i in 0 until ingredients.length()) {
          val ing = ingredients.optJSONObject(i) ?: continue
          if (ing.optString("relationship") == "parentOf") {
            parentLabel = ing.optString("active_manifest").takeIf { it.isNotEmpty() }
            break
          }
        }
      }
      // Only an interposed timestamp Update Manifest (has c2pa.time-stamp AND a
      // parentOf) is walked past; the capture (no timestamp assertion) ends it.
      if (hasTimestamp && parentLabel != null) {
        cur = parentLabel
        depth += 1
      } else {
        break
      }
    }
    return cur
  }

  private fun buildCaptureManifestJSON(
    sourceFile: File,
    mime: String,
    isVideo: Boolean,
    capturerUuid: String,
    alias: String,
    context: android.content.Context,
    gps: Map<String, Any?>?,
    title: String,
    captureTimestampMs: Double?,
  ): String {
    val appName = "RealReel"
    val appVersion = try {
      context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0.0.0"
    } catch (_: PackageManager.NameNotFoundException) {
      "0.0.0"
    }

    val assertions = JSONArray()

    if (isVideo) {
      extractIptcAssertionForVideo(sourceFile, gps, captureTimestampMs)?.let {
        assertions.put(JSONObject().put("label", "stds.iptc").put("data", it))
      }
    } else {
      extractExifAssertionForImage(sourceFile, gps)?.let {
        assertions.put(JSONObject().put("label", "stds.exif").put("data", it))
      }
    }

    val realreelCapture = JSONObject().apply {
      put("capturerUuid", capturerUuid)
      put("deviceManufacturer", Build.MANUFACTURER)
      // Build.MODEL is the marketing model (e.g. "Pixel 7"); Build.DEVICE is
      // the codename (e.g. "panther"). We use MODEL since that's the user-
      // visible identifier, but parallel apps that need the codename can
      // expand this assertion later.
      put("deviceModel", Build.MODEL)
      put("osVersion", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
      put("appVersion", appVersion)
      put("deviceTrustLevel", detectKeyTrustLevel(alias))
    }
    assertions.put(JSONObject().put("label", "org.realreel.capture").put("data", realreelCapture))

    val manifest = JSONObject().apply {
      put("claim_generator", "$appName/$appVersion")
      put("claim_generator_info", JSONArray().put(
        JSONObject().put("name", appName).put("version", appVersion)
      ))
      put("format", mime)
      put("title", title)
      put("assertions", assertions)
    }
    return manifest.toString()
  }

  // Build manifest JSON for Stage 2 (upload-time signing). Mirrors
  // buildCaptureManifestJSON but threads the JS-supplied actions list and
  // optional claim thumbnail. c2pa-rs's BuilderIntent.Edit auto-prepends
  // c2pa.opened referring to the parent ingredient, so we don't include
  // it ourselves.
  //
  // Redaction handling: any { action: "c2pa.redacted", parameters:
  // { assertionLabel } } entries are split off into the manifest's top-level
  // `redactions` array (URI form expanded via redactionTargetUrn = the CAPTURE
  // manifest's urn), AND emitted into c2pa.actions.v2 as `{ action:
  // "c2pa.redacted", reason: "c2pa.PII.present", description: "GPS",
  // parameters: { redacted: <uri> } }` so the action list stays self-describing.
  // c2pa-rs zero-fills the referenced JUMBF Content boxes during sign —
  // including a grandparent capture's assertion when an interposed timestamp
  // Update Manifest sits between Stage 2 and the capture.
  private fun buildUploadManifestJSON(
    transformedFile: File,
    transformedMime: String,
    isVideo: Boolean,
    alias: String,
    context: android.content.Context,
    gps: Map<String, Any?>?,
    captureTimestampMs: Double?,
    title: String,
    actions: List<Map<String, Any?>>,
    redactionTargetUrn: String,
    /** (mime, identifier) of the claim thumbnail to embed, or null. */
    claimThumbnailRef: Pair<String, String>?,
    attestationEnvelope: Map<String, Any?>?,
  ): String {
    val appName = "RealReel"
    val appVersion = try {
      context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "0.0.0"
    } catch (_: PackageManager.NameNotFoundException) {
      "0.0.0"
    }

    val assertions = JSONArray()

    // Build c2pa.actions.v2. JS-supplied actions get translated; redactions
    // expand the assertionLabel into a JUMBF URI.
    val actionsArray = JSONArray()
    val redactionUris = mutableListOf<String>()
    for (entry in actions) {
      val actionName = entry["action"] as? String ?: continue
      @Suppress("UNCHECKED_CAST")
      val params = entry["parameters"] as? Map<String, Any?>
      if (actionName == "c2pa.redacted") {
        val label = params?.get("assertionLabel") as? String ?: continue
        val uri = "self#jumbf=/c2pa/$redactionTargetUrn/c2pa.assertions/$label"
        redactionUris.add(uri)
        actionsArray.put(JSONObject().apply {
          put("action", actionName)
          put("reason", "c2pa.PII.present")
          put("description", "GPS")
          put("parameters", JSONObject().apply { put("redacted", uri) })
        })
      } else {
        actionsArray.put(JSONObject().apply {
          put("action", actionName)
          if (params != null) put("parameters", JSONObject(params))
        })
      }
    }
    if (actionsArray.length() > 0) {
      assertions.put(
        JSONObject()
          .put("label", "c2pa.actions.v2")
          .put("data", JSONObject().put("actions", actionsArray))
      )
    }

    // Stage-2 metadata describes the TRANSFORMED file (e.g. new dimensions).
    if (isVideo) {
      extractIptcAssertionForVideo(transformedFile, gps, captureTimestampMs)?.let {
        assertions.put(JSONObject().put("label", "stds.iptc").put("data", it))
      }
    } else {
      extractExifAssertionForImage(transformedFile, gps)?.let {
        assertions.put(JSONObject().put("label", "stds.exif").put("data", it))
      }
    }

    // org.realreel.upload describes the upload-stage processing context
    // (device + app version + trust level of whatever signed THIS manifest).
    // Capture context (capturerUuid, capture-side device fields) lives only
    // in the parent ingredient's org.realreel.capture; verifiers walk the
    // parent chain per C2PA §10.3.2.2 + §15.11 rather than expecting derived
    // manifests to re-emit ancestor assertions. This split also accommodates
    // the future flow where the parent is a third-party capture (Pixel /
    // Leica) and only RealReel's upload-stage processing belongs here.
    val realreelUpload = JSONObject().apply {
      put("deviceManufacturer", Build.MANUFACTURER)
      put("deviceModel", Build.MODEL)
      put("osVersion", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
      put("appVersion", appVersion)
      put("deviceTrustLevel", detectKeyTrustLevel(alias))
    }
    assertions.put(JSONObject().put("label", "org.realreel.upload").put("data", realreelUpload))

    playIntegrityAssertionEntry(attestationEnvelope)?.let { assertions.put(it) }

    val manifest = JSONObject().apply {
      put("claim_generator", "$appName/$appVersion")
      put("claim_generator_info", JSONArray().put(
        JSONObject().put("name", appName).put("version", appVersion)
      ))
      put("format", transformedMime)
      put("title", title)
      put("assertions", assertions)
      // Redactions array — c2pa-rs zero-fills these URIs in the parent
      // ingredient's JUMBF Content during sign.
      if (redactionUris.isNotEmpty()) {
        put("redactions", JSONArray(redactionUris))
      }
      // Claim thumbnail — references the resource added via
      // builder.addResource(<identifier>, stream). Format + identifier
      // sniffed from caller-supplied path extension upstream.
      if (claimThumbnailRef != null) {
        val (mime, ident) = claimThumbnailRef
        put("thumbnail", JSONObject().apply {
          put("format", mime)
          put("identifier", ident)
        })
      }
    }
    return manifest.toString()
  }

  // Builds the org.realreel.play_integrity assertion entry from a JS-supplied
  // envelope dict. Returns null when no envelope is supplied. Throws
  // INVALID_CAPTURE_CONTEXT when an envelope IS present but any sub-field is
  // missing — fail-loud rather than silently dropping the assertion, since a
  // lenient verifier gate tolerates a missing one and a buggy JS regression
  // would slip past.
  //
  // The verifier (verifier/src/attestation/play_integrity.ts):
  //   1. Decodes the JWS token via Google's decodeIntegrityToken server API
  //      (signature validated by Google).
  //   2. Enforces appRecognitionVerdict == PLAY_RECOGNIZED and that
  //      deviceRecognitionVerdict includes MEETS_DEVICE_INTEGRITY.
  //   3. Burns the challenge nonce single-use in attestation_challenges.
  //
  // The result is embedded as a manifest assertion so c2pa-rs's COSE_Sign1
  // hash-binds it — a tampered runtime can't strip or swap this assertion
  // without invalidating the signature.
  //
  // Sister of the Swift `appAttestAssertionEntry` helper. Parallel namespace
  // (`org.realreel.play_integrity` vs `org.realreel.app_attest`) because the
  // verifier branches on platform via the assertion label.
  private fun playIntegrityAssertionEntry(envelope: Map<String, Any?>?): JSONObject? {
    if (envelope == null) return null
    val platform = envelope["platform"] as? String
    if (platform != "android") {
      throw CodedException(
        "INVALID_CAPTURE_CONTEXT",
        "attestationEnvelope.platform must be 'android' on Android (got '${platform ?: "(missing)"}')",
        null,
      )
    }
    val token = envelope["token"] as? String
    val challenge = envelope["challenge"] as? String
    if (token.isNullOrEmpty() || challenge.isNullOrEmpty()) {
      throw CodedException(
        "INVALID_CAPTURE_CONTEXT",
        "attestationEnvelope is present but missing token / challenge",
        null,
      )
    }
    val data = JSONObject().apply {
      put("token", token)
      put("challenge", challenge)
      put("platform", "android")
    }
    return JSONObject().put("label", "org.realreel.play_integrity").put("data", data)
  }

  // Per-capture Play Integrity Standard token. Bound to
  // `SHA256(challenge_bytes || spki_der_bytes)` via the request's `requestHash`
  // field (URL-safe base64 no-pad). The SPKI binding is the same convention iOS
  // uses for App Attest clientDataHash. Today the verifier validates
  // structurally + nonce burn + JWS signature + verdicts; reconstructing the
  // requestHash from the signing leaf SPKI is deferred (the SDK doesn't expose
  // the leaf SPKI yet).
  //
  // The actual content the device is signing (the C2PA claim) is not folded
  // into requestHash — c2pa-rs's COSE_Sign1 already hash-binds every
  // assertion (including this Play Integrity result) to the file bytes via
  // `c2pa.hash.data` or `c2pa.hash.bmff`. The Play Integrity layer's job is
  // freshness + app-integrity proof, not content binding.
  //
  // The Google Cloud project number is a compile-time const (CLOUD_PROJECT_NUMBER
  // in the companion object below) — see the const's comment for why this is
  // baked in rather than env-driven.
  private fun generatePlayIntegrityTokenInternal(
    alias: String,
    challengeBase64: String,
  ): String {
    if (alias.isEmpty()) {
      throw CodedException("INVALID_CAPTURE_CONTEXT", "alias must be non-empty", null)
    }
    if (CLOUD_PROJECT_NUMBER <= 0L) {
      // Tripped when this build's CLOUD_PROJECT_NUMBER const is the unset
      // 0L sentinel. INVALID_CAPTURE_CONTEXT is mapped JS-side to a
      // permanent failure (no retry), so the dev / misconfigured-build
      // surface fails immediately with a clear toast rather than burning
      // three Play Integrity round-trips first.
      throw CodedException(
        "INVALID_CAPTURE_CONTEXT",
        "CLOUD_PROJECT_NUMBER const is unset in PhotoAttestModule.kt — fill in your Google Cloud project number before shipping",
        null,
      )
    }

    val challenge = try {
      Base64.decode(challengeBase64, Base64.DEFAULT)
    } catch (e: IllegalArgumentException) {
      throw CodedException("PLAY_INTEGRITY_FAILED", "Invalid base64 challenge: ${e.message}", e)
    }

    val keystoreCert = keystore.getCertificate(alias)
      ?: throw CodedException("KEY_NOT_FOUND", "No key with alias '$alias'", null)
    // Java's getEncoded() on a keystore-resident public key returns the SPKI
    // (SubjectPublicKeyInfo) DER bytes — the same envelope the iOS module
    // hand-rolls in spkiDerForP256. We use it verbatim so the verifier-side
    // requestHash reconstruction is byte-identical across platforms.
    val spki = keystoreCert.publicKey.encoded
      ?: throw CodedException("KEY_NOT_FOUND", "keystore cert has no encodable public key for '$alias'", null)

    // requestHash = SHA256(challenge || SPKI), then URL-safe base64 no-pad
    // (the encoding Play Integrity expects per the docs). Google round-trips
    // this exact string back in tokenPayloadExternal.requestDetails.requestHash.
    val md = MessageDigest.getInstance("SHA-256")
    md.update(challenge)
    md.update(spki)
    val requestHashBytes = md.digest()
    val requestHash = Base64.encodeToString(
      requestHashBytes,
      Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )

    val context = appContext.reactContext
      ?: throw CodedException("PLAY_INTEGRITY_FAILED", "No app context available", null)

    val provider = getOrPrepareIntegrityTokenProvider(context)
    val request = StandardIntegrityTokenRequest.builder()
      .setRequestHash(requestHash)
      .build()
    val token: StandardIntegrityToken = try {
      // Tasks.await blocks the calling thread. The Expo modules AsyncFunction
      // dispatcher runs us off the main thread by default, so this is safe —
      // an assumption load-bearing for this call NOT to freeze the UI on a
      // Google-side hang. If Expo ever flips AsyncFunction to main-thread
      // dispatch, this becomes a UI freeze.
      //
      // The timeout caps tail latency. Typical request() is 100–300ms;
      // we give it 5s for slow networks / Play services warm-up edge cases.
      // Without the timeout, a stuck Google services call would block this
      // worker thread until OS TCP-level keepalive eventually fails (minutes).
      // On timeout, Tasks.await throws TimeoutException → caught below →
      // PLAY_INTEGRITY_FAILED → JS retry layer classifies as transient.
      // Symmetric with the verifier-side decodeIntegrityToken 3s timeout.
      Tasks.await(provider.request(request), REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
    } catch (e: Exception) {
      throw CodedException(
        "PLAY_INTEGRITY_FAILED",
        "Play Integrity request failed: ${e.message}",
        e,
      )
    }
    return token.token()
  }

  // Lazily prepare-and-cache the StandardIntegrityTokenProvider.
  // `prepareIntegrityToken` is documented to take ~1–2s on cold start
  // (it warms internal Play services state); subsequent token requests
  // are fast. Exactly-once init via double-checked locking — the fast
  // path (provider already prepared) is a single volatile read with no
  // lock contention. Two simultaneous first-capture threads serialize
  // on the lock so we never double-prepare against Google's API.
  private fun getOrPrepareIntegrityTokenProvider(
    context: android.content.Context,
  ): StandardIntegrityTokenProvider {
    integrityProvider?.let { return it }
    synchronized(integrityProviderLock) {
      integrityProvider?.let { return it }
      val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
      val prepReq = PrepareIntegrityTokenRequest.builder()
        .setCloudProjectNumber(CLOUD_PROJECT_NUMBER)
        .build()
      val provider = try {
        // prepareIntegrityToken is documented to take ~1–2s on cold start
        // (Google warming internal Play services state + binding the
        // cloud project). 10s is well past the worst legitimate cold-start
        // case, short of unbounded OS keepalive hangs. Same overall pattern
        // as the request() timeout above; see that comment for the
        // Expo-threading-assumption note.
        Tasks.await(
          manager.prepareIntegrityToken(prepReq),
          PREPARE_TIMEOUT_SECONDS,
          TimeUnit.SECONDS,
        )
      } catch (e: Exception) {
        throw CodedException(
          "PLAY_INTEGRITY_FAILED",
          "prepareIntegrityToken failed for project $CLOUD_PROJECT_NUMBER: ${e.message}",
          e,
        )
      }
      integrityProvider = provider
      return provider
    }
  }

  // Parse the leaf cert (first cert) out of a PEM chain and confirm its
  // SubjectPublicKey matches the public key associated with `alias` in the
  // Android keystore. Throws CERT_KEY_MISMATCH if they differ — caller is
  // probably holding a stale enrollment cert or wired up the wrong alias.
  private fun assertCertChainMatchesKey(certChainPEM: String, alias: String) {
    val keystoreCert = keystore.getCertificate(alias)
      ?: throw CodedException(
        "CERT_KEY_MISMATCH",
        "keystore has no cert for alias '$alias'",
        null,
      )
    val expected = keystoreCert.publicKey.encoded // SPKI DER

    val factory = CertificateFactory.getInstance("X.509")
    // generateCertificates parses the entire PEM chain. The first entry is
    // the leaf — that's what c2pa-rs uses as the signing cert.
    val parsed = try {
      factory.generateCertificates(ByteArrayInputStream(certChainPEM.toByteArray(Charsets.UTF_8)))
    } catch (e: Exception) {
      throw CodedException(
        "CERT_KEY_MISMATCH",
        "failed to parse cert chain PEM: ${e.message}",
        e,
      )
    }
    val leaf = parsed.firstOrNull()
      ?: throw CodedException("CERT_KEY_MISMATCH", "cert chain PEM is empty", null)
    val actual = leaf.publicKey.encoded

    if (!expected.contentEquals(actual)) {
      throw CodedException(
        "CERT_KEY_MISMATCH",
        "leaf cert pubkey does not match keystore key for alias '$alias'. " +
          "Re-enroll or pass the cert minted at enrollment time.",
        null,
      )
    }
  }

  // Inspect the keystore key's KeyInfo to report whether it lives in StrongBox
  // (API 28+ hardware secure element) or the TEE (Trusted Execution
  // Environment, API 24+ floor). Mirrors the iOS "secure-enclave" string so
  // verifier-side dashboards can group "hardware-backed" platforms uniformly.
  private fun detectKeyTrustLevel(alias: String): String {
    return try {
      val privateKey = keystore.getKey(alias, null) as? PrivateKey ?: return "unknown"
      val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
      val info = factory.getKeySpec(privateKey, KeyInfo::class.java)
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        when (info.securityLevel) {
          KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
          KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
          KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
          else -> "unknown"
        }
      } else {
        @Suppress("DEPRECATION")
        if (info.isInsideSecureHardware) "tee" else "software"
      }
    } catch (_: Exception) {
      "unknown"
    }
  }

  // ExifInterface enumerates ~80 known tag constants. We pull the well-known
  // subset (camera, lens, exposure, orientation) and emit them under the
  // stds.exif schema's `exif:` / `tiff:` prefixes. GPS is NOT read from the
  // file — it comes from the JS-supplied `gps` map (single source of truth;
  // see `SignC2PACaptureOptions.gps` for the rationale). We don't reformat
  // non-GPS values — the verifier signs them verbatim.
  private fun extractExifAssertionForImage(file: File, gps: Map<String, Any?>?): JSONObject? {
    val exif = try { ExifInterface(file.absolutePath) } catch (_: Exception) { return null }
    val out = JSONObject()

    fun put(key: String, tag: String) {
      val v = exif.getAttribute(tag) ?: return
      if (v.isNotEmpty()) out.put(key, v)
    }

    // TIFF block
    put("tiff:Make", ExifInterface.TAG_MAKE)
    put("tiff:Model", ExifInterface.TAG_MODEL)
    put("tiff:Software", ExifInterface.TAG_SOFTWARE)
    put("tiff:Orientation", ExifInterface.TAG_ORIENTATION)
    put("tiff:DateTime", ExifInterface.TAG_DATETIME)
    put("tiff:ImageWidth", ExifInterface.TAG_IMAGE_WIDTH)
    put("tiff:ImageLength", ExifInterface.TAG_IMAGE_LENGTH)

    // Exif block
    put("exif:DateTimeOriginal", ExifInterface.TAG_DATETIME_ORIGINAL)
    put("exif:ExposureTime", ExifInterface.TAG_EXPOSURE_TIME)
    put("exif:FNumber", ExifInterface.TAG_F_NUMBER)
    put("exif:ISOSpeedRatings", ExifInterface.TAG_ISO_SPEED_RATINGS)
    put("exif:FocalLength", ExifInterface.TAG_FOCAL_LENGTH)
    put("exif:LensMake", ExifInterface.TAG_LENS_MAKE)
    put("exif:LensModel", ExifInterface.TAG_LENS_MODEL)
    put("exif:WhiteBalance", ExifInterface.TAG_WHITE_BALANCE)
    put("exif:Flash", ExifInterface.TAG_FLASH)

    emitJsGpsToExif(out, gps)

    return if (out.length() > 0) out else null
  }

  // Decimal-degree GPS straight from JS into the assertion. Lockstep with iOS:
  // identical key set, identical reference-letter derivation, identical
  // GPSAltitudeRef integer convention (0 = above sea level, 1 = below).
  // Non-finite values (NaN/Infinity) are silently skipped per field — the
  // JS layer is the source of truth, but a transient Location-service quirk
  // shouldn't hard-fail capture.
  private fun emitJsGpsToExif(out: JSONObject, gps: Map<String, Any?>?) {
    if (gps == null) return
    val lat = (gps["latitude"] as? Number)?.toDouble()?.takeIf { it.isFinite() }
    val lon = (gps["longitude"] as? Number)?.toDouble()?.takeIf { it.isFinite() }
    val alt = (gps["altitude"] as? Number)?.toDouble()?.takeIf { it.isFinite() }
    val ts = (gps["timestampMs"] as? Number)?.toLong()

    if (lat != null) {
      out.put("exif:GPSLatitude", lat)
      out.put("exif:GPSLatitudeRef", if (lat >= 0) "N" else "S")
    }
    if (lon != null) {
      out.put("exif:GPSLongitude", lon)
      out.put("exif:GPSLongitudeRef", if (lon >= 0) "E" else "W")
    }
    if (alt != null) {
      out.put("exif:GPSAltitude", alt)
      out.put("exif:GPSAltitudeRef", if (alt >= 0) 0 else 1)
    }
    if (ts != null) {
      val cal = Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC")).apply {
        timeInMillis = ts
      }
      out.put(
        "exif:GPSDateStamp",
        String.format(
          "%04d:%02d:%02d",
          cal.get(Calendar.YEAR),
          cal.get(Calendar.MONTH) + 1,
          cal.get(Calendar.DAY_OF_MONTH),
        ),
      )
      out.put(
        "exif:GPSTimeStamp",
        String.format(
          "%02d:%02d:%02d",
          cal.get(Calendar.HOUR_OF_DAY),
          cal.get(Calendar.MINUTE),
          cal.get(Calendar.SECOND),
        ),
      )
    }
  }

  // MediaMetadataRetriever pulls QuickTime/MP4 metadata. Most cheap Android
  // OEMs DON'T write Make/Model into MP4s (no ISO standard for it), so this
  // assertion is often sparse — device identity primarily lives in the
  // RealReel device-identity assertion (org.realreel.capture in Stage 1,
  // org.realreel.upload in Stage 2). Date and JS-supplied GPS are the
  // reliable fields.
  //
  // Location: we deliberately do NOT project METADATA_KEY_LOCATION (the
  // camera's ISO 6709 string, e.g. "+34.29-119.29+/") into the assertion.
  // Per IPTC Video Metadata Hub, `Iptc4xmpExt:LocationCreated` is an array
  // of structured location objects, not a flat string — putting an ISO 6709
  // string there is non-conformant. The camera's location claim is still
  // cryptographically protected by `c2pa.hash.bmff.v3` via the QuickTime
  // location atom in the file bytes; we just don't duplicate it as a
  // misshapen JSON projection. Our structured form is emitted by
  // `emitJsGpsToIptc` from JS-supplied coords below.
  //
  // dc:date fallback chain — camera-supplied values are preserved as
  // faithfully as the platform API allows; this fallback never substitutes
  // a different value when the camera wrote one:
  //   1. METADATA_KEY_DATE — Android's API returns a String, passed through
  //      verbatim (typically MMR's compact ISO 8601 like `20260509T203821.000Z`).
  //   2. (Android has no analogue to iOS AVAsset.creationDate — skipped.)
  //   3. JS-supplied `captureTimestampMs` formatted as ISO 8601 UTC.
  private fun extractIptcAssertionForVideo(
    file: File,
    gps: Map<String, Any?>?,
    captureTimestampMs: Double?,
  ): JSONObject? {
    val mmr = MediaMetadataRetriever()
    val out = JSONObject()
    var hasDate = false
    try {
      mmr.setDataSource(file.absolutePath)
      mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DATE)?.let {
        out.put("dc:date", it)
        hasDate = true
      }
      // METADATA_KEY_DURATION returns milliseconds as a string. xmpDM:duration
      // convention (what iOS emits via CMTime.seconds, what Adobe writes) is
      // seconds as a JSON number. Convert here so verifiers see the same
      // shape regardless of source platform.
      mmr.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)
        ?.toLongOrNull()
        ?.let { ms -> out.put("xmpDM:duration", ms / 1000.0) }
    } catch (_: Exception) {
      return null
    } finally {
      try { mmr.release() } catch (_: Exception) {}
    }

    if (!hasDate && captureTimestampMs != null
        && !captureTimestampMs.isNaN() && !captureTimestampMs.isInfinite()) {
      out.put("dc:date", formatIsoUtc(captureTimestampMs.toLong()))
    }

    emitJsGpsToIptc(out, gps)

    return if (out.length() > 0) out else null
  }

  // ISO 8601 UTC ("2026-05-09T13:12:41Z"). Used for the JS-supplied dc:date
  // fallback when neither the file's metadata atom nor a platform creation-
  // date API produced a value. Camera-written timestamps from layer 1 retain
  // their native format (MediaMetadataRetriever's compact `20260509T131241.000Z`).
  private fun formatIsoUtc(epochMs: Long): String {
    val sdf = java.text.SimpleDateFormat(
      "yyyy-MM-dd'T'HH:mm:ss'Z'",
      java.util.Locale.US,
    )
    sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
    return sdf.format(Date(epochMs))
  }

  // Decimal-degree GPS straight from JS into the IPTC video assertion.
  // Shape matches IPTC Video Metadata Hub's published C2PA sample — see
  // https://iptc.org/std/videometadatahub/examples/c2pa/. `LocationCreated`
  // is an array of structured location objects; GPS lives nested inside as
  // `exif:GPS{Latitude,Longitude,Altitude}` with signed decimal degrees and
  // no separate `*Ref` fields (sign carries direction).
  //
  // Lockstep with iOS — same shape, same key set. Non-finite values silently
  // skipped per field. We omit timestamp here because the IPTC LocationCreated
  // structure has no timestamp slot — capture time lives separately in
  // `dc:date`. We omit the JS `gps.timestampMs` (which carries GPS-fix time,
  // not capture time) entirely from the IPTC projection.
  private fun emitJsGpsToIptc(out: JSONObject, gps: Map<String, Any?>?) {
    if (gps == null) return
    val lat = (gps["latitude"] as? Number)?.toDouble()?.takeIf { it.isFinite() }
    val lon = (gps["longitude"] as? Number)?.toDouble()?.takeIf { it.isFinite() }
    val alt = (gps["altitude"] as? Number)?.toDouble()?.takeIf { it.isFinite() }

    // Need at least one usable coord to emit anything.
    if (lat == null && lon == null && alt == null) return

    val location = JSONObject()
    if (lat != null) location.put("exif:GPSLatitude", lat)
    if (lon != null) location.put("exif:GPSLongitude", lon)
    if (alt != null) location.put("exif:GPSAltitude", alt)

    out.put("Iptc4xmpExt:LocationCreated", JSONArray().put(location))
  }

  // Local-time YYYYMMDD-HHmmss for gallery-friendly filenames.
  private fun captureTimestamp(): String {
    return java.text.SimpleDateFormat("yyyyMMdd-HHmmss", java.util.Locale.US)
      .format(Date())
  }

  private fun pemEncode(label: String, der: ByteArray): String {
    val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
    val wrapped = b64.chunked(64).joinToString("\n")
    return "-----BEGIN $label-----\n$wrapped\n-----END $label-----\n"
  }

  private companion object {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val PLATFORM_STRONGBOX = "android-strongbox"
    const val PLATFORM_TEE = "android-tee"
    // PER-APP SWAP-POINT: CSR subject DN attributes (forker: set your own org).
    // These go into the CSR subject only — the RealReel CA OVERWRITES the leaf
    // subject DN at issuance (see ca/_shared/attestation/pki.ts), so these
    // values never appear in a published leaf cert; they're a debug marker.
    // Left a native constant (not env-driven) because a Kotlin `const val` can't
    // read env without Gradle buildConfigField plumbing. DN values must match
    // the iOS sister module exactly. The two platforms currently emit DER via
    // different paths (Android via BouncyCastle; iOS hand-rolled until the
    // swift-certificates migration lands), so cert bytes momentarily diverge —
    // but the DN attribute values themselves must agree.
    // O= is the legal organization (Whole Earth Labs, LLC); OU= is the
    // product/brand (RealReel). C= is ISO 3166 two-letter; ST= is the
    // full state name per RFC 5280 convention.
    const val COUNTRY_NAME = "US"
    const val STATE_NAME = "California"
    const val ORG_NAME = "Whole Earth Labs, LLC"
    const val ORG_UNIT_NAME = "RealReel"

    // Pair<mime, isVideo>. Mirror of iOS SUPPORTED_FORMATS — must stay in sync.
    val SUPPORTED_FORMATS: Map<String, Pair<String, Boolean>> = mapOf(
      "jpg" to ("image/jpeg" to false),
      "jpeg" to ("image/jpeg" to false),
      "heic" to ("image/heic" to false),
      "mp4" to ("video/mp4" to true),
      "mov" to ("video/quicktime" to true),
    )

    // c2pa-rs settings (global, applied via loadSettings before each sign).
    // Merge semantics mean every path must set auto_timestamp_assertion.enabled
    // EXPLICITLY — otherwise a drain that turned it on would leak into a later
    // Stage-2 upload, whose parentOf ingredient WOULD then get auto-stamped.
    // Mirror of iOS SIGN_SETTINGS_JSON / UPDATE_MANIFEST_SETTINGS_JSON.
    //
    // Capture + Stage-2 upload: auto-timestamp OFF (their TSA, when any, is the
    // inline sigTst2 c2pa-rs fetches over the CURRENT signature via the signer's
    // tsaURL — not a parent-scoped c2pa.timestamp assertion).
    const val SIGN_SETTINGS_JSON =
      """{"version":1,"verify":{"verify_trust":false,"verify_after_sign":false},"builder":{"auto_timestamp_assertion":{"enabled":false}}}"""

    // Update-Manifest drain: auto-timestamp ON with fetch_scope=parent, so
    // c2pa-rs stamps the PARENT (Stage-1) signature it auto-incorporates from
    // the source asset and bakes the c2pa.timestamp assertion. skip_existing=false
    // — a queued capture is, by definition, not yet timestamped.
    const val UPDATE_MANIFEST_SETTINGS_JSON =
      """{"version":1,"verify":{"verify_trust":false,"verify_after_sign":false},"builder":{"auto_timestamp_assertion":{"enabled":true,"skip_existing":false,"fetch_scope":"parent"}}}"""

    // Hard timeouts for the two blocking Tasks.await calls. Without these,
    // a stuck Google Play services call would pin the calling thread until
    // the OS TCP keepalive eventually fails — potentially minutes. The
    // timeouts bound that worst case to a few seconds, after which
    // Tasks.await throws TimeoutException → CodedException → JS retry
    // layer classifies as transient and either retries or soft-fails.
    //
    // PREPARE: 10s. Google docs say 1–2s typical on cold start; 10s
    //   covers slow-network warm-up edge cases.
    // REQUEST: 5s. Typical ~100–300ms; 5s for tail latency without
    //   letting a hang freeze capture.
    //
    // Symmetric with the verifier-side AbortSignal.timeout(3000) on the
    // decodeIntegrityToken call (verifier/src/attestation/play_integrity.ts).
    const val PREPARE_TIMEOUT_SECONDS: Long = 10L
    const val REQUEST_TIMEOUT_SECONDS: Long = 5L

    // PER-APP SWAP-POINT: Google Cloud project number for Play Integrity.
    // Left a native constant (not env-driven) because a Kotlin `const val`
    // can't read env without Gradle buildConfigField plumbing — a forker edits
    // the value here and rebuilds. Must equal the verifier's
    // PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER env var.
    //
    // Google Cloud project number that issues Play Integrity tokens for
    // this app build. Numeric (NOT the project ID — Google Cloud has two
    // identifiers per project; we want the numeric one, typically 12
    // digits). Hardcoded rather than env-driven because the value is
    // app-identity-bound: the same Google Cloud project that Play Console
    // links to for this package name will ALWAYS be this number, for the
    // lifetime of the app. No environment-specific variation. Same
    // pattern as ca/_shared/config.ts:ANDROID_PACKAGE_NAME.
    //
    // To deploy:
    //   1. Create a Google Cloud project (or reuse an existing one).
    //   2. In Play Console → App integrity → Play Integrity API → link the
    //      project. Copy the project number Google shows.
    //   3. Replace 0L below with that number.
    //   4. Grant the verifier's runtime service account the
    //      `roles/playintegrity.user` IAM role on this same project.
    //
    // The 0L sentinel below trips a hard "INVALID_CAPTURE_CONTEXT" error
    // at first capture attempt — surfaces as a permanent failure toast,
    // no silent degradation. Multiple flavors (dev / staging / prod
    // builds with different package names) → Gradle productFlavors with
    // different buildConfigField values; not needed today.
    //
    // Verifier-side counterpart: the verifier passes this same number as
    // PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER env var to construct the
    // decodeIntegrityToken URL. Both must match or decode fails.
    const val CLOUD_PROJECT_NUMBER: Long = 874158087818L
  }
}
