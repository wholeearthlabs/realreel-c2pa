import ExpoModulesCore
import Foundation
import Security
import CryptoKit
import DeviceCheck
import ImageIO
import AVFoundation
import UIKit
import C2PA
import X509
import Photos

public class PhotoAttestModule: Module {
  public func definition() -> ModuleDefinition {
    Name("PhotoAttest")

    AsyncFunction("isHardwareSupported") { () -> Bool in
      // Secure Enclave is present on every iOS device since A7 (iPhone 5s, 2013).
      // RealReel's iOS deployment target is 15.1 → effectively always true.
      return true
    }

    AsyncFunction("isAppAttestAvailable") { () -> Bool in
      return DCAppAttestService.shared.isSupported
    }

    AsyncFunction("hasKey") { (alias: String) -> Bool in
      return PhotoAttestModule.findKey(alias: alias) != nil
    }

    AsyncFunction("deleteKey") { (alias: String) throws in
      try PhotoAttestModule.deleteKeyInternal(alias: alias)
    }

    AsyncFunction("generateKey") { (alias: String) throws -> [String: Any] in
      let publicKey = try PhotoAttestModule.generateKeyInternal(alias: alias)
      return ["publicKey": publicKey, "platform": "ios"]
    }

    AsyncFunction("getPublicKey") { (alias: String) throws -> String in
      return try PhotoAttestModule.getPublicKeyInternal(alias: alias)
    }

    AsyncFunction("getAttestation") { (alias: String, challengeBase64: String, promise: Promise) in
      Task {
        do {
          let result = try await PhotoAttestModule.attestInternal(
            alias: alias,
            challengeBase64: challengeBase64
          )
          promise.resolve([
            "attestation": result.attestation,
            "keyId": result.keyId,
            "platform": "ios",
          ])
        } catch let err as PhotoAttestError {
          promise.reject(err.code, err.message)
        } catch {
          promise.reject("ATTESTATION_FAILED", error.localizedDescription)
        }
      }
    }

    // Stage-2 (upload) App Attest assertion. Produces a CBOR-encoded assertion
    // bound to `SHA256(challenge_bytes || spki_der_bytes)` (the clientDataHash).
    // The caller provides a server-issued single-use challenge and the
    // persisted App Attest keyId from enrollment, and embeds the returned
    // assertion into the upload C2PA `org.realreel.app_attest` assertion so the
    // verifier can validate Apple's signature chain, confirm clientDataHash
    // binds the challenge + signing key, and burn the nonce single-use.
    AsyncFunction("generateCaptureAttestation") {
      (alias: String, appAttestKeyId: String, challengeBase64: String, promise: Promise) in
      Task {
        do {
          let assertion = try await PhotoAttestModule.generateCaptureAttestationInternal(
            alias: alias,
            appAttestKeyId: appAttestKeyId,
            challengeBase64: challengeBase64
          )
          promise.resolve(["assertion": assertion])
        } catch let err as PhotoAttestError {
          promise.reject(err.code, err.message)
        } catch {
          promise.reject("APP_ATTEST_FAILED", error.localizedDescription)
        }
      }
    }

    AsyncFunction("generateCSR") { (alias: String) throws -> String in
      return try PhotoAttestModule.generateCSRInternal(alias: alias)
    }

    // Bridged as a single options dict (mirror of signC2PAUpload) for the typed
    // JS options shape. Capture is a single-pass sign with no embedded
    // per-capture attestation (device trust is established at enrollment +
    // re-proven at Stage-2 upload). Uses the Promise pattern so
    // PhotoAttestError's code/message surface to JS as the rejection's
    // code/message (Swift's NSError bridging would otherwise reduce a struct
    // Error to a generic "error 1").
    AsyncFunction("signC2PACapture") { (options: [String: Any], promise: Promise) in
      do {
        guard let alias = options["alias"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'alias'")
        }
        guard let mediaPath = options["mediaPath"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'mediaPath'")
        }
        guard let certChainPEM = options["certChainPEM"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'certChainPEM'")
        }
        guard let capturerUuid = options["capturerUuid"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'capturerUuid'")
        }
        let gps = options["gps"] as? [String: Any]
        let captureTimestampMs = (options["captureTimestampMs"] as? NSNumber)?.doubleValue
        let tsaUrl = options["tsaUrl"] as? String
        let result = try PhotoAttestModule.signC2PACaptureInternal(
          alias: alias,
          mediaPath: mediaPath,
          certChainPEM: certChainPEM,
          capturerUuid: capturerUuid,
          gps: gps,
          captureTimestampMs: captureTimestampMs,
          tsaUrl: tsaUrl
        )
        promise.resolve(result)
      } catch let err as PhotoAttestError {
        promise.reject(err.code, err.message)
      } catch {
        promise.reject("C2PA_SIGN_FAILED", error.localizedDescription)
      }
    }

    // Bridged as a single options dict — symmetric with Android, where Expo
    // modules' AsyncFunction overload set caps at 8 typed params and Stage 2
    // sits right at the cap. Uses the Promise pattern for the same reason
    // signC2PACapture does (see comment above).
    AsyncFunction("signC2PAUpload") { (options: [String: Any], promise: Promise) in
      do {
        guard let alias = options["alias"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'alias'")
        }
        guard let parentMediaPath = options["parentMediaPath"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'parentMediaPath'")
        }
        guard let transformedMediaPath = options["transformedMediaPath"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'transformedMediaPath'")
        }
        guard let certChainPEM = options["certChainPEM"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'certChainPEM'")
        }
        let actions = options["actions"] as? [[String: Any]] ?? []
        let gps = options["gps"] as? [String: Any]
        let captureTimestampMs = (options["captureTimestampMs"] as? NSNumber)?.doubleValue
        let claimThumbnailPath = options["claimThumbnailPath"] as? String
        let attestationEnvelope = options["attestationEnvelope"] as? [String: Any]
        let tsaUrl = options["tsaUrl"] as? String
        let result = try PhotoAttestModule.signC2PAUploadInternal(
          alias: alias,
          parentMediaPath: parentMediaPath,
          transformedMediaPath: transformedMediaPath,
          certChainPEM: certChainPEM,
          actions: actions,
          gps: gps,
          captureTimestampMs: captureTimestampMs,
          claimThumbnailPath: claimThumbnailPath,
          attestationEnvelope: attestationEnvelope,
          tsaUrl: tsaUrl
        )
        promise.resolve(result)
      } catch let err as PhotoAttestError {
        promise.reject(err.code, err.message)
      } catch {
        promise.reject("C2PA_SIGN_FAILED", error.localizedDescription)
      }
    }

    // Stamp a queued offline capture via a c2pa.timestamp Update Manifest
    // (signed by the device hardware key; TSA token fetched inside c2pa-rs).
    // Writes a stamped file to staging; the caller overwrites the gallery asset
    // with it via overwriteMediaLibraryAsset.
    AsyncFunction("signTimestampUpdateManifest") { (options: [String: Any], promise: Promise) in
      do {
        guard let alias = options["alias"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'alias'")
        }
        guard let parentMediaPath = options["parentMediaPath"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'parentMediaPath'")
        }
        guard let certChainPEM = options["certChainPEM"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'certChainPEM'")
        }
        guard let tsaUrl = options["tsaUrl"] as? String else {
          throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "missing 'tsaUrl'")
        }
        let result = try PhotoAttestModule.signTimestampUpdateManifestInternal(
          alias: alias,
          parentMediaPath: parentMediaPath,
          certChainPEM: certChainPEM,
          tsaUrl: tsaUrl
        )
        promise.resolve(result)
      } catch let err as PhotoAttestError {
        promise.reject(err.code, err.message)
      } catch {
        promise.reject("C2PA_SIGN_FAILED", error.localizedDescription)
      }
    }

    // Overwrite a gallery asset's bytes in place with a stamped file (PhotoKit
    // content-edit; prompt-free for app-created assets, original revertable).
    // Resolves on success; rejects ASSET_NOT_FOUND if the asset was deleted
    // from the gallery since enqueue.
    AsyncFunction("overwriteMediaLibraryAsset") { (options: [String: Any], promise: Promise) in
      guard let assetId = options["assetId"] as? String else {
        promise.reject("INVALID_CAPTURE_CONTEXT", "missing 'assetId'")
        return
      }
      guard let sourcePath = options["sourcePath"] as? String else {
        promise.reject("INVALID_CAPTURE_CONTEXT", "missing 'sourcePath'")
        return
      }
      PhotoAttestModule.overwriteMediaLibraryAsset(
        assetId: assetId,
        sourcePath: sourcePath,
        promise: promise
      )
    }

    AsyncFunction("generateAndAttestKey") { (alias: String, challengeBase64: String, promise: Promise) in
      Task {
        do {
          let publicKey = try PhotoAttestModule.generateKeyInternal(alias: alias)
          do {
            let attestation = try await PhotoAttestModule.attestInternal(
              alias: alias,
              challengeBase64: challengeBase64
            )
            promise.resolve([
              "publicKey": publicKey,
              "platform": "ios",
              "attestation": attestation.attestation,
              "keyId": attestation.keyId,
            ])
          } catch {
            // Attestation failed — roll back the SE key so the next attempt
            // doesn't trip KEY_ALREADY_EXISTS. We hard-require attested keys, so
            // a partial-success enrollment is worse than no key at all.
            try? PhotoAttestModule.deleteKeyInternal(alias: alias)
            throw error
          }
        } catch let err as PhotoAttestError {
          promise.reject(err.code, err.message)
        } catch {
          promise.reject("ATTESTATION_FAILED", error.localizedDescription)
        }
      }
    }
  }

  // MARK: - Internals

  private struct PhotoAttestError: Error {
    let code: String
    let message: String
  }

  private struct AttestationOutcome {
    let attestation: String
    let keyId: String
  }

  private static func aliasTag(_ alias: String) -> Data {
    return alias.data(using: .utf8) ?? Data()
  }

  private static func findKey(alias: String) -> SecKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: aliasTag(alias),
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecReturnRef as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let result = item else { return nil }
    return (result as! SecKey)
  }

  private static func deleteKeyInternal(alias: String) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: aliasTag(alias),
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      throw PhotoAttestError(
        code: "KEY_NOT_FOUND",
        message: "SecItemDelete failed (status \(status))"
      )
    }
  }

  private static func generateKeyInternal(alias: String) throws -> String {
    if findKey(alias: alias) != nil {
      throw PhotoAttestError(
        code: "KEY_ALREADY_EXISTS",
        message: "Key with alias '\(alias)' already exists"
      )
    }

    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      .privateKeyUsage,
      &accessError
    ) else {
      let err = accessError?.takeRetainedValue()
      throw PhotoAttestError(
        code: "HARDWARE_UNAVAILABLE",
        message: err.map { "\($0)" } ?? "Failed to create SecAccessControl"
      )
    }

    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: aliasTag(alias),
        kSecAttrAccessControl as String: access,
      ],
    ]

    var genError: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
      let err = genError?.takeRetainedValue()
      throw PhotoAttestError(
        code: "HARDWARE_UNAVAILABLE",
        message: err.map { "\($0)" } ?? "SecKeyCreateRandomKey returned nil"
      )
    }

    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw PhotoAttestError(
        code: "HARDWARE_UNAVAILABLE",
        message: "SecKeyCopyPublicKey returned nil"
      )
    }

    let spki = try spkiDerForP256(publicKey: publicKey)
    return spki.base64EncodedString()
  }

  private static func getPublicKeyInternal(alias: String) throws -> String {
    guard let privateKey = findKey(alias: alias) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "No key with alias '\(alias)'")
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "SecKeyCopyPublicKey returned nil")
    }
    let spki = try spkiDerForP256(publicKey: publicKey)
    return spki.base64EncodedString()
  }

  private static func attestInternal(
    alias: String,
    challengeBase64: String
  ) async throws -> AttestationOutcome {
    let service = DCAppAttestService.shared
    guard service.isSupported else {
      throw PhotoAttestError(
        code: "APP_ATTEST_UNAVAILABLE",
        message: "DCAppAttestService is not supported on this device (likely simulator)"
      )
    }

    guard let privateKey = findKey(alias: alias) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "No key with alias '\(alias)'")
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "SecKeyCopyPublicKey returned nil")
    }
    let spki = try spkiDerForP256(publicKey: publicKey)

    guard let challenge = Data(base64Encoded: challengeBase64) else {
      throw PhotoAttestError(code: "APP_ATTEST_FAILED", message: "Invalid base64 challenge")
    }

    // clientDataHash binds the SE public key to the App Attest assertion. The
    // server reconstructs the same hash from (challenge, claimed SE public key)
    // and refuses anything that doesn't match.
    var hasher = SHA256()
    hasher.update(data: challenge)
    hasher.update(data: spki)
    let clientDataHash = Data(hasher.finalize())

    // Generate a fresh App Attest key. The App Attest service manages its own
    // keys separately from our SE signing key — we only need its keyId here.
    let keyId: String = try await withCheckedThrowingContinuation { continuation in
      service.generateKey { id, err in
        if let err = err {
          continuation.resume(throwing: PhotoAttestError(
            code: "APP_ATTEST_FAILED",
            message: "DCAppAttestService.generateKey: \(err.localizedDescription)"
          ))
        } else if let id = id {
          continuation.resume(returning: id)
        } else {
          continuation.resume(throwing: PhotoAttestError(
            code: "APP_ATTEST_FAILED",
            message: "DCAppAttestService.generateKey returned no keyId"
          ))
        }
      }
    }

    let attestation: Data = try await withCheckedThrowingContinuation { continuation in
      service.attestKey(keyId, clientDataHash: clientDataHash) { data, err in
        if let err = err {
          continuation.resume(throwing: PhotoAttestError(
            code: "APP_ATTEST_FAILED",
            message: "DCAppAttestService.attestKey: \(err.localizedDescription)"
          ))
        } else if let data = data {
          continuation.resume(returning: data)
        } else {
          continuation.resume(throwing: PhotoAttestError(
            code: "APP_ATTEST_FAILED",
            message: "DCAppAttestService.attestKey returned empty data"
          ))
        }
      }
    }

    return AttestationOutcome(
      attestation: attestation.base64EncodedString(),
      keyId: keyId
    )
  }

  // App Attest assertion over `clientDataHash = SHA256(challengeBytes || SE_SPKI)`.
  // Used by the Stage-2 upload path: the challenge is a server-issued single-use
  // nonce (freshness + app-integrity proof, burned by the verifier). The
  // verifier rebuilds clientDataHash from (nonce, SE_SPKI) and refuses anything
  // that doesn't match — folding SE_SPKI in defeats assertion-stapling.
  private static func generateCaptureAttestationInternal(
    alias: String,
    appAttestKeyId: String,
    challengeBase64: String
  ) async throws -> String {
    let service = DCAppAttestService.shared
    guard service.isSupported else {
      throw PhotoAttestError(
        code: "APP_ATTEST_UNAVAILABLE",
        message: "DCAppAttestService is not supported on this device (likely simulator)"
      )
    }

    guard !appAttestKeyId.isEmpty else {
      throw PhotoAttestError(
        code: "APP_ATTEST_FAILED",
        message: "appAttestKeyId must be non-empty (persisted at enrollment)"
      )
    }

    guard let challenge = Data(base64Encoded: challengeBase64) else {
      throw PhotoAttestError(
        code: "APP_ATTEST_FAILED",
        message: "Invalid base64 challenge"
      )
    }

    guard let privateKey = findKey(alias: alias) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "No key with alias '\(alias)'")
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "SecKeyCopyPublicKey returned nil")
    }
    let spki = try spkiDerForP256(publicKey: publicKey)

    var hasher = SHA256()
    hasher.update(data: challenge)
    hasher.update(data: spki)
    let clientDataHash = Data(hasher.finalize())

    let assertion: Data = try await withCheckedThrowingContinuation { continuation in
      service.generateAssertion(appAttestKeyId, clientDataHash: clientDataHash) { data, err in
        if let err = err {
          continuation.resume(throwing: PhotoAttestError(
            code: "APP_ATTEST_FAILED",
            message: "DCAppAttestService.generateAssertion: \(err.localizedDescription)"
          ))
        } else if let data = data {
          continuation.resume(returning: data)
        } else {
          continuation.resume(throwing: PhotoAttestError(
            code: "APP_ATTEST_FAILED",
            message: "DCAppAttestService.generateAssertion returned empty data"
          ))
        }
      }
    }

    return assertion.base64EncodedString()
  }

  // Mints a PKCS#10 CertificationRequest (PEM) carrying the SE-backed public
  // key for `alias`, self-signed with the same key (proof-of-possession). The
  // RealReel CA edge function validates the self-signature + matches SPKI
  // against the attested key, then issues a CA-signed leaf cert. The CSR
  // subject is informational — the server overwrites it with its own DN at
  // issuance, so CN=RealReel-CSR (a debug marker) never appears in a published
  // leaf.
  private static func generateCSRInternal(alias: String) throws -> String {
    guard let privateKey = findKey(alias: alias) else {
      throw PhotoAttestError(code: "KEY_NOT_FOUND", message: "No key with alias '\(alias)'")
    }
    let signingKey = try Certificate.PrivateKey(privateKey)

    let subject = try DistinguishedName {
      CountryName(PhotoAttestModule.COUNTRY_NAME)
      StateOrProvinceName(PhotoAttestModule.STATE_NAME)
      OrganizationName(PhotoAttestModule.ORG_NAME)
      OrganizationalUnitName(PhotoAttestModule.ORG_UNIT_NAME)
      CommonName("RealReel-CSR")
    }

    let csr = try CertificateSigningRequest(
      version: .v1,
      subject: subject,
      privateKey: signingKey,
      attributes: CertificateSigningRequest.Attributes(),
      signatureAlgorithm: .ecdsaWithSHA256
    )
    return try csr.serializeAsPEM().pemString
  }

  // Parse the leaf cert (first cert) out of a PEM chain and confirm its
  // SubjectPublicKey matches the SE-backed public key for `alias`. Throws
  // CERT_KEY_MISMATCH if they differ — caller is probably holding a stale
  // enrollment cert or wired up the wrong alias.
  private static func assertCertChainMatchesKey(
    certChainPEM: String,
    alias: String
  ) throws {
    guard let privateKey = findKey(alias: alias) else {
      throw PhotoAttestError(
        code: "CERT_KEY_MISMATCH",
        message: "No keystore key for alias '\(alias)'"
      )
    }
    guard let pubFromKey = SecKeyCopyPublicKey(privateKey),
          let expected = SecKeyCopyExternalRepresentation(pubFromKey, nil) as Data?
    else {
      throw PhotoAttestError(
        code: "CERT_KEY_MISMATCH",
        message: "Failed to extract pubkey from SE for alias '\(alias)'"
      )
    }

    // Strip the first PEM block from the chain (the leaf), decode base64.
    guard let leafDer = firstPEMBlockDer(pem: certChainPEM, label: "CERTIFICATE") else {
      throw PhotoAttestError(
        code: "CERT_KEY_MISMATCH",
        message: "Failed to parse leaf cert from chain PEM"
      )
    }
    guard let cert = SecCertificateCreateWithData(nil, leafDer as CFData) else {
      throw PhotoAttestError(
        code: "CERT_KEY_MISMATCH",
        message: "SecCertificateCreateWithData rejected the leaf cert DER"
      )
    }
    guard let pubFromCert = SecCertificateCopyKey(cert),
          let actual = SecKeyCopyExternalRepresentation(pubFromCert, nil) as Data?
    else {
      throw PhotoAttestError(
        code: "CERT_KEY_MISMATCH",
        message: "Failed to extract pubkey from cert"
      )
    }

    if expected != actual {
      throw PhotoAttestError(
        code: "CERT_KEY_MISMATCH",
        message: "Leaf cert pubkey does not match Secure Enclave key for alias '\(alias)'. Re-enroll or pass the cert minted at enrollment time."
      )
    }
  }

  // Extracts the first PEM block matching the given label and returns its
  // base64-decoded DER bytes. Tolerates Windows line endings and surrounding
  // whitespace. Returns nil if no matching block is found.
  private static func firstPEMBlockDer(pem: String, label: String) -> Data? {
    let begin = "-----BEGIN \(label)-----"
    let end = "-----END \(label)-----"
    guard let beginRange = pem.range(of: begin),
          let endRange = pem.range(of: end, range: beginRange.upperBound..<pem.endIndex)
    else { return nil }
    let body = String(pem[beginRange.upperBound..<endRange.lowerBound])
    let stripped = body.replacingOccurrences(of: "\r", with: "")
                       .replacingOccurrences(of: "\n", with: "")
                       .replacingOccurrences(of: " ", with: "")
    return Data(base64Encoded: stripped)
  }

  // MARK: - C2PA Stage 1 (capture-time) signing
  //
  // Sister implementation: native/android/.../PhotoAttestModule.kt
  // Manifest shape (assertions, action codes, custom-namespace label) MUST stay
  // in lockstep across both platforms — the verifier asserts structural
  // equality regardless of which device captured.
  //
  // What this does at a high level:
  //  1. Mints a fresh self-signed leaf cert wrapping the SE key for this alias.
  //  2. Inspects the source file's EXIF (photos) or QuickTime (videos) metadata.
  //  3. Builds a C2PA manifest JSON with three assertion families:
  //       - c2pa.actions.v2 with a single c2pa.created action (carries
  //         digitalSourceType=digitalCapture via setIntent below; spec §17.5).
  //       - stds.exif (photos) / stds.iptc (videos) with whatever the file
  //         carried so the verifier can re-anchor against the file's own
  //         metadata after Stage 2 transformations.
  //       - org.realreel.capture: device identity. This is the
  //         single cross-platform slot for "what device made this" because
  //         Android MP4s reliably do NOT carry Make/Model in the file itself.
  //  4. Hands manifest + source file + Secure Enclave-backed signer to c2pa-rs
  //     (via c2pa-ios), which embeds the manifest + signature into the output
  //     file via either c2pa.hash.data (image) or c2pa.hash.bmff (video).
  //  5. Returns the path to the signed media. No sidecar — Stage 2 reads the
  //     parent ingredient back out of the signed file directly.
  //
  // PER-APP SWAP-POINT: CSR subject DN attributes (forker: set your own org).
  // These go into the CSR subject only — the RealReel CA OVERWRITES the leaf
  // subject DN at issuance (see ca/_shared/attestation/pki.ts), so they never
  // appear in a published leaf cert; CN=RealReel-CSR (below, in generateCSR) is
  // a debug marker. Left a native constant (not env-driven) because a Swift
  // `static let` can't read deployment env without build plumbing. Must match
  // the Android sister module exactly. O= is the legal organization; OU= is the
  // product/brand. C= is ISO 3166 two-letter; ST= is the full state name per
  // RFC 5280 convention.
  private static let COUNTRY_NAME = "US"
  private static let STATE_NAME = "California"
  private static let ORG_NAME = "Whole Earth Labs, LLC"
  private static let ORG_UNIT_NAME = "RealReel"

  private static let SUPPORTED_FORMATS: [String: (mime: String, isVideo: Bool)] = [
    "jpg": ("image/jpeg", false),
    "jpeg": ("image/jpeg", false),
    "heic": ("image/heic", false),
    "mp4": ("video/mp4", true),
    "mov": ("video/quicktime", true),
  ]

  // c2pa-rs settings (global, applied via Signer.loadSettings before each sign).
  // Merge semantics mean every path must set auto_timestamp_assertion.enabled
  // EXPLICITLY rather than relying on the key's absence — otherwise a drain that
  // turned it on would leak into a later Stage-2 upload, whose parentOf
  // ingredient WOULD then get auto-stamped.
  //
  // verify_trust / verify_after_sign are off (see signCaptureManifest's comment).
  //
  // Capture + Stage-2 upload: auto-timestamp OFF (their TSA, when any, is the
  // inline sigTst2 c2pa-rs fetches over the CURRENT signature via the signer's
  // tsa URL — not a parent-scoped c2pa.timestamp assertion).
  private static let SIGN_SETTINGS_JSON =
    #"{"version":1,"verify":{"verify_trust":false,"verify_after_sign":false},"builder":{"auto_timestamp_assertion":{"enabled":false}}}"#

  // Update-Manifest drain: auto-timestamp ON with fetch_scope=parent, so
  // c2pa-rs stamps the PARENT (Stage-1) signature it auto-incorporates from the
  // source asset and bakes the c2pa.timestamp assertion. skip_existing=false —
  // a queued capture is, by definition, not yet timestamped.
  private static let UPDATE_MANIFEST_SETTINGS_JSON =
    #"{"version":1,"verify":{"verify_trust":false,"verify_after_sign":false},"builder":{"auto_timestamp_assertion":{"enabled":true,"skip_existing":false,"fetch_scope":"parent"}}}"#

  // Single-pass capture signing: build the capture manifest and sign it once
  // with the enrolled Secure Enclave key. No embedded per-capture attestation —
  // device trust is established at enrollment and re-proven at upload (Stage 2).
  private static func signC2PACaptureInternal(
    alias: String,
    mediaPath: String,
    certChainPEM: String,
    capturerUuid: String,
    gps: [String: Any]?,
    captureTimestampMs: Double?,
    tsaUrl: String?
  ) throws -> [String: String] {
    if capturerUuid.isEmpty {
      throw PhotoAttestError(
        code: "INVALID_CAPTURE_CONTEXT",
        message: "capturerUuid must be non-empty"
      )
    }

    let sourceURL = URL(fileURLWithPath: mediaPath)
    let ext = sourceURL.pathExtension.lowercased()
    guard let format = SUPPORTED_FORMATS[ext] else {
      let supported = SUPPORTED_FORMATS.keys.sorted().joined(separator: ", ")
      throw PhotoAttestError(
        code: "UNSUPPORTED_FORMAT",
        message: "Unsupported file extension '.\(ext)'. Supported: \(supported)"
      )
    }

    guard FileManager.default.fileExists(atPath: sourceURL.path) else {
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "Source file does not exist: \(sourceURL.path)"
      )
    }

    // Defensive check: the cert chain we embed must wrap the SAME pubkey as
    // the Secure Enclave key we're about to sign with. Mismatch usually means
    // the caller passed a stale cert (e.g. cached from before a key rotation,
    // or wired to the wrong alias). Catching it here produces a clear error
    // instead of a silently-wrong manifest that the verifier rejects later
    // with an opaque message.
    try assertCertChainMatchesKey(certChainPEM: certChainPEM, alias: alias)

    // Output: <appSupport>/c2pa-staging/<uuid>/realreel-<localtime>.<ext>.
    // Native owns cleanup; Stage 2 deletes the dir after a successful upload.
    let appSupport = try FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: true
    )
    let stagingDir = appSupport
      .appendingPathComponent("c2pa-staging", isDirectory: true)
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
      at: stagingDir, withIntermediateDirectories: true
    )
    // Gallery-friendly filename: `realreel-<localtime>.<ext>`. Local time
    // (not UTC) so users see the timestamp in their wall-clock zone, matching
    // every native camera app's convention. The UUID staging dir guarantees
    // uniqueness regardless of name collisions across rapid captures.
    let outputFileName = "realreel-\(captureTimestamp()).\(ext)"
    let destURL = stagingDir.appendingPathComponent(outputFileName)

    do {
      let manifestJSON = try buildCaptureManifestJSON(
        sourceURL: sourceURL,
        mime: format.mime,
        isVideo: format.isVideo,
        capturerUuid: capturerUuid,
        gps: gps,
        title: outputFileName,
        captureTimestampMs: captureTimestampMs
      )
      try signCaptureManifest(
        manifestJSON: manifestJSON,
        sourceURL: sourceURL,
        destURL: destURL,
        mime: format.mime,
        alias: alias,
        certChainPEM: certChainPEM,
        tsaUrl: tsaUrl
      )
    } catch let error as PhotoAttestError {
      // Roll back the half-written output dir so we don't leak staging dirs on
      // retry. Preserve the coded error.
      try? FileManager.default.removeItem(at: stagingDir)
      throw error
    } catch {
      try? FileManager.default.removeItem(at: stagingDir)
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "C2PA sign failed: \(error.localizedDescription)"
      )
    }

    // Read back the active manifest's URN so the offline TSA queue can key a
    // future Update-Manifest stamp on this Stage-1 manifest. Done AFTER the
    // sign do/catch so a read-back failure never rolls back a
    // successfully-signed-and-written asset — the bytes are on disk regardless.
    // Empty string on any failure; JS treats `''` as "unknown" and re-derives
    // at drain time.
    var manifestId = ""
    do {
      let readStream = try Stream(readFrom: destURL)
      let reader = try Reader(format: format.mime, stream: readStream)
      manifestId = try extractActiveManifestUrn(reader.json())
    } catch {
      NSLog("[PhotoAttest] capture manifest URN read-back failed (non-fatal): \(error.localizedDescription)")
    }

    return ["signedMediaPath": destURL.path, "manifestId": manifestId]
  }

  // Sign a capture manifest into `destURL` with the SE-backed key for `alias`.
  //
  // verify_trust / verify_after_sign are disabled: our leaf chains only to the
  // RealReel CA, not a public CA. verify_trust=false alone wasn't enough on
  // older c2pa-rs (the post-sign verify ran structural cert checks beyond chain
  // validation and rejected the cert with an opaque "the certificate is
  // invalid"). The verifier authenticates by chaining to the RealReel CA, so
  // neither flag is load-bearing for us. Global setting; idempotent.
  private static func signCaptureManifest(
    manifestJSON: String,
    sourceURL: URL,
    destURL: URL,
    mime: String,
    alias: String,
    certChainPEM: String,
    tsaUrl: String?
  ) throws {
    try Signer.loadSettings(SIGN_SETTINGS_JSON, format: .json)

    let builder = try Builder(manifestJSON: manifestJSON)
    try builder.setIntent(.create(.digitalCapture))

    // TSA: when JS passes a tsaUrl (online capture), c2pa-ios (via c2pa-rs)
    // fetches an RFC 3161 token over the COSE signature at sign time and embeds
    // it in the COSE unprotected header (sigTst2). Offline captures pass nil and
    // stay unstamped — the JS layer enqueues them for a later Update-Manifest
    // stamp. On a TSA fetch failure the sign throws; the JS orchestrator handles
    // provider fallback and, if both fail, re-signs without TSA + enqueues
    // rather than failing the capture.
    //
    // Normalize the URL string first: trim whitespace and treat empty as nil.
    // Without this, URL(string: "") returns a non-nil empty URL that c2pa-rs
    // would try to POST to (a silent confusing failure). Android does the
    // equivalent normalization so both platforms behave identically on bad input.
    let trimmedTsaUrl = tsaUrl?.trimmingCharacters(in: .whitespacesAndNewlines)
    let parsedTsaUrl: URL? = (trimmedTsaUrl?.isEmpty ?? true) ? nil : URL(string: trimmedTsaUrl!)
    let signer = try Signer(
      algorithm: .es256,
      certificateChainPEM: certChainPEM,
      tsa: parsedTsaUrl,
      secureEnclaveConfig: SecureEnclaveSignerConfig(keyTag: alias)
    )

    let sourceStream = try Stream(readFrom: sourceURL)
    let destStream = try Stream(writeTo: destURL)

    _ = try builder.sign(
      format: mime,
      source: sourceStream,
      destination: destStream,
      signer: signer
    )
  }

  // Stage 2. Re-signs a transformed asset with the Stage-1 file (gallery
  // copy) as a `parentOf` ingredient. c2pa-rs's BuilderIntent.edit
  // semantics auto-incorporate the parent and auto-prepend `c2pa.opened`
  // to the actions list, so JS callers list only the transformations they
  // actually performed.
  //
  // Hard-fail policy: if the parent's embedded JUMBF can't be read,
  // STAGE1_PARENT_UNREADABLE is thrown. Callers must NOT fall back to
  // single-stage signing — that would lie about provenance.
  private static func signC2PAUploadInternal(
    alias: String,
    parentMediaPath: String,
    transformedMediaPath: String,
    certChainPEM: String,
    actions: [[String: Any]],
    gps: [String: Any]?,
    captureTimestampMs: Double?,
    claimThumbnailPath: String?,
    attestationEnvelope: [String: Any]?,
    tsaUrl: String?
  ) throws -> [String: String] {
    let parentURL = URL(fileURLWithPath: parentMediaPath)
    let transformedURL = URL(fileURLWithPath: transformedMediaPath)
    let parentExt = parentURL.pathExtension.lowercased()
    let transformedExt = transformedURL.pathExtension.lowercased()
    guard let parentFormat = SUPPORTED_FORMATS[parentExt] else {
      throw PhotoAttestError(
        code: "UNSUPPORTED_FORMAT",
        message: "Unsupported parent extension '.\(parentExt)'."
      )
    }
    guard let transformedFormat = SUPPORTED_FORMATS[transformedExt] else {
      throw PhotoAttestError(
        code: "UNSUPPORTED_FORMAT",
        message: "Unsupported transformed extension '.\(transformedExt)'."
      )
    }

    guard FileManager.default.fileExists(atPath: parentURL.path) else {
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "Parent file does not exist: \(parentURL.path)"
      )
    }
    guard FileManager.default.fileExists(atPath: transformedURL.path) else {
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "Transformed file does not exist: \(transformedURL.path)"
      )
    }

    try assertCertChainMatchesKey(certChainPEM: certChainPEM, alias: alias)

    // Resolve the claim-thumbnail (mime, identifier) up-front. Hard-fail on
    // a missing-but-supplied path matches the wider hard-fail philosophy
    // (parent-unreadable etc.); silently skipping would let the manifest
    // reference a resource we never added.
    let claimThumbnailRef: (mime: String, identifier: String)?
    if let path = claimThumbnailPath {
      let thumbURL = URL(fileURLWithPath: path)
      guard FileManager.default.fileExists(atPath: thumbURL.path) else {
        throw PhotoAttestError(
          code: "C2PA_SIGN_FAILED",
          message: "Claim thumbnail file does not exist: \(path)"
        )
      }
      switch thumbURL.pathExtension.lowercased() {
      case "jpg", "jpeg":
        claimThumbnailRef = ("image/jpeg", "claim_thumbnail.jpg")
      case "png":
        claimThumbnailRef = ("image/png", "claim_thumbnail.png")
      default:
        throw PhotoAttestError(
          code: "UNSUPPORTED_FORMAT",
          message: "Claim thumbnail must be JPEG or PNG (got '\(path)')"
        )
      }
    } else {
      claimThumbnailRef = nil
    }

    // Read parent's embedded manifest. Hard-fail if absent/corrupted.
    let parentManifestJSON: String
    do {
      let parentReadStream = try Stream(readFrom: parentURL)
      let parentReader = try Reader(format: parentFormat.mime, stream: parentReadStream)
      parentManifestJSON = try parentReader.json()
    } catch {
      throw PhotoAttestError(
        code: "STAGE1_PARENT_UNREADABLE",
        message: "Failed to read parent manifest from \(parentURL.path): \(error.localizedDescription)"
      )
    }

    // The CAPTURE manifest's urn (walked past any interposed timestamp Update
    // Manifest) is the redaction target — see extractCaptureManifestUrn. On the
    // common never-offline path this equals the active-manifest urn.
    let captureURN = try extractCaptureManifestUrn(parentManifestJSON)

    let appSupport = try FileManager.default.url(
      for: .applicationSupportDirectory,
      in: .userDomainMask,
      appropriateFor: nil,
      create: true
    )
    let outputFileName = "realreel-\(captureTimestamp()).\(transformedExt)"

    // Staging dir creation moved INTO the do/catch so any failure between
    // here and the final sign() rolls back the dir. Without this, a throw
    // from buildUploadManifestJSON or Builder(manifestJSON:) would leave an
    // empty staging dir behind on each retry.
    var stagingDirCreated: URL?
    let destPath: String
    do {
      let stagingDir = appSupport
        .appendingPathComponent("c2pa-staging", isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
      try FileManager.default.createDirectory(
        at: stagingDir, withIntermediateDirectories: true
      )
      stagingDirCreated = stagingDir
      let destURL = stagingDir.appendingPathComponent(outputFileName)

      let manifestJSON = try buildUploadManifestJSON(
        transformedURL: transformedURL,
        transformedMime: transformedFormat.mime,
        isVideo: transformedFormat.isVideo,
        gps: gps,
        captureTimestampMs: captureTimestampMs,
        title: outputFileName,
        actions: actions,
        redactionTargetUrn: captureURN,
        claimThumbnailRef: claimThumbnailRef,
        attestationEnvelope: attestationEnvelope
      )

      try Signer.loadSettings(SIGN_SETTINGS_JSON, format: .json)

      let builder = try Builder(manifestJSON: manifestJSON)
      try builder.setIntent(.edit)

      // Add parent ingredient — c2pa-rs hashes the parent stream + auto-
      // generates the ingredient thumbnail. Minimal JSON: c2pa-rs fills
      // instanceId/documentId/hash from the stream contents.
      let parentIngredientJSON = try JSONSerialization.data(
        withJSONObject: [
          "title": parentURL.lastPathComponent,
          "format": parentFormat.mime,
          "relationship": "parentOf",
        ] as [String: Any],
        options: [.sortedKeys]
      )
      guard let parentIngredientJSONString = String(data: parentIngredientJSON, encoding: .utf8) else {
        throw PhotoAttestError(code: "C2PA_SIGN_FAILED", message: "Failed to serialize parent ingredient JSON")
      }
      let ingredientStream = try Stream(readFrom: parentURL)
      try builder.addIngredient(
        json: parentIngredientJSONString,
        format: parentFormat.mime,
        from: ingredientStream
      )

      // Optional claim thumbnail (user-selected video poster frame).
      // File existence + format already validated above (claimThumbnailRef
      // is nil iff caller passed nothing).
      if let ref = claimThumbnailRef, let path = claimThumbnailPath {
        let thumbnailURL = URL(fileURLWithPath: path)
        let thumbnailStream = try Stream(readFrom: thumbnailURL)
        try builder.addResource(uri: ref.identifier, stream: thumbnailStream)
      }

      // TSA: when JS passes a tsaUrl, c2pa-ios (via c2pa-rs) fetches an
      // RFC 3161 token over the COSE signature at sign time and embeds
      // it in the COSE unprotected header (sigTst2). On TSA fetch failure
      // the whole sign throws — JS layer handles provider fallback
      // (DigiCert → SSL.com) at the wrapper level.
      //
      // Normalize the URL string before constructing URL: trim whitespace
      // and treat empty as nil. Without this, URL(string: "") returns a
      // non-nil empty URL that c2pa-rs would try to POST to (silent
      // confusing failure mode). Android does the equivalent normalization
      // — match-keeps the two platforms' behavior identical on bad input.
      let trimmedTsaUrl = tsaUrl?.trimmingCharacters(in: .whitespacesAndNewlines)
      let parsedTsaUrl: URL? = (trimmedTsaUrl?.isEmpty ?? true) ? nil : URL(string: trimmedTsaUrl!)
      let signer = try Signer(
        algorithm: .es256,
        certificateChainPEM: certChainPEM,
        tsa: parsedTsaUrl,
        secureEnclaveConfig: SecureEnclaveSignerConfig(keyTag: alias)
      )

      let sourceStream = try Stream(readFrom: transformedURL)
      let destStream = try Stream(writeTo: destURL)

      _ = try builder.sign(
        format: transformedFormat.mime,
        source: sourceStream,
        destination: destStream,
        signer: signer
      )

      destPath = destURL.path
    } catch let error as PhotoAttestError {
      if let dir = stagingDirCreated { try? FileManager.default.removeItem(at: dir) }
      throw error
    } catch {
      if let dir = stagingDirCreated { try? FileManager.default.removeItem(at: dir) }
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "C2PA Stage-2 sign failed: \(error.localizedDescription)"
      )
    }

    return ["signedMediaPath": destPath]
  }

  // TSA drain. Wrap a queued Stage-1 capture in a c2pa.timestamp Update
  // Manifest signed by the SE-backed key for `alias`. c2pa-rs does the heavy
  // lifting: with BuilderIntent.update + the source asset carrying an existing
  // manifest, it auto-incorporates Stage-1 as the parent (NO explicit
  // addIngredient — see c2pa-rs sdk/tests/timestamp_assertion.rs), and with
  // UPDATE_MANIFEST_SETTINGS_JSON (auto_timestamp_assertion fetch_scope=parent)
  // + the signer's tsa URL it fetches an RFC 3161 token over the PARENT's COSE
  // signature and bakes the c2pa.timestamp assertion keyed by the Stage-1 URN.
  //
  // Output goes to a fresh staging dir; the gallery asset is NOT touched here
  // (the caller overwrites it via overwriteMediaLibraryAsset only after this
  // succeeds — so a TSA/sign failure never corrupts the saved capture).
  private static func signTimestampUpdateManifestInternal(
    alias: String,
    parentMediaPath: String,
    certChainPEM: String,
    tsaUrl: String
  ) throws -> [String: String] {
    let parentURL = URL(fileURLWithPath: parentMediaPath)
    let ext = parentURL.pathExtension.lowercased()
    guard let format = SUPPORTED_FORMATS[ext] else {
      throw PhotoAttestError(
        code: "UNSUPPORTED_FORMAT",
        message: "Unsupported extension '.\(ext)'."
      )
    }
    guard FileManager.default.fileExists(atPath: parentURL.path) else {
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "Parent file does not exist: \(parentURL.path)"
      )
    }

    try assertCertChainMatchesKey(certChainPEM: certChainPEM, alias: alias)

    // Confirm the source actually carries a Stage-1 manifest — Update intent
    // needs an existing manifest to make the parent. A missing/corrupt parent
    // manifest is the same hard-fail class as Stage 2's STAGE1_PARENT_UNREADABLE.
    do {
      let probeStream = try Stream(readFrom: parentURL)
      let probeReader = try Reader(format: format.mime, stream: probeStream)
      _ = try probeReader.json()
    } catch {
      throw PhotoAttestError(
        code: "STAGE1_PARENT_UNREADABLE",
        message: "Failed to read Stage-1 manifest from \(parentURL.path): \(error.localizedDescription)"
      )
    }

    let appName = "RealReel"
    let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    let outputFileName = "realreel-\(captureTimestamp()).\(ext)"

    // Minimal Update Manifest definition — no assertions (c2pa-rs adds the
    // c2pa.timestamp itself) and no hard-binding (Update Manifests don't hash
    // content; the parent's binding stands).
    let manifestDict: [String: Any] = [
      "claim_generator": "\(appName)/\(appVersion)",
      "claim_generator_info": [["name": appName, "version": appVersion]],
      "title": outputFileName,
    ]
    let manifestJSONData = try JSONSerialization.data(
      withJSONObject: manifestDict, options: [.sortedKeys]
    )
    guard let manifestJSON = String(data: manifestJSONData, encoding: .utf8) else {
      throw PhotoAttestError(code: "C2PA_SIGN_FAILED", message: "Failed to serialize Update Manifest JSON")
    }

    let appSupport = try FileManager.default.url(
      for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
    )

    var stagingDirCreated: URL?
    let destPath: String
    do {
      let stagingDir = appSupport
        .appendingPathComponent("c2pa-staging", isDirectory: true)
        .appendingPathComponent(UUID().uuidString, isDirectory: true)
      try FileManager.default.createDirectory(at: stagingDir, withIntermediateDirectories: true)
      stagingDirCreated = stagingDir
      let destURL = stagingDir.appendingPathComponent(outputFileName)

      // Settings are PROCESS-GLOBAL (thread-local). We flip auto_timestamp_
      // assertion ON for this Update-Manifest sign; restore the safe baseline
      // (auto-timestamp OFF) on the way out so a Stage-2 upload — which HAS a
      // parent and would otherwise auto-stamp it — can never inherit it, even
      // if a future sign path forgets to lead with loadSettings. INVARIANT:
      // every iOS sign path must call loadSettings before signing (capture +
      // upload already do, with SIGN_SETTINGS_JSON); this defer is belt-and-
      // suspenders, not the primary guard.
      try Signer.loadSettings(UPDATE_MANIFEST_SETTINGS_JSON, format: .json)
      defer { try? Signer.loadSettings(SIGN_SETTINGS_JSON, format: .json) }

      let builder = try Builder(manifestJSON: manifestJSON)
      try builder.setIntent(.update)

      // TSA is REQUIRED here (the caller never drains without one) — c2pa-rs
      // fetches the token over the parent signature. Normalize like the
      // capture/upload paths; an empty/unparseable URL would silently produce
      // an un-timestamped Update Manifest, defeating the whole drain.
      let trimmedTsaUrl = tsaUrl.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmedTsaUrl.isEmpty, let parsedTsaUrl = URL(string: trimmedTsaUrl) else {
        throw PhotoAttestError(code: "INVALID_CAPTURE_CONTEXT", message: "tsaUrl is empty or invalid")
      }
      let signer = try Signer(
        algorithm: .es256,
        certificateChainPEM: certChainPEM,
        tsa: parsedTsaUrl,
        secureEnclaveConfig: SecureEnclaveSignerConfig(keyTag: alias)
      )

      // Source = the Stage-1 file (its embedded manifest becomes the parent);
      // destination = the new stamped file with Stage-1 + the Update Manifest.
      let sourceStream = try Stream(readFrom: parentURL)
      let destStream = try Stream(writeTo: destURL)
      _ = try builder.sign(
        format: format.mime,
        source: sourceStream,
        destination: destStream,
        signer: signer
      )
      destPath = destURL.path
    } catch let error as PhotoAttestError {
      if let dir = stagingDirCreated { try? FileManager.default.removeItem(at: dir) }
      throw error
    } catch {
      if let dir = stagingDirCreated { try? FileManager.default.removeItem(at: dir) }
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "C2PA Update-Manifest sign failed: \(error.localizedDescription)"
      )
    }

    // Read back the Update Manifest's URN (non-fatal — the stamp succeeded).
    var manifestId = ""
    do {
      let readStream = try Stream(readFrom: URL(fileURLWithPath: destPath))
      let reader = try Reader(format: format.mime, stream: readStream)
      manifestId = try extractActiveManifestUrn(reader.json())
    } catch {
      NSLog("[PhotoAttest] Update-Manifest URN read-back failed (non-fatal): \(error.localizedDescription)")
    }

    return ["signedMediaPath": destPath, "manifestId": manifestId]
  }

  // TSA drain. Overwrite an app-created gallery asset's bytes in place with the
  // stamped file at `sourcePath`, via PhotoKit's content-edit flow — the only
  // Apple-sanctioned way to mutate a library asset. Prompt-free for assets this
  // app created (it has read-write Photos access); the pre-stamp original stays
  // revertable. Async (PhotoKit callbacks), so this resolves the Promise
  // directly rather than returning.
  //
  // Does a PHAsset still exist for this local identifier? Used to classify
  // overwrite failures: a gone asset → ASSET_NOT_FOUND (the drain reclaims and
  // dequeues it, matching Android's FileNotFoundException → ASSET_NOT_FOUND);
  // a present-but-unwritable asset → C2PA_SIGN_FAILED (retryable). Cheap
  // synchronous fetch.
  private static func phAssetExists(_ assetId: String) -> Bool {
    PHAsset.fetchAssets(withLocalIdentifiers: [assetId], options: nil).firstObject != nil
  }

  private static func overwriteMediaLibraryAsset(
    assetId: String,
    sourcePath: String,
    promise: Promise
  ) {
    let sourceURL = URL(fileURLWithPath: sourcePath)
    guard FileManager.default.fileExists(atPath: sourceURL.path) else {
      promise.reject("C2PA_SIGN_FAILED", "stamped source file does not exist: \(sourceURL.path)")
      return
    }

    // expo-media-library's Asset.id is the PHAsset localIdentifier prefixed
    // with `ph://`; strip the scheme for PHAsset.fetchAssets.
    let localId = String(assetId.dropFirst("ph://".count))
    let fetch = PHAsset.fetchAssets(withLocalIdentifiers: [localId], options: nil)
    guard let asset = fetch.firstObject else {
      // Deleted from the gallery between enqueue and drain — caller dequeues.
      promise.reject("ASSET_NOT_FOUND", "no PHAsset for local identifier \(assetId)")
      return
    }

    let editOptions = PHContentEditingInputRequestOptions()
    // We replace the whole rendered content with our own file, so accept any
    // prior adjustment as handleable rather than bailing on already-edited assets.
    editOptions.canHandleAdjustmentData = { _ in true }
    asset.requestContentEditingInput(with: editOptions) { input, _ in
      guard let input = input else {
        // No editing input. This is the asset-deleted-after-fetch TOCTOU window
        // (and the limited / add-only Photos authorization case). Re-check
        // existence so a genuinely-gone asset is reported ASSET_NOT_FOUND (the
        // drain dequeues it) rather than C2PA_SIGN_FAILED (which would retry it
        // forever). If it's still present, it's a real, retryable failure.
        if !phAssetExists(localId) {
          promise.reject("ASSET_NOT_FOUND", "PHAsset \(assetId) no longer exists (deleted after fetch)")
        } else {
          promise.reject("C2PA_SIGN_FAILED", "could not obtain PHContentEditingInput for \(assetId) (asset present — likely limited Photos access)")
        }
        return
      }
      let output = PHContentEditingOutput(contentEditingInput: input)
      // Tag the edit so it's recognizable + revertable in Photos. Opaque Photos
      // revert marker only — deliberately NOT a c2pa assertion label (decoupled
      // to avoid the wrong-label foot-gun; c2pa never parses this).
      output.adjustmentData = PHAdjustmentData(
        formatIdentifier: "xyz.realreel.tsa.timestamp",
        formatVersion: "1",
        data: Data("realreel.tsa-drain".utf8)
      )
      do {
        if FileManager.default.fileExists(atPath: output.renderedContentURL.path) {
          try FileManager.default.removeItem(at: output.renderedContentURL)
        }
        try FileManager.default.copyItem(at: sourceURL, to: output.renderedContentURL)
      } catch {
        promise.reject("C2PA_SIGN_FAILED", "failed to stage rendered content: \(error.localizedDescription)")
        return
      }
      PHPhotoLibrary.shared().performChanges {
        let request = PHAssetChangeRequest(for: asset)
        request.contentEditingOutput = output
      } completionHandler: { success, error in
        if success {
          promise.resolve(nil)
          return
        }
        // Classify the failure: a not-found / deleted asset → ASSET_NOT_FOUND
        // (drain reclaims + dequeues, matching Android); anything else stays
        // C2PA_SIGN_FAILED (retryable). Prefer the explicit PHPhotosError code
        // when available, else fall back to a version-agnostic re-fetch.
        var gone = !phAssetExists(localId)
        if #available(iOS 15, *), let phErr = error as? PHPhotosError,
           phErr.code == .identifierNotFound {
          gone = true
        }
        if gone {
          promise.reject(
            "ASSET_NOT_FOUND",
            "PHAsset \(assetId) gone during content edit: \(error?.localizedDescription ?? "unknown")"
          )
        } else {
          promise.reject(
            "C2PA_SIGN_FAILED",
            "PhotoKit content edit failed: \(error?.localizedDescription ?? "unknown error")"
          )
        }
      }
    }
  }

  // Pull `active_manifest` (the parent's URN) out of c2pa-rs Reader's JSON.
  // Used for redaction URI expansion (`self#jumbf=/c2pa/<urn>/c2pa.assertions/<label>`).
  // Distinguishes JSON-parse failure from missing-field so debugging from
  // a STAGE1_PARENT_UNREADABLE error message points at the right cause.
  private static func extractActiveManifestUrn(_ readerJson: String) throws -> String {
    guard let data = readerJson.data(using: .utf8) else {
      throw PhotoAttestError(
        code: "STAGE1_PARENT_UNREADABLE",
        message: "Parent manifest JSON is not UTF-8 decodable"
      )
    }
    let parsed: Any
    do {
      parsed = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw PhotoAttestError(
        code: "STAGE1_PARENT_UNREADABLE",
        message: "Failed to parse parent manifest JSON: \(error.localizedDescription)"
      )
    }
    guard let dict = parsed as? [String: Any],
          let urn = dict["active_manifest"] as? String,
          !urn.isEmpty
    else {
      throw PhotoAttestError(
        code: "STAGE1_PARENT_UNREADABLE",
        message: "Parent has no 'active_manifest' field"
      )
    }
    return urn
  }

  // Walk past any interposed timestamp Update Manifest(s) in the parent's
  // manifest store to the real CAPTURE manifest's URN — the manifest that
  // actually carries the redactable assertions (stds.exif / stds.iptc /
  // org.realreel.capture). c2pa.redacted URIs must target THIS urn, not the
  // immediate-parent urn: for a once-offline-then-TSA-drained parent the active
  // manifest is the Update Manifest (carries a `c2pa.time-stamp` assertion + a
  // parentOf to the capture), which holds no GPS — so redacting against it
  // would miss the capture's GPS and leak location. c2pa-rs permits redacting a
  // grandparent assertion through the chain (redaction.md). For a never-offline
  // parent the active manifest IS the capture, so this returns the same urn as
  // extractActiveManifestUrn (no behavior change on the common path).
  private static func extractCaptureManifestUrn(_ readerJson: String) throws -> String {
    let activeUrn = try extractActiveManifestUrn(readerJson)
    guard let data = readerJson.data(using: .utf8),
          let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let manifests = root["manifests"] as? [String: Any]
    else {
      return activeUrn
    }
    var cur = activeUrn
    var depth = 0
    // Cap matches the verifier + client gate (MAX_UPDATE_MANIFEST_DEPTH = 4);
    // fails open to the active urn, so it can never crash.
    while depth < 4 {
      guard let m = manifests[cur] as? [String: Any] else { break }
      let assertions = (m["assertions"] as? [[String: Any]]) ?? []
      let hasTimestamp = assertions.contains { ($0["label"] as? String) == "c2pa.time-stamp" }
      let ingredients = (m["ingredients"] as? [[String: Any]]) ?? []
      let parentLabel = ingredients
        .first { ($0["relationship"] as? String) == "parentOf" }?["active_manifest"] as? String
      // Only an interposed timestamp Update Manifest (has c2pa.time-stamp AND a
      // parentOf) is walked past; the capture (no timestamp assertion) ends it.
      guard hasTimestamp, let parent = parentLabel, !parent.isEmpty else { break }
      cur = parent
      depth += 1
    }
    return cur
  }

  // Builds the org.realreel.app_attest assertion entry from a JS-supplied
  // envelope dict. STAGE 2 (upload) ONLY. Returns nil when no envelope is
  // supplied. Throws INVALID_CAPTURE_CONTEXT when an envelope IS present but
  // any sub-field is missing — fail-loud rather than silently dropping the
  // assertion, since the verifier tolerates a missing one and a buggy JS
  // regression would slip past.
  //
  // The verifier (Stage 2): re-derives clientDataHash = SHA256(challenge_bytes
  // || SE_SPKI_bytes), validates Apple's signature chain, and burns the
  // challenge nonce single-use.
  //
  // The result is embedded as a manifest assertion so c2pa-rs's COSE_Sign1
  // hash-binds it — a tampered runtime can't strip or swap this assertion
  // without invalidating the signature.
  private static func appAttestAssertionEntry(
    envelope: [String: Any]?
  ) throws -> [String: Any]? {
    // Nil envelope is a silent no-op (returns nil; caller skips assertion).
    // On iOS this should never happen in production — the JS upload path always
    // produces an iOS envelope for Stage 2. If it ever does, the manifest is
    // unattested and the Stage-2 strict verifier rejects the upload; flagged
    // here so future readers don't mistake nil-handling for a missing platform
    // check.
    guard let envelope = envelope else { return nil }
    // Bridge field is the single, cross-platform `attestationEnvelope` — iOS
    // only honors entries marked `platform: "ios"`. An Android-shaped payload
    // reaching iOS (or vice versa) is a JS routing bug; fail loud rather than
    // silently dropping the assertion (which a lenient verifier gate would
    // otherwise tolerate as "no envelope").
    let platform = envelope["platform"] as? String
    if platform != "ios" {
      throw PhotoAttestError(
        code: "INVALID_CAPTURE_CONTEXT",
        message: "attestationEnvelope.platform must be 'ios' on iOS (got '\(platform ?? "(missing)")')"
      )
    }
    guard
      let keyId = envelope["keyId"] as? String,
      let challenge = envelope["challenge"] as? String,
      let assertion = envelope["assertion"] as? String,
      !keyId.isEmpty,
      !challenge.isEmpty,
      !assertion.isEmpty
    else {
      throw PhotoAttestError(
        code: "INVALID_CAPTURE_CONTEXT",
        message: "attestationEnvelope is present but missing keyId / challenge / assertion"
      )
    }
    return [
      "label": "org.realreel.app_attest",
      "data": [
        "keyId": keyId,
        "challenge": challenge,
        "assertion": assertion,
        "platform": "ios",
      ] as [String: Any],
    ]
  }

  // Builds the manifest JSON payload handed to c2pa-rs. setIntent(.create(...))
  // adds the c2pa.created action with digitalSourceType automatically, so we
  // only need to enumerate non-action assertions here.
  private static func buildCaptureManifestJSON(
    sourceURL: URL,
    mime: String,
    isVideo: Bool,
    capturerUuid: String,
    gps: [String: Any]?,
    title: String,
    captureTimestampMs: Double?
  ) throws -> String {
    let appName = "RealReel"
    let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    let claimGenerator = "\(appName)/\(appVersion)"

    var assertions: [[String: Any]] = []

    if isVideo {
      if let iptcData = extractIptcAssertionForVideo(
        at: sourceURL,
        gps: gps,
        captureTimestampMs: captureTimestampMs
      ) {
        assertions.append([
          "label": "stds.iptc",
          "data": iptcData,
        ])
      }
    } else {
      if let exifData = extractExifAssertionForImage(at: sourceURL, gps: gps) {
        assertions.append([
          "label": "stds.exif",
          "data": exifData,
        ])
      }
    }

    let device = UIDevice.current
    // Hardware identifier (e.g. "iPhone15,2") is more useful than the
    // marketing-name `model` for "what device captured this" — it disambiguates
    // SKUs that share a name. Fallback to `model` if utsname parse fails.
    var sysinfo = utsname()
    uname(&sysinfo)
    let hardwareModel: String = withUnsafePointer(to: &sysinfo.machine) {
      $0.withMemoryRebound(to: CChar.self, capacity: 1) {
        String(cString: $0)
      }
    }
    let realreelCapture: [String: Any] = [
      "capturerUuid": capturerUuid,
      "deviceManufacturer": "Apple",
      "deviceModel": hardwareModel.isEmpty ? device.model : hardwareModel,
      "osVersion": "\(device.systemName) \(device.systemVersion)",
      "appVersion": appVersion,
      "deviceTrustLevel": "secure-enclave",
    ]
    assertions.append([
      "label": "org.realreel.capture",
      "data": realreelCapture,
    ])

    let manifest: [String: Any] = [
      "claim_generator": claimGenerator,
      "claim_generator_info": [["name": appName, "version": appVersion]],
      "format": mime,
      "title": title,
      "assertions": assertions,
    ]

    let data = try JSONSerialization.data(
      withJSONObject: manifest,
      options: [.sortedKeys]
    )
    guard let json = String(data: data, encoding: .utf8) else {
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "Failed to serialize manifest JSON"
      )
    }
    return json
  }

  // Build manifest JSON for Stage 2 (upload-time signing). Mirrors
  // buildCaptureManifestJSON but threads the JS-supplied actions list and
  // optional claim thumbnail. c2pa-rs's BuilderIntent.edit auto-prepends
  // c2pa.opened referring to the parent ingredient, so we don't include it
  // ourselves.
  //
  // Redaction handling: any { action: "c2pa.redacted", parameters:
  // { assertionLabel } } entries are split off into the manifest's top-level
  // `redactions` array (URI form expanded via redactionTargetUrn = the CAPTURE
  // manifest's urn), AND emitted into c2pa.actions.v2 as { action:
  // "c2pa.redacted", parameters: { redacted: <uri> } } so the action list stays
  // self-describing. c2pa-rs zero-fills the referenced JUMBF Content boxes
  // during sign — including a grandparent capture's assertion when an interposed
  // timestamp Update Manifest sits between Stage 2 and the capture.
  private static func buildUploadManifestJSON(
    transformedURL: URL,
    transformedMime: String,
    isVideo: Bool,
    gps: [String: Any]?,
    captureTimestampMs: Double?,
    title: String,
    actions: [[String: Any]],
    redactionTargetUrn: String,
    /// (mime, identifier) of the claim thumbnail to embed, or nil.
    claimThumbnailRef: (mime: String, identifier: String)?,
    attestationEnvelope: [String: Any]?
  ) throws -> String {
    let appName = "RealReel"
    let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    let claimGenerator = "\(appName)/\(appVersion)"

    var assertions: [[String: Any]] = []

    // Build c2pa.actions.v2 from JS-supplied actions; redactions expand the
    // assertionLabel into a JUMBF URI and also collect into the top-level
    // `redactions` array.
    var actionsArray: [[String: Any]] = []
    var redactionUris: [String] = []
    for entry in actions {
      guard let actionName = entry["action"] as? String else { continue }
      let params = entry["parameters"] as? [String: Any]
      if actionName == "c2pa.redacted" {
        guard let label = params?["assertionLabel"] as? String else { continue }
        let uri = "self#jumbf=/c2pa/\(redactionTargetUrn)/c2pa.assertions/\(label)"
        redactionUris.append(uri)
        actionsArray.append([
          "action": actionName,
          "parameters": ["redacted": uri],
        ])
      } else {
        var entryOut: [String: Any] = ["action": actionName]
        if let p = params { entryOut["parameters"] = p }
        actionsArray.append(entryOut)
      }
    }
    if !actionsArray.isEmpty {
      assertions.append([
        "label": "c2pa.actions.v2",
        "data": ["actions": actionsArray],
      ])
    }

    // Stage-2 metadata describes the TRANSFORMED file (e.g. new dimensions).
    if isVideo {
      if let iptcData = extractIptcAssertionForVideo(
        at: transformedURL,
        gps: gps,
        captureTimestampMs: captureTimestampMs
      ) {
        assertions.append([
          "label": "stds.iptc",
          "data": iptcData,
        ])
      }
    } else {
      if let exifData = extractExifAssertionForImage(at: transformedURL, gps: gps) {
        assertions.append([
          "label": "stds.exif",
          "data": exifData,
        ])
      }
    }

    let device = UIDevice.current
    var sysinfo = utsname()
    uname(&sysinfo)
    let hardwareModel: String = withUnsafePointer(to: &sysinfo.machine) {
      $0.withMemoryRebound(to: CChar.self, capacity: 1) {
        String(cString: $0)
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
    let realreelUpload: [String: Any] = [
      "deviceManufacturer": "Apple",
      "deviceModel": hardwareModel.isEmpty ? device.model : hardwareModel,
      "osVersion": "\(device.systemName) \(device.systemVersion)",
      "appVersion": appVersion,
      "deviceTrustLevel": "secure-enclave",
    ]
    assertions.append([
      "label": "org.realreel.upload",
      "data": realreelUpload,
    ])

    if let appAttestEntry = try appAttestAssertionEntry(envelope: attestationEnvelope) {
      assertions.append(appAttestEntry)
    }

    var manifest: [String: Any] = [
      "claim_generator": claimGenerator,
      "claim_generator_info": [["name": appName, "version": appVersion]],
      "format": transformedMime,
      "title": title,
      "assertions": assertions,
    ]
    if !redactionUris.isEmpty {
      manifest["redactions"] = redactionUris
    }
    if let ref = claimThumbnailRef {
      manifest["thumbnail"] = [
        "format": ref.mime,
        "identifier": ref.identifier,
      ]
    }

    let data = try JSONSerialization.data(
      withJSONObject: manifest,
      options: [.sortedKeys]
    )
    guard let json = String(data: data, encoding: .utf8) else {
      throw PhotoAttestError(
        code: "C2PA_SIGN_FAILED",
        message: "Failed to serialize Stage-2 manifest JSON"
      )
    }
    return json
  }

  // ImageIO returns nested dicts keyed by Exif/TIFF/GPS — we flatten the Exif
  // and TIFF dicts with namespace prefixes that match the stds.exif schema.
  // We don't reformat values (e.g. exposure rationals stay as-is); the
  // verifier accepts what the camera wrote and signs the bytes verbatim.
  //
  // GPS is intentionally NOT extracted from the file — it comes from the
  // JS-supplied `gps` map (single source of truth; see
  // `SignC2PACaptureOptions.gps` for the rationale). This keeps iOS and
  // Android emitting identical assertion shapes regardless of platform-
  // specific EXIF readback quirks.
  private static func extractExifAssertionForImage(
    at url: URL,
    gps: [String: Any]?
  ) -> [String: Any]? {
    guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
          let raw = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [String: Any]
    else { return nil }

    var out: [String: Any] = [:]

    if let exif = raw[kCGImagePropertyExifDictionary as String] as? [String: Any] {
      for (k, v) in exif { out["exif:\(k)"] = v }
    }
    if let tiff = raw[kCGImagePropertyTIFFDictionary as String] as? [String: Any] {
      for (k, v) in tiff { out["tiff:\(k)"] = v }
    }

    emitJsGpsToExif(into: &out, gps: gps)

    return out.isEmpty ? nil : out
  }

  // Decimal-degree GPS straight from JS into the assertion. Lockstep with
  // Android: identical key set, identical reference-letter derivation,
  // identical GPSAltitudeRef integer convention (0 = above sea level,
  // 1 = below). Non-finite values (NaN/Infinity) are silently skipped per
  // field — the JS layer is the source of truth, but a transient Location
  // service quirk shouldn't hard-fail capture.
  private static func emitJsGpsToExif(into out: inout [String: Any], gps: [String: Any]?) {
    guard let gps = gps else { return }
    let lat = (gps["latitude"] as? NSNumber)?.doubleValue
    let lon = (gps["longitude"] as? NSNumber)?.doubleValue
    let alt = (gps["altitude"] as? NSNumber)?.doubleValue
    let tsMs = (gps["timestampMs"] as? NSNumber)?.doubleValue

    if let lat = lat, lat.isFinite {
      out["exif:GPSLatitude"] = lat
      out["exif:GPSLatitudeRef"] = lat >= 0 ? "N" : "S"
    }
    if let lon = lon, lon.isFinite {
      out["exif:GPSLongitude"] = lon
      out["exif:GPSLongitudeRef"] = lon >= 0 ? "E" : "W"
    }
    if let alt = alt, alt.isFinite {
      out["exif:GPSAltitude"] = alt
      out["exif:GPSAltitudeRef"] = alt >= 0 ? 0 : 1
    }
    if let tsMs = tsMs, tsMs.isFinite {
      let date = Date(timeIntervalSince1970: tsMs / 1000.0)
      var cal = Calendar(identifier: .gregorian)
      cal.timeZone = TimeZone(identifier: "UTC")!
      let comps = cal.dateComponents(
        [.year, .month, .day, .hour, .minute, .second],
        from: date
      )
      if let y = comps.year, let mo = comps.month, let d = comps.day,
         let h = comps.hour, let mi = comps.minute, let s = comps.second {
        out["exif:GPSDateStamp"] = String(format: "%04d:%02d:%02d", y, mo, d)
        out["exif:GPSTimeStamp"] = String(format: "%02d:%02d:%02d", h, mi, s)
      }
    }
  }

  // AVAsset metadata is keyed by AVMetadataKey constants. We pull the QuickTime
  // common keys that map cleanly to IPTC fields. Device identity is also
  // duplicated into the RealReel device-identity assertion (single source of
  // truth across platforms; org.realreel.capture in Stage 1,
  // org.realreel.upload in Stage 2), so this IPTC payload is only useful
  // when present.
  //
  // Location: we deliberately do NOT project commonKey.location (the camera's
  // ISO 6709 string, e.g. "+34.29-119.29+/") into the assertion. Per IPTC
  // Video Metadata Hub, `Iptc4xmpExt:LocationCreated` is an array of structured
  // location objects, not a flat string — putting an ISO 6709 string there is
  // non-conformant. The camera's location claim is still cryptographically
  // protected by `c2pa.hash.bmff.v3` via the QuickTime location atom in the
  // file bytes; we just don't duplicate it as a misshapen JSON projection.
  // Our structured form is emitted by `emitJsGpsToIptc` from JS-supplied
  // coords below.
  //
  // dc:date fallback chain — camera-supplied values are preserved as
  // faithfully as the platform API allows; this fallback never substitutes
  // a different value when the camera wrote one:
  //   1. asset.metadata commonKey.creationDate — Apple's API returns a typed
  //      `Date`. We serialize as ISO 8601 UTC since there's no literal camera
  //      string to preserve.
  //   2. asset.creationDate (separate Apple API; sometimes catches what (1)
  //      misses). Same Date → ISO 8601 serialization.
  //   3. JS-supplied `captureTimestampMs` formatted as ISO 8601 UTC.
  //
  // Behavior diverges slightly from Android (whose layer 1 passes a string
  // through verbatim) — that's an artifact of Apple returning typed Dates
  // vs Android returning strings, not a deliberate parity decision.
  //
  // xmpDM:duration is always emitted when AVAsset can compute it (which is
  // every well-formed playable file), since duration isn't a metadata atom
  // but is derived from the track timing — there's nothing camera-side
  // to "win" against.
  private static func extractIptcAssertionForVideo(
    at url: URL,
    gps: [String: Any]?,
    captureTimestampMs: Double?
  ) -> [String: Any]? {
    let asset = AVURLAsset(url: url)
    var out: [String: Any] = [:]
    var hasDate = false

    for item in asset.metadata {
      guard let key = item.commonKey?.rawValue
      else { continue }
      switch key {
      case AVMetadataKey.commonKeyCreationDate.rawValue:
        if let date = item.dateValue {
          out["dc:date"] = isoUtcFormat(date)
          hasDate = true
        } else if let value = item.value as? NSObject {
          // Non-Date value (rare); preserve the camera's string verbatim.
          out["dc:date"] = "\(value)"
          hasDate = true
        }
      case AVMetadataKey.commonKeyMake.rawValue:
        // Apple QuickTime "make" → IPTC has no clean equivalent; leave to
        // the RealReel device-identity assertion (org.realreel.capture in
        // Stage 1, org.realreel.upload in Stage 2). Recorded here only
        // for completeness when ingest needs it.
        if let value = item.value as? NSObject {
          out["xmpDM:videoCameraManufacturer"] = "\(value)"
        }
      case AVMetadataKey.commonKeyModel.rawValue:
        if let value = item.value as? NSObject {
          out["xmpDM:videoCameraModel"] = "\(value)"
        }
      // commonKey.location intentionally omitted — see file-level comment.
      default:
        continue
      }
    }

    // Layer 2: AVAsset.creationDate (separate API surface from metadata loop).
    if !hasDate, let creation = asset.creationDate?.dateValue {
      out["dc:date"] = isoUtcFormat(creation)
      hasDate = true
    }

    // Layer 3: JS fallback, only if file had nothing.
    if !hasDate, let tsMs = captureTimestampMs, tsMs.isFinite {
      out["dc:date"] = isoUtcFormat(Date(timeIntervalSince1970: tsMs / 1000.0))
    }

    // Duration: always available from the asset's track timing. CMTime's
    // `.seconds` is iOS 13+; we already require iOS ≥ 14 (App Attest floor).
    let durSecs = asset.duration.seconds
    if durSecs.isFinite && durSecs > 0 {
      out["xmpDM:duration"] = durSecs
    }

    emitJsGpsToIptc(into: &out, gps: gps)

    return out.isEmpty ? nil : out
  }

  // ISO 8601 UTC ("2026-05-09T13:12:41Z"). Used for all three dc:date
  // layers so verifier-side tooling sees a consistent shape regardless
  // of which fallback fired.
  private static func isoUtcFormat(_ date: Date) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime]
    formatter.timeZone = TimeZone(identifier: "UTC")
    return formatter.string(from: date)
  }

  // Decimal-degree GPS straight from JS into the IPTC video assertion.
  // Shape matches IPTC Video Metadata Hub's published C2PA sample — see
  // https://iptc.org/std/videometadatahub/examples/c2pa/. `LocationCreated`
  // is an array of structured location objects; GPS lives nested inside as
  // `exif:GPS{Latitude,Longitude,Altitude}` with signed decimal degrees and
  // no separate `*Ref` fields (sign carries direction).
  //
  // Lockstep with Android — same shape, same key set. Non-finite values
  // silently skipped per field. We omit timestamp here because the IPTC
  // LocationCreated structure has no timestamp slot — capture time lives
  // separately in `dc:date`. We omit the JS `gps.timestampMs` (which carries
  // GPS-fix time, not capture time) entirely from the IPTC projection.
  private static func emitJsGpsToIptc(into out: inout [String: Any], gps: [String: Any]?) {
    guard let gps = gps else { return }
    let lat = (gps["latitude"] as? NSNumber)?.doubleValue
    let lon = (gps["longitude"] as? NSNumber)?.doubleValue
    let alt = (gps["altitude"] as? NSNumber)?.doubleValue

    let finiteLat = lat.flatMap { $0.isFinite ? $0 : nil }
    let finiteLon = lon.flatMap { $0.isFinite ? $0 : nil }
    let finiteAlt = alt.flatMap { $0.isFinite ? $0 : nil }

    // Need at least one usable coord to emit anything.
    if finiteLat == nil && finiteLon == nil && finiteAlt == nil { return }

    var location: [String: Any] = [:]
    if let lat = finiteLat { location["exif:GPSLatitude"] = lat }
    if let lon = finiteLon { location["exif:GPSLongitude"] = lon }
    if let alt = finiteAlt { location["exif:GPSAltitude"] = alt }

    out["Iptc4xmpExt:LocationCreated"] = [location]
  }

  // SecKeyCopyExternalRepresentation returns a 65-byte uncompressed X9.62
  // point (0x04 || X || Y). Wrap it in the standard SPKI envelope so the
  // server can ingest via crypto.subtle.importKey('spki', ...).
  private static func spkiDerForP256(publicKey: SecKey) throws -> Data {
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      let err = error?.takeRetainedValue()
      throw PhotoAttestError(
        code: "HARDWARE_UNAVAILABLE",
        message: err.map { "\($0)" } ?? "SecKeyCopyExternalRepresentation returned nil"
      )
    }
    let header: [UInt8] = [
      0x30, 0x59,                                                 // SEQUENCE (89 bytes)
      0x30, 0x13,                                                 //   SEQUENCE (19 bytes)
      0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,       //     OID 1.2.840.10045.2.1 ecPublicKey
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, //     OID 1.2.840.10045.3.1.7 prime256v1
      0x03, 0x42, 0x00,                                           //   BIT STRING (66 bytes, 0 unused)
    ]
    return Data(header) + raw
  }

  // Local-time YYYYMMDD-HHmmss for gallery-friendly filenames.
  private static func captureTimestamp() -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyyMMdd-HHmmss"
    return formatter.string(from: Date())
  }
}
