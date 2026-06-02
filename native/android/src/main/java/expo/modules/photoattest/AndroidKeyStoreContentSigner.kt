package expo.modules.photoattest

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.ContentSigner
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.PrivateKey
import java.security.Signature

/**
 * Bridges an AndroidKeyStore-backed EC private key into BouncyCastle's
 * [ContentSigner] interface so [org.bouncycastle.cert.X509v3CertificateBuilder]
 * can sign certs without ever extracting the key from hardware.
 *
 * BouncyCastle's [org.bouncycastle.cert.X509v3CertificateBuilder] requires a
 * [ContentSigner] to do the actual signing, so some adapter from our key to
 * that interface is mandatory. BC's standard
 * [org.bouncycastle.operator.jcajce.JcaContentSignerBuilder] also implements
 * the interface (routing through `Signature.getInstance("SHA256withECDSA")`)
 * and works in many cases with AndroidKeyStore keys. We use this explicit
 * adapter instead because it avoids any BC code paths that try to introspect
 * raw key material — which AndroidKeyStore restricts for non-extractable keys.
 *
 * Algorithm fixed to ES256 / ecdsa-with-SHA256 — the only signing algorithm
 * RealReel uses today. Adding RSA/etc. would mean switching on
 * [PrivateKey.getAlgorithm].
 */
internal class AndroidKeyStoreContentSigner(
  private val privateKey: PrivateKey,
) : ContentSigner {
  private val buf = ByteArrayOutputStream()

  // ecdsa-with-SHA256 (1.2.840.10045.4.3.2), no params per RFC 5758.
  private val sigAlgId = AlgorithmIdentifier(
    ASN1ObjectIdentifier("1.2.840.10045.4.3.2")
  )

  override fun getAlgorithmIdentifier(): AlgorithmIdentifier = sigAlgId

  override fun getOutputStream(): OutputStream = buf

  override fun getSignature(): ByteArray {
    // Snapshot + reset so the adapter can be safely reused across multiple
    // build() calls (e.g. signing a CSR and a cert with one signer). BC's
    // current call pattern is single-shot per builder, so this is purely
    // defensive — but cheap, and prevents a silent stale-buffer signature
    // bug if reuse is introduced later.
    val data = buf.toByteArray()
    buf.reset()
    val sig = Signature.getInstance("SHA256withECDSA").apply {
      initSign(privateKey)
      update(data)
    }
    // Returns DER ECDSA-Sig-Value bytes — the format BC's certificate
    // signing path expects. The COSE conversion to P1363 happens later at
    // c2pa-android's signing layer, not here.
    return sig.sign()
  }
}
