---
"@realreel/verifier": minor
---

The verifier's engine moves to `@contentauth/c2pa-node` 0.9.10 (c2pa-rs 0.91.3), and the crJSON harness to `c2patool` 0.28.2 (c2pa-rs 0.91.2), now downloaded from `contentauth/c2patool`.

- Network revocation accepts an OCSP answer only from a responder whose certificate carries OCSP signing and chains to a trust anchor, so a party on the path to the responder can no longer forge a `good` answer.
- c2pa-rs 0.91 files a stapled response's `notRevoked` as `success`. The parent revocation gate now counts only a fetched answer (`url` `OCSP_RESPONSE`), so a staple still never satisfies it.
- The trust check now requires every certificate in the chain to be valid at signing time, and c2pa-rs logs it before the certificate profile. An expired signer therefore reads `untrusted` and then `expired`; the classifier still maps that pair to `CERT_EXPIRED`.
- Trust settings use the c2pa-rs 0.91 `trust.anchors[]` shape.
