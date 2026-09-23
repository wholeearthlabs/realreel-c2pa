---
"@realreel/verifier": minor
---

Enforce the Play Integrity `requestHash` binding on Android Stage 2 uploads. The verifier rebuilds `base64url(SHA256(challenge || signing-key SPKI))` from the manifest's challenge and the enrollment-stored public key, and requires the decoded token's `requestDetails.requestHash` to equal it (constant-time compare). A token whose hash is missing or differs, or an Android row with no stored public key, is rejected as `ATTESTATION_INVALID`. Until now the challenge lived only outside the token, so any fresh token for the package could be paired with any key's nonce. The Android module has sent this binding since photo-attest 0.1.0, so no app change is needed; lenient mode (no Play Integrity config) is unchanged.
