---
"@realreel/verifier": minor
---

Enforce the Play Integrity `requestHash` binding on Android Stage 2 uploads. The verifier rebuilds `base64url(SHA256(challenge || signing-key SPKI))` from the manifest's challenge and the enrollment-stored public key, and requires the decoded token's `requestDetails.requestHash` to equal it (constant-time compare). A token whose hash is missing or differs is rejected as `ATTESTATION_INVALID`. An Android Stage 2 row with no stored public key is also rejected as `ATTESTATION_INVALID`, in strict and lenient mode alike (the same rule the iOS App Attest path already applies); such rows only occur for revoked keys, which reject earlier. Until now the challenge lived only outside the token, so any fresh token for the package could be paired with any key's nonce. The Android module has sent this binding since photo-attest 0.1.0, so no app change is needed. Lenient mode (no Play Integrity config) still skips the Google decode and therefore the hash check.
