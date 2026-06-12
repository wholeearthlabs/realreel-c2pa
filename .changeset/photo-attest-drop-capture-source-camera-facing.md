---
"@realreel/photo-attest": minor
---

Drop `captureSource` and `cameraFacing` from the `org.realreel.capture` capture assertion.

`captureSource` was a hardcoded constant (`"in-app-camera"`) that carried no information — the assertion is only ever emitted by RealReel's own capture signer, so a third-party/wrap-mode parent never sets it. `cameraFacing` (`front`/`back`) was informational only and was never read by the verifier or trust list. Both are removed from the iOS and Android signers and from the `SignC2PACaptureOptions` bridge in lockstep; the assertion now carries `capturerUuid`, `deviceManufacturer`, `deviceModel`, `osVersion`, `appVersion`, and `deviceTrustLevel`.
