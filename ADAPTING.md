# Adapting this for your own app

This repository is **RealReel's actual** C2PA signing and verification stack,
published as a reference implementation. It is **not a turnkey SDK** — it's built
around RealReel's specific model (a two-stage, force-wrapped manifest; the
RealReel CA; the `org.realreel.*` assertion namespace; the `user_signing_keys`
registry schema), so expect to **adapt**, not drop in. Below: what's genuinely
reusable, what's RealReel-specific, and exactly what you'd change.

## What's reusable

| Workspace | Reuse value |
|---|---|
| `native/` | A strong reference for hardware-backed C2PA capture signing: generate a key in the Secure Enclave / StrongBox, attest it (App Attest / Key Attestation), build a CSR, and sign a C2PA manifest on-device. The crypto patterns transfer to any app. |
| `ca/` attestation validators | `ca/_shared/attestation/{apple,android}.ts` are largely generic server-side validators for Apple App Attest and Android Key Attestation. Reusable with little change. |
| `verifier/` | The validation *patterns* — cert-chain trust against a configurable trust list, App Attest / Play Integrity server checks, RFC 3161 timestamp validation, and the pluggable datastore port — are reusable. The two-stage + force-wrap + RealReel-CA *policy* is RealReel-specific. |
| `trust-core/` | Mostly RealReel-specific (it encodes RealReel's trust list + policies), but a clean example of sharing one policy source between a client and a server. |

## The swap-points

The RealReel-specific identity values live in known places. The verifier and CA
read them from the environment (with RealReel's values as the defaults, so the
tests and the reference deploy run unconfigured); the native values are
build-time constants.

| What | Where | How to change |
|---|---|---|
| Apple Team ID | `ca/_shared/config.ts`, `verifier/src/attestation/apple.ts` | env `APPLE_TEAM_ID` |
| Apple bundle ID | `ca/_shared/config.ts`, `verifier/src/attestation/apple.ts` | env `APPLE_BUNDLE_ID` |
| Android package | `ca/_shared/config.ts` | env `ANDROID_PACKAGE_NAME` |
| Play Integrity package + project (verifier) | verifier config | env `PLAY_INTEGRITY_PACKAGE_NAME`, `PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER` |
| Play Integrity project (native) | `native/android/.../PhotoAttestModule.kt` (`CLOUD_PROJECT_NUMBER`) | edit the constant (native build-time) |
| CSR subject DN (native) | `native/{android,ios}/...` constants | edit the constants — but note the CA overwrites the leaf subject at issuance, so these never reach a published cert |
| Leaf cert subject DN | `ca/_shared/attestation/pki.ts` | env `LEAF_SUBJECT_COUNTRY` / `LEAF_SUBJECT_ORG` / `LEAF_SUBJECT_OU` / `LEAF_SUBJECT_CN` |
| Asset-storage SSRF allowlist | verifier config | env `ASSET_STORAGE_HOST_REGEX`, `ASSET_STORAGE_HOST_ALLOWLIST` |

## The big-ticket changes (beyond config)

Three things aren't a config flip — they're the heart of what makes this
*RealReel's* stack:

1. **Your own CA.** Replace `verifier/trust-sources/realreel/root.pem` with your
   CA's root, run your own issuing hierarchy (the `register-signing-key` function
   signs leaves via a Cloud KMS HSM key), and update
   `trust-core/src/trust-list/trusted-issuers.ts` + `verifier/trust-sources.yaml`.
   **Note:** the verifier matches trust on the *issuer* DN (your CA's subject),
   not the leaf subject — so rebranding means re-issuing your CA hierarchy, not
   just changing the leaf-DN env vars above.
2. **Your assertion namespace.** RealReel emits `org.realreel.capture` /
   `org.realreel.app_attest` / `org.realreel.play_integrity`. Rename to your own
   namespace on both the signing (`native/`) and verifying (`verifier/`) sides.
3. **Your datastore.** The verifier abstracts its two stateful dependencies —
   revocation lookup and single-use nonce burn — behind the `VerifierDatastore`
   port (`verifier/src/ports.ts`). Implement that interface over your own store
   and pass it to `verify()`; the default is a Postgres adapter
   (`verifier/src/db.ts`).

## What you can't easily reuse

The **two-stage, force-wrapped** manifest model is baked into the verifier's
single ingestion profile (`verifier/src/profiles/realreel.ts`). If your product
doesn't re-sign every upload (RealReel does, to resize/compress — see
[`TRUST_ARCHITECTURE.md`](./TRUST_ARCHITECTURE.md)), you'll be forking that
profile, not configuring it.

## Support

This is a reference implementation, offered **best-effort** with no support or
stability promise. For security issues, see [`SECURITY.md`](./SECURITY.md).
