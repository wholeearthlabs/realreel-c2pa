# @realreel/verifier

## 0.9.0

### Minor Changes

- [`aa7aee0`](https://github.com/wholeearthlabs/realreel-c2pa/commit/aa7aee03a3a8dbaae2f3ff7b399ef02355069f37) Thanks [@boojamya](https://github.com/boojamya)! - Remove `c2pa.cropped` from the Stage-2 action allowlist, the content-hash extent set, and the `Stage2Action` union. The app never emits it, and an allowlisted-but-unemitted action is free attack surface — a declared crop could trim away the telltale edges of a recaptured scene. Any Stage 2 manifest declaring a crop now hard-rejects (`SIGNATURE_INVALID`); no published manifest ever carried the action, so no stored media or `content_hash` is affected.

### Patch Changes

- [#39](https://github.com/wholeearthlabs/realreel-c2pa/pull/39) [`5d1ce6a`](https://github.com/wholeearthlabs/realreel-c2pa/commit/5d1ce6ab31ebfe24d12b0ceb9ce3df1c243ca4ce) Thanks [@dependabot](https://github.com/apps/dependabot)! - Update the C2PA engine: `@contentauth/c2pa-node` 0.8.0 → 0.8.3 and `@contentauth/c2pa-types` 0.7.2 → 0.7.3, which carries `c2pa-rs` 0.90.3 → 0.90.5.

  Unlike the last engine bump, this one is worth a redeploy for the read path rather than the builder: 0.90.4 replaces the `mp4` crate with a hardened native BMFF sample reader (CAI-12277), rejects timed-media BMFF Merkle maps that verify against no track, hardens the ID3 v2.3 frame decoder against integer underflow, and tightens URI checks for (data)boxes reached through redactions; 0.90.5 fixes an integer-underflow panic in `read_desc_box` via a JUMD toggle-driven field-size mismatch. Every one of those is a stricter verdict or a removed panic on attacker-supplied bytes — none relaxes a check. The full verification suite passes unchanged against the real fixture media.

  The published tarball still bundles a single-arch `linux/amd64` prebuilt with a glibc 2.34 floor, so the image's `--platform=linux/amd64` + `--ignore-scripts` + bookworm assumptions are unchanged.

  Also bumps `fastify` 5.11.0 → 5.11.3.

- Updated dependencies [[`aa7aee0`](https://github.com/wholeearthlabs/realreel-c2pa/commit/aa7aee03a3a8dbaae2f3ff7b399ef02355069f37), [`6e533a6`](https://github.com/wholeearthlabs/realreel-c2pa/commit/6e533a644983aeab0354824a646590064b5efc60)]:
  - @realreel/c2pa-trust-core@0.6.0

## 0.8.1

### Patch Changes

- [`5001976`](https://github.com/wholeearthlabs/realreel-c2pa/commit/50019764d14e33aed8e5c752d71fd1bebccb866e) Thanks [@boojamya](https://github.com/boojamya)! - Read GPS from the C2PA 2.x `c2pa.metadata` assertion (with permanent fallback to the deprecated `stds.exif` / `stds.iptc` for pre-cutover app builds and third-party wrap-mode parents), and parse XMP GPSCoordinate strings (`"34,16.8548N"`) in addition to signed decimals. Must be deployed BEFORE any `@realreel/photo-attest` ≥ 0.4.0 signer ships — otherwise the location-privacy backstop hard-rejects precise-location uploads (`LOCATION_PRIVACY_VIOLATION`).

- [#36](https://github.com/wholeearthlabs/realreel-c2pa/pull/36) [`1f21fa6`](https://github.com/wholeearthlabs/realreel-c2pa/commit/1f21fa6bae5a4751ad40d7a0994c448b08d70c81) Thanks [@dependabot](https://github.com/apps/dependabot)! - Update the verifier's server-side dependencies: `@sentry/node` 8.55.2 → 10.69.0, `google-auth-library` 9.15.1 → 11.0.0, and `pino` 9.14.0 → 10.3.1.

  `google-auth-library` v11's only breaking change is raising the floor to Node >= 22, and the image is `node:24-bookworm-slim`. The surface this service uses — `new GoogleAuth({ scopes })` and `getAccessToken(): Promise<string | null | undefined>` — is unchanged from v9, so Play Integrity token decoding is untouched. The v10 churn (the `Request`/`Transporter` overhaul) doesn't reach either call. Worth noting for the deploy: the transitive `gcp-metadata` moves 6.1.1 → 8.1.2, which is the Application Default Credentials path against Cloud Run's metadata server — the one code path the suite mocks rather than exercises. It fails closed (`VERIFIER_UNAVAILABLE`, retryable), never into an attestation bypass.

  `pino` 10 keeps the same default JSON shape (`level`/`time`/`pid`/`hostname`/`msg`), so Cloud Logging field extraction is unaffected. Fastify 5.11 already declares `pino ^9.14.0 || ^10.1.0`, so the bump stays deduped to a single copy.

  `@sentry/node` 10 shrinks rather than grows the image: `@sentry` + `@opentelemetry` together drop from ~68 MB to ~51 MB. `init()` and `captureMessage()` keep their v8 signatures, and both still work from ESM without an `--import` loader — which is how `observability.ts` and the trust loader call them.

  `pino-pretty` 11 → 13 lands alongside this but carries no changeset: it is a dev dependency, and the runtime image installs with `--omit=dev`.

- Updated dependencies [[`bfae840`](https://github.com/wholeearthlabs/realreel-c2pa/commit/bfae840b3c9b62c6dbb80b9f3012d088a454ab63), [`5001976`](https://github.com/wholeearthlabs/realreel-c2pa/commit/50019764d14e33aed8e5c752d71fd1bebccb866e)]:
  - @realreel/c2pa-trust-core@0.5.0

## 0.8.0

### Minor Changes

- [#24](https://github.com/wholeearthlabs/realreel-c2pa/pull/24) [`879959e`](https://github.com/wholeearthlabs/realreel-c2pa/commit/879959e2c84a3b8d4edbdee29010bc3a0323cc2d) Thanks [@dependabot](https://github.com/apps/dependabot)! - Update the C2PA engine: `@contentauth/c2pa-node` 0.5.5 → 0.8.0 and `@contentauth/c2pa-types` 0.4.4 → 0.7.2, which carries `c2pa-rs` 0.89.x → 0.90.0.

  The upstream changes are builder-side (archive-metadata stripping, experimental builder reduction methods, prebuilt-binary distribution fixes) — this service only reads and validates, and the full verification suite passes unchanged against the real fixture media. The `c2pa-rs` bump is the part worth a redeploy: validation behavior lives there.

  The published tarball still bundles a single-arch `linux/amd64` prebuilt with a glibc 2.34 floor, so the image's `--platform=linux/amd64` + `--ignore-scripts` + bookworm assumptions are unchanged.

  Also bumps `fastify` 5.8.5 → 5.11.0, `@peculiar/asn1-android` / `@peculiar/asn1-x509` 2.7.0 → 2.8.0, and `cbor-x` 1.6.4 → 1.6.5.

### Patch Changes

- [#29](https://github.com/wholeearthlabs/realreel-c2pa/pull/29) [`ac8ac9b`](https://github.com/wholeearthlabs/realreel-c2pa/commit/ac8ac9bb98bec927d03994924f88a5d17d852868) Thanks [@boojamya](https://github.com/boojamya)! - Read `signature_info.time` through its declared type instead of a local cast, and type-check the test suite in CI.

  `readSignatureTime` — the input to the cert-validity gate — reached the field via `as { time?: string }` because `SignatureInfoShape` didn't declare it. It does now, so the cast is gone.

  `tsconfig.test.json` was never gated, and five fixtures had drifted from the types they stand in for: `Config` grew `maxAssetBytes`, `TrustConfig` grew `tsaRoots`, `LocationLevel` moved to trust-core, and a fail-closed case deleted a property its inferred type marked required. vitest transpiles with esbuild, which strips types without checking them, so every one of those suites passed green throughout. CI now runs `tsc -p tsconfig.test.json` alongside the src typecheck.

- [#27](https://github.com/wholeearthlabs/realreel-c2pa/pull/27) [`2f86592`](https://github.com/wholeearthlabs/realreel-c2pa/commit/2f8659245eb220a8832914445897a7d6690d4f6e) Thanks [@boojamya](https://github.com/boojamya)! - State the non-shared-`ArrayBuffer` requirement in the App Attest hash helpers' types instead of leaving it implicit.

  `webcrypto.subtle.digest` rejects a view onto a `SharedArrayBuffer` at runtime (`TypeError: ... is a view on a SharedArrayBuffer, which is not allowed`). `sha256` in `src/attestation/pki-node.ts` declared its input as the unparameterised `Uint8Array`, which admits that shape, so the constraint was enforced only by Node — and only at request time. It now takes and returns `Uint8Array<ArrayBuffer>`, and `concat` reports the fresh, never-shared buffer it actually allocates. No cast, no copy, no change to what bytes are hashed.

  This is also what `@types/node@26` began rejecting at compile time; the verifier now typechecks clean under both `^24` (what it ships on) and `26`.

- [#26](https://github.com/wholeearthlabs/realreel-c2pa/pull/26) [`2bb4d97`](https://github.com/wholeearthlabs/realreel-c2pa/commit/2bb4d97005944bda7ca5c1dbd18eec7f011a12c8) Thanks [@boojamya](https://github.com/boojamya)! - Raise the supported Node floor to 24, matching the runtime the image has shipped since it moved to `node:24-bookworm-slim`.

  `engines` said `>=22` and CI tested on 22 while the container ran 24, so the suite gating verification never exercised the runtime executing it — and 22 entered maintenance-only in October 2025. Node 24 is Active LTS through 2026-10-20 and supported to 2028-04-30. `@types/node` moves to `^24` to match.

- Updated dependencies [[`a6f8caa`](https://github.com/wholeearthlabs/realreel-c2pa/commit/a6f8caa2f34c925425f5f19af49c8dc775548617), [`ac8ac9b`](https://github.com/wholeearthlabs/realreel-c2pa/commit/ac8ac9bb98bec927d03994924f88a5d17d852868)]:
  - @realreel/c2pa-trust-core@0.4.1

## 0.7.0

### Minor Changes

- [`416e1a8`](https://github.com/wholeearthlabs/realreel-c2pa/commit/416e1a89e17b7b6ab87fbb529e62aae4081eabf0) Thanks [@boojamya](https://github.com/boojamya)! - Dual trust anchors (v2 `realreel` + `realreel-legacy`) and ledger-backed leaf
  validity. checkLedgerTimeBounds replaces the flat 180-day cert-lifetime ceiling
  with per-leaf issued_at/expires_at from lookup_signing_key_revocation — apply the
  app-side RPC reshape before deploying this image. Adds the ocsp-leaf leaf-status
  OCSP responder.

## 0.6.2

### Patch Changes

- [`d6baeff`](https://github.com/wholeearthlabs/realreel-c2pa/commit/d6baeff49a287e0e20309f5ec6c762936374199e) Thanks [@boojamya](https://github.com/boojamya)! - Fix two EXIF metadata-derivation bugs in the photo verifier:
  - **UserComment is no longer dropped.** Spec-compliant EXIF `UserComment` tags store their text after an 8-byte character-code prefix (`ASCII\0\0\0`, `UNICODE\0`, `JIS\0\0\0\0\0`, or 8 NULs). exifr returns the value with that prefix intact, and its NUL bytes tripped the control-byte guard, so the comment was silently discarded from derived metadata. The prefix is now stripped before formatting, so capture breadcrumbs (and any camera UserComment) display again.
  - **GPS coordinates no longer leak into display entries.** exifr emits `latitude`/`longitude`/`altitude` convenience keys even with `gps: false`, and the coordinate-scrub regex didn't match those labels — so precise coordinates could reach `media.metadata` for any GPS-bearing upload. Those keys are now scrubbed; coordinates remain authoritative only from the signed assertion.
  - **Hardening.** Every derived value is clamped to a max length (no oversized comment can bloat `media.metadata`), the video `creation_time` fallback now routes through the same value guard, and exifr's `sanitize` option is pinned explicitly.

## 0.6.1

### Patch Changes

- [`53a1d8a`](https://github.com/wholeearthlabs/realreel-c2pa/commit/53a1d8afcd9a3c84c752e20724ed082c9aea4432) Thanks [@boojamya](https://github.com/boojamya)! - Make the `/verify` asset fetch/buffer ceiling configurable. The size gate
  previously hard-coded a 50 MiB limit (`MAX_ASSET_BYTES`); it now reads
  `config.maxAssetBytes`, overridable via the optional `MAX_ASSET_MIB` env var
  and defaulting to 50 (so default behavior is unchanged). Set it to match the
  asset-storage bucket's `file_size_limit` when that exceeds 50 MiB — otherwise
  an upload whose size lands in the gap band passes Storage and then fails
  verification as oversize. Validated at startup: non-positive or above a 512 MiB
  sanity ceiling throws.

- [`a7bb35d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/a7bb35d606965ec75f88afd27f3aaf6c896586a4) Thanks [@boojamya](https://github.com/boojamya)! - Add a per-upload content hash so a consumer can block re-posting the same
  capture to one profile. The verifier now derives `contentHash` and returns it
  in the `/verify` 200 response: `sha256("rrc1:" + identity)`, where `identity`
  is the resolved Stage-1 capture manifest label (walked past any interposed TSA
  Update Manifests) plus, for video, the signed `c2pa.trimmed`/`c2pa.cropped`
  parameters (canonicalized). Anchored to the capture, not the bytes — so the same
  capture re-uploaded with any transform collides, while two different video trims
  do not. The verifier is stateless about dedup; enforcing uniqueness (e.g. a
  `UNIQUE(user_id, content_hash)` index) is the consumer's job.

  trust-core gains `buildContentIdentity` and `extractContentExtent` (new
  `policies/content-hash`), a shared `extractActionEntries` walk now backing
  `extractManifestActions`, and a `DUPLICATE_CONTENT` error code for consumers
  that map a uniqueness violation to a user-facing reject.

- Updated dependencies [[`a7bb35d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/a7bb35d606965ec75f88afd27f3aaf6c896586a4)]:
  - @realreel/c2pa-trust-core@0.3.0

## 0.6.0

### Minor Changes

- [`fba91ab`](https://github.com/wholeearthlabs/realreel-c2pa/commit/fba91abc08666c5063b1e86469fa471db899aa90) Thanks [@boojamya](https://github.com/boojamya)! - Location-privacy gate: enforce the uploader's declared location level. The
  `/verify` request now carries a required `declaredLocation` field (`none` |
  `general` | `precise`, forwarded unsigned). A non-precise level rejects any GPS
  present in either the validated file bytes or the signed assertion with
  `LOCATION_PRIVACY_VIOLATION`. This is additive to the existing bytes-vs-assertion
  spine (kept as the arg-independent backstop) and closes its two blind spots when
  the level is known: a correlated double-regression, and the Direction-2
  assertion-only leak the spine could previously only signal. Strict — a request
  missing or carrying an invalid level is a 400.

### Patch Changes

- [`7e8806d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/7e8806da4195fb24b11e7dbf0acf5e25bf9227d4) Thanks [@boojamya](https://github.com/boojamya)! - Move the declared location level into trust-core as the single source of truth:
  add `LocationLevel`, `LOCATION_LEVELS`, and the `isLocationLevel` guard. The
  verifier's location-privacy gate and POST /verify validation now consume them
  instead of a local copy, so the client and verifier can't drift on the level set.
- Updated dependencies [[`7e8806d`](https://github.com/wholeearthlabs/realreel-c2pa/commit/7e8806da4195fb24b11e7dbf0acf5e25bf9227d4)]:
  - @realreel/c2pa-trust-core@0.2.0

## 0.5.0

### Minor Changes

- [`5c25737`](https://github.com/wholeearthlabs/realreel-c2pa/commit/5c257376b314bd2fdecc94be464cdfeb8e1562a1) Thanks [@boojamya](https://github.com/boojamya)! - Add a server-side location-privacy backstop.

  The verifier now cross-checks GPS presence in the validated file bytes against
  the signed manifest and rejects an upload (with `LOCATION_PRIVACY_VIOLATION`)
  whose bytes carry coordinates the manifest doesn't — closing the gap where a
  client-side GPS strip on a non-precise ("none"/"general") upload could silently
  publish exact coordinates if it ever regressed. The reverse mismatch (manifest
  carries coordinates the bytes don't) is reported to telemetry rather than
  rejected.

### Patch Changes

- Updated dependencies [[`5c25737`](https://github.com/wholeearthlabs/realreel-c2pa/commit/5c257376b314bd2fdecc94be464cdfeb8e1562a1)]:
  - @realreel/c2pa-trust-core@0.1.2

## 0.4.0

### Minor Changes

- [`1189ec9`](https://github.com/wholeearthlabs/realreel-c2pa/commit/1189ec9a8c8bba144e63bae03fa132d7e57469ab) Thanks [@boojamya](https://github.com/boojamya)! - Derive displayed photo/video metadata from the verified upload.

  The `/verify` response now carries a `derived` object (`entries`, `latitude`, `longitude`, `location`, `metadataType`) so the metadata a viewer sees is bound to the verified upload instead of a client-supplied request field. Photos are byte-probed with `exifr`, video with `ffprobe` (the moov-box technical fields aren't in the manifest); GPS comes only from the signed `stds.exif`/`stds.iptc` assertion and is scrubbed from the byte probe, and the location string from the signed `org.realreel.upload` `locationLabel`. `ffprobe` is a new hard runtime dependency, baked into the image as a single sha256-pinned static binary.

## 0.3.0

### Minor Changes

- [`db809bb`](https://github.com/wholeearthlabs/realreel-c2pa/commit/db809bb97cdcdc3787cad2133001818c2d417e91) Thanks [@boojamya](https://github.com/boojamya)! - Lift the RFC-3161 Time-Stamping Authority provider name onto the sanitized
  manifest's `signature_info.timestamp_authority` (per manifest), parsed from
  c2pa-rs's `validation_results`, so a viewer can show "Timestamped by …" without
  re-reading the asset.
