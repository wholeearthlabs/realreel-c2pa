# Attestation test fixtures

This directory holds **real** attestation request bodies captured from real
devices during on-device enrollment. Each fixture is a JSON file that
matches the body shape `register-signing-key` accepts.

These files are intentionally committed to the repo (private). They contain:

- The Apple-signed attestation blob (or Android cert chain) for **one specific
  enrollment ceremony** that has already completed and whose challenge has
  been burned at the database layer.
- The corresponding base64 public key.
- The `keyId`, `keyVersion`, and `challenge` from that ceremony. (Older
  fixtures may also carry `exp` and `challengeToken` left over from the
  legacy HMAC-gated flow — those fields are no longer read by tests.)

They are not secrets — the attestation only proves a key was generated on a
device by our app at a moment in time. They cannot be replayed against the
production server because:

1. The challenge row in `enrollment_challenges` was atomically burned at
   first use (`consume_enrollment_challenge` UPDATEs with `consumed_at IS
   NULL`); any second redemption fails with `enrollment_challenge_unavailable`.
2. The corresponding row's `key_id` is the PRIMARY KEY of `user_signing_keys`,
   so re-submitting the same attestation fails the PK constraint.

## Required fixtures

- `ios_production.json` — captured from a real iPhone running a TestFlight or
  Xcode-on-device build (production AAGUID).
- `android_strongbox.json` — captured from a Pixel 3+ / Galaxy S20+ / etc.
- `android_tee.json` — captured from a TEE-only device (older Pixels, most
  Samsungs pre-S20, or any device where StrongBox is unavailable). **Not yet
  captured.** Tests for this platform skip silently until a fixture lands.
- `sample_csr.pem` — a synthetic P-256 PKCS#10 CSR (subject
  `CN=RealReel-Test-CSR`) generated via
  `step certificate create --csr --kty EC --crv P-256`. Its matching private key
  was discarded immediately. Used only by `pki_ca_test.ts` to exercise CSR parse
  / signature-verify / SPKI-extraction. Not derived from any real enrollment.

## Capture workflow

These fixtures were captured by logging the exact body POSTed to
`register-signing-key` during a real on-device enrollment. To gather
additional fixtures, instrument the enrollment client to log the request
body and run it on a real device.

## Running tests

From the repo root:

```sh
make test-ca
```

Or directly:

```sh
deno test --allow-read --allow-env ca/_shared/attestation/
```

Both `--allow-read` (to load fixtures) and `--allow-env` (cbor-x reads
`CBOR_NATIVE_ACCELERATION_DISABLED` at module init) are required.
