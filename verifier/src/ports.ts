// Datastore port interfaces for the verifier.
//
// The verifier needs exactly two things from a backing datastore:
//   1. Look up a signing key's revocation/enrollment row by leaf cert serial.
//   2. Atomically burn a single-use attestation challenge (nonce).
//
// These ports express that contract independently of HOW it's stored.
// `src/db.ts` provides the default `postgresAdapter` (Supabase / Postgres RPC),
// but an open-source integrator can implement these interfaces over any
// datastore — a different SQL dialect, a key/value store, an HTTP service —
// without touching the verification logic.
//
// Why ports, not a DI framework: the verifier's storage surface is two
// functions. A port-interface + a default adapter is the right amount of
// abstraction — it documents the integration seam and makes the storage
// backend swappable, with no container, no decorators, no runtime wiring cost.
//
// Wiring: `verify()` accepts an optional `datastore` (defaulting to
// `postgresAdapter`) and threads it through the profile and attestation
// consumers, so both the revocation lookup and the nonce burn run against the
// injected adapter. Swapping the storage backend is therefore a pure call-site
// change — pass a different VerifierDatastore to `verify()`.

import type { RevocationRow } from "./db.js";

export type { RevocationRow };

/**
 * Revocation / enrollment lookup by leaf cert serial.
 *
 * Returns the row when the `cert_serial_number` is enrolled (regardless of
 * `revoked_at` — the caller decides what a revoked row means), or null when
 * the serial isn't in the registry (e.g. a wrap-mode third-party capture key
 * that was never enrolled).
 */
export interface RevocationLookup {
  lookup(certSerialNumber: string): Promise<RevocationRow | null>;
}

/**
 * Single-use attestation-challenge consumption — the sole anti-replay
 * primitive for Stage-2 upload attestation.
 *
 * Resolves iff an unconsumed challenge exists for `(keyId, nonce)` and this
 * call wins the race to mark it consumed. Implementations MUST signal an
 * already-consumed / unknown nonce by throwing an error whose message
 * contains `attestation_challenge_unavailable` (the attestation consumers map
 * that substring to VerifyErrorCode.ATTESTATION_REPLAY).
 */
export interface NonceBurner {
  burn(keyId: string, nonce: string): Promise<void>;
}

/**
 * Readiness probe — round-trips the datastore to assert it's reachable and
 * the revocation-lookup surface is healthy before the instance serves traffic.
 * Throws on any failure (the /healthz/ready handler maps a throw to 503).
 */
export interface HealthCheck {
  ping(): Promise<void>;
}

/**
 * The full datastore surface the verifier depends on, as a single injectable
 * port object. `db.ts` exports `postgresAdapter` satisfying this; an OSS
 * integrator supplies their own implementation.
 */
export interface VerifierDatastore
  extends RevocationLookup,
    NonceBurner,
    HealthCheck {}
