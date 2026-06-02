// Postgres client + the two RPC functions the verifier ever calls, plus
// `postgresAdapter` — the default implementation of the verifier's storage
// ports (src/ports.ts). This module is the reference datastore adapter:
// verify() injects `postgresAdapter` by default, and an OSS integrator can
// supply their own VerifierDatastore instead without touching the
// verification logic.
//
// IMPORTANT: prepare: false is mandatory.
//
//   Supabase exposes Postgres at port 6543 via PgBouncer in
//   transaction-mode pooling. Different requests may be dispatched to
//   different upstream connections, so prepared-statement state set on
//   one request is invisible to the next. Postgres.js prepares
//   statements by default; with PgBouncer transaction mode, that
//   results in 'prepared statement "..." does not exist' errors at
//   random query intervals.
//
//   Session-mode pooling (port 5432) would also work, but transaction-
//   mode is the right choice for serverless callers like Cloud Run
//   where each request opens, queries, and closes its own logical
//   connection without persistent prepared-statement state.

import postgres from "postgres";
import type { VerifierDatastore } from "./ports.js";

export interface RevocationRow {
  /** sha256(SPKI) — kept on the row for telemetry / migration parity; not
   * the lookup key (that's cert_serial_number). */
  key_id: string;
  user_id: string;
  revoked_at: string | null;
  /** Decimal-form leaf cert serial. The actual lookup key — matches
   * c2pa-node's signature_info.cert_serial_number byte-for-byte. */
  cert_serial_number: string;
  /** Platform the key was enrolled under: 'ios' | 'android-strongbox' |
   * 'android-tee'. CHECK-constrained at the table level. Exposed via the
   * revocation lookup so the verifier can route per-platform attestation
   * requirements (require app_attest on iOS-signed manifests, require
   * play_integrity on Android-signed manifests). Schema is open to future
   * platform values — verifier code defends with an unknown-platform
   * branch, doesn't assume the union is closed. */
  platform: string;
  /** SPKI DER bytes of the device's signing key (the SE/StrongBox public
   * key registered at enrollment). Used by the Stage-2 App Attest
   * validator to reconstruct clientData = SHA256(challenge || SE_SPKI)
   * and verify Apple's signature over the assertion.
   * postgres.js returns bytea columns as Node Buffer. */
  public_key: Buffer;
  /** X9.63 uncompressed P-256 public key (0x04 || X || Y, 65 bytes) of
   * the Apple App Attest credCert. Populated at enrollment for iOS rows;
   * NULL for Android. The Stage-2 validator uses this to verify the
   * upload assertion's ECDSA signature. */
  app_attest_public_key: Buffer | null;
}

let sqlClient: postgres.Sql | null = null;

/**
 * Initialize the Postgres client with the URL from loaded config.
 * Called once at startup from server.ts after loadConfig() completes —
 * keeps config the single source of truth for DATABASE_URL (db.ts
 * doesn't peek at process.env directly).
 */
export function initDb(databaseUrl: string): void {
  if (sqlClient !== null) {
    throw new Error("initDb called twice — verifier expects single init");
  }
  sqlClient = postgres(databaseUrl, {
    // Mandatory for PgBouncer transaction-mode pooling. See file header.
    prepare: false,
    // Single client = single connection from the pool's perspective. We
    // don't run long-lived statements so this is fine even under load.
    max: 10,
    idle_timeout: 30,
    connect_timeout: 10,
  });
}

function getSql(): postgres.Sql {
  if (sqlClient === null) {
    throw new Error(
      "Postgres client not initialized — call initDb(config.databaseUrl) at startup",
    );
  }
  return sqlClient;
}

/**
 * Call the lookup_signing_key_revocation SECURITY DEFINER function in
 * public schema. Returns the row if the cert_serial_number exists,
 * null otherwise.
 *
 * Note: returns the row regardless of revoked_at — the caller decides
 * what to do with a revoked_at IS NOT NULL row. Profiles enforce
 * "revoked_at IS NULL or reject" themselves.
 *
 * Lookup key: cert_serial_number, which c2pa-node exposes via
 * signature_info.cert_serial_number for every manifest.
 */
export async function lookupSigningKeyRevocation(
  certSerialNumber: string,
): Promise<RevocationRow | null> {
  const sql = getSql();
  // Every field on RevocationRow MUST appear in this projection — postgres.js
  // returns only the columns selected, regardless of what the row type declares.
  // The regression test in __tests__/db-shape.test.ts asserts this contract
  // by source-inspecting the SELECT against the type fields.
  const rows = await sql<RevocationRow[]>`
    SELECT
      key_id,
      user_id,
      revoked_at::text AS revoked_at,
      cert_serial_number,
      platform,
      public_key,
      app_attest_public_key
    FROM public.lookup_signing_key_revocation(${certSerialNumber})
  `;
  return rows.length === 0 ? null : rows[0]!;
}

/**
 * Round-trips the same SECURITY DEFINER function /verify uses, with a
 * sentinel that returns zero rows. Used by /healthz/ready to assert
 * three things at once before Cloud Run marks an instance ready:
 *   - the pool can reach Postgres,
 *   - verifier_readonly has EXECUTE on lookup_signing_key_revocation,
 *   - the function signature still matches what the verifier expects
 *     (a column rename or return-shape change surfaces here, not on
 *     the first real /verify request).
 *
 * Wrapped in a transaction with `SET LOCAL statement_timeout = 2s`.
 * Without that, a hung query (pooler half-open, table lock) would
 * pin a pool connection until the OS TCP timeout fires (minutes).
 * Cloud Run polls /healthz/ready every few seconds during an
 * incident — sustained hangs would chew through the 10-connection
 * pool quickly. SET LOCAL only applies within the txn so the
 * /verify hot path keeps its default (no statement_timeout). The
 * Postgres-side cancel both frees the connection AND surfaces to
 * the caller as a normal error (which server.ts maps to 503).
 *
 * Throws whatever postgres.js throws (connection refused, permission
 * denied, function does not exist, statement timeout) — caller maps
 * to 503.
 */
export async function pingDb(): Promise<void> {
  const sql = getSql();
  await sql.begin(async (tx) => {
    await tx`SET LOCAL statement_timeout = 2000`;
    // SELECT every column lookupSigningKeyRevocation projects, including
    // platform — if a future migration drops or renames a column from the
    // RPC's RETURNS TABLE shape, this probe fails at startup rather than
    // letting /verify start serving requests with a broken column projection.
    // The sentinel arg matches no real row so the SELECT returns zero rows;
    // we only care that the column references resolve.
    await tx`
      SELECT key_id, user_id, revoked_at, cert_serial_number, platform,
             public_key, app_attest_public_key
      FROM public.lookup_signing_key_revocation('healthcheck-sentinel-no-match')
    `;
  });
}

/**
 * Atomic single-use challenge consumption. Backed by the (text, text)
 * SECURITY DEFINER function in
 * 20260526202035_drop_attestation_counters.sql.
 *
 * Returns successfully iff a row exists in attestation_challenges for
 * (key_id, nonce) with consumed_at IS NULL — and the UPDATE that sets
 * consumed_at = now() wins the race against any concurrent caller.
 * Single-use nonce burn is the sole anti-replay primitive.
 *
 * Throws postgres errors with code 'P0001':
 *   - message starting 'attestation_challenge_unavailable':
 *     unknown nonce or already-consumed (replay attempt).
 *
 * Caller maps to VerifyErrorCode.ATTESTATION_REPLAY.
 */
export async function consumeAndRecordAttestation(
  keyId: string,
  nonce: string,
): Promise<void> {
  const sql = getSql();
  await sql`
    SELECT public.consume_and_record_attestation(${keyId}, ${nonce})
  `;
}

/** Test-only: close the connection pool. Useful between vitest runs. */
export async function closeDbPool(): Promise<void> {
  if (sqlClient !== null) {
    await sqlClient.end();
    sqlClient = null;
  }
}

// The default datastore adapter: a Supabase/Postgres-RPC implementation of the
// verifier's storage ports (see src/ports.ts). This is the OSS-facing seam —
// an integrator can swap in their own VerifierDatastore implementation; this
// adapter is the reference one bound to the standard RealReel schema.
//
// The methods delegate to the module functions above (rather than inlining the
// SQL) so the existing module-boundary test mocks — which replace those
// functions — keep working unchanged.
export const postgresAdapter: VerifierDatastore = {
  lookup: lookupSigningKeyRevocation,
  burn: consumeAndRecordAttestation,
  ping: pingDb,
};
