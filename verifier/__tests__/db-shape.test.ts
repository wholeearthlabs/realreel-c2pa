// Regression guard for the lookupSigningKeyRevocation SELECT projection.
//
// postgres.js (and any SQL client) returns ONLY the columns the SELECT
// names — it does NOT validate that the projected columns cover the row
// type's declared fields. The TypeScript generic on
// `sql<RevocationRow[]>` is a trust-me-bro assertion, not enforcement.
//
// In a previous regression, the SELECT in db.ts missed `platform` after
// the column was added to RevocationRow + the RPC. Strict-mode rejected
// every upload at runtime with "unrecognized platform 'undefined'"; lenient
// mode silently no-op'd the cross-platform mismatch checks. Caught only by
// review, because every test in the verifier mocks db.ts wholesale.
//
// This test source-inspects db.ts: every field declared on the
// RevocationRow interface MUST appear in the SELECT projection. Catches
// future column additions where someone updates the type but forgets the
// SQL, and vice versa.
//
// Why this style rather than an integration test:
//   - A real-DB integration test would need `supabase start` in CI, which
//     isn't wired today. This catches the specific regression class
//     without that dependency.
//   - `pingDb` (db.ts:131) explicitly SELECTs all projected columns from
//     the RPC, so a column drop on the migration side trips the readiness
//     probe at startup. Together with this test, both directions of
//     drift (type vs SQL) are guarded.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

describe("lookupSigningKeyRevocation SELECT projection", () => {
  const dbSrc = readFileSync(
    resolve(import.meta.dirname, "../src/db.ts"),
    "utf-8",
  );

  // Pull the SELECT body for the lookup_signing_key_revocation call. We
  // anchor on the FROM clause so we don't accidentally match pingDb's
  // SELECT — that one is a separate projection (intentionally probes
  // every column for column-drift detection, but isn't the type-bearing
  // call site).
  function extractLookupSelectBody(): string {
    // Match: "sql<RevocationRow[]>`\n SELECT ... FROM public.lookup_signing_key_revocation"
    const match = dbSrc.match(
      /sql<RevocationRow\[\]>`\s*SELECT\s+([\s\S]+?)\s+FROM\s+public\.lookup_signing_key_revocation/,
    );
    expect(
      match,
      "SELECT statement for lookup_signing_key_revocation not found in db.ts",
    ).toBeTruthy();
    return match![1]!;
  }

  // Fields declared on the RevocationRow interface. Update this list when
  // the interface changes. The test cross-checks against the actual
  // interface source so it can't drift silently.
  const declaredFields = [
    "key_id",
    "user_id",
    "revoked_at",
    "cert_serial_number",
    "platform",
    "public_key",
    "app_attest_public_key",
  ];

  it("declaredFields matches the RevocationRow interface in db.ts (self-check)", () => {
    // Cross-check: parse the interface body and assert it has exactly
    // the fields this test knows about. Otherwise an added field on
    // RevocationRow could slip past without test coverage.
    const interfaceMatch = dbSrc.match(
      /export interface RevocationRow\s*\{([\s\S]+?)\n\}/,
    );
    expect(
      interfaceMatch,
      "RevocationRow interface not found in db.ts",
    ).toBeTruthy();
    const body = interfaceMatch![1]!;

    // Extract field names: lines like `  key_id: string;` — match
    // identifier before colon, after any leading whitespace, skipping
    // comment lines (which start with /** or */ or //).
    const lines = body.split("\n");
    const actualFields = new Set<string>();
    for (const line of lines) {
      const m = line.match(/^\s*([a-z_][a-z0-9_]*)\??:\s/);
      if (m && !line.trim().startsWith("//") && !line.trim().startsWith("*")) {
        actualFields.add(m[1]!);
      }
    }

    expect(
      [...actualFields].sort(),
      "declaredFields constant drifted from RevocationRow — update this test",
    ).toEqual([...declaredFields].sort());
  });

  for (const field of declaredFields) {
    it(`SELECT projects \`${field}\``, () => {
      const selectBody = extractLookupSelectBody();
      // Allow `field`, `field AS alias`, or `something AS field` (the
      // revoked_at cast uses `revoked_at::text AS revoked_at`). Match
      // the field name as a whole word so we don't false-positive on
      // substring matches (`user_id` is a substring of `signing_key_user_id`).
      const wordBoundaryRegex = new RegExp(`\\b${field}\\b`);
      expect(
        wordBoundaryRegex.test(selectBody),
        `SELECT body does not project ${field}. Body: ${selectBody}`,
      ).toBe(true);
    });
  }
});
