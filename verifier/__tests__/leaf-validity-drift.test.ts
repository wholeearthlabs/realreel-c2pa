// Drift guard: the verifier's cert-lifetime ceiling (DEFAULT_CERT_LIFETIME_MS)
// must match the lifetime the CA bakes into RealReel-issued leaf certs
// (LEAF_VALIDITY_DAYS), hand-synced across two packages. Scope is RealReel's
// own leaf — wrap-mode vendor parents (Pixel/iOS) carry their own validity,
// unaffected here.
//
// The CA is a Deno module this Node package can't import, so read its constant
// as text.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { DEFAULT_CERT_LIFETIME_MS } from "../src/cert-validity.js";

// Anchored at this test file's location so it runs regardless of cwd.
const HERE = dirname(fileURLToPath(import.meta.url));
const CA_REGISTER_SOURCE = resolve(
  HERE,
  "..",
  "..",
  "ca",
  "register-signing-key",
  "index.ts",
);

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Pull `LEAF_VALIDITY_DAYS = <n>` from the CA source; throw if it's renamed
 * so a refactor trips this guard instead of slipping past. */
function readCaLeafValidityDays(): number {
  const source = readFileSync(CA_REGISTER_SOURCE, "utf-8");
  const match = /LEAF_VALIDITY_DAYS\s*=\s*(\d+)\s*;/.exec(source);
  if (!match) {
    throw new Error(
      `Could not find a 'LEAF_VALIDITY_DAYS = <n>;' declaration in ${CA_REGISTER_SOURCE}. ` +
        `If it was renamed, update this drift guard to match.`,
    );
  }
  return Number(match[1]);
}

describe("leaf-validity drift guard (CA LEAF_VALIDITY_DAYS ↔ verifier DEFAULT_CERT_LIFETIME_MS)", () => {
  it("the verifier cert-lifetime ceiling equals the CA's leaf validity", () => {
    const caLeafDays = readCaLeafValidityDays();
    expect(DEFAULT_CERT_LIFETIME_MS).toBe(caLeafDays * MS_PER_DAY);
  });
});
