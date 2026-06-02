// CLI verify-demo — runs the RealReel C2PA verifier end-to-end against a
// bundled sample file and prints a friendly trust verdict.
//
// This is the runnable twin of verifier/__tests__/verify-realreel.test.ts.
// It wires the real verify() pipeline with:
//   - an IN-MEMORY VerifierDatastore (verifier/src/ports.ts) so it needs NO
//     database: the revocation lookup returns the sample's pre-registered
//     enrollment row, and the attestation nonce-burn is a no-op.
//   - LENIENT attestation mode (no playIntegrityConfig, attestationRequired
//     left false) so it needs NO Google Play Integrity API call.
//
// Everything else is the production path: c2pa-node parses + chain-validates
// the embedded manifest against the RealReel CA root in
// verifier/trust-sources/realreel/root.pem, the realreel profile enforces the
// two-stage structure + the revocation denylist + the action allowlist, and
// the result is sanitized exactly as the Cloud Run service would return it.
//
// Run:  npm run demo        (from the repo root)
// or:   cd verifier && npx tsx ../examples/verify-demo.ts

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verify } from "../verifier/src/verify.js";
import { loadTrustConfig } from "../verifier/src/trust/loader.js";
import { VerifyError } from "../verifier/src/errors.js";
import type { VerifierDatastore, RevocationRow } from "../verifier/src/ports.js";
import type { SanitizedManifestStore, SanitizedManifest } from "../verifier/src/sanitize.js";

const HERE = resolve(fileURLToPath(import.meta.url), "..");
const VERIFIER_ROOT = resolve(HERE, "../verifier");

// The sample is a real RealReel-signed JPEG: a Pixel 10 capture (Stage 1)
// re-signed at upload (Stage 2), trust-rooted at the RealReel CA. Both stages
// carry a DigiCert RFC-3161 timestamp. Reused straight from the test fixtures
// (Git LFS — run `git lfs pull` if this reads as a small text pointer file).
const SAMPLE_PATH = resolve(VERIFIER_ROOT, "__tests__/fixtures/realreel-uploaded.jpg");
const TRUST_SOURCES_PATH = resolve(VERIFIER_ROOT, "trust-sources.yaml");

// Identity baked into the sample's manifest. The cert serial is the lookup key
// the verifier hands to the datastore; the capturer UUID is the enrolled
// owner. (Mirrors verify-realreel.test.ts.)
const SAMPLE_CERT_SERIAL = "363929595041533803483005728970001726554859632395";
const SAMPLE_CAPTURER_UUID = "a73f9e58-7323-4fd6-970e-59fb0b4d2ea4";

/**
 * In-memory datastore: the sample's signing key is "enrolled" (non-revoked),
 * the nonce burn is a no-op, and the health check is a no-op. No Postgres.
 *
 * `lookup()` returns the same enrollment row for any cert serial — the sample
 * is a single-device capture, so both stages key the same enrolled key.
 */
const inMemoryDatastore: VerifierDatastore = {
  async lookup(certSerialNumber: string): Promise<RevocationRow | null> {
    if (certSerialNumber !== SAMPLE_CERT_SERIAL) return null;
    return {
      key_id: "demo-enrolled-key",
      user_id: SAMPLE_CAPTURER_UUID,
      revoked_at: null, // not revoked → accepted
      cert_serial_number: SAMPLE_CERT_SERIAL,
      platform: "android", // the sample is a Pixel 10 capture
      public_key: Buffer.alloc(0),
      app_attest_public_key: null,
    };
  },
  async burn(): Promise<void> {
    // Single-use attestation nonce burn. No-op in the demo (lenient mode never
    // reaches a real burn for this sample, and there's no DB to write to).
  },
  async ping(): Promise<void> {
    // Readiness probe — trivially healthy.
  },
};

// ----- pretty-printing helpers -------------------------------------------

const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

// Short human label for a manifest: prefer the claim generator, fall back to
// the title, then the issuer (c2pa-node doesn't always surface all three).
function describe(manifest: SanitizedManifest): string {
  return (
    manifest.claim_generator ??
    manifest.title ??
    manifest.signature_info.issuer ??
    "(unnamed manifest)"
  );
}

function actionsOf(manifest: SanitizedManifest): string[] {
  const out: string[] = [];
  for (const a of manifest.assertions) {
    if (a.label !== "c2pa.actions" && a.label !== "c2pa.actions.v2") continue;
    const actions = (a.data as { actions?: Array<{ action?: unknown }> })?.actions;
    if (!Array.isArray(actions)) continue;
    for (const entry of actions) {
      if (typeof entry?.action === "string" && entry.action.length > 0) {
        out.push(entry.action);
      }
    }
  }
  return [...new Set(out)];
}

function printVerdict(result: SanitizedManifestStore): void {
  const trusted = result.validation_state === "trusted";

  console.log("");
  console.log(`${BOLD}RealReel C2PA — verify demo${RESET}`);
  console.log(`${DIM}sample: ${SAMPLE_PATH}${RESET}`);
  console.log("");

  if (trusted) {
    console.log(`  ${GREEN}${BOLD}✓ TRUSTED${RESET}  — manifest chains to the RealReel CA and passed every gate`);
  } else {
    console.log(`  ${RED}${BOLD}✗ NOT TRUSTED${RESET}  (validation_state=${result.validation_state})`);
  }
  console.log(`  trust source: ${result.trust_source}`);
  console.log("");

  // Stage 2 = the active (upload) manifest; its parent is Stage 1 (capture).
  const stage2 = result.active_manifest;
  const stage1Label = stage2?.parent_label ?? null;
  const stage1 = stage1Label ? result.manifests[stage1Label] : undefined;

  console.log(`${BOLD}Two-stage provenance${RESET}`);
  if (stage1) {
    console.log(`  Stage 1 (capture): ${describe(stage1)}`);
    console.log(`    ${DIM}issuer: ${stage1.signature_info.issuer ?? "—"}${RESET}`);
    console.log(`    ${DIM}signed: ${stage1.signature_info.time ?? "—"}${RESET}`);
    const captureAssertion = stage1.assertions.find((a) => a.label === "org.realreel.capture");
    const capturer = (captureAssertion?.data as { capturerUuid?: string } | undefined)?.capturerUuid;
    if (capturer) console.log(`    ${DIM}capturer: ${capturer}${RESET}`);
  } else {
    console.log(`  Stage 1 (capture): ${DIM}(no parent manifest found)${RESET}`);
  }
  if (stage2) {
    console.log(`  Stage 2 (upload):  ${describe(stage2)}`);
    console.log(`    ${DIM}issuer: ${stage2.signature_info.issuer ?? "—"}${RESET}`);
    console.log(`    ${DIM}signed: ${stage2.signature_info.time ?? "—"}${RESET}`);
  }
  console.log("");

  console.log(`${BOLD}Declared actions${RESET}`);
  const stage1Actions = stage1 ? actionsOf(stage1) : [];
  const stage2Actions = stage2 ? actionsOf(stage2) : [];
  console.log(`  Stage 1: ${stage1Actions.length ? stage1Actions.join(", ") : DIM + "(none)" + RESET}`);
  console.log(`  Stage 2: ${stage2Actions.length ? stage2Actions.join(", ") : DIM + "(none)" + RESET}`);
  console.log("");
}

// ----- main ---------------------------------------------------------------

async function main(): Promise<void> {
  const [assetBytes, trustConfig] = await Promise.all([
    readFile(SAMPLE_PATH),
    loadTrustConfig(TRUST_SOURCES_PATH),
  ]);

  try {
    const { sanitizedManifest } = await verify({
      assetBytes,
      mimeType: "image/jpeg",
      expectedUserId: SAMPLE_CAPTURER_UUID,
      trustConfig,
      datastore: inMemoryDatastore,
      // attestationRequired left false + no playIntegrityConfig → lenient mode.
    });
    printVerdict(sanitizedManifest);
    process.exit(sanitizedManifest.validation_state === "trusted" ? 0 : 1);
  } catch (e) {
    console.log("");
    if (e instanceof VerifyError) {
      console.log(`  ${RED}${BOLD}✗ REJECTED${RESET}  errorCode=${e.code}`);
      if (e.detail) console.log(`  ${DIM}${e.detail}${RESET}`);
    } else {
      console.log(`  ${RED}${BOLD}✗ ERROR${RESET}  ${e instanceof Error ? e.message : String(e)}`);
    }
    console.log("");
    process.exit(1);
  }
}

main();
