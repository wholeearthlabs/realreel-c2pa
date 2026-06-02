// Lockstep guard between the shared trust-list metadata
// (@realreel/c2pa-trust-core/trust-list) and the actual PEM files this
// verifier reads at startup (verifier/trust-sources/<id>/root.pem).
//
// The shared metadata declares a `rootCommonName` for each trusted
// issuer — a string the client gate and other shared consumers rely on
// without parsing the PEM. This test reads each PEM, parses it with
// node:crypto.X509Certificate, and asserts the subject CN equals the
// shared metadata. Two failure classes it catches:
//
//   - Someone updates the shared metadata's rootCommonName without
//     swapping the PEM (or vice versa). The strings drift; the client
//     starts trusting issuers whose actual root has a different name.
//   - A new entry is added to TRUSTED_ISSUERS without committing the
//     matching root.pem (or the other way around).
//
// Also asserts the inverse: every trust-sources/<id>/ subdir has a
// matching TRUSTED_ISSUERS entry — so the verifier can't silently
// trust a root that isn't documented in the shared metadata.

import { describe, it, expect } from "vitest";
import { X509Certificate } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { TRUSTED_ISSUERS } from "@realreel/c2pa-trust-core";

// Path is anchored at this test file's location so the test runs
// correctly regardless of cwd (vitest, ide, etc.).
const HERE = dirname(fileURLToPath(import.meta.url));
const TRUST_SOURCES_DIR = resolve(HERE, "..", "trust-sources");

/**
 * Subdirectories of `verifier/trust-sources/` that hold non-signer
 * trust material (TSA roots, etc.) and intentionally do NOT have a
 * matching TRUSTED_ISSUERS entry. TRUSTED_ISSUERS is for content
 * signers — entities whose certs sign C2PA claims and need an
 * `issuerMatch` substring for runtime dispatch. TSAs sign timestamps
 * over signatures; they're trust-pool members but not content issuers.
 *
 * Add a directory here when it holds non-signer PEMs (TSA roots, OCSP
 * responder roots, future trust material) so the inverse-direction
 * lockstep check below ignores it.
 */
const NON_SIGNER_TRUST_DIRS = new Set<string>([
  "c2pa-tsa",          // primary C2PA-conformant TSA roots (C2PA Trust List)
  "c2pa-tsa-fallback", // general-purpose DigiCert + SSL.com roots (degraded-mode TSA fallback)
]);

/** Parse a PEM file and extract the subject's CN attribute. Node's
 * X509Certificate.subject is a DN string like
 * `C=US\nO=Google LLC\nCN=Google C2PA Root CA G3`. We pull the CN line
 * with a deliberate regex rather than relying on field order. */
function readSubjectCn(pemPath: string): string {
  const pem = readFileSync(pemPath, "utf-8");
  const cert = new X509Certificate(pem);
  const match = /^CN=(.+)$/m.exec(cert.subject);
  if (!match) {
    throw new Error(`PEM at ${pemPath} has no CN in subject: ${cert.subject}`);
  }
  return match[1]!.trim();
}

describe("trust list lockstep (shared metadata ↔ verifier PEMs)", () => {
  for (const issuer of TRUSTED_ISSUERS) {
    it(`PEM for '${issuer.id}' has subject CN '${issuer.rootCommonName}'`, () => {
      const pemPath = resolve(TRUST_SOURCES_DIR, issuer.id, "root.pem");
      const actualCn = readSubjectCn(pemPath);
      expect(actualCn).toBe(issuer.rootCommonName);
    });
  }

  it("every trust-sources/<id>/root.pem has a matching TRUSTED_ISSUERS entry (excluding non-signer dirs)", () => {
    // Inverse-direction check: the verifier shouldn't carry a SIGNER
    // trust anchor that isn't declared in the shared metadata. Forces
    // every new signer-PEM addition through the shared package's audit
    // surface. Non-signer dirs (TSA roots, etc.) are exempt — see
    // NON_SIGNER_TRUST_DIRS above for the rationale.
    const pemDirs = readdirSync(TRUST_SOURCES_DIR, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .filter((id) => !NON_SIGNER_TRUST_DIRS.has(id));
    const knownIds = new Set(TRUSTED_ISSUERS.map((entry) => entry.id));
    const undeclared = pemDirs.filter((id) => !knownIds.has(id));
    expect(
      undeclared,
      `verifier/trust-sources/ contains undeclared PEM directories: ${undeclared.join(", ")}`,
    ).toEqual([]);
  });
});
