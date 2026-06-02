// Targeted tests for loadTrustConfig invariants that don't surface
// via the end-to-end verify-*.test.ts fixtures.
//
// Today the suite covers exactly one invariant: every YAML source id
// must have a matching @realreel/c2pa-trust-core TRUSTED_ISSUERS row.
// This replaces the deleted trust-list-yaml-lockstep.test.ts (which
// guarded YAML/shared drift on the issuer_match field — no longer a
// distinct concern after f00153b's single-source refactor) with a
// runtime startup-time check inside the loader, plus this assertion
// that the check fires.

import { describe, it, expect, afterAll } from "vitest";
import { writeFile, rm, mkdir, copyFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { loadTrustConfig } from "../src/trust/loader.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERIFIER_ROOT = resolve(HERE, "..");

// Temporary fixture dir lives under __tests__/ so vitest's testPathIgnore
// glob picks it up cleanly and the real trust-sources tree is untouched.
// Listed in verifier/__tests__/.gitignore so a Ctrl-C-interrupted run
// doesn't leave the dir tracked in `git status`.
const TMP_DIR = resolve(HERE, ".tmp-trust-loader");

async function writeYamlFixture(yaml: string): Promise<string> {
  // mkdir is recursive + idempotent, so each fixture call ensures the
  // tree exists from scratch. No beforeAll bootstrap needed.
  await mkdir(TMP_DIR, { recursive: true });
  // The loader resolves root_cert paths relative to the YAML's directory,
  // so we co-locate a real PEM next to the YAML to keep the load happy.
  // Reuse the realreel root.pem — it's just bytes the loader read into
  // the bundle; nothing in the invariant test path looks at its content.
  await mkdir(resolve(TMP_DIR, "trust-sources", "realreel"), { recursive: true });
  await copyFile(
    resolve(VERIFIER_ROOT, "trust-sources", "realreel", "root.pem"),
    resolve(TMP_DIR, "trust-sources", "realreel", "root.pem"),
  );
  const yamlPath = resolve(TMP_DIR, "trust-sources.yaml");
  await writeFile(yamlPath, yaml, "utf-8");
  return yamlPath;
}

afterAll(async () => {
  await rm(TMP_DIR, { recursive: true, force: true });
});

async function writeYamlFixtureWithTsa(yaml: string): Promise<string> {
  // Same as writeYamlFixture but ALSO stages a c2pa-tsa/ subdir with a
  // copy of an existing PEM (any PEM works — the loader just reads the
  // bytes into the trust bundle, doesn't parse them at load time). The
  // realreel root is reused for convenience.
  await mkdir(TMP_DIR, { recursive: true });
  await mkdir(resolve(TMP_DIR, "trust-sources", "realreel"), { recursive: true });
  await mkdir(resolve(TMP_DIR, "trust-sources", "c2pa-tsa"), { recursive: true });
  await copyFile(
    resolve(VERIFIER_ROOT, "trust-sources", "realreel", "root.pem"),
    resolve(TMP_DIR, "trust-sources", "realreel", "root.pem"),
  );
  await copyFile(
    resolve(VERIFIER_ROOT, "trust-sources", "c2pa-tsa", "c2pa-tsa-trust-list.pem"),
    resolve(TMP_DIR, "trust-sources", "c2pa-tsa", "c2pa-tsa-trust-list.pem"),
  );
  const yamlPath = resolve(TMP_DIR, "trust-sources.yaml");
  await writeFile(yamlPath, yaml, "utf-8");
  return yamlPath;
}

describe("loadTrustConfig — YAML/TRUSTED_ISSUERS lockstep", () => {
  it("throws when a YAML entry's id has no matching TRUSTED_ISSUERS row", async () => {
    // Inverse-direction check: deleting the YAML lockstep test from
    // f00153b left this hole open (a YAML entry like `id: leica`
    // without a matching shared-package entry would load its PEM into
    // the trust bundle but fail-closed at dispatch with no signal).
    // The loader now throws at startup; this assertion confirms it.
    const yamlPath = await writeYamlFixture(`
sources:
  - id: leica
    name: Leica
    description: A vendor that hasn't been registered in TRUSTED_ISSUERS.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: wrap_parent_only
`);
    await expect(loadTrustConfig(yamlPath)).rejects.toThrow(
      /id 'leica' has no matching entry in .* TRUSTED_ISSUERS/,
    );
  });

  it("accepts a YAML entry whose id IS in TRUSTED_ISSUERS", async () => {
    // Sanity check on the positive path — uses 'realreel' which is
    // registered in the shared trust list.
    const yamlPath = await writeYamlFixture(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel
`);
    const config = await loadTrustConfig(yamlPath);
    expect(config.sources).toHaveLength(1);
    expect(config.sources[0]!.id).toBe("realreel");
    expect(config.loadedIds.has("realreel")).toBe(true);
  });

  it("loads tsa_roots into trustAnchorsBundle without requiring TRUSTED_ISSUERS membership", async () => {
    // TSA roots don't sign content — they sign timestamps over
    // signatures. They're trust-pool members but not content issuers,
    // so they're exempt from the TRUSTED_ISSUERS lockstep check. The
    // loader concatenates them into the same trustAnchorsBundle (single
    // c2pa-rs trust pool for both signing-cert and TSA validation) but
    // does NOT include them in loadedIds (which is used by
    // identifyTrustSource() to route content manifests, never TSAs).
    const yamlPath = await writeYamlFixtureWithTsa(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel

tsa_roots:
  - id: c2pa-tsa-list
    name: C2PA TSA Trust List
    description: Test fixture.
    root_cert: trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem
`);
    const config = await loadTrustConfig(yamlPath);
    expect(config.sources).toHaveLength(1);
    expect(config.tsaRoots).toHaveLength(1);
    expect(config.tsaRoots[0]!.id).toBe("c2pa-tsa-list");
    expect(config.tsaRoots[0]!.rootCertPem).toContain("BEGIN CERTIFICATE");
    // Bundle contains BOTH the signer root and the TSA roots.
    expect(config.trustAnchorsBundle).toContain(config.sources[0]!.rootCertPem.trim());
    expect(config.trustAnchorsBundle).toContain(config.tsaRoots[0]!.rootCertPem.trim());
    // loadedIds is for content-issuer routing — TSAs are excluded.
    expect(config.loadedIds.has("realreel")).toBe(true);
    expect(config.loadedIds.has("c2pa-tsa-list")).toBe(false);
  });

  it("accepts a YAML without tsa_roots (backwards-compatible)", async () => {
    // tsa_roots is optional — older / minimal configs without it must
    // still load successfully. sigTst2-bearing manifests will fail
    // verification (no TSA roots in the trust pool), but legacy
    // non-sigTst2 manifests are unaffected.
    const yamlPath = await writeYamlFixture(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel
`);
    const config = await loadTrustConfig(yamlPath);
    expect(config.tsaRoots).toEqual([]);
  });

  it("throws when a tsa_roots entry is missing id", async () => {
    // Just enough validation to catch obvious YAML typos. TSA entries
    // intentionally skip the heavier checks signers get (no lockstep,
    // no profile, no revocation flag).
    const yamlPath = await writeYamlFixtureWithTsa(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel

tsa_roots:
  - name: Missing id
    description: bogus
    root_cert: trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem
`);
    await expect(loadTrustConfig(yamlPath)).rejects.toThrow(
      /tsa_roots entry .* missing or non-string 'id'/,
    );
  });

  it("throws when a tsa_roots entry is missing root_cert", async () => {
    // Mirror of the missing-id case for the second required field.
    // Caught by validateTsaRootConfig — independent branch from the
    // id check so a typo in either field surfaces cleanly.
    const yamlPath = await writeYamlFixtureWithTsa(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel

tsa_roots:
  - id: c2pa-tsa-no-cert
    name: TSA without root_cert
    description: Forgot to set root_cert
`);
    await expect(loadTrustConfig(yamlPath)).rejects.toThrow(
      /tsa_roots entry .*'c2pa-tsa-no-cert': missing or non-string 'root_cert'/,
    );
  });

  it("throws on a duplicate tsa_roots id (silent double-bundling guard)", async () => {
    // Without this check, two YAML entries with the same id would both
    // concatenate their PEMs into trustAnchorsBundle. Harmless at the
    // crypto layer (cert pool is set-like) but a misconfiguration we
    // want to surface so operators don't accidentally maintain dead
    // entries thinking they were overridden.
    const yamlPath = await writeYamlFixtureWithTsa(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel

tsa_roots:
  - id: dup
    name: First entry
    description: a
    root_cert: trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem
  - id: dup
    name: Second entry
    description: b
    root_cert: trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem
`);
    await expect(loadTrustConfig(yamlPath)).rejects.toThrow(
      /duplicate id 'dup'/,
    );
  });

  it("throws when a tsa_roots id collides with a sources id (cross-section collision)", async () => {
    // Sources and tsa_roots share one id namespace. Even though
    // loadedIds only contains signer ids today, accepting a collision
    // would poison any future cross-section lookup. Easier to forbid
    // up front than to retro-fit later.
    const yamlPath = await writeYamlFixtureWithTsa(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: realreel

tsa_roots:
  - id: realreel
    name: Collides with the signer id
    description: bogus
    root_cert: trust-sources/c2pa-tsa/c2pa-tsa-trust-list.pem
`);
    await expect(loadTrustConfig(yamlPath)).rejects.toThrow(
      /duplicate id 'realreel'.*already declared as source.*conflicts with tsa_root/,
    );
  });

  it("throws on an unknown verification_profile literal", async () => {
    // Guards against silent acceptance of a stale or typo'd profile name
    // (e.g. `c2pa_standard` post-rename, or a typo'd literal). The loader
    // validator at loader.ts:131 enumerates the accepted literals in its
    // error message to point operators at the right values.
    const yamlPath = await writeYamlFixture(`
sources:
  - id: realreel
    name: RealReel
    description: Test fixture with bogus profile.
    root_cert: trust-sources/realreel/root.pem
    verification_profile: c2pa_standard
`);
    await expect(loadTrustConfig(yamlPath)).rejects.toThrow(
      /unknown verification_profile 'c2pa_standard'.*expected 'realreel' or 'wrap_parent_only'/,
    );
  });
});
