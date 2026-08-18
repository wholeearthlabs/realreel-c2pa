// Shared plumbing for the crJSON-harness suites: tool availability, the
// trust lists the fixtures were signed under, the spec schema validator, and
// the fixture registry. Kept out of the test files so the harness's OWN
// correctness tests (crjson-harness.test.ts) and the tests that merely USE it
// (crjson-goldens.test.ts) share nothing but data.

import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormatsCjs from "ajv-formats";
import { loadTrustConfig } from "../../src/trust/loader.js";
import { probeHarnessEnvironment } from "../../src/harness/crjson.js";

export const FIXTURES = resolve(import.meta.dirname, "../fixtures");
export const GOLDENS = resolve(import.meta.dirname, "goldens");
export const fixture = (name: string): string => resolve(FIXTURES, name);

// ── Tool availability ───────────────────────────────────────────────────────
// c2patool + faketime absent → these suites SKIP locally (like an LFS-pointer
// checkout); CRJSON_HARNESS_REQUIRED=1 (CI) makes absence a hard failure.

export const harnessEnv = probeHarnessEnvironment();
export const harnessAvailable = harnessEnv.c2patool !== null && harnessEnv.faketime;
if (!harnessAvailable && process.env.CRJSON_HARNESS_REQUIRED === "1") {
  throw new Error(
    `CRJSON_HARNESS_REQUIRED=1 but the harness tools are missing: ` +
      `c2patool=${harnessEnv.c2patool ?? "MISSING"} faketime=${harnessEnv.faketime ? "ok" : "MISSING"}`,
  );
}

// LFS-pointer-only checkouts leave a text stub in place of the media; treat
// those as absent.
export async function fixturePresent(name: string): Promise<boolean> {
  try {
    await access(fixture(name));
    const head = (await readFile(fixture(name))).subarray(0, 64).toString("latin1");
    return !head.startsWith("version https://git-lfs.github.com/");
  } catch {
    return false;
  }
}

/** All named fixtures present? Under CRJSON_HARNESS_REQUIRED=1 a missing one
 *  throws instead — a skipped suite must not read as green in CI. */
export async function fixturesReady(names: string[]): Promise<boolean> {
  const missing: string[] = [];
  for (const n of names) if (!(await fixturePresent(n))) missing.push(n);
  if (missing.length && process.env.CRJSON_HARNESS_REQUIRED === "1") {
    throw new Error(`CRJSON_HARNESS_REQUIRED=1 but fixtures are missing or LFS pointers: ${missing.join(", ")}`);
  }
  return missing.length === 0;
}

// ── Trust lists ─────────────────────────────────────────────────────────────
// PEM bundles, as the Program supplies them; ours come out of trust-sources.yaml
// through the loader the verifier boots with, split back into the two roles.

const trustConfig = await loadTrustConfig(resolve(import.meta.dirname, "../../trust-sources.yaml"));

const bundle = (pems: string[]): string => pems.map((p) => p.trim()).join("\n") + (pems.length ? "\n" : "");

export const TRUST_LISTS = {
  /** Every claim-signing anchor in trust-sources.yaml (RealReel v2 + legacy, Pixel). */
  production: bundle(trustConfig.sources.map((s) => s.rootCertPem)),
  /** Production minus the Pixel root — the wrap-mode parent becomes untrusted. */
  productionWithoutPixel: bundle(trustConfig.sources.filter((s) => s.id !== "pixel").map((s) => s.rootCertPem)),
  /** The throwaway P-384 root fixtures/v2-hierarchy-signed.jpg chains to. */
  v2TestRoot: await readFile(fixture("v2-hierarchy-test-root.pem"), "utf8"),
  /** Nothing trusted. */
  empty: "",
};

export const TSA_LISTS = {
  /** trust-sources.yaml's tsa_roots (C2PA TSA Trust List + fallback). */
  production: bundle(trustConfig.tsaRoots.map((t) => t.rootCertPem)),
  empty: "",
};

// ── Spec schema ─────────────────────────────────────────────────────────────

const schema = JSON.parse(await readFile(resolve(import.meta.dirname, "crjson-2.4.schema.json"), "utf8")) as object;
const ajv = new Ajv2020({ strict: false, allErrors: true });
// ajv-formats is CJS: under NodeNext the default import is module.exports,
// whose `.default` is the plugin.
addFormatsCjs.default(ajv);
const validateSchema = ajv.compile(schema);

/** Ajv errors for a document against the crJSON 2.4 schema; [] when valid. */
export function schemaErrors(doc: unknown): string[] {
  return validateSchema(doc)
    ? []
    : (validateSchema.errors ?? []).map((e) => `${e.instancePath || "/"} ${e.message ?? ""} ${JSON.stringify(e.params)}`);
}

// ── Instants ────────────────────────────────────────────────────────────────

/** Frozen validation instants the suites use. Chosen against the fixtures'
 *  certificate windows (see the golden scenarios for which is which). */
export const AT = {
  /** Inside every fixture's leaf validity; the goldens' default. */
  baseline: new Date("2026-08-18T00:00:00Z"),
  /** Past the untimestamped v2-hierarchy leaf's notAfter (2026-10-25). */
  future: new Date("2031-01-01T00:00:00Z"),
};
