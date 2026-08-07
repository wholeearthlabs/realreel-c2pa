// Lockstep guard between the client's published trust-anchors bundle
// (@realreel/c2pa-trust-core/trust-anchors — what the app passes into
// photo-attest so Stage-2 ingredient validation records trusted results
// for parents the server actually trusts) and the pool this verifier
// builds at boot from trust-sources.yaml.
//
// The client bundle is the verifier pool's CLIENT PROJECTION: same PEMs,
// same order, minus entries marked `client_bundle: false` — those are
// verifier-private acceptance roots (e.g. the general-purpose TSA roots
// anchoring our own timestamps) that the generator's conformance-visible
// recorded validation must NOT assert trust for. Drift in either
// direction is a real defect: a missing root records untrusted for
// content the server accepts; an extra private root records trust the
// C2PA program doesn't endorse.
//
// On failure: `npm run codegen:trust-anchors` in trust-core/ and commit
// the regenerated client-trust-anchors.generated.ts.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

import { CLIENT_TRUST_ANCHORS_PEM } from "@realreel/c2pa-trust-core/trust-anchors";
import { loadTrustConfig } from "../src/trust/loader.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PROD_YAML = resolve(HERE, "..", "trust-sources.yaml");

// Ids the YAML marks verifier-private. Parsed from the same file the
// loader reads, so a new `client_bundle: false` entry reshapes the
// expected projection without touching this test.
function privateIds(): Set<string> {
  const raw = parseYaml(readFileSync(PROD_YAML, "utf-8")) as {
    sources?: Array<{ id: string; client_bundle?: boolean }>;
    tsa_roots?: Array<{ id: string; client_bundle?: boolean }>;
  };
  return new Set(
    [...(raw.sources ?? []), ...(raw.tsa_roots ?? [])]
      .filter((e) => e.client_bundle === false)
      .map((e) => e.id),
  );
}

describe("client trust-anchors bundle lockstep (trust-core ↔ verifier pool)", () => {
  it("CLIENT_TRUST_ANCHORS_PEM byte-equals the loader pool's client projection", async () => {
    // Derive the expectation through the verifier's REAL loader (full YAML
    // parse + the same trim/join concatenation the server boots with), then
    // apply the client_bundle filter — not a re-implementation of either.
    const trustConfig = await loadTrustConfig(PROD_YAML);
    const priv = privateIds();
    const expected = [
      ...trustConfig.sources.filter((s) => !priv.has(s.id)),
      ...trustConfig.tsaRoots.filter((t) => !priv.has(t.id)),
    ]
      .map((e) => e.rootCertPem.trim())
      .join("\n");
    expect(CLIENT_TRUST_ANCHORS_PEM).toBe(expected);
  });

  it("verifier-private roots never leak into the client bundle", async () => {
    const trustConfig = await loadTrustConfig(PROD_YAML);
    const priv = privateIds();
    expect(priv.size).toBeGreaterThan(0); // c2pa-tsa-fallback today
    for (const entry of [...trustConfig.sources, ...trustConfig.tsaRoots]) {
      if (!priv.has(entry.id)) continue;
      expect(
        CLIENT_TRUST_ANCHORS_PEM.includes(entry.rootCertPem.trim()),
        `verifier-private root '${entry.id}' must not be in CLIENT_TRUST_ANCHORS_PEM`,
      ).toBe(false);
    }
  });

  it("bundle contains every non-private signer + TSA root", async () => {
    // Belt-and-suspenders readability check: byte-equality above already
    // implies this, but these named probes turn "bundles differ" into
    // "which root went missing".
    const trustConfig = await loadTrustConfig(PROD_YAML);
    const priv = privateIds();
    for (const entry of [...trustConfig.sources, ...trustConfig.tsaRoots]) {
      if (priv.has(entry.id)) continue;
      expect(
        CLIENT_TRUST_ANCHORS_PEM.includes(entry.rootCertPem.trim()),
        `root '${entry.id}' missing from CLIENT_TRUST_ANCHORS_PEM`,
      ).toBe(true);
    }
  });
});
