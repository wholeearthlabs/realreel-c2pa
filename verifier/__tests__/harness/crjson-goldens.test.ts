// crJSON goldens: the verifier's validation behaviour on the committed
// fixtures, pinned in the externally specified format rather than our own
// result shape — they break when BEHAVIOUR changes (c2pa-rs bump, trust-list
// edit, regenerated fixture), not when we rename a field. Byte-deterministic
// because every scenario runs at a frozen instant (crjson-harness.test.ts
// proves that; this file relies on it).
//
// Regenerate: UPDATE_CRJSON_GOLDENS=1 npm test --workspace verifier -- goldens
// — then READ THE DIFF. A c2patool bump moves every jsonGenerator.version;
// anything moving in validationResults needs a reason.

import { describe, it, expect } from "vitest";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { runCrjsonHarness } from "../../src/harness/crjson.js";
import { AT, fixture, fixturesReady, GOLDENS, harnessAvailable, TRUST_LISTS, TSA_LISTS } from "./_support.js";

interface Scenario {
  /** Golden file stem: <fixture>@<instant>[+<variant>]. */
  id: string;
  asset: string;
  trustList: keyof typeof TRUST_LISTS;
  tsaList: keyof typeof TSA_LISTS;
  at: keyof typeof AT;
  /** What the scenario is for — kept next to the data, not in a README. */
  why: string;
}

const SCENARIOS: Scenario[] = [
  { id: "realreel-uploaded@baseline", asset: "realreel-uploaded.jpg", trustList: "production", tsaList: "production", at: "baseline",
    why: "two-stage RealReel capture+upload under the legacy root, both stages DigiCert-timestamped" },
  { id: "realreel-uploaded@baseline+no-tsa", asset: "realreel-uploaded.jpg", trustList: "production", tsaList: "empty", at: "baseline",
    why: "TSA list input: without it the time-stamps are untrusted (informational) but the leaves are still inside validity" },
  { id: "realreel-drained@baseline", asset: "realreel-drained.jpg", trustList: "production", tsaList: "production", at: "baseline",
    why: "three-manifest offline chain: capture → interposed timestamp Update Manifest → upload" },
  { id: "pixel-uploaded@baseline", asset: "pixel-uploaded.jpg", trustList: "production", tsaList: "production", at: "baseline",
    why: "wrap mode: RealReel Stage 2 over a Pixel Camera parent" },
  { id: "pixel-uploaded@baseline+no-pixel-no-tsa", asset: "pixel-uploaded.jpg", trustList: "productionWithoutPixel", tsaList: "empty", at: "baseline",
    why: "wrap parent falls back to the clock (Google root reachable through neither list) and is past its leaf validity → expired; active manifest unaffected" },
  { id: "pixel-og@baseline", asset: "pixel-og.jpg", trustList: "production", tsaList: "production", at: "baseline",
    why: "TSA-anchored validity: leaf expired 2026-05-06, valid at 2026-08-22 through its time-stamp" },
  { id: "v2-hierarchy@baseline+test-root", asset: "v2-hierarchy-signed.jpg", trustList: "v2TestRoot", tsaList: "production", at: "baseline",
    why: "conformant v2 hierarchy (P-256 leaf under P-384 chain) validates cleanly against its root" },
  { id: "v2-hierarchy@future+test-root", asset: "v2-hierarchy-signed.jpg", trustList: "v2TestRoot", tsaList: "production", at: "future",
    why: "validation time input: untimestamped leaf (notAfter 2026-10-25) is expired at 2031" },
  { id: "v2-hierarchy@baseline+production", asset: "v2-hierarchy-signed.jpg", trustList: "production", tsaList: "production", at: "baseline",
    why: "trust list input: the same asset is untrusted when its root is not supplied" },
];
// No golden for the no-manifest empty document: it carries the harness's own
// version, which moves on every release; crjson-harness.test.ts asserts its shape.

const UPDATE = process.env.UPDATE_CRJSON_GOLDENS === "1";
const goldenPath = (id: string): string => resolve(GOLDENS, `${id}.crjson`);
const ready = await fixturesReady([...new Set(SCENARIOS.map((s) => s.asset))]);

describe.skipIf(!harnessAvailable || !ready)("crJSON goldens", () => {
  it.each(SCENARIOS)("$id — $why", (scenario) => {
    const run = runCrjsonHarness({
      assetPath: fixture(scenario.asset),
      trustListPem: TRUST_LISTS[scenario.trustList],
      tsaTrustListPem: TSA_LISTS[scenario.tsaList],
      validationTime: AT[scenario.at],
    });
    // The deployed engine must agree with every golden, or the golden is not
    // a statement about the verifier.
    expect(run.record.engineAgreement).toEqual({ checked: true, agree: true, differences: [] });

    const path = goldenPath(scenario.id);
    if (UPDATE) {
      mkdirSync(GOLDENS, { recursive: true });
      writeFileSync(path, run.crjsonText);
    }
    expect(existsSync(path), `missing golden ${path} — run with UPDATE_CRJSON_GOLDENS=1 and review the diff`).toBe(true);
    expect(run.crjsonText).toBe(readFileSync(path, "utf8"));
  });
});
