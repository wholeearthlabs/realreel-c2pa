// Pins the c2pa-rs behaviour the recorded-ingredient-results gate rests on,
// through the real Reader: a finding the recorded report lists is dropped
// from validation_status, and a parent the verifier trusts but the record
// calls untrusted still gets a live signingCredential.trusted.
//
// Fixtures (throwaway hierarchies, plain gradient base), each a capture
// wrapped by a Stage-2 sign whose pool anchors only the capture and upload
// roots:
//   parent-gate-aged.jpg       capture leaf valid only in a past window; the
//                              Stage-2 signer recorded it untrusted + expired.
//   parent-gate-untrusted.jpg  capture under an unanchored CA; recorded
//                              untrusted.
//   parent-gate-drained*.jpg   the untrusted capture behind a timestamp Update
//                              Manifest signed under a verifier-only root (not
//                              a RealReel source); -misfiled records the
//                              capture's failure outside the failure bucket.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFile, access, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Reader } from "@contentauth/c2pa-node";

import { buildVerifierSettings } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { makeTrustSourceResolver } from "../src/trust/dispatcher.js";
import type { TrustSourceResolver } from "../src/trust/dispatcher.js";
import {
  classifyStrictValidationStatus,
  enforceRecordedIngredientResults,
} from "../src/profiles/_shared.js";
import { verifyRealReel } from "../src/profiles/realreel.js";
import { VerifyErrorCode } from "../src/errors.js";
import type { ManifestStoreShape } from "@realreel/c2pa-trust-core";

const fixturesDir = resolve(import.meta.dirname, "fixtures");
const fixture = (name: string) => resolve(fixturesDir, `parent-gate-${name}.jpg`);
const aged = fixture("aged");
const untrusted = fixture("untrusted");
const drained = fixture("drained");
const drainedMisfiled = fixture("drained-misfiled");

// LFS-pulled fixtures may be absent (pointer-only checkout) — skip then.
const fixturesExist = await Promise.all(
  [aged, untrusted, drained, drainedMisfiled].map((f) => access(f)),
)
  .then(() => true)
  .catch(() => false);

function recordedFailures(store: ManifestStoreShape): string[] {
  return Object.values(store.manifests ?? {}).flatMap((m) =>
    (m.ingredients ?? []).flatMap((i) =>
      (i.validation_results?.activeManifest?.failure ?? []).map((e) => e.code),
    ),
  );
}

describe.skipIf(!fixturesExist)("parent gate — recorded ingredient results (real engine)", () => {
  let tmp: string;
  let settings: string;
  let resolveSource: TrustSourceResolver;

  beforeAll(async () => {
    tmp = await mkdtemp(join(tmpdir(), "parent-gate-"));
    const yamlPath = join(tmp, "trust-sources.yaml");
    await writeFile(
      yamlPath,
      [
        "sources:",
        "  - id: realreel",
        "    name: capture root (test)",
        `    root_cert: ${resolve(fixturesDir, "parent-gate-capture-root.pem")}`,
        "    verification_profile: realreel",
        "  - id: realreel-legacy",
        "    name: upload root (test)",
        `    root_cert: ${resolve(fixturesDir, "parent-gate-upload-root.pem")}`,
        "    verification_profile: realreel",
        "tsa_roots:",
        "  - id: update-root",
        "    name: verifier-only root (test)",
        `    root_cert: ${resolve(fixturesDir, "parent-gate-update-root.pem")}`,
        "    client_bundle: false",
        "",
      ].join("\n"),
    );
    const trustConfig = await loadTrustConfig(yamlPath);
    settings = buildVerifierSettings(trustConfig);
    resolveSource = makeTrustSourceResolver(trustConfig);
  });

  afterAll(async () => {
    await rm(tmp, { recursive: true, force: true });
  });

  async function read(path: string): Promise<ManifestStoreShape> {
    const reader = await Reader.fromAsset(
      { buffer: await readFile(path), mimeType: "image/jpeg" },
      settings,
    );
    return reader!.json() as unknown as ManifestStoreShape;
  }

  it("accepts a parent the verifier trusts despite its record", async () => {
    const store = await read(aged);
    expect(recordedFailures(store)).toEqual([
      "signingCredential.untrusted",
      "signingCredential.expired",
    ]);
    expect(() => classifyStrictValidationStatus(store.validation_status ?? [])).not.toThrow();
    expect(() => enforceRecordedIngredientResults(store)).not.toThrow();
  });

  it("rejects an untrusted parent the engine left out of validation_status", async () => {
    const store = await read(untrusted);
    expect(recordedFailures(store)).toEqual(["signingCredential.untrusted"]);
    expect(() => classifyStrictValidationStatus(store.validation_status ?? [])).not.toThrow();
    expect(() => enforceRecordedIngredientResults(store)).toThrow(
      expect.objectContaining({ code: VerifyErrorCode.UNTRUSTED_ISSUER }),
    );
  });

  // Each drained fixture is caught twice over: by the recorded-results gate
  // alone, and by the Update Manifest signer check in the full profile.
  it.each([
    ["drained", drained],
    ["drained-misfiled", drainedMisfiled],
  ])("rejects the %s chain", async (_, path) => {
    const store = await read(path);
    expect(() => classifyStrictValidationStatus(store.validation_status ?? [])).not.toThrow();
    expect(() => enforceRecordedIngredientResults(store)).toThrow(
      expect.objectContaining({ code: VerifyErrorCode.UNTRUSTED_ISSUER }),
    );
    await expect(verifyRealReel(store, "realreel", resolveSource)).rejects.toMatchObject({
      code: VerifyErrorCode.UNTRUSTED_ISSUER,
      detail: expect.stringContaining("Update Manifest"),
    });
  });
});
