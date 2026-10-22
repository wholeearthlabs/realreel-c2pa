// Pins the c2pa-rs behaviour the recorded-ingredient-results gate rests on,
// through the real Reader: a finding the recorded report lists is dropped
// from validation_status, and a parent the verifier trusts but the record
// calls untrusted still gets a live signingCredential.trusted.
//
// Fixtures (throwaway hierarchies, plain gradient base), each a capture
// wrapped by a Stage-2 sign whose pool anchors only the capture and upload
// roots:
//   parent-gate-aged.jpg    capture leaf valid only in a past window; the
//                           Stage-2 signer recorded it untrusted + expired.
//   parent-gate-untrusted.jpg  capture under an unanchored CA; recorded
//                              untrusted.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFile, access, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Reader } from "@contentauth/c2pa-node";

import { buildVerifierSettings } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import {
  classifyStrictValidationStatus,
  enforceRecordedIngredientResults,
} from "../src/profiles/_shared.js";
import { VerifyErrorCode } from "../src/errors.js";
import type { ManifestStoreShape } from "@realreel/c2pa-trust-core";

const fixturesDir = resolve(import.meta.dirname, "fixtures");
const aged = resolve(fixturesDir, "parent-gate-aged.jpg");
const untrusted = resolve(fixturesDir, "parent-gate-untrusted.jpg");

// LFS-pulled fixtures may be absent (pointer-only checkout) — skip then.
const fixturesExist = await Promise.all([access(aged), access(untrusted)])
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
        "",
      ].join("\n"),
    );
    settings = buildVerifierSettings(await loadTrustConfig(yamlPath));
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
});
