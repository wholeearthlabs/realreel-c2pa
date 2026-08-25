// Generative-AI provenance gate.
//
//   - Unit: enforceNoGenerativeAi over synthetic stores. A chain-valid,
//     structurally clean two-stage RealReel store whose CAPTURE declares
//     trainedAlgorithmicMedia is refused; a Pixel computationalCapture is not.
//   - End to end through verify(): fixtures/ai-generated-signed.jpg is a
//     single-stage JPEG whose c2pa.created declares trainedAlgorithmicMedia,
//     signed by a throwaway P-256 leaf (subject O "Whole Earth Labs LLC", so
//     the dispatcher routes it to `realreel`; CN "AI Fixture Leaf") under
//     fixtures/ai-generated-test-root.pem (CN "AI Fixture Test Root"; no
//     production trust decision references it). Anchored at that root the
//     chain is trusted and the single-stage shape would otherwise fail the
//     profile as MANIFEST_MALFORMED; under the production anchors it is
//     untrusted and would otherwise read UNTRUSTED_ISSUER. Both read
//     AI_GENERATED: the gate sits ahead of issuer resolution and every
//     structural rule. Signed with c2patool 0.27.15 on 2026-08-25 from
//     synthetic-usercomment.jpg; the leaf key was discarded.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { verify } from "../src/verify.js";
import { enforceNoGenerativeAi } from "../src/generative-ai.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import type { TrustConfig } from "../src/trust/types.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";
import type { ManifestStoreShape } from "../src/c2pa-shape.js";

const DST = "http://cv.iptc.org/newscodes/digitalsourcetype/";
const FIXTURE_USER_ID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";

/** A two-stage RealReel store that passes every structural rule; only the
 *  capture's digitalSourceType varies. */
function twoStageStore(captureSourceType: string): ManifestStoreShape {
  return {
    active_manifest: "urn:c2pa:stage2",
    manifests: {
      "urn:c2pa:stage2": {
        label: "urn:c2pa:stage2",
        signature_info: { issuer: "Whole Earth Labs LLC", common_name: "RealReel iOS" },
        assertions: [
          {
            label: "c2pa.actions.v2",
            data: { actions: [{ action: "c2pa.opened" }, { action: "c2pa.resized.proportional" }] },
          },
        ],
        ingredients: [{ active_manifest: "urn:c2pa:stage1", relationship: "parentOf" }],
      },
      "urn:c2pa:stage1": {
        label: "urn:c2pa:stage1",
        signature_info: { issuer: "Whole Earth Labs LLC", common_name: "RealReel iOS" },
        assertions: [
          {
            label: "c2pa.actions.v2",
            data: { actions: [{ action: "c2pa.created", digitalSourceType: captureSourceType }] },
          },
        ],
        ingredients: [],
      },
    },
  };
}

describe("enforceNoGenerativeAi", () => {
  it("refuses a chain-valid two-stage RealReel store whose capture declares a model", () => {
    let thrown: unknown;
    try {
      enforceNoGenerativeAi(twoStageStore(`${DST}trainedAlgorithmicMedia`));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VerifyError);
    const err = thrown as VerifyError;
    expect(err.code).toBe(VerifyErrorCode.AI_GENERATED);
    expect(err.detail).toContain("urn:c2pa:stage1");
    expect(err.detail).toContain("c2pa.created");
    expect(err.detail).toContain("trainedAlgorithmicMedia");
  });

  it("refuses a model edit declared on the upload manifest", () => {
    const store = twoStageStore(`${DST}digitalCapture`);
    store.manifests!["urn:c2pa:stage2"]!.assertions = [
      {
        label: "c2pa.actions.v2",
        data: {
          actions: [
            { action: "c2pa.opened" },
            { action: "c2pa.edited", digitalSourceType: `${DST}compositeWithTrainedAlgorithmicMedia` },
          ],
        },
      },
    ];
    expect(() => enforceNoGenerativeAi(store)).toThrow(VerifyError);
  });

  it.each(["digitalCapture", "computationalCapture", "algorithmicallyEnhanced"])(
    "accepts a capture declaring %s",
    (term) => {
      expect(() => enforceNoGenerativeAi(twoStageStore(`${DST}${term}`))).not.toThrow();
    },
  );
});

const fixturePath = resolve(import.meta.dirname, "fixtures/ai-generated-signed.jpg");
const testRootPath = resolve(import.meta.dirname, "fixtures/ai-generated-test-root.pem");
const TMP_DIR = resolve(import.meta.dirname, ".tmp-ai-generated");

// LFS pointer-only checkout leaves a text stub in place of the JPEG → skip,
// same convention as the other fixture suites.
const fixtureReady = await access(fixturePath)
  .then(async () => {
    const head = (await readFile(fixturePath)).subarray(0, 64).toString("latin1");
    return !head.startsWith("version https://git-lfs.github.com/");
  })
  .catch(() => false);

describe.skipIf(!fixtureReady)("verify() refuses generative-AI provenance ahead of trust", () => {
  let bytes: Buffer;
  let anchoredConfig: TrustConfig;
  let productionConfig: TrustConfig;

  beforeAll(async () => {
    bytes = await readFile(fixturePath);

    // Anchor `realreel` at the fixture's throwaway root so the chain is
    // trusted and the issuer resolves. root_cert paths resolve relative to
    // the YAML's directory; an absolute path passes through unchanged.
    await mkdir(TMP_DIR, { recursive: true });
    const yamlPath = resolve(TMP_DIR, "trust-sources.yaml");
    await writeFile(
      yamlPath,
      [
        "sources:",
        "  - id: realreel",
        "    name: RealReel (AI fixture test hierarchy)",
        "    description: throwaway root the AI-declaring fixture chains to",
        `    root_cert: ${testRootPath}`,
        "    verification_profile: realreel",
        "",
      ].join("\n"),
      "utf-8",
    );
    anchoredConfig = await loadTrustConfig(yamlPath);
    productionConfig = await loadTrustConfig(resolve(import.meta.dirname, "../trust-sources.yaml"));
  });

  afterAll(async () => {
    await rm(TMP_DIR, { recursive: true, force: true });
  });

  const run = (trustConfig: TrustConfig) =>
    verify({
      assetBytes: bytes,
      mimeType: "image/jpeg",
      expectedUserId: FIXTURE_USER_ID,
      declaredLocation: "none",
      trustConfig,
    });

  it("rejects AI_GENERATED when the chain is TRUSTED (the single-stage shape would otherwise be MANIFEST_MALFORMED)", async () => {
    await expect(run(anchoredConfig)).rejects.toMatchObject({
      code: VerifyErrorCode.AI_GENERATED,
      detail: expect.stringContaining("trainedAlgorithmicMedia"),
    });
  });

  it("rejects AI_GENERATED under the production anchors (would otherwise be UNTRUSTED_ISSUER)", async () => {
    await expect(run(productionConfig)).rejects.toMatchObject({
      code: VerifyErrorCode.AI_GENERATED,
    });
  });
});
