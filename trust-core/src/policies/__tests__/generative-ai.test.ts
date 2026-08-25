// Unit tests for the generative-AI provenance policy. Pure-function tests —
// no network, no DB, no native modules. The store shapes mirror the
// Conformance Program's sample library (a synthetic video whose lineage is
// inputTo, a PNG that buries an OpenAI generation two edits down, a Magic
// Editor JPEG over a Pixel capture) and the trusted-camera case the policy
// exists for.

import { describe, it, expect } from "vitest";

import {
  GENERATIVE_AI_SOURCE_TYPES,
  findGenerativeAiSource,
} from "../generative-ai.js";
import type { ManifestShape, ManifestStoreShape } from "../../shapes/manifest.js";

const DST = "http://cv.iptc.org/newscodes/digitalsourcetype/";

type ActionEntry = { action?: string; digitalSourceType?: string; related?: ActionEntry[] };

function manifest(
  actions: ActionEntry[],
  ingredients: ManifestShape["ingredients"] = [],
  label = "c2pa.actions.v2",
): ManifestShape {
  return {
    signature_info: { issuer: "Whole Earth Labs LLC" },
    assertions: [{ label, data: { actions } }],
    ingredients,
  };
}

describe("GENERATIVE_AI_SOURCE_TYPES — surface contract", () => {
  it("is exactly the two model-backed IPTC terms", () => {
    // Pinned: widening this set to a camera-pipeline term
    // (computationalCapture, algorithmicallyEnhanced) would refuse every
    // Pixel capture; narrowing it would let model output through.
    expect([...GENERATIVE_AI_SOURCE_TYPES].sort()).toEqual([
      `${DST}compositeWithTrainedAlgorithmicMedia`,
      `${DST}trainedAlgorithmicMedia`,
    ]);
  });
});

describe("findGenerativeAiSource", () => {
  it("finds trainedAlgorithmicMedia on the active manifest's c2pa.created", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:gen",
      manifests: {
        "urn:c2pa:gen": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)).toEqual({
      label: "urn:c2pa:gen",
      action: "c2pa.created",
      digitalSourceType: `${DST}trainedAlgorithmicMedia`,
    });
  });

  it("refuses a TRUSTED two-stage RealReel store whose capture declares a model", () => {
    // The case the policy exists for: chain-valid, structurally a fresh
    // capture, actions within the allowlist — and still model output.
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:stage2",
      manifests: {
        "urn:c2pa:stage2": manifest(
          [{ action: "c2pa.opened" }, { action: "c2pa.resized.proportional" }],
          [{ active_manifest: "urn:c2pa:stage1", relationship: "parentOf" }],
        ),
        "urn:c2pa:stage1": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)?.label).toBe("urn:c2pa:stage1");
  });

  it("follows inputTo ingredients, not only the parentOf chain", () => {
    // The Program's synthetic video: the active manifest's lineage is
    // inputTo (model inputs); no parentOf exists to walk.
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:out",
      manifests: {
        "urn:c2pa:out": manifest(
          [{ action: "c2pa.created", digitalSourceType: `${DST}computationalCapture` }],
          [{ active_manifest: "urn:c2pa:in", relationship: "inputTo" }],
        ),
        "urn:c2pa:in": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)?.label).toBe("urn:c2pa:in");
  });

  it("reaches a generation buried two edits down (the Program PNG chain)", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:converted",
      manifests: {
        "urn:c2pa:converted": manifest(
          [{ action: "c2pa.opened" }, { action: "c2pa.edited", digitalSourceType: `${DST}composite` }],
          [{ active_manifest: "urn:c2pa:resized", relationship: "parentOf" }],
        ),
        "urn:c2pa:resized": manifest(
          [{ action: "c2pa.opened" }, { action: "c2pa.resized" }],
          [{ active_manifest: "urn:c2pa:openai", relationship: "parentOf" }],
        ),
        "urn:c2pa:openai": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)?.label).toBe("urn:c2pa:openai");
  });

  it("finds compositeWithTrainedAlgorithmicMedia on an edit action", () => {
    // Magic Editor: c2pa.edited over a Pixel capture.
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:edit",
      manifests: {
        "urn:c2pa:edit": manifest(
          [
            { action: "c2pa.opened" },
            { action: "c2pa.edited", digitalSourceType: `${DST}compositeWithTrainedAlgorithmicMedia` },
          ],
          [{ active_manifest: "urn:c2pa:capture", relationship: "parentOf" }],
        ),
        "urn:c2pa:capture": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}computationalCapture` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)).toMatchObject({
      label: "urn:c2pa:edit",
      action: "c2pa.edited",
    });
  });

  it("finds a declaration on a nested related sub-action", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:edit",
      manifests: {
        "urn:c2pa:edit": manifest([
          {
            action: "c2pa.edited",
            related: [{ action: "c2pa.filtered", digitalSourceType: `${DST}trainedAlgorithmicMedia` }],
          },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)).toMatchObject({ action: "c2pa.filtered" });
  });

  it("ignores a manifest the active one does not reference", () => {
    // A stray manifest appended to the store is not part of the file's
    // provenance claim and cannot relabel a genuine capture.
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:capture",
      manifests: {
        "urn:c2pa:capture": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}digitalCapture` },
        ]),
        "urn:c2pa:stray": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)).toBeNull();
  });

  it("returns null when the store has no resolvable active manifest", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:missing",
      manifests: {
        "urn:c2pa:gen": manifest([
          { action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)).toBeNull();
    expect(findGenerativeAiSource({})).toBeNull();
  });

  it("terminates on an ingredient cycle", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:a",
      manifests: {
        "urn:c2pa:a": manifest([{ action: "c2pa.opened" }], [
          { active_manifest: "urn:c2pa:b", relationship: "parentOf" },
        ]),
        "urn:c2pa:b": manifest([{ action: "c2pa.opened" }], [
          { active_manifest: "urn:c2pa:a", relationship: "parentOf" },
        ]),
      },
    };
    expect(findGenerativeAiSource(store)).toBeNull();
  });

  it("accepts the https spelling of the vocabulary URI and reports it verbatim", () => {
    const dst = `https://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia`;
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:gen",
      manifests: { "urn:c2pa:gen": manifest([{ action: "c2pa.created", digitalSourceType: dst }]) },
    };
    expect(findGenerativeAiSource(store)?.digitalSourceType).toBe(dst);
  });

  it("reads the legacy c2pa.actions (v1) assertion label too", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:gen",
      manifests: {
        "urn:c2pa:gen": manifest(
          [{ action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` }],
          [],
          "c2pa.actions",
        ),
      },
    };
    expect(findGenerativeAiSource(store)?.action).toBe("c2pa.created");
  });

  it.each([
    "digitalCapture",
    "computationalCapture",
    "algorithmicallyEnhanced",
    "compositeCapture",
    "compositeSynthetic",
    "algorithmicMedia",
    "humanEdits",
    "minorHumanEdits",
  ])("returns null for the neighbouring term %s", (term) => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:cap",
      manifests: {
        "urn:c2pa:cap": manifest([{ action: "c2pa.created", digitalSourceType: `${DST}${term}` }]),
      },
    };
    expect(findGenerativeAiSource(store)).toBeNull();
  });

  it("tolerates null manifests, null assertions, and malformed actions without throwing", () => {
    const store = {
      active_manifest: "urn:c2pa:a",
      manifests: {
        "urn:c2pa:a": {
          assertions: [
            null,
            { label: "c2pa.actions.v2", data: { actions: "nope" } },
            { label: "c2pa.actions.v2", data: null },
            { label: "c2pa.actions.v2", data: { actions: [null, 7, { related: null }] } },
          ],
          ingredients: [null, { active_manifest: "urn:c2pa:b" }, { active_manifest: 4 }],
        },
        "urn:c2pa:b": null,
      },
    } as unknown as ManifestStoreShape;
    expect(findGenerativeAiSource(store)).toBeNull();
  });

  it("ignores digitalSourceType outside an actions assertion", () => {
    // A metadata assertion carrying the IPTC field is not an action
    // declaration; the policy reads actions only.
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:a",
      manifests: {
        "urn:c2pa:a": {
          assertions: [
            { label: "c2pa.metadata", data: { "Iptc4xmpExt:DigitalSourceType": `${DST}trainedAlgorithmicMedia` } },
            { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } },
          ],
        },
      },
    };
    expect(findGenerativeAiSource(store)).toBeNull();
  });
});
