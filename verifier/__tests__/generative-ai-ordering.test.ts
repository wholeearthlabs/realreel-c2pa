// Ordering pin for the generative-AI gate that needs no fixture. c2pa-node's
// Reader is mocked to hand verify() a synthetic store, so this suite runs on
// an LFS-pointer checkout and fails if enforceNoGenerativeAi ever moves
// behind issuer resolution, the force-wrap gate, or the realreel profile.
// The fixture-backed end-to-end proof lives in generative-ai.test.ts.

import { describe, it, expect, vi, beforeEach } from "vitest";
import { resolve } from "node:path";

const { readerJson } = vi.hoisted(() => ({ readerJson: vi.fn() }));

vi.mock("@contentauth/c2pa-node", () => ({
  Reader: { fromAsset: vi.fn(async () => ({ json: readerJson })) },
  createTrustSettings: () => ({}),
  settingsToJson: () => "{}",
}));

vi.mock("../src/db.js", () => {
  const lookupSigningKeyRevocation = vi.fn().mockResolvedValue(null);
  const consumeAndRecordAttestation = vi.fn().mockResolvedValue(undefined);
  const pingDb = vi.fn();
  return {
    lookupSigningKeyRevocation,
    consumeAndRecordAttestation,
    pingDb,
    initDb: vi.fn(),
    closeDbPool: vi.fn(),
    postgresAdapter: {
      lookup: lookupSigningKeyRevocation,
      burn: consumeAndRecordAttestation,
      ping: pingDb,
    },
  };
});

import { verify } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { VerifyErrorCode } from "../src/errors.js";
import type { ManifestStoreShape } from "../src/c2pa-shape.js";

const DST = "http://cv.iptc.org/newscodes/digitalsourcetype/";
const FIXTURE_USER_ID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
// Enough of a JPEG for the container sniff; the mocked Reader never reads it.
const JPEG_SOI = Buffer.from([0xff, 0xd8, 0xff, 0xe0]);

const trustConfig = await loadTrustConfig(resolve(import.meta.dirname, "../trust-sources.yaml"));

/** Two-stage RealReel store (issuer resolves to `realreel`); the capture's
 *  digitalSourceType varies. */
function realreelStore(captureSourceType: string): ManifestStoreShape {
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

/** Single-stage store from a generator no trust source resolves. */
function foreignStore(sourceType: string): ManifestStoreShape {
  return {
    active_manifest: "urn:c2pa:gen",
    manifests: {
      "urn:c2pa:gen": {
        label: "urn:c2pa:gen",
        signature_info: { issuer: "Google LLC", common_name: "Google Media Processing Services" },
        assertions: [
          {
            label: "c2pa.actions.v2",
            data: { actions: [{ action: "c2pa.created", digitalSourceType: sourceType }] },
          },
        ],
        ingredients: [],
      },
    },
  };
}

const run = (store: ManifestStoreShape) => {
  readerJson.mockReturnValueOnce(store);
  return verify({
    assetBytes: JPEG_SOI,
    mimeType: "image/jpeg",
    expectedUserId: FIXTURE_USER_ID,
    declaredLocation: "none",
    trustConfig,
  });
};

beforeEach(() => {
  readerJson.mockReset();
});

describe("verify() runs the generative-AI gate ahead of trust and structure", () => {
  it("rejects a TRUSTED two-stage store whose capture declares a model as AI_GENERATED", async () => {
    // Behind the profile this store would fail on the missing cert serial
    // (MANIFEST_MALFORMED); the AI code proves the gate ran first.
    await expect(run(realreelStore(`${DST}trainedAlgorithmicMedia`))).rejects.toMatchObject({
      code: VerifyErrorCode.AI_GENERATED,
      detail: expect.stringContaining("urn:c2pa:stage1"),
    });
  });

  it("rejects a foreign generator's store as AI_GENERATED, not UNTRUSTED_ISSUER", async () => {
    await expect(run(foreignStore(`${DST}trainedAlgorithmicMedia`))).rejects.toMatchObject({
      code: VerifyErrorCode.AI_GENERATED,
    });
  });

  it("lets a foreign store without a model declaration reach the trust gate", async () => {
    // Sanity for the mock path: the same store minus the declaration is
    // refused by the force-wrap / dispatcher, so the AI verdict above is not
    // an artifact of the harness.
    await expect(run(foreignStore(`${DST}digitalCapture`))).rejects.toMatchObject({
      code: VerifyErrorCode.UNTRUSTED_ISSUER,
    });
  });

  it("does not let an unreferenced manifest relabel a trusted capture", async () => {
    const store = realreelStore(`${DST}digitalCapture`);
    store.manifests!["urn:c2pa:stray"] = {
      label: "urn:c2pa:stray",
      signature_info: { issuer: "CN=Acme Generator" },
      assertions: [
        {
          label: "c2pa.actions.v2",
          data: { actions: [{ action: "c2pa.created", digitalSourceType: `${DST}trainedAlgorithmicMedia` }] },
        },
      ],
      ingredients: [],
    };
    let code: string | undefined;
    try {
      await run(store);
    } catch (e) {
      code = (e as { code?: string }).code;
    }
    expect(code).toBeDefined();
    expect(code).not.toBe(VerifyErrorCode.AI_GENERATED);
  });
});
