// Pins the contract of getActiveManifest — the one helper in the shapes
// module. Both the verifier profile and the client preflight gate rely on
// this resolving the LABEL string to the actual manifest object; if a
// future TypeScript refactor breaks the indirection, all downstream
// "no active manifest" rejects regress in confusing ways.

import { describe, it, expect } from "vitest";
import { getActiveManifest, type ManifestStoreShape } from "../manifest.js";

describe("getActiveManifest", () => {
  it("returns the manifest object referenced by active_manifest", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:test:stage2",
      manifests: {
        "urn:test:stage1": { label: "urn:test:stage1" },
        "urn:test:stage2": { label: "urn:test:stage2" },
      },
    };
    expect(getActiveManifest(store)).toEqual({ label: "urn:test:stage2" });
  });

  it("returns undefined when active_manifest is missing", () => {
    const store: ManifestStoreShape = {
      manifests: { "urn:test:stage1": { label: "urn:test:stage1" } },
    };
    expect(getActiveManifest(store)).toBeUndefined();
  });

  it("returns undefined when active_manifest points at a non-existent label", () => {
    const store: ManifestStoreShape = {
      active_manifest: "urn:test:nope",
      manifests: { "urn:test:stage1": { label: "urn:test:stage1" } },
    };
    expect(getActiveManifest(store)).toBeUndefined();
  });

  it("returns undefined when manifests map is absent", () => {
    const store: ManifestStoreShape = { active_manifest: "urn:test:stage1" };
    expect(getActiveManifest(store)).toBeUndefined();
  });

  it("does not throw on the empty store", () => {
    expect(getActiveManifest({})).toBeUndefined();
  });
});
