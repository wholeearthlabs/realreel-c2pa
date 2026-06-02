// Unit tests for structural-rule helpers. Pure-function tests against
// hand-built ManifestShape fixtures — no c2pa-rs, no I/O. Mirrors the
// shape the verifier's policy.test.ts exercises end-to-end against real
// JPEGs, with finer-grained coverage of each pure helper.

import { describe, it, expect } from "vitest";

import {
  APP_ATTEST_LABEL,
  PLAY_INTEGRITY_LABEL,
  requireFreshCapture,
  resolveParentOfIngredient,
  isTimestampUpdateManifest,
  TIMESTAMP_ASSERTION_LABEL,
} from "../structure.js";
import type {
  ManifestShape,
  ManifestStoreShape,
} from "../../shapes/manifest.js";

describe("requireFreshCapture", () => {
  it("returns null when the manifest has no ingredients", () => {
    expect(requireFreshCapture({})).toBeNull();
    expect(requireFreshCapture({ ingredients: [] })).toBeNull();
  });

  it("returns the violation with parent labels when ingredients are present", () => {
    expect(
      requireFreshCapture({
        ingredients: [
          { active_manifest: "urn:test:editor1", relationship: "parentOf" },
          { active_manifest: "urn:test:editor2", relationship: "parentOf" },
        ],
      }),
    ).toEqual({
      parentLabels: ["urn:test:editor1", "urn:test:editor2"],
      ingredientCount: 2,
    });
  });

  it("surfaces unlabeled ingredients as '(unlabeled)' so error formatters can print them", () => {
    // Triage signal: if a real-world manifest arrives with an ingredient
    // that's missing its active_manifest label, we still want to know it
    // existed when looking at Sentry tags.
    expect(
      requireFreshCapture({
        ingredients: [{ relationship: "parentOf" }],
      }),
    ).toEqual({ parentLabels: ["(unlabeled)"], ingredientCount: 1 });
  });
});

describe("resolveParentOfIngredient", () => {
  function store(stage1: ManifestShape, stage2: ManifestShape): ManifestStoreShape {
    return {
      active_manifest: "urn:test:stage2",
      manifests: {
        "urn:test:stage1": stage1,
        "urn:test:stage2": stage2,
      },
    };
  }

  it("resolves a clean Stage 2 → Stage 1 parentOf relationship", () => {
    const s = store(
      { label: "urn:test:stage1" },
      {
        label: "urn:test:stage2",
        ingredients: [
          { active_manifest: "urn:test:stage1", relationship: "parentOf" },
        ],
      },
    );
    const active = s.manifests!["urn:test:stage2"]!;
    const result = resolveParentOfIngredient(s, active);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.parentLabel).toBe("urn:test:stage1");
      expect(result.parent).toBe(s.manifests!["urn:test:stage1"]);
    }
  });

  it("rejects no_ingredients when the active manifest has zero ingredients", () => {
    const active: ManifestShape = { label: "urn:test:stage2", ingredients: [] };
    const result = resolveParentOfIngredient({ manifests: {} }, active);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("no_ingredients");
      expect(result.detail).toContain("got 0");
    }
  });

  it("rejects too_many_ingredients when there are more than one", () => {
    const active: ManifestShape = {
      ingredients: [
        { active_manifest: "urn:test:a", relationship: "parentOf" },
        { active_manifest: "urn:test:b", relationship: "parentOf" },
      ],
    };
    const result = resolveParentOfIngredient({ manifests: {} }, active);
    expect(result.ok).toBe(false);
    if (!result.ok && result.reason === "too_many_ingredients") {
      expect(result.detail).toContain("got 2");
      expect(result.ingredientCount).toBe(2);
    } else {
      throw new Error("expected too_many_ingredients reason");
    }
  });

  it("rejects wrong_relationship when the single ingredient isn't parentOf", () => {
    const active: ManifestShape = {
      ingredients: [
        { active_manifest: "urn:test:a", relationship: "componentOf" },
      ],
    };
    const result = resolveParentOfIngredient({ manifests: {} }, active);
    expect(result.ok).toBe(false);
    if (!result.ok && result.reason === "wrong_relationship") {
      expect(result.detail).toContain("'parentOf'");
      expect(result.detail).toContain("'componentOf'");
      expect(result.observed).toBe("componentOf");
    } else {
      throw new Error("expected wrong_relationship reason");
    }
  });

  it("surfaces missing relationship as '(missing)' in the detail and observed fields", () => {
    const active: ManifestShape = {
      ingredients: [{ active_manifest: "urn:test:a" }],
    };
    const result = resolveParentOfIngredient({ manifests: {} }, active);
    expect(result.ok).toBe(false);
    if (!result.ok && result.reason === "wrong_relationship") {
      expect(result.observed).toBe("(missing)");
      expect(result.detail).toContain("'(missing)'");
    } else {
      throw new Error("expected wrong_relationship reason");
    }
  });

  it("rejects dangling_parent_ref when active_manifest label is absent", () => {
    const active: ManifestShape = {
      ingredients: [{ relationship: "parentOf" }],
    };
    const result = resolveParentOfIngredient({ manifests: {} }, active);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("dangling_parent_ref");
      expect(result.detail).toContain("missing active_manifest label");
    }
  });

  it("rejects dangling_parent_ref when the label points at a non-existent manifest", () => {
    const active: ManifestShape = {
      ingredients: [
        { active_manifest: "urn:test:does-not-exist", relationship: "parentOf" },
      ],
    };
    const result = resolveParentOfIngredient(
      { manifests: { "urn:test:other": {} } },
      active,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("dangling_parent_ref");
      expect(result.detail).toContain("urn:test:does-not-exist");
    }
  });
});

describe("attestation envelope labels", () => {
  it("constants match the wire labels emitted by the native modules", () => {
    // String pin: these literals are part of the C2PA assertion label
    // namespace contract — native/ emits them on the
    // device, and verifier/src/attestation/{apple,play_integrity}.ts
    // import them from this package (no longer duplicates literals).
    // The drift surface that used to exist between server attestation
    // modules and this package was closed in the e10cc61 review pass.
    expect(APP_ATTEST_LABEL).toBe("org.realreel.app_attest");
    expect(PLAY_INTEGRITY_LABEL).toBe("org.realreel.play_integrity");
  });
});

describe("isTimestampUpdateManifest", () => {
  it("the constant matches the C2PA assertion label", () => {
    expect(TIMESTAMP_ASSERTION_LABEL).toBe("c2pa.time-stamp");
  });

  it("returns true for a manifest with both a timestamp assertion and an ingredient", () => {
    expect(
      isTimestampUpdateManifest({
        assertions: [{ label: TIMESTAMP_ASSERTION_LABEL, data: { "urn:x": "tok" } }],
        ingredients: [{ active_manifest: "urn:x", relationship: "parentOf" }],
      }),
    ).toBe(true);
  });

  it("returns false for a fresh capture even if it (hypothetically) carries a timestamp assertion", () => {
    // The ingredient requirement is the guard: a capture has no upstream
    // ingredient, so it can never be mistaken for an interposed Update Manifest.
    expect(
      isTimestampUpdateManifest({
        assertions: [{ label: TIMESTAMP_ASSERTION_LABEL, data: {} }],
        ingredients: [],
      }),
    ).toBe(false);
  });

  it("returns false for a Stage-2-shaped manifest that has an ingredient but no timestamp assertion", () => {
    // A normal Stage-2 (or a never-offline parent walk) must NOT be treated
    // as an interposed Update Manifest.
    expect(
      isTimestampUpdateManifest({
        assertions: [{ label: "c2pa.actions.v2", data: { actions: [] } }],
        ingredients: [{ active_manifest: "urn:p", relationship: "parentOf" }],
      }),
    ).toBe(false);
  });

  it("returns false for an empty manifest", () => {
    expect(isTimestampUpdateManifest({})).toBe(false);
  });
});
