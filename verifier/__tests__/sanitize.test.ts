// sanitize.ts tests. End-to-end shape testing against real c2pa-node
// output is in __tests__/verify-realreel.test.ts, against a real
// fixture. Here we cover the structural pieces: shape mapping,
// missing fields → null, parent ingredient extraction, validation
// state derivation, trust_source propagation.

import { describe, it, expect } from "vitest";
import { sanitizeManifestStore } from "../src/sanitize.js";

describe("sanitizeManifestStore", () => {
  it("derives validation_state: 'trusted' when validation_status is empty", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: { m1: { label: "m1", claim_generator: "RealReel/1.0" } },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.validation_state).toBe("trusted");
  });

  it("derives validation_state: 'invalid' when validation_status has any entry", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: { m1: { label: "m1" } },
        validation_status: [{ code: "claimSignature.mismatch" }],
      },
      "realreel",
    );
    expect(out.validation_state).toBe("invalid");
    expect(out.validation_status).toHaveLength(1);
    expect(out.validation_status[0]!.code).toBe("claimSignature.mismatch");
  });

  it("propagates trust_source from the argument", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: { m1: { label: "m1" } },
        validation_status: [],
      },
      "pixel",
    );
    expect(out.trust_source).toBe("pixel");
  });

  it("extracts parent_label from the first ingredient with active_manifest", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "stage2",
        manifests: {
          stage1: { label: "stage1", claim_generator: "RealReel-capture" },
          stage2: {
            label: "stage2",
            claim_generator: "RealReel-upload",
            ingredients: [{ active_manifest: "stage1" }],
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.parent_label).toBe("stage1");
    expect(out.manifests["stage1"]?.parent_label).toBeNull();
  });

  it("returns parent_label: null when manifest has no ingredients", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "lone",
        manifests: { lone: { label: "lone" } },
        validation_status: [],
      },
      "pixel",
    );
    expect(out.active_manifest?.parent_label).toBeNull();
  });

  it("preserves assertion label + data, drops malformed assertions", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: {
          m1: {
            label: "m1",
            assertions: [
              { label: "c2pa.actions", data: { actions: [{ action: "c2pa.resized" }] } },
              { label: "org.realreel.capture", data: { capturerUuid: "abc" } },
              // malformed — no label, should be dropped
              { data: "should be dropped" },
              // malformed — label not a string
              { label: 123 as unknown as string, data: "should be dropped" },
            ],
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.assertions).toHaveLength(2);
    expect(out.active_manifest?.assertions[0]!.label).toBe("c2pa.actions");
    expect(out.active_manifest?.assertions[1]!.label).toBe("org.realreel.capture");
  });

  it("maps signature_info: issuer + ISO time string", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: {
          m1: {
            label: "m1",
            signature_info: {
              issuer: "CN=RealReel Issuing CA",
              time: "2026-05-14T10:30:00Z",
            },
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.signature_info.issuer).toBe("CN=RealReel Issuing CA");
    expect(out.active_manifest?.signature_info.time).toBe("2026-05-14T10:30:00Z");
  });

  it("falls back to timeObject.toISOString() when time string is missing", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: {
          m1: {
            label: "m1",
            signature_info: { timeObject: new Date("2026-01-15T08:00:00.000Z") },
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.signature_info.time).toBe("2026-01-15T08:00:00.000Z");
  });

  it("nulls signature_info fields when missing entirely", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: { m1: { label: "m1" } },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.signature_info.issuer).toBeNull();
    expect(out.active_manifest?.signature_info.time).toBeNull();
  });

  it("targets a small JSON payload (<2 KB for a typical 2-stage manifest)", () => {
    const typical = {
      active_manifest: "stage2",
      manifests: {
        stage1: {
          label: "stage1",
          claim_generator: "RealReel-capture/1.2.3 c2pa-rs/0.13.0",
          title: "img.jpg",
          format: "image/jpeg",
          signature_info: { issuer: "CN=RealReel Issuing CA", time: "2026-05-14T10:30:00Z" },
          assertions: [
            { label: "org.realreel.capture", data: { capturerUuid: "00000000-0000-0000-0000-000000000000", deviceManufacturer: "Apple" } },
          ],
        },
        stage2: {
          label: "stage2",
          claim_generator: "RealReel-upload/1.2.3 c2pa-rs/0.13.0",
          title: "img.jpg",
          format: "image/jpeg",
          signature_info: { issuer: "CN=RealReel Issuing CA", time: "2026-05-14T10:30:05Z" },
          assertions: [
            { label: "org.realreel.upload", data: { deviceManufacturer: "Apple", appVersion: "1.2.3" } },
            { label: "c2pa.actions", data: { actions: [{ action: "c2pa.resized" }, { action: "c2pa.transcoded" }] } },
          ],
          ingredients: [{ active_manifest: "stage1" }],
        },
      },
      validation_status: [],
    };
    const out = sanitizeManifestStore(typical, "realreel");
    const json = JSON.stringify(out);
    // Ceiling documented in sanitize.ts. If this grows materially,
    // revisit the kept-fields policy — assertions are the bulk of the
    // size, but the capturer-UUID UI needs them for the Content
    // Credentials overlay.
    expect(json.length).toBeLessThan(2048);
  });
});
