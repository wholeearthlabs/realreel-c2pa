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

  it("drops re-verification-only assertions (hash bindings, timestamp token, attestation envelopes)", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: {
          m1: {
            label: "m1",
            assertions: [
              { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.resized" }] } },
              { label: "stds.exif", data: { "tiff:Model": "Pixel 10" } },
              { label: "org.realreel.upload", data: { appVersion: "1.2.3" } },
              // dropped — re-verification / consumed-at-ingest material
              { label: "c2pa.hash.data.part", data: { hash: "…" } },
              { label: "c2pa.hash.multi-asset", data: { hash: "…" } },
              { label: "c2pa.time-stamp", data: { "urn:c2pa:x": "<base64 RFC 3161 token>" } },
              { label: "org.realreel.play_integrity", data: { token: "…" } },
              { label: "org.realreel.app_attest", data: { token: "…" } },
            ],
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.assertions.map((a) => a.label)).toEqual([
      "c2pa.actions.v2",
      "stds.exif",
      "org.realreel.upload",
    ]);
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
    expect(out.active_manifest?.signature_info.common_name).toBeNull();
    expect(out.active_manifest?.signature_info.alg).toBeNull();
    expect(out.active_manifest?.signature_info.time).toBeNull();
  });

  it("keeps signature_info common_name + alg (the human-readable signer)", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "m1",
        manifests: {
          m1: {
            label: "m1",
            signature_info: {
              issuer: "CN=Google LLC",
              common_name: "Pixel Camera",
              alg: "Es256",
            },
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.active_manifest?.signature_info.common_name).toBe("Pixel Camera");
    expect(out.active_manifest?.signature_info.alg).toBe("Es256");
  });

  it("lifts the TSA provider name per manifest from validation_results timeStamp.* explanations", () => {
    // Mirrors the real c2pa-node shape: the active manifest's timestamp entry
    // is under validation_results.activeManifest; the parent (Stage-1) entry is
    // under validation_results.ingredientDeltas[]. The name is the substring
    // after the first ": " in the explanation, keyed by the url's manifest label.
    const out = sanitizeManifestStore(
      {
        active_manifest: "stage2",
        manifests: {
          stage1: { label: "stage1" },
          stage2: { label: "stage2", ingredients: [{ active_manifest: "stage1" }] },
        },
        validation_status: [],
        validation_results: {
          activeManifest: {
            success: [
              {
                code: "timeStamp.validated",
                url: "self#jumbf=/c2pa/stage2/c2pa.signature",
                explanation:
                  "timestamp message digest matched: DigiCert SHA256 RSA4096 Timestamp Responder 2025 1",
              },
            ],
          },
          ingredientDeltas: [
            {
              validationDeltas: {
                success: [
                  {
                    code: "timeStamp.trusted",
                    url: "self#jumbf=/c2pa/stage1/c2pa.signature",
                    explanation:
                      "timestamp cert trusted: Google Pixel Time Stamping Authority",
                  },
                ],
              },
            },
          ],
        },
      },
      "realreel",
    );
    expect(out.active_manifest?.signature_info.timestamp_authority).toBe(
      "DigiCert SHA256 RSA4096 Timestamp Responder 2025 1",
    );
    expect(out.manifests["stage1"]?.signature_info.timestamp_authority).toBe(
      "Google Pixel Time Stamping Authority",
    );
  });

  it("also resolves a parent TSA from the ingredient-nested validation_results", () => {
    // c2pa-node surfaces the parent's timeStamp entry both top-level (above) and
    // nested under the active manifest's ingredient — either source must resolve.
    const out = sanitizeManifestStore(
      {
        active_manifest: "stage2",
        manifests: {
          stage1: { label: "stage1" },
          stage2: {
            label: "stage2",
            ingredients: [
              {
                active_manifest: "stage1",
                validation_results: {
                  activeManifest: {
                    success: [
                      {
                        code: "timeStamp.validated",
                        url: "self#jumbf=/c2pa/stage1/c2pa.signature",
                        explanation: "timestamp message digest matched: SSL.com TSA",
                      },
                    ],
                  },
                },
              },
            ],
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.manifests["stage1"]?.signature_info.timestamp_authority).toBe("SSL.com TSA");
  });

  it("leaves timestamp_authority null when there is no sigTst2 validation entry", () => {
    const out = sanitizeManifestStore(
      { active_manifest: "m1", manifests: { m1: { label: "m1" } }, validation_status: [] },
      "realreel",
    );
    expect(out.active_manifest?.signature_info.timestamp_authority).toBeNull();
  });

  it("lifts the TSA name from an untrusted (informational) stamp but not from the failure bucket", () => {
    const store = (activeManifest: unknown) => ({
      active_manifest: "m1",
      manifests: { m1: { label: "m1" } },
      validation_status: [],
      validation_results: { activeManifest },
    });
    // An untrusted-but-present stamp (informational) still names the TSA.
    const untrusted = sanitizeManifestStore(
      store({
        informational: [
          { code: "timeStamp.untrusted", url: "self#jumbf=/c2pa/m1/c2pa.signature", explanation: "timestamp cert untrusted: SSL.com TSA" },
        ],
      }),
      "realreel",
    );
    expect(untrusted.active_manifest?.signature_info.timestamp_authority).toBe("SSL.com TSA");
    // A timeStamp.* entry in the failure bucket is NOT surfaced as a timestamp.
    const failed = sanitizeManifestStore(
      store({
        failure: [
          { code: "timeStamp.mismatch", url: "self#jumbf=/c2pa/m1/c2pa.signature", explanation: "timestamp message digest mismatch: Nope TSA" },
        ],
      }),
      "realreel",
    );
    expect(failed.active_manifest?.signature_info.timestamp_authority).toBeNull();
  });

  it("preserves ingredient title/format/relationship alongside the parent pointer", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "stage2",
        manifests: {
          stage1: { label: "stage1" },
          stage2: {
            label: "stage2",
            ingredients: [
              {
                title: "PXL_20260516.jpg",
                format: "image/jpeg",
                relationship: "parentOf",
                active_manifest: "stage1",
              },
            ],
          },
        },
        validation_status: [],
      },
      "realreel",
    );
    const ingredients = out.active_manifest?.ingredients;
    expect(ingredients).toHaveLength(1);
    expect(ingredients?.[0]).toEqual({
      title: "PXL_20260516.jpg",
      format: "image/jpeg",
      relationship: "parentOf",
      active_manifest: "stage1",
    });
    // parent_label still derives from the same ingredient.
    expect(out.active_manifest?.parent_label).toBe("stage1");
  });

  it("nulls absent ingredient fields and returns [] when there are no ingredients", () => {
    const out = sanitizeManifestStore(
      {
        active_manifest: "stage2",
        manifests: {
          lone: { label: "lone" },
          stage2: { label: "stage2", ingredients: [{ active_manifest: "lone" }] },
        },
        validation_status: [],
      },
      "realreel",
    );
    expect(out.manifests["lone"]?.ingredients).toEqual([]);
    expect(out.active_manifest?.ingredients[0]).toEqual({
      title: null,
      format: null,
      relationship: null,
      active_manifest: "lone",
    });
  });

  it("drops the re-verification bulk, keeping the persisted shape compact", () => {
    // Hard-binding hashes + an attestation envelope dominate a raw manifest
    // (~2 KB here) but carry no provenance a viewer reads — sanitize drops
    // them, so the kept shape stays small. Real-row sizes are pinned against
    // actual fixtures in verify-realreel*.test.ts; this guards the structure.
    const heavyReVerify = [
      { label: "c2pa.hash.data.part", data: { hash: "A".repeat(1200), pad: "B".repeat(400) } },
      { label: "c2pa.time-stamp", data: { "urn:c2pa:x": "D".repeat(8000) } },
      { label: "org.realreel.play_integrity", data: { token: "C".repeat(900) } },
    ];
    const typical = {
      active_manifest: "stage2",
      manifests: {
        stage1: {
          label: "stage1",
          claim_generator: "RealReel-capture/1.2.3 c2pa-rs/0.13.0",
          title: "img.jpg",
          format: "image/jpeg",
          signature_info: { issuer: "CN=RealReel Issuing CA", common_name: "RealReel-Device-Key", alg: "Es256", time: "2026-05-14T10:30:00Z" },
          assertions: [
            { label: "org.realreel.capture", data: { capturerUuid: "00000000-0000-0000-0000-000000000000", deviceManufacturer: "Apple" } },
            ...heavyReVerify,
          ],
        },
        stage2: {
          label: "stage2",
          claim_generator: "RealReel-upload/1.2.3 c2pa-rs/0.13.0",
          title: "img.jpg",
          format: "image/jpeg",
          signature_info: { issuer: "CN=RealReel Issuing CA", common_name: "RealReel-Device-Key", alg: "Es256", time: "2026-05-14T10:30:05Z" },
          assertions: [
            { label: "org.realreel.upload", data: { deviceManufacturer: "Apple", appVersion: "1.2.3" } },
            { label: "c2pa.actions", data: { actions: [{ action: "c2pa.resized" }, { action: "c2pa.transcoded" }] } },
            { label: "stds.exif", data: { "tiff:Make": "Apple", "tiff:Model": "iPhone 15 Pro", "exif:FNumber": "1.78" } },
            ...heavyReVerify,
          ],
          ingredients: [{ title: "img.jpg", format: "image/jpeg", relationship: "parentOf", active_manifest: "stage1" }],
        },
      },
      validation_status: [],
    };
    const json = JSON.stringify(sanitizeManifestStore(typical, "realreel"));
    // The dropped categories leave no trace...
    expect(json).not.toContain("c2pa.hash.");
    expect(json).not.toContain("c2pa.time-stamp");
    expect(json).not.toContain("play_integrity");
    // ...and the kept shape stays compact despite the ~20 KB of dropped input.
    expect(json.length).toBeLessThan(2048);
  });
});
