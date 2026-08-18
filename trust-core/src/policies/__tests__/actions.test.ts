// Unit tests for the action-allowlist policy. Pure-function tests — no
// network, no DB, no native modules. Lifted from the verifier-side suite
// (which had only end-to-end fixture coverage of these primitives via
// verify-realreel.test.ts); having them here means a future refactor of
// the pure logic surfaces here first, isolated from c2pa-rs noise.

import { describe, it, expect } from "vitest";

import {
  CAPTURE_ALLOWED_ACTIONS,
  REALREEL_UPLOAD_ALLOWED_ACTIONS,
  TRANSITIONAL_RETIRED_UPLOAD_ACTIONS,
  extractManifestActions,
  extractCreatedDigitalSourceType,
  findDisallowedActions,
} from "../actions.js";
import type { ManifestShape } from "../../shapes/manifest.js";

function manifestWithActions(actions: string[]): ManifestShape {
  return {
    assertions: [
      {
        label: "c2pa.actions.v2",
        data: { actions: actions.map((action) => ({ action })) },
      },
    ],
  };
}

describe("allowlist constants — surface contract", () => {
  it("CAPTURE_ALLOWED_ACTIONS is exactly { c2pa.created }", () => {
    // Pinned because expanding the capture allowlist would weaken the
    // "fresh capture only" guarantee. If a future PEM legitimately needs
    // a different action on capture (e.g., c2pa.placed for synthetic
    // origins), that's a deliberate policy decision and should land with
    // a docs update — not a silent expansion.
    expect([...CAPTURE_ALLOWED_ACTIONS].sort()).toEqual(["c2pa.created"]);
  });

  it("REALREEL_UPLOAD_ALLOWED_ACTIONS matches the documented Stage 2 vocabulary", () => {
    // Pins the exact Stage-2 vocabulary so any allowlist edit is deliberate.
    // Nothing imports the native Stage2Action union — that union, this pin,
    // and the allowlist are kept in sync by hand.
    // c2pa.cropped is deliberately absent (a declared crop could conceal
    // recapture edges); re-adding it is a policy decision, not drift.
    expect([...REALREEL_UPLOAD_ALLOWED_ACTIONS].sort()).toEqual(
      [
        "c2pa.opened",
        "c2pa.orientation",
        "c2pa.resized.proportional",
        "c2pa.transcoded",
        "c2pa.trimmed",
        "c2pa.redacted",
        "c2pa.edited.metadata",
        // Transitional, pinned again below so removing them is deliberate.
        "c2pa.rotated",
        "c2pa.resized",
      ].sort(),
    );
  });

  it("accepts exactly two retired spellings, transitionally", () => {
    // Delete this case with the set itself once no pre-cutover build uploads.
    expect([...TRANSITIONAL_RETIRED_UPLOAD_ACTIONS].sort()).toEqual(
      ["c2pa.resized", "c2pa.rotated"].sort(),
    );
  });
});

describe("extractManifestActions", () => {
  it("returns the action list for a single c2pa.actions.v2 assertion", () => {
    expect(
      extractManifestActions(manifestWithActions(["c2pa.created"])),
    ).toEqual(["c2pa.created"]);
  });

  it("also reads the legacy c2pa.actions label", () => {
    const manifest: ManifestShape = {
      assertions: [
        {
          label: "c2pa.actions",
          data: { actions: [{ action: "c2pa.created" }] },
        },
      ],
    };
    expect(extractManifestActions(manifest)).toEqual(["c2pa.created"]);
  });

  it("unions actions across multiple c2pa.actions assertions", () => {
    // Spec-discouraged but technically possible — a malicious or buggy
    // emitter could split actions across two assertions to evade a
    // first-match-wins reader. We must surface every action.
    const manifest: ManifestShape = {
      assertions: [
        { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.opened" }] } },
        { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.edited" }] } },
      ],
    };
    expect(extractManifestActions(manifest).sort()).toEqual([
      "c2pa.edited",
      "c2pa.opened",
    ]);
  });

  it("returns an empty array when no actions assertion is present", () => {
    expect(extractManifestActions({ assertions: [] })).toEqual([]);
    expect(extractManifestActions({})).toEqual([]);
  });

  it("survives malformed shapes: non-array `actions`, missing `action`, empty strings", () => {
    const manifest: ManifestShape = {
      assertions: [
        // non-array actions
        { label: "c2pa.actions.v2", data: { actions: "c2pa.opened" as unknown } },
        // entry without an `action` field
        { label: "c2pa.actions.v2", data: { actions: [{}] } },
        // empty-string action — filtered
        { label: "c2pa.actions.v2", data: { actions: [{ action: "" }] } },
        // non-string action — filtered
        { label: "c2pa.actions.v2", data: { actions: [{ action: 42 }] } },
        // valid one mixed in
        { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } },
      ],
    };
    expect(extractManifestActions(manifest)).toEqual(["c2pa.created"]);
  });

  it("ignores non-actions assertion labels", () => {
    const manifest: ManifestShape = {
      assertions: [
        { label: "c2pa.hash.data", data: { exclusions: [] } },
        { label: "org.realreel.capture", data: { capturerUuid: "u" } },
      ],
    };
    expect(extractManifestActions(manifest)).toEqual([]);
  });
});

describe("findDisallowedActions", () => {
  it("returns null when every action is allowed (CAPTURE allowlist, c2pa.created only)", () => {
    expect(
      findDisallowedActions(
        manifestWithActions(["c2pa.created"]),
        CAPTURE_ALLOWED_ACTIONS,
      ),
    ).toBeNull();
  });

  it("returns null when every action is allowed (UPLOAD allowlist, multiple actions)", () => {
    expect(
      findDisallowedActions(
        manifestWithActions(["c2pa.opened", "c2pa.resized.proportional", "c2pa.transcoded"]),
        REALREEL_UPLOAD_ALLOWED_ACTIONS,
      ),
    ).toBeNull();
  });

  it("returns the disallowed action when one action is out of the allowlist", () => {
    expect(
      findDisallowedActions(
        manifestWithActions(["c2pa.created", "c2pa.color_adjustments"]),
        CAPTURE_ALLOWED_ACTIONS,
      ),
    ).toEqual({ disallowed: ["c2pa.color_adjustments"] });
  });

  it("collects every disallowed action, not just the first", () => {
    // Sentry triage relies on seeing the complete picture, not just one.
    const result = findDisallowedActions(
      manifestWithActions([
        "c2pa.opened",
        "c2pa.color_adjustments",
        "c2pa.filtered",
        "c2pa.transcoded",
      ]),
      REALREEL_UPLOAD_ALLOWED_ACTIONS,
    );
    expect(result).not.toBeNull();
    expect(result!.disallowed.sort()).toEqual([
      "c2pa.color_adjustments",
      "c2pa.filtered",
    ]);
  });

  it("deduplicates repeated disallowed actions", () => {
    const result = findDisallowedActions(
      manifestWithActions([
        "c2pa.created",
        "c2pa.color_adjustments",
        "c2pa.color_adjustments",
        "c2pa.color_adjustments",
      ]),
      CAPTURE_ALLOWED_ACTIONS,
    );
    expect(result).toEqual({ disallowed: ["c2pa.color_adjustments"] });
  });

  it("returns null for a manifest with no actions assertion at all", () => {
    // Empty actions = trivially allowed by every allowlist. Whether
    // the caller should ALSO require an actions assertion to be present
    // is a separate policy (the verifier doesn't enforce that today;
    // c2pa-rs validation would catch a manifest without actions).
    expect(
      findDisallowedActions({ assertions: [] }, CAPTURE_ALLOWED_ACTIONS),
    ).toBeNull();
  });
});

describe("extractCreatedDigitalSourceType", () => {
  const DIGITAL_CAPTURE = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";
  const COMPUTATIONAL = "http://cv.iptc.org/newscodes/digitalsourcetype/computationalCapture";

  it("returns the created action's digitalSourceType verbatim", () => {
    const manifest: ManifestShape = {
      assertions: [
        {
          label: "c2pa.actions.v2",
          data: { actions: [{ action: "c2pa.created", digitalSourceType: COMPUTATIONAL }] },
        },
      ],
    };
    expect(extractCreatedDigitalSourceType(manifest)).toBe(COMPUTATIONAL);
  });

  it("ignores digitalSourceType on other actions and reads only c2pa.created", () => {
    const manifest: ManifestShape = {
      assertions: [
        {
          label: "c2pa.actions.v2",
          data: {
            actions: [
              { action: "c2pa.orientation", digitalSourceType: COMPUTATIONAL },
              { action: "c2pa.created", digitalSourceType: DIGITAL_CAPTURE },
            ],
          },
        },
      ],
    };
    expect(extractCreatedDigitalSourceType(manifest)).toBe(DIGITAL_CAPTURE);
  });

  it("returns null when there is no created action, or it carries no / an empty value", () => {
    expect(extractCreatedDigitalSourceType(manifestWithActions(["c2pa.opened"]))).toBeNull();
    expect(extractCreatedDigitalSourceType(manifestWithActions(["c2pa.created"]))).toBeNull();
    const empty: ManifestShape = {
      assertions: [
        { label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created", digitalSourceType: "" }] } },
      ],
    };
    expect(extractCreatedDigitalSourceType(empty)).toBeNull();
    expect(extractCreatedDigitalSourceType({ assertions: [] })).toBeNull();
  });
});
