// extractActionEntries is the single actions walker every policy builds on
// (allowlist, content extent, created digitalSourceType, generative-AI
// provenance). These tests pin the parts the policies rely on beyond the
// name list: nested `related` sub-actions are flattened in after their
// parent, digitalSourceType rides along verbatim, and malformed shapes are
// skipped rather than thrown on.

import { describe, it, expect } from "vitest";

import {
  extractActionEntries,
  extractCreatedDigitalSourceType,
  findDisallowedActions,
  CAPTURE_ALLOWED_ACTIONS,
} from "../actions.js";
import type { ManifestShape } from "../../shapes/manifest.js";

const DST = "http://cv.iptc.org/newscodes/digitalsourcetype/";

function withActions(actions: unknown): ManifestShape {
  return { assertions: [{ label: "c2pa.actions.v2", data: { actions } }] };
}

describe("extractActionEntries — related sub-actions", () => {
  it("flattens related actions in document order after their parent", () => {
    const entries = extractActionEntries(
      withActions([
        {
          action: "c2pa.edited",
          related: [
            { action: "c2pa.filtered", digitalSourceType: `${DST}trainedAlgorithmicMedia` },
            { action: "c2pa.cropped", related: [{ action: "c2pa.resized" }] },
          ],
        },
        { action: "c2pa.converted" },
      ]),
    );
    expect(entries.map((e) => e.action)).toEqual([
      "c2pa.edited",
      "c2pa.filtered",
      "c2pa.cropped",
      "c2pa.resized",
      "c2pa.converted",
    ]);
    expect(entries[1]?.digitalSourceType).toBe(`${DST}trainedAlgorithmicMedia`);
  });

  it("makes a related action visible to the allowlist", () => {
    // An edit hidden under a permitted parent is still an edit.
    const violation = findDisallowedActions(
      withActions([{ action: "c2pa.created", related: [{ action: "c2pa.cropped" }] }]),
      CAPTURE_ALLOWED_ACTIONS,
    );
    expect(violation?.disallowed).toEqual(["c2pa.cropped"]);
  });

  it("stops descending past the nesting bound", () => {
    let deepest: { action: string; related?: unknown } = { action: "l6" };
    for (const name of ["l5", "l4", "l3", "l2", "l1", "l0"]) {
      deepest = { action: name, related: [deepest] };
    }
    const names = extractActionEntries(withActions([deepest])).map((e) => e.action);
    expect(names).toEqual(["l0", "l1", "l2", "l3", "l4"]);
  });
});

describe("extractActionEntries — digitalSourceType and malformed shapes", () => {
  it("carries digitalSourceType verbatim and omits it when absent or non-string", () => {
    const entries = extractActionEntries(
      withActions([
        { action: "c2pa.created", digitalSourceType: `${DST}digitalCapture` },
        { action: "c2pa.opened" },
        { action: "c2pa.edited", digitalSourceType: 7 },
        { action: "c2pa.resized", digitalSourceType: "" },
      ]),
    );
    expect(entries.map((e) => e.digitalSourceType)).toEqual([
      `${DST}digitalCapture`,
      undefined,
      undefined,
      undefined,
    ]);
  });

  it("skips null assertions, null entries, non-object entries, and a non-array actions field", () => {
    const manifest = {
      assertions: [
        null,
        { label: "c2pa.actions.v2", data: { actions: "nope" } },
        { label: "c2pa.actions.v2", data: null },
        { label: "c2pa.actions.v2", data: 3 },
        { label: "c2pa.actions.v2", data: { actions: [null, 7, "x", { action: "" }, { action: "c2pa.created" }] } },
      ],
    } as unknown as ManifestShape;
    expect(extractActionEntries(manifest).map((e) => e.action)).toEqual(["c2pa.created"]);
  });

  it("extractCreatedDigitalSourceType reads the first c2pa.created only", () => {
    expect(
      extractCreatedDigitalSourceType(
        withActions([
          { action: "c2pa.opened" },
          { action: "c2pa.created" },
          { action: "c2pa.created", digitalSourceType: `${DST}digitalCapture` },
        ]),
      ),
    ).toBeNull();
    expect(
      extractCreatedDigitalSourceType(
        withActions([{ action: "c2pa.created", digitalSourceType: `${DST}computationalCapture` }]),
      ),
    ).toBe(`${DST}computationalCapture`);
    expect(extractCreatedDigitalSourceType({ assertions: [] })).toBeNull();
  });
});
