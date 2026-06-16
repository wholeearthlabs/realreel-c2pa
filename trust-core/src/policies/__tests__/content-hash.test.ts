// Unit tests for the per-content dedup identity policy. Pure-function tests —
// no network, no DB, no crypto (the verifier hashes the returned string; here
// we assert the canonical identity itself). The end-to-end fixture coverage
// (real captured-then-uploaded asset → 64-hex contentHash) lives in
// verifier/__tests__/verify-realreel.test.ts.

import { describe, it, expect } from "vitest";

import {
  buildContentIdentity,
  extractContentExtent,
} from "../content-hash.js";
import type { ManifestShape } from "../../shapes/manifest.js";

/** A capture (Stage-1) manifest with the given label. */
function capture(label: string): ManifestShape {
  return { label, assertions: [{ label: "c2pa.actions.v2", data: { actions: [{ action: "c2pa.created" }] } }] };
}

/** A Stage-2 (active) upload manifest carrying the given actions. */
function upload(actions: Array<{ action: string; parameters?: unknown }>): ManifestShape {
  return {
    label: "urn:c2pa:upload",
    assertions: [{ label: "c2pa.actions.v2", data: { actions } }],
  };
}

const PHOTO_UPLOAD = upload([
  { action: "c2pa.opened" },
  { action: "c2pa.resized", parameters: { width: 1080, height: 1440 } },
  { action: "c2pa.transcoded", parameters: { quality: 0.8, format: "image/jpeg" } },
]);

describe("extractContentExtent", () => {
  it("is empty for a photo upload (no trim/crop action)", () => {
    expect(extractContentExtent(PHOTO_UPLOAD)).toBe("");
  });

  it("is empty for an untrimmed video upload", () => {
    expect(extractContentExtent(upload([{ action: "c2pa.transcoded" }]))).toBe("");
  });

  it("captures the trim parameters for a trimmed video", () => {
    const extent = extractContentExtent(upload([{ action: "c2pa.trimmed", parameters: { start: 0, end: 60 } }]));
    expect(extent).toContain("c2pa.trimmed");
    expect(extent).toContain("60");
  });

  it("is independent of parameter key order (canonical)", () => {
    const a = extractContentExtent(upload([{ action: "c2pa.trimmed", parameters: { start: 1, end: 5 } }]));
    const b = extractContentExtent(upload([{ action: "c2pa.trimmed", parameters: { end: 5, start: 1 } }]));
    expect(a).toBe(b);
  });

  it("includes crop the same way (forward-compatible)", () => {
    const extent = extractContentExtent(upload([{ action: "c2pa.cropped", parameters: { x: 0, y: 0, width: 100, height: 100 } }]));
    expect(extent).toContain("c2pa.cropped");
  });

  it("ignores non-extent actions (resize/rotate/transcode/redact/opened)", () => {
    const extent = extractContentExtent(upload([
      { action: "c2pa.opened" },
      { action: "c2pa.rotated", parameters: { angle: 90 } },
      { action: "c2pa.resized", parameters: { width: 1, height: 1 } },
      { action: "c2pa.redacted", parameters: { redacted: "x" } },
    ]));
    expect(extent).toBe("");
  });

  it("survives malformed action shapes", () => {
    const manifest: ManifestShape = {
      assertions: [
        { label: "c2pa.actions.v2", data: { actions: "not-an-array" as unknown } },
        { label: "c2pa.actions.v2", data: { actions: [{}] } },
        { label: "c2pa.hash.data", data: { exclusions: [] } },
      ],
    };
    expect(extractContentExtent(manifest)).toBe("");
  });
});

describe("buildContentIdentity", () => {
  it("photo: identity is the capture label alone (no extent)", () => {
    expect(buildContentIdentity(capture("urn:c2pa:CAP"), PHOTO_UPLOAD)).toBe("urn:c2pa:CAP");
  });

  it("photo: same capture, different transforms → same identity (re-upload collides)", () => {
    const a = buildContentIdentity(capture("urn:c2pa:CAP"), upload([{ action: "c2pa.resized", parameters: { width: 1080, height: 1440 } }]));
    const b = buildContentIdentity(capture("urn:c2pa:CAP"), upload([{ action: "c2pa.resized", parameters: { width: 720, height: 960 } }, { action: "c2pa.rotated", parameters: { angle: 90 } }]));
    expect(a).toBe(b);
    expect(a).toBe("urn:c2pa:CAP");
  });

  it("different captures → different identity (no false dedup)", () => {
    expect(buildContentIdentity(capture("urn:c2pa:A"), PHOTO_UPLOAD)).not.toBe(
      buildContentIdentity(capture("urn:c2pa:B"), PHOTO_UPLOAD),
    );
  });

  it("video: same capture, DIFFERENT trims → different identity (both allowed)", () => {
    const trimA = buildContentIdentity(capture("urn:c2pa:VID"), upload([{ action: "c2pa.trimmed", parameters: { start: 0, end: 60 } }]));
    const trimB = buildContentIdentity(capture("urn:c2pa:VID"), upload([{ action: "c2pa.trimmed", parameters: { start: 60, end: 120 } }]));
    expect(trimA).not.toBe(trimB);
  });

  it("video: same capture, SAME trim → same identity (re-post collides)", () => {
    const a = buildContentIdentity(capture("urn:c2pa:VID"), upload([{ action: "c2pa.trimmed", parameters: { start: 0.5, end: 12.25 } }]));
    const b = buildContentIdentity(capture("urn:c2pa:VID"), upload([{ action: "c2pa.trimmed", parameters: { start: 0.5, end: 12.25 } }]));
    expect(a).toBe(b);
  });

  it("video: trim distinguishes otherwise-identical uploads of one capture", () => {
    const trimmed = buildContentIdentity(capture("urn:c2pa:VID"), upload([{ action: "c2pa.trimmed", parameters: { start: 0, end: 30 } }]));
    const whole = buildContentIdentity(capture("urn:c2pa:VID"), upload([{ action: "c2pa.transcoded" }]));
    expect(trimmed).not.toBe(whole);
    expect(whole).toBe("urn:c2pa:VID");
  });

  it("returns null when the capture manifest has no label (anomalous)", () => {
    expect(buildContentIdentity({ assertions: [] }, PHOTO_UPLOAD)).toBeNull();
    expect(buildContentIdentity({ label: "" }, PHOTO_UPLOAD)).toBeNull();
  });
});
