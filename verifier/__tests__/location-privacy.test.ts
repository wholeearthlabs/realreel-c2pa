// Unit tests for the location-privacy gate — pure over a DerivedMetadata (the
// bytes-vs-assertion presence matrix). The byte-probe that produces bytesHadGps
// is pinned against real fixtures in derive-metadata.test.ts.

import { describe, it, expect } from "vitest";
import { enforceLocationPrivacy } from "../src/location-privacy.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";
import type { DerivedMetadata } from "../src/derive-metadata.js";

const base: DerivedMetadata = {
  entries: [],
  latitude: null,
  longitude: null,
  location: null,
  metadataType: "exif",
  bytesHadGps: false,
};
const make = (o: Partial<DerivedMetadata>): DerivedMetadata => ({ ...base, ...o });

describe("enforceLocationPrivacy — bytes-vs-assertion GPS presence matrix", () => {
  it("passes when neither side carries GPS (non-precise, working)", () => {
    expect(enforceLocationPrivacy(make({}))).toEqual({ displayLeak: false });
  });

  it("passes when both sides carry GPS (precise, working)", () => {
    expect(
      enforceLocationPrivacy(make({ bytesHadGps: true, latitude: 34.28, longitude: -119.28 })),
    ).toEqual({ displayLeak: false });
  });

  it("REJECTS (Direction 1) when bytes carry GPS the assertion lacks — the durable file leak", () => {
    let thrown: unknown;
    try {
      enforceLocationPrivacy(make({ bytesHadGps: true }));
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(VerifyError);
    expect((thrown as VerifyError).code).toBe(VerifyErrorCode.LOCATION_PRIVACY_VIOLATION);
  });

  it("SIGNALS, not rejects (Direction 2) when the assertion carries GPS the bytes lack", () => {
    // Display leak OR a legit precise upload whose EXIF dropped — never a reject.
    expect(
      enforceLocationPrivacy(make({ latitude: 34.28, longitude: -119.28 })),
    ).toEqual({ displayLeak: true });
  });
});
