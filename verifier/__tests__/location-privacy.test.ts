// Unit tests for the location-privacy gate — pure over (DerivedMetadata,
// declared level). Two layers compose (see location-privacy.ts):
//   - the declared-level check (a non-precise level forbids GPS in either
//     artifact), and
//   - the bytes-vs-assertion spine (arg-independent: Direction-1 reject,
//     Direction-2 signal).
// The byte-probe that produces bytesHadGps is pinned against real fixtures in
// derive-metadata.test.ts.

import { describe, it, expect } from "vitest";
import {
  enforceLocationPrivacy,
  type LocationLevel,
} from "../src/location-privacy.js";
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

// The four GPS-presence states the gate distinguishes.
const NEITHER = {};
const BYTES_ONLY = { bytesHadGps: true };
const ASSERTION_ONLY = { latitude: 34.28, longitude: -119.28 };
const BOTH = { bytesHadGps: true, latitude: 34.28, longitude: -119.28 };

function expectViolation(derived: DerivedMetadata, declared: LocationLevel) {
  let thrown: unknown;
  try {
    enforceLocationPrivacy(derived, declared);
  } catch (e) {
    thrown = e;
  }
  expect(thrown).toBeInstanceOf(VerifyError);
  expect((thrown as VerifyError).code).toBe(
    VerifyErrorCode.LOCATION_PRIVACY_VIOLATION,
  );
}

describe("enforceLocationPrivacy — precise: bytes-vs-assertion spine (arg-independent)", () => {
  it("passes when neither side carries GPS", () => {
    expect(enforceLocationPrivacy(make(NEITHER), "precise")).toEqual({
      displayLeak: false,
    });
  });

  it("passes when both sides carry GPS (precise, working)", () => {
    expect(enforceLocationPrivacy(make(BOTH), "precise")).toEqual({
      displayLeak: false,
    });
  });

  it("REJECTS (Direction 1) when bytes carry GPS the assertion lacks — the durable file leak", () => {
    expectViolation(make(BYTES_ONLY), "precise");
  });

  it("SIGNALS, not rejects (Direction 2) when the assertion carries GPS the bytes lack", () => {
    // Display leak OR a legit precise upload whose EXIF dropped — never a reject.
    expect(enforceLocationPrivacy(make(ASSERTION_ONLY), "precise")).toEqual({
      displayLeak: true,
    });
  });
});

describe("enforceLocationPrivacy — non-precise declared level forbids GPS in either artifact", () => {
  // "none" and "general" both mean "publish no coordinates" — general shares
  // only a coarse label, signed separately, never lat/lon. Identical here.
  for (const declared of ["none", "general"] as const) {
    describe(`declared = ${declared}`, () => {
      it("passes when neither side carries GPS (working strip)", () => {
        expect(enforceLocationPrivacy(make(NEITHER), declared)).toEqual({
          displayLeak: false,
        });
      });

      it("REJECTS when bytes carry GPS (strip failed — durable file leak)", () => {
        expectViolation(make(BYTES_ONLY), declared);
      });

      it("REJECTS when the assertion carries GPS — closes the spine's Direction-2 signal-only blind spot", () => {
        // The spine alone can only SIGNAL this (precise EXIF-drop is
        // indistinguishable). A non-precise declared level resolves the
        // ambiguity → it's an unambiguous manifest leak, so hard reject.
        expectViolation(make(ASSERTION_ONLY), declared);
      });

      it("REJECTS when both sides carry GPS — closes the correlated double-regression blind spot", () => {
        // Both paths leaking in lockstep reads as a consistent "precise" to the
        // spine and would pass; the declared level catches it.
        expectViolation(make(BOTH), declared);
      });
    });
  }
});
