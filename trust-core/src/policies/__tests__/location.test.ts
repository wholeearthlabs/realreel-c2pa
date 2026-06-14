import { describe, it, expect } from "vitest";
import {
  LOCATION_LEVELS,
  isLocationLevel,
} from "../location.js";

describe("isLocationLevel", () => {
  it("accepts the three declared levels", () => {
    for (const level of LOCATION_LEVELS) {
      expect(isLocationLevel(level)).toBe(true);
    }
  });

  it("rejects anything else", () => {
    for (const x of ["", "PRECISE", "city", 0, 1, null, undefined, {}, ["none"]]) {
      expect(isLocationLevel(x)).toBe(false);
    }
  });

  it("pins the level set so a change here is deliberate", () => {
    expect([...LOCATION_LEVELS]).toEqual(["none", "general", "precise"]);
  });
});
