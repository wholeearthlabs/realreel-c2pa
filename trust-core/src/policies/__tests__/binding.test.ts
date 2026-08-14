// Unit tests for the hard-binding policy.
//
// Shape provenance, stated precisely: the CLEAN recorded-report shape is
// pinned end-to-end by the verifier's real committed fixtures
// (realreel-uploaded / pixel-uploaded / realreel-drained all carry
// `validation_results.activeManifest` with `assertion.dataHash.match` and
// pass the gate in the verifier suites). The NEGATIVE shapes below are
// hand-written literals — no committed tampered fixture exists. That is
// safe because acceptance never rests on failure-shape recognition: the
// positive-proof requirement (match_missing) rejects any tampered record
// regardless of how its failure bucket is spelled.

import { describe, it, expect } from "vitest";

import {
  findBindingFailureCodes,
  findContentTamperCodes,
  findRecordedBindingViolation,
} from "../binding.js";
import type {
  ManifestShape,
  ManifestStoreShape,
  ValidationResultsBucketsShape,
  ValidationStatusEntryShape,
} from "../../shapes/manifest.js";

const CAPTURE_LABEL = "urn:c2pa:capture";

function capture(): ManifestShape {
  return { label: CAPTURE_LABEL, assertions: [{ label: "c2pa.actions.v2" }] };
}

/** A store shaped like a Stage-2 wrap: active manifest with one parentOf
 * ingredient referencing the capture, carrying the given recorded report. */
function wrapStore(
  recorded: ValidationResultsBucketsShape | undefined,
): ManifestStoreShape {
  return {
    active_manifest: "urn:c2pa:upload",
    manifests: {
      "urn:c2pa:upload": {
        label: "urn:c2pa:upload",
        ingredients: [
          {
            active_manifest: CAPTURE_LABEL,
            relationship: "parentOf",
            ...(recorded ? { validation_results: { activeManifest: recorded } } : {}),
          },
        ],
      },
      [CAPTURE_LABEL]: capture(),
    },
  };
}

describe("findBindingFailureCodes", () => {
  it("keeps only binding-family codes with explicit failure suffixes", () => {
    expect(
      findBindingFailureCodes([
        { code: "assertion.bmffHash.mismatch" },
        { code: "assertion.dataHash.malformed" },
        { code: "assertion.dataHash.match" },
        { code: "signingCredential.untrusted" },
        { code: "claimSignature.mismatch" }, // not binding-family
      ]),
    ).toEqual(["assertion.bmffHash.mismatch", "assertion.dataHash.malformed"]);
  });

  it("does NOT flag advisory binding codes — every Pixel photo records additionalExclusionsPresent", () => {
    // Regression pin: pixel-uploaded.jpg's recorded report carries
    // `assertion.dataHash.additionalExclusionsPresent` (informational).
    // Sweeping it in would hard-reject every Pixel photo if a future SDK
    // re-buckets it.
    expect(
      findBindingFailureCodes([
        { code: "assertion.dataHash.additionalExclusionsPresent" },
      ]),
    ).toEqual([]);
  });

  it("tolerates undefined and malformed entries", () => {
    expect(findBindingFailureCodes(undefined)).toEqual([]);
    expect(
      findBindingFailureCodes([
        null as unknown as ValidationStatusEntryShape,
        {} as ValidationStatusEntryShape,
        { code: "assertion.dataHash.mismatch" },
      ]),
    ).toEqual(["assertion.dataHash.mismatch"]);
  });
});

describe("findContentTamperCodes", () => {
  it("denylists anchorless-reader noise and flags everything else (unknown codes fail closed)", () => {
    expect(
      findContentTamperCodes([
        // noise — never tamper
        { code: "signingCredential.untrusted" },
        { code: "signingCredential.expired" },
        { code: "timeStamp.untrusted" },
        { code: "assertion.dataHash.additionalExclusionsPresent" },
        { code: "assertion.dataHash.match" },
        // tamper
        { code: "assertion.bmffHash.mismatch" },
        { code: "claimSignature.mismatch" },
        { code: "assertion.hashedURI.mismatch" },
        // unknown / future codes must fail closed
        { code: "claim.hardBindings.missing" },
        { code: "claimSignature.missing" },
      ]),
    ).toEqual([
      "assertion.bmffHash.mismatch",
      "claimSignature.mismatch",
      "assertion.hashedURI.mismatch",
      "claim.hardBindings.missing",
      "claimSignature.missing",
    ]);
  });

  it("tolerates undefined and malformed entries", () => {
    expect(findContentTamperCodes(undefined)).toEqual([]);
    expect(
      findContentTamperCodes([
        null as unknown as ValidationStatusEntryShape,
        { code: "timeStamp.mismatch" },
      ]),
    ).toEqual(["timeStamp.mismatch"]);
  });
});

describe("findRecordedBindingViolation", () => {
  const CLEAN: ValidationResultsBucketsShape = {
    success: [
      { code: "claimSignature.validated" },
      { code: "assertion.dataHash.match" },
    ],
    informational: [],
    failure: [],
  };

  it("accepts a clean recorded report", () => {
    expect(
      findRecordedBindingViolation(wrapStore(CLEAN), CAPTURE_LABEL),
    ).toBeNull();
  });

  it("accepts any binding family's positive proof", () => {
    // The genuine SDK picks the family (data for JPEG, bmff for MP4/HEIC).
    // Requiring a specific family would buy nothing against a hostile build
    // (it authors the record either way) and would hard-reject BMFF stills.
    expect(
      findRecordedBindingViolation(
        wrapStore({ success: [{ code: "assertion.bmffHash.match" }], failure: [] }),
        CAPTURE_LABEL,
      ),
    ).toBeNull();
  });

  it("rejects a recorded binding failure, surfacing the codes", () => {
    expect(
      findRecordedBindingViolation(
        wrapStore({
          success: [],
          failure: [{ code: "assertion.dataHash.mismatch" }],
        }),
        CAPTURE_LABEL,
      ),
    ).toMatchObject({
      reason: "binding_failure",
      failureCodes: ["assertion.dataHash.mismatch"],
    });
  });

  it("ignores recorded trust-config failures (cert/TSA) — the server chain-validates those itself", () => {
    expect(
      findRecordedBindingViolation(
        wrapStore({
          success: [{ code: "assertion.dataHash.match" }],
          failure: [
            { code: "signingCredential.untrusted" },
            { code: "signingCredential.expired" },
          ],
        }),
        CAPTURE_LABEL,
      ),
    ).toBeNull();
  });

  it("fails closed when the report is absent entirely", () => {
    expect(
      findRecordedBindingViolation(wrapStore(undefined), CAPTURE_LABEL),
    ).toMatchObject({ reason: "no_recorded_results" });
  });

  it("fails closed when the positive proof is missing — the backstop for unknown failure spellings", () => {
    expect(
      findRecordedBindingViolation(
        wrapStore({ success: [{ code: "claimSignature.validated" }], failure: [] }),
        CAPTURE_LABEL,
      ),
    ).toMatchObject({ reason: "match_missing" });
  });

  it("an advisory binding note alongside the positive proof does not reject", () => {
    expect(
      findRecordedBindingViolation(
        wrapStore({
          success: [{ code: "assertion.dataHash.match" }],
          informational: [
            { code: "assertion.dataHash.additionalExclusionsPresent" },
          ],
          failure: [],
        }),
        CAPTURE_LABEL,
      ),
    ).toBeNull();
  });

  it("judges the UM-held record in the interposed offline-TSA chain shape", () => {
    // Stage-2 → Update Manifest → capture: the entry referencing the capture
    // lives on the UM; Stage-2's own entry references the UM.
    const store: ManifestStoreShape = {
      active_manifest: "urn:c2pa:upload",
      manifests: {
        "urn:c2pa:upload": {
          label: "urn:c2pa:upload",
          ingredients: [{ active_manifest: "urn:c2pa:um", relationship: "parentOf" }],
        },
        "urn:c2pa:um": {
          label: "urn:c2pa:um",
          assertions: [{ label: "c2pa.time-stamp" }],
          ingredients: [
            {
              active_manifest: CAPTURE_LABEL,
              relationship: "parentOf",
              validation_results: {
                activeManifest: {
                  success: [],
                  failure: [{ code: "assertion.bmffHash.mismatch" }],
                },
              },
            },
          ],
        },
        [CAPTURE_LABEL]: capture(),
      },
    };
    expect(
      findRecordedBindingViolation(store, CAPTURE_LABEL),
    ).toMatchObject({ reason: "binding_failure" });
  });

  it("fails closed when nothing references the capture at all", () => {
    const store: ManifestStoreShape = {
      manifests: { [CAPTURE_LABEL]: capture() },
    };
    expect(
      findRecordedBindingViolation(store, CAPTURE_LABEL),
    ).toMatchObject({ reason: "no_recorded_results" });
  });
});
