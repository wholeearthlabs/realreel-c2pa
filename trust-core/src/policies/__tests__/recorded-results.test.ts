import { describe, it, expect } from "vitest";

import { findUnverifiedRecordedFailures } from "../recorded-results.js";
import type {
  ManifestStoreShape,
  ValidationResultsShape,
} from "../../shapes/manifest.js";

const HOLDER = "urn:c2pa:upload";
const PARENT = "urn:c2pa:capture";
const ING_LABEL = "c2pa.ingredient.v3";
const ING_URI = `self#jumbf=/c2pa/${HOLDER}/c2pa.assertions/${ING_LABEL}`;
const SIG = `self#jumbf=/c2pa/${PARENT}/c2pa.signature`;

const e = (...codes: string[]) => codes.map((code) => ({ code, url: SIG }));

/** One parentOf ingredient carrying `recorded`; `liveTrusted` adds the
 *  verifier's own signingCredential.trusted for that parent. */
function store(opts: {
  recorded?: ValidationResultsShape;
  legacyStatus?: { code: string }[];
  liveTrusted?: boolean;
  liveTrustedUrl?: string;
  ingredientLabel?: string;
}): ManifestStoreShape {
  return {
    active_manifest: HOLDER,
    manifests: {
      [HOLDER]: {
        label: HOLDER,
        ingredients: [
          {
            label: "ingredientLabel" in opts ? opts.ingredientLabel : ING_LABEL,
            active_manifest: PARENT,
            relationship: "parentOf",
            validation_results: opts.recorded,
            validation_status: opts.legacyStatus,
          },
        ],
      },
      [PARENT]: { label: PARENT, ingredients: [] },
    },
    validation_results: {
      ingredientDeltas: [
        {
          ingredientAssertionURI: ING_URI,
          validationDeltas: opts.liveTrusted
            ? { success: [{ code: "signingCredential.trusted", url: opts.liveTrustedUrl ?? SIG }] }
            : {},
        },
      ],
    },
  };
}

const codes = (s: ManifestStoreShape) =>
  findUnverifiedRecordedFailures(s).map((x) => x.code);

describe("findUnverifiedRecordedFailures", () => {
  it("passes a clean record", () => {
    const recorded = {
      activeManifest: {
        success: e("signingCredential.trusted", "claimSignature.validated", "assertion.dataHash.match"),
        informational: e("timeStamp.untrusted", "signingCredential.ocsp.skipped"),
      },
    };
    expect(codes(store({ recorded }))).toEqual([]);
  });

  it("returns a recorded untrusted the verifier doesn't clear", () => {
    const recorded = { activeManifest: { failure: e("signingCredential.untrusted") } };
    expect(codes(store({ recorded }))).toEqual(["signingCredential.untrusted"]);
  });

  it("clears untrusted and expired on a parent the verifier trusts", () => {
    const recorded = {
      activeManifest: { failure: e("signingCredential.untrusted", "signingCredential.expired") },
    };
    expect(codes(store({ recorded, liveTrusted: true }))).toEqual([]);
  });

  it("clears nothing else on a trusted parent", () => {
    const recorded = { activeManifest: { failure: e("claimSignature.mismatch") } };
    expect(codes(store({ recorded, liveTrusted: true }))).toEqual(["claimSignature.mismatch"]);
  });

  it("never clears a revoked or invalid credential on a trusted parent", () => {
    const recorded = {
      activeManifest: { failure: e("signingCredential.ocsp.revoked", "signingCredential.invalid") },
    };
    expect(codes(store({ recorded, liveTrusted: true }))).toEqual([
      "signingCredential.ocsp.revoked",
      "signingCredential.invalid",
    ]);
  });

  it("takes trust credit only from a live trusted for the parent itself", () => {
    const recorded = { activeManifest: { failure: e("signingCredential.untrusted") } };
    const other = "self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature";
    expect(codes(store({ recorded, liveTrusted: true, liveTrustedUrl: other }))).toEqual([
      "signingCredential.untrusted",
    ]);
  });

  it("clears only entries about the trusted parent itself", () => {
    const other = "self#jumbf=/c2pa/urn:c2pa:other/c2pa.signature";
    const recorded = {
      ingredientDeltas: [
        { validationDeltas: { failure: [{ code: "signingCredential.untrusted", url: other }] } },
      ],
    };
    expect(codes(store({ recorded, liveTrusted: true }))).toEqual(["signingCredential.untrusted"]);
  });

  it("judges the code, not the bucket", () => {
    const recorded = { activeManifest: { success: e("signingCredential.untrusted") } };
    expect(codes(store({ recorded }))).toEqual(["signingCredential.untrusted"]);
  });

  it("counts an unknown code as a failure", () => {
    const recorded = { activeManifest: { informational: e("vendor.unknown") } };
    expect(codes(store({ recorded }))).toEqual(["vendor.unknown"]);
  });

  it("leaves hard-binding codes to the binding gate", () => {
    const recorded = {
      activeManifest: { failure: e("assertion.dataHash.mismatch", "signingCredential.untrusted") },
    };
    expect(codes(store({ recorded }))).toEqual(["signingCredential.untrusted"]);
  });

  it("reads the report's own ingredient deltas", () => {
    const recorded = {
      ingredientDeltas: [{ validationDeltas: { failure: e("assertion.hashedURI.mismatch") } }],
    };
    expect(codes(store({ recorded }))).toEqual(["assertion.hashedURI.mismatch"]);
  });

  it("reads the pre-v3 validation_status", () => {
    expect(codes(store({ legacyStatus: [{ code: "signingCredential.untrusted" }] }))).toEqual([
      "signingCredential.untrusted",
    ]);
  });

  it("gives an unlabelled ingredient no trusted credit", () => {
    const recorded = { activeManifest: { failure: e("signingCredential.untrusted") } };
    expect(
      codes(store({ recorded, liveTrusted: true, ingredientLabel: undefined })),
    ).toEqual(["signingCredential.untrusted"]);
  });

  it("tolerates an empty store", () => {
    expect(findUnverifiedRecordedFailures({})).toEqual([]);
  });
});
