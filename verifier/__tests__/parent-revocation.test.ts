// enforceParentRevocationStatus (src/profiles/_shared.ts): the positive-answer
// rule over synthetic Reader JSON — the store of the second, OCSP-on read the
// profile requests for a wrap whose capture source declares responders. c2pa-rs files a wrapped capture's OCSP
// codes under the ingredient assertion that references it, so the capture's
// row is found by ingredientAssertionURI — never by position — and the active
// manifest's own OCSP codes (always `inaccessible`: RealReel's responder is
// off the allow-list) are ignored. Only the `success` bucket is evidence: a
// stapled response, which anyone assembling the upload can write into the
// COSE unprotected header, files `notRevoked` as `informational`. The `url`
// of the notRevoked / revoked / unknown entries is the literal
// "OCSP_RESPONSE"; `inaccessible` carries the signature URI.

import { describe, it, expect } from "vitest";

import { enforceParentRevocationStatus } from "../src/profiles/_shared.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";
import type { ManifestStoreShape } from "../src/c2pa-shape.js";
import type { ResolvedTrustSource } from "../src/trust/dispatcher.js";

const CAPTURE = "urn:c2pa:capture";
const ACTIVE = "urn:c2pa:active";
const CAPTURE_URI = `self#jumbf=/c2pa/${ACTIVE}/c2pa.assertions/c2pa.ingredient.v3`;

const NOT_REVOKED = "signingCredential.ocsp.notRevoked";
const INACCESSIBLE = "signingCredential.ocsp.inaccessible";

const PIXEL: ResolvedTrustSource = {
  id: "pixel",
  name: "Google Pixel",
  profile: "wrap_parent_only",
  revocation: { ocsp_hosts: ["http://c2pa-ocsp.pki.goog"] },
};
const REALREEL: ResolvedTrustSource = { id: "realreel", name: "RealReel", profile: "realreel" };

type Delta = NonNullable<
  NonNullable<ManifestStoreShape["validation_results"]>["ingredientDeltas"]
>[number];
type Bucket = "success" | "informational" | "failure";

function delta(uri: string, codes: Partial<Record<Bucket, string[]>> = {}): Delta {
  const entries = (bucket: Bucket) =>
    (codes[bucket] ?? []).map((code) => ({
      code,
      url: code === INACCESSIBLE ? `self#jumbf=/c2pa/${CAPTURE}/c2pa.signature` : "OCSP_RESPONSE",
    }));
  return {
    ingredientAssertionURI: uri,
    validationDeltas: {
      success: entries("success"),
      informational: entries("informational"),
      failure: entries("failure"),
    },
  };
}

/** Stage 2 (active) wrapping the capture directly, as pixel-uploaded.jpg. */
function store(deltas: Delta[]): ManifestStoreShape {
  return {
    active_manifest: ACTIVE,
    manifests: {
      [CAPTURE]: { label: CAPTURE, ingredients: [] },
      [ACTIVE]: {
        label: ACTIVE,
        ingredients: [
          { label: "c2pa.ingredient.v3", relationship: "parentOf", active_manifest: CAPTURE },
        ],
      },
    },
    validation_results: {
      activeManifest: {
        informational: [{ code: INACCESSIBLE, url: `self#jumbf=/c2pa/${ACTIVE}/c2pa.signature` }],
      },
      ingredientDeltas: deltas,
    },
  };
}

const capture = (s: ManifestStoreShape) => s.manifests![CAPTURE]!;

function thrownBy(fn: () => void): VerifyError | null {
  try {
    fn();
    return null;
  } catch (e) {
    expect(e).toBeInstanceOf(VerifyError);
    return e as VerifyError;
  }
}

describe("enforceParentRevocationStatus", () => {
  it("passes on the responder's notRevoked answer under the capture's ingredient assertion", () => {
    const s = store([delta(CAPTURE_URI, { success: [NOT_REVOKED] })]);
    expect(() => enforceParentRevocationStatus(s, capture(s), PIXEL)).not.toThrow();
  });

  it("rejects VERIFIER_UNAVAILABLE when the responder was inaccessible, naming the bucket and code seen", () => {
    const s = store([delta(CAPTURE_URI, { informational: [INACCESSIBLE] })]);
    const err = thrownBy(() => enforceParentRevocationStatus(s, capture(s), PIXEL));
    expect(err?.code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
    expect(err?.detail).toContain(`informational:${INACCESSIBLE}`);
    expect(err?.detail).toContain("'pixel'");
    expect(err?.category).toBe("ocsp");
  });

  it("a notRevoked outside the success bucket is not evidence (a stapled response files as informational)", () => {
    for (const bucket of ["informational", "failure"] as const) {
      const s = store([delta(CAPTURE_URI, { [bucket]: [NOT_REVOKED] })]);
      const err = thrownBy(() => enforceParentRevocationStatus(s, capture(s), PIXEL));
      expect(err?.code, bucket).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
      expect(err?.detail, bucket).toContain(`${bucket}:${NOT_REVOKED}`);
    }
  });

  it("rejects when no OCSP code reached the capture at all", () => {
    for (const s of [store([delta(CAPTURE_URI)]), store([])]) {
      const err = thrownBy(() => enforceParentRevocationStatus(s, capture(s), PIXEL));
      expect(err?.code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
      expect(err?.detail).toContain("none");
    }
  });

  it("locates the capture's row by assertion URI, not by position", () => {
    const other = `self#jumbf=/c2pa/${ACTIVE}/c2pa.assertions/c2pa.ingredient.v3__1`;
    // notRevoked at index 0 belongs to another ingredient: no evidence for the capture.
    const wrongRow = store([
      delta(other, { success: [NOT_REVOKED] }),
      delta(CAPTURE_URI, { informational: [INACCESSIBLE] }),
    ]);
    expect(
      thrownBy(() => enforceParentRevocationStatus(wrongRow, capture(wrongRow), PIXEL))?.code,
    ).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
    // notRevoked at index 1 under the capture's URI is.
    const rightRow = store([
      delta(other, { informational: [INACCESSIBLE] }),
      delta(CAPTURE_URI, { success: [NOT_REVOKED] }),
    ]);
    expect(() =>
      enforceParentRevocationStatus(rightRow, capture(rightRow), PIXEL),
    ).not.toThrow();
  });

  it("never reads the active manifest's own OCSP codes as evidence for the capture", () => {
    const s = store([]);
    s.validation_results!.activeManifest = { success: [{ code: NOT_REVOKED, url: "OCSP_RESPONSE" }] };
    expect(
      thrownBy(() => enforceParentRevocationStatus(s, capture(s), PIXEL))?.code,
    ).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
  });

  it("ignores an ingredient entry that references the capture but carries no label", () => {
    const s = store([delta(CAPTURE_URI, { success: [NOT_REVOKED] })]);
    delete s.manifests![ACTIVE]!.ingredients![0]!.label;
    expect(
      thrownBy(() => enforceParentRevocationStatus(s, capture(s), PIXEL))?.detail,
    ).toContain("none");
  });

  it("follows the drained chain: the capture's row hangs off the Update Manifest's ingredient", () => {
    // Stage 2 → timestamp Update Manifest → capture: the ingredient assertion
    // that references the capture lives in the Update Manifest.
    const UPDATE = "urn:c2pa:update";
    const s: ManifestStoreShape = {
      active_manifest: ACTIVE,
      manifests: {
        [CAPTURE]: { label: CAPTURE, ingredients: [] },
        [UPDATE]: {
          label: UPDATE,
          ingredients: [
            { label: "c2pa.ingredient.v3", relationship: "parentOf", active_manifest: CAPTURE },
          ],
        },
        [ACTIVE]: {
          label: ACTIVE,
          ingredients: [
            { label: "c2pa.ingredient.v3", relationship: "parentOf", active_manifest: UPDATE },
          ],
        },
      },
      validation_results: {
        ingredientDeltas: [
          delta(CAPTURE_URI, { informational: [INACCESSIBLE] }),
          delta(`self#jumbf=/c2pa/${UPDATE}/c2pa.assertions/c2pa.ingredient.v3`, {
            success: [NOT_REVOKED],
          }),
        ],
      },
    };
    expect(() =>
      enforceParentRevocationStatus(s, s.manifests![CAPTURE]!, PIXEL),
    ).not.toThrow();
  });

  it("skips sources without revocation", () => {
    const s = store([]);
    expect(() => enforceParentRevocationStatus(s, capture(s), REALREEL)).not.toThrow();
  });
});
