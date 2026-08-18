// Correctness of the crJSON conformance harness ITSELF (src/harness/crjson.ts):
// that each Program input reaches the validator, that the output is the spec's
// crJSON, that it is deterministic, and that the deployed engine agrees with
// it. Deliberately separate from crjson-goldens.test.ts, which USES the
// harness as regression infrastructure — if the harness were wrong, goldens
// would bake the bug in and every golden test would agree with it.
//
// Needs c2patool + faketime on PATH (skips otherwise; CI sets
// CRJSON_HARNESS_REQUIRED=1 so it can't skip there — see _support.ts).

import { describe, it, expect } from "vitest";
import {
  compareWithEngine,
  CrjsonHarnessError,
  ENGINE_IDENTITY,
  harnessSettings,
  mimeTypeForAsset,
  parseValidationTime,
  pemCertificates,
  runCrjsonHarness,
  toFaketime,
  type CrjsonDocument,
} from "../../src/harness/crjson.js";
import { buildVerifierSettings } from "../../src/verify.js";
import { AT, fixture, fixturesReady, harnessAvailable, schemaErrors, TRUST_LISTS, TSA_LISTS } from "./_support.js";

// ── Pure pieces (no external tools) ─────────────────────────────────────────

describe("harness inputs", () => {
  it("counts PEM certificates and tolerates an empty bundle", () => {
    expect(pemCertificates(TRUST_LISTS.production)).toHaveLength(3);
    expect(pemCertificates(TSA_LISTS.production).length).toBeGreaterThan(10);
    expect(pemCertificates("")).toEqual([]);
    expect(pemCertificates("not a pem")).toEqual([]);
  });

  it("builds the settings through the verifier's own builder, with the two lists pooled", () => {
    const settings = JSON.parse(harnessSettings(TRUST_LISTS.production, TSA_LISTS.production)) as {
      trust: { trust_anchors: string };
      verify: Record<string, unknown>;
    };
    const anchors = pemCertificates(settings.trust.trust_anchors);
    expect(anchors).toEqual([...pemCertificates(TRUST_LISTS.production), ...pemCertificates(TSA_LISTS.production)]);
    // Byte-identical to what verify.ts hands c2pa-node for the same bundle —
    // the verifier's no-network + time-stamp-trust flags ride along.
    expect(harnessSettings(TRUST_LISTS.production, TSA_LISTS.production)).toBe(
      buildVerifierSettings({ trustAnchorsBundle: anchors.join("\n") + "\n" }),
    );
    expect(settings.verify).toMatchObject({
      verify_timestamp_trust: true,
      remote_manifest_fetch: false,
      ocsp_fetch: false,
    });
  });

  it("omits the anchors key when both lists are empty (c2pa-rs rejects an empty anchor string)", () => {
    const settings = JSON.parse(harnessSettings("", "")) as { trust: Record<string, unknown> };
    expect("trust_anchors" in settings.trust).toBe(false);
  });

  it("parses the validation time strictly as RFC 3339 with an offset", () => {
    expect(parseValidationTime("2026-08-17T00:00:00Z").toISOString()).toBe("2026-08-17T00:00:00.000Z");
    expect(parseValidationTime("2026-08-17t01:30:00.5+02:00").toISOString()).toBe("2026-08-16T23:30:00.500Z");
    expect(parseValidationTime("2016-12-31T23:59:60Z").toISOString()).toBe("2016-12-31T23:59:59.000Z"); // leap second
    // No offset → would be local time under new Date(); refused instead.
    for (const bad of ["2026-08-17T00:00:00", "08/17/2026", "2026-08-17", "2026-13-01T00:00:00Z", ""]) {
      expect(() => parseValidationTime(bad), bad).toThrow(expect.objectContaining({ kind: "input" }));
    }
  });

  it("formats the validation instant as libfaketime's frozen-clock syntax, UTC, second precision", () => {
    expect(toFaketime(new Date("2031-01-01T00:00:00Z"))).toBe("2031-01-01 00:00:00");
    expect(toFaketime(new Date("2026-08-17T23:59:59.999-01:00"))).toBe("2026-08-18 00:59:59");
    expect(() => toFaketime(new Date("nope"))).toThrow(CrjsonHarnessError);
  });

  it("maps asset extensions to the MIME type c2pa-node needs, null when unknown", () => {
    expect(mimeTypeForAsset("a.JPG")).toBe("image/jpeg");
    expect(mimeTypeForAsset("clip.mov")).toBe("video/quicktime");
    expect(mimeTypeForAsset("mystery.xyz")).toBeNull();
  });
});

describe("compareWithEngine", () => {
  const status = (code: string, url = "u") => ({ code, url, explanation: "x" });
  const doc = (active: string, failure: ReturnType<typeof status>[], deltaUri?: string): CrjsonDocument =>
    ({
      "@context": {},
      jsonGenerator: { name: "t", version: "0.0.0" },
      manifests: [
        {
          label: active,
          assertions: {},
          signature: {},
          validationResults: { success: [status("claimSignature.validated")], informational: [], failure, specVersion: "2.3.0", validationTime: "t" },
          ...(deltaUri
            ? { ingredientDeltas: [{ ingredientAssertionURI: deltaUri, validationDeltas: { success: [status("ingredient.manifest.validated")], informational: [], failure: [] } }] }
            : {}),
        },
      ],
    }) as CrjsonDocument;
  const engine = (active: string, failure: ReturnType<typeof status>[], deltaUri?: string) => ({
    found: true,
    activeManifest: active,
    validationResults: {
      activeManifest: { success: [{ code: "claimSignature.validated", url: "u", explanation: "different wording" }], informational: [], failure },
      ingredientDeltas: deltaUri ? [{ ingredientAssertionURI: deltaUri, validationDeltas: { success: [status("ingredient.manifest.validated")], informational: [], failure: [] } }] : [],
    },
  });

  it("agrees when codes and urls match, ignoring explanation wording", () => {
    expect(compareWithEngine(doc("m1", [], "d1"), engine("m1", [], "d1"))).toEqual([]);
  });

  it("reports a differing active manifest, differing failure set, and a one-sided delta", () => {
    expect(compareWithEngine(doc("m1", []), engine("m2", []))).toEqual([expect.stringMatching(/active manifest: crJSON m1 vs engine m2/)]);
    expect(compareWithEngine(doc("m1", [status("signingCredential.expired")]), engine("m1", []))).toEqual([
      expect.stringMatching(/activeManifest\.failure: crJSON \[signingCredential\.expired @ u\] vs engine \[\]/),
    ]);
    expect(compareWithEngine(doc("m1", [], "d1"), engine("m1", []))).toEqual([expect.stringMatching(/ingredientDeltas: crJSON-only \[d1 .*\] engine-only \[\]/)]);
  });

  it("flags a delta hung off the wrong manifest even when the status multiset matches", () => {
    const uri = "self#jumbf=/c2pa/m2/c2pa.assertions/c2pa.ingredient.v3";
    expect(compareWithEngine(doc("m1", [], uri), engine("m1", [], uri))).toEqual([expect.stringMatching(/placed under manifest m1/)]);
  });

  it("treats 'engine found nothing' as agreement only for an empty document", () => {
    expect(compareWithEngine({ "@context": {}, manifests: [], jsonGenerator: { name: "t", version: "0.0.0" } }, { found: false })).toEqual([]);
    expect(compareWithEngine(doc("m1", []), { found: false })).toEqual([expect.stringMatching(/engine found no manifest store/)]);
  });
});

// ── End to end (c2patool + faketime + c2pa-node) ────────────────────────────

const V2 = "v2-hierarchy-signed.jpg";
const REALREEL = "realreel-uploaded.jpg";
const DRAINED = "realreel-drained.jpg";
const PIXEL_WRAP = "pixel-uploaded.jpg";
const PIXEL_OG = "pixel-og.jpg";
const PIXEL_EDITED = "pixel-edited.jpg";
const NO_MANIFEST = "synthetic-usercomment.jpg";
const ALL_SIGNED = [V2, REALREEL, DRAINED, PIXEL_WRAP, PIXEL_OG];

const ready = await fixturesReady([...ALL_SIGNED, PIXEL_EDITED, NO_MANIFEST]);

const production = { trustListPem: TRUST_LISTS.production, tsaTrustListPem: TSA_LISTS.production };
const codes = (doc: CrjsonDocument, group: "failure" | "informational", manifest = 0) =>
  doc.manifests[manifest].validationResults[group].map((e) => e.code);

describe.skipIf(!harnessAvailable || !ready)("runCrjsonHarness (end to end)", () => {
  it("emits spec-2.4 crJSON for every signed fixture, and the deployed engine agrees with each", () => {
    for (const name of ALL_SIGNED) {
      const run = runCrjsonHarness({ assetPath: fixture(name), ...production, validationTime: AT.baseline });
      // realreel-drained.jpg predates the v0.2 cutover: its Update Manifest
      // gathers every assertion, so claim.v2.created_assertions is empty —
      // schema-invalid. Post-cutover builds create them; drop this special
      // case when the fixture regeneration makes it fail with [].
      expect(schemaErrors(run.crjson), name).toEqual(
        name === DRAINED ? ["/manifests/1/claim.v2/created_assertions must NOT have fewer than 1 items {\"limit\":1}"] : [],
      );
      expect(run.crjson.manifests.length, name).toBeGreaterThan(0);
      // The active manifest leads (§3.4) and carries the injected instant.
      expect(run.crjson.manifests[0].validationResults.validationTime, name).toBe("2026-08-18T00:00:00+00:00");
      expect(run.record.engineAgreement, name).toEqual({ checked: true, agree: true, differences: [] });
      expect(run.record.engine).toEqual(ENGINE_IDENTITY);
      expect(run.record.validator.crjsonOrigin).toBe("c2patool");
      expect(run.record.inputs.validationTime).toBe("2026-08-18T00:00:00Z");
    }
  });

  it("pins the validator/engine pair: same c2pa-rs minor, versions as recorded in README", () => {
    // Bump these together with ci.yml, the Dockerfile stage and the README
    // table; the cross-check only means "same engine" while the minor matches.
    const run = runCrjsonHarness({ assetPath: fixture(V2), ...production, validationTime: AT.baseline });
    expect(run.record.validator.c2patool).toBe("c2patool 0.27.15");
    expect(run.record.validator.c2paRs).toBe("0.90.15");
    expect(ENGINE_IDENTITY).toEqual({ package: "@contentauth/c2pa-node", version: "0.8.3", c2paRs: "0.90.5" });
    expect(run.record.validator.c2paRs!.split(".").slice(0, 2)).toEqual(ENGINE_IDENTITY.c2paRs!.split(".").slice(0, 2));
    // c2pa-rs's own statement of the spec it validated against (a constant in
    // its crJSON serializer) — not ours to rewrite; noticed here if it moves.
    for (const m of run.crjson.manifests) expect(m.validationResults.specVersion).toBe("2.3.0");
  });

  it("is byte-deterministic for the same inputs (frozen clock)", () => {
    const a = runCrjsonHarness({ assetPath: fixture(DRAINED), ...production, validationTime: AT.baseline });
    const b = runCrjsonHarness({ assetPath: fixture(DRAINED), ...production, validationTime: AT.baseline });
    expect(a.crjsonText).toBe(b.crjsonText);
    expect(a.record.inputs.asset.sha256).toBe(b.record.inputs.asset.sha256);
  });

  it("validation time reaches the validator: an untimestamped leaf expires when the clock passes notAfter", () => {
    // v2-hierarchy-signed.jpg: no time-stamp, leaf notAfter 2026-10-25.
    const inputs = { assetPath: fixture(V2), trustListPem: TRUST_LISTS.v2TestRoot, tsaTrustListPem: TSA_LISTS.production };
    const now = runCrjsonHarness({ ...inputs, validationTime: AT.baseline });
    const later = runCrjsonHarness({ ...inputs, validationTime: AT.future });
    expect(codes(now.crjson, "failure")).toEqual([]);
    expect(codes(later.crjson, "failure")).toEqual(["signingCredential.expired"]);
    expect(later.crjson.manifests[0].validationResults.validationTime).toBe("2031-01-01T00:00:00+00:00");
    // …and the deployed engine moved with it.
    expect(later.record.engineAgreement.agree).toBe(true);
  });

  it("validation time does NOT expire a time-stamped signature (TSA-anchored validity)", () => {
    // pixel-og.jpg: leaf notAfter 2026-05-26, Google-TSA countersigned —
    // valid at both instants because validity is judged at the time-stamp.
    for (const at of [AT.baseline, AT.future]) {
      const run = runCrjsonHarness({ assetPath: fixture(PIXEL_OG), ...production, validationTime: at });
      expect(codes(run.crjson, "failure")).toEqual([]);
      expect(run.record.engineVerdict?.validationState).toBe("Trusted");
    }
  });

  it("the C2PA trust list reaches the validator: the same asset is trusted or not by the supplied anchors", () => {
    const withRoot = runCrjsonHarness({ assetPath: fixture(V2), trustListPem: TRUST_LISTS.v2TestRoot, tsaTrustListPem: TSA_LISTS.production, validationTime: AT.baseline });
    const withoutRoot = runCrjsonHarness({ assetPath: fixture(V2), ...production, validationTime: AT.baseline });
    expect(codes(withRoot.crjson, "failure")).toEqual([]);
    expect(codes(withoutRoot.crjson, "failure")).toEqual(["signingCredential.untrusted"]);
  });

  it("wrap mode: the two lists are ONE anchor pool — a root present only in the TSA list still anchors a claim signer", () => {
    // "Google C2PA Root CA G3" signs both the Pixel camera ICA and Google's
    // TSA ICAs and is on the official C2PA TSA Trust List; c2pa-rs keeps one
    // anchor pool (trust/types.ts "RESIDUAL"). So dropping the Pixel root
    // from the C2PA list changes nothing while the TSA list carries it; only
    // dropping both sends the wrapped parent to the clock — past its leaf's
    // notAfter (2026-05-26), hence expired. The policy layer, not the engine,
    // scopes anchor roles; this pins the raw engine.
    const wrap = runCrjsonHarness({ assetPath: fixture(PIXEL_WRAP), ...production, validationTime: AT.baseline });
    const noPixelRoot = runCrjsonHarness({ assetPath: fixture(PIXEL_WRAP), trustListPem: TRUST_LISTS.productionWithoutPixel, tsaTrustListPem: TSA_LISTS.production, validationTime: AT.baseline });
    const noPixelNoTsa = runCrjsonHarness({ assetPath: fixture(PIXEL_WRAP), trustListPem: TRUST_LISTS.productionWithoutPixel, tsaTrustListPem: TSA_LISTS.empty, validationTime: AT.baseline });
    for (const run of [wrap, noPixelRoot]) {
      expect(codes(run.crjson, "failure")).toEqual([]);
      expect(codes(run.crjson, "failure", 1)).toEqual([]);
      expect(run.crjson.manifests[1].validationResults.success.map((e) => e.code)).toContain("signingCredential.trusted");
    }
    expect(codes(noPixelNoTsa.crjson, "failure")).toEqual([]); // RealReel active: own root, still listed
    expect(codes(noPixelNoTsa.crjson, "failure", 1)).toEqual(["signingCredential.expired"]);
    expect(noPixelNoTsa.record.engineVerdict?.validationState).toBe("Invalid");
    expect(noPixelNoTsa.record.engineAgreement.agree).toBe(true);
  });

  it("the TSA trust list reaches the validator: an empty list leaves the time-stamp untrusted", () => {
    const withTsa = runCrjsonHarness({ assetPath: fixture(REALREEL), ...production, validationTime: AT.baseline });
    const noTsa = runCrjsonHarness({ assetPath: fixture(REALREEL), trustListPem: TRUST_LISTS.production, tsaTrustListPem: TSA_LISTS.empty, validationTime: AT.baseline });
    expect(codes(withTsa.crjson, "informational")).not.toContain("timeStamp.untrusted");
    expect(codes(noTsa.crjson, "informational")).toContain("timeStamp.untrusted");
    expect(noTsa.record.inputs.tsaTrustList.certificates).toBe(0);
    expect(noTsa.record.engineAgreement.agree).toBe(true);
  });

  it("two empty lists trust nothing", () => {
    const run = runCrjsonHarness({ assetPath: fixture(REALREEL), trustListPem: TRUST_LISTS.empty, tsaTrustListPem: TSA_LISTS.empty, validationTime: AT.baseline });
    expect(codes(run.crjson, "failure")).toEqual(["signingCredential.untrusted"]);
    expect(codes(run.crjson, "informational")).toContain("timeStamp.untrusted");
    expect(run.record.engineAgreement.agree).toBe(true);
  });

  it("an asset with no manifest store yields the empty document under the harness's own name", () => {
    const run = runCrjsonHarness({ assetPath: fixture(NO_MANIFEST), ...production, validationTime: AT.baseline });
    expect(run.crjson.manifests).toEqual([]);
    expect(run.crjson.jsonGenerator.name).toMatch(/crjson-harness/);
    expect(schemaErrors(run.crjson)).toEqual([]);
    expect(run.record.validator.c2paRs).toBeNull();
    expect(run.record.validator.crjsonOrigin).toBe("harness-empty-document");
    expect(run.record.validator.stderr).toMatch(/No claim found/);
    expect(run.record.engineVerdict).toEqual({ found: false, activeManifest: null, validationState: null });
    expect(run.record.engineAgreement.agree).toBe(true);
  });

  it("KNOWN LIMITATION (c2pa-rs ≤ 0.90.15): the crJSON serializer aborts on an ingredient v3 that breaks the CDDL co-presence rule", () => {
    // pixel-edited.jpg's ingredient has activeManifest without
    // validationResults; c2pa-rs's Ingredient serializer Errs and crjson.rs
    // propagates it, so c2patool exits instead of emitting `{}` for that
    // assertion (crJSON §3.6.1). The verifier still validates the file
    // (verify-pixel.test.ts). When upstream fixes it this fails: delete it
    // and add the fixture to the goldens.
    expect(() => runCrjsonHarness({ assetPath: fixture(PIXEL_EDITED), ...production, validationTime: AT.baseline })).toThrow(
      expect.objectContaining({ kind: "validator-failed", detail: expect.stringMatching(/must both be present or absent/) }),
    );
  });

  it("can skip the engine cross-check, and says so in the record", () => {
    const run = runCrjsonHarness({ assetPath: fixture(REALREEL), ...production, validationTime: AT.baseline }, { crossCheck: false });
    expect(run.record.engineAgreement.checked).toBe(false);
    expect(run.record.engine).toBeNull();
    expect(run.record.engineVerdict).toBeNull();
  });

  it("refuses a trust list that has text but no PEM certificate, rather than treating it as empty", () => {
    expect(() =>
      runCrjsonHarness({ assetPath: fixture(REALREEL), trustListPem: "-----BEGIN TRUSTED CERTIFICATE-----\nMIIB\n-----END TRUSTED CERTIFICATE-----\n", tsaTrustListPem: TSA_LISTS.production, validationTime: AT.baseline }),
    ).toThrow(expect.objectContaining({ kind: "input", message: expect.stringMatching(/trust list contains no PEM/) }));
  });

  it("surfaces environment problems as typed errors", () => {
    expect(() => runCrjsonHarness({ assetPath: fixture(REALREEL), ...production, validationTime: AT.baseline }, { c2patool: "/nonexistent/c2patool" })).toThrow(
      expect.objectContaining({ kind: "c2patool-missing" }),
    );
    expect(() => runCrjsonHarness({ assetPath: fixture(REALREEL), ...production, validationTime: AT.baseline }, { faketime: "/nonexistent/faketime" })).toThrow(
      expect.objectContaining({ kind: "faketime-missing" }),
    );
    expect(() => runCrjsonHarness({ assetPath: fixture("does-not-exist.jpg"), ...production, validationTime: AT.baseline })).toThrow(
      expect.objectContaining({ kind: "input" }),
    );
  });
});
