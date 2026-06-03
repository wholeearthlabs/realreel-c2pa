// Pins the verifier's "no outbound fetch during verify" hardening. c2pa-rs
// defaults remote_manifest_fetch ON, so without the flag an asset carrying only
// a remote-manifest reference (no embedded manifest) would make Reader.fromAsset
// issue an outbound GET to an attacker-chosen URL — SSRF from inside the
// verifier's network. ocsp_fetch is the same class of vector (responder URL from
// the cert AIA). RealReel ingests EMBEDDED manifests only and does revocation via
// the datastore, so disabling both is lossless. This test guards against a
// refactor silently dropping a flag and reopening the vector with green CI.

import { describe, it, expect } from "vitest";

import { buildVerifierSettings } from "../src/verify.js";
import type { TrustConfig } from "../src/trust/types.js";

const TRUST_CONFIG: TrustConfig = {
  sources: [],
  tsaRoots: [],
  loadedIds: new Set(),
  trustAnchorsBundle:
    "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n",
};

describe("verifier c2pa settings (no-outbound-fetch hardening)", () => {
  const settings = JSON.parse(buildVerifierSettings(TRUST_CONFIG));

  it("makes no outbound fetch during verify (remote-manifest + OCSP)", () => {
    expect(settings.verify.remote_manifest_fetch).toBe(false);
    expect(settings.verify.ocsp_fetch).toBe(false);
  });

  it("still pins timestamp-trust verification on", () => {
    expect(settings.verify.verify_timestamp_trust).toBe(true);
  });

  it("pins the trust block: our anchors, not the system trust list", () => {
    // The camelCase->snake_case conversion must hold or the anchors get dropped
    // (every manifest would then report signingCredential.untrusted).
    expect(settings.trust.trust_anchors).toContain("BEGIN CERTIFICATE");
    expect(settings.trust.verify_trust_list).toBe(false);
  });
});
