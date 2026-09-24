// Pins the verifier's c2pa settings contract. Every request c2pa-rs makes
// passes core.allowed_network_hosts — the OCSP responders trust-sources.yaml
// declares, or an empty list that blocks all of them — and remote_manifest_fetch
// stays off: an asset with no embedded manifest but a remote-manifest reference
// would otherwise make Reader.fromAsset GET an attacker-chosen URL from inside
// the verifier's network. ocsp_fetch turns on only with network revocation
// enabled AND a declared responder, so tests, local runs and the conformance
// harness never leave the machine. This guards a refactor silently dropping a
// flag with green CI.

import { describe, it, expect } from "vitest";

import { buildVerifierSettings, fetchesOcsp } from "../src/verify.js";
import type { TrustConfig } from "../src/trust/types.js";

const NO_HOSTS: TrustConfig = {
  sources: [],
  tsaRoots: [],
  loadedIds: new Set(),
  trustAnchorsBundle:
    "-----BEGIN CERTIFICATE-----\nMIIBdummy\n-----END CERTIFICATE-----\n",
  ocspHosts: [],
};
const PIXEL_HOSTS: TrustConfig = {
  ...NO_HOSTS,
  ocspHosts: ["http://c2pa-ocsp.pki.goog"],
};

interface SettingsDocument {
  core: { allowed_network_hosts: string[] };
  verify: Record<string, unknown>;
  trust: Record<string, unknown>;
}
const parse = (json: string): SettingsDocument => JSON.parse(json) as SettingsDocument;

describe("verifier c2pa settings", () => {
  it("offline by default: an empty allow-list blocks every c2pa-rs request; no remote-manifest or OCSP fetch", () => {
    const settings = parse(buildVerifierSettings(NO_HOSTS));
    expect(settings.core).toEqual({ allowed_network_hosts: [] });
    expect(settings.verify.remote_manifest_fetch).toBe(false);
    expect(settings.verify.ocsp_fetch).toBe(false);
  });

  it("the allow-list is always the declared responder set, even with network revocation off", () => {
    const settings = parse(buildVerifierSettings(PIXEL_HOSTS));
    expect(settings.core.allowed_network_hosts).toEqual(["http://c2pa-ocsp.pki.goog"]);
    expect(settings.verify.ocsp_fetch).toBe(false);
  });

  it("ocsp_fetch needs network revocation enabled AND a declared responder", () => {
    expect(parse(buildVerifierSettings(PIXEL_HOSTS, true)).verify.ocsp_fetch).toBe(true);
    expect(parse(buildVerifierSettings(NO_HOSTS, true)).verify.ocsp_fetch).toBe(false);
    expect(fetchesOcsp(PIXEL_HOSTS, true)).toBe(true);
    expect(fetchesOcsp(PIXEL_HOSTS, false)).toBe(false);
    expect(fetchesOcsp(NO_HOSTS, true)).toBe(false);
  });

  it("remote-manifest fetch stays off with network revocation on", () => {
    const settings = parse(buildVerifierSettings(PIXEL_HOSTS, true));
    expect(settings.verify.remote_manifest_fetch).toBe(false);
    expect(settings.core.allowed_network_hosts).toEqual(["http://c2pa-ocsp.pki.goog"]);
  });

  it("still pins timestamp-trust verification on", () => {
    expect(parse(buildVerifierSettings(NO_HOSTS)).verify.verify_timestamp_trust).toBe(true);
  });

  it("pins the trust block: our anchors, not the system trust list", () => {
    // The camelCase->snake_case conversion must hold or the anchors get dropped
    // (every manifest would then report signingCredential.untrusted).
    const settings = parse(buildVerifierSettings(NO_HOSTS));
    expect(settings.trust.trust_anchors).toContain("BEGIN CERTIFICATE");
    expect(settings.trust.verify_trust_list).toBe(false);
  });
});
