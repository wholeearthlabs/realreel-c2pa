// Trust-source dispatcher tests.
//
// The dispatcher's only job is routing-to-profile. The trust gate is
// c2pa-node chain validation (verify_trust_list: false + trust_anchors
// bundle), which runs before identifyTrustSource() is ever called.
//
// The substring-matching logic itself lives in
// @realreel/c2pa-trust-core's TRUSTED_ISSUERS — covered by
// trust-core/src/trust-list/__tests__/trusted-issuers.test.ts.
// These tests cover only the verifier-side concerns the dispatcher adds:
//
//   1. Routing returns the source id when the issuer matches AND that
//      source has a loaded PEM.
//   2. Routing returns null when the issuer matches a TRUSTED_ISSUERS
//      entry whose PEM is NOT loaded (the YAML declared it but root_cert
//      was missing on disk — loader skips it and the dispatcher refuses
//      to route).
//   3. Empty string + no-match return null.
//   4. The substring contract DOES match attacker-controlled strings —
//      the routing layer is permissive; trust comes from c2pa-node chain
//      validation, not from string matching. This regression test
//      documents the contract.

import { describe, it, expect } from "vitest";
import { identifyTrustSource } from "../src/trust/dispatcher.js";
import type { TrustConfig, TrustSource } from "../src/trust/types.js";

/** Build a minimal TrustConfig.sources entry for the given id. The
 *  dispatcher only reads `id`, so empty strings on the other fields are
 *  fine for these routing tests. */
function source(id: string): TrustSource {
  return {
    id,
    name: id,
    description: "",
    root_cert: `trust-sources/${id}/root.pem`,
    verification_profile: id === "realreel" ? "realreel" : "wrap_parent_only",
    rootCertPem: "",
  };
}

function configWithLoaded(...ids: string[]): TrustConfig {
  return {
    sources: ids.map(source),
    trustAnchorsBundle: "",
    loadedIds: new Set(ids),
  };
}

// Note on DN shape: these tests build synthetic full-DN issuer strings
// (e.g. "CN=RealReel Issuing CA, O=RealReel Inc, C=US") because that's
// the worst-case shape the substring contract has to handle. The real
// c2pa-rs output is usually narrower — verify-pixel.test.ts confirms
// signature_info.issuer === "Google LLC" (bare string) for the Pixel
// fixture. Whether c2pa-rs surfaces the full DN or just the O field
// varies by cert chain shape; the substring match works either way.

describe("identifyTrustSource — routing", () => {
  it("matches the RealReel substring inside a full DN (no common_name pin)", () => {
    expect(
      identifyTrustSource(
        "CN=RealReel Issuing CA, O=RealReel Inc, C=US",
        "RealReel-Device-Key",
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBe("realreel");
  });

  it("matches RealReel even with null common_name (entry is unopinionated)", () => {
    // RealReel has no commonNameMatch — routes on issuer alone.
    expect(
      identifyTrustSource(
        "CN=RealReel Issuing CA, O=RealReel Inc, C=US",
        null,
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBe("realreel");
  });

  it("matches Pixel only when issuer AND Pixel-Camera common_name both match", () => {
    expect(
      identifyTrustSource(
        "Google LLC",
        "Pixel Camera",
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBe("pixel");
  });

  it("rejects Google LLC issuer when common_name is not 'Pixel Camera' (H6 regression)", () => {
    // Closes the loose-substring window: a hypothetical future Google
    // C2PA program (Workspace export, Drive, etc.) signed as
    // "Google LLC" must NOT route to the Pixel profile just because
    // the issuer substring matches. The commonNameMatch pin on the
    // Pixel entry is the second gate.
    expect(
      identifyTrustSource(
        "Google LLC",
        "Workspace Export",
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBeNull();
    expect(
      identifyTrustSource(
        "Google LLC",
        null,
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBeNull();
    expect(
      identifyTrustSource(
        "Google LLC",
        undefined,
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBeNull();
  });

  it("returns null when no TRUSTED_ISSUERS entry matches the issuer string", () => {
    expect(
      identifyTrustSource(
        "CN=Some Other CA, O=Other, C=US",
        null,
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBeNull();
  });

  it("returns null on empty issuer", () => {
    expect(
      identifyTrustSource("", null, configWithLoaded("realreel", "pixel")),
    ).toBeNull();
  });
});

describe("identifyTrustSource — loaded-source filter", () => {
  // This is the verifier-side bit the dispatcher adds on top of the
  // shared substring match: a TRUSTED_ISSUERS entry whose PEM didn't
  // load at startup MUST NOT be routed to, otherwise c2pa-node would
  // have rejected the manifest at chain validation but we'd still claim
  // to recognize it.

  it("returns null when the matching issuer's source is not loaded", () => {
    // The shared TRUSTED_ISSUERS contains a 'pixel' entry, but this
    // config didn't load pixel's PEM (loader skipped it because the
    // root_cert path was missing on disk). The dispatcher refuses to
    // route Pixel-signed manifests under that condition.
    expect(
      identifyTrustSource(
        "Google LLC",
        "Pixel Camera",
        configWithLoaded("realreel"),
      ),
    ).toBeNull();
  });

  it("still routes the other source when only one is loaded", () => {
    expect(
      identifyTrustSource(
        "CN=RealReel Issuing CA, O=RealReel Inc, C=US",
        null,
        configWithLoaded("realreel"),
      ),
    ).toBe("realreel");
  });

  it("returns null when no sources are loaded at all", () => {
    expect(
      identifyTrustSource(
        "CN=RealReel Issuing CA, O=RealReel Inc, C=US",
        null,
        configWithLoaded(),
      ),
    ).toBeNull();
  });
});

// -------- Routing safety: substring-match-on-trusted-only --------
//
// These cases document the dispatcher's contract:
//
//   The substring match is for ROUTING, not TRUST. By the time
//   identifyTrustSource() runs, the manifest's cert chain has
//   already been validated against a trust anchor by c2pa-node.
//   An attacker can forge "CN=RealReel Issuing CA" in their own
//   cert string, but unless that cert chains to a root in our
//   trust_anchors bundle, c2pa-node rejects it before this code
//   runs. We don't unit-test the c2pa-node chain validation here
//   (that's c2pa-rs's job) — we just document the assumption.

describe("identifyTrustSource — substring contract", () => {
  it("regression: attacker-controlled 'contains' a known issuer still routes via dispatch; trust is c2pa-node's job", () => {
    // If c2pa-node validates this chain (it WON'T — attacker can't
    // forge a cert chaining to our root), the dispatcher would route
    // it to the realreel profile. This is intentional: trust comes
    // from chain validation, not from string matching.
    expect(
      identifyTrustSource(
        "CN=RealReel Issuing CA Evil Twin, O=Attacker",
        null,
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBe("realreel");
    // ← Confirms substring routing fires. Real-world protection: this
    //   only ever happens on certs c2pa-node already accepted, which
    //   means they chain to our root, which means they ARE our certs.
  });
});
