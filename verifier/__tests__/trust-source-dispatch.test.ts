// Trust-source dispatcher tests.
//
// The dispatcher maps a chain-validated signature to its trust source. The
// match criteria mirror @realreel/c2pa-trust-core's findTrustedIssuer —
// covered by trust-core/src/trust-list/__tests__/trusted-issuers.test.ts.
// These tests cover the verifier side:
//
//   1. Routing returns the source id when the issuer matches AND that
//      source has a loaded PEM.
//   2. Routing returns null when the issuer matches a TRUSTED_ISSUERS
//      entry whose PEM is NOT loaded (the YAML declared it but root_cert
//      was missing on disk — loader skips it and the dispatcher refuses
//      to route).
//   3. Empty string + no-match return null.
//   4. A lookalike organization does NOT route: chain validation accepts
//      any pooled anchor, TSA roots included, so the exact match is what
//      scopes a cert to a source.

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
    verification_profile: id.startsWith("realreel")
      ? "realreel"
      : "wrap_parent_only",
    rootCertPem: "",
  };
}

function configWithLoaded(...ids: string[]): TrustConfig {
  return {
    sources: ids.map(source),
    tsaRoots: [],
    trustAnchorsBundle: "",
    loadedIds: new Set(ids),
    ocspHosts: [],
  };
}

// c2pa-rs surfaces signature_info.issuer as the leaf's subject O alone
// (verify-pixel.test.ts pins "Google LLC" for the Pixel fixture), so these
// tests use bare organizations.

describe("identifyTrustSource — routing", () => {
  it("routes v2-hierarchy leaves (subject O) to 'realreel'", () => {
    expect(
      identifyTrustSource(
        "Whole Earth Labs LLC",
        "RealReel iOS",
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBe("realreel");
  });

  it("routes legacy-hierarchy leaves nowhere", () => {
    expect(
      identifyTrustSource(
        "RealReel",
        "RealReel-Device-Key",
        configWithLoaded("realreel", "pixel"),
      ),
    ).toBeNull();
  });

  it("matches RealReel even with null common_name (the entry is unopinionated)", () => {
    // The RealReel entry has no commonNameMatch — routes on issuer alone.
    expect(
      identifyTrustSource(
        "Whole Earth Labs LLC",
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
    // A hypothetical future Google C2PA program (Workspace export, Drive,
    // etc.) signed as "Google LLC" must NOT route to the Pixel profile
    // just because the organization matches. The commonNameMatch pin on
    // the Pixel entry is the second gate.
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

  it("routes ProofMode leaves under either pinned app CN to 'proofmode'", () => {
    for (const cn of ["Proofmode for iOS", "Proofmode for Android"]) {
      expect(
        identifyTrustSource(
          "Proofmode Reality Systems LLC",
          cn,
          configWithLoaded("realreel", "pixel", "proofmode"),
        ),
      ).toBe("proofmode");
    }
  });

  it("rejects a ProofMode leaf outside the pinned app CNs", () => {
    // Same gate as the client's findTrustedIssuer (shared matchesCommonName).
    for (const cn of ["Proofmode Desktop", null, undefined]) {
      expect(
        identifyTrustSource(
          "Proofmode Reality Systems LLC",
          cn,
          configWithLoaded("realreel", "pixel", "proofmode"),
        ),
      ).toBeNull();
    }
  });

  it("returns null when no TRUSTED_ISSUERS entry matches the issuer string", () => {
    expect(
      identifyTrustSource(
        "Other Inc",
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
  // shared organization match: a TRUSTED_ISSUERS entry whose PEM didn't
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

  it("still routes a loaded source when another is unloaded", () => {
    expect(
      identifyTrustSource(
        "Google LLC",
        "Pixel Camera",
        configWithLoaded("pixel"),
      ),
    ).toBe("pixel");
  });

  it("returns null when no sources are loaded at all", () => {
    expect(
      identifyTrustSource(
        "Whole Earth Labs LLC",
        null,
        configWithLoaded(),
      ),
    ).toBeNull();
  });
});

// -------- Routing safety: exact organization match --------
//
// A chain-valid cert can come from any pooled anchor, including the public
// CAs on the C2PA TSA Trust List, which issue real claim-signing certs to
// organizations they vet. So routing must not admit an organization that
// merely contains a trusted one.

describe("identifyTrustSource — exact organization match", () => {
  it("does not route an organization that contains a trusted one", () => {
    const all = configWithLoaded("realreel", "pixel", "proofmode");
    for (const [issuer, cn] of [
      ["New Whole Earth Labs LLC", "RealReel iOS"],
      ["RealReel Media LLC", null],
      ["RealReel Issuing CA Evil Twin", null],
      ["NotGoogle LLC", "Pixel Camera"],
      ["Proofmode Reality Systems LLC Europe", "Proofmode for iOS"],
    ] as const) {
      expect(identifyTrustSource(issuer, cn, all), issuer).toBeNull();
    }
  });
});
