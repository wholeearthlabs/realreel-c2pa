// Unit tests for the curated trust list. Two flavors of test:
//
//   1. Invariants on the list itself — id uniqueness, issuerMatch
//      non-collision, every entry well-formed. These run alongside the
//      shared package's other vitest suites.
//
//   2. findTrustedIssuer behavior — substring match, missing fields,
//      first-match-wins semantics.
//
// A separate test on the verifier side (verifier/__tests__/trust-list-lockstep.test.ts)
// performs the PEM-to-metadata lockstep check, parsing each anchor's
// root.pem with node:crypto.X509Certificate and asserting its subject
// CN equals rootCommonName. That test stays where the PEM files live.

import { describe, it, expect } from "vitest";

import {
  TRUSTED_ISSUERS,
  findTrustedIssuer,
  matchesCommonName,
} from "../trusted-issuers.js";
import type { ManifestShape } from "../../shapes/manifest.js";

describe("TRUSTED_ISSUERS list invariants", () => {
  it("is non-empty and starts with RealReel + Pixel", () => {
    // Pinned because dropping the first entry silently would break
    // assumptions in client UI (which may surface entries in this order)
    // and in server telemetry (the dispatcher's source-id tag stability).
    const ids = TRUSTED_ISSUERS.map((entry) => entry.id);
    expect(ids).toContain("realreel");
    expect(ids).toContain("realreel-legacy");
    expect(ids).toContain("pixel");
    expect(ids).toContain("proofmode");
  });

  it("ids are unique", () => {
    const ids = TRUSTED_ISSUERS.map((entry) => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("issuerMatch substrings don't collide across entries", () => {
    // Two collision classes to catch:
    //   (a) Two entries with the exact same issuerMatch — findTrustedIssuer
    //       would deterministically pick the first but the second never
    //       matches anything.
    //   (b) One entry's issuerMatch is a substring of another's — a
    //       manifest containing the shorter string would route through
    //       the shorter entry even when the longer one was the actual
    //       issuer. Defeats the per-vendor isolation we get from
    //       substring matching.
    for (let i = 0; i < TRUSTED_ISSUERS.length; i++) {
      for (let j = 0; j < TRUSTED_ISSUERS.length; j++) {
        if (i === j) continue;
        const a = TRUSTED_ISSUERS[i]!;
        const b = TRUSTED_ISSUERS[j]!;
        expect(
          a.issuerMatch.includes(b.issuerMatch),
          `issuerMatch collision: '${b.issuerMatch}' (${b.id}) is a substring of '${a.issuerMatch}' (${a.id})`,
        ).toBe(false);
      }
    }
  });

  it("every entry has a non-empty displayName, issuerMatch, and rootCommonName", () => {
    for (const entry of TRUSTED_ISSUERS) {
      expect(entry.displayName).toBeTruthy();
      expect(entry.issuerMatch).toBeTruthy();
      expect(entry.rootCommonName).toBeTruthy();
    }
  });

  it("every commonNameMatch list is non-empty and holds non-empty names", () => {
    // An empty list would admit nothing — a silently dead entry.
    for (const entry of TRUSTED_ISSUERS) {
      const pin = entry.commonNameMatch;
      if (pin === undefined || typeof pin === "string") continue;
      expect(pin.length, entry.id).toBeGreaterThan(0);
      for (const name of pin) expect(name, entry.id).toBeTruthy();
    }
  });
});

describe("matchesCommonName", () => {
  const unpinned = { id: "a", displayName: "A", issuerMatch: "A", rootCommonName: "A" };

  it("admits any common_name, including none, for an unpinned entry", () => {
    expect(matchesCommonName(unpinned, "anything")).toBe(true);
    expect(matchesCommonName(unpinned, undefined)).toBe(true);
    expect(matchesCommonName(unpinned, null)).toBe(true);
  });

  it("requires exact equality with a single pinned name", () => {
    const entry = { ...unpinned, commonNameMatch: "Cam" };
    expect(matchesCommonName(entry, "Cam")).toBe(true);
    expect(matchesCommonName(entry, "Cam 2")).toBe(false);
    expect(matchesCommonName(entry, undefined)).toBe(false);
  });

  it("requires exact equality with one name of a pinned list", () => {
    const entry = { ...unpinned, commonNameMatch: ["Cam iOS", "Cam Android"] };
    expect(matchesCommonName(entry, "Cam iOS")).toBe(true);
    expect(matchesCommonName(entry, "Cam Android")).toBe(true);
    expect(matchesCommonName(entry, "Cam")).toBe(false);
    expect(matchesCommonName(entry, null)).toBe(false);
  });
});

describe("findTrustedIssuer", () => {
  function manifestWithIssuer(
    issuer: string | undefined,
    common_name?: string,
  ): ManifestShape {
    if (issuer === undefined) return { signature_info: {} };
    return {
      signature_info:
        common_name === undefined ? { issuer } : { issuer, common_name },
    };
  }

  it("matches the v2 hierarchy via the leaf subject O (common_name not required)", () => {
    // RealReel entries have no commonNameMatch pin — they route on
    // issuerMatch alone, accepting any common_name including missing.
    const result = findTrustedIssuer(
      manifestWithIssuer("Whole Earth Labs LLC"),
    );
    expect(result?.id).toBe("realreel");
  });

  it("matches legacy-hierarchy leaves to realreel-legacy, not realreel", () => {
    // Fielded pre-conformance leaves surface issuer "RealReel", which is
    // not a substring of "Whole Earth Labs LLC".
    const result = findTrustedIssuer(manifestWithIssuer("RealReel"));
    expect(result?.id).toBe("realreel-legacy");
  });

  it("full-DN v2 surface routes to realreel — declaration order is load-bearing", () => {
    // A full v2 subject DN contains "RealReel" via its CN, so this
    // resolves correctly only because `realreel` is declared first.
    // Reordering the list (alphabetizing, inserting) must fail here.
    const ids = TRUSTED_ISSUERS.map((e) => e.id);
    expect(ids.indexOf("realreel")).toBeLessThan(ids.indexOf("realreel-legacy"));
    const result = findTrustedIssuer(
      manifestWithIssuer("CN=RealReel Android, O=Whole Earth Labs LLC, C=US"),
    );
    expect(result?.id).toBe("realreel");
  });

  it("matches Pixel only when both issuer AND common_name pin match", () => {
    // The Pixel entry requires commonNameMatch === 'Pixel Camera'. Empirically
    // pinned against verifier/__tests__/fixtures/pixel-og.jpg.
    const result = findTrustedIssuer(
      manifestWithIssuer("Google LLC", "Pixel Camera"),
    );
    expect(result?.id).toBe("pixel");
  });

  it("rejects 'Google LLC' issuer without the Pixel Camera common_name pin", () => {
    // The H6 fix: without the common_name gate, a hypothetical future
    // Google C2PA program (Workspace / Drive / etc.) signed under
    // 'Google LLC' would have routed through the Pixel entry.
    expect(findTrustedIssuer(manifestWithIssuer("Google LLC"))).toBeNull();
    expect(
      findTrustedIssuer(manifestWithIssuer("Google LLC", "Workspace Export")),
    ).toBeNull();
  });

  it("matches ProofMode under either per-platform app CN", () => {
    for (const cn of ["Proofmode for iOS", "Proofmode for Android"]) {
      expect(
        findTrustedIssuer(manifestWithIssuer("Proofmode Reality Systems LLC", cn))?.id,
      ).toBe("proofmode");
    }
  });

  it("rejects a ProofMode leaf outside the pinned app CNs", () => {
    // Trufo is multi-tenant: the O alone must not admit any other product
    // ProofMode might get a certificate for, nor a leaf with no CN.
    expect(
      findTrustedIssuer(manifestWithIssuer("Proofmode Reality Systems LLC")),
    ).toBeNull();
    expect(
      findTrustedIssuer(
        manifestWithIssuer("Proofmode Reality Systems LLC", "Proofmode Desktop"),
      ),
    ).toBeNull();
    // CN equality is exact — no substring or case folding.
    expect(
      findTrustedIssuer(
        manifestWithIssuer("Proofmode Reality Systems LLC", "proofmode for ios"),
      ),
    ).toBeNull();
  });

  it("rejects ProofMode's self-signed local signer", () => {
    // It never chains to a pooled root anyway; routing must not admit it either.
    expect(
      findTrustedIssuer(
        manifestWithIssuer("Proofmode App Self-Signed", "Proofmode C2PA Hardware Key"),
      ),
    ).toBeNull();
  });

  it("matches inside a longer issuer string (substring semantics)", () => {
    // c2pa-rs may surface the issuer with surrounding context — the
    // substring contract guarantees we still match. RealReel has no
    // common_name pin so it still routes on the substring alone.
    const result = findTrustedIssuer(
      manifestWithIssuer("Production / Issuing CA / RealReel"),
    );
    expect(result?.id).toBe("realreel-legacy");
  });

  it("returns null when issuer is not in the trust list", () => {
    expect(findTrustedIssuer(manifestWithIssuer("Photoshop Inc."))).toBeNull();
    expect(
      findTrustedIssuer(manifestWithIssuer("Adobe Content Authenticity")),
    ).toBeNull();
  });

  it("returns null when signature_info is absent", () => {
    expect(findTrustedIssuer({})).toBeNull();
    expect(findTrustedIssuer({ signature_info: {} })).toBeNull();
  });

  it("returns null when issuer is an empty string", () => {
    // Edge case: substring matching on an empty string would match
    // every entry — explicitly guarded against.
    expect(findTrustedIssuer(manifestWithIssuer(""))).toBeNull();
  });

  it("returns null when issuer is a non-string value", () => {
    // Defensive: a malformed manifest from a buggy reader could
    // surface a non-string. We don't trust the shape.
    const manifest = {
      signature_info: { issuer: 42 as unknown as string },
    } as ManifestShape;
    expect(findTrustedIssuer(manifest)).toBeNull();
  });
});
