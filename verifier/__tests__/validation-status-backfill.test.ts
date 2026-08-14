// Pins the c2pa-node behavior the verifier's primary c2pa-verdict gate
// depends on: for claim-v2 assets, failures are backfilled into the flat
// store-level `validation_status` that classifyStrictValidationStatus reads.
// If a c2pa-node bump stopped backfilling, that gate would silently no-op —
// this test fails instead, by reading a REAL fixture off a Reader configured
// with a trust bundle that deliberately excludes the fixture's root.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { Reader } from "@contentauth/c2pa-node";
import { buildVerifierSettings } from "../src/verify.js";
import type { ManifestStoreShape } from "../src/c2pa-shape.js";
import type { TrustConfig } from "../src/trust/types.js";

const fixturesDir = resolve(import.meta.dirname, "fixtures");

describe("c2pa-node validation_status backfill (claim v2)", () => {
  it("a chain failure on a real v2 fixture surfaces in store-level validation_status", async () => {
    // pixel-og.jpg chains to the Google root; anchor ONLY the RealReel root
    // so the chain is untrusted by construction.
    const realreelRootPem = await readFile(
      resolve(
        import.meta.dirname,
        "../trust-sources/realreel/realreel-c2pa-root.pem",
      ),
      "utf-8",
    );
    const trustConfig: TrustConfig = {
      sources: [],
      tsaRoots: [],
      trustAnchorsBundle: realreelRootPem,
      loadedIds: new Set(),
    };

    const bytes = await readFile(resolve(fixturesDir, "pixel-og.jpg"));
    const reader = await Reader.fromAsset(
      { buffer: bytes, mimeType: "image/jpeg" },
      buildVerifierSettings(trustConfig),
    );
    expect(reader).not.toBeNull();
    const store = reader!.json() as unknown as ManifestStoreShape;

    const codes = (store.validation_status ?? []).map((e) => e.code);
    expect(codes.length).toBeGreaterThan(0);
    expect(codes).toContain("signingCredential.untrusted");
  });
});
