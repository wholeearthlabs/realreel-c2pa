// Chain-validation pin for the conformant (v2) CA hierarchy through the
// REAL c2pa-node Reader — not c2patool, whose bundled c2pa-rs is newer.
// Proves three empirical claims the cutover rests on, in the exact
// library the production verifier runs:
//
//   1. A mixed-curve chain (P-256 leaf under a P-384/SHA-384 root+ICA)
//      with the CP §7.1.2 leaf extensions (certificatePolicies, AIA,
//      c2pa-al, c2pa-cpl-record) validates cleanly.
//   2. c2pa-rs surfaces the leaf SUBJECT O as signature_info.issuer
//      ("Whole Earth Labs LLC") and the subject CN as common_name — the
//      strings TRUSTED_ISSUERS[id=realreel] pins.
//   3. The dispatcher routes that issuer to the `realreel` source.
//
// Fixture: fixtures/v2-hierarchy-signed.jpg — single-stage, signed with a
// leaf minted by the PRODUCTION issuance path (issueLeafChainFromCSR with
// v2 options: android AL2 DN, SHA-384 chain declaration, all four v2
// extensions) under a THROWAWAY P-384 hierarchy whose root is committed
// alongside (fixtures/v2-hierarchy-test-root.pem — subject CN "A0 Test
// C2PA Root CA"; no production trust decisions reference it). Signed via
// c2patool 2026-07-27. Single-stage on purpose: the two-stage profile
// shape is covered by the real-device fixtures, which get regenerated
// against the live v2 ICA once dev issuance flips — this test only pins
// chain validation + string surfacing, which need no device.

import { describe, it, expect, beforeAll } from "vitest";
import { readFile, access, mkdir, writeFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { Reader } from "@contentauth/c2pa-node";

import { buildVerifierSettings } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { identifyTrustSource } from "../src/trust/dispatcher.js";
import { classifyStrictValidationStatus } from "../src/profiles/_shared.js";
import {
  getActiveManifest,
  type ManifestStoreShape,
} from "../src/c2pa-shape.js";

const fixturePath = resolve(
  import.meta.dirname,
  "fixtures/v2-hierarchy-signed.jpg",
);
const testRootPath = resolve(
  import.meta.dirname,
  "fixtures/v2-hierarchy-test-root.pem",
);
const TMP_DIR = resolve(import.meta.dirname, ".tmp-v2-hierarchy");

// LFS-pulled fixture may be absent (pointer-only checkout) — skip then,
// same convention as the other fixture suites.
const fixtureExists = await access(fixturePath)
  .then(() => true)
  .catch(() => false);

describe.skipIf(!fixtureExists)(
  "v2 hierarchy chain validation (c2pa-node, mixed-curve)",
  () => {
    let store: ManifestStoreShape;
    let trustConfig: Awaited<ReturnType<typeof loadTrustConfig>>;

    beforeAll(async () => {
      // A minimal trust config anchoring `realreel` at the throwaway v2
      // root. root_cert paths resolve relative to the YAML's directory;
      // an absolute path passes through resolve() unchanged.
      await mkdir(TMP_DIR, { recursive: true });
      const yamlPath = resolve(TMP_DIR, "trust-sources.yaml");
      await writeFile(
        yamlPath,
        [
          "sources:",
          "  - id: realreel",
          "    name: RealReel (v2 test hierarchy)",
          "    description: throwaway v2-shaped root for chain-validation tests",
          `    root_cert: ${testRootPath}`,
          "    verification_profile: realreel",
          "",
        ].join("\n"),
        "utf-8",
      );
      trustConfig = await loadTrustConfig(yamlPath);

      const bytes = await readFile(fixturePath);
      const reader = await Reader.fromAsset(
        { buffer: bytes, mimeType: "image/jpeg" },
        buildVerifierSettings(trustConfig),
      );
      expect(reader).not.toBeNull();
      store = reader!.json() as unknown as ManifestStoreShape;

      await rm(TMP_DIR, { recursive: true, force: true });
    });

    it("validates the mixed-curve v2 chain with zero strict validation issues", () => {
      // classifyStrictValidationStatus throws on any c2pa-rs issue —
      // signingCredential.untrusted here would mean c2pa-node choked on
      // the P-256-leaf-under-P-384-chain shape or one of the new
      // extensions.
      expect(() =>
        classifyStrictValidationStatus(store.validation_status ?? []),
      ).not.toThrow();
    });

    it("surfaces the v2 DN exactly as TRUSTED_ISSUERS pins it", () => {
      const active = getActiveManifest(store)!;
      const si = active.signature_info as {
        issuer?: string;
        common_name?: string;
        alg?: string;
      };
      expect(si.issuer).toBe("Whole Earth Labs LLC");
      expect(si.common_name).toBe("RealReel Android");
      // Mixed-curve pin: the LEAF stays P-256 (es256) under the P-384 chain.
      expect(si.alg?.toLowerCase()).toBe("es256");
    });

    it("dispatches to the 'realreel' source", () => {
      const active = getActiveManifest(store)!;
      const si = active.signature_info as {
        issuer?: string;
        common_name?: string;
      };
      expect(
        identifyTrustSource(si.issuer!, si.common_name ?? null, trustConfig),
      ).toBe("realreel");
    });
  },
);
