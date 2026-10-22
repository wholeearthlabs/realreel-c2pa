// c2pa-eku-capture.jpg: a capture whose leaf carries only the C2PA
// claim-signing and document-signing EKUs, under a throwaway root on a plain
// gradient base. Read through the real engine with the verifier's settings.

import { describe, it, expect } from "vitest";
import { readFile, access, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Reader } from "@contentauth/c2pa-node";

import { buildVerifierSettings, C2PA_SIGNING_EKU_OIDS } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";

const fixturesDir = resolve(import.meta.dirname, "fixtures");
const capture = resolve(fixturesDir, "c2pa-eku-capture.jpg");
const nativeDir = resolve(import.meta.dirname, "../../native");

// LFS-pulled fixtures may be absent (pointer-only checkout) — skip then.
const fixtureExists = await access(capture).then(() => true, () => false);

describe("signing-cert EKUs", () => {
  it.skipIf(!fixtureExists)("trusts a leaf whose only EKUs are C2PA claim signing / document signing", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "signing-ekus-"));
    try {
      const yamlPath = join(tmp, "trust-sources.yaml");
      await writeFile(
        yamlPath,
        [
          "sources:",
          "  - id: realreel",
          "    name: capture root (test)",
          `    root_cert: ${resolve(fixturesDir, "parent-gate-capture-root.pem")}`,
          "    verification_profile: realreel",
          "",
        ].join("\n"),
      );
      const settings = buildVerifierSettings(await loadTrustConfig(yamlPath));
      const reader = await Reader.fromAsset(
        { buffer: await readFile(capture), mimeType: "image/jpeg" },
        settings,
      );
      const store = reader!.json() as unknown as {
        validation_status?: { code: string }[];
        validation_results?: { activeManifest?: { success?: { code: string }[] } };
      };
      expect(store.validation_status ?? []).toEqual([]);
      expect(store.validation_results?.activeManifest?.success?.map((e) => e.code)).toContain(
        "signingCredential.trusted",
      );
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  });

  it.each([
    ["android", "android/src/main/java/expo/modules/photoattest/PhotoAttestModule.kt", /C2PA_SIGNING_EKU_OIDS =\s*"([^"]*)"/],
    ["ios", "ios/PhotoAttestModule.swift", /c2paSigningEkuOids =\s*"([^"]*)"/],
  ])("photo-attest %s carries the same list", async (_, path, pattern) => {
    const source = await readFile(resolve(nativeDir, path), "utf-8");
    const oids = pattern.exec(source)?.[1]?.split("\\n").filter(Boolean);
    expect(oids).toEqual(C2PA_SIGNING_EKU_OIDS);
  });
});
