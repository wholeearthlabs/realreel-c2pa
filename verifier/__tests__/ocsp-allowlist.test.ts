// Pins the c2pa-node contract network revocation stands on: the
// core.allowed_network_hosts setting reaches c2pa-rs. With OCSP fetch on and
// an allow-list that excludes the Pixel chain's responder (c2pa-ocsp.pki.goog),
// the request is refused inside c2pa-rs and the chain reads
// signingCredential.ocsp.inaccessible — informational, still Trusted — which
// is why enforceParentRevocationStatus requires the positive answer itself.
// c2pa-rs reports a blocked request and a failed connection with the same
// code, so this test tells a dropped setting apart from "no egress" only
// where egress exists (CI): the fetch would then reach Google and produce
// notRevoked, which the first case asserts against.

import { describe, it, expect } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Reader } from "@contentauth/c2pa-node";

import { buildVerifierSettings } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import type { ManifestStoreShape } from "../src/c2pa-shape.js";

const trustConfig = await loadTrustConfig(resolve(import.meta.dirname, "../trust-sources.yaml"));
const pixelBytes = await readFile(resolve(import.meta.dirname, "fixtures/pixel-og.jpg"));

async function read(settings: string): Promise<ManifestStoreShape> {
  const reader = await Reader.fromAsset({ buffer: pixelBytes, mimeType: "image/jpeg" }, settings);
  expect(reader).not.toBeNull();
  return reader!.json() as unknown as ManifestStoreShape;
}

type Bucket = "success" | "informational" | "failure";
const codes = (store: ManifestStoreShape, bucket: Bucket): string[] =>
  (store.validation_results?.activeManifest?.[bucket] ?? []).map((e) => e.code);
const ocspCodes = (store: ManifestStoreShape): string[] =>
  (["success", "informational", "failure"] as const)
    .flatMap((b) => codes(store, b))
    .filter((c) => c.startsWith("signingCredential.ocsp."));

describe("c2pa-rs host allow-list (hermetic)", () => {
  it("a responder off the allow-list reads signingCredential.ocsp.inaccessible and leaves the chain Trusted", async () => {
    const store = await read(
      buildVerifierSettings({ ...trustConfig, ocspHosts: ["http://ocsp.invalid"] }, true),
    );
    expect(codes(store, "informational")).toContain("signingCredential.ocsp.inaccessible");
    expect(codes(store, "success")).not.toContain("signingCredential.ocsp.notRevoked");
    expect(store.validation_status ?? []).toEqual([]);
    expect(store.validation_state).toBe("Trusted");
  });

  it("with network revocation off, no OCSP code appears at all", async () => {
    expect(ocspCodes(await read(buildVerifierSettings(trustConfig)))).toEqual([]);
  });
});
