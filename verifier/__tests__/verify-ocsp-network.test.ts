// Network: Google's C2PA OCSP responder (c2pa-ocsp.pki.goog) is asked about
// the Pixel wrap fixture's capture chain. Opt in with OCSP_NETWORK_TESTS=1;
// skipped otherwise so the suite stays hermetic.
//
//   OCSP_NETWORK_TESTS=1 npx vitest run verify-ocsp-network
//
// The Pixel capture in fixtures/pixel-uploaded.jpg is genuine, so the expected
// answer is `notRevoked`, filed under the Stage-2 ingredient assertion that
// references the capture; the RealReel active manifest reads `inaccessible`
// because its responder is off the allow-list by design.

import { describe, it, expect, vi } from "vitest";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Reader } from "@contentauth/c2pa-node";

vi.mock("../src/db.js", () => {
  const lookupSigningKeyRevocation = vi.fn();
  const consumeAndRecordAttestation = vi.fn().mockResolvedValue(undefined);
  const pingDb = vi.fn();
  return {
    lookupSigningKeyRevocation,
    consumeAndRecordAttestation,
    pingDb,
    initDb: vi.fn(),
    closeDbPool: vi.fn(),
    postgresAdapter: {
      lookup: lookupSigningKeyRevocation,
      burn: consumeAndRecordAttestation,
      ping: pingDb,
    },
  };
});

import { buildVerifierSettings, verify } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { lookupSigningKeyRevocation } from "../src/db.js";
import type { ManifestStoreShape } from "../src/c2pa-shape.js";

const NETWORK = process.env.OCSP_NETWORK_TESTS === "1";

const trustConfig = await loadTrustConfig(resolve(import.meta.dirname, "../trust-sources.yaml"));
const wrapBytes = await readFile(resolve(import.meta.dirname, "fixtures/pixel-uploaded.jpg"));

// The wrap fixture's Stage-2 leaf serial (see verify-realreel-wrap.test.ts).
const WRAP_STAGE2_SERIAL = "377878420465038296556426931842186971350666267668";
const STAGE2_USER = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";

describe.skipIf(!NETWORK)("Pixel parent OCSP (network)", () => {
  it("c2pa-rs reports notRevoked for the Pixel capture under its ingredient assertion", async () => {
    expect(trustConfig.ocspHosts).toEqual(["http://c2pa-ocsp.pki.goog"]);
    const reader = await Reader.fromAsset(
      { buffer: wrapBytes, mimeType: "image/jpeg" },
      buildVerifierSettings(trustConfig, true),
    );
    const store = reader!.json() as unknown as ManifestStoreShape;
    const captureRow = store.validation_results?.ingredientDeltas?.find(
      (d) =>
        d.ingredientAssertionURI ===
        `self#jumbf=/c2pa/${store.active_manifest}/c2pa.assertions/c2pa.ingredient.v3`,
    );
    expect(captureRow?.validationDeltas?.success?.map((e) => e.code)).toContain(
      "signingCredential.ocsp.notRevoked",
    );
    expect(store.validation_results?.activeManifest?.informational?.map((e) => e.code)).toContain(
      "signingCredential.ocsp.inaccessible",
    );
    expect(store.validation_status ?? []).toEqual([]);
  });

  it("verify() accepts the wrap with network revocation on", async () => {
    vi.mocked(lookupSigningKeyRevocation).mockImplementation(async (serial: string) =>
      serial === WRAP_STAGE2_SERIAL
        ? {
            key_id: "stage2-mocked-key-id",
            user_id: STAGE2_USER,
            revoked_at: null,
            cert_serial_number: WRAP_STAGE2_SERIAL,
            platform: "android-strongbox",
            public_key: Buffer.alloc(0),
            app_attest_public_key: null,
            issued_at: "2026-05-01T00:00:00.000Z",
            expires_at: "2026-10-28T00:00:00.000Z",
          }
        : null,
    );
    const result = await verify({
      assetBytes: wrapBytes,
      mimeType: "image/jpeg",
      expectedUserId: STAGE2_USER,
      trustConfig,
      declaredLocation: "precise",
      networkRevocation: true,
    });
    expect(result.sanitizedManifest.validation_state).toBe("trusted");
  });
});
