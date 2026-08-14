// The verifier-side mimeType gate: allowlist + magic-number cross-check,
// running BEFORE the client-supplied mimeType can select a c2pa-rs asset
// handler in Reader.fromAsset. The edge function carries the same allowlist
// for a cheap 400; this is the trust-boundary copy.
//
// Positive-path coverage (real JPEG + image/jpeg reaching the manifest
// gates) lives in every fixture suite; these tests pin the rejects.

import { describe, it, expect } from "vitest";
import { resolve } from "node:path";

import { verify } from "../src/verify.js";
import { loadTrustConfig } from "../src/trust/loader.js";
import { VerifyErrorCode } from "../src/errors.js";

const trustSourcesPath = resolve(import.meta.dirname, "../trust-sources.yaml");
const trustConfig = await loadTrustConfig(trustSourcesPath);

const USER_ID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";

function verifyBytes(bytes: Buffer, mimeType: string) {
  return verify({
    assetBytes: bytes,
    mimeType,
    expectedUserId: USER_ID,
    declaredLocation: "precise",
    trustConfig,
  });
}

/** Minimal byte stubs — the gate fires before any real parsing. */
const JPEG_MAGIC = Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
  Buffer.alloc(32),
]);
const BMFF_MAGIC = Buffer.concat([
  Buffer.from([0x00, 0x00, 0x00, 0x18]),
  Buffer.from("ftypisom", "latin1"),
  Buffer.alloc(32),
]);

describe("verify() mimeType gate", () => {
  it("rejects a mimeType outside the allowlist", async () => {
    await expect(verifyBytes(JPEG_MAGIC, "image/png")).rejects.toMatchObject({
      code: VerifyErrorCode.MANIFEST_MALFORMED,
      detail: expect.stringContaining("unsupported mimeType"),
    });
  });

  it("rejects JPEG bytes declared as video/mp4", async () => {
    await expect(verifyBytes(JPEG_MAGIC, "video/mp4")).rejects.toMatchObject({
      code: VerifyErrorCode.MANIFEST_MALFORMED,
      detail: expect.stringContaining("do not match declared mimeType"),
    });
  });

  it("rejects BMFF bytes declared as image/jpeg", async () => {
    await expect(verifyBytes(BMFF_MAGIC, "image/jpeg")).rejects.toMatchObject({
      code: VerifyErrorCode.MANIFEST_MALFORMED,
      detail: expect.stringContaining("do not match declared mimeType"),
    });
  });

  it("mime-consistent bytes pass the gate (and fail later, on missing provenance)", async () => {
    // BMFF magic + video/mp4 clears the gate; the Reader then rejects the
    // stub for having no C2PA manifest — proving gate order.
    await expect(verifyBytes(BMFF_MAGIC, "video/mp4")).rejects.toMatchObject({
      code: VerifyErrorCode.MANIFEST_MALFORMED,
      detail: expect.not.stringContaining("mimeType"),
    });
  });
});
