// withOcspTimeout (src/verify.ts): the bound around a Reader read with OCSP
// fetch on, since c2pa-rs's HTTP client carries no timeout of its own.

import { describe, it, expect, vi, afterEach } from "vitest";

import { OCSP_FETCH_TIMEOUT_MS, withOcspTimeout } from "../src/verify.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("withOcspTimeout", () => {
  it("passes a read that finishes in time through unchanged, and clears its timer", async () => {
    vi.useFakeTimers();
    await expect(withOcspTimeout(Promise.resolve("reader"), 1_000)).resolves.toBe("reader");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rejects a hung read as retryable VERIFIER_UNAVAILABLE tagged ocsp", async () => {
    vi.useFakeTimers();
    const pending = withOcspTimeout(new Promise<never>(() => {}), 50);
    const settled = pending.then(
      () => null,
      (e: unknown) => e,
    );
    await vi.advanceTimersByTimeAsync(50);
    const err = await settled;
    expect(err).toBeInstanceOf(VerifyError);
    expect((err as VerifyError).code).toBe(VerifyErrorCode.VERIFIER_UNAVAILABLE);
    expect((err as VerifyError).category).toBe("ocsp");
    expect((err as VerifyError).detail).toContain("exceeded 50 ms");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("propagates the read's own failure, and clears its timer", async () => {
    vi.useFakeTimers();
    await expect(withOcspTimeout(Promise.reject(new Error("truncated JUMBF")), 1_000)).rejects.toThrow(
      "truncated JUMBF",
    );
    expect(vi.getTimerCount()).toBe(0);
  });

  it("defaults to the 10 s route budget", () => {
    expect(OCSP_FETCH_TIMEOUT_MS).toBe(10_000);
  });
});
