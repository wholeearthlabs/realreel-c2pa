// shouldReportFastifyError (src/observability.ts): the filter handed to
// Sentry's Fastify integration, which would otherwise report every
// VerifyError as an unhandled, error-level exception before the custom
// error handler in server.ts turns it into a 422 plus a structured message.

import { describe, it, expect } from "vitest";

import { shouldReportFastifyError } from "../src/observability.js";
import { VerifyError, VerifyErrorCode } from "../src/errors.js";

describe("shouldReportFastifyError", () => {
  it("leaves a VerifyError to the error handler's structured message", () => {
    const rejected = new VerifyError(
      VerifyErrorCode.UNTRUSTED_ISSUER,
      "signingCredential.ocsp.revoked: certificate revoked",
      { category: "ocsp" },
    );
    expect(shouldReportFastifyError(rejected)).toBe(false);
  });

  it("still reports every other throw as the 500 it becomes", () => {
    expect(shouldReportFastifyError(new Error("boom"))).toBe(true);
    expect(shouldReportFastifyError(new TypeError("bad"))).toBe(true);
  });
});
