// Verifier-side error class. The `VerifyErrorCode` enum lives in
// @realreel/c2pa-trust-core so the React Native client preflight gate and
// this server share one source of truth for code strings; it's re-exported
// here so existing imports from "./errors.js" keep working. The class itself
// is server-only.

import { VerifyErrorCode } from "@realreel/c2pa-trust-core";

export { VerifyErrorCode };

export class VerifyError extends Error {
  public readonly code: VerifyErrorCode;
  public readonly detail: string | undefined;
  /** Optional grouping tag for Sentry / alerting, attached verbatim by the
   *  server.ts error handler. Conventions: 'play-integrity' (Android) and
   *  'app-attest' (iOS). Cross-platform / generic errors omit category so
   *  platform-specific alerts don't fire on them. */
  public readonly category: string | undefined;

  constructor(
    code: VerifyErrorCode,
    detail?: string,
    options?: { category?: string },
  ) {
    super(`${code}${detail ? `: ${detail}` : ""}`);
    this.code = code;
    this.detail = detail;
    this.category = options?.category;
    this.name = "VerifyError";
  }
}
