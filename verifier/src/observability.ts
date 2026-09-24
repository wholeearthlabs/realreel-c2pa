// Sentry init. Pino logger lives inline in server.ts (Fastify's
// `logger: true` for production JSON, pino-pretty in dev) — this file
// only handles the Sentry wiring so the rest of the codebase can
// `import { Sentry } from "./observability.js"` without thinking about
// init order.

import * as SentrySdk from "@sentry/node";
import type { Config } from "./config.js";
import { VerifyError } from "./errors.js";

let initialized = false;

/**
 * Which throws the Fastify integration may report on its own.
 *
 * `@sentry/node` registers an `onError` hook on every Fastify instance it
 * sees, and Fastify runs that hook BEFORE the custom error handler in
 * server.ts. At that point `reply.statusCode` is still 200, so the SDK's
 * default filter (report when the status is <= 299 or >= 500) captures every
 * VerifyError as an unhandled, error-level exception: a duplicate of the
 * structured info/warning `verify_error.<CODE>` message the error handler
 * files once it has set the 422, and the copy that pages on routine
 * rejections. A VerifyError is the verifier's verdict, not a fault. Every
 * other throw is the 500 it becomes and still reports here.
 */
export function shouldReportFastifyError(error: unknown): boolean {
  return !(error instanceof VerifyError);
}

export function initObservability(config: Config): void {
  if (initialized) return;
  initialized = true;

  if (!config.sentryDsn) {
    // Local dev / tests run without Sentry. Captures become no-ops via
    // the SDK's lazy init guards.
    return;
  }

  SentrySdk.init({
    dsn: config.sentryDsn,
    environment: config.isProduction ? "production" : "development",
    // Replaces the default Fastify integration instance (same name) so its
    // auto error capture goes through shouldReportFastifyError.
    integrations: [
      SentrySdk.fastifyIntegration({ shouldHandleError: shouldReportFastifyError }),
    ],
    // Events only — no perf traces. The verifier is short-lived per
    // request and traces add cost without much signal at this scope.
    tracesSampleRate: 0,
  });
}

export const Sentry = SentrySdk;
