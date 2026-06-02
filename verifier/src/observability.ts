// Sentry init. Pino logger lives inline in server.ts (Fastify's
// `logger: true` for production JSON, pino-pretty in dev) — this file
// only handles the Sentry wiring so the rest of the codebase can
// `import { Sentry } from "./observability.js"` without thinking about
// init order.

import * as SentrySdk from "@sentry/node";
import type { Config } from "./config.js";

let initialized = false;

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
    // Events only — no perf traces. The verifier is short-lived per
    // request and traces add cost without much signal at this scope.
    tracesSampleRate: 0,
  });
}

export const Sentry = SentrySdk;
