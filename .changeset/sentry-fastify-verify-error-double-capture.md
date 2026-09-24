---
"@realreel/verifier": patch
---

Stop Sentry's Fastify integration from reporting every `VerifyError` a second time as an unhandled, error-level exception. Fastify runs the SDK's `onError` hook before the verifier's own error handler, so the reply status is still 200 when the SDK's default filter looks at it, and each routine 422 rejection also surfaced as a high-priority issue next to the structured `verify_error.<CODE>` message. The integration now receives a `shouldHandleError` that skips `VerifyError`; every other throw still reports as the 500 it becomes.
