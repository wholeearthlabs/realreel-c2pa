// Upload MIME allowlist — one definition for the three gates that consume
// it: the verifier's trust-boundary check (verify.ts), the
// verify-and-create-media edge function's cheap 400 (Deno; can't import
// this package, so it carries a literal copy pinned by an app-repo lockstep
// test), and that lockstep test itself.

export const ALLOWED_UPLOAD_MIME_TYPES: ReadonlySet<string> = new Set([
  "image/jpeg",
  "image/heic",
  "image/heif",
  "video/mp4",
  "video/quicktime",
]);
