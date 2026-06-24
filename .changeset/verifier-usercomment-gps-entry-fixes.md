---
"@realreel/verifier": patch
---

Fix two EXIF metadata-derivation bugs in the photo verifier:

- **UserComment is no longer dropped.** Spec-compliant EXIF `UserComment` tags store their text after an 8-byte character-code prefix (`ASCII\0\0\0`, `UNICODE\0`, `JIS\0\0\0\0\0`, or 8 NULs). exifr returns the value with that prefix intact, and its NUL bytes tripped the control-byte guard, so the comment was silently discarded from derived metadata. The prefix is now stripped before formatting, so capture breadcrumbs (and any camera UserComment) display again.
- **GPS coordinates no longer leak into display entries.** exifr emits `latitude`/`longitude`/`altitude` convenience keys even with `gps: false`, and the coordinate-scrub regex didn't match those labels — so precise coordinates could reach `media.metadata` for any GPS-bearing upload. Those keys are now scrubbed; coordinates remain authoritative only from the signed assertion.
- **Hardening.** Every derived value is clamped to a max length (no oversized comment can bloat `media.metadata`), the video `creation_time` fallback now routes through the same value guard, and exifr's `sanitize` option is pinned explicitly.
