// Pin vitest's test discovery to this directory. Without this, vitest 2
// walks up to the repo root (because Yarn workspaces puts `workspaces` on
// the root package.json) and tries to run the React Native Jest tests in
// lib/__tests__/, which use jest-globals not vitest. The result is
// confusing "0 tests, FAIL" lines on RN-only test files.

import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// `verifier/package.json` is `"type": "module"`, so this file loads as
// ESM — `__dirname` isn't defined. Use the import.meta.url-derived form
// instead, which is robust even if vitest's config loader ever switches
// from its bundler-transpiled path to native ESM.
const here = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  test: {
    root: here,
    include: ["__tests__/**/*.test.ts"],
  },
});
