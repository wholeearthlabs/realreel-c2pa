---
'@realreel/photo-attest': patch
---

Formatting-only pass over the package source. No API, type, or behavior change.

`npm run lint` had never actually run here: ESLint 9 requires a flat config and
there was none anywhere in the repo, so `expo-module lint` failed to start on a
clean checkout. The package now has `eslint.config.js` (base from
`expo-module-scripts`) and a `.prettierrc` pinning `singleQuote`, which is what
the source was already written in — without it Prettier's default would have
flipped every string in the package.

`src/` ships in the published tarball, so the reflow changes published bytes;
hence the patch bump. Lint also now covers the config plugin (`plugin/src`),
`app.plugin.js` and the release scripts, none of which were linted before.
