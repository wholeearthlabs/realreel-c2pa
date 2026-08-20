// Flat config for the JS/TS surface of this package. expo-module-scripts ships
// the base (eslint-config-universe/native plus its ESLint 9 shims); without a
// config file here ESLint 9 refuses to start, which is why `npm run lint` had
// never actually run.
const { defineConfig } = require('eslint/config');
const baseConfig = require('expo-module-scripts/eslint.config.base');
const globals = require('globals');

module.exports = defineConfig([
  baseConfig,
  {
    // Compiled output, not source. `build/` is the module emit and
    // `plugin/build/` the config-plugin emit; both are gitignored.
    ignores: ['build/**', 'plugin/build/**'],
  },
  {
    // Repo tooling — plain Node ESM, not React Native. The base config only
    // wires Node globals for ./*.config.js and ./.*rc.js, so without this
    // `new URL(...)` in scripts/verify-packaging.mjs reads as undefined.
    files: ['scripts/**', 'app.plugin.js'],
    languageOptions: { globals: globals.node },
  },
]);
