// The base comes from expo-module-scripts; this file exists because ESLint 9
// refuses to start without a flat config, so `npm run lint` never ran.
const { defineConfig } = require('eslint/config');
const baseConfig = require('expo-module-scripts/eslint.config.base');
const globals = require('globals');

module.exports = defineConfig([
  baseConfig,
  {
    ignores: ['build/**', 'plugin/build/**'],
  },
  {
    // The base wires Node globals only for ./*.config.js and ./.*rc.js, so
    // without this `new URL(...)` in scripts/ lints as undefined.
    files: ['scripts/**', 'app.plugin.js'],
    languageOptions: { globals: globals.node },
  },
]);
