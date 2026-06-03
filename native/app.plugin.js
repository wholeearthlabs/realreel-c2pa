// Entry point for the Expo config plugin. Consumers apply it by adding
// "@realreel/photo-attest" to the `plugins` array in app.json / app.config.js.
// The TypeScript source lives in plugin/src and is compiled to plugin/build by
// `expo-module prepare` at publish time.
module.exports = require('./plugin/build');
