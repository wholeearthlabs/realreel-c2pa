---
"@realreel/photo-attest": patch
---

Fix packaging: include the compiled Expo config plugin (`plugin/build`) in the published tarball.

`app.plugin.js` does `require('./plugin/build')`, but the publish lifecycle (`expo-module prepublishOnly` = clean + build the native module) never built the config plugin, so every clean publish shipped without it. Consumers then crashed on any Expo app-config read (`expo start`, `expo prebuild`, web export) with `PluginError: Cannot find module './plugin/build'`.

The config plugin is now built during `prepack`, a CI gate packs the tarball and fails if `plugin/build` is absent, and the plugin TypeScript compiles cleanly (`@types/node`).
