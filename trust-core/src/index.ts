// @realreel/c2pa-trust-core — public entry point.
//
// This package is the shared trust-policy layer between the RealReel
// React Native client (preflight gate) and the Cloud Run C2PA verifier.
// It is pure TypeScript: no I/O, no crypto, no native dependencies. Both
// consumers load a C2PA manifest store via their respective bindings
// (c2pa-ios / c2pa-android on the client; c2pa-node on the server) and
// then run the same pure policy functions from here against the parsed
// structure.
//
// What lives here:
//   - shapes/    Typed shapes for the c2pa-rs JSON output (same on both sides).
//   - errors/    The VerifyErrorCode enum — one source of truth for both
//                client and server. Client maps a subset to user-facing toasts;
//                server returns the full set in 422 responses.
//   - policies/  Pure functions: action-allowlist checks, structural rules,
//                issuer membership lookup. Each function takes parsed objects
//                in, returns a decision (boolean / VerifyError-shape) out.
//   - trust-list/ Curated allowlist of trusted camera/PEM issuers (RealReel,
//                Pixel, etc.). Adding a new entry here is the only change
//                required to extend trust to a new device line.
//
// The trust list, action allowlists, and structural rules are intentionally
// readable + auditable: anyone can inspect what RealReel considers a trusted
// capture.

// Note on .js extensions: relative imports use `.js` extensions even though
// the source files are `.ts`. TypeScript accepts this under all resolution
// modes, and NodeNext consumers (the verifier's tsconfig) REQUIRE it for
// relative ESM imports. Bundler-resolution tools (vitest, Metro, jest-expo)
// tolerate the .js extension as well, so this is the universally-correct form.
export * from "./shapes/index.js";
export * from "./errors/index.js";
export * from "./policies/index.js";
export * from "./trust-list/index.js";
