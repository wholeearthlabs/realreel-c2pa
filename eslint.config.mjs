import tseslint from 'typescript-eslint';

// trust-core + verifier. `native/` has its own config (Expo base); the Deno
// services use `deno lint` (scripts/lint-deno.sh).
//
// Small rule set rather than recommendedTypeChecked, because typescript-eslint
// can't run on TypeScript 7 — TS 7 dropped the JS compiler API its parser needs.
// It type-checks with the TS 5.9 that Expo's toolchain hoists to the root while
// `tsc` checks with 7, so only rules whose verdict survives that split are on:
// promise-shaped ones key off whether a value is a Promise (stable across both),
// while inference-sensitive ones (no-unnecessary-type-assertion, no-unsafe-*)
// are exactly where two compilers drift. Revisit when typescript-eslint
// supports TS 7.
const rules = {
  // An unawaited promise here is a revocation, chain, or attestation check
  // resolving to "pass" without having run.
  '@typescript-eslint/no-floating-promises': 'error',
  '@typescript-eslint/no-misused-promises': 'error',
  '@typescript-eslint/await-thenable': 'error',
  '@typescript-eslint/switch-exhaustiveness-check': 'error',
  // Three eslint-disable-next-line no-control-regex comments in verifier/
  // predate any working ESLint; this makes them mean something.
  'no-control-regex': 'error',
};

// *.test.json are the projects covering src, tests, scripts and vitest.config.ts
// — the emit configs deliberately exclude tests.
const workspace = (dir) => ({
  files: [`${dir}/**/*.ts`],
  extends: [tseslint.configs.base],
  languageOptions: {
    parserOptions: {
      project: [`./${dir}/tsconfig.test.json`],
      tsconfigRootDir: import.meta.dirname,
    },
  },
  rules,
});

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/build/**', 'native/**', 'ca/**', 'ocsp/**', 'ocsp-leaf/**', 'pki/**'],
  },
  workspace('trust-core'),
  workspace('verifier'),
);
