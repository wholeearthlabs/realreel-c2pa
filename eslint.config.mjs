import tseslint from 'typescript-eslint';

// trust-core + verifier. `native/` has its own config; the Deno services use
// `deno lint` (scripts/lint-deno.sh).
//
// Small rule set by necessity, not preference: typescript-eslint can't run on
// TypeScript 7, so it type-checks with the TS 5.9 that Expo's toolchain hoists
// to the root while `tsc` uses 7. Only rules whose verdict survives that split
// are on — promise-shaped ones are stable across compilers, inference-sensitive
// ones (no-unnecessary-type-assertion, no-unsafe-*) are where the two drift.
// Revisit when typescript-eslint supports TS 7.
const rules = {
  // An unawaited promise here is a revocation or chain check that resolves to
  // "pass" without having run.
  '@typescript-eslint/no-floating-promises': 'error',
  '@typescript-eslint/no-misused-promises': 'error',
  '@typescript-eslint/await-thenable': 'error',
  '@typescript-eslint/switch-exhaustiveness-check': 'error',
  // Makes the eslint-disable-next-line no-control-regex comments already in
  // verifier/ mean something.
  'no-control-regex': 'error',
};

// The emit configs exclude tests; *.test.json covers src, tests, scripts and
// vitest.config.ts.
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
