// @ts-check
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'node_modules/**'],
  },
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // Auto-discovers the right tsconfig per file (tsconfig.json covers
        // src/corpus/test/examples/bench) and gracefully skips type-aware
        // rules for anything outside that project (this file itself,
        // vitest.config.ts) rather than erroring.
        projectService: {
          // vitest.config.ts, this file itself, and scripts/*.mjs aren't in
          // tsconfig.json's include (that's the library's real TS surface,
          // not build tooling) — lint them without full project type info
          // instead of erroring. scripts/smoke-test-dist.mjs deliberately
          // runs plain JS directly against dist/ output with Node's own ESM
          // loader (see its own header comment for why it must NOT go
          // through the same tsc/esbuild project the rest of the repo does).
          allowDefaultProject: ['eslint.config.js', 'vitest.config.ts', 'scripts/*.mjs'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Not in recommendedTypeChecked by default, but genuinely high-value
      // here specifically: this codebase's correctness hinges on exact
      // async/lock ordering (Broker.withLock, AsyncLocalStorage — see
      // DESIGN.md §4.1 and GAPS.md #17's implementation note). A silently
      // dropped promise is exactly the class of bug that would slip past
      // the type checker but not this rule.
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // ToolExecutor.execute() (and ApprovalChannel.requestApproval()) are
      // typed as returning a Promise, so both real implementations and
      // test-fixture mocks correctly declare `async execute()` to satisfy
      // that contract even when a particular mock's body has no actual
      // await — that's conformance to the interface, not a mistake this
      // rule should flag.
      '@typescript-eslint/require-await': 'off',
    },
  },
  {
    files: ['scripts/**/*.mjs'],
    rules: {
      // scripts/smoke-test-dist.mjs deliberately dynamic-imports the
      // COMPILED dist/ output (see its own header) specifically to bypass
      // the project's own TS type information — that import is `any` by
      // design, not a real unsafe-use finding these type-aware rules exist
      // to catch elsewhere. `allowDefaultProject` above still gives it
      // baseline (non-type-aware) linting.
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },
  eslintConfigPrettier,
);
