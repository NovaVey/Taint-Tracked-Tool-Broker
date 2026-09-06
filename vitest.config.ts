import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'json-summary', 'html'],
      // Only src/ is the shipped library surface — corpus/, examples/, and
      // bench/ are exercised by their own scripts (npm run corpus / example* /
      // bench*), not by vitest, and types.ts is declarations with no
      // executable branches to cover.
      include: ['src/**/*.ts'],
      // src/cli/** is this package's bin entry (`tttb doctor`) — a genuine
      // part of the shipped library surface (dist/cli/doctor.js is what
      // package.json's "bin" field points at), but exercised the same way
      // examples/ is: test/cli-doctor.spec.ts and
      // scripts/smoke-test-doctor-cli.mjs both run it as a real subprocess
      // (a genuine `node`/`npx tsx` process, main()'s own process.exit()
      // paths included), never imported into vitest's own instrumented
      // process — so v8 coverage here would always read 0% regardless of
      // how thoroughly it's actually tested, the identical "exercised by
      // its own script, not by vitest" reasoning the comment above already
      // gives for corpus/examples/bench, just for one file living under
      // src/ instead of a sibling top-level directory.
      exclude: ['src/types.ts', 'src/cli/**'],
      // A real floor, not a moving target: set a few points below the
      // actual measured coverage as of the commit that last ratcheted this
      // config (statements 98.23% / branches 95.77% / functions 99.56% /
      // lines 98.94%, after the source-class axis, doctor CLI, and
      // observe-mode enforcement features) so CI catches a genuine
      // regression without tripping on ordinary refactors. Ratchet these up
      // over time rather than down.
      thresholds: {
        statements: 95,
        branches: 92,
        functions: 97,
        lines: 96,
      },
    },
  },
});
