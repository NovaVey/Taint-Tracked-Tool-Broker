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
      exclude: ['src/types.ts'],
      // A real floor, not a moving target: set a few points below the
      // actual measured coverage as of the commit that added this config
      // (statements 96.32% / branches 91.82% / functions 99.21% / lines
      // 98.03%) so CI catches a genuine regression without tripping on
      // ordinary refactors. Ratchet these up over time rather than down.
      thresholds: {
        statements: 90,
        branches: 85,
        functions: 95,
        lines: 95,
      },
    },
  },
});
