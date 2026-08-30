/**
 * Benchmarks structuredClone (the default `cloneArgs`) against
 * jsonSafeClone (src/json-safe-clone.ts) at representative tool-call args
 * sizes, so shipping jsonSafeClone as an opt-in `cloneArgs` is a decision
 * backed by actual numbers, not a guess. Not part of `npm test`/CI —
 * benchmark timings are noisy and shouldn't gate a build. Run with:
 *
 *   npx tsx bench/args-clone.ts
 */

import { jsonSafeClone } from '../src/json-safe-clone.js';

interface Case {
  name: string;
  make: () => unknown;
}

const CASES: Case[] = [
  {
    name: 'small (typical shell_exec-style args)',
    make: () => ({ cmd: 'deploy.sh --target=prod --replicas=3' }),
  },
  {
    name: 'medium (a moderately nested tool-call object, ~50 fields)',
    make: () => {
      const obj: Record<string, unknown> = {
        path: '/tmp/report.json',
        metadata: { author: 'agent', tags: ['report', 'quarterly'] },
      };
      for (let i = 0; i < 50; i++)
        obj[`field_${i}`] = { index: i, value: `value-${i}`, nested: { a: i, b: i * 2 } };
      return obj;
    },
  },
  {
    name: 'large (a ~50KB fetched-page-style string field)',
    make: () => ({
      url: 'https://example.com/docs',
      contents: 'Lorem ipsum dolor sit amet. '.repeat(1800),
    }),
  },
  {
    name: 'deep (50 levels of nesting)',
    make: () => {
      let obj: Record<string, unknown> = { leaf: true };
      for (let i = 0; i < 50; i++) obj = { depth: i, child: obj };
      return obj;
    },
  },
];

const ITERATIONS = 20_000;

function timeIt(fn: () => void, iterations: number): number {
  // Warm up the JIT before the timed run, same treatment for both cloners.
  for (let i = 0; i < Math.min(1000, iterations); i++) fn();
  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  return performance.now() - start;
}

function main(): void {
  console.log(
    `Comparing structuredClone vs jsonSafeClone, ${ITERATIONS.toLocaleString()} iterations per case:\n`,
  );
  console.log(
    'case'.padEnd(52),
    'structuredClone'.padStart(18),
    'jsonSafeClone'.padStart(16),
    'speedup'.padStart(10),
  );
  console.log('-'.repeat(100));

  for (const c of CASES) {
    const args = c.make();
    const structuredMs = timeIt(() => structuredClone(args), ITERATIONS);
    const jsonSafeMs = timeIt(() => jsonSafeClone(args), ITERATIONS);
    const speedup = structuredMs / jsonSafeMs;
    console.log(
      c.name.padEnd(52),
      `${structuredMs.toFixed(1)}ms`.padStart(18),
      `${jsonSafeMs.toFixed(1)}ms`.padStart(16),
      `${speedup.toFixed(2)}x`.padStart(10),
    );
  }
}

main();
