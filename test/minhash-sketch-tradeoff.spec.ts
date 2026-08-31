import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// bench/minhash-sketch-tradeoff.ts runs a full benchmark (300 trials x 4
// document-size ratios x 3 sketch sizes, over documents up to ~10,000
// shingles) as a side effect of module load — see that file's `main()` call
// at the bottom. Actually importing it here would make every `npm test` run
// pay for the whole benchmark, so this spec instead asserts on the file's
// SOURCE TEXT: the concrete, cheap, always-true structural property the
// finding below is about, without paying to execute the thing being
// validated.
const BENCH_SOURCE_PATH = fileURLToPath(
  new URL('../bench/minhash-sketch-tradeoff.ts', import.meta.url),
);

function readBenchSource(): string {
  return readFileSync(BENCH_SOURCE_PATH, 'utf8');
}

describe('bench/minhash-sketch-tradeoff.ts shingleHashesOf() (code-review finding: duplication)', () => {
  it('imports shingleHashesOf from src/taint/fingerprint.ts instead of reimplementing it locally', () => {
    const source = readBenchSource();

    // Regression guard for the confirmed duplication finding: this bench
    // script used to hand-roll its own `shingleHashesOf()` — a byte-for-byte
    // copy of the Set-based-dedup + fnv1a32 + sort logic that
    // src/taint/fingerprint.ts already exports under the same name. That
    // let the two silently drift: a future edit to the production
    // shingleHashesOf() (e.g. a change to normalization, hashing, or
    // dedup) would leave this benchmark validating an algorithm the
    // registry no longer runs, defeating the whole point of the script
    // (see its file header: this is evidence for a rejected feature, and
    // that evidence is only meaningful if it reflects the real algorithm).
    //
    // The fix is to import the production function instead of copying it,
    // alongside the fnv1a32/overlapCoefficient it already imports from the
    // same module. This assertion would have FAILED against the pre-fix
    // source (no `shingleHashesOf` in the import list) and PASSES now that
    // the import includes it.
    expect(source).toMatch(
      /import\s*\{[^}]*\bshingleHashesOf\b[^}]*\}\s*from\s*['"]\.\.\/src\/taint\/fingerprint\.js['"]/,
    );

    // The other half of the same regression: no local reimplementation left
    // behind alongside the import. A `function shingleHashesOf(` (or a
    // `const shingleHashesOf =`) declared in this file would either shadow
    // the imported one (silently reintroducing the drift risk the import
    // exists to close) or fail to compile as a duplicate identifier — both
    // are the exact bug this test guards against.
    expect(source).not.toMatch(/\bfunction\s+shingleHashesOf\s*\(/);
    expect(source).not.toMatch(/\bconst\s+shingleHashesOf\s*=/);
  });
});
