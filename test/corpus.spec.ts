import { describe, expect, it } from 'vitest';
import { CORPUS } from '../corpus/cases.js';
import { runCorpusCase, runUnprotectedCase } from '../corpus/schema.js';

describe('injection corpus', () => {
  for (const c of CORPUS) {
    it(`${c.attackClass} :: ${c.id}`, async () => {
      const outcome = await runCorpusCase(c);
      expect(outcome.pass, outcome.failureDetail ?? '').toBe(true);
    });
  }

  it('covers every documented true known gap', () => {
    const trueGapIds = ['untracked-tool-description-injection', 'cross-turn-latent-influence'];
    for (const id of trueGapIds) {
      expect(CORPUS.some((c) => c.id === id)).toBe(true);
    }
  });

  // The counterfactual baseline run-corpus.ts's summary rests on: every
  // case's sink call(s) actually execute against the real fixtures with no
  // broker mediating them at all. If a future fixture change made one throw
  // instead, the "N sink calls would have executed unprotected" claim in
  // the corpus report would silently become false — this locks that in as
  // a real regression test rather than only being visible by eyeballing
  // `npm run corpus`'s output.
  for (const c of CORPUS) {
    it(`${c.id}: sink call(s) execute with no broker mediating them (counterfactual baseline)`, async () => {
      const outcome = await runUnprotectedCase(c);
      const errorMessage = outcome.error instanceof Error ? outcome.error.message : '';
      expect(outcome.sinkExecuted, errorMessage).toBe(true);
    });
  }
});
