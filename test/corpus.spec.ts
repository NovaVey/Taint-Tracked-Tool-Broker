import { describe, expect, it } from 'vitest';
import { CORPUS } from '../corpus/cases.js';
import { runCorpusCase } from '../corpus/schema.js';

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
});
