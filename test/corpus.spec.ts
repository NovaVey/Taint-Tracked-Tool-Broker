import { describe, expect, it } from 'vitest';
import { CORPUS, TRUE_GAP_IDS } from '../corpus/cases.js';
import type { CorpusCase } from '../corpus/schema.js';
import { runCorpusCase, runUnprotectedCase } from '../corpus/schema.js';

describe('injection corpus', () => {
  for (const c of CORPUS) {
    it(`${c.attackClass} :: ${c.id}`, async () => {
      const outcome = await runCorpusCase(c);
      expect(outcome.pass, outcome.failureDetail ?? '').toBe(true);
    });
  }

  it('covers every documented true known gap', () => {
    // TRUE_GAP_IDS is exported from corpus/cases.ts and is the SAME
    // constant run-corpus.ts's summary line reads from — previously each
    // hardcoded its own separate copy of this list with nothing keeping
    // them in sync (see corpus/cases.ts's own doc comment on TRUE_GAP_IDS).
    for (const id of TRUE_GAP_IDS) {
      expect(CORPUS.some((c) => c.id === id)).toBe(true);
    }
  });

  // Regression coverage for a runCorpusCase() error-handling gap: its catch
  // block used to special-case only 3 of this library's 12 exported error
  // types (ToolCallBlockedError, UnplannedPrivilegedActionError,
  // DisallowedOutboundHostError) — any other error thrown during
  // c.quarantine/c.actions collapsed to the opaque failureDetail
  // 'decision: expected X, got ERROR' with no hint of why, and the
  // underlying error's own descriptive .message never surfaced anywhere
  // this spec file's own assertion (`outcome.failureDetail ?? ''` above)
  // could see it. Both ad-hoc cases below construct a real, well-formed
  // error via a path no real corpus case takes (an unregistered tool name;
  // args containing a function) and assert failureDetail now names it.
  describe('runCorpusCase() surfaces the underlying error message for uncommon broker errors', () => {
    it('UnknownToolError (a case action names a tool nothing registered)', async () => {
      const adHocCase = {
        id: 'schema-spec-unknown-tool',
        description:
          'ad-hoc case for schema.ts error-handling coverage, not a real corpus attack case',
        attackClass: 'schema-spec-only',
        setup: [],
        actions: [{ tool: 'this_tool_was_never_registered', args: {} }],
        expected: { decision: 'BLOCK' },
      } as unknown as CorpusCase;

      const outcome = await runCorpusCase(adHocCase);

      expect(outcome.pass).toBe(false);
      expect(outcome.actualDecision).toBe('ERROR');
      // Pre-fix, this was exactly 'decision: expected BLOCK, got ERROR' —
      // no mention of WHY. Post-fix it must name the actual problem.
      expect(outcome.failureDetail).toContain(
        'No tool registered with name "this_tool_was_never_registered"',
      );
    });

    it('NonCloneableArgsError (a case action passes a non-cloneable arg value)', async () => {
      const adHocCase = {
        id: 'schema-spec-noncloneable-args',
        description:
          'ad-hoc case for schema.ts error-handling coverage, not a real corpus attack case',
        attackClass: 'schema-spec-only',
        setup: [],
        // write_file IS a real registered fixture — the failure here is
        // structuredClone() rejecting a function-valued argument, not an
        // unknown-tool lookup (that's the sibling test above).
        actions: [
          { tool: 'write_file', args: { path: '/tmp/x', contents: () => 'not cloneable' } },
        ],
        expected: { decision: 'BLOCK' },
      } as unknown as CorpusCase;

      const outcome = await runCorpusCase(adHocCase);

      expect(outcome.pass).toBe(false);
      expect(outcome.actualDecision).toBe('ERROR');
      expect(outcome.failureDetail).toContain('could not be cloned');
    });
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
