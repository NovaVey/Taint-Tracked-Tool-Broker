import { describe, expect, it } from 'vitest';
import { checkFieldGrounding } from '../src/index.js';

// A realistic Q-LLM extraction source. Deliberately well over SHINGLE_WIDTH
// (5) words per clause, and every grounded field below is checked with a
// value that is ALSO >= SHINGLE_WIDTH words -- so neither side of the
// comparison trips wordShingles()'s short-text width-narrowing
// (fingerprint.ts), which is GAPS.md #8's own still-open false-negative for
// text shorter than SHINGLE_WIDTH words (grounding.ts's own "known
// limitations" note #1 names this explicitly). This is the identical
// GAPS.md #8-aware fixture convention test/fingerprint.spec.ts and
// test/fingerprint.property.spec.ts already use for their own
// containment-property coverage ("generated with >= SHINGLE_WIDTH (5) words
// specifically so BOTH the substring alone and the full container use the
// same effective shingle width").
const SOURCE =
  'The quarterly compliance report confirms that vendor invoice number 88213 was formally approved by the finance director on the morning of August the twelfth, after the standard three-step review process completed without any flagged discrepancies.';

// Genuinely unrelated content, not an edited/reworded version of SOURCE --
// if this ever scored above 0 against SOURCE it would be a real false
// negative for the "detect a fabricated field" case this module exists
// for, not merely a low score on a paraphrase.
const UNRELATED =
  'The board voted unanimously to relocate company headquarters to a new office park near the airport starting next fiscal year.';

describe('checkFieldGrounding', () => {
  it('reports a verbatim, clean substring of the source as grounded, with a snippet and score 1', () => {
    const exactQuote =
      'vendor invoice number 88213 was formally approved by the finance director on the morning of August the twelfth';
    expect(SOURCE).toContain(exactQuote);

    const [result] = checkFieldGrounding({ summary: exactQuote }, SOURCE);
    expect(result).toBeDefined();
    expect(result!.field).toBe('summary');
    expect(result!.grounded).toBe(true);
    expect(result!.score).toBe(1);
    expect(result!.bestSourceIndex).toBe(0);
    expect(result!.snippet).toBeDefined();
  });

  it('reports a genuine paraphrase -- reworded at both ends, not just an exact substring -- as grounded', () => {
    // Not a literal substring of SOURCE: reworded opening ("This quarter's"
    // vs "The quarterly ... confirms that") and reworded closing
    // ("wrapping up a routine review with nothing flagged" vs "after the
    // standard three-step review process completed without any flagged
    // discrepancies"), with a long shared run in the middle -- a realistic
    // Q-LLM summary of the source, not a copy-paste of it.
    const paraphrase =
      "This quarter's compliance report confirms that vendor invoice number 88213 was formally approved by the finance director on the morning of August the twelfth, wrapping up a routine review with nothing flagged.";
    expect(SOURCE).not.toContain(paraphrase);
    expect(paraphrase).not.toBe(SOURCE);

    const [result] = checkFieldGrounding({ summary: paraphrase }, SOURCE);
    expect(result!.grounded).toBe(true);
    // Genuinely partial overlap, not a disguised exact match: strictly
    // between "shares nothing" and "is the same text".
    expect(result!.score).toBeGreaterThan(0.3);
    expect(result!.score).toBeLessThan(1);
    expect(result!.snippet).toBeDefined();
  });

  it('THE REGRESSION THIS MODULE EXISTS FOR: reports a fabricated field -- content invented by the Q-LLM, present nowhere in the source -- as ungrounded, not a false negative', () => {
    // This is the exact failure mode DESIGN.md §6.2's quarantine path
    // cannot itself detect: a capability-less Q-LLM (or one manipulated by
    // an injected payload embedded in the source it was summarizing)
    // returns a field value with no basis in the source text at all, and
    // quarantine.ts unconditionally trusts and registers whatever it
    // returns. UNRELATED is genuinely different content, not an
    // edited/reworded version of SOURCE, specifically so a nonzero score
    // here would be a real false negative for the case this whole module
    // exists to catch -- not merely "a low score that happened to round
    // down".
    const [result] = checkFieldGrounding({ boardDecision: UNRELATED }, SOURCE);
    expect(result!.grounded).toBe(false);
    expect(result!.score).toBe(0);
    expect(result!.bestSourceIndex).toBeUndefined();
    expect(result!.snippet).toBeUndefined();
  });

  it('checks every field of a structured extraction independently -- a mix of grounded and fabricated fields in one result', () => {
    const results = checkFieldGrounding(
      {
        invoiceApproved:
          'vendor invoice number 88213 was formally approved by the finance director on the morning of August',
        secretBoardDecision: UNRELATED,
      },
      SOURCE,
    );
    const byField = new Map(results.map((r) => [r.field, r]));
    expect(byField.get('invoiceApproved')!.grounded).toBe(true);
    expect(byField.get('secretBoardDecision')!.grounded).toBe(false);
  });

  it('an empty field value is reported grounded (vacuous) -- there is nothing in it that could have been fabricated', () => {
    const [result] = checkFieldGrounding({ optionalNote: '' }, SOURCE);
    expect(result).toEqual({ field: 'optionalNote', grounded: true, score: 1 });
  });

  it('a non-string field value is coerced the same way the rest of this library coerces registrable text (toRegistrableText/JSON.stringify)', () => {
    // 88213 alone stringifies to "88213" -- a single token far under
    // SHINGLE_WIDTH words, so per this module's own documented limitation
    // #1 this genuinely scores 0 even though "88213" literally appears in
    // SOURCE. Asserting the actually-documented behavior (rather than a
    // nicer one that does not hold) is the point: it pins the known
    // limitation so a silent behavior change here doesn't go unnoticed.
    const [result] = checkFieldGrounding({ invoiceNumber: 88213 }, SOURCE);
    expect(result!.score).toBe(0);
    expect(result!.grounded).toBe(false);
  });

  it('picks the best-matching source, and reports its correct index, out of several candidate sources', () => {
    const otherSource =
      'Building maintenance completed a full inspection of the north elevator shaft on Tuesday and found no safety issues requiring immediate repair.';
    const [result] = checkFieldGrounding(
      {
        note: 'a full inspection of the north elevator shaft found no safety issues requiring immediate repair',
      },
      [SOURCE, otherSource],
    );
    expect(result!.grounded).toBe(true);
    expect(result!.bestSourceIndex).toBe(1);
    expect(result!.snippet).toContain('elevator shaft');
  });

  it('threshold is tunable: the same near-miss score is reported ungrounded under a strict threshold and grounded under a loose one', () => {
    // A heavier paraphrase than the "genuine paraphrase" test above -- more
    // of the wording changed throughout, not just at the two ends -- so it
    // lands as a real, nonzero-but-below-default-threshold near miss
    // rather than either a clean hit or a clean zero.
    const heavyParaphrase =
      'Formally approved by the finance director, vendor invoice number 88213 cleared review on the morning of August the twelfth without any trouble at all.';

    const [defaultResult] = checkFieldGrounding({ note: heavyParaphrase }, SOURCE);
    expect(defaultResult!.grounded).toBe(false); // below the default 0.3 threshold

    const [strict] = checkFieldGrounding({ note: heavyParaphrase }, SOURCE, { threshold: 0.9 });
    const [loose] = checkFieldGrounding({ note: heavyParaphrase }, SOURCE, { threshold: 0.2 });

    // Same underlying score either way -- only the grounded/ungrounded
    // verdict, never the score itself, moves with the threshold.
    expect(strict!.score).toBe(defaultResult!.score);
    expect(loose!.score).toBe(defaultResult!.score);
    expect(strict!.grounded).toBe(false);
    expect(loose!.grounded).toBe(true);
  });

  it('accepts a single source string as shorthand for a one-element sources array', () => {
    const exactQuote = 'vendor invoice number 88213 was formally approved by the finance director';
    const asString = checkFieldGrounding({ note: exactQuote }, SOURCE);
    const asArray = checkFieldGrounding({ note: exactQuote }, [SOURCE]);
    expect(asString).toEqual(asArray);
  });

  it('throws when given zero source texts -- there is nothing to check groundedness against', () => {
    expect(() => checkFieldGrounding({ note: 'anything' }, [])).toThrow(/at least one source/i);
  });

  it('returns an empty report list for an extraction with no fields at all', () => {
    expect(checkFieldGrounding({}, SOURCE)).toEqual([]);
  });
});
