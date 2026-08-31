import { createHash } from 'node:crypto';
import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { buildFingerprint, exactHash, overlapCoefficient } from '../src/index.js';

/**
 * Property-based regression coverage for fingerprint.ts, aimed squarely at
 * the exact bug SHAPE this module has already shipped TWICE — see GAPS.md
 * #8 and the CHANGELOG.md `[Unreleased]` entry beginning "`exactHash()`
 * hashed text via Node's lossy UTF-8 encoding...": a real invariant
 * violated by a Unicode input class nobody happened to hand-write an
 * example for (a lone/unpaired UTF-16 surrogate; a text made entirely of
 * punctuation/symbols/emoji that `normalize()` reduces to nothing). Both
 * were caught by adversarial review, not the existing example-based test
 * suite (`test/fingerprint.spec.ts`) — the textbook property-based-testing
 * failure mode. These tests exist to make that failure mode structurally
 * harder to repeat: the arbitraries below are deliberately WEIGHTED toward
 * those two proven bug classes rather than relying on `fc.string()`'s
 * default distribution, which — per fast-check's own documented behavior —
 * only rarely produces a lone (unpaired) surrogate on its own (a matched
 * surrogate PAIR, i.e. a well-formed astral character, is far likelier than
 * a lone half of one) and gives punctuation-only/emoji-only output
 * vanishingly little weight next to ordinary letters and digits.
 *
 * These run as plain `fc.assert(fc.property(...))` calls inside ordinary
 * vitest `it()` blocks — fast-check's own first-class integration point —
 * so they execute as part of the normal `npm test` output, with the same
 * pass/fail reporting and the same counterexample-shrinking fast-check
 * always does on failure, not a separate harness or CI job.
 *
 * Complements, and deliberately does not replace, `test/fingerprint.spec.ts`'s
 * hand-picked example-based regression tests for the same two historical
 * bugs — those pin the EXACT reported repros (e.g. `'\uD800X'` vs
 * `'\uD801X'`) permanently; these sweep the surrounding input space so the
 * NEXT bug in this shape doesn't need its own hand-picked example first.
 */

// ---------------------------------------------------------------------------
// Arbitraries biased toward the two proven bug classes.
// ---------------------------------------------------------------------------

/** A single lone high (D800-DBFF) UTF-16 surrogate code unit, as its own one-character string. */
const loneHighSurrogateUnit = fc
  .integer({ min: 0xd800, max: 0xdbff })
  .map((codeUnit) => String.fromCharCode(codeUnit));
/** A single lone low (DC00-DFFF) UTF-16 surrogate code unit, as its own one-character string. */
const loneLowSurrogateUnit = fc
  .integer({ min: 0xdc00, max: 0xdfff })
  .map((codeUnit) => String.fromCharCode(codeUnit));
const loneSurrogateUnit = fc.oneof(loneHighSurrogateUnit, loneLowSurrogateUnit);

/**
 * Plain ASCII filler, guaranteed to contain no surrogate code units at all
 * — so embedding a lone surrogate between two of these keeps it genuinely
 * LONE (not accidentally paired into a well-formed astral character by
 * whatever random code unit fast-check happened to place next to it).
 */
const asciiFiller = fc.string({ unit: 'grapheme-ascii', maxLength: 6 });

/**
 * A string with exactly one deliberately-embedded lone surrogate — the
 * exact input shape that collided under the pre-fix lossy-UTF-8-then-hash
 * path (see fingerprint.ts's `escapeLoneSurrogatesForHashing` doc comment
 * for the mechanism: `TextEncoder`/`Buffer`'s UTF-8 encoder silently
 * substitutes U+FFFD for any unpaired surrogate).
 */
const stringWithLoneSurrogate = fc
  .tuple(asciiFiller, loneSurrogateUnit, asciiFiller)
  .map(([pre, lone, post]) => pre + lone + post);

/** A string made entirely of punctuation/symbol characters outside `\p{L}\p{N}\s` — the input class `normalize()` collapses to the empty string. */
const symbolOnlyString = fc
  .array(fc.constantFrom(...'!@#$%^&*()_+-=[]{}|;:,.<>?/~`"\'\\'.split('')), {
    minLength: 1,
    maxLength: 40,
  })
  .map((chars) => chars.join(''));

/** A string made entirely of emoji, including a multi-code-point ZWJ sequence — the same all-symbol bug class, at the surrogate-pair/grapheme-cluster end of it. */
const emojiOnlyString = fc
  .array(fc.constantFrom('😀', '🚀', '✅', '👍', '🔥', '💥', '🎉', '⭐', '👨‍👩‍👧‍👦'), {
    minLength: 1,
    maxLength: 10,
  })
  .map((chars) => chars.join(''));

/** Whitespace-only, including empty — the other realistic input `normalize()` reduces to zero words. */
const whitespaceOnlyString = fc
  .array(fc.constantFrom(' ', '\t', '\n', '\r'), { minLength: 0, maxLength: 20 })
  .map((chars) => chars.join(''));

/**
 * General-purpose text arbitrary for the properties below, weighted toward
 * the proven bug classes rather than `fc.string()`'s own default
 * distribution (see file header). `fc.string()` itself still gets the
 * largest share — these tests are about widening coverage of the two proven
 * failure classes, not abandoning the general case.
 */
const biasedText = fc.oneof(
  { weight: 3, arbitrary: fc.string() },
  { weight: 2, arbitrary: stringWithLoneSurrogate },
  { weight: 2, arbitrary: symbolOnlyString },
  { weight: 2, arbitrary: emojiOnlyString },
  { weight: 1, arbitrary: whitespaceOnlyString },
);

/**
 * Local re-implementation of fingerprint.ts's own lone-surrogate detection
 * (its `LONE_HIGH_SURROGATE`/`LONE_LOW_SURROGATE` regexes are not exported —
 * deliberately, they're an internal pre-processing detail of `exactHash()`
 * alone). Used only to FILTER an arbitrary down to well-formed strings for
 * the "unchanged vs. raw UTF-8 hashing" property below, which is specifically
 * about the well-formed case; the lone-surrogate case has its own dedicated
 * property instead. Mirrors `test/fingerprint.spec.ts`'s existing
 * `rawUtf8Hash` helper in spirit: duplicating a small amount of hashing
 * logic in the test file rather than reaching into the module's private
 * internals.
 */
function hasLoneSurrogate(text: string): boolean {
  const loneHigh = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])/;
  const loneLow = /(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
  return loneHigh.test(text) || loneLow.test(text);
}
const wellFormedBiasedText = fc
  .oneof(
    { weight: 3, arbitrary: fc.string() },
    { weight: 2, arbitrary: symbolOnlyString },
    { weight: 2, arbitrary: emojiOnlyString },
    { weight: 1, arbitrary: whitespaceOnlyString },
  )
  .filter((text) => !hasLoneSurrogate(text));

/**
 * Lowercase ASCII letters only, joined into short words. `normalize()`
 * (lowercase + strip non-letter/digit/whitespace + collapse whitespace) is a
 * byte-for-byte no-op on text built exclusively from these — so a word
 * list's own shingle windows line up EXACTLY with the same words' windows
 * once embedded in a larger, space-joined document, which is what the
 * containment property below depends on being exact, not approximate.
 */
const word = fc
  .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'.split('')), {
    minLength: 1,
    maxLength: 6,
  })
  .map((letters) => letters.join(''));

// ---------------------------------------------------------------------------
// exactHash
// ---------------------------------------------------------------------------

describe('exactHash (property-based)', () => {
  it('never collides two strings differing only in WHICH lone surrogate they embed — the exact proven bug class (GAPS.md #8)', () => {
    // Direct generalization of the historical repro ('\uD800X' vs
    // '\uD801X'): same ASCII context on both sides, only the specific lone
    // surrogate code unit differs. Pre-fix, both encoded to the same UTF-8
    // byte sequence (U+FFFD in place of either) and so hashed identically.
    fc.assert(
      fc.property(
        asciiFiller,
        asciiFiller,
        loneSurrogateUnit,
        loneSurrogateUnit,
        (pre, post, loneA, loneB) => {
          fc.pre(loneA !== loneB);
          expect(exactHash(pre + loneA + post)).not.toBe(exactHash(pre + loneB + post));
        },
      ),
    );
  });

  it('never collides two distinct strings drawn from a bug-class-biased distribution', () => {
    fc.assert(
      fc.property(biasedText, biasedText, (a, b) => {
        fc.pre(a !== b);
        expect(exactHash(a)).not.toBe(exactHash(b));
      }),
    );
  });

  it('is deterministic across repeated calls on the same (including bug-class) input', () => {
    fc.assert(
      fc.property(biasedText, (text) => {
        expect(exactHash(text)).toBe(exactHash(text));
      }),
    );
  });

  it('is byte-for-byte identical to hashing the raw UTF-8 bytes directly, for any well-formed (no lone surrogate) string — including symbol-only/emoji-only/whitespace-only text', () => {
    fc.assert(
      fc.property(wellFormedBiasedText, (text) => {
        const rawUtf8Hash = createHash('sha256').update(text, 'utf8').digest('hex');
        expect(exactHash(text)).toBe(rawUtf8Hash);
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// overlapCoefficient
// ---------------------------------------------------------------------------

describe('overlapCoefficient (property-based)', () => {
  it('is always within [0, 1], for arbitrary (including bug-class-biased) text pairs', () => {
    fc.assert(
      fc.property(biasedText, biasedText, (a, b) => {
        const score = overlapCoefficient(
          buildFingerprint(a).shingleHashes,
          buildFingerprint(b).shingleHashes,
        );
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(1);
      }),
    );
  });

  it('is symmetric: overlapCoefficient(a, b) === overlapCoefficient(b, a)', () => {
    fc.assert(
      fc.property(biasedText, biasedText, (a, b) => {
        const ha = buildFingerprint(a).shingleHashes;
        const hb = buildFingerprint(b).shingleHashes;
        expect(overlapCoefficient(ha, hb)).toBe(overlapCoefficient(hb, ha));
      }),
    );
  });

  it('is exactly 1 for identical non-empty input, including symbol-only/emoji-only/lone-surrogate text — the "reaches something meaningful for identical input" property', () => {
    // Every non-empty text yields at least one shingle: normalize()'s
    // word-shingling path handles ordinary text, and charShingles()'s
    // fallback (fingerprint.ts) guarantees a non-empty shingle set even for
    // text that normalizes to zero words — see its own doc comment for the
    // GAPS.md #8 bug this fallback fixed. Only the truly EMPTY string
    // produces zero shingles either way, hence the length filter below.
    fc.assert(
      fc.property(
        biasedText.filter((text) => text.length > 0),
        (text) => {
          const hashes = buildFingerprint(text).shingleHashes;
          expect(overlapCoefficient(hashes, hashes)).toBe(1);
        },
      ),
    );
  });

  it('scores a substring embedded verbatim in a larger document as nonzero overlap with its container — the containment property the module doc comment explicitly claims', () => {
    // The embedded substring is generated with >= SHINGLE_WIDTH (5) words
    // specifically so BOTH the substring alone and the full container use
    // the same effective shingle width (wordShingles()'s width-narrowing
    // only kicks in below SHINGLE_WIDTH words — see its own doc comment).
    // A substring narrow enough to trigger that narrowing when embedded in
    // a much longer document is GAPS.md #8's own documented, still-OPEN
    // false-negative case ("a short excerpt... embedded verbatim in a MUCH
    // longer document... still shares no shingle string with it") — this
    // property is about the guarantee the module doc comment claims it
    // provides, not a claim that the open gap is secretly fixed.
    fc.assert(
      fc.property(
        fc.array(word, { minLength: 0, maxLength: 8 }), // prefix words
        fc.array(word, { minLength: 5, maxLength: 12 }), // the embedded substring
        fc.array(word, { minLength: 0, maxLength: 8 }), // suffix words
        (prefixWords, subWords, suffixWords) => {
          const subText = subWords.join(' ');
          const containerText = [...prefixWords, ...subWords, ...suffixWords].join(' ');
          const subHashes = buildFingerprint(subText).shingleHashes;
          const containerHashes = buildFingerprint(containerText).shingleHashes;
          expect(overlapCoefficient(containerHashes, subHashes)).toBeGreaterThan(0);
        },
      ),
    );
  });
});
