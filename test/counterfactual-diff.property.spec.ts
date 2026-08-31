import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { diffProposedArgs } from '../src/index.js';

/**
 * Property-based regression coverage for counterfactual-diff.ts, in the
 * same spirit as fingerprint.property.spec.ts and
 * json-safe-clone.property.spec.ts (see fingerprint.property.spec.ts's
 * header for the full rationale — GAPS.md #8, two shipped Unicode/
 * invariant-violation bugs found by adversarial review, not the test
 * suite). `diffProposedArgs()` makes a load-bearing "never a false
 * negative" promise (see its own `leafEqual` doc comment): a real
 * divergence between `actual` and `counterfactual` must always show up as
 * an `ArgDiff`. The narrowest possible witness of that promise holding is
 * its own converse — REFLEXIVITY: comparing a tree against itself, or
 * against a genuinely independent structural copy of itself, must never
 * spuriously report a diff. `test/counterfactual-diff.spec.ts` pins this
 * (and the "never a false negative" direction) with a handful of hand-built
 * example trees; this file sweeps a much wider, deliberately
 * Unicode-bug-class-biased space of generated JSON-safe trees
 * (`fc.jsonValue()`) through exactly the reflexivity property, on the same
 * theory as the other two property-test files: a narrow invariant violation
 * nobody hand-wrote an example for is exactly this project's proven,
 * twice-shipped failure mode.
 *
 * Uses plain `fc.assert(fc.property(...))` inside ordinary vitest `it()`
 * blocks — fast-check's own first-class integration point — so these run
 * inside the normal `npm test` output.
 */

/** A single lone high (D800-DBFF) or low (DC00-DFFF) UTF-16 surrogate code unit, as its own one-character string. Same construction as fingerprint.property.spec.ts. */
const loneHighSurrogateUnit = fc
  .integer({ min: 0xd800, max: 0xdbff })
  .map((codeUnit) => String.fromCharCode(codeUnit));
const loneLowSurrogateUnit = fc
  .integer({ min: 0xdc00, max: 0xdfff })
  .map((codeUnit) => String.fromCharCode(codeUnit));
const asciiFiller = fc.string({ unit: 'grapheme-ascii', maxLength: 6 });
/** A string with one deliberately-embedded lone surrogate — see fingerprint.property.spec.ts's identically-named arbitrary for why this construction (rather than plain fc.string()) is needed to reliably hit this input class at all. */
const stringWithLoneSurrogate = fc
  .tuple(asciiFiller, fc.oneof(loneHighSurrogateUnit, loneLowSurrogateUnit), asciiFiller)
  .map(([pre, lone, post]) => pre + lone + post);

/** A string made entirely of punctuation/symbol characters. */
const symbolOnlyString = fc
  .array(fc.constantFrom(...'!@#$%^&*()_+-=[]{}|;:,.<>?/~`"\'\\'.split('')), {
    minLength: 1,
    maxLength: 20,
  })
  .map((chars) => chars.join(''));

/** A string made entirely of emoji, including a multi-code-point ZWJ sequence. */
const emojiOnlyString = fc
  .array(fc.constantFrom('😀', '🚀', '✅', '👍', '🔥', '👨‍👩‍👧‍👦'), {
    minLength: 1,
    maxLength: 8,
  })
  .map((chars) => chars.join(''));

/** Whitespace-only, including empty. */
const whitespaceOnlyString = fc
  .array(fc.constantFrom(' ', '\t', '\n', '\r'), { minLength: 0, maxLength: 12 })
  .map((chars) => chars.join(''));

/**
 * `diffProposedArgs()` never inspects a string's Unicode structure — its
 * leaf comparison is `Object.is` (see `leafEqual`'s doc comment) — so none
 * of these bias classes is expected to trip a diffing-specific bug the way
 * they tripped fingerprint.ts's normalize()/exactHash(). They're included
 * as candidate LEAF VALUES anyway, per this project's standing rule of
 * biasing generated text toward its two proven bug classes rather than
 * assuming a general-purpose string arbitrary already covers them well: if
 * a future change ever makes this module Unicode-aware (e.g. a
 * normalized-string-comparison mode), this coverage is already in place
 * without needing to be added retroactively.
 */
const biasedLeafString = fc.oneof(
  { weight: 2, arbitrary: stringWithLoneSurrogate },
  { weight: 2, arbitrary: symbolOnlyString },
  { weight: 2, arbitrary: emojiOnlyString },
  { weight: 1, arbitrary: whitespaceOnlyString },
);

/**
 * A bounded-depth JSON-safe value: boolean / finite-number / null / string
 * (ordinary or bug-class-biased) at the leaves, arrays and plain objects
 * (`fc.dictionary`) as containers. Hand-rolled via plain recursion — rather
 * than this installed fast-check version's own `fc.jsonValue()`, whose
 * `JsonSharedConstraints` type has no hook for injecting extra leaf
 * arbitraries (only `stringUnit`, which replaces the string generator
 * wholesale rather than adding to it) — specifically so the bug-class-
 * biased strings above can appear ALONGSIDE ordinary generated values as
 * leaves, not instead of them. `depth` bounds recursion explicitly (no
 * reliance on fast-check's own depth-biasing machinery) — small enough to
 * keep the generated trees a realistic tool-call-argument size, large
 * enough to exercise real nesting through both `diffProposedArgs()`'s
 * object and array branches.
 */
function biasedJsonArbitrary(depth: number): fc.Arbitrary<unknown> {
  const leaf = fc.oneof(
    fc.boolean(),
    fc.integer(),
    fc.double({ noNaN: true, noDefaultInfinity: true }),
    fc.constant(null),
    fc.string(),
    biasedLeafString,
  );
  if (depth <= 0) return leaf;
  const container = fc.oneof(
    fc.array(biasedJsonArbitrary(depth - 1), { maxLength: 5 }),
    fc.dictionary(fc.string(), biasedJsonArbitrary(depth - 1), { maxKeys: 5 }),
  );
  return fc.oneof({ weight: 2, arbitrary: leaf }, { weight: 1, arbitrary: container });
}
const biasedJsonValue = biasedJsonArbitrary(3);

describe('diffProposedArgs (property-based)', () => {
  it('is reflexive: diffProposedArgs(x, x) is always empty, for a wide bug-class-biased space of generated JSON-safe trees', () => {
    fc.assert(
      fc.property(biasedJsonValue, (x) => {
        expect(diffProposedArgs(x, x)).toEqual([]);
      }),
    );
  });

  it('is empty for x compared against structuredClone(x) — a genuinely independent structural copy, not the same reference', () => {
    fc.assert(
      fc.property(biasedJsonValue, (x) => {
        const copy = structuredClone(x);
        // Sanity-check the premise of this property: structuredClone must
        // actually have produced an independent copy for object/array `x`,
        // not (by some future refactor) started returning the same
        // reference — otherwise this test would silently degrade into a
        // duplicate of the reflexivity property above instead of testing
        // what it claims to.
        if (x !== null && typeof x === 'object') {
          expect(copy).not.toBe(x);
        }
        expect(diffProposedArgs(x, copy)).toEqual([]);
      }),
    );
  });
});
