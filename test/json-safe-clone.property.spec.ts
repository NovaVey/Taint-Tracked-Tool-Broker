import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { jsonSafeClone } from '../src/index.js';

/**
 * Property-based regression coverage for json-safe-clone.ts, in the same
 * spirit as fingerprint.property.spec.ts (see that file's header for the
 * full rationale — GAPS.md #8, two shipped Unicode/invariant-violation bugs
 * found by adversarial review rather than the test suite). `jsonSafeClone`
 * makes two specific promises about ANY JSON-safe input, stated directly in
 * its own header doc comment: the clone is structurally equal to the
 * original, and it is "a fresh, fully independent copy" — no part of the
 * clone is the SAME object as any part of the input. `test/json-safe-clone.spec.ts`
 * pins both with a handful of hand-built example trees; this file sweeps a
 * much wider space of generated JSON-safe trees (`fc.jsonValue()`) through
 * the exact same two properties, on the theory that an invariant violation
 * this narrow (a specific key shape, nesting depth, or value type nobody
 * happened to hand-write) is exactly the class of bug this project has
 * already shipped twice elsewhere in its Unicode-handling code.
 *
 * Uses plain `fc.assert(fc.property(...))` inside ordinary vitest `it()`
 * blocks — fast-check's own first-class integration point — so these run
 * inside the normal `npm test` output.
 */

/**
 * Collects every object/array reference reachable from `value` (including
 * `value` itself, if it is one) into `out`. Used only by the
 * reference-independence property below, to compare "every object node in
 * the original tree" against "every object node in the cloned tree" as
 * SETS of references, not by re-walking both trees in lockstep (which would
 * have to assume they're shaped identically going in — exactly the thing a
 * cloning bug could violate).
 *
 * `fc.jsonValue()` never produces a cycle (JSON has none), so no cycle
 * guard is needed here for correctness — the `out.has(value)` check exists
 * purely so a DAG-shaped input (the same object reachable via two paths,
 * which `fc.jsonValue()` also never produces, since each generated node is
 * freshly allocated) wouldn't cause redundant work, not because it's load-
 * bearing for this specific arbitrary.
 */
function collectObjectRefs(value: unknown, out: Set<object>): void {
  if (value === null || typeof value !== 'object') return;
  if (out.has(value)) return;
  out.add(value);
  if (Array.isArray(value)) {
    for (const item of value) collectObjectRefs(item, out);
  } else {
    for (const key of Object.keys(value)) {
      collectObjectRefs((value as Record<string, unknown>)[key], out);
    }
  }
}

describe('jsonSafeClone (property-based)', () => {
  it('deep-equals its input for any JSON-safe value', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(jsonSafeClone(value)).toEqual(value);
      }),
    );
  });

  it('never returns a value that is reference-equal to any object/array reachable from the input — "a fresh, fully independent copy" (jsonSafeClone\'s own header doc comment)', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const originalRefs = new Set<object>();
        collectObjectRefs(value, originalRefs);

        const cloned = jsonSafeClone(value);
        const clonedRefs = new Set<object>();
        collectObjectRefs(cloned, clonedRefs);

        for (const ref of clonedRefs) {
          expect(originalRefs.has(ref)).toBe(false);
        }
      }),
    );
  });

  it('is idempotent under re-cloning: cloning the clone produces an equal value, still with no shared references to either the original or the first clone', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        const firstClone = jsonSafeClone(value);
        const secondClone = jsonSafeClone(firstClone);
        expect(secondClone).toEqual(value);

        const firstCloneRefs = new Set<object>();
        collectObjectRefs(firstClone, firstCloneRefs);
        const secondCloneRefs = new Set<object>();
        collectObjectRefs(secondClone, secondCloneRefs);
        for (const ref of secondCloneRefs) {
          expect(firstCloneRefs.has(ref)).toBe(false);
        }
      }),
    );
  });
});
