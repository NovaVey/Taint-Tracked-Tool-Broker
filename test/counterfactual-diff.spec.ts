import { describe, expect, it } from 'vitest';
import { ArgsTooDeepError, diffProposedArgs } from '../src/index.js';

describe('diffProposedArgs', () => {
  it('returns no diffs for two identical plain-object trees', () => {
    expect(
      diffProposedArgs(
        { to: 'a@example.com', body: 'hi', n: 3 },
        { to: 'a@example.com', body: 'hi', n: 3 },
      ),
    ).toEqual([]);
  });

  it('reports a top-level primitive change with the bare key as path', () => {
    expect(diffProposedArgs({ cmd: 'ls' }, { cmd: 'rm -rf /' })).toEqual([
      { path: 'cmd', actual: 'ls', counterfactual: 'rm -rf /' },
    ]);
  });

  it('reports a nested change with a dotted path', () => {
    expect(diffProposedArgs({ body: { text: 'a' } }, { body: { text: 'b' } })).toEqual([
      { path: 'body.text', actual: 'a', counterfactual: 'b' },
    ]);
  });

  it('reports an array-index change with a bracketed path', () => {
    expect(diffProposedArgs({ items: ['a', 'b'] }, { items: ['a', 'c'] })).toEqual([
      { path: 'items[1]', actual: 'b', counterfactual: 'c' },
    ]);
  });

  it('reports only the deepest divergence, not every ancestor object/array along the way', () => {
    const diffs = diffProposedArgs(
      { outer: { inner: { leaf: 1 }, other: 'x' } },
      { outer: { inner: { leaf: 2 }, other: 'x' } },
    );
    expect(diffs).toEqual([{ path: 'outer.inner.leaf', actual: 1, counterfactual: 2 }]);
  });

  it('a key present on one side only is reported with the missing side as undefined', () => {
    expect(diffProposedArgs({ a: 1, b: 2 }, { a: 1 })).toEqual([
      { path: 'b', actual: 2, counterfactual: undefined },
    ]);
    expect(diffProposedArgs({ a: 1 }, { a: 1, b: 2 })).toEqual([
      { path: 'b', actual: undefined, counterfactual: 2 },
    ]);
  });

  it('an array with a different length is reported at the extra index(es), not as one whole-array diff', () => {
    expect(diffProposedArgs({ items: ['a'] }, { items: ['a', 'b'] })).toEqual([
      { path: 'items[1]', actual: undefined, counterfactual: 'b' },
    ]);
  });

  it('a value present at one path but shaped differently (array vs object) is one diff at that path, not descended into', () => {
    expect(diffProposedArgs({ x: ['a', 'b'] }, { x: { a: 1 } })).toEqual([
      { path: 'x', actual: ['a', 'b'], counterfactual: { a: 1 } },
    ]);
  });

  it('treats null and undefined as distinct leaf values', () => {
    expect(diffProposedArgs({ x: null }, { x: undefined })).toEqual([
      { path: 'x', actual: null, counterfactual: undefined },
    ]);
    expect(diffProposedArgs({ x: null }, { x: null })).toEqual([]);
  });

  it('treats NaN as equal to itself (Object.is semantics), unlike ===', () => {
    expect(diffProposedArgs({ x: NaN }, { x: NaN })).toEqual([]);
  });

  it('multiple independent divergences are all reported', () => {
    const diffs = diffProposedArgs({ a: 1, b: 2, c: 3 }, { a: 1, b: 20, c: 30 });
    expect(diffs).toEqual(
      expect.arrayContaining([
        { path: 'b', actual: 2, counterfactual: 20 },
        { path: 'c', actual: 3, counterfactual: 30 },
      ]),
    );
    expect(diffs).toHaveLength(2);
  });

  it('is cycle-safe on a self-referential actual tree — does not recurse forever', () => {
    const actual: Record<string, unknown> = { x: 1 };
    actual.self = actual;
    expect(() => diffProposedArgs(actual, { x: 1, self: {} })).not.toThrow();
  });

  it('is cycle-safe when BOTH sides are (independently) self-referential', () => {
    const actual: Record<string, unknown> = { x: 1 };
    actual.self = actual;
    const counterfactual: Record<string, unknown> = { x: 2 };
    counterfactual.self = counterfactual;
    const diffs = diffProposedArgs(actual, counterfactual);
    expect(diffs).toContainEqual({ path: 'x', actual: 1, counterfactual: 2 });
  });

  it('throws a clean, catchable ArgsTooDeepError instead of overflowing the call stack on a pathologically deep tree', () => {
    let deepActual: unknown = 'bottom';
    let deepCounterfactual: unknown = 'different';
    for (let i = 0; i < 10_000; i++) {
      deepActual = { nested: deepActual };
      deepCounterfactual = { nested: deepCounterfactual };
    }
    expect(() => diffProposedArgs(deepActual, deepCounterfactual)).toThrow(ArgsTooDeepError);
  });

  it('does not reject an ordinary, realistically-nested tree', () => {
    let a: unknown = 'bottom';
    let b: unknown = 'bottom';
    for (let i = 0; i < 50; i++) {
      a = { nested: a };
      b = { nested: b };
    }
    expect(() => diffProposedArgs(a, b)).not.toThrow();
  });

  it('compares two Date instances by time value, not by silently treating them as structurally equal empty objects', () => {
    const a = new Date('2024-01-01T00:00:00.000Z');
    const bSame = new Date('2024-01-01T00:00:00.000Z');
    const bDifferent = new Date('2025-01-01T00:00:00.000Z');
    expect(diffProposedArgs({ at: a }, { at: bSame })).toEqual([]);
    expect(diffProposedArgs({ at: a }, { at: bDifferent })).toEqual([
      { path: 'at', actual: a, counterfactual: bDifferent },
    ]);
  });

  it('compares two RegExp instances by source+flags, not by silently treating them as structurally equal empty objects', () => {
    expect(diffProposedArgs({ pattern: /abc/gi }, { pattern: /abc/gi })).toEqual([]);
    expect(diffProposedArgs({ pattern: /abc/gi }, { pattern: /abc/g })).toEqual([
      { path: 'pattern', actual: /abc/gi, counterfactual: /abc/g },
    ]);
    expect(diffProposedArgs({ pattern: /abc/g }, { pattern: /xyz/g })).toEqual([
      { path: 'pattern', actual: /abc/g, counterfactual: /xyz/g },
    ]);
  });

  it('falls back to reference equality for a non-plain, non-Date/RegExp object (e.g. a class instance with no custom toString) — different instances are reported as different even with equivalent content, never silently treated as equal', () => {
    class Box {
      constructor(public n: number) {}
    }
    const b1 = new Box(1);
    const b2 = new Box(1); // same content, different instance
    expect(diffProposedArgs({ box: b1 }, { box: b1 })).toEqual([]); // same reference -> equal
    expect(diffProposedArgs({ box: b1 }, { box: b2 })).toEqual([
      { path: 'box', actual: b1, counterfactual: b2 },
    ]);
  });

  it('a plain object on one side and a non-plain object (e.g. a Date) on the other is reported as different, regardless of which side is which', () => {
    const date = new Date('2024-01-01T00:00:00.000Z');
    expect(diffProposedArgs({ at: {} }, { at: date })).toEqual([
      { path: 'at', actual: {}, counterfactual: date },
    ]);
    expect(diffProposedArgs({ at: date }, { at: {} })).toEqual([
      { path: 'at', actual: date, counterfactual: {} },
    ]);
  });

  it('two completely identical trees at the root produce no diffs at all, including for primitives at the root', () => {
    expect(diffProposedArgs('same', 'same')).toEqual([]);
    expect(diffProposedArgs(42, 43)).toEqual([{ path: '', actual: 42, counterfactual: 43 }]);
  });
});
