import { describe, expect, it } from 'vitest';
import {
  concatTainted,
  createScope,
  declassifyScope,
  isTaintedValue,
  mapTainted,
  markPrivateDataSeen,
  maxLevel,
  raiseWatermark,
  spreadTainted,
  taintAwareJSONStringify,
  unwrap,
  wrapTainted,
  type ProvenanceTag,
} from '../src/index.js';

function tag(id: string): ProvenanceTag {
  return { id, sourceCallId: `call-${id}`, toolName: 'fetch_url', sessionId: 's', capturedAt: 0 };
}

describe('maxLevel', () => {
  it('is a total order: CLEAN < DERIVED_UNTRUSTED < RAW_UNTRUSTED', () => {
    expect(maxLevel('CLEAN', 'DERIVED_UNTRUSTED')).toBe('DERIVED_UNTRUSTED');
    expect(maxLevel('DERIVED_UNTRUSTED', 'RAW_UNTRUSTED')).toBe('RAW_UNTRUSTED');
    expect(maxLevel('RAW_UNTRUSTED', 'CLEAN')).toBe('RAW_UNTRUSTED');
    expect(maxLevel('CLEAN', 'CLEAN')).toBe('CLEAN');
  });
});

describe('taint/scope', () => {
  it('raiseWatermark is monotonic — never lowers the level', () => {
    const scope = createScope('session', 's');
    raiseWatermark(scope, 'RAW_UNTRUSTED', tag('a'));
    raiseWatermark(scope, 'DERIVED_UNTRUSTED', tag('b'));
    expect(scope.watermark.level).toBe('RAW_UNTRUSTED');
    expect(scope.watermark.sources.map((t) => t.id)).toEqual(['a', 'b']);
  });

  it('markPrivateDataSeen only ever sets the flag true', () => {
    const scope = createScope('session', 's');
    markPrivateDataSeen(scope);
    expect(scope.watermark.privateDataSeen).toBe(true);
  });

  it('declassifyScope is the only thing that lowers the watermark', () => {
    const scope = createScope('session', 's');
    raiseWatermark(scope, 'RAW_UNTRUSTED', tag('a'));
    markPrivateDataSeen(scope);
    declassifyScope(scope);
    expect(scope.watermark).toEqual({ level: 'CLEAN', privateDataSeen: false, sources: [] });
  });
});

describe('taint/wrapper (Layer 1)', () => {
  it('wrapTainted / isTaintedValue / unwrap round-trip', () => {
    const w = wrapTainted('hello', 'RAW_UNTRUSTED', [tag('a')]);
    expect(isTaintedValue(w)).toBe(true);
    expect(isTaintedValue('plain string')).toBe(false);
    expect(unwrap(w)).toBe('hello');
    expect(unwrap('plain')).toBe('plain');
  });

  it('concatTainted unions level and dedupes sources', () => {
    const a = wrapTainted('foo ', 'DERIVED_UNTRUSTED', [tag('a')]);
    const b = wrapTainted('bar', 'RAW_UNTRUSTED', [tag('a'), tag('b')]);
    const result = concatTainted(a, b, ' baz');
    expect(result.value).toBe('foo bar baz');
    expect(result.level).toBe('RAW_UNTRUSTED');
    expect(result.sources.map((t) => t.id)).toEqual(['a', 'b']);
  });

  it('concatTainted with only plain strings stays CLEAN', () => {
    const result = concatTainted('a', 'b', 'c');
    expect(result.value).toBe('abc');
    expect(result.level).toBe('CLEAN');
    expect(result.sources).toEqual([]);
  });

  it('taintAwareJSONStringify unions taint across nested tainted leaves', () => {
    const tainted = wrapTainted('secret', 'RAW_UNTRUSTED', [tag('a')]);
    const result = taintAwareJSONStringify({ a: 1, b: tainted, c: [tainted] });
    expect(JSON.parse(result.value)).toEqual({ a: 1, b: 'secret', c: ['secret'] });
    expect(result.level).toBe('RAW_UNTRUSTED');
  });

  it('spreadTainted merges objects and unions taint', () => {
    // The cast looks unnecessary in isolation (wrapTainted's parameter type
    // doesn't require it), but removing it narrows T from Record<string,
    // number> to the literal type { x: number }, which then makes the next
    // line's { y: 2 } fail TypeScript's excess-property check against
    // spreadTainted's inferred generic — a real cross-line interaction the
    // rule's single-assertion analysis can't see. Verified: removing this
    // breaks `npm run typecheck`.
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-type-assertion
    const t = wrapTainted({ x: 1 } as Record<string, number>, 'DERIVED_UNTRUSTED', [tag('a')]);
    const result = spreadTainted({ y: 2 }, t);
    expect(result.value).toEqual({ y: 2, x: 1 });
    expect(result.level).toBe('DERIVED_UNTRUSTED');
  });

  it('mapTainted carries the source array taint onto the mapped result', () => {
    const arr = wrapTainted([1, 2, 3], 'RAW_UNTRUSTED', [tag('a')]);
    const result = mapTainted(arr, (x) => x * 2);
    expect(result.value).toEqual([2, 4, 6]);
    expect(result.level).toBe('RAW_UNTRUSTED');
  });

  it('mapTainted over a plain (untainted) array stays CLEAN', () => {
    const result = mapTainted([1, 2], (x) => x + 1);
    expect(result.value).toEqual([2, 3]);
    expect(result.level).toBe('CLEAN');
  });

  it('mapTainted aggregates taint from individually-wrapped elements, not just an outer-wrapped array', () => {
    // The exact reproduction from the confirmed finding: a plain array
    // (not itself a TaintedValue) whose ELEMENTS are each individually
    // wrapTainted(). Before the fix, mapTainted only ever checked whether
    // the outer array was a TaintedValue and silently fell back to
    // level: 'CLEAN', sources: [] here, even though the mapped output is
    // plainly derived from RAW_UNTRUSTED content.
    const evil = wrapTainted('evil', 'RAW_UNTRUSTED', [tag('a')]);
    const benign = wrapTainted('benign', 'CLEAN', []);
    const result = mapTainted([evil, benign], (item) => item.value.toUpperCase());
    expect(result.value).toEqual(['EVIL', 'BENIGN']);
    expect(result.level).toBe('RAW_UNTRUSTED');
    expect(result.sources.map((t) => t.id)).toEqual(['a']);
  });

  it("mapTainted unions an outer-wrapped array's taint with its individually-wrapped elements' taint", () => {
    const outer = wrapTainted(
      [wrapTainted('x', 'DERIVED_UNTRUSTED', [tag('outer')])],
      'RAW_UNTRUSTED',
      [tag('a')],
    );
    const result = mapTainted(outer, (item) => item.value);
    expect(result.value).toEqual(['x']);
    expect(result.level).toBe('RAW_UNTRUSTED');
    expect(result.sources.map((t) => t.id)).toEqual(['a', 'outer']);
  });

  it('taintAwareJSONStringify preserves a Date the same way plain JSON.stringify does, instead of corrupting it to {}', () => {
    const when = new Date('2020-01-01T00:00:00.000Z');
    const result = taintAwareJSONStringify({ when });
    expect(result.value).toBe(JSON.stringify({ when }));
    expect(JSON.parse(result.value)).toEqual({ when: '2020-01-01T00:00:00.000Z' });
  });

  it('taintAwareJSONStringify still unions taint for a tainted leaf alongside a Date sibling', () => {
    const tainted = wrapTainted('secret', 'RAW_UNTRUSTED', [tag('a')]);
    const when = new Date('2020-01-01T00:00:00.000Z');
    const result = taintAwareJSONStringify({ when, secret: tainted });
    expect(JSON.parse(result.value)).toEqual({
      when: '2020-01-01T00:00:00.000Z',
      secret: 'secret',
    });
    expect(result.level).toBe('RAW_UNTRUSTED');
  });

  it('taintAwareJSONStringify throws rather than silently dropping taint hidden inside a Map or Set', () => {
    const tainted = wrapTainted('secret', 'RAW_UNTRUSTED', [tag('a')]);
    expect(() => taintAwareJSONStringify({ m: new Map([['k', tainted]]) })).toThrow(TypeError);
    expect(() => taintAwareJSONStringify({ s: new Set([tainted]) })).toThrow(TypeError);
  });
});
