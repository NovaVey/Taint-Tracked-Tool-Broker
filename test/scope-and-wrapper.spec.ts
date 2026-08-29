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
    const t = wrapTainted({ x: 1 } as Record<string, number>, 'DERIVED_UNTRUSTED', [tag('a')]);
    const result = spreadTainted({ y: 2 } as Record<string, number>, t);
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
});
