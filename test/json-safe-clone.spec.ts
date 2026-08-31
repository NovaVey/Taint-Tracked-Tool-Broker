import { describe, expect, it } from 'vitest';
import {
  createBroker,
  jsonSafeClone,
  NonCloneableArgsError,
  type ToolExecutor,
} from '../src/index.js';

describe('jsonSafeClone', () => {
  it('deep-clones plain objects and arrays — an independent copy, not a shared reference', () => {
    const original = { a: 1, b: { c: [1, 2, { d: 'x' }] } };
    const cloned = jsonSafeClone(original) as typeof original;
    expect(cloned).toEqual(original);
    expect(cloned).not.toBe(original);
    expect(cloned.b).not.toBe(original.b);
    expect(cloned.b.c).not.toBe(original.b.c);
    (cloned.b.c[2] as { d: string }).d = 'mutated';
    expect((original.b.c[2] as { d: string }).d).toBe('x'); // original untouched
  });

  it('passes through JSON-safe primitives, null, and undefined unchanged', () => {
    expect(jsonSafeClone('x')).toBe('x');
    expect(jsonSafeClone(42)).toBe(42);
    expect(jsonSafeClone(true)).toBe(true);
    expect(jsonSafeClone(null)).toBeNull();
    expect(jsonSafeClone(undefined)).toBeUndefined();
  });

  it('clones an object containing undefined-valued properties without dropping them (unlike JSON.stringify)', () => {
    const cloned = jsonSafeClone({ a: 1, b: undefined }) as { a: number; b: unknown };
    expect('b' in cloned).toBe(true);
    expect(cloned.b).toBeUndefined();
  });

  it('throws on a function, symbol, or bigint — types that cannot round-trip as JSON', () => {
    expect(() => jsonSafeClone(() => {})).toThrow(TypeError);
    expect(() => jsonSafeClone(Symbol('x'))).toThrow(TypeError);
    expect(() => jsonSafeClone(10n)).toThrow(TypeError);
  });

  it('throws on a Date, rather than silently producing an empty {} (Date has no enumerable own properties)', () => {
    expect(() => jsonSafeClone(new Date())).toThrow(TypeError);
  });

  it('throws on Map, Set, RegExp, and other non-plain-object instances', () => {
    expect(() => jsonSafeClone(new Map())).toThrow(TypeError);
    expect(() => jsonSafeClone(new Set())).toThrow(TypeError);
    expect(() => jsonSafeClone(/x/)).toThrow(TypeError);
    class Custom {}
    expect(() => jsonSafeClone(new Custom())).toThrow(TypeError);
  });

  it('throws on a nested non-plain value, not just a top-level one', () => {
    expect(() => jsonSafeClone({ ok: 1, bad: new Date() })).toThrow(TypeError);
    expect(() => jsonSafeClone([1, 2, () => {}])).toThrow(TypeError);
  });

  it('throws a TypeError (not an uncaught RangeError) on a self-referential plain object, rather than recursing forever', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    expect(() => jsonSafeClone(obj)).toThrow(TypeError);
    expect(() => jsonSafeClone(obj)).not.toThrow(RangeError);
  });

  it('throws a TypeError (not an uncaught RangeError) on a self-referential array, rather than recursing forever', () => {
    const arr: unknown[] = [1, 2];
    arr.push(arr);
    expect(() => jsonSafeClone(arr)).toThrow(TypeError);
    expect(() => jsonSafeClone(arr)).not.toThrow(RangeError);
  });

  it('throws a TypeError on a cycle reached indirectly through nested objects/arrays, not just a direct self-reference', () => {
    const inner: Record<string, unknown> = {};
    const outer = { a: [1, { b: inner }] };
    inner.backToOuter = outer;
    expect(() => jsonSafeClone(outer)).toThrow(TypeError);
  });

  it('does NOT treat the same object reachable via two independent (non-circular) paths as a cycle', () => {
    const shared = { x: 1 };
    const value = { a: shared, b: shared };
    const cloned = jsonSafeClone(value) as { a: { x: number }; b: { x: number } };
    expect(cloned).toEqual({ a: { x: 1 }, b: { x: 1 } });
    // Not reference-preserving (jsonSafeClone always makes independent copies) — just not a cycle error either.
    expect(cloned.a).not.toBe(cloned.b);
  });

  it('accepts an object created with Object.create(null) (no prototype) as a plain object', () => {
    const bare = Object.create(null) as Record<string, unknown>;
    bare.x = 1;
    expect(jsonSafeClone(bare)).toEqual({ x: 1 });
  });

  it('faithfully clones an own, enumerable property literally named "__proto__" instead of corrupting the clone\'s actual prototype — found by test/json-safe-clone.property.spec.ts', () => {
    // Computed-property syntax, not the `__proto__:` object-literal
    // shorthand: this creates a genuine OWN data property named
    // "__proto__" on `original` (Object.keys(original) includes it), as
    // opposed to `{ __proto__: { poisoned: true } }`, which would set
    // original's actual prototype and create no own property at all. Only
    // the computed-property form reaches the buggy code path: the clone
    // loop's `Object.keys()` walk sees "__proto__" as an ordinary key to
    // copy, and a plain `out[key] = value` bracket assignment on the
    // FRESH output object then hits Object.prototype's inherited
    // `__proto__` accessor setter (since `out` has no own "__proto__"
    // property yet to shadow it) — silently reassigning the clone's real
    // prototype to the cloned value instead of creating an own property.
    const original: Record<string, unknown> = {};
    Object.defineProperty(original, '__proto__', {
      value: { poisoned: true },
      writable: true,
      enumerable: true,
      configurable: true,
    });
    expect(Object.keys(original)).toEqual(['__proto__']);

    const cloned = jsonSafeClone(original) as Record<string, unknown>;

    // The pre-fix bug: `cloned`'s actual prototype became `{ poisoned:
    // true }` (an object with no Object.prototype methods of its own, and
    // Object.keys(cloned) empty since the "__proto__" key was consumed by
    // the prototype-set instead of becoming an own property) rather than
    // faithfully copying the key. Both assertions below fail against the
    // pre-fix code (Object.getPrototypeOf(cloned) !== Object.prototype,
    // and Object.keys(cloned) is [] not ['__proto__']) and pass now that
    // Object.defineProperty is used for every key, "__proto__" included.
    expect(Object.getPrototypeOf(cloned)).toBe(Object.prototype);
    expect(Object.keys(cloned)).toEqual(['__proto__']);
    expect(cloned['__proto__']).toEqual({ poisoned: true });
    // The cloned value under that key is itself a fresh, independent copy
    // — the same invariant every other key already gets.
    expect(cloned['__proto__']).not.toBe(original['__proto__']);
  });

  it('works end-to-end as a custom cloneArgs, and still fails loud (NonCloneableArgsError) on a type it rejects', async () => {
    const shellExec: ToolExecutor = {
      name: 'shell_exec',
      capabilities: { capabilities: ['exec:shell'] },
      async execute(args) {
        return `ran: ${JSON.stringify(args)}`;
      },
    };
    const broker = createBroker({ cloneArgs: jsonSafeClone });
    broker.register(shellExec);

    // A normal, JSON-safe call works exactly as with the default cloneArgs
    // (CLEAN scope + EXEC is an unconditional ALLOW — nothing to do with
    // cloning either way).
    await expect(broker.call('shell_exec', { cmd: 'echo hi' })).resolves.toContain('ran:');
    // A non-JSON-safe arg surfaces as NonCloneableArgsError, same contract as structuredClone throwing.
    await expect(broker.call('shell_exec', { cmd: 'x', when: new Date() })).rejects.toBeInstanceOf(
      NonCloneableArgsError,
    );
  });
});
