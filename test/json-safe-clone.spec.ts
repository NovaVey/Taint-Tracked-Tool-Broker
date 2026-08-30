import { describe, expect, it } from 'vitest';
import { createBroker, jsonSafeClone, NonCloneableArgsError, type ToolExecutor } from '../src/index.js';

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

  it('accepts an object created with Object.create(null) (no prototype) as a plain object', () => {
    const bare = Object.create(null) as Record<string, unknown>;
    bare.x = 1;
    expect(jsonSafeClone(bare)).toEqual({ x: 1 });
  });

  it('works end-to-end as a custom cloneArgs, and still fails loud (NonCloneableArgsError) on a type it rejects', async () => {
    const shellExec: ToolExecutor = { name: 'shell_exec', capabilities: { capabilities: ['exec:shell'] }, async execute(args) { return `ran: ${JSON.stringify(args)}`; } };
    const broker = createBroker({ cloneArgs: jsonSafeClone });
    broker.register(shellExec);

    // A normal, JSON-safe call works exactly as with the default cloneArgs
    // (CLEAN scope + EXEC is an unconditional ALLOW — nothing to do with
    // cloning either way).
    await expect(broker.call('shell_exec', { cmd: 'echo hi' })).resolves.toContain('ran:');
    // A non-JSON-safe arg surfaces as NonCloneableArgsError, same contract as structuredClone throwing.
    await expect(broker.call('shell_exec', { cmd: 'x', when: new Date() })).rejects.toBeInstanceOf(NonCloneableArgsError);
  });
});
