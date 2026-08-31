/**
 * An opt-in, faster alternative to the default `structuredClone`-based args
 * cloner (`BrokerOptions.cloneArgs`, GAPS.md #16). `dispatch()` clones args
 * at least twice per executed call, by design, so the approved/audited/
 * executed argument copies can never silently diverge — a real,
 * args-size-proportional cost paid on every gated call. `structuredClone`
 * runs Node's general structured-clone algorithm (cycle detection, support
 * for Map/Set/Date/RegExp/ArrayBuffer/typed arrays/...) even though
 * realistic LLM tool-call args are overwhelmingly plain JSON — see
 * `bench/args-clone.ts` for the actual numbers this claim is based on.
 *
 * This clones ONLY plain objects, arrays, and JSON-safe primitives
 * (string/number/boolean/null/undefined) — anything else (functions,
 * class instances, Date, Map, Set, RegExp, symbols, bigints) throws rather
 * than silently misrepresenting it. This matters concretely: naively
 * recursing into a `Date` with `Object.keys()` would silently produce an
 * empty `{}` (a `Date`'s actual time value isn't an enumerable own
 * property) instead of erroring or preserving it — exactly the kind of
 * silent-degradation bug GAPS.md #16 already closed once for the default
 * cloner. Fail loud instead, consistent with that fix: a tool whose args
 * need one of these types should keep the default `structuredClone`-based
 * cloner, or supply its own `cloneArgs`.
 *
 * A circular plain object/array is handled the same way: `structuredClone`
 * supports cycles (it preserves reference identity in its clone), but this
 * module always produces a fresh, fully independent copy, so a cycle has no
 * representable result here. Rather than recursing forever into one and
 * crashing with an undocumented `RangeError` (stack overflow), a WeakSet-
 * based guard (the same pattern `taint/scan.ts` uses for the same reason)
 * detects the cycle and throws the same kind of clean, typed `TypeError`
 * this module throws for every other unsupported input.
 */

function isPlainObject(value: object): boolean {
  // Object.getPrototypeOf's lib.d.ts return type is `any` — assert its
  // genuine runtime return type explicitly rather than letting that `any`
  // flow through unchecked.
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

export function jsonSafeClone(value: unknown): unknown {
  return cloneWithCycleGuard(value, new WeakSet<object>());
}

/**
 * `jsonSafeClone`'s recursive worker. Takes an extra `ancestors` set —
 * plain objects/arrays currently on the path from the root down to `value`,
 * not "every node visited so far" — so that the SAME object reachable via
 * two independent, non-circular paths (e.g. `{ a: shared, b: shared }`)
 * still clones fine (it's just cloned twice, same as any other duplicate
 * value), while an object that reappears as its OWN descendant is caught.
 *
 * Unlike `structuredClone`, which supports cycles by preserving reference
 * identity in the clone, `jsonSafeClone` always produces a fresh, fully
 * independent copy (see the header comment) — there is no cyclic shape it
 * could represent. Left unguarded, a cyclic plain object or array would
 * recurse until the JS call stack overflows: an undocumented `RangeError`,
 * not the clean, typed rejection this module promises for everything else
 * it doesn't support. A tool whose args are genuinely cyclic needs the
 * default `structuredClone`-based cloner (or its own `cloneArgs`), same as
 * for the other unsupported types this module rejects above.
 */
function cloneWithCycleGuard(value: unknown, ancestors: WeakSet<object>): unknown {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return value;
  if (t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new TypeError(`jsonSafeClone: cannot clone a value of type "${t}".`);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) {
      throw new TypeError(
        'jsonSafeClone: cannot clone a circular array — the value contains itself, directly or through a nested ' +
          'object/array. jsonSafeClone always produces a fresh, fully independent copy, so a cycle has no representable ' +
          'result (unlike structuredClone, which preserves cyclic reference identity in its clone). Use the default ' +
          'structuredClone-based cloneArgs, or your own, for cyclic values.',
      );
    }
    ancestors.add(value);
    const out = value.map((item) => cloneWithCycleGuard(item, ancestors));
    ancestors.delete(value);
    return out;
  }
  if (!isPlainObject(value)) {
    const ctorName = (value as { constructor?: { name?: string } }).constructor?.name ?? 'unknown';
    throw new TypeError(
      `jsonSafeClone: cannot clone a non-plain object (a "${ctorName}" instance) — only plain objects, arrays, and ` +
        'JSON-safe primitives are supported. Use the default structuredClone-based cloneArgs, or your own, for this type.',
    );
  }
  if (ancestors.has(value)) {
    throw new TypeError(
      'jsonSafeClone: cannot clone a circular object — the value contains itself, directly or through a nested ' +
        'object/array. jsonSafeClone always produces a fresh, fully independent copy, so a cycle has no representable ' +
        'result (unlike structuredClone, which preserves cyclic reference identity in its clone). Use the default ' +
        'structuredClone-based cloneArgs, or your own, for cyclic values.',
    );
  }
  ancestors.add(value);
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    out[key] = cloneWithCycleGuard((value as Record<string, unknown>)[key], ancestors);
  }
  ancestors.delete(value);
  return out;
}
