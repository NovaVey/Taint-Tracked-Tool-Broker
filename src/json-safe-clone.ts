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
 */

function isPlainObject(value: object): boolean {
  // Object.getPrototypeOf's lib.d.ts return type is `any` — assert its
  // genuine runtime return type explicitly rather than letting that `any`
  // flow through unchecked.
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

export function jsonSafeClone(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return value;
  if (t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new TypeError(`jsonSafeClone: cannot clone a value of type "${t}".`);
  }
  if (Array.isArray(value)) return value.map(jsonSafeClone);
  if (!isPlainObject(value)) {
    const ctorName = (value as { constructor?: { name?: string } }).constructor?.name ?? 'unknown';
    throw new TypeError(
      `jsonSafeClone: cannot clone a non-plain object (a "${ctorName}" instance) — only plain objects, arrays, and ` +
        'JSON-safe primitives are supported. Use the default structuredClone-based cloneArgs, or your own, for this type.',
    );
  }
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value)) {
    out[key] = jsonSafeClone((value as Record<string, unknown>)[key]);
  }
  return out;
}
