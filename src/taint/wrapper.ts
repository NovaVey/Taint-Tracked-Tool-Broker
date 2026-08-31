/**
 * Layer 1 — the in-process `TaintedValue<T>` wrapper (DESIGN.md §4.3, §5).
 *
 * Best-effort fast path only. Every helper here degrades silently the
 * moment code uses raw `+`, an untagged template literal, `JSON.stringify`
 * directly, or the moment content passes through an LLM rewrite (a fresh
 * generation shares no object identity with anything). None of that matters
 * for soundness — the scope watermark (taint/scope.ts) already committed
 * before any of those operations could run. This layer exists purely so
 * that code which *does* use these helpers gets cheap, precise,
 * zero-lookup attribution instead of falling through to the Layer 2
 * registry scan in taint/scan.ts.
 */

import type { ProvenanceTag, TaintLevel, TaintedValue } from '../types.js';
import { TAINT_BRAND, maxLevel } from '../types.js';

export function wrapTainted<T>(
  value: T,
  level: TaintLevel,
  sources: ProvenanceTag[],
): TaintedValue<T> {
  return { [TAINT_BRAND]: true, value, level, sources };
}

export function isTaintedValue(x: unknown): x is TaintedValue<unknown> {
  return (
    typeof x === 'object' && x !== null && (x as Record<PropertyKey, unknown>)[TAINT_BRAND] === true
  );
}

export function unwrap<T>(x: T | TaintedValue<T>): T {
  return isTaintedValue(x) ? x.value : x;
}

function mergeSources(...groups: ProvenanceTag[][]): ProvenanceTag[] {
  const seen = new Set<string>();
  const merged: ProvenanceTag[] = [];
  for (const group of groups) {
    for (const tag of group) {
      if (!seen.has(tag.id)) {
        seen.add(tag.id);
        merged.push(tag);
      }
    }
  }
  return merged;
}

/** Concatenates strings (tainted or plain), unioning level and sources of any tainted parts (§5). */
export function concatTainted(
  ...parts: Array<string | TaintedValue<string>>
): TaintedValue<string> {
  let level: TaintLevel = 'CLEAN';
  const sourceGroups: ProvenanceTag[][] = [];
  let text = '';
  for (const part of parts) {
    if (isTaintedValue(part)) {
      level = maxLevel(level, part.level);
      sourceGroups.push(part.sources);
      text += part.value;
    } else {
      text += part;
    }
  }
  return wrapTainted(text, level, mergeSources(...sourceGroups));
}

/**
 * JSON.stringify that unions taint across every value it visits, tainted or
 * not (§5).
 *
 * `strip()`'s generic-object branch walks any non-array, non-TaintedValue
 * object via `Object.entries()` — fine for plain objects, but a naive
 * recursive walk like that silently mishandles anything whose real content
 * isn't exposed as own enumerable string-keyed properties. This is the
 * exact failure mode `json-safe-clone.ts`'s header comment calls out for
 * the default args cloner ("naively recursing into a Date with
 * Object.keys() would silently produce an empty {}") — this function had
 * the same bug, just silent instead of throwing. Two things had to be
 * checked before deciding how to fix it (don't assume every "exotic" type
 * is broken the same way):
 *
 *   - `Date`: `Object.entries(new Date())` is `[]`, so the naive walk
 *     rebuilt it as `{}` — but plain `JSON.stringify` does NOT produce `{}`
 *     for a Date; it detects Date's own `toJSON()` method and calls it,
 *     producing the ISO string. This was a genuine, confirmed divergence
 *     from what plain `JSON.stringify` produces on the same input. Fixed
 *     below by mirroring that same toJSON-delegation JSON.stringify itself
 *     performs, generically (not just for Date — any object with a callable
 *     `toJSON()` gets the same treatment, matching native semantics), and
 *     then continuing to walk whatever `toJSON()` returns for embedded taint.
 *
 *   - `Map`/`Set`/`RegExp`: verified directly — `Object.entries()` on any
 *     of these is also `[]`, so the naive walk rebuilds them as `{}` too,
 *     but so does plain `JSON.stringify` (none of the three define a
 *     `toJSON()`, and `Object.entries` doesn't see a Map/Set's actual
 *     entries or a RegExp's source/flags either way). So the STRING output
 *     for these was never actually wrong relative to native JSON.stringify
 *     — no fix needed there for string fidelity.
 *
 *     Map/Set still get a fix, but a different kind: unlike a RegExp (whose
 *     only state is its immutable source/flags string — nothing that could
 *     ever be a TaintedValue), a Map or Set can hold arbitrary values,
 *     including live TaintedValue entries, that this function's whole job
 *     is to notice. Because those entries are invisible to Object.entries(),
 *     any taint nested inside a Map/Set would be silently dropped from the
 *     returned level/sources with no error — a real instance of exactly the
 *     silent-taint-loss failure this module exists to prevent, even though
 *     the resulting JSON *string* would happen to be "correct" (matching
 *     what native JSON.stringify also produces). Consistent with this
 *     module's and json-safe-clone.ts's shared fail-loud philosophy, that
 *     case now throws instead of silently under-reporting taint. Typed
 *     arrays were also checked and excluded: their entries are always
 *     numbers (never object references), so there is no way for a
 *     TaintedValue to hide inside one, and Object.entries() already walks
 *     their indices the same way JSON.stringify itself does.
 */
export function taintAwareJSONStringify(value: unknown): TaintedValue<string> {
  let level: TaintLevel = 'CLEAN';
  const sourceGroups: ProvenanceTag[][] = [];

  function strip(node: unknown): unknown {
    if (isTaintedValue(node)) {
      level = maxLevel(level, node.level);
      sourceGroups.push(node.sources);
      return strip(node.value);
    }
    if (Array.isArray(node)) return node.map(strip);
    if (node !== null && typeof node === 'object') {
      const toJSON = (node as { toJSON?: unknown }).toJSON;
      if (typeof toJSON === 'function') {
        // Mirrors JSON.stringify's own toJSON-delegation (Date is the
        // ubiquitous example, but any object exposing toJSON() gets the
        // same treatment). Keep walking the delegate's return value —
        // it's usually already a primitive, but nothing stops a custom
        // toJSON() from returning an object that itself embeds a
        // TaintedValue.
        return strip((toJSON as () => unknown).call(node));
      }
      if (node instanceof Map || node instanceof Set) {
        throw new TypeError(
          `taintAwareJSONStringify: cannot walk a ${node instanceof Map ? 'Map' : 'Set'} for taint — its entries ` +
            'are not visible as own enumerable properties, so any TaintedValue inside it would be silently dropped ' +
            "from the result's level/sources instead of being reflected in them (see this function's doc comment). " +
            'Convert it to a plain object/array first — e.g. Object.fromEntries(map) or [...set] — before passing ' +
            'it to taintAwareJSONStringify().',
        );
      }
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node)) out[k] = strip(v);
      return out;
    }
    return node;
  }

  const plain = strip(value);
  return wrapTainted(JSON.stringify(plain), level, mergeSources(...sourceGroups));
}

/** Object spread that preserves the union of taint across every source object (§5). */
export function spreadTainted<T extends Record<string, unknown>>(
  ...objects: Array<T | TaintedValue<T>>
): TaintedValue<T> {
  let level: TaintLevel = 'CLEAN';
  const sourceGroups: ProvenanceTag[][] = [];
  let merged = {} as T;
  for (const obj of objects) {
    if (isTaintedValue(obj)) {
      level = maxLevel(level, obj.level);
      sourceGroups.push(obj.sources);
      merged = { ...merged, ...obj.value };
    } else {
      merged = { ...merged, ...obj };
    }
  }
  return wrapTainted(merged, level, mergeSources(...sourceGroups));
}

/**
 * Array.prototype.map that carries taint onto the mapped result (§5).
 *
 * Two independent call shapes need to propagate here, not one:
 *
 *   1. `mapTainted(taintedArr, fn)` — a single TaintedValue<T[]> wrapping
 *      the whole array (e.g. straight off `broker.wrap(executor)`). The
 *      taint lives on the outer array.
 *   2. `mapTainted(arrayOfIndividuallyWrappedItems, fn)` — a plain T[]
 *      whose individual ELEMENTS are themselves TaintedValues, each from
 *      its own separate `wrapTainted()`/`broker.wrap()` call. This is a
 *      perfectly natural, type-checked call — `arr: TaintedValue<T[]> |
 *      T[]` doesn't distinguish "T happens to be TaintedValue<something>"
 *      from any other T — and it is at least as common as shape 1 for code
 *      that builds up a list of results one tainted item at a time before
 *      mapping over it.
 *
 * The original implementation only ever checked shape 1 (`isTaintedValue(arr)`
 * on the OUTER array), so shape 2 silently fell through to level: 'CLEAN',
 * sources: [] — a real, silent taint-drop for a call site that never did
 * anything unusual (see the regression test for the exact reproduction).
 * Fixed by checking both: aggregate the outer array's own taint (if any)
 * AND each element's individual taint (if any) into the same running
 * level/sources, the same union idiom `concatTainted`/`spreadTainted` above
 * already use, via `maxLevel` and `mergeSources`. Only the outer TaintedValue
 * wrapper (if present) is unwrapped before iterating — an individually-
 * tainted element is still handed to `fn` exactly as-is (still wrapped), so
 * callers that unwrap inside `fn` themselves (as the regression test's
 * `item => item.value.toUpperCase()` does) keep working unchanged.
 */
export function mapTainted<T, U>(
  arr: TaintedValue<T[]> | T[],
  fn: (item: T, index: number) => U,
): TaintedValue<U[]> {
  let level: TaintLevel = 'CLEAN';
  const sourceGroups: ProvenanceTag[][] = [];

  if (isTaintedValue(arr)) {
    level = maxLevel(level, arr.level);
    sourceGroups.push(arr.sources);
  }
  const items = isTaintedValue(arr) ? arr.value : arr;

  const mapped = items.map((item, index) => {
    if (isTaintedValue(item)) {
      level = maxLevel(level, item.level);
      sourceGroups.push(item.sources);
    }
    return fn(item, index);
  });
  return wrapTainted(mapped, level, mergeSources(...sourceGroups));
}
