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

/** JSON.stringify that unions taint across every value it visits, tainted or not (§5). */
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

/** Array.prototype.map that carries the source array's taint onto the mapped result (§5). */
export function mapTainted<T, U>(
  arr: TaintedValue<T[]> | T[],
  fn: (item: T, index: number) => U,
): TaintedValue<U[]> {
  const level = isTaintedValue(arr) ? arr.level : 'CLEAN';
  const sources = isTaintedValue(arr) ? arr.sources : [];
  const items = isTaintedValue(arr) ? arr.value : arr;
  return wrapTainted(items.map(fn), level, sources);
}
