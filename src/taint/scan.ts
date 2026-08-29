/**
 * The mandatory fallback scan (DESIGN.md §4.2, §5): runs before every gated
 * tool dispatch regardless of whether any Layer 1 helper was used upstream.
 * This is what makes propagation non-manual — even code that never touches
 * a broker helper is still scanned at the one moment that matters,
 * immediately before a real side effect.
 *
 * Produces both the explainability matches (`TaintMatch[]`) and the single
 * `TaintLevel` floor Layer 2 contributes to policy (`TaintContext.argFingerprintFloor`)
 * in one tree walk.
 */

import type { TaintLevel, TaintMatch, TaintRegistry } from '../types.js';
import { maxLevel } from '../types.js';
import { isTaintedValue } from './wrapper.js';

export interface ScanResult {
  matches: TaintMatch[];
  /** Union of every matched record's level — floors (never lowers) a policy verdict. */
  floor: TaintLevel;
}

export function scanArgsForTaint(args: unknown, registry: TaintRegistry): ScanResult {
  const matches: TaintMatch[] = [];
  let floor: TaintLevel = 'CLEAN';
  const bump = (level: TaintLevel): void => {
    floor = maxLevel(floor, level);
  };

  function visit(node: unknown, path: string): void {
    if (node === null || node === undefined) return;

    // Layer 1 fast path: a still-wrapped TaintedValue carries its own level
    // and sources directly — no hash lookup needed. It still gets attributed
    // to a concrete TaintRecord (via getById) whenever the registry knows one.
    if (isTaintedValue(node)) {
      bump(node.level);
      for (const tag of node.sources) {
        const record = registry.getById(tag.id);
        if (record) matches.push({ record, matchType: 'wrapper', argPath: path, score: 1 });
      }
      visit(node.value, path);
      return;
    }

    if (typeof node === 'string') {
      const exact = registry.lookupExact(node);
      if (exact) {
        matches.push({ record: exact, matchType: 'exact', argPath: path, score: 1 });
        bump(exact.level);
      }
      for (const match of registry.lookupFuzzy(node)) {
        matches.push({ ...match, argPath: path });
        bump(match.record.level);
      }
      return;
    }

    if (Array.isArray(node)) {
      node.forEach((child, i) => visit(child, `${path}[${i}]`));
      return;
    }

    if (typeof node === 'object') {
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        visit(value, path ? `${path}.${key}` : key);
      }
    }
  }

  visit(args, '');
  return { matches, floor };
}
