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
import { LEVEL_ORDER, maxLevel } from '../types.js';
import { isTaintedValue } from './wrapper.js';

export interface ScanResult {
  matches: TaintMatch[];
  /** Union of every matched record's level — floors (never lowers) a policy verdict. */
  floor: TaintLevel;
}

// Bounds the final ScanResult.matches array size across an entire args tree
// (many string leaves, each potentially contributing several fuzzy matches).
// Purely a size bound on the returned explainability list — `floor` is
// accumulated independently via bump() as the tree is walked, not re-derived
// from `matches` afterward, so truncating this array can never affect a
// policy verdict, only how many matched records an audit/approval UI sees.
const MAX_SCAN_MATCHES = 50;

export function scanArgsForTaint(args: unknown, registry: TaintRegistry): ScanResult {
  const matches: TaintMatch[] = [];
  let floor: TaintLevel = 'CLEAN';
  const bump = (level: TaintLevel): void => {
    floor = maxLevel(floor, level);
  };

  function checkStringLeaf(text: string, path: string): void {
    // lookupCombined() (when the registry provides it — InMemoryTaintRegistry
    // does) computes the text's fingerprint once instead of twice: calling
    // lookupExact() then lookupFuzzy() separately re-hashes the same text a
    // second time inside lookupFuzzy()'s own buildFingerprint() call. See
    // TaintRegistry.lookupCombined()'s doc comment in types.ts. Falls back to
    // the two separate calls for a custom registry that doesn't implement it.
    const { exact, fuzzy } = registry.lookupCombined
      ? registry.lookupCombined(text)
      : { exact: registry.lookupExact(text), fuzzy: registry.lookupFuzzy(text) };
    if (exact) {
      matches.push({ record: exact, matchType: 'exact', argPath: path, score: 1 });
      bump(exact.level);
    }
    for (const match of fuzzy) {
      matches.push({ ...match, argPath: path });
      bump(match.record.level);
    }
  }

  // Guards against a circular args object (e.g. a raw HTTP client/response
  // object forwarded from a prior tool's result into a later call's
  // arguments, unremarkable in ordinary JS) recursing forever. `structuredClone`
  // happily produces a cyclic snapshot (Node's structuredClone supports
  // cycles), so a cyclic value reaches this scan intact — this is reachable
  // in practice, not just in theory. A node already visited is skipped, not
  // re-scanned: a cycle can only make the same subtree reachable via a
  // second path, never expose content that wasn't already scanned on its
  // first visit, so skipping loses no coverage.
  const visited = new WeakSet<object>();

  function visit(node: unknown, path: string): void {
    if (node === null || node === undefined) return;
    if (typeof node === 'object') {
      if (visited.has(node as object)) return;
      visited.add(node as object);
    }

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
      checkStringLeaf(node, path);
      return;
    }

    if (Array.isArray(node)) {
      node.forEach((child, i) => visit(child, `${path}[${i}]`));
      return;
    }

    if (typeof node === 'object') {
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        // Untrusted text can be smuggled as an object KEY, not just a value
        // (e.g. `{ [attackerText]: true }`) — scan the key itself as a
        // string leaf too, not just what it maps to.
        const childPath = path ? `${path}.${key}` : key;
        checkStringLeaf(key, childPath);
        visit(value, childPath);
      }
    }
  }

  visit(args, '');
  if (matches.length > MAX_SCAN_MATCHES) {
    // Level first, score second — same rationale as InMemoryTaintRegistry's
    // own per-lookup cap (registry.ts): `floor` above is already fixed by
    // this point (computed via bump() during the walk, not from this array),
    // so this truncation is a pure explainability-list size bound, never a
    // policy-affecting one.
    matches.sort((a, b) => LEVEL_ORDER[b.record.level] - LEVEL_ORDER[a.record.level] || b.score - a.score);
    matches.length = MAX_SCAN_MATCHES;
  }
  return { matches, floor };
}
