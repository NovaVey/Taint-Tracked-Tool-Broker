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
import { ArgsTooDeepError } from '../errors.js';
import { isTaintedValue } from './wrapper.js';

export interface ScanResult {
  matches: TaintMatch[];
  /** Union of every matched record's level — floors (never lowers) a policy verdict. */
  floor: TaintLevel;
  /**
   * True when at least one string leaf in the scanned args tree is at or
   * above `UNATTRIBUTED_CONTENT_MIN_LENGTH` chars and produced NO taint
   * match at all — not `exact`, not even a below-threshold `fuzzy` one that
   * `lookupFuzzy()` itself declined to return. This is a narrower, weaker
   * question than `floor`/`matches`: it says nothing about whether the SCOPE
   * is tainted (that's the watermark's job, §4.1, never this scan's), only
   * whether THIS call's own arguments contain a chunk of text Layer 2 has no
   * story for at all.
   *
   * Exists for exactly one consumer: `defaultPolicy`'s
   * `bestQuarantineCandidate()` (`policy/default-policy.ts`), which uses it
   * to withhold QUARANTINE_AND_RETRY confidence when a qualifying match
   * might be an unrelated decoy sitting alongside genuinely dangerous but
   * untraceable content elsewhere in the same call's argument tree — see
   * that function's own doc comment for the exact exploit this closes and
   * why a fingerprint match's mere PRESENCE in the tree was never sufficient
   * evidence that it explains the call's actual risk. Never itself gates or
   * tightens anything the way `floor` does — a call with unattributed
   * substantial content is not thereby more suspicious than the watermark
   * already says it is; it only means Layer 2 cannot vouch for the WHOLE
   * picture, so a feature that both replaces a BLOCK/REQUIRE_APPROVAL
   * verdict AND names a specific "fix this" source should decline rather
   * than guess.
   */
  hasUnattributedSubstantialContent: boolean;
}

/**
 * The length (chars) a string leaf must reach before its complete absence
 * from every taint match (`exact` and `fuzzy` both empty) counts as
 * "unattributed substantial content" (`ScanResult.hasUnattributedSubstantialContent`
 * above) rather than being ignored as a short, structurally-necessary field
 * — a file path, a recipient address, an id, a URL used as a plain
 * identifier. Every one of those appears, unmatched, in at least one of the
 * shipped QUARANTINE_AND_RETRY corpus/unit-test positive cases (a
 * `write_file` call's `path`, a `send_email` call's `to`) sitting right next
 * to the argument that actually carries the matched untrusted content; a
 * threshold of 0 (treating ANY unmatched leaf as disqualifying) would make
 * `bestQuarantineCandidate()` reject those too, which would defeat the
 * feature entirely rather than close the decoy-match hole it's meant to
 * close. 40 deliberately reuses the same rough magnitude this codebase
 * already treats as "not a trivial short field" elsewhere (see
 * `corpus/cases.ts`'s own `QUOTED_EXCERPT_EMAIL_BODY` comment, "a >40-char
 * quoted excerpt") rather than inventing an unrelated number — it comfortably
 * clears realistic path/id/email/short-URL fields while still catching a
 * realistic unmatched instruction or command string sitting in a sibling
 * argument.
 */
const UNATTRIBUTED_CONTENT_MIN_LENGTH = 40;

// Bounds the final ScanResult.matches array size across an entire args tree
// (many string leaves, each potentially contributing several fuzzy matches).
// Purely a size bound on the returned explainability list — `floor` is
// accumulated independently via bump() as the tree is walked, not re-derived
// from `matches` afterward, so truncating this array can never affect a
// policy verdict, only how many matched records an audit/approval UI sees.
const MAX_SCAN_MATCHES = 50;

// Bounds the args tree's nesting depth `visit()` will recurse into. Without
// this, a sufficiently deep tree (nested objects/arrays forwarded as a tool
// argument — e.g. a prior tool's own deeply-nested JSON result passed
// straight through) recurses until the JS call stack overflows: an
// unpredictable-depth RangeError instead of a clean, catchable, documented
// failure. 500 is comfortably below any realistic JS engine's stack limit
// for this function's frame size, while remaining far deeper than any
// legitimate real-world JSON payload plausibly nests. Same value used in
// taint/egress.ts and taint/counterfactual-diff.ts for consistency — see
// ArgsTooDeepError's doc comment in errors.ts.
const MAX_ARGS_TREE_DEPTH = 500;

export function scanArgsForTaint(args: unknown, registry: TaintRegistry): ScanResult {
  const matches: TaintMatch[] = [];
  let floor: TaintLevel = 'CLEAN';
  let hasUnattributedSubstantialContent = false;
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
    // See ScanResult.hasUnattributedSubstantialContent's own doc comment for
    // why this is length-gated rather than firing on any unmatched leaf, and
    // why "no fuzzy match at all" (as opposed to "no QUALIFYING fuzzy match")
    // is the right bar here: a leaf with a weak fuzzy hit still has SOME
    // Layer 2 story, however thin, whereas zero hits means the registry has
    // no candidate explanation for this text whatsoever.
    if (!exact && fuzzy.length === 0 && text.length >= UNATTRIBUTED_CONTENT_MIN_LENGTH) {
      hasUnattributedSubstantialContent = true;
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

  function visit(node: unknown, path: string, depth: number): void {
    if (depth > MAX_ARGS_TREE_DEPTH) throw new ArgsTooDeepError(MAX_ARGS_TREE_DEPTH);
    if (node === null || node === undefined) return;
    if (typeof node === 'object') {
      if (visited.has(node)) return;
      visited.add(node);
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
      visit(node.value, path, depth + 1);
      return;
    }

    if (typeof node === 'string') {
      checkStringLeaf(node, path);
      return;
    }

    if (Array.isArray(node)) {
      node.forEach((child, i) => visit(child, `${path}[${i}]`, depth + 1));
      return;
    }

    // Map/Set hold their entries as internal slots, not own-enumerable
    // properties, so the generic `Object.entries(node)` fallback below
    // returns literally nothing for either of them — a Map or Set reaching
    // this scan was completely invisible to it, a total miss rather than a
    // partial one. This is not a theoretical gap: the broker's default
    // cloneArgs is `structuredClone` specifically *because* it preserves
    // Map/Set/Date/RegExp/typed arrays (see broker.ts), so a tool call whose
    // args legitimately include a Map or Set survives intact into the exact
    // snapshot this "mandatory" scan walks — and would sail through
    // unscanned without this branch. Handled explicitly, before the generic
    // fallback, rather than by unwrapping into a plain object first, so the
    // existing `visited` cycle-guard and MAX_ARGS_TREE_DEPTH bound above
    // continue to apply uniformly (each recursive `visit()` call re-checks
    // both).
    if (node instanceof Map) {
      let i = 0;
      for (const [key, value] of node.entries()) {
        // A Map key can itself carry attacker text (mirrors the plain-object
        // KEY-scanning rationale just below) — e.g. a tool that echoes
        // untrusted text back as a Map key rather than a value. Keys aren't
        // necessarily strings, so route them through visit() rather than
        // checkStringLeaf() directly; a string key still ends up scanned via
        // visit()'s own `typeof node === 'string'` branch. There's no
        // "property name" to build a path segment from (a Map key isn't a
        // JS identifier), so both the key and its value are addressed
        // positionally.
        const entryPath = path ? `${path}<Map>[${i}]` : `<Map>[${i}]`;
        visit(key, `${entryPath}.key`, depth + 1);
        visit(value, `${entryPath}.value`, depth + 1);
        i++;
      }
      return;
    }

    if (node instanceof Set) {
      let i = 0;
      for (const value of node.values()) {
        visit(value, path ? `${path}<Set>[${i}]` : `<Set>[${i}]`, depth + 1);
        i++;
      }
      return;
    }

    if (typeof node === 'object') {
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        // Untrusted text can be smuggled as an object KEY, not just a value
        // (e.g. `{ [attackerText]: true }`) — scan the key itself as a
        // string leaf too, not just what it maps to.
        const childPath = path ? `${path}.${key}` : key;
        checkStringLeaf(key, childPath);
        visit(value, childPath, depth + 1);
      }
    }
  }

  visit(args, '', 0);
  if (matches.length > MAX_SCAN_MATCHES) {
    // Level first, score second — same rationale as InMemoryTaintRegistry's
    // own per-lookup cap (registry.ts): `floor` above is already fixed by
    // this point (computed via bump() during the walk, not from this array),
    // so this truncation is a pure explainability-list size bound, never a
    // policy-affecting one.
    matches.sort(
      (a, b) => LEVEL_ORDER[b.record.level] - LEVEL_ORDER[a.record.level] || b.score - a.score,
    );
    matches.length = MAX_SCAN_MATCHES;
  }
  return { matches, floor, hasUnattributedSubstantialContent };
}
