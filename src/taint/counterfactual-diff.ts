/**
 * A pure, stateless structural diff between two proposed tool-call argument
 * trees — the implementation half of DESIGN.md §6's "counterfactual argument
 * diffing" research direction (GAPS.md #15's overclaiming disclaimer).
 *
 * This library gates on exposure ("was untrusted content live in this
 * scope"), a sound but conservative proxy for influence ("did the model's
 * reasoning actually depend on it"). One way to get closer to the second
 * question for a specific gated call: re-run the SAME decision step with the
 * tainted content excised (or replaced with an inert placeholder), and diff
 * the resulting proposed arguments against what was actually proposed. A
 * genuine difference is direct evidence the untrusted content shaped the
 * call — a signal that survives exactly the paraphrase/heavy-rewrite cases
 * that defeat Layer 2's fingerprint matching (DESIGN.md §4.2, GAPS.md #8).
 *
 * TTTB does not, and cannot, perform the re-run itself — it has no model
 * access (see quarantine.ts's own "TTTB has no opinion on which model you
 * use" stance). Producing the counterfactual proposal is the INTEGRATOR's
 * job: re-invoke the same model call that produced `actual`, with the
 * tainted content excised from context, and pass whatever it proposes this
 * time as `counterfactual`. `diffProposedArgs()` is what you call after
 * that, so you don't have to hand-write the tree-walking/path-tracking
 * machinery yourself. It is a pure comparison utility — it never touches
 * the broker, a scope, or any policy decision, and using it changes no
 * gating behavior whatsoever.
 *
 * Still not proof, even with a genuine diff in hand: DESIGN.md's own note on
 * this names two real limits neither this function nor any diffing scheme
 * closes — ordinary model nondeterminism can produce a diff that has
 * nothing to do with the excised content (mitigating this, e.g. via
 * temperature=0 or majority-voting across several counterfactual re-runs,
 * is the integrator's responsibility, not something a pure diff utility can
 * help with), and ABSENCE of a diff is not proof of no influence (the model
 * may have been influenced in a way that doesn't show up as an argument
 * difference at all). What this function *does* close, relative to
 * DESIGN.md's original note: "diff the arguments" doesn't trivially
 * generalize to non-textual/structured tool schemas — this walks arbitrary
 * JSON-safe argument trees structurally (objects, arrays, primitives), not
 * just flat strings.
 */

import { ArgsTooDeepError } from '../errors.js';

// Same bound and rationale as taint/scan.ts's MAX_ARGS_TREE_DEPTH — see
// ArgsTooDeepError's doc comment in errors.ts. Even though this utility
// never touches the broker or any gating decision (see the module doc
// comment above), an unbounded walk() here is just as exploitable/fragile
// against a deeply-nested `actual`/`counterfactual` tree as the mandatory
// scan path is — a caller passing through a prior tool's own deeply-nested
// result deserves the same clean, catchable failure instead of an
// unpredictable-depth RangeError.
const MAX_ARGS_TREE_DEPTH = 500;

/** One point where `actual` and `counterfactual` diverge. */
export interface ArgDiff {
  /**
   * Dotted/bracketed path into the argument tree where the divergence was
   * found, e.g. "body.text[0]" — the SAME convention `TaintMatch.argPath`
   * uses (taint/scan.ts), so a diff and a fingerprint match can be
   * cross-referenced by path directly.
   */
  path: string;
  actual: unknown;
  counterfactual: unknown;
}

type Shape = 'array' | 'object' | 'leaf';

function shapeOf(value: unknown): Shape {
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'object' && value !== null) return 'object';
  return 'leaf';
}

/** Same plain-object test as json-safe-clone.ts — a class instance (Date, a
 * custom class, ...) is walked as a LEAF (see leafEqual below), not
 * recursed into via Object.keys(), which would silently show two different
 * Dates as identical (a Date's time value isn't an enumerable own property).
 */
function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as object | null;
  return proto === Object.prototype || proto === null;
}

/**
 * Leaf-level equality. Primitives (including `NaN`, treated as equal to
 * itself, and `null`/`undefined`) use `Object.is`. `Date`/`RegExp` get a
 * real content comparison (time value; source+flags). Anything else
 * non-plain (`Map`, `Set`, a class instance, a function) falls back to
 * reference equality (`===`) rather than `String()` — an arbitrary class
 * instance with no overridden `toString()` stringifies to the generic
 * `"[object Object]"` for every instance, which would make two genuinely
 * DIFFERENT instances silently compare equal. Reference equality can only
 * ever err the other way (two different instances holding equivalent
 * content reported as "different," adding diff noise) — a false positive,
 * never a false negative — which fits this function's purely diagnostic
 * role: nothing gates on its output, so over-reporting a divergence is a
 * far cheaper mistake than silently hiding a real one.
 */
function leafEqual(a: unknown, b: unknown): boolean {
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime();
  if (a instanceof RegExp && b instanceof RegExp)
    return a.source === b.source && a.flags === b.flags;
  if (typeof a === 'object' && a !== null && !isPlainObject(a)) return a === b;
  if (typeof b === 'object' && b !== null && !isPlainObject(b)) return a === b;
  return Object.is(a, b);
}

/**
 * Structurally diffs two proposed tool-call argument trees, returning one
 * `ArgDiff` per point of divergence — only at the deepest level a
 * difference actually occurs (a changed leaf inside an otherwise-identical
 * object does not also produce a diff entry for the containing object).
 * `actual`/`counterfactual` swapping shape entirely at some path (e.g. an
 * array where the other side has a plain object) is itself reported as one
 * diff at that path, not descended into.
 *
 * Cycle-safe: `actual`/`counterfactual` are walked in parallel with the
 * cycle guard keyed on the PAIR of nodes currently being compared — a
 * `WeakMap<object, WeakSet<object>>` from an `actual`-side node to the set
 * of `counterfactual`-side nodes it has already been paired with. Only a
 * re-visit of the EXACT SAME (aObj, bObj) pair short-circuits; a true cycle
 * necessarily re-visits the same pair (walking the cycle back around lands
 * on the same two objects being compared again), so this still terminates a
 * cyclic argument tree (structuredClone tolerates cycles, and args are
 * commonly snapshotted with it — see broker.ts) exactly as reliably as a
 * naive single-tree guard would.
 *
 * This pairing is deliberate, not incidental: an earlier version of this
 * guard used two INDEPENDENT single-sided `WeakSet`s (one per side) ORed
 * together — `visitedActual.has(aObj) || visitedCounterfactual.has(bObj)`.
 * That looks equivalent for a true cycle, but it is not, and it silently
 * broke this function's own "never a false negative" guarantee (see
 * `leafEqual`'s doc comment above) on any DAG-shaped tree, i.e. one where
 * the SAME object is referenced from more than one path on either side —
 * not a cycle at all, just ordinary shared structure, which
 * `structuredClone` (the broker's default `cloneArgs`) preserves faithfully.
 * Concretely: `const X = {val: 1}; const actual = {shared: X, other: X};`
 * paired with `counterfactual = {shared: {val: 1}, other: {val: 999}}` has
 * a real divergence at `other.val` — but the single-sided guard adds `X` to
 * `visitedActual` while walking `shared`, then incorrectly refuses to
 * re-descend into `X` at all when it reaches `other`, even though `other`
 * is being compared against a DIFFERENT, never-before-seen counterfactual
 * node. Keying on the pair instead of either side alone fixes exactly this:
 * `(X, {val:1})` and `(X, {val:999})` are two distinct pairs, so both get
 * walked, and the real divergence is found. See
 * test/counterfactual-diff.spec.ts for the regression test built on this
 * exact repro.
 */
export function diffProposedArgs(actual: unknown, counterfactual: unknown): ArgDiff[] {
  const diffs: ArgDiff[] = [];
  // Maps an `actual`-side node to the `counterfactual`-side nodes it has
  // already been compared against, so the guard below can ask "have THIS
  // pair been visited" rather than "has EITHER side been visited on ANY
  // path" — see the doc comment above for why that distinction matters.
  const visitedPairs = new WeakMap<object, WeakSet<object>>();

  function walk(a: unknown, b: unknown, path: string, depth: number): void {
    if (depth > MAX_ARGS_TREE_DEPTH) throw new ArgsTooDeepError(MAX_ARGS_TREE_DEPTH);
    const shapeA = shapeOf(a);
    const shapeB = shapeOf(b);

    if (shapeA !== shapeB) {
      diffs.push({ path, actual: a, counterfactual: b });
      return;
    }

    if (shapeA === 'leaf') {
      if (!leafEqual(a, b)) diffs.push({ path, actual: a, counterfactual: b });
      return;
    }

    // Both are real objects/arrays here, of the same shape.
    const aObj = a as object;
    const bObj = b as object;
    let pairedWith = visitedPairs.get(aObj);
    if (pairedWith?.has(bObj)) return;
    if (!pairedWith) {
      pairedWith = new WeakSet<object>();
      visitedPairs.set(aObj, pairedWith);
    }
    pairedWith.add(bObj);

    if (shapeA === 'array') {
      const aArr = a as unknown[];
      const bArr = b as unknown[];
      const len = Math.max(aArr.length, bArr.length);
      for (let i = 0; i < len; i++) {
        walk(aArr[i], bArr[i], `${path}[${i}]`, depth + 1);
      }
      return;
    }

    // 'object' — if either side isn't a plain object (Date, RegExp, a class
    // instance, ...) it's compared as a leaf via leafEqual() instead, same
    // reasoning as isPlainObject()'s own doc comment above.
    if (!isPlainObject(aObj) || !isPlainObject(bObj)) {
      if (!leafEqual(a, b)) diffs.push({ path, actual: a, counterfactual: b });
      return;
    }
    const aRec = aObj as Record<string, unknown>;
    const bRec = bObj as Record<string, unknown>;
    const keys = new Set([...Object.keys(aRec), ...Object.keys(bRec)]);
    for (const key of keys) {
      walk(aRec[key], bRec[key], path ? `${path}.${key}` : key, depth + 1);
    }
  }

  walk(actual, counterfactual, '', 0);
  return diffs;
}
