/**
 * Layer 0 — the scope watermark (DESIGN.md §4.1). Pure state transitions;
 * the broker decides *when* to call these, this module only enforces that
 * the watermark is monotonic outside of an explicit declassify.
 */

import type { ProvenanceTag, ScopeKind, TaintLevel, TaintScope, TaintWatermark } from '../types.js';
import { maxLevel } from '../types.js';

export function createWatermark(): TaintWatermark {
  return { level: 'CLEAN', privateDataSeen: false, sources: [] };
}

export function createScope(kind: ScopeKind, id: string): TaintScope {
  return { kind, id, watermark: createWatermark() };
}

/** Raises the watermark to at least `level`, never lowers it. */
export function raiseWatermark(scope: TaintScope, level: TaintLevel, tag?: ProvenanceTag): void {
  scope.watermark.level = maxLevel(scope.watermark.level, level);
  if (tag) scope.watermark.sources.push(tag);
}

export function markPrivateDataSeen(scope: TaintScope): void {
  scope.watermark.privateDataSeen = true;
}

/**
 * The distinct `ProvenanceTag.sourceClass` values present across `sources`,
 * deduplicated, in order of first appearance, skipping any tag with no
 * declared `sourceClass` — the pure derivation behind `TaintContext
 * .sourceClasses` (see that field's own doc comment, types.ts, for the full
 * GAPS.md #28 motivation and why this is a bounded, derived SUMMARY rather
 * than the raw `sources` array `TaintWatermark.sources`'s own doc comment
 * says policy gating logic must never branch on directly).
 *
 * Always returns a real array, never `undefined` — including `[]` when
 * `sources` is empty or none of its entries declared a `sourceClass` — so
 * every real `TaintContext` construction site can set this field
 * explicitly rather than omitting it, the same "false, not absent"
 * discipline `hasUnattributedSubstantialContent` already follows
 * (`taint/scan.ts`). `TaintContext.sourceClasses` stays typed optional only
 * so a `TaintContext` literal predating this field still type-checks — see
 * that field's own doc comment for why `undefined` there must never be
 * read as "computed to empty."
 *
 * Exported (also re-exported from `src/index.ts`, alongside this module's
 * other scope primitives) so a caller building a `TaintContext` fixture by
 * hand, or inspecting a live `broker.scope.watermark.sources` directly, can
 * recompute the identical derivation this library uses internally instead
 * of hand-rolling their own deduplication.
 */
export function deriveSourceClasses(sources: readonly ProvenanceTag[]): readonly string[] {
  const seen = new Set<string>();
  for (const tag of sources) {
    if (tag.sourceClass !== undefined) seen.add(tag.sourceClass);
  }
  return [...seen];
}

/** The only operation that lowers a watermark. Callers (broker.declassify) are responsible for auditing this. */
export function declassifyScope(scope: TaintScope): void {
  scope.watermark.level = 'CLEAN';
  scope.watermark.privateDataSeen = false;
  scope.watermark.sources = [];
}
