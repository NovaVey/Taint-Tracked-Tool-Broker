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

/** The only operation that lowers a watermark. Callers (broker.declassify) are responsible for auditing this. */
export function declassifyScope(scope: TaintScope): void {
  scope.watermark.level = 'CLEAN';
  scope.watermark.privateDataSeen = false;
  scope.watermark.sources = [];
}
