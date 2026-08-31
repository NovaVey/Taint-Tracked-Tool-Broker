/**
 * Internal helpers shared between broker.ts and quarantine.ts. Not part of
 * the public API (see index.ts) — this module exists only to stop the
 * "trivial taint context + administrative AuditEvent" shape, the
 * reserved-synthetic-tool-name convention, and the "is this call an
 * untrusted source" predicate from being hand-duplicated at every call site
 * and independently drifting from each other over time.
 */

import type {
  AuditSink,
  PolicyDecision,
  TaintContext,
  TaintLevel,
  ToolCall,
  ToolExecutor,
} from './types.js';

/**
 * Prefix reserved for TTTB's own internal/administrative audit-only tool
 * names: `__tttb_context_exposure` (markContextExposure), `__tttb_turn_reset`
 * (startNewTurn), `__tttb_declassify` (declassify), `__tttb_summarize`
 * (summarize), `__tttb_registration_warning` (register()'s
 * warnOnLikelyUnclassifiedSink advisory, GAPS.md #10). A real tool
 * registered under this prefix would be indistinguishable, in the audit
 * log, from one of these library-generated events — register()/wrap()
 * reject it; see errors.ts's ReservedToolNameError.
 */
export const RESERVED_TOOL_NAME_PREFIX = '__tttb_';

export function isReservedToolName(name: string): boolean {
  return name.startsWith(RESERVED_TOOL_NAME_PREFIX);
}

/**
 * True for a tool whose successful execution should raise the watermark —
 * an untrusted source. Shared by register()'s dual-role check,
 * applyPostExecutionEffects()'s raise, and dispatch()'s escalator-audit
 * reason so the three can't independently drift on what "untrusted source"
 * means (they used to each re-derive `tool.isSource && !tool.trusted`
 * separately).
 */
export function isUntrustedSource(tool: Pick<ToolExecutor, 'isSource' | 'trusted'>): boolean {
  return tool.isSource === true && !tool.trusted;
}

/**
 * The "nothing sink-related happened, only ambient scope state matters"
 * TaintContext shape shared by every administrative AuditEvent the broker
 * emits on its own initiative: declassify(), startNewTurn(),
 * markContextExposure(), the NONE-sinkClass escalator advisory and the
 * warnOnLikelyUnmarkedSource advisory in dispatch(), and quarantine.ts's
 * unknown-source-record rejection. None of these involve a sink or a
 * fingerprint match driving the decision — only the scope level and
 * privateDataSeen flag at the time.
 *
 * `scope.id` populates `TaintContext.scopeId` (see that field's own doc
 * comment, types.ts) — every one of this function's callers already has a
 * `TaintScope`'s id in hand (either `this.currentScope.id` directly, a
 * captured `dispatchScope`/prior-scope id for the two call sites that need
 * one other than the live current scope, or `getScope().id` from
 * quarantine.ts's own scope accessor), so there is no call site that would
 * have to fabricate one.
 */
export function trivialTaintContext(scope: {
  id: string;
  level: TaintLevel;
  privateDataSeen: boolean;
}): TaintContext {
  return {
    matchedRecords: [],
    scopeLevel: scope.level,
    argFingerprintFloor: 'CLEAN',
    privateDataSeen: scope.privateDataSeen,
    sinkClass: 'NONE',
    hasUnattributedSubstantialContent: false,
    scopeId: scope.id,
  };
}

/** Records an administrative AuditEvent built from trivialTaintContext() — the common case among the sites listed there. */
export function recordTrivialAudit(
  auditSink: AuditSink,
  verdict: PolicyDecision,
  call: ToolCall,
  scope: { id: string; level: TaintLevel; privateDataSeen: boolean },
  executed: boolean,
): void {
  auditSink.record({ verdict, call, taint: trivialTaintContext(scope), at: Date.now(), executed });
}
