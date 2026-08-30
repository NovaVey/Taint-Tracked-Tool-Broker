import type { PolicyDecision, ToolCall } from './types.js';
import { RESERVED_TOOL_NAME_PREFIX } from './internal-audit.js';

export class TaintBrokerError extends Error {}

/**
 * Thrown by register()/wrap() when a tool's name starts with the
 * `__tttb_` prefix TTTB reserves for its own internal/administrative
 * audit-only events (declassify(), startNewTurn(), markContextExposure(),
 * summarize(), the warnOnLikelyUnclassifiedSink registration advisory).
 * Registering a real tool under this prefix would make its audit events
 * indistinguishable from one of those library-generated ones.
 */
export class ReservedToolNameError extends TaintBrokerError {
  constructor(toolName: string) {
    super(
      `Tool name "${toolName}" starts with the reserved prefix "${RESERVED_TOOL_NAME_PREFIX}", which TTTB uses for ` +
        'its own internal/administrative audit events (declassify(), startNewTurn(), markContextExposure(), ' +
        'summarize()). Choose a different name for this tool.',
    );
    this.name = 'ReservedToolNameError';
  }
}

export class UnknownToolError extends TaintBrokerError {
  constructor(toolName: string) {
    super(
      `No tool registered with name "${toolName}". Tools must be registered via broker.register()/broker.wrap() before being called.`,
    );
    this.name = 'UnknownToolError';
  }
}

/** Thrown by ToolCallBroker.call() whenever the policy verdict was not ALLOW/ALLOW_WITH_WARNING or an approved REQUIRE_APPROVAL. */
export class ToolCallBlockedError extends TaintBrokerError {
  readonly call: ToolCall;
  readonly decision: PolicyDecision;

  constructor(call: ToolCall, decision: PolicyDecision, message: string) {
    super(message);
    this.name = 'ToolCallBlockedError';
    this.call = call;
    this.decision = decision;
  }
}

/** Thrown by broker.summarize() when sourceTaintRecordId does not name a known TaintRecord (DESIGN.md §6.2 step 1). */
export class QuarantineInputUnknownError extends TaintBrokerError {
  constructor(recordId: string) {
    super(
      `summarize() input references unknown taint record "${recordId}". Quarantine input must be registry-known text ` +
        '(a live TaintedValue, or a taintRecordId from a real tool result) — not text the agent free-typed from memory. See DESIGN.md §6.2.',
    );
    this.name = 'QuarantineInputUnknownError';
  }
}

/**
 * Thrown by broker.summarize() when `text` bears essentially no resemblance
 * to the record named by `sourceTaintRecordId` (too long relative to the
 * source, or too little of `text`'s own content traces back to it). Not a
 * spoofing-proof check — see DESIGN.md §6.2, GAPS.md #4.
 */
export class QuarantineInputMismatchError extends TaintBrokerError {
  constructor(recordId: string) {
    super(
      `summarize() input text does not resemble the content of taint record "${recordId}". ` +
        'The claimed source and the text being quarantined must actually be related. See DESIGN.md §6.2, GAPS.md #4.',
    );
    this.name = 'QuarantineInputMismatchError';
  }
}

/**
 * Thrown by register()/wrap() when a tool declares itself both a source of
 * untrusted content (isSource: true, not trusted) AND a privileged sink
 * (non-empty capabilities). Such a tool can read and act on untrusted
 * content within a single, un-gated call — the watermark that is supposed
 * to gate its own sink behavior has no way to be raised until AFTER the
 * call's privileged effect has already happened. Split it into two
 * separate broker-mediated calls (a source-only fetch, then a sink-only
 * act), or use the composite fetch-and-quarantine pattern in DESIGN.md
 * §6.2's implementation note instead.
 */
export class DualRoleToolError extends TaintBrokerError {
  constructor(toolName: string) {
    super(
      `Tool "${toolName}" is registered as both isSource:true (untrusted) and a privileged sink (non-empty capabilities). ` +
        'A single call to such a tool could read and act on untrusted content before the watermark that gates its own ' +
        'sink behavior is ever raised. Split it into a source-only call and a separate sink-only call, mark it trusted ' +
        'if its source content is genuinely not attacker-influenceable, or use the fetch-and-quarantine pattern in ' +
        "DESIGN.md §6.2's implementation note. See GAPS.md.",
    );
    this.name = 'DualRoleToolError';
  }
}

/**
 * Thrown by call() when a tool's args can't be cloned (structuredClone
 * threw — functions, most class instances, WeakMap/WeakSet, etc. — and no
 * BrokerOptions.cloneArgs override was supplied). Args snapshotting is what
 * keeps "what was approved", "what executed", and "what got audited" from
 * silently diverging (see DESIGN.md's concurrency implementation note); a
 * value that can't be cloned would silently reopen exactly that gap if the
 * call proceeded on a shared, mutable reference instead. Fails loud rather
 * than degrading quietly — see GAPS.md #16. Pass a custom `cloneArgs` to
 * createBroker() if your tools genuinely need non-JSON-able argument types.
 */
export class NonCloneableArgsError extends TaintBrokerError {
  constructor(toolName: string, cause: unknown) {
    super(
      `Tool call "${toolName}" was not dispatched: its arguments could not be cloned (structuredClone threw). ` +
        'Args must be snapshotted so that what an approver sees, what executes, and what gets audited cannot silently ' +
        'diverge — see GAPS.md #16. Pass a custom cloneArgs to createBroker() if this tool genuinely needs ' +
        'non-JSON-able argument types.',
      { cause },
    );
    this.name = 'NonCloneableArgsError';
  }
}

/**
 * Thrown by declarePlan() when the scope has already left CLEAN. Plan-freeze
 * strict mode (DESIGN.md §11) only means something if the plan is committed
 * BEFORE any untrusted content is read — declaring one retroactively, after
 * exposure, would let the very content the plan is meant to constrain shape
 * the plan itself.
 */
export class PlanNotDeclarableError extends TaintBrokerError {
  constructor() {
    super(
      'declarePlan() must be called while the scope is still CLEAN. Untrusted content is already live in this scope, ' +
        'so committing to a plan now would let that content help shape the very plan meant to constrain it. See DESIGN.md §11.',
    );
    this.name = 'PlanNotDeclarableError';
  }
}

/**
 * Thrown by call() under plan-freeze strict mode when a privileged call's
 * tool does not match the next committed PlanStep. This is checked in
 * addition to (never instead of) the normal policy decision — see
 * DESIGN.md §11.
 */
export class UnplannedPrivilegedActionError extends TaintBrokerError {
  constructor(toolName: string, expectedToolName: string | undefined) {
    super(
      `Tool call "${toolName}" was not executed: plan-freeze strict mode is active and this call does not match the ` +
        `next committed step${expectedToolName ? ` ("${expectedToolName}")` : ' (the plan has no steps left)'}. ` +
        'Untrusted content is live in this scope, so only the pre-committed call sequence may proceed. See DESIGN.md §11.',
    );
    this.name = 'UnplannedPrivilegedActionError';
  }
}

/**
 * Thrown by a registerRawForQuarantine()-wrapped tool's execute() when its
 * result can't be turned into the `{ text, taintRecordId }` pair the helper
 * promises: either the result isn't text-representable (toRegistrableText()
 * threw — e.g. a circular object) or, in the narrow window between this
 * call's own registration and this check, the record was evicted from the
 * registry (a bounded `maxEntries` registry under heavy concurrent use —
 * see GAPS.md #13). The underlying tool call already executed and the
 * watermark already raised by this point; only the id lookup this helper
 * exists to save callers from doing themselves has failed. Call
 * broker.summarize() manually with a taintRecordId obtained another way, or
 * avoid registerRawForQuarantine() for tools whose results aren't
 * text/JSON-representable.
 */
export class QuarantineSourceUnavailableError extends TaintBrokerError {
  constructor(toolName: string, cause?: unknown) {
    super(
      `registerRawForQuarantine()-wrapped tool "${toolName}" executed successfully, but its result could not be ` +
        'resolved to a taintRecordId for summarize(). Either the result is not text/JSON-representable, or the ' +
        'record was evicted from the registry before it could be looked up (see GAPS.md #13).',
      cause !== undefined ? { cause } : undefined,
    );
    this.name = 'QuarantineSourceUnavailableError';
  }
}

/**
 * Thrown when broker.call() is invoked reentrantly — from within a tool's
 * own execute() (or anything it awaited), OR from within a broker.summarize()
 * quarantine callback (or anything IT awaited), on the SAME broker instance,
 * before the outer call/summarize() has finished. Reentrant calls would
 * deadlock the per-broker serialization lock that makes watermark raises
 * atomic with respect to concurrently-dispatched calls (see DESIGN.md's
 * concurrency implementation note). If a tool genuinely needs to invoke
 * another registered tool, call that tool's own execute() directly and take
 * responsibility for its policy implications yourself.
 *
 * A useful side effect of this, not its original purpose: it also means a
 * `QuarantineImpl` (the Q-LLM callback `broker.summarize()` invokes) cannot
 * itself call `broker.call()` — the reentrancy guard is active for the
 * callback's entire execution window, whether summarize() was called
 * top-level or nested inside a tool's own execute(). This is one piece
 * (not the whole) of the "quarantined model has no tool access" property
 * DESIGN.md §6.2's dual-model-split note describes — structurally enforced,
 * not merely a documented calling convention. See that note for exactly
 * what this does and does not cover.
 */
export class ReentrantCallError extends TaintBrokerError {
  constructor(toolName: string) {
    super(
      `Reentrant broker.call("${toolName}", ...) detected: a tool's execute() (or something it awaited), or a ` +
        'broker.summarize() quarantine callback (or something it awaited), called broker.call() again on the same ' +
        'broker instance before the outer call/summarize() finished. This is not supported — it would deadlock the ' +
        'serialization lock that makes watermark raises atomic across concurrently-dispatched calls. If a tool needs ' +
        "another registered tool's behavior, call its execute() directly instead of going back through the broker. " +
        'If this was a quarantine callback: a QuarantineImpl must be capability-less (DESIGN.md §6.2) — it cannot ' +
        'invoke tools at all, by design.',
    );
    this.name = 'ReentrantCallError';
  }
}

/**
 * Thrown when `BrokerOptions.allowedOutboundHosts` is configured and an
 * EXFIL-class call's arguments reference an http(s) URL whose hostname
 * isn't in it. This is a pure firewall-style rule (DESIGN.md §7.4) —
 * independent of, and applied even when, the taint-based policy in §7.2
 * would otherwise ALLOW the call (e.g. a CLEAN scope), since the whole
 * point of an explicit allowlist is a structural boundary rather than
 * another approval prompt subject to GAPS.md #7's fatigue risk.
 */
export class DisallowedOutboundHostError extends TaintBrokerError {
  constructor(toolName: string, disallowedHosts: readonly string[]) {
    super(
      `Tool call "${toolName}" was not executed: outbound host allowlist violation — ` +
        `${disallowedHosts.map((h) => `"${h}"`).join(', ')} not in BrokerOptions.allowedOutboundHosts. ` +
        'See DESIGN.md §7.4 and GAPS.md #18 for what this check does and does not cover.',
    );
    this.name = 'DisallowedOutboundHostError';
  }
}
