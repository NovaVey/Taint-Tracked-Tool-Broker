import type { PolicyDecision, ToolCall } from './types.js';

export class TaintBrokerError extends Error {}

export class UnknownToolError extends TaintBrokerError {
  constructor(toolName: string) {
    super(`No tool registered with name "${toolName}". Tools must be registered via broker.register()/broker.wrap() before being called.`);
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
        'DESIGN.md §6.2\'s implementation note. See GAPS.md.',
    );
    this.name = 'DualRoleToolError';
  }
}

/**
 * Thrown when broker.call() is invoked reentrantly — from within a tool's
 * own execute() (or anything it awaited) on the SAME broker instance,
 * before the outer call has finished. Reentrant calls would deadlock the
 * per-broker serialization lock that makes watermark raises atomic with
 * respect to concurrently-dispatched calls (see DESIGN.md's concurrency
 * implementation note). If a tool genuinely needs to invoke another
 * registered tool, call that tool's own execute() directly and take
 * responsibility for its policy implications yourself.
 */
export class ReentrantCallError extends TaintBrokerError {
  constructor(toolName: string) {
    super(
      `Reentrant broker.call("${toolName}", ...) detected: a tool's execute() (or something it awaited) called ` +
        "broker.call() again on the same broker instance before the outer call finished. This is not supported — it " +
        'would deadlock the serialization lock that makes watermark raises atomic across concurrently-dispatched ' +
        "calls. If a tool needs another registered tool's behavior, call its execute() directly instead of going " +
        'back through the broker.',
    );
    this.name = 'ReentrantCallError';
  }
}
