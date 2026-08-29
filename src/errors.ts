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
 * to the record named by `sourceTaintRecordId`. This is a narrow check
 * (loose overlap threshold) — it catches "no relation at all" abuse, not a
 * determined spoof. See GAPS.md #4.
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
