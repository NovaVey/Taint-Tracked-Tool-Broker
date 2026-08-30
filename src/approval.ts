/**
 * A reference `ApprovalChannel` for the common "resolved by a webhook or UI
 * click sometime later" shape (DESIGN.md §7, `ApprovalChannel.requestApproval`).
 *
 * Every `ApprovalChannel` implementation in this repo's own tests and
 * examples is a synchronous stub that never actually defers — real
 * deployments need something that genuinely suspends a `REQUIRE_APPROVAL`
 * call until a human responds out-of-band (a Slack button, an email link,
 * an approval-queue UI), keyed by `decision.approvalToken` exactly as the
 * type's own doc comment describes. This is that: a token-keyed pending-
 * request map an integrator's webhook/UI handler resolves by calling
 * `resolve(approvalToken, granted)`.
 *
 * Not registered anywhere automatically — `createBroker()` has no default
 * `ApprovalChannel` (see broker.ts), so every `REQUIRE_APPROVAL` decision
 * fails closed (denied) unless one is configured. This is the intended,
 * documented default: `createDeferredApprovalChannel()` is an opt-in
 * building block, not a default.
 */

import type { ApprovalChannel, RequireApprovalDecision, TaintContext, ToolCall } from './types.js';

export interface DeferredApprovalChannel extends ApprovalChannel {
  /**
   * Resolve a pending approval request by the `approvalToken` your
   * webhook/UI handler received (from `decision.approvalToken`, e.g.
   * surfaced via an `AuditSink` implementation watching for
   * `REQUIRE_APPROVAL` verdicts). Returns `true` if a pending request for
   * that token was found and resolved, `false` if the token is unknown,
   * already resolved, or already timed out — a safe no-op either way, so a
   * duplicate or late webhook delivery can't throw.
   */
  resolve(approvalToken: string, granted: boolean): boolean;
  /** Number of requests currently awaiting resolution. */
  readonly pendingCount: number;
}

export interface DeferredApprovalChannelOpts {
  /**
   * If set, a pending request auto-resolves to `false` (denied — fail-safe,
   * matching the no-channel-configured default) after this many
   * milliseconds if `resolve()` is never called for it. Omit for no
   * timeout (waits indefinitely; make sure whatever surfaces pending
   * requests to a human doesn't lose track of them if you do).
   */
  timeoutMs?: number;
  /**
   * Called synchronously the moment a new request starts waiting — before
   * `requestApproval()`'s returned promise ever settles. This is how an
   * integrator's own code learns about a newly pending request in order to
   * surface it to a human (send a Slack message, insert an approval-queue
   * UI row) and remember its `approvalToken` for the later `resolve()`
   * call. The `AuditSink`'s own `REQUIRE_APPROVAL` record is NOT a
   * substitute for this: `broker.ts` only records it after
   * `requestApproval()` resolves, which is too late to notify anyone about
   * a request that still needs a decision.
   */
  onPending?: (
    approvalToken: string,
    call: ToolCall,
    taint: TaintContext,
    decision: RequireApprovalDecision,
  ) => void;
}

export function createDeferredApprovalChannel(
  opts: DeferredApprovalChannelOpts = {},
): DeferredApprovalChannel {
  const pending = new Map<string, (granted: boolean) => void>();

  return {
    async requestApproval(
      call: ToolCall,
      taint: TaintContext,
      decision: RequireApprovalDecision,
    ): Promise<boolean> {
      return new Promise<boolean>((resolvePromise) => {
        let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
        const settle = (granted: boolean): void => {
          if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
          pending.delete(decision.approvalToken);
          resolvePromise(granted);
        };
        pending.set(decision.approvalToken, settle);
        opts.onPending?.(decision.approvalToken, call, taint, decision);
        if (opts.timeoutMs !== undefined) {
          timeoutHandle = setTimeout(() => settle(false), opts.timeoutMs);
        }
      });
    },

    resolve(approvalToken: string, granted: boolean): boolean {
      const settle = pending.get(approvalToken);
      if (!settle) return false;
      settle(granted);
      return true;
    },

    get pendingCount(): number {
      return pending.size;
    },
  };
}
