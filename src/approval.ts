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
import { TaintBrokerError } from './errors.js';

/**
 * Thrown by `createDeferredApprovalChannel()`'s `requestApproval()` when
 * `decision.approvalToken` is already in use by another request still
 * awaiting resolution.
 *
 * `pending` is keyed by `approvalToken` alone, and nothing in this module
 * generates that token — it comes from whatever `PolicyFn` produced the
 * `RequireApprovalDecision` (see `types.js`'s doc comment on
 * `RequireApprovalDecision.approvalToken`). A single shared
 * `DeferredApprovalChannel` is a natural pattern for e.g. one human-approval
 * queue serving multiple `ToolCallBroker` instances, and a custom
 * `PolicyFn`'s token generation is not guaranteed globally unique across all
 * of them. Silently overwriting the colliding map entry (the pre-fix
 * behavior) would orphan the earlier request forever: its `settle` closure
 * becomes unreachable, so neither `resolve()` nor a configured `timeoutMs`
 * can ever settle its promise again — a permanent hang with no error and no
 * audit trail. Matching this project's fail-loud philosophy elsewhere
 * (`NonCloneableArgsError`, `ReservedToolNameError`, etc. in errors.ts),
 * this fails loud at the moment of collision instead, while the FIRST
 * request's entry is still untouched in `pending` and can still be resolved
 * normally by whoever holds its token.
 *
 * If you hit this in practice, make sure your `PolicyFn`'s approval-token
 * generation is actually collision-resistant (a UUID or similarly
 * high-entropy value) — see DESIGN.md §7's note on `RequireApprovalDecision`.
 */
export class DuplicateApprovalTokenError extends TaintBrokerError {
  constructor(approvalToken: string) {
    super(
      `createDeferredApprovalChannel(): a request for approvalToken "${approvalToken}" is already pending. ` +
        'Two concurrent requestApproval() calls used the same token, which would otherwise silently orphan the ' +
        "earlier request's promise (it can never be resolved or timed out again once its map entry is " +
        'overwritten). Make sure your PolicyFn generates a collision-resistant approvalToken (e.g. a UUID) — ' +
        'especially important if multiple ToolCallBroker instances share one DeferredApprovalChannel.',
    );
    this.name = 'DuplicateApprovalTokenError';
  }
}

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
        // Fail loud on a token collision rather than silently overwriting
        // an in-flight request's map entry below — see
        // DuplicateApprovalTokenError's doc comment for why an overwrite
        // would permanently orphan the earlier request. Thrown here,
        // synchronously inside the executor, this simply rejects THIS
        // call's returned promise (standard Promise-executor semantics) —
        // the colliding earlier entry in `pending` is left completely
        // untouched, so it can still be resolved normally.
        if (pending.has(decision.approvalToken)) {
          throw new DuplicateApprovalTokenError(decision.approvalToken);
        }

        let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
        const settle = (granted: boolean): void => {
          if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
          pending.delete(decision.approvalToken);
          resolvePromise(granted);
        };
        pending.set(decision.approvalToken, settle);
        opts.onPending?.(decision.approvalToken, call, taint, decision);
        // onPending() may synchronously resolve this very request (e.g. an
        // integrator's auto-approval rule calling channel.resolve() before
        // its own callback returns) — settle() then runs to completion,
        // including pending.delete(), before timeoutHandle has even been
        // assigned below. Unconditionally scheduling the timeout in that
        // case would leak a live setTimeout that nothing can ever clear
        // (settle()'s own clearTimeout(timeoutHandle) guard had nothing to
        // clear when it ran), holding the event loop open for the full
        // duration for no purpose. pending.has(...) reflects exactly
        // whether that already happened: only this call's own settle()
        // could have deleted this token (collisions are rejected above),
        // so its absence here means this request already settled.
        if (opts.timeoutMs !== undefined && pending.has(decision.approvalToken)) {
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
