/**
 * ToolCallBroker (DESIGN.md §7.3, §8) — the integration point. Every tool
 * call from the agent loop is meant to go through `call()` (or the
 * interposed executor returned by `wrap()`); nothing else in this library
 * enforces anything on a call that bypasses it — see GAPS.md #11.
 */

import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import type {
  ApprovalChannel,
  AuditSink,
  PolicyFn,
  QuarantineFn,
  QuarantineImpl,
  ResetScope,
  TaintContext,
  TaintLevel,
  TaintRegistry,
  TaintScope,
  ToolCall,
  ToolCallBroker,
  ToolExecutor,
} from './types.js';
import { NOT_SENSITIVE, sinkClassOf } from './types.js';
import { InMemoryTaintRegistry } from './taint/registry.js';
import { createScope, declassifyScope, markPrivateDataSeen, raiseWatermark } from './taint/scope.js';
import { scanArgsForTaint } from './taint/scan.js';
import { exactHash, toRegistrableText } from './taint/fingerprint.js';
import { defaultPolicy } from './policy/default-policy.js';
import { createQuarantine, unconfiguredQuarantineImpl } from './quarantine.js';
import { DualRoleToolError, ReentrantCallError, ToolCallBlockedError, UnknownToolError } from './errors.js';

export interface BrokerOptions {
  sessionId?: string;
  /** 'session' (default) never resets until an explicit declassify(); 'turn' trades soundness for usability — GAPS.md #2. */
  resetScope?: ResetScope;
  policy?: PolicyFn;
  approvalChannel?: ApprovalChannel;
  auditSink?: AuditSink;
  /** The capability-less LLM call used by broker.summarize(). No default — see quarantine.ts. */
  quarantineImpl?: QuarantineImpl;
  registry?: TaintRegistry;
}

const NOOP_AUDIT: AuditSink = { record() {} };

function blockedMessage(toolName: string, decision: { action: string; reason?: string }): string {
  const reason = decision.reason ?? 'no approval channel was configured to grant it';
  return `Tool call "${toolName}" was not executed (${decision.action}): ${reason}`;
}

/** Best-effort deep clone for args snapshotting. Falls back to the original reference for values structuredClone can't handle (functions, etc.) — a documented residual gap, not silently unsafe for the common JSON-able-args case. */
function safeClone<T>(value: T): T {
  try {
    return structuredClone(value);
  } catch {
    return value;
  }
}

class Broker implements ToolCallBroker {
  private readonly sessionId: string;
  private readonly resetScopeMode: ResetScope;
  private readonly policy: PolicyFn;
  private readonly approvalChannel: ApprovalChannel | undefined;
  private readonly auditSink: AuditSink;
  private readonly tools = new Map<string, ToolExecutor>();
  private currentScope: TaintScope;

  // Serializes every call() invocation on this broker instance so that a
  // source call's watermark raise always happens-before any later call's
  // gating decision reads that watermark, even under concurrent dispatch
  // (e.g. an agent harness running a model's parallel tool_use blocks via
  // Promise.all). See DESIGN.md's concurrency implementation note.
  private lockTail: Promise<void> = Promise.resolve();
  // Detects a tool's execute() calling broker.call() again on the same
  // broker before the outer call finishes — that would deadlock the lock
  // above, so it's rejected immediately instead.
  private readonly reentrancyGuard = new AsyncLocalStorage<true>();

  readonly registry: TaintRegistry;
  readonly summarize: QuarantineFn;

  constructor(opts: BrokerOptions = {}) {
    this.sessionId = opts.sessionId ?? randomUUID();
    this.resetScopeMode = opts.resetScope ?? 'session';
    this.policy = opts.policy ?? defaultPolicy;
    this.approvalChannel = opts.approvalChannel;
    this.auditSink = opts.auditSink ?? NOOP_AUDIT;
    this.registry = opts.registry ?? new InMemoryTaintRegistry();
    this.currentScope = createScope(this.resetScopeMode, this.sessionId);
    this.summarize = createQuarantine(opts.quarantineImpl ?? unconfiguredQuarantineImpl, this.registry, (tag) =>
      raiseWatermark(this.currentScope, 'DERIVED_UNTRUSTED', tag),
    );
  }

  get scope(): Readonly<TaintScope> {
    return this.currentScope;
  }

  register(tool: ToolExecutor): void {
    const sinkClass = sinkClassOf(tool.capabilities.capabilities);
    if (tool.isSource && !tool.trusted && sinkClass !== 'NONE') {
      // A single call to a dual-role tool could read untrusted content and
      // act on it in the same, un-gated step: the watermark that would
      // gate its OWN sink behavior can't rise until after execute()
      // resolves. Rejected at registration time — see errors.ts and
      // GAPS.md.
      throw new DualRoleToolError(tool.name);
    }
    this.tools.set(tool.name, tool);
  }

  /** Registers `executor` and returns a drop-in replacement whose execute() is interposed through call(). */
  wrap<T extends ToolExecutor>(executor: T): T {
    this.register(executor);
    return { ...executor, execute: (args: unknown) => this.call(executor.name, args) } as T;
  }

  async call(toolName: string, args: unknown): Promise<unknown> {
    if (this.reentrancyGuard.getStore()) {
      throw new ReentrantCallError(toolName);
    }
    return this.withLock(() => this.reentrancyGuard.run(true, () => this.dispatch(toolName, args)));
  }

  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.lockTail;
    let release: () => void = () => {};
    this.lockTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  private async dispatch(toolName: string, args: unknown): Promise<unknown> {
    const tool = this.tools.get(toolName);
    if (!tool) throw new UnknownToolError(toolName);

    // One snapshot used everywhere a caller-visible record of "what was
    // requested" is needed (policy, approval, audit) — never the live
    // object — plus a second, independent snapshot handed to execute().
    // Otherwise a tool that mutates its own args in place (an entirely
    // ordinary pattern) silently corrupts what the approval channel showed
    // a human and what the audit log records as having executed, since
    // both would share one mutable reference with whatever execute() did
    // to it.
    const argsSnapshot = safeClone(args);
    const call: ToolCall = { id: randomUUID(), toolName, args: argsSnapshot, sessionId: this.sessionId };
    const sinkClass = sinkClassOf(tool.capabilities.capabilities);

    let result: unknown;

    if (sinkClass === 'NONE') {
      // Not a privileged sink: no gating, no audit record. Source tools
      // (fetch_url, read_email, ...) typically land here — their taint
      // effects are applied below, after execution, regardless of sinkClass.
      result = await tool.execute(safeClone(args));
    } else {
      const { matches, floor } = scanArgsForTaint(argsSnapshot, this.registry);
      const taint: TaintContext = {
        matchedRecords: matches,
        scopeLevel: this.currentScope.watermark.level,
        argFingerprintFloor: floor,
        privateDataSeen: this.currentScope.watermark.privateDataSeen,
        sinkClass,
      };

      const decision = await this.policy(call, taint);
      let executed = false;

      if (decision.action === 'ALLOW' || decision.action === 'ALLOW_WITH_WARNING') {
        result = await tool.execute(safeClone(args));
        executed = true;
      } else if (decision.action === 'REQUIRE_APPROVAL') {
        const granted = this.approvalChannel ? await this.approvalChannel.requestApproval(call, taint, decision) : false;
        if (granted) {
          result = await tool.execute(safeClone(args));
          executed = true;
        }
      }
      // BLOCK / QUARANTINE_AND_RETRY, or a denied REQUIRE_APPROVAL: never auto-executed (§7.2).

      this.auditSink.record({ verdict: decision, call, taint, at: Date.now(), executed });
      if (!executed) {
        throw new ToolCallBlockedError(call, decision, blockedMessage(toolName, decision));
      }
    }

    this.applyPostExecutionEffects(tool, call, result);
    return result;
  }

  markContextExposure(source: { toolName?: string; note: string }, level: TaintLevel = 'RAW_UNTRUSTED'): void {
    raiseWatermark(this.currentScope, level, {
      id: randomUUID(),
      sourceCallId: `context-exposure:${randomUUID()}`,
      toolName: source.toolName ?? '__untracked_context__',
      sessionId: this.sessionId,
      capturedAt: Date.now(),
      note: source.note,
    });
  }

  startNewTurn(): void {
    if (this.resetScopeMode === 'turn') {
      this.currentScope = createScope('turn', randomUUID());
    }
    // 'session' mode: no-op by design — the watermark persists for the whole session (§4.1).
  }

  declassify(reason: string, approvedBy: string): void {
    declassifyScope(this.currentScope);
    this.auditSink.record({
      verdict: { action: 'ALLOW' },
      call: { id: randomUUID(), toolName: '__tttb_declassify', args: { reason, approvedBy }, sessionId: this.sessionId },
      taint: { matchedRecords: [], scopeLevel: 'CLEAN', argFingerprintFloor: 'CLEAN', privateDataSeen: false, sinkClass: 'NONE' },
      at: Date.now(),
      executed: true,
    });
  }

  private applyPostExecutionEffects(tool: ToolExecutor, call: ToolCall, result: unknown): void {
    const capabilities = tool.capabilities;

    if (capabilities.readsPrivateData) {
      markPrivateDataSeen(this.currentScope);
    }

    if (tool.isSource && !tool.trusted) {
      const text = toRegistrableText(result);
      const sensitivity = capabilities.readsPrivateData
        ? { containsPrivateData: true, categories: capabilities.readsPrivateData.categories }
        : NOT_SENSITIVE;
      const provenance = {
        id: exactHash(text),
        sourceCallId: call.id,
        toolName: tool.name,
        sessionId: this.sessionId,
        capturedAt: Date.now(),
      };
      this.registry.register(text, provenance, 'RAW_UNTRUSTED', sensitivity);
      raiseWatermark(this.currentScope, 'RAW_UNTRUSTED', provenance);
    }
  }
}

export function createBroker(opts: BrokerOptions = {}): ToolCallBroker {
  return new Broker(opts);
}
