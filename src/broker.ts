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
  CallResult,
  PlanStep,
  PolicyFn,
  ProvenanceTag,
  QuarantineFn,
  QuarantineImpl,
  QuarantineSourceResult,
  RawQuarantineSourceTool,
  ResetScope,
  SinkClass,
  TaintContext,
  TaintLevel,
  TaintRegistry,
  TaintScope,
  TaintWatermark,
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
import { isReservedToolName, isUntrustedSource, recordTrivialAudit } from './internal-audit.js';
import {
  DualRoleToolError,
  NonCloneableArgsError,
  PlanNotDeclarableError,
  QuarantineSourceUnavailableError,
  ReentrantCallError,
  ReservedToolNameError,
  ToolCallBlockedError,
  UnknownToolError,
  UnplannedPrivilegedActionError,
} from './errors.js';

export interface BrokerOptions {
  sessionId?: string;
  /** 'session' (default) never resets until an explicit declassify(); 'turn' trades soundness for usability — GAPS.md #2. 'turn-decay' is a bounded middle ground — see turnDecayWindow. */
  resetScope?: ResetScope;
  /**
   * Required when `resetScope` is `'turn-decay'`; ignored otherwise. The
   * number of consecutive turns with no NEW exposure (no watermark raise)
   * required before the watermark clears. Must be a positive integer.
   * `turnDecayWindow: 1` is exactly equivalent to `resetScope: 'turn'`
   * (clears at the very next turn boundary) — turn-decay generalizes 'turn'
   * mode, it doesn't replace it. No default is picked for you: this is a
   * security-relevant magic number (how many turns of residual risk you're
   * accepting in exchange for less approval friction) the integrator must
   * choose deliberately. See DESIGN.md's implementation note and GAPS.md #2.
   */
  turnDecayWindow?: number;
  policy?: PolicyFn;
  approvalChannel?: ApprovalChannel;
  auditSink?: AuditSink;
  /** The capability-less LLM call used by broker.summarize(). No default — see quarantine.ts. */
  quarantineImpl?: QuarantineImpl;
  registry?: TaintRegistry;
  /**
   * Restores a previously-exported `broker.scope.watermark` (e.g. from a
   * prior process, persisted alongside a restored registry) instead of
   * starting CLEAN. `TaintWatermark` is a plain JSON-able object — no
   * special deserialization needed. See GAPS.md #12 and persistence.ts for
   * the matching registry-side restore helpers.
   */
  initialWatermark?: TaintWatermark;
  /**
   * Custom args cloner, used in place of `structuredClone` for snapshotting
   * (see NonCloneableArgsError). Only needed if a tool's arguments include
   * values `structuredClone` can't handle (functions, most class
   * instances, WeakMap/WeakSet). Must still produce an independent copy —
   * returning the input unchanged reopens the args-mutation gap this
   * snapshotting exists to close.
   */
  cloneArgs?: (value: unknown) => unknown;
  /**
   * Opt-in advisory heuristic for GAPS.md #1: when a call to a tool NOT
   * registered `isSource: true` returns at least this many characters of
   * text, an `ALLOW_WITH_WARNING` `AuditEvent` flags it — the most probable
   * real-world way #1 bites isn't an exotic untracked channel, it's an
   * ordinary source tool (a wiki reader, a Slack fetcher) that simply
   * forgot the `isSource: true` declaration, so its results never raise
   * the watermark. Purely advisory: never changes the watermark, never
   * gates anything, and can false-positive on a genuinely large but
   * inert/trusted result — tune the threshold (or leave this unset) per
   * how noisy that is for your tools. `true` uses a default threshold of
   * 200 characters; a number sets your own.
   */
  warnOnLikelyUnmarkedSource?: boolean | number;
}

const DEFAULT_UNMARKED_SOURCE_WARN_THRESHOLD = 200;

const NOOP_AUDIT: AuditSink = { record() {} };

function blockedMessage(toolName: string, decision: { action: string; reason?: string }): string {
  const reason = decision.reason ?? 'no approval channel was configured to grant it';
  return `Tool call "${toolName}" was not executed (${decision.action}): ${reason}`;
}

class Broker implements ToolCallBroker {
  private readonly sessionId: string;
  private readonly resetScopeMode: ResetScope;
  /** Only meaningful when resetScopeMode === 'turn-decay'; validated non-undefined in the constructor for that mode. */
  private readonly turnDecayWindow: number | undefined;
  // 'turn-decay' mode's own counter: turns crossed (via startNewTurn())
  // since the watermark was last raised. Reset to 0 by every watermark
  // raise (raiseWatermarkAndResetDecay()); incremented by startNewTurn()
  // only while the watermark is non-CLEAN. Inert (never read) in 'turn'/
  // 'session' mode.
  private turnsSinceExposure = 0;
  private readonly policy: PolicyFn;
  private readonly approvalChannel: ApprovalChannel | undefined;
  private readonly auditSink: AuditSink;
  private readonly cloneArgs: (value: unknown) => unknown;
  private readonly warnOnLikelyUnmarkedSource: number | undefined;
  private readonly tools = new Map<string, ToolExecutor>();
  private currentScope: TaintScope;

  // Plan-freeze strict mode (DESIGN.md §11) — undefined means not opted in.
  // `cursor` is the index of the next step a privileged call must match.
  private plan: PlanStep[] | undefined;
  private planCursor = 0;

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
    if (this.resetScopeMode === 'turn-decay') {
      if (!Number.isInteger(opts.turnDecayWindow) || (opts.turnDecayWindow as number) < 1) {
        throw new RangeError(
          `createBroker({ resetScope: 'turn-decay' }) requires turnDecayWindow to be a positive integer, got ${opts.turnDecayWindow}. ` +
            "This is a deliberate security-relevant choice (how many turns of residual cross-turn exposure risk to accept) — there is no default.",
        );
      }
      this.turnDecayWindow = opts.turnDecayWindow;
    } else {
      this.turnDecayWindow = undefined;
    }
    this.policy = opts.policy ?? defaultPolicy;
    this.approvalChannel = opts.approvalChannel;
    this.auditSink = opts.auditSink ?? NOOP_AUDIT;
    this.cloneArgs = opts.cloneArgs ?? structuredClone;
    this.warnOnLikelyUnmarkedSource =
      opts.warnOnLikelyUnmarkedSource === true
        ? DEFAULT_UNMARKED_SOURCE_WARN_THRESHOLD
        : opts.warnOnLikelyUnmarkedSource === false || opts.warnOnLikelyUnmarkedSource === undefined
          ? undefined
          : opts.warnOnLikelyUnmarkedSource;
    this.registry = opts.registry ?? new InMemoryTaintRegistry();
    this.currentScope = createScope(this.resetScopeMode, this.sessionId);
    if (opts.initialWatermark) {
      this.currentScope.watermark = { ...opts.initialWatermark, sources: [...opts.initialWatermark.sources] };
    }
    this.summarize = createQuarantine({
      impl: opts.quarantineImpl ?? unconfiguredQuarantineImpl,
      registry: this.registry,
      raiseToDerivedUntrusted: (tag) => this.raiseWatermarkAndResetDecay('DERIVED_UNTRUSTED', tag),
      getScope: () => this.currentScope.watermark,
      auditSink: this.auditSink,
    });
  }

  get scope(): Readonly<TaintScope> {
    return this.currentScope;
  }

  /**
   * The one path every watermark raise in this class must go through
   * (instead of calling the imported raiseWatermark() directly): resets
   * 'turn-decay' mode's turnsSinceExposure counter to 0 on every NEW
   * exposure, so the decay window restarts from the latest exposure rather
   * than the first. A no-op write in 'turn'/'session' mode — cheap enough
   * not to bother branching on resetScopeMode here.
   */
  private raiseWatermarkAndResetDecay(level: TaintLevel, tag?: ProvenanceTag): void {
    raiseWatermark(this.currentScope, level, tag);
    this.turnsSinceExposure = 0;
  }

  /** Best-effort deep clone for args snapshotting; throws NonCloneableArgsError rather than silently degrading — see GAPS.md #16. */
  private cloneArgsOrThrow(toolName: string, value: unknown): unknown {
    try {
      return this.cloneArgs(value);
    } catch (cause) {
      throw new NonCloneableArgsError(toolName, cause);
    }
  }

  declarePlan(steps: PlanStep[]): void {
    if (this.currentScope.watermark.level !== 'CLEAN') {
      throw new PlanNotDeclarableError();
    }
    this.plan = [...steps];
    this.planCursor = 0;
  }

  register(tool: ToolExecutor): void {
    if (isReservedToolName(tool.name)) {
      // Reserved for the broker's own internal/administrative audit events
      // (see internal-audit.ts) — a real tool registered under this prefix
      // would be indistinguishable from one of those in the audit log.
      throw new ReservedToolNameError(tool.name);
    }
    const sinkClass = sinkClassOf(tool.capabilities.capabilities);
    if (isUntrustedSource(tool) && sinkClass !== 'NONE') {
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

  registerAll<T extends Record<string, ToolExecutor>>(tools: T): void {
    for (const tool of Object.values(tools)) this.register(tool);
  }

  wrapAll<T extends Record<string, ToolExecutor>>(tools: T): T {
    const wrapped = {} as Record<string, ToolExecutor>;
    for (const [key, tool] of Object.entries(tools)) {
      wrapped[key] = this.wrap(tool);
    }
    return wrapped as T;
  }

  registerRawForQuarantine<A = unknown, R = unknown>(
    tool: RawQuarantineSourceTool<A, R>,
  ): { name: string; execute(args: A): Promise<QuarantineSourceResult> } {
    const wrapped = this.wrap({
      name: tool.name,
      capabilities: { capabilities: [] },
      isSource: true,
      // Deliberately never `trusted` — a trusted source is never registered
      // into the fingerprint registry (see applyPostExecutionEffects), so
      // there would be no taintRecordId for this helper to hand back. See
      // RawQuarantineSourceTool's doc comment in types.ts.
      execute: tool.execute,
    });
    return {
      name: tool.name,
      execute: async (args: A): Promise<QuarantineSourceResult> => {
        const result = await wrapped.execute(args);
        // The call above already ran this through the normal call()/dispatch()
        // pipeline, which — for an isSource:true tool — registered its result
        // into the registry via applyPostExecutionEffects() using this exact
        // same toRegistrableText()+exactHash() derivation (see broker.ts). So
        // rather than re-deriving an id independently (and risking it silently
        // drift from whatever actually got registered — the lesson of
        // internal-audit.ts's isUntrustedSource() dedup), look up the record
        // that call already created and use ITS id.
        let text: string;
        try {
          text = toRegistrableText(result);
        } catch (cause) {
          throw new QuarantineSourceUnavailableError(tool.name, cause);
        }
        const record = this.registry.lookupExact(text);
        if (!record) {
          // Only reachable if applyPostExecutionEffects()'s own registration
          // failed for a reason this call's toRegistrableText() didn't hit
          // (shouldn't happen — same function, same input), or a bounded
          // registry (maxEntries, GAPS.md #13) evicted the record in the
          // narrow window between that registration and this lookup.
          throw new QuarantineSourceUnavailableError(tool.name);
        }
        return { text, taintRecordId: record.id };
      },
    };
  }

  /**
   * True for a call that can safely bypass the serialization lock entirely
   * — see DESIGN.md's implementation note on narrowing the lock to a
   * targeted barrier. A call is exempt only if it can neither READ the
   * watermark for a gating decision (`sinkClass === 'NONE'`) nor WRITE to
   * it (not an untrusted source that would raise the level, and doesn't
   * read private data that would set `privateDataSeen`). An exempt call's
   * entire dispatch — gating (skipped for NONE), execute(), and
   * applyPostExecutionEffects() — is then provably inert to
   * `this.currentScope.watermark` in both directions, so its presence or
   * absence in the lock queue cannot affect the correctness of any other
   * call's relative ordering. An unknown tool name is deliberately never
   * exempt (see call() below) — it falls through to dispatch()'s own
   * UnknownToolError inside the lock, same as today, just via the "not
   * exempt" path rather than a special case here.
   */
  private isBarrierExempt(tool: ToolExecutor, sinkClass: SinkClass): boolean {
    return sinkClass === 'NONE' && !isUntrustedSource(tool) && !tool.capabilities.readsPrivateData;
  }

  async call(toolName: string, args: unknown): Promise<unknown> {
    if (this.reentrancyGuard.getStore()) {
      throw new ReentrantCallError(toolName);
    }
    // Tool lookup + sinkClass + exemption decision all happen synchronously
    // here, before any `await` — exactly like withLock()'s own queue-join
    // happens synchronously today — so an exempt call's decision to skip
    // the queue is made at the same deterministic invocation-order point a
    // participating call's queue position would be captured at. dispatch()
    // still does its own tool lookup independently; recomputing sinkClass
    // there too is cheap and can't disagree (same tool object, pure function).
    const tool = this.tools.get(toolName);
    const run = (): Promise<unknown> => this.reentrancyGuard.run(true, () => this.dispatch(toolName, args));
    if (tool && this.isBarrierExempt(tool, sinkClassOf(tool.capabilities.capabilities))) {
      return run();
    }
    return this.withLock(run);
  }

  async callSafe(toolName: string, args: unknown): Promise<CallResult> {
    try {
      const result = await this.call(toolName, args);
      return { ok: true, result };
    } catch (error) {
      return { ok: false, error };
    }
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
    const argsSnapshot = this.cloneArgsOrThrow(toolName, args);
    const call: ToolCall = { id: randomUUID(), toolName, args: argsSnapshot, sessionId: this.sessionId };
    const sinkClass = sinkClassOf(tool.capabilities.capabilities);

    let result: unknown;

    if (sinkClass === 'NONE') {
      // Not a privileged sink: no gating. Source tools (fetch_url,
      // read_email, ...) typically land here — their taint effects are
      // applied below, after execution, regardless of sinkClass. A NONE-
      // sinkClass call with no side effect on the watermark/private-data
      // flag (an ordinary noop, or a trusted source) still gets no audit
      // record — nothing safety-relevant happened. One that DOES raise the
      // watermark or the private-data flag is audited below, after those
      // effects are applied, so the recorded taint reflects the new state.
      result = await tool.execute(this.cloneArgsOrThrow(toolName, args));
    } else {
      const { matches, floor } = scanArgsForTaint(argsSnapshot, this.registry);
      const taint: TaintContext = {
        matchedRecords: matches,
        scopeLevel: this.currentScope.watermark.level,
        argFingerprintFloor: floor,
        privateDataSeen: this.currentScope.watermark.privateDataSeen,
        sinkClass,
      };

      // Plan-freeze strict mode (DESIGN.md §11), additive on top of the
      // normal policy check below, never instead of it. Only engages once
      // the scope has left CLEAN — a plan is inert until the first
      // exposure, exactly matching "committed before any untrusted read".
      if (this.plan !== undefined && this.currentScope.watermark.level !== 'CLEAN') {
        const expected = this.plan[this.planCursor];
        if (!expected || expected.toolName !== toolName) {
          this.auditSink.record({
            verdict: {
              action: 'BLOCK',
              reason: `Unplanned privileged action after exposure (plan-freeze strict mode): ${
                expected ? `expected "${expected.toolName}"` : 'no steps left in the declared plan'
              }.`,
            },
            call,
            taint,
            at: Date.now(),
            executed: false,
          });
          throw new UnplannedPrivilegedActionError(toolName, expected?.toolName);
        }
        this.planCursor++;
      }

      const decision = await this.policy(call, taint);
      let executed = false;

      if (decision.action === 'ALLOW' || decision.action === 'ALLOW_WITH_WARNING') {
        result = await tool.execute(this.cloneArgsOrThrow(toolName, args));
        executed = true;
      } else if (decision.action === 'REQUIRE_APPROVAL') {
        const granted = this.approvalChannel ? await this.approvalChannel.requestApproval(call, taint, decision) : false;
        if (granted) {
          result = await tool.execute(this.cloneArgsOrThrow(toolName, args));
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

    if (sinkClass === 'NONE' && (tool.capabilities.readsPrivateData || isUntrustedSource(tool))) {
      const reasons: string[] = [];
      if (isUntrustedSource(tool)) reasons.push(`untrusted source call raised the scope watermark to ${this.currentScope.watermark.level}.`);
      if (tool.capabilities.readsPrivateData) reasons.push('private data was read this scope (lethal-trifecta escalator, §3.2).');
      recordTrivialAudit(this.auditSink, { action: 'ALLOW_WITH_WARNING', reason: reasons.join(' ') }, call, this.currentScope.watermark, true);
    }

    if (this.warnOnLikelyUnmarkedSource !== undefined && sinkClass === 'NONE' && !tool.isSource) {
      // Opt-in, purely advisory (GAPS.md #1): the most probable real-world
      // way #1 bites isn't an exotic untracked channel, it's an ordinary
      // source tool that simply forgot isSource:true, so its results never
      // raise the watermark — silently, with no error and no test failure
      // to catch it. Best-effort like applyPostExecutionEffects()'s own
      // serialization — a result toRegistrableText() can't handle just
      // skips the check rather than throwing.
      let text: string | undefined;
      try {
        text = toRegistrableText(result);
      } catch {
        text = undefined;
      }
      if (text !== undefined && text.length >= this.warnOnLikelyUnmarkedSource) {
        recordTrivialAudit(
          this.auditSink,
          {
            action: 'ALLOW_WITH_WARNING',
            reason: `Advisory: tool "${toolName}" is not registered isSource:true but returned ${text.length} chars of text (>= the warnOnLikelyUnmarkedSource threshold of ${this.warnOnLikelyUnmarkedSource}). If this tool can return content the agent didn't originate, it likely should be isSource:true (GAPS.md #1) — this warning never changes the watermark or gates anything on its own.`,
          },
          call,
          this.currentScope.watermark,
          true,
        );
      }
    }

    return result;
  }

  markContextExposure(source: { toolName?: string; note: string; text?: string }, level: TaintLevel = 'RAW_UNTRUSTED'): void {
    // Optional `text`: registers the actual exposed content into the Layer
    // 2 fingerprint registry (mirroring applyPostExecutionEffects()'s
    // register-then-raise pattern for ordinary source-tool calls), instead
    // of leaving this channel's content permanently invisible to fuzzy
    // matching. Best-effort like that path too — a text that can't be
    // fingerprinted (unlikely here, since it's always a plain string
    // already, not an arbitrary result needing serialization) still raises
    // the watermark; registration just falls back to a random id.
    const provenance = {
      id: source.text !== undefined ? exactHash(source.text) : randomUUID(),
      sourceCallId: `context-exposure:${randomUUID()}`,
      toolName: source.toolName ?? '__untracked_context__',
      sessionId: this.sessionId,
      capturedAt: Date.now(),
      note: source.note,
    };
    if (source.text !== undefined) {
      this.registry.register(source.text, provenance, level, NOT_SENSITIVE);
    }
    this.raiseWatermarkAndResetDecay(level, provenance);
    recordTrivialAudit(
      this.auditSink,
      {
        action: 'ALLOW_WITH_WARNING',
        reason: `markContextExposure(): untrusted content reached the model outside any tracked tool call (${provenance.toolName}) — "${source.note}". This is the manual escape hatch for GAPS.md #1; the library could not detect this exposure on its own.`,
      },
      {
        id: provenance.sourceCallId,
        toolName: '__tttb_context_exposure',
        args: { toolName: source.toolName, note: source.note, level, ...(source.text !== undefined ? { text: source.text } : {}) },
        sessionId: this.sessionId,
      },
      this.currentScope.watermark,
      true,
    );
  }

  markToolDescriptionExposure(toolName: string, description: string, level: TaintLevel = 'RAW_UNTRUSTED'): void {
    this.markContextExposure(
      { toolName, note: `tool/plugin description exposure: "${toolName}"'s description was ingested (or changed) outside a tracked tool call — see GAPS.md #1.`, text: description },
      level,
    );
  }

  markSystemPromptExposure(note: string, text?: string, level: TaintLevel = 'RAW_UNTRUSTED'): void {
    this.markContextExposure({ toolName: 'system-prompt', note: `system-prompt exposure: ${note}`, ...(text !== undefined ? { text } : {}) }, level);
  }

  markPastedContentExposure(note: string, text?: string, level: TaintLevel = 'RAW_UNTRUSTED'): void {
    this.markContextExposure({ toolName: 'pasted-content', note: `user-pasted content exposure: ${note}`, ...(text !== undefined ? { text } : {}) }, level);
  }

  /**
   * Shared by 'turn' mode (called every startNewTurn()) and 'turn-decay'
   * mode (called only once its decay window has elapsed, from within
   * startNewTurn()'s own branch below): actually clears the scope to a
   * fresh CLEAN watermark, resets the declared plan alongside it, and
   * audits a discarded non-CLEAN watermark.
   *
   * A declared plan (declarePlan(), §11) is a commitment tied to the
   * exposure episode it was made against. Leaving it in place across a
   * reset that just cleared that episode's watermark would silently
   * constrain unrelated future actions — with no way for the agent to know
   * a plan is even still in effect — and fixes nothing, since plan-freeze
   * is additive: a stale plan can only ever cause spurious blocking, never
   * a bypass.
   *
   * Only worth an audit entry when there was something to discard —
   * routine resets of an already-CLEAN scope are not a safety-relevant
   * event and shouldn't add audit-log noise. Discarding a genuinely
   * non-CLEAN watermark is exactly the moment GAPS.md #2's cross-turn risk
   * crystallizes, though, and (unlike declassify()) had no audit trail
   * before this. `buildReason` is only invoked when there's something to
   * audit, and receives the pre-clear level/hadPlan so each caller can
   * phrase its own reason text without duplicating this snapshot/clear
   * sequence.
   */
  private clearScopeForTurnReset(kind: 'turn' | 'turn-decay', buildReason: (priorLevel: TaintLevel, hadPlan: boolean) => string): void {
    const priorLevel = this.currentScope.watermark.level;
    const priorPrivateDataSeen = this.currentScope.watermark.privateDataSeen;
    const hadPlan = this.plan !== undefined;
    this.currentScope = createScope(kind, randomUUID());
    this.plan = undefined;
    this.planCursor = 0;
    this.turnsSinceExposure = 0;
    if (priorLevel !== 'CLEAN') {
      recordTrivialAudit(
        this.auditSink,
        { action: 'ALLOW_WITH_WARNING', reason: buildReason(priorLevel, hadPlan) },
        { id: randomUUID(), toolName: '__tttb_turn_reset', args: {}, sessionId: this.sessionId },
        { level: priorLevel, privateDataSeen: priorPrivateDataSeen },
        true,
      );
    }
  }

  startNewTurn(): void {
    if (this.resetScopeMode === 'turn') {
      this.clearScopeForTurnReset(
        'turn',
        (priorLevel, hadPlan) =>
          `startNewTurn(): turn boundary discarded a ${priorLevel} watermark${hadPlan ? ' and its declared plan' : ''} under resetScope:'turn'. See GAPS.md #2.`,
      );
    } else if (this.resetScopeMode === 'turn-decay') {
      // Nothing to decay from an already-CLEAN scope — stay silent, same as
      // 'turn' mode's own early exit (via clearScopeForTurnReset()'s own
      // priorLevel !== 'CLEAN' check). Checked here too so a CLEAN scope
      // never even advances turnsSinceExposure — the counter only means
      // "turns since the CURRENT exposure episode started."
      if (this.currentScope.watermark.level === 'CLEAN') return;
      this.turnsSinceExposure++;
      if (this.turnsSinceExposure >= this.turnDecayWindow!) {
        const window = this.turnDecayWindow;
        this.clearScopeForTurnReset(
          'turn-decay',
          (priorLevel, hadPlan) =>
            `startNewTurn(): turn-decay window (${window} turn(s) with no new exposure) elapsed — discarded a ${priorLevel} watermark${hadPlan ? ' and its declared plan' : ''} under resetScope:'turn-decay'. See GAPS.md #2.`,
        );
      }
      // else: still within the decay window — watermark persists untouched, no audit noise (nothing changed yet).
    }
    // 'session' mode: no-op by design — the watermark persists for the whole session (§4.1).
  }

  declassify(reason: string, approvedBy: string): void {
    // Snapshot the watermark's VALUES before clearing it — declassifyScope()
    // mutates this.currentScope.watermark in place, so a plain reference
    // taken beforehand would already read back as CLEAN afterward. Recording
    // what was actually cleared (not just "declassify happened, now CLEAN",
    // which is true of every declassify() call and so tells an investigator
    // nothing) is the point of auditing this action at all.
    const priorLevel = this.currentScope.watermark.level;
    const priorPrivateDataSeen = this.currentScope.watermark.privateDataSeen;
    declassifyScope(this.currentScope);
    // Defensive, not load-bearing: a stale nonzero counter left over from
    // before this declassify() is already inert while the scope reads
    // CLEAN (startNewTurn()'s 'turn-decay' branch returns early on CLEAN,
    // and any future raise resets the counter itself anyway) — reset here
    // too so the invariant is locally obvious, not something a future
    // change could accidentally depend on non-local reasoning to keep true.
    this.turnsSinceExposure = 0;
    recordTrivialAudit(
      this.auditSink,
      {
        action: 'ALLOW_WITH_WARNING',
        reason: `declassify(): watermark manually cleared from ${priorLevel} — reason: "${reason}"; approved by ${approvedBy}.`,
      },
      { id: randomUUID(), toolName: '__tttb_declassify', args: { reason, approvedBy }, sessionId: this.sessionId },
      { level: priorLevel, privateDataSeen: priorPrivateDataSeen },
      true,
    );
  }

  private applyPostExecutionEffects(tool: ToolExecutor, call: ToolCall, result: unknown): void {
    const capabilities = tool.capabilities;

    if (capabilities.readsPrivateData) {
      markPrivateDataSeen(this.currentScope);
    }

    if (isUntrustedSource(tool)) {
      // The watermark raise below is Layer 0 — load-bearing, must never be
      // skipped for an untrusted source's result. Fingerprint registration
      // (Layer 2) is best-effort/never load-bearing by design (§4.2) — so a
      // result toRegistrableText() can't serialize (e.g. JSON.stringify
      // throwing on a circular object, a realistic shape for a raw
      // HTTP-client/response result) must not be allowed to silently
      // suppress the raise it would otherwise gate. structuredClone (used
      // to snapshot args elsewhere) tolerates cycles; JSON.stringify does
      // not, so this is a real, reachable gap, not just a theoretical one.
      let text: string | undefined;
      try {
        text = toRegistrableText(result);
      } catch {
        text = undefined;
      }
      const provenance = {
        id: text !== undefined ? exactHash(text) : randomUUID(),
        sourceCallId: call.id,
        toolName: tool.name,
        sessionId: this.sessionId,
        capturedAt: Date.now(),
      };
      if (text !== undefined) {
        const sensitivity = capabilities.readsPrivateData
          ? { containsPrivateData: true, categories: capabilities.readsPrivateData.categories }
          : NOT_SENSITIVE;
        this.registry.register(text, provenance, 'RAW_UNTRUSTED', sensitivity);
      }
      this.raiseWatermarkAndResetDecay('RAW_UNTRUSTED', provenance);
    }
  }
}

export function createBroker(opts: BrokerOptions = {}): ToolCallBroker {
  return new Broker(opts);
}
