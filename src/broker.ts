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
  PolicyDecision,
  PolicyFn,
  ProvenanceTag,
  QuarantineFn,
  QuarantineImpl,
  QuarantineOpts,
  QuarantineResult,
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
import { LEVEL_ORDER, NOT_SENSITIVE, sinkClassOf } from './types.js';
import { InMemoryTaintRegistry } from './taint/registry.js';
import {
  createScope,
  declassifyScope,
  markPrivateDataSeen,
  raiseWatermark,
} from './taint/scope.js';
import { scanArgsForTaint } from './taint/scan.js';
import { findOutboundHosts, isAllowedOutboundHost } from './taint/egress.js';
import { exactHash, toRegistrableText } from './taint/fingerprint.js';
import { defaultPolicy } from './policy/default-policy.js';
import { createQuarantine, unconfiguredQuarantineImpl } from './quarantine.js';
import { isReservedToolName, isUntrustedSource, recordTrivialAudit } from './internal-audit.js';
import {
  ArgsTooDeepError,
  DisallowedOutboundHostError,
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
  /**
   * Identifies this broker instance in ProvenanceTag/ToolCall/AuditEvent
   * records. Defaults to a fresh `randomUUID()` — pass your own only if you
   * need audit records to carry an externally-meaningful session id (e.g.
   * to correlate with your own request-tracing).
   *
   * This is NOT a lookup key for sharing state across broker instances —
   * two `createBroker()` calls given the same `sessionId` do not share a
   * watermark, registry, or lock; each is a fully independent object with
   * its own in-memory state (GAPS.md #19). One `Broker` instance IS one
   * session: create exactly one per agent conversation/session and reuse
   * it for that session's entire lifetime (across turns — via
   * `startNewTurn()`/`resetScope`, never a new broker), and never share a
   * single instance across two concurrent, unrelated sessions — every
   * `call()` on one instance is serialized against every other `call()` on
   * that SAME instance (§8's core guarantee), which is meaningless
   * isolation between sessions if one instance is reused for more than
   * one. See createBroker()'s own doc comment.
   */
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
  /**
   * Opt-in outbound-host allowlist for EXFIL-class sink calls (`net:outbound`
   * / `net:email` / `net:api-call` / `net:post-message`). When set, every
   * such call's arguments are scanned for genuine http(s) URLs
   * (`taint/egress.ts`'s `findOutboundHosts`); if any found hostname isn't
   * in the allowlist, the call is rejected with `DisallowedOutboundHostError`
   * — a pure firewall-style rule, independent of the taint-based policy in
   * §7.2 and applied even to a `CLEAN` scope, since the point of an explicit
   * allowlist is a structural boundary rather than another approval prompt
   * (GAPS.md #7's fatigue risk). A string array is matched exactly
   * (case-insensitively, no subdomain/wildcard matching); a predicate
   * function gets the lowercased hostname directly for callers who want
   * that. Deliberately narrow in scope — see DESIGN.md §7.4 and GAPS.md #18
   * for exactly what this does and doesn't cover (a call with no http(s)
   * URL argument at all, e.g. a bare email address, is invisible to this
   * check; it is not a general egress-classification mechanism).
   */
  allowedOutboundHosts?: readonly string[] | ((hostname: string) => boolean);
  /**
   * Opt-in advisory heuristic for GAPS.md #10, mirroring
   * `warnOnLikelyUnmarkedSource` above: when `register()`/`wrap()` is
   * called for a tool declaring NO sink capabilities (`sinkClass === 'NONE'`
   * — invisible to every policy check) whose `name` contains a keyword that
   * often indicates a mutating/dangerous action, an `ALLOW_WITH_WARNING`
   * `AuditEvent` flags it at registration time. The most probable real-world
   * way #10 bites isn't a deliberately-deceptive tool (this heuristic
   * cannot catch that — a genuinely deceptive tool wouldn't be named
   * `delete_row` in the first place) — it's an ordinary tool (a
   * `write_file`, a `send_email`, a `delete_row`) whose `capabilities` array
   * was simply left empty or wrong by mistake. Purely advisory: never
   * changes what's registered or gates anything, and can false-positive on
   * a genuinely inert tool whose name happens to contain a matched keyword
   * — tune the keyword list (or leave this unset) per how noisy that is for
   * your tools. `true` uses a default keyword list (`write`, `delete`,
   * `remove`, `exec`, `execute`, `send`, `post`, `purchase`, `pay`,
   * `transfer`, `email`, `publish`, `deploy`, `shell`, `upload`); an array
   * sets your own (case-insensitive substring match against the tool name).
   */
  warnOnLikelyUnclassifiedSink?: boolean | readonly string[];
}

const DEFAULT_UNMARKED_SOURCE_WARN_THRESHOLD = 200;

const DEFAULT_UNCLASSIFIED_SINK_KEYWORDS: readonly string[] = [
  'write',
  'delete',
  'remove',
  'exec',
  'execute',
  'send',
  'post',
  'purchase',
  'pay',
  'transfer',
  'email',
  'publish',
  'deploy',
  'shell',
  'upload',
];

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
  private readonly allowedOutboundHosts:
    readonly string[] | ((hostname: string) => boolean) | undefined;
  private readonly warnOnLikelyUnclassifiedSink: readonly string[] | undefined;
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
  // above, so it's rejected immediately instead. Also tells summarize()
  // (GAPS.md #17) whether it's already running inside a call() that HOLDS
  // the lock (safe to raise the watermark inline, no new lock needed) or
  // is nested inside a barrier-exempt call that never took the lock (must
  // acquire it itself, exactly like a top-level summarize() call would) —
  // see summarize()'s own wrapper in the constructor below.
  private readonly reentrancyGuard = new AsyncLocalStorage<{ lockHeld: boolean }>();

  readonly registry: TaintRegistry;
  // The actual quarantine logic (quarantine.ts), unaware of locking — see
  // the constructor for the serialization wrapper assigned to `summarize`
  // itself (GAPS.md #17).
  private readonly rawSummarize: QuarantineFn;
  readonly summarize: QuarantineFn;

  constructor(opts: BrokerOptions = {}) {
    this.sessionId = opts.sessionId ?? randomUUID();
    this.resetScopeMode = opts.resetScope ?? 'session';
    if (this.resetScopeMode === 'turn-decay') {
      if (!Number.isInteger(opts.turnDecayWindow) || (opts.turnDecayWindow as number) < 1) {
        throw new RangeError(
          `createBroker({ resetScope: 'turn-decay' }) requires turnDecayWindow to be a positive integer, got ${opts.turnDecayWindow}. ` +
            'This is a deliberate security-relevant choice (how many turns of residual cross-turn exposure risk to accept) — there is no default.',
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
    this.allowedOutboundHosts = opts.allowedOutboundHosts;
    this.warnOnLikelyUnclassifiedSink =
      opts.warnOnLikelyUnclassifiedSink === true
        ? DEFAULT_UNCLASSIFIED_SINK_KEYWORDS
        : opts.warnOnLikelyUnclassifiedSink === false ||
            opts.warnOnLikelyUnclassifiedSink === undefined
          ? undefined
          : opts.warnOnLikelyUnclassifiedSink;
    this.registry = opts.registry ?? new InMemoryTaintRegistry();
    this.currentScope = createScope(this.resetScopeMode, this.sessionId);
    if (opts.initialWatermark) {
      this.currentScope.watermark = {
        ...opts.initialWatermark,
        sources: [...opts.initialWatermark.sources],
      };
    }
    this.rawSummarize = createQuarantine({
      impl: opts.quarantineImpl ?? unconfiguredQuarantineImpl,
      registry: this.registry,
      raiseToDerivedUntrusted: (tag) => this.raiseWatermarkAndResetDecay('DERIVED_UNTRUSTED', tag),
      getScope: () => this.currentScope.watermark,
      auditSink: this.auditSink,
    });
    // GAPS.md #17: summarize() raises the watermark exactly like a source
    // call does, so it needs the same happens-before guarantee relative to
    // a concurrently-dispatched call() — but it must not naively join the
    // same lock unconditionally, or the documented fetch-and-quarantine
    // composite-tool pattern (§6.2, calling broker.summarize() from within
    // a tool's own execute()) would deadlock on a lock that call already
    // holds. reentrancyGuard's lockHeld flag distinguishes the two cases:
    // already inside a lock-holding call() -> raise inline, already
    // serialized, no new lock needed; anything else (a genuine top-level
    // call, OR nested inside a barrier-EXEMPT call that never took the lock
    // at all) -> acquire the lock exactly like a fresh call() would.
    this.summarize = <S = string>(
      text: string,
      quarantineOpts: QuarantineOpts<S>,
    ): Promise<QuarantineResult<S>> => {
      const ctx = this.reentrancyGuard.getStore();
      if (ctx?.lockHeld) {
        return this.rawSummarize<S>(text, quarantineOpts);
      }
      return this.withLock(() =>
        this.reentrancyGuard.run({ lockHeld: true }, () =>
          this.rawSummarize<S>(text, quarantineOpts),
        ),
      );
    };
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
    if (this.warnOnLikelyUnclassifiedSink !== undefined && sinkClass === 'NONE') {
      // Opt-in, purely advisory (GAPS.md #10): the most probable real-world
      // way #10 bites isn't a deliberately-deceptive tool (this cannot catch
      // that — see BrokerOptions' own doc comment), it's an ordinary tool
      // (a write_file, a send_email, a delete_row) whose capabilities array
      // was simply left empty or wrong by mistake, the same "integrator
      // forgot the declaration" shape warnOnLikelyUnmarkedSource catches for
      // GAPS.md #1. Checked once at registration time (a static property of
      // the declaration), not per-call like warnOnLikelyUnmarkedSource
      // (which needs the actual returned text length, a runtime property).
      const nameLower = tool.name.toLowerCase();
      const matchedKeyword = this.warnOnLikelyUnclassifiedSink.find((kw) =>
        nameLower.includes(kw.toLowerCase()),
      );
      if (matchedKeyword !== undefined) {
        recordTrivialAudit(
          this.auditSink,
          {
            action: 'ALLOW_WITH_WARNING',
            reason: `Advisory: tool "${tool.name}" declares no sink capabilities (capabilities: []) but its name contains "${matchedKeyword}", which often indicates a mutating/dangerous action (GAPS.md #10). If this tool actually performs exec/write/exfil, it likely needs a non-empty capabilities array — this warning never changes what's registered or gates anything on its own.`,
          },
          {
            id: randomUUID(),
            toolName: '__tttb_registration_warning',
            args: { toolName: tool.name, matchedKeyword },
            sessionId: this.sessionId,
          },
          this.currentScope.watermark,
          true,
        );
      }
    }
    this.tools.set(tool.name, tool);
  }

  /** Registers `executor` and returns a drop-in replacement whose execute() is interposed through call(). */
  wrap<T extends ToolExecutor>(executor: T): T {
    this.register(executor);
    return { ...executor, execute: (args: unknown) => this.call(executor.name, args) };
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
      // RawQuarantineSourceTool's doc comment in types.ts. Bound (not a
      // bare reference) since ToolExecutor.execute is a method-shorthand
      // interface member — an integrator's implementation is free to use
      // `this` internally, and extracting it unbound would silently break
      // that once it's called here detached from `tool`.
      execute: tool.execute.bind(tool),
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
   * it: not an untrusted source that would raise the level, doesn't read
   * private data that would set `privateDataSeen`, AND — GAPS.md #17's
   * fetch-and-quarantine interaction, found while implementing that fix —
   * does not declare `mayCallSummarize`. Without that last check, a
   * composite tool whose execute() calls `broker.summarize()` internally
   * (a real, documented pattern, §6.2) could still raise the watermark
   * indirectly through that nested call; being exempt means the OUTER call
   * never reserved a lock position, so a call dispatched after it can slip
   * past before the nested summarize() is even reached, let alone resolved
   * — summarize()'s own lock-awareness alone cannot fix this, since by the
   * time it runs, another call's gating check may already have completed.
   * `mayCallSummarize` is an integrator declaration, not something this
   * check can infer from a tool's shape (the library cannot see into an
   * execute() function body) — the same "integrator declares, library
   * enforces" trust boundary `isSource`/`readsPrivateData` already rest on
   * (GAPS.md #10). An exempt call's entire dispatch is otherwise provably
   * inert to `this.currentScope.watermark` in both directions, so its
   * presence or absence in the lock queue cannot affect the correctness of
   * any other call's relative ordering. An unknown tool name is
   * deliberately never exempt (see call() below) — it falls through to
   * dispatch()'s own UnknownToolError inside the lock, same as today, just
   * via the "not exempt" path rather than a special case here.
   */
  private isBarrierExempt(tool: ToolExecutor, sinkClass: SinkClass): boolean {
    return (
      sinkClass === 'NONE' &&
      !isUntrustedSource(tool) &&
      !tool.capabilities.readsPrivateData &&
      !tool.mayCallSummarize
    );
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
    if (tool && this.isBarrierExempt(tool, sinkClassOf(tool.capabilities.capabilities))) {
      // Exempt: never touches the lock, so the context records lockHeld:false
      // — a nested broker.summarize() call must still acquire the lock
      // itself (GAPS.md #17), it cannot assume one is already held here.
      return this.reentrancyGuard.run({ lockHeld: false }, () => this.dispatch(toolName, args));
    }
    if (!tool || sinkClassOf(tool.capabilities.capabilities) === 'NONE') {
      // Unknown tool name (dispatch() throws UnknownToolError inside the
      // lock, same as always), or a non-exempt NONE-sinkClass call (an
      // untrusted source, a readsPrivateData source, or a
      // mayCallSummarize tool): serialize through the lock for the whole
      // call, exactly as before this fix. Only the GATED path below gets
      // multi-phase locking — a NONE-sinkClass call is never gated, so it
      // has no REQUIRE_APPROVAL wait to release the lock around.
      return this.withLock(() =>
        this.reentrancyGuard.run({ lockHeld: true }, () => this.dispatch(toolName, args)),
      );
    }
    // Gated (sinkClass !== 'NONE'): dispatch() delegates to dispatchGated(),
    // which acquires and releases the broker lock itself across separate
    // phases — notably, it releases the lock for a REQUIRE_APPROVAL wait —
    // rather than one call()-level withLock() holding it for the whole,
    // potentially human-timescale, operation (a prior liveness bug: every
    // other gated call on this broker froze for the full approval wait).
    // lockHeld:true here is only the initial value; dispatchGated()'s own
    // phases immediately establish the accurate value for each phase — see
    // its doc comment.
    return this.reentrancyGuard.run({ lockHeld: true }, () => this.dispatch(toolName, args));
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
    // requested" is needed (policy, approval, audit, AND execute()) — never
    // the live `args` object. Every execute() call site below clones from
    // this one frozen snapshot instead of re-deriving its own clone from
    // the live `args`. Otherwise a tool that mutates its own args in place
    // (an entirely ordinary pattern), or a caller that keeps mutating the
    // object it passed to call() after calling it (e.g. across a
    // REQUIRE_APPROVAL wait), could silently desync what the approval
    // channel showed a human and what the audit log records from what
    // actually executed.
    const argsSnapshot = this.cloneArgsOrThrow(toolName, args);
    const call: ToolCall = {
      id: randomUUID(),
      toolName,
      args: argsSnapshot,
      sessionId: this.sessionId,
    };
    const sinkClass = sinkClassOf(tool.capabilities.capabilities);

    if (sinkClass === 'NONE') {
      // Not a privileged sink: no gating. Source tools (fetch_url,
      // read_email, ...) typically land here — their taint effects are
      // applied below, after execution, regardless of sinkClass. A NONE-
      // sinkClass call with no side effect on the watermark/private-data
      // flag (an ordinary noop, or a trusted source) still gets no audit
      // record — nothing safety-relevant happened. One that DOES raise the
      // watermark or the private-data flag is audited below, after those
      // effects are applied, so the recorded taint reflects the new state.
      const result = await tool.execute(this.cloneArgsOrThrow(toolName, argsSnapshot));
      return this.finishDispatch(tool, call, sinkClass, result);
    }

    // Gated (privileged sink): dispatchGated() manages its own multi-phase
    // locking — see its doc comment for why.
    return this.dispatchGated(tool, call, argsSnapshot, sinkClass);
  }

  /** Builds a fresh TaintContext from the CURRENT watermark — the same shape captured once at the top of the (former) gated dispatch path, now re-derivable on demand so it can be recomputed after an async gap. */
  private buildTaintContext(argsSnapshot: unknown, sinkClass: SinkClass): TaintContext {
    const { matches, floor } = scanArgsForTaint(argsSnapshot, this.registry);
    return {
      matchedRecords: matches,
      scopeLevel: this.currentScope.watermark.level,
      argFingerprintFloor: floor,
      privateDataSeen: this.currentScope.watermark.privateDataSeen,
      sinkClass,
    };
  }

  /** Whether the CURRENT watermark is strictly more tainted than the snapshot captured in `taint` — either dimension moving counts (§3.2's two dimensions are independent escalators). */
  private watermarkEscalatedSince(taint: TaintContext): boolean {
    return (
      LEVEL_ORDER[this.currentScope.watermark.level] > LEVEL_ORDER[taint.scopeLevel] ||
      (this.currentScope.watermark.privateDataSeen && !taint.privateDataSeen)
    );
  }

  /**
   * Immediately before ever executing a gated tool call, re-checks the
   * watermark against what it was when `decision` was computed. Closes two
   * races at once, both stemming from the same root cause — an async gap
   * (policy()'s own await, or the REQUIRE_APPROVAL wait) during which the
   * watermark can move without the already-computed `decision` knowing:
   *   - markContextExposure() (and its 3 specializations): a synchronous
   *     escape hatch by design (GAPS.md #1) that never acquires the broker
   *     lock, so it can land during either gap.
   *   - a concurrently-dispatched source call raising the watermark during
   *     the now-unlocked REQUIRE_APPROVAL wait (see dispatchGated()).
   * If the watermark did NOT move, `decision` is still valid — proceed
   * exactly as already decided. If it escalated, `decision` was computed
   * against a stale, now-too-permissive taint context: re-decide against
   * the CURRENT one instead of trusting it. Bounded to this single extra
   * round — a fresh REQUIRE_APPROVAL is never re-prompted (there is no
   * fresh human grant for it) and is conservatively treated as not
   * approved rather than looping.
   */
  private async revalidateBeforeExecute(
    call: ToolCall,
    argsSnapshot: unknown,
    sinkClass: SinkClass,
    taint: TaintContext,
    decision: PolicyDecision,
  ): Promise<{ taint: TaintContext; decision: PolicyDecision; proceed: boolean }> {
    if (!this.watermarkEscalatedSince(taint)) {
      return { taint, decision, proceed: true };
    }
    // No ArgsTooDeepError handling needed here (contrast gateDecision()'s
    // own try/catch around its first buildTaintContext() call): this scans
    // the SAME frozen argsSnapshot gateDecision() already scanned once
    // successfully — the walk is a pure, deterministic function of the
    // (unchanged) argsSnapshot, so it cannot throw here having already
    // succeeded there. dispatchGated() would never have reached this far
    // otherwise.
    const freshTaint = this.buildTaintContext(argsSnapshot, sinkClass);
    const freshDecision = await this.policy(call, freshTaint);
    const proceed =
      freshDecision.action === 'ALLOW' || freshDecision.action === 'ALLOW_WITH_WARNING';
    return { taint: freshTaint, decision: freshDecision, proceed };
  }

  /** Plan-freeze + outbound-host allowlist + policy() — everything needed to reach a gating decision, run once under the lock. */
  private async gateDecision(
    tool: ToolExecutor,
    call: ToolCall,
    argsSnapshot: unknown,
    sinkClass: SinkClass,
  ): Promise<{ taint: TaintContext; decision: PolicyDecision }> {
    const toolName = call.toolName;
    let taint: TaintContext;
    try {
      taint = this.buildTaintContext(argsSnapshot, sinkClass);
    } catch (error) {
      if (error instanceof ArgsTooDeepError) this.auditArgsTooDeep(call, sinkClass, error);
      throw error;
    }

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

    // Outbound-host allowlist (DESIGN.md §7.4), additive on top of the
    // normal policy check below, never instead of it — a pure firewall
    // rule that runs regardless of scope level, unlike everything else
    // in this branch. Only ever examines EXFIL-class calls; a non-EXFIL
    // sink with a URL-shaped argument (e.g. write_file writing a URL
    // string to disk) is not egress and is out of scope for this check.
    const allowlist = this.allowedOutboundHosts;
    if (allowlist !== undefined && sinkClass === 'EXFIL') {
      let hosts: string[];
      try {
        // Defensive, not currently reachable via this call path: this
        // walks the SAME argsSnapshot buildTaintContext() already walked
        // above (scanArgsForTaint()), at the same depth bound (500, defined
        // independently in each of scan.ts/egress.ts) — so a tree deep
        // enough to make THIS throw would already have made the earlier
        // buildTaintContext() call throw first, short-circuiting before
        // execution ever reaches here. Kept anyway: it costs nothing, and
        // it's the only thing standing between an integrator who changes
        // one file's depth bound (or gateDecision()'s check order) without
        // the other and reopening an unaudited RangeError right here.
        hosts = findOutboundHosts(argsSnapshot);
      } catch (error) {
        if (error instanceof ArgsTooDeepError) this.auditArgsTooDeep(call, sinkClass, error);
        throw error;
      }
      const disallowedHosts = hosts.filter((host) => !isAllowedOutboundHost(host, allowlist));
      if (disallowedHosts.length > 0) {
        this.auditSink.record({
          verdict: {
            action: 'BLOCK',
            reason: `Outbound host allowlist violation: ${disallowedHosts.map((h) => `"${h}"`).join(', ')} not in BrokerOptions.allowedOutboundHosts.`,
          },
          call,
          taint,
          at: Date.now(),
          executed: false,
        });
        throw new DisallowedOutboundHostError(toolName, disallowedHosts);
      }
    }

    const decision = await this.policy(call, taint);
    return { taint, decision };
  }

  /**
   * Records a BLOCK audit event for an ArgsTooDeepError caught while
   * computing this call's gating inputs (buildTaintContext()'s scan, or
   * findOutboundHosts()'s egress scan) — the one structural rejection in
   * gateDecision() that can happen before a real TaintContext exists to
   * audit with. Uses the CURRENT scope watermark (still fully valid,
   * unaffected by the failed scan) for scopeLevel/privateDataSeen, with
   * matchedRecords empty and argFingerprintFloor CLEAN to honestly reflect
   * that Layer 2 never got to run — never claiming a clean scan that didn't
   * actually happen. See ArgsTooDeepError's doc comment (errors.ts).
   */
  private auditArgsTooDeep(call: ToolCall, sinkClass: SinkClass, error: ArgsTooDeepError): void {
    const taint: TaintContext = {
      matchedRecords: [],
      scopeLevel: this.currentScope.watermark.level,
      argFingerprintFloor: 'CLEAN',
      privateDataSeen: this.currentScope.watermark.privateDataSeen,
      sinkClass,
    };
    this.auditSink.record({
      verdict: { action: 'BLOCK', reason: error.message },
      call,
      taint,
      at: Date.now(),
      executed: false,
    });
  }

  /**
   * Runs `decision`, waiting for human approval if required, revalidating
   * against the current watermark immediately before ever executing, then
   * auditing and returning the result — the tail half of the gated path,
   * run under the lock again after dispatchGated()'s unlocked approval wait.
   */
  private async finalizeGated(
    tool: ToolExecutor,
    call: ToolCall,
    argsSnapshot: unknown,
    sinkClass: SinkClass,
    taint: TaintContext,
    decision: PolicyDecision,
    approvedByHuman: boolean,
  ): Promise<unknown> {
    const toolName = call.toolName;
    let result: unknown;
    let executed = false;
    let auditTaint = taint;
    let auditDecision = decision;

    const provisionallyApproved =
      decision.action === 'ALLOW' ||
      decision.action === 'ALLOW_WITH_WARNING' ||
      (decision.action === 'REQUIRE_APPROVAL' && approvedByHuman);

    if (provisionallyApproved) {
      const revalidated = await this.revalidateBeforeExecute(
        call,
        argsSnapshot,
        sinkClass,
        taint,
        decision,
      );
      auditTaint = revalidated.taint;
      auditDecision = revalidated.decision;
      if (revalidated.proceed) {
        result = await tool.execute(this.cloneArgsOrThrow(toolName, argsSnapshot));
        executed = true;
      }
    }
    // BLOCK / QUARANTINE_AND_RETRY, a denied REQUIRE_APPROVAL, or a
    // watermark escalation caught by revalidateBeforeExecute(): never
    // auto-executed (§7.2).

    this.auditSink.record({
      verdict: auditDecision,
      call,
      taint: auditTaint,
      at: Date.now(),
      executed,
    });
    if (!executed) {
      throw new ToolCallBlockedError(call, auditDecision, blockedMessage(toolName, auditDecision));
    }

    return this.finishDispatch(tool, call, sinkClass, result);
  }

  /**
   * The gated (sinkClass !== 'NONE') dispatch path. In the common case
   * (ALLOW / ALLOW_WITH_WARNING / BLOCK / QUARANTINE_AND_RETRY — no human
   * in the loop), gateDecision() and finalizeGated() run inside ONE
   * unbroken lock hold, exactly like the pre-fix single-lock dispatch: the
   * lock must never be released between a call's decision and its
   * execution when there is no async gap to release it across, or a call
   * queued behind this one on the lock could interleave there and run out
   * of turn (this is a real regression this fix hit and reverted — see the
   * "gates correctly regardless of which call is listed first" test).
   *
   * Only a REQUIRE_APPROVAL decision splits into three phases, so the
   * (potentially human-timescale) approval wait does not hold the
   * broker-wide lock for its full duration:
   *   1. gateDecision() under the lock — reach a decision against the
   *      current watermark, atomically with respect to any concurrently-
   *      dispatched source call.
   *   2. Wait for the approval channel WITHOUT the lock held, so other
   *      calls on this broker are not frozen for the wait.
   *      markContextExposure() or another call's source tool can freely
   *      raise the watermark during this window.
   *   3. finalizeGated() under the lock again — revalidateBeforeExecute()
   *      re-checks the watermark against phase 1's snapshot before ever
   *      executing, closing the race phase 2's unlocked window (and,
   *      independently, markContextExposure()'s always-unlocked nature)
   *      would otherwise open.
   */
  private async dispatchGated(
    tool: ToolExecutor,
    call: ToolCall,
    argsSnapshot: unknown,
    sinkClass: SinkClass,
  ): Promise<unknown> {
    const phase1 = await this.withLock(async () => {
      const { taint, decision } = await this.reentrancyGuard.run({ lockHeld: true }, () =>
        this.gateDecision(tool, call, argsSnapshot, sinkClass),
      );
      if (decision.action !== 'REQUIRE_APPROVAL') {
        const result = await this.reentrancyGuard.run({ lockHeld: true }, () =>
          this.finalizeGated(tool, call, argsSnapshot, sinkClass, taint, decision, false),
        );
        return { needsApproval: false as const, result };
      }
      return { needsApproval: true as const, taint, decision };
    });

    if (!phase1.needsApproval) {
      return phase1.result;
    }
    const { taint, decision } = phase1;

    const approvedByHuman = this.approvalChannel
      ? await this.reentrancyGuard.run({ lockHeld: false }, () =>
          this.approvalChannel!.requestApproval(call, taint, decision),
        )
      : false;

    return this.withLock(() =>
      this.reentrancyGuard.run({ lockHeld: true }, () =>
        this.finalizeGated(tool, call, argsSnapshot, sinkClass, taint, decision, approvedByHuman),
      ),
    );
  }

  /** Post-execution bookkeeping shared by both the NONE-sinkClass and gated dispatch paths — always runs under whatever lock the caller currently holds. */
  private finishDispatch(
    tool: ToolExecutor,
    call: ToolCall,
    sinkClass: SinkClass,
    result: unknown,
  ): unknown {
    const toolName = call.toolName;
    this.applyPostExecutionEffects(tool, call, result);

    if (sinkClass === 'NONE' && (tool.capabilities.readsPrivateData || isUntrustedSource(tool))) {
      const reasons: string[] = [];
      if (isUntrustedSource(tool))
        reasons.push(
          `untrusted source call raised the scope watermark to ${this.currentScope.watermark.level}.`,
        );
      if (tool.capabilities.readsPrivateData)
        reasons.push('private data was read this scope (lethal-trifecta escalator, §3.2).');
      recordTrivialAudit(
        this.auditSink,
        { action: 'ALLOW_WITH_WARNING', reason: reasons.join(' ') },
        call,
        this.currentScope.watermark,
        true,
      );
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

  markContextExposure(
    source: { toolName?: string; note: string; text?: string },
    level: TaintLevel = 'RAW_UNTRUSTED',
  ): void {
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
        args: {
          toolName: source.toolName,
          note: source.note,
          level,
          ...(source.text !== undefined ? { text: source.text } : {}),
        },
        sessionId: this.sessionId,
      },
      this.currentScope.watermark,
      true,
    );
  }

  markToolDescriptionExposure(
    toolName: string,
    description: string,
    level: TaintLevel = 'RAW_UNTRUSTED',
  ): void {
    this.markContextExposure(
      {
        toolName,
        note: `tool/plugin description exposure: "${toolName}"'s description was ingested (or changed) outside a tracked tool call — see GAPS.md #1.`,
        text: description,
      },
      level,
    );
  }

  markSystemPromptExposure(note: string, text?: string, level: TaintLevel = 'RAW_UNTRUSTED'): void {
    this.markContextExposure(
      {
        toolName: 'system-prompt',
        note: `system-prompt exposure: ${note}`,
        ...(text !== undefined ? { text } : {}),
      },
      level,
    );
  }

  markPastedContentExposure(
    note: string,
    text?: string,
    level: TaintLevel = 'RAW_UNTRUSTED',
  ): void {
    this.markContextExposure(
      {
        toolName: 'pasted-content',
        note: `user-pasted content exposure: ${note}`,
        ...(text !== undefined ? { text } : {}),
      },
      level,
    );
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
  private clearScopeForTurnReset(
    kind: 'turn' | 'turn-decay',
    buildReason: (priorLevel: TaintLevel, hadPlan: boolean) => string,
  ): void {
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
      {
        id: randomUUID(),
        toolName: '__tttb_declassify',
        args: { reason, approvedBy },
        sessionId: this.sessionId,
      },
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

/**
 * Creates one taint-tracked tool-call broker. **One instance = one
 * session** (GAPS.md #19): every safety guarantee this library makes —
 * the scope watermark, the Layer 2 fingerprint registry, and `withLock`'s
 * call-ordering serialization (§8) — is per-INSTANCE in-memory state, not
 * shared across `createBroker()` calls (even ones given the same
 * `BrokerOptions.sessionId` — that field is a label for audit records, not
 * a lookup key). Concretely:
 *   - DO create exactly one broker per agent conversation/session, and
 *     reuse that same instance for the session's entire lifetime — across
 *     turns too, via `startNewTurn()`/`resetScope`, never by constructing
 *     a fresh broker mid-session (that silently resets the watermark to
 *     CLEAN, discarding whatever taint state existed).
 *   - DO NOT reuse a single broker instance across two concurrent,
 *     unrelated sessions/users — `withLock`'s serialization only
 *     guarantees ordering between calls on the SAME instance; sharing one
 *     instance would either serialize unrelated users' calls against each
 *     other (a availability bug) or, if you work around that by routing
 *     calls loosely, silently mix one user's watermark/registry state into
 *     another's (a soundness bug far worse than either).
 *   - For persistence across PROCESS restarts of the SAME session, see
 *     GAPS.md #12 and `persistence.ts` — that is a different, supported
 *     concern from cross-session sharing.
 */
export function createBroker(opts: BrokerOptions = {}): ToolCallBroker {
  return new Broker(opts);
}
