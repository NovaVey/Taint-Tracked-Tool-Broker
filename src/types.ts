/**
 * Core type contract for the Taint-Tracked Tool Broker (TTTB).
 *
 * This module is the single source of truth every other module imports
 * from. See DESIGN.md for the full rationale — in short:
 *
 *   - A single trust lattice (`TaintLevel`) is used EVERYWHERE: both for
 *     the per-scope watermark (the actual safety boundary, §4.1) and for
 *     individual fingerprint records (attribution/explainability, §4.2).
 *   - The watermark, not content matching, decides whether a call is
 *     gated. Fingerprint matches can only ever tighten a verdict, never
 *     loosen one (§4.2, §7.2).
 *
 * This file contains only types and small, pure, dependency-free helpers
 * (the lattice ordering and the sink-class mapping). Anything that needs
 * Node built-ins (crypto, timers) lives in a downstream module.
 */

// ---------------------------------------------------------------------------
// The trust lattice (§4.0)
// ---------------------------------------------------------------------------

/** CLEAN(0) < DERIVED_UNTRUSTED(1) < RAW_UNTRUSTED(2). Totally ordered. */
export type TaintLevel = 'CLEAN' | 'DERIVED_UNTRUSTED' | 'RAW_UNTRUSTED';

export const LEVEL_ORDER: Record<TaintLevel, number> = {
  CLEAN: 0,
  DERIVED_UNTRUSTED: 1,
  RAW_UNTRUSTED: 2,
};

export function maxLevel(a: TaintLevel, b: TaintLevel): TaintLevel {
  return LEVEL_ORDER[a] >= LEVEL_ORDER[b] ? a : b;
}

export function levelAtLeast(level: TaintLevel, floor: TaintLevel): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[floor];
}

// ---------------------------------------------------------------------------
// Provenance & sensitivity
// ---------------------------------------------------------------------------

export interface ProvenanceTag {
  /** Equal to the originating fingerprint's exactHash, or a uuid for non-text events. */
  id: string;
  sourceCallId: string;
  toolName: string;
  sessionId: string;
  capturedAt: number;
  note?: string;
}

export interface SensitivityLabel {
  containsPrivateData: boolean;
  /** e.g. 'credentials' | 'pii' | 'email-contents' | ... — free-form, integrator-defined. */
  categories: string[];
}

export const NOT_SENSITIVE: SensitivityLabel = { containsPrivateData: false, categories: [] };

// ---------------------------------------------------------------------------
// Layer 2 — content-addressed fingerprint registry (precision & explainability
// only; NEVER the sole basis for a gating decision — see §4.2)
// ---------------------------------------------------------------------------

export interface Fingerprint {
  exactHash: string;
  /** 64-bit simhash, survives light edits/reordering better than exact hashing. */
  simhash: bigint;
  /** Deduplicated hashes of word-shingles, used for overlap/containment scoring. */
  shingleHashes: Uint32Array;
  length: number;
}

export interface TaintRecord {
  /** Equal to fingerprint.exactHash. */
  id: string;
  provenance: ProvenanceTag;
  level: TaintLevel;
  sensitivity: SensitivityLabel;
  fingerprint: Fingerprint;
  /** Explicit provenance-graph parents, e.g. set by the quarantine/summarize path. */
  derivedFrom?: string[];
  /** 1.0 for exact/derived records; decays for fuzzy matches produced during lookup. */
  confidence: number;
}

export type MatchType = 'exact' | 'simhash' | 'shingle' | 'quarantine-derived' | 'wrapper';

export interface TaintMatch {
  record: TaintRecord;
  matchType: MatchType;
  /** Dotted/bracketed path into the argument object where the match was found, e.g. "body.text[0]". */
  argPath: string;
  score: number;
}

export interface FuzzyLookupOpts {
  simhashMaxDistance?: number;
  /**
   * Named `overlapMin`, not `jaccardMin`, because it is genuinely an overlap
   * coefficient (|A∩B| / min(|A|,|B|)), not a plain Jaccard index
   * (|A∩B| / |A∪B|) — that distinction is not cosmetic. Jaccard and the
   * overlap coefficient diverge sharply exactly when one set is much larger
   * than the other, which is precisely the "short malicious excerpt embedded
   * in a much larger blob (or vice versa)" scenario this whole fuzzy-match
   * layer exists to catch: a plain Jaccard index would score that case low
   * (dominated by the larger set's size) right when it most needs to score
   * high. A caller tuning this threshold from the field's name alone, rather
   * than this comment, would reason about the wrong statistic. See
   * DESIGN.md §4.2 and taint/fingerprint.ts.
   */
  overlapMin?: number;
  /**
   * Caps how many TaintMatch entries lookupFuzzy() returns for a single
   * query, defending against a pathological registry (many attacker-chosen
   * near-duplicate records all fuzzy-matching the same later text) producing
   * an unbounded match list. Survivors are chosen by taint level first, then
   * score — so this can never drop the single highest-level match, which is
   * the only one that can affect a policy verdict's floor (Layer 2 only ever
   * tightens, never loosens — see TaintContext.argFingerprintFloor). Default
   * 20; a caller that genuinely wants every candidate can pass a large value.
   */
  maxMatches?: number;
}

export interface TaintRegistry {
  register(
    text: string,
    provenance: ProvenanceTag,
    level: TaintLevel,
    sensitivity: SensitivityLabel,
    derivedFrom?: string[],
  ): TaintRecord;
  lookupExact(text: string): TaintRecord | undefined;
  lookupFuzzy(text: string, opts?: FuzzyLookupOpts): TaintMatch[];
  getById(id: string): TaintRecord | undefined;
  readonly size: number;

  /**
   * Every stored record, oldest-registered first. The registry deliberately
   * never stores raw plaintext (only fingerprints derived from it), so this
   * — not re-deriving fingerprints from a text corpus — is the supported
   * basis for exporting registry state, e.g. for cross-process/cross-agent
   * persistence (GAPS.md #12, persistence.ts).
   */
  entries(): readonly TaintRecord[];

  /**
   * Inserts an already-built `TaintRecord` directly, bypassing register()'s
   * text -> fingerprint computation. The counterpart to entries(): restoring
   * previously-exported state doesn't have the original plaintext to
   * re-fingerprint, only the record itself. Restoring an id that's already
   * present replaces it in place rather than duplicating it. See
   * persistence.ts.
   */
  restore(record: TaintRecord): void;

  /**
   * Optional hot-path combination of lookupExact() + lookupFuzzy() in one
   * call, computing the text's fingerprint only once instead of twice
   * (lookupExact() hashes the text directly; lookupFuzzy() separately calls
   * buildFingerprint(), which redundantly recomputes that same exact hash
   * as part of building the full fingerprint). scanArgsForTaint() — the
   * mandatory pre-dispatch scan run on every gated call — uses this when a
   * registry provides it, and falls back to the two separate calls
   * otherwise. Optional (not required by the interface) so an existing
   * custom TaintRegistry implementation that only implements lookupExact()/
   * lookupFuzzy() keeps working unchanged, at the cost of the redundant
   * hash this exists to skip. InMemoryTaintRegistry implements it.
   */
  lookupCombined?(
    text: string,
    opts?: FuzzyLookupOpts,
  ): { exact: TaintRecord | undefined; fuzzy: TaintMatch[] };
}

// ---------------------------------------------------------------------------
// Layer 1 — in-process wrapper (best-effort fast path, never load-bearing —
// see §4.3. Degrades silently; soundness never depends on it surviving.)
// ---------------------------------------------------------------------------

export const TAINT_BRAND: unique symbol = Symbol('tttb.taintedValue');

export interface TaintedValue<T> {
  readonly [TAINT_BRAND]: true;
  readonly value: T;
  readonly level: TaintLevel;
  readonly sources: ProvenanceTag[];
}

// ---------------------------------------------------------------------------
// Layer 0 — scope watermark (THE load-bearing safety boundary, §4.1)
// ---------------------------------------------------------------------------

export interface TaintWatermark {
  level: TaintLevel;
  /** Independent dimension: an escalator on policy decisions, never itself a gate (§3.2, §7.2). */
  privateDataSeen: boolean;
  /** Audit trail only — policy gating logic must never branch on the contents of this array. */
  sources: ProvenanceTag[];
}

export type ScopeKind = 'session' | 'turn' | 'turn-decay';

export interface TaintScope {
  kind: ScopeKind;
  id: string;
  watermark: TaintWatermark;
}

/**
 * Whether `startNewTurn()` clears the watermark. 'session' (the default) never
 * clears until an explicit declassify(); 'turn' is a lower-friction opt-in
 * that trades soundness for usability — see GAPS.md #2 (cross-turn latent
 * influence is a named, accepted gap of 'turn' mode). 'turn-decay' is a
 * bounded middle ground: the watermark persists across
 * `BrokerOptions.turnDecayWindow` consecutive turns with no NEW exposure
 * before clearing, instead of clearing at the very next turn boundary
 * regardless. `turnDecayWindow: 1` is exactly equivalent to `'turn'` — it
 * generalizes 'turn' mode rather than replacing it. See DESIGN.md's
 * implementation note and GAPS.md #2.
 */
export type ResetScope = 'turn' | 'session' | 'turn-decay';

// ---------------------------------------------------------------------------
// Sinks (§7.1)
// ---------------------------------------------------------------------------

export type SinkClass = 'EXEC' | 'MUTATE' | 'EXFIL' | 'NONE';

export type SinkCapability =
  | 'exec:shell'
  | 'exec:code'
  | 'write:fs'
  | 'write:external-account'
  | 'finance:purchase'
  | 'irreversible:other'
  | 'net:outbound'
  | 'net:email'
  | 'net:api-call'
  | 'net:post-message';

const CAPABILITY_TO_CLASS: Record<SinkCapability, SinkClass> = {
  'exec:shell': 'EXEC',
  'exec:code': 'EXEC',
  'write:fs': 'MUTATE',
  'write:external-account': 'MUTATE',
  'finance:purchase': 'MUTATE',
  'irreversible:other': 'MUTATE',
  'net:outbound': 'EXFIL',
  'net:email': 'EXFIL',
  'net:api-call': 'EXFIL',
  'net:post-message': 'EXFIL',
};

/** EXEC is the most severe class (needs no private data to be catastrophic, §3.2), then EXFIL, then MUTATE. */
const CLASS_SEVERITY: Record<SinkClass, number> = { NONE: 0, MUTATE: 1, EXFIL: 2, EXEC: 3 };

/** A tool with multiple capabilities spanning classes is gated by its most severe declared class. */
export function sinkClassOf(capabilities: readonly SinkCapability[]): SinkClass {
  let best: SinkClass = 'NONE';
  for (const cap of capabilities) {
    const cls = CAPABILITY_TO_CLASS[cap];
    if (CLASS_SEVERITY[cls] > CLASS_SEVERITY[best]) best = cls;
  }
  return best;
}

export interface SinkCapabilities {
  /** Empty ⇒ sinkClass NONE — the tool is not policy-gated at all. */
  capabilities: SinkCapability[];
  readsPrivateData?: { categories: string[] } | false;
}

export interface ToolExecutor<A = unknown, R = unknown> {
  name: string;
  capabilities: SinkCapabilities;
  /** Does a successful call raise the watermark to RAW_UNTRUSTED? */
  isSource?: boolean;
  /**
   * Exempts an `isSource: true` tool from raising the watermark AND from
   * Layer 2 fingerprint registration (`isUntrustedSource()`,
   * `internal-audit.ts`) — its result is treated as though it never
   * happened, safety-wise. `true` only when you have reviewed the actual
   * code path and every possible result is either hardcoded, deterministic,
   * or otherwise something no external party can shape — e.g. a local
   * deploy-config file your own build process writes.
   *
   * The right question is "is the CONTENT genuinely not
   * attacker-influenceable", not "is this function deterministic/pure" —
   * those are not the same thing, and confusing them is the most likely way
   * this field gets misused. A perfectly deterministic, side-effect-free
   * function can still return attacker-influenceable content (e.g. one that
   * pure-functionally fills a fixed template with a caller-supplied or
   * otherwise externally-sourced argument — deterministic, but the
   * TEMPLATE'S FILLED-IN VALUE can still carry an injected instruction).
   * Conversely, "an internal API my company controls" is usually NOT a
   * reasonable case for `trusted: true` unless you've also verified nothing
   * upstream of it (another team's service, a partner integration,
   * user-submitted content stored earlier) can reach it.
   *
   * This is the single most consequential yes/no in a `ToolExecutor`
   * declaration — unlike every other gate here, a wrong `trusted: true`
   * doesn't just misclassify a call, it makes the content permanently
   * invisible to BOTH the watermark (Layer 0) and fingerprint matching
   * (Layer 2), with no error and no audit trail hinting anything is
   * missing (the same "integrator declares, library enforces" trust
   * boundary as GAPS.md #10). When genuinely unsure, leave this unset
   * (defaults to untrusted) — see `docs/classifying-tools.md`'s question 2
   * for the full checklist and worked examples.
   */
  trusted?: boolean;
  /**
   * Declare `true` if this tool's `execute()` calls `broker.summarize()`
   * internally (the fetch-and-quarantine composite-tool pattern, DESIGN.md
   * §6.2's implementation note) — this tells `register()`/`wrap()` the tool
   * is NOT eligible for lock-barrier exemption (DESIGN.md's "narrowing the
   * lock to a targeted barrier" note) even if its `sinkClass`/`isSource`/
   * `readsPrivateData` would otherwise qualify it, because its `execute()`
   * can still raise the watermark indirectly through that nested
   * `summarize()` call. Leaving this unset/false for a tool that DOES call
   * `summarize()` internally reopens GAPS.md #17's race for that specific
   * tool — the same "integrator declares, library enforces" trust boundary
   * `isSource`/`readsPrivateData` already rest on (GAPS.md #10). Unset by
   * default so existing tools are unaffected.
   */
  mayCallSummarize?: boolean;
  execute(args: A): Promise<R>;
}

export interface ToolCall {
  id: string;
  toolName: string;
  args: unknown;
  sessionId: string;
}

// ---------------------------------------------------------------------------
// Policy (§7)
// ---------------------------------------------------------------------------

export interface TaintContext {
  matchedRecords: TaintMatch[];
  /** Authoritative — read from the scope watermark, NOT derived from argument content. */
  scopeLevel: TaintLevel;
  /** Belt-and-suspenders signal from Layer 2; a policy may only use this to TIGHTEN a verdict. */
  argFingerprintFloor: TaintLevel;
  privateDataSeen: boolean;
  sinkClass: SinkClass;
}

export type PolicyDecision =
  | { action: 'ALLOW' }
  | { action: 'ALLOW_WITH_WARNING'; reason: string }
  | { action: 'REQUIRE_APPROVAL'; reason: string; approvalToken: string }
  | { action: 'BLOCK'; reason: string }
  | { action: 'QUARANTINE_AND_RETRY'; reason: string; suggestedSchemaId?: string };

export type RequireApprovalDecision = Extract<PolicyDecision, { action: 'REQUIRE_APPROVAL' }>;

export type PolicyFn = (
  call: ToolCall,
  taint: TaintContext,
) => Promise<PolicyDecision> | PolicyDecision;

export interface ApprovalChannel {
  /**
   * Receives the full REQUIRE_APPROVAL decision (not just its reason string)
   * so an implementation can bind its response to `decision.approvalToken`
   * — e.g. an approval UI that generates a link/webhook keyed by the token
   * and verifies a matching response before resolving true, rather than
   * trusting that whatever comes back on this call corresponds to this
   * particular request.
   */
  requestApproval(
    call: ToolCall,
    taint: TaintContext,
    decision: RequireApprovalDecision,
  ): Promise<boolean>;
}

export interface AuditEvent {
  verdict: PolicyDecision;
  call: ToolCall;
  taint: TaintContext;
  at: number;
  /** Set when the underlying tool actually ran (ALLOW*, or REQUIRE_APPROVAL that was granted). */
  executed: boolean;
}

export interface AuditSink {
  record(event: AuditEvent): void;
}

// ---------------------------------------------------------------------------
// The mandatory, sanctioned quarantine/summarize path (§6.2)
// ---------------------------------------------------------------------------

export interface QuarantineOpts<S = unknown> {
  sessionId: string;
  instructions?: string;
  /** A narrow/enum/bounded schema tightens the result and is the actual safety property — see GAPS.md #4. */
  schema?: { parse(x: unknown): S };
  /** Input MUST be registry-known, not text the agent free-typed from memory (§6.2 step 1). */
  sourceTaintRecordId: string;
}

export interface QuarantineResult<S = string> {
  text: string;
  value: S;
  taintRecordId: string;
  level: 'DERIVED_UNTRUSTED';
}

export type QuarantineFn = <S = string>(
  text: string,
  opts: QuarantineOpts<S>,
) => Promise<QuarantineResult<S>>;

/**
 * The actual LLM call an integrator supplies for the quarantine path. Must be
 * capability-less: no tool access, no conversation history beyond `text` and
 * `opts.instructions`. TTTB does not ship a default implementation — it has
 * no opinion on which model/provider you use — see quarantine.ts.
 */
export type QuarantineImpl = <S = string>(
  text: string,
  opts: { instructions?: string; schema?: { parse(x: unknown): S } },
) => Promise<S>;

// ---------------------------------------------------------------------------
// Optional strict mode: plan-freeze (§11)
// ---------------------------------------------------------------------------

/**
 * One committed step in a declared plan: which tool the NEXT privileged
 * call must be, once the scope leaves CLEAN. v1 matches on tool identity
 * only — matching on argument shape too is a possible future enhancement,
 * not implemented; see GAPS.md.
 */
export interface PlanStep {
  toolName: string;
  /** Free-form note for audit/debugging — not enforced. */
  note?: string;
}

// ---------------------------------------------------------------------------
// The broker (§7.3, §8)
// ---------------------------------------------------------------------------

/** Result of callSafe() — call()'s outcome as a value instead of a throw/resolve split, for call sites that would rather branch on `ok` than wrap every call() in try/catch. */
export type CallResult<T = unknown> = { ok: true; result: T } | { ok: false; error: unknown };

/**
 * Input to registerRawForQuarantine(): a source-only tool (no sink
 * capabilities, always untrusted) — this helper is specifically for the
 * fetch-and-quarantine composite pattern (DESIGN.md §6.2's implementation
 * note), which only makes sense for untrusted content: a `trusted` source is
 * never fingerprinted into the registry at all (see applyPostExecutionEffects
 * in broker.ts), so there would be no `taintRecordId` for this helper to hand
 * back. A genuinely trusted source doesn't need quarantining in the first
 * place — register it normally with broker.register()/wrap() instead.
 */
export interface RawQuarantineSourceTool<A = unknown, R = unknown> {
  name: string;
  execute(args: A): Promise<R>;
}

/** Result of a registerRawForQuarantine()-wrapped tool's execute(): the fetched text plus the taintRecordId summarize() needs as its sourceTaintRecordId — no separate lookup required. */
export interface QuarantineSourceResult {
  text: string;
  taintRecordId: string;
}

/**
 * One instance = one session (GAPS.md #19) — see `createBroker()`'s own
 * doc comment in broker.ts for the full explanation. In short: the
 * watermark, registry, and call-ordering lock this interface's guarantees
 * rest on are all per-instance in-memory state, never shared across
 * separate `createBroker()` calls; construct one per session and never
 * reuse a single instance across two concurrent, unrelated sessions.
 */
export interface ToolCallBroker {
  register(tool: ToolExecutor): void;
  /** Registers `executor` and returns an interposed drop-in replacement whose execute() routes through call(). */
  wrap<T extends ToolExecutor>(executor: T): T;
  call(toolName: string, args: unknown): Promise<unknown>;

  /** Same as call(), but resolves to a CallResult instead of throwing — for call sites that would rather branch on `ok` than wrap every call() in try/catch. */
  callSafe(toolName: string, args: unknown): Promise<CallResult>;

  /** Bulk register() over a name -> tool record — equivalent to calling register() once per value, in Object.values() order. */
  registerAll<T extends Record<string, ToolExecutor>>(tools: T): void;
  /** Bulk wrap() over a name -> tool record, returning the same keys mapped to their wrapped executors — equivalent to calling wrap() once per value, in Object.values() order. */
  wrapAll<T extends Record<string, ToolExecutor>>(tools: T): T;

  /**
   * Registers a source-only tool for the fetch-and-quarantine composite
   * pattern (DESIGN.md §6.2's implementation note) and returns a wrapper
   * whose execute() resolves to `{ text, taintRecordId }` instead of just
   * the raw result — `taintRecordId` is exactly what summarize() needs as
   * `sourceTaintRecordId`, so callers don't have to separately compute or
   * look up the fetched content's fingerprint id themselves. Throws
   * DualRoleToolError at registration if `tool` also declares sink
   * capabilities — this helper is for source-only tools; see register().
   */
  registerRawForQuarantine<A = unknown, R = unknown>(
    tool: RawQuarantineSourceTool<A, R>,
  ): { name: string; execute(args: A): Promise<QuarantineSourceResult> };

  summarize: QuarantineFn;

  /**
   * Escape hook for untrusted content that reaches the model outside any
   * tracked tool call — see GAPS.md #1. Pass `text` when the actual exposed
   * content is known so it also gets a Layer 2 fingerprint record (the same
   * register-then-raise pattern an ordinary source-tool call gets); omit it
   * when only the fact of an exposure is known (e.g. "this tool's
   * description changed since last seen"), not its content.
   */
  markContextExposure(
    source: { toolName?: string; note: string; text?: string },
    level?: TaintLevel,
  ): void;

  /** markContextExposure() specialized for a tool/plugin/MCP-server description read at discovery time (GAPS.md #1's own canonical example) — see examples/mcp-integration.ts's rug-pull guard for a worked pattern. */
  markToolDescriptionExposure(toolName: string, description: string, level?: TaintLevel): void;
  /** markContextExposure() specialized for an untrusted system-prompt fragment. `text` is optional, same as markContextExposure() — omit it when only the fact of the exposure, not its content, is known. */
  markSystemPromptExposure(note: string, text?: string, level?: TaintLevel): void;
  /** markContextExposure() specialized for content a user pastes directly into a turn. `text` is optional, same as markContextExposure(). */
  markPastedContentExposure(note: string, text?: string, level?: TaintLevel): void;

  /** Per `resetScope`: clears the watermark ('turn' mode) or is a no-op ('session' mode, the default). */
  startNewTurn(): void;
  /** The ONLY path that lowers a watermark. Explicit, audited, never an implicit side effect of an approval. */
  declassify(reason: string, approvedBy: string): void;

  /**
   * Opt into plan-freeze strict mode (§11): once the scope leaves CLEAN, a
   * privileged call whose tool doesn't match the next committed step is
   * blocked as unplanned, on top of (never instead of) the normal policy
   * check. Must be called while the scope is still CLEAN — committing to a
   * plan after exposure would be meaningless, since the whole point is that
   * the shape of what may happen was fixed before any untrusted content was
   * read. Throws if the scope has already left CLEAN.
   *
   * Only privileged calls (non-NONE sinkClass) are matched against — and
   * advance — the plan. NONE-sink calls, including source/read-only tools
   * like a `fetch_url`, are never gated by policy in the first place (see
   * "NONE" in SinkClass) and are correspondingly invisible to the plan: do
   * not list them as steps expecting them to be consumed, and expect them
   * to run freely between (and interleaved with) planned privileged steps.
   */
  declarePlan(steps: PlanStep[]): void;

  readonly scope: Readonly<TaintScope>;
  readonly registry: TaintRegistry;
}
