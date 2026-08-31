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
  /**
   * Names the argument key(s) that carry this tool's actual network
   * destination, for the opt-in `BrokerOptions.allowedOutboundHosts` egress
   * allowlist (DESIGN.md §7.4). Threaded straight through, unchanged, as
   * `findOutboundHosts(argsSnapshot, { destinationKeys })`'s own
   * `destinationKeys` option at the EXFIL gating call site in `broker.ts`'s
   * `gateDecision()` — see `FindOutboundHostsOptions.destinationKeys`
   * (`taint/egress.ts`) for exactly how a named key's subtree is scanned.
   *
   * `findOutboundHosts()` over-detects by default: with no
   * `destinationKeys`, it treats every string leaf anywhere in a call's
   * argument tree as a candidate destination, so a benign field whose value
   * merely happens to be, in its entirety, a valid URL or email address
   * (e.g. a chat tool's `text` body that is exactly
   * `"https://internal-wiki.example/kb/42"`) is indistinguishable from a
   * genuine destination and trips the same unconditional hard `BLOCK` as a
   * real disallowed egress target — GAPS.md #18's own "over-detection"
   * sub-bullet and `taint/egress.ts`'s header comment work through this in
   * full. Declaring `destinationKeys` here narrows the scan to just the
   * named key(s)' subtrees, eliminating that false positive.
   *
   * Declared on the tool itself, at registration time, the same way
   * `isSource`/`trusted`/`readsPrivateData` above are, rather than accepted
   * as per-call configuration: which argument key(s) actually name a given
   * tool's destination (a webhook tool's `url`, as opposed to its unrelated
   * `text`/`channel`/`notes` fields) is a fixed property of that tool's own
   * schema, not something that varies call to call. Purely additive and
   * opt-in — a tool that leaves this unset gets `broker.ts`'s original,
   * unscoped whole-tree scan exactly as it behaved before this field
   * existed; no previously-registered tool's behavior changes. Only ever
   * consulted for an `EXFIL`-class tool, and only when
   * `BrokerOptions.allowedOutboundHosts` is configured — inert otherwise,
   * including for a tool that declares it but has no sink capabilities at
   * all.
   */
  destinationKeys?: readonly string[];
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
  /**
   * Mirrors `taint/scan.ts`'s `ScanResult.hasUnattributedSubstantialContent`
   * — see that field's own doc comment for the exact bar (a string leaf of
   * at least `UNATTRIBUTED_CONTENT_MIN_LENGTH` chars with zero taint matches
   * at all, not even a weak fuzzy one). `defaultPolicy`'s
   * `bestQuarantineCandidate()` (`policy/default-policy.ts`) is this field's
   * only reader: it withholds QUARANTINE_AND_RETRY when this is `true`,
   * because a qualifying match sitting next to a chunk of text Layer 2 has
   * no story for at all might be an unrelated decoy, not the actual reason
   * this call is risky — see that function's doc comment for the concrete
   * exploit this closes. Like `argFingerprintFloor`, this is a Layer 2
   * signal a `PolicyFn` may read, but unlike it, this one never tightens
   * anything on its own — it only ever narrows an already-permissive
   * decision (offering the softer QUARANTINE_AND_RETRY verdict in place of
   * BLOCK/REQUIRE_APPROVAL), never gates a call that would otherwise be
   * ALLOWed. A hand-written `PolicyFn` that doesn't implement
   * QUARANTINE_AND_RETRY at all is free to ignore this field entirely.
   * Administrative `TaintContext`s built for non-sink audit events
   * (`internal-audit.ts`'s `trivialTaintContext()`, `quarantine.ts`'s own
   * audit records, `broker.ts`'s `auditArgsTooDeep()`) always set this
   * `false` — honestly reflecting that no real args scan ran, the same
   * convention those sites already use for `matchedRecords`/
   * `argFingerprintFloor`.
   *
   * **Optional, not required — deliberately, for API stability.** Every
   * `TaintContext` this library itself constructs (the broker's real
   * dispatch path, both internal-audit call sites, both `quarantine.ts`
   * sites) always sets this explicitly; it is typed optional only so a
   * `TaintContext` object literal written before this field existed —
   * plausibly, a hand-built fixture in a custom `PolicyFn`'s own test
   * suite, since `TaintContext` is a public, integrator-facing parameter
   * type (§7.3) — still type-checks unchanged after this field was added
   * post-`1.0.0`. Per this project's versioning policy (README.md
   * "Versioning"), a NEW REQUIRED field on an already-public interface is
   * exactly the kind of shape change `1.0.0` commits to only ever doing
   * behind a major bump; making it optional avoids that bump for what is,
   * functionally, an additive Layer 2 signal. A reader must therefore treat
   * `undefined` the same as `true` (the conservative direction — decline to
   * offer `QUARANTINE_AND_RETRY`), never the same as `false`; see
   * `bestQuarantineCandidate()`'s own `!== false` check for the concrete
   * convention.
   */
  hasUnattributedSubstantialContent?: boolean;

  /**
   * The `TaintScope.id` (`broker.ts`'s `this.currentScope.id`) this
   * `TaintContext` was computed against — the id of the exposure episode
   * currently in effect. Freshly generated by `createScope()` at broker
   * construction and again by every `resetScope: 'turn'`/`'turn-decay'`
   * turn-boundary reset (`clearScopeForTurnReset()`, `broker.ts`); a plain
   * `declassify()` clears the watermark IN PLACE without minting a new
   * scope object, so it does not change `scopeId` — see that method's own
   * doc comment. `clearScopeForTurnReset()`'s own administrative
   * `AuditEvent` is a deliberate, documented exception to "current scope
   * id": since that one event describes a watermark just DISCARDED (its
   * `taint.scopeLevel` already reports the prior, pre-clear level, not the
   * new `CLEAN` one — see that method's doc comment), its `scopeId` is
   * likewise the id of the scope that just ended, not the fresh one
   * created to replace it.
   *
   * Exists so an integrator watching `AuditEvent`s (or building a
   * `TaintContext` fixture for a hand-written `PolicyFn`'s own test) can
   * group "which events belong to the same turn/exposure episode" — e.g.
   * computing a turn-scoped or turn-decay-scoped block rate, or lining up
   * every event a given turn produced — without separately threading the
   * live scope id through their own orchestration code and correlating it
   * back to each event by hand, the same "how would I even do this well"
   * gap `broker.scope.id` already existed to close for direct callers but
   * left unaddressed for anything reading only the audit trail.
   * `resetScope: 'session'` (the default) never mints a new scope after
   * construction, so every event for the life of that broker carries the
   * identical `scopeId` — grouping by it degenerates to "the whole
   * session," correctly, since there is only ever one episode to group.
   *
   * **Optional, not required — deliberately, for API stability**, the
   * identical reasoning `hasUnattributedSubstantialContent`'s own doc
   * comment gives just above, applied to a second field added to this same
   * interface after `1.0.0`: every `TaintContext` this library itself
   * constructs (the broker's real dispatch path via `buildTaintContext()`,
   * the `ArgsTooDeepError` audit path, both `internal-audit.ts` call
   * sites, both `quarantine.ts` sites) always sets this explicitly; it is
   * typed optional only so a `TaintContext` object literal written before
   * this field existed — plausibly a hand-built fixture in a custom
   * `PolicyFn`'s own test suite, since `TaintContext` is a public,
   * integrator-facing parameter type (§7.3) — still type-checks unchanged
   * now that this field exists. Per this project's versioning policy
   * (README.md "Versioning", CHANGELOG.md's header), a NEW REQUIRED field
   * on an already-public interface is exactly the kind of shape change
   * `1.0.0` commits to only ever doing behind a major bump; a reader
   * should treat `undefined` as simply "no scope-correlation info
   * available for this particular `TaintContext`," not infer anything
   * about which episode it belongs to.
   */
  scopeId?: string;
}

export type PolicyDecision =
  | { action: 'ALLOW' }
  | { action: 'ALLOW_WITH_WARNING'; reason: string }
  | { action: 'REQUIRE_APPROVAL'; reason: string; approvalToken: string }
  | { action: 'BLOCK'; reason: string }
  /**
   * Offered IN PLACE OF (never alongside) a BLOCK/REQUIRE_APPROVAL verdict
   * when the call's arguments trace to a specifically identifiable
   * untrusted source that a `summarize()`-then-retry could plausibly
   * neutralize (DESIGN.md §7.2). The shipped `defaultPolicy`
   * (`src/policy/default-policy.ts`) constructs this itself under that
   * condition — see `bestQuarantineCandidate()` there for the exact
   * eligibility bar — and any custom `PolicyFn` may construct one directly
   * too. Purely informational, exactly like BLOCK/REQUIRE_APPROVAL: the
   * broker never re-runs anything on its own on receiving this verdict
   * (`src/broker.ts` treats it identically to BLOCK — never auto-executed,
   * always audited, always surfaced to the caller via
   * `ToolCallBlockedError`) — actually retrying through `summarize()` is a
   * decision for whatever handles the verdict (a human, or a supervising
   * process), never something this library does for you.
   */
  | {
      action: 'QUARANTINE_AND_RETRY';
      reason: string;
      /**
       * Reserved for a future named-schema-registry feature this library
       * does not currently have — nothing anywhere in this codebase lets a
       * schema be registered under an id a `PolicyFn` could name here.
       * `defaultPolicy` never sets this field; it always leaves it
       * `undefined` and puts the entire actionable suggestion (which
       * source to re-run through `summarize()`, and how) into `reason`
       * instead, naming the specific matched source where possible. A
       * custom `PolicyFn` integrated with its own, externally-maintained
       * schema registry is free to populate this if it wants to — it is
       * plumbed through end-to-end (the type is part of the public
       * `PolicyDecision` union and reaches every consumer of a
       * QUARANTINE_AND_RETRY verdict unchanged), just never written by
       * anything this library ships.
       */
      suggestedSchemaId?: string;
    };

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

  /**
   * When the approval WAIT actually started for a `REQUIRE_APPROVAL`
   * verdict — captured in `broker.ts`'s `dispatchGated()` immediately
   * before phase 2 (the unlocked approval wait; see that method's own doc
   * comment for the three-phase gateDecision()/wait/finalizeGated() split)
   * begins, regardless of whether `BrokerOptions.approvalChannel` is
   * actually configured to consult. Paired with `at` (the instant the
   * FINAL verdict — granted, denied, or a `revalidateBeforeExecute()`-driven
   * escalation — was recorded and this very `AuditEvent` built),
   * `event.at - event.requestedAt` is exactly the approval latency for
   * this call: `at` alone can only ever say WHEN a verdict landed, never
   * how long the wait leading up to it took, since nothing previously
   * recorded when that wait began.
   *
   * Set ONLY on the `REQUIRE_APPROVAL` path — every other verdict
   * (`ALLOW`, `ALLOW_WITH_WARNING`, `BLOCK`, `QUARANTINE_AND_RETRY`, and
   * the plan-freeze/outbound-host-allowlist structural rejections
   * `gateDecision()` can throw before a `PolicyFn` even runs) reaches no
   * approval wait at all, and this field is left `undefined` for those —
   * the honest default, never a synthetic `0` or a copy of `at`, since for
   * those verdicts there genuinely was no wait to time. Still set even
   * when `approvalChannel` was never configured: that case still reaches
   * the identical phase-2 code path in `dispatchGated()`, it just resolves
   * the wait synchronously to `false` (per `BrokerOptions.approvalChannel`'s
   * own fail-SAFE doc comment) rather than actually consulting a channel —
   * a near-zero `at - requestedAt` for that case is itself a useful signal
   * (a `REQUIRE_APPROVAL` call denied with essentially no wait at all),
   * not something worth hiding by leaving the field unset only in that one
   * sub-case.
   *
   * **Optional, not required — deliberately, for API stability**: the same
   * `1.0.0` SemVer commitment (CHANGELOG.md's header, README.md
   * "Versioning") that keeps `TaintContext.hasUnattributedSubstantialContent`
   * and `TaintContext.scopeId` optional applies identically here —
   * `AuditEvent` is an already-public, integrator-facing type (the
   * parameter to every `AuditSink.record()` call), so a NEW REQUIRED field
   * on it would be exactly the breaking shape change that policy rules out
   * short of a major bump. This library itself always sets it on the one
   * path it's meaningful for; a reader should treat `undefined` as "no
   * approval wait happened for this event" and never attempt
   * `at - requestedAt` when it is absent.
   */
  requestedAt?: number;
}

export interface AuditSink {
  /**
   * **`event` is not naturally JSON-safe — do not hand it straight to
   * `JSON.stringify()` (directly, or via a JSON-based log shipper: pino,
   * Winston-JSON, a Datadog/CloudWatch agent).** When `event.taint.matchedRecords`
   * is non-empty — the ordinary, expected case for a real fuzzy- or
   * exact-matched attack, not an edge case — each entry's `record.fingerprint`
   * (`Fingerprint`, above) carries `simhash: bigint` and
   * `shingleHashes: Uint32Array`. `JSON.stringify` THROWS on a `bigint`
   * (`TypeError: Do not know how to serialize a BigInt`) and silently
   * mangles a `Uint32Array` into a plain index-keyed object — so the single
   * most obvious `AuditSink` implementation, `record(e) { console.log(JSON.stringify(e)) }`,
   * crashes on the very first audited event that carries a fuzzy-matched
   * record. Use `serializeAuditEvent()` (`src/persistence.ts`) first —
   * `JSON.stringify(serializeAuditEvent(event))` — which converts exactly
   * these two fields to JSON-safe forms (a decimal string, a plain number
   * array) via the same conversion `serializeRegistry()` already uses for a
   * `TaintRecord` exported for cross-process persistence (GAPS.md #12);
   * everything else on `AuditEvent` is already plain JSON-safe data. This is
   * purely a converter an integrator opts into inside their own
   * `record()` — `AuditEvent`'s own shape is unchanged.
   *
   * **The DEFAULT `AuditSink` — what `createBroker()` gets when
   * `BrokerOptions.auditSink` is left unset entirely, exactly what
   * README.md's own Quick start does — is a silent no-op (`broker.ts`'s
   * `NOOP_AUDIT`).** Every gated decision this library makes is still
   * enforced correctly either way — auditing is pure observability, never
   * part of the gate itself — but an integrator who never configures a
   * real sink gets a broker that behaves exactly as documented and
   * produces ZERO audit trail, with nothing in the API surface surfacing
   * that fact. Worth naming explicitly rather than leaving implicit in
   * "`auditSink?` is optional": a genuinely production-shaped deployment
   * almost always wants at least one configured (GAPS.md #25).
   *
   * **`src/debug.ts` (also exported from `src/index.ts`) turns a
   * configured sink's raw `AuditEvent`s into something a human can
   * actually use**, rather than leaving every integrator to hand-roll the
   * same rendering: `formatAuditTrail(events)` renders a session's events
   * as readable, timestamped, one-line-per-event prose; `explainWatermark(scope)`
   * renders `TaintScope.watermark.sources` (§4.1's `ProvenanceTag[]`,
   * already collected on every scope but never itself rendered anywhere)
   * into a plain-language explanation of which tool call(s) raised the
   * current watermark level, and when; `AggregatingAuditSink` is a small,
   * dependency-free `AuditSink` you can wrap around your own (or use
   * standalone) that accumulates verdict/sinkClass counts,
   * `REQUIRE_APPROVAL` grant/deny counts, `QUARANTINE_AND_RETRY` offer
   * counts, and `requestedAt`-derived approval latency into a plain
   * `Record<string, number>` snapshot you render however your own stack
   * wants. See GAPS.md #25 and each export's own doc comment.
   */
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

/**
 * A declared plan's live state: the full committed step list plus the
 * cursor position marking which step the NEXT privileged call must match
 * (`steps.length` once the plan has been fully consumed). This is the
 * shape `ToolCallBroker.planState` reads out of a live broker and
 * `BrokerOptions.initialPlan` (broker.ts) seeds a fresh one with — see
 * both for the persistence mechanism this exists to support
 * (`serializeBrokerState()`/`restoreBrokerState()`, GAPS.md #12,
 * DESIGN.md §11's persistence note). Kept as a small named type, rather
 * than two loose fields threaded separately everywhere, precisely because
 * `steps` and `cursor` are only ever meaningful together — a cursor
 * without the plan it indexes into is meaningless, and
 * `persistence.ts`'s `validateSerializedBrokerState()` enforces exactly
 * that pairing on the wire-format side (`SerializedBrokerState.plan`/
 * `.planCursor`).
 */
export interface PlanState {
  /** The full committed step list, in original declared order — never mutated in place; `declarePlan()`/restore both copy in. */
  steps: PlanStep[];
  /** Index into `steps` of the next step a privileged call must match. */
  cursor: number;
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

  /**
   * Read-only snapshot of the currently-declared plan and its cursor
   * position (§11), or `undefined` if no plan is in effect — never
   * declared in the first place, or discarded by a turn-boundary reset
   * (`startNewTurn()` under `'turn'`/`'turn-decay'`) or `declassify()`,
   * both of which clear a declared plan alongside the watermark it was
   * committed against (see broker.ts's `clearScopeForTurnReset()`/
   * `declassify()`). Each read returns a fresh copy — mutating the
   * returned `steps` array has no effect on the broker's own plan state.
   *
   * Exists primarily so `persistence.ts`'s `serializeBrokerState()` has a
   * supported way to read a live broker's plan state out for export
   * (GAPS.md #12, DESIGN.md §11's persistence note) — the counterpart to
   * `BrokerOptions.initialPlan` (broker.ts) on the restore side. Otherwise
   * inert: reading it never changes anything, and nothing about exposing
   * it changes `declarePlan()`'s own guard or plan-freeze's enforcement.
   */
  readonly planState: Readonly<PlanState> | undefined;

  readonly scope: Readonly<TaintScope>;
  readonly registry: TaintRegistry;
}
