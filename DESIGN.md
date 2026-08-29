# DESIGN.md — Taint-Tracked Tool Broker (TTTB)

## 0. Status

This document is the complete, implementable architecture for `taint-tracked-tool-broker`, a framework-agnostic TypeScript/Node.js library. It resolves an internal design panel that produced four candidate architectures; this is the synthesized result, not a menu. Where the panel's proposals conflicted, the resolution and the reasoning are stated explicitly in §3.

## 1. Problem Statement

An LLM agent with tool-calling access is dangerous the moment it reads content it did not originate — a fetched page, an email, a file, another tool's output — because at the token level there is no boundary between *data* and *instructions* once both are in context. This is indirect prompt injection. The fix is enforcement at the boundary where the model's decisions become real side effects: the tool call.

TTTB is a broker that every tool call passes through. It must:

1. Attach provenance/taint labels to tool results.
2. Propagate those labels as data flows into later tool-call arguments.
3. Enforce policy at call time — block, warn, or require human approval for privileged sinks (shell, file write, network, email, purchase, code execution) whose arguments (or whose *context*) carry untrusted influence, especially in combination with private-data access and exfiltration capability (Simon Willison's "lethal trifecta").
4. **Survive the one operation that destroys literal taint tracking: the agent reading untrusted content and re-emitting it in its own words.** A broker that only does substring/reference propagation is defeated by "summarize this page, then act on the summary." This is the hardest requirement and the one this document treats as load-bearing, not an afterthought.

## 2. Prior Art & Positioning

- **CaMeL** (Google DeepMind): a privileged planner generates a program; a custom interpreter tags every runtime value; a quarantined, tool-less LLM performs schema-constrained extraction of untrusted content; untrusted data can be a *value* but never *control flow*. Strongest soundness of any prior art here, at the cost of requiring a bespoke interpreter and a plan committed before data is read — a real practicality tax for retrofitting onto an existing OpenAI/Anthropic-style function-calling loop.
- **The lethal trifecta** (Willison): private data + untrusted content + exfiltration capability together is the dangerous combination; any two alone are usually lower-risk. TTTB uses this as an **escalator** on top of a content-agnostic gate, not as the sole gate — see §3 for why treating it as the sole gate is unsound.
- **Dynamic taint tracking / Perl taint mode**: wrap values, propagate on string ops, forbid tainted values at dangerous sinks without explicit untainting. TTTB keeps this as a best-effort, non-load-bearing convenience layer (§4, Layer 1).
- **Classic IFC (Jif, DLM)**: explicit flow (trackable via syntax) vs. implicit flow (information leaked through control-flow decisions conditioned on secret/tainted data). TTTB's central mechanism (§6) is a direct, deliberately coarse answer to implicit flow: it does not try to trace *which* decision was influenced, only *whether* untrusted content was live when a privileged decision was made.

TTTB departs from CaMeL by not requiring a custom interpreter or a frozen program; it departs from pure fingerprint-based taint tracking by **not treating content matching as the safety boundary** — content matching is demoted to an explainability and false-positive-reduction layer, and a structural, content-agnostic scope watermark becomes the actual enforcement mechanism.

## 3. Design Principles (resolving the panel's tensions)

The panel produced four proposals. The winning one (content-addressed fingerprint registry) had the best explainability and practicality, but the judges identified a concrete soundness hole: its policy only escalated untrusted-content-into-exfil-sink calls to `REQUIRE_APPROVAL`/`BLOCK` when a *separate* private-data leg had also fired in-session; absent that leg, a verbatim malicious payload could ride straight into an exfiltration sink under a bare `ALLOW_WITH_WARNING`. A second proposal (session/turn watermark) fixed the paraphrase-survival problem cleanly by gating on *scope exposure* rather than *argument content*, but its own default policy repeated a structurally similar bug: it lumped `exec:shell`/`exec:code`/`write:fs`/irreversible sinks into an "exfil-class" bucket gated by the same private-data-contingent trifecta check at the `DERIVED_UNTRUSTED` tier, so a schema-quarantined payload could reach unconditional shell execution under a bare warning whenever no private-data tool happened to fire first.

This design makes three explicit resolutions:

1. **The scope watermark, not content matching, is the safety boundary.** Every tool call is checked against a monotonic per-scope `TaintWatermark` that the broker raises structurally the instant untrusted content (or a sanctioned quarantine derivative) enters a scope's context — *before* the model gets a chance to transform it. Fingerprint matching (content-addressed hashing/simhash/minhash, from the winning proposal) is retained in full, but reassigned to a secondary role: precise source attribution, audit-quality explanations, and — carefully — eligibility to *downgrade* a verdict's severity when a literal chain is intact. It can never be the sole reason a call is allowed, and it can never *loosen* a verdict the watermark already produced.

2. **Sink severity is keyed off capability class first, private-data-seen second.** `EXEC`-class sinks (arbitrary code/shell execution) are hard-gated by watermark level alone — never contingent on whether a private-data tool happened to fire — because arbitrary code execution needs no private data to be catastrophic. `EXFIL`-class sinks require approval the moment untrusted content is or was live in scope, *regardless* of the private-data leg; `privateDataSeen` is used purely as an **escalator** (bumping `REQUIRE_APPROVAL` to `BLOCK`), matching Willison's framing that the full trifecta is worse than any two legs, without ever letting the two-legs-only case degrade to a silent pass-through. This directly closes the gap both panel proposals shared.

3. **Because the gate is scope-level and content-agnostic, most of the "hard part" is solved by construction, not by cleverness.** Inline paraphrase, translation, and boolean/enum decision-laundering (an untrusted page causing the model to flip a flag with zero tainted text ever appearing in the sink's arguments) are all caught the same way: the sink check never looks at argument content to decide whether to gate, only at whether untrusted content has been in this scope's tracked context. What genuinely escapes detection is narrower and named honestly in §10: content that enters the model's context through a channel the broker never observes at all.

## 4. Taint & Provenance Data Model

Raw JS strings cannot carry metadata. TTTB uses three cooperating layers with a strict authority order: **watermark > fingerprint registry > in-process wrapper**. Each layer degrading does not break the one above it.

### 4.0 A single trust lattice, used everywhere

```
CLEAN (0) < DERIVED_UNTRUSTED (1) < RAW_UNTRUSTED (2)
```

- `CLEAN`: no untrusted content contributed — a developer-declared literal, or a scope after explicit `declassify()`.
- `DERIVED_UNTRUSTED`: content that reached the model exclusively through the sanctioned, schema-constrained quarantine path (§6) — bounded, typed, but still not clean.
- `RAW_UNTRUSTED`: untrusted content is or was live in the scope's tracked context via any other path.

This single vocabulary is used for both the per-scope watermark (Layer 0) and per-record fingerprint trust (Layer 2), eliminating the parallel, inconsistent trust enums the panel's four proposals each invented independently.

### 4.1 Layer 0 — Scope Watermark (the safety boundary)

```
TaintWatermark { level: TaintLevel; privateDataSeen: boolean; sources: ProvenanceTag[] }
TaintScope { kind: 'session' | 'turn'; id: string; watermark: TaintWatermark }
```

A session holds a `sessionScope` and a rotating `turnScope`. `resetScope: 'turn' | 'session'` (configurable; `'session'` is the default for autonomous/unattended agents, `'turn'` an explicit lower-friction opt-in for chat assistants) determines whether the watermark clears at each new user turn. `level` and `privateDataSeen` are **monotonic non-decreasing** within a scope's lifetime; the only way down is `broker.declassify(reason, approvedBy)` — an explicit, audited, human action, never an implicit side effect of an approved call (approving one blocked call does not declassify the scope).

**The watermark is raised atomically inside `ToolCallBroker.call()`, in the same step that a source tool's result is captured** — before that result is ever handed back to the agent loop for the model to read, let alone rewrite. This is why it survives paraphrase, translation, re-encoding, and decision-laundering: none of those operations happen before the raise; they can only happen after, on a scope whose watermark is already committed.

### 4.2 Layer 2 — Content-Addressed Fingerprint Registry (precision & explainability)

Every tool result and every sanctioned quarantine output is decomposed into a `Fingerprint {exactHash, simhash, shingleHashes, length}` and stored as a `TaintRecord {id, provenance, level, sensitivity, fingerprint, derivedFrom?, confidence}` in a `TaintRegistry`. Before every tool dispatch, `scanArgsForTaint(args)` walks the JSON-able argument tree and, for every string leaf (or ≥40-char substring window), attempts exact-hash lookup, then simhash lookup (Hamming distance ≤3, tunable), then LSH-banded minhash/shingle lookup (Jaccard ≥0.6, tunable). This produces `TaintMatch[]` with a `matchType` and confidence score, giving precise "this argument literally contains text from `fetch_url(evil.example)`" explanations whenever a literal or near-literal chain survives.

This layer is exactly the winning proposal's mechanism, unchanged in its mechanics — what changes is its **authority**: it feeds `TaintContext.argFingerprintFloor`, which the policy function may use only to *tighten* a verdict (floor it at `REQUIRE_APPROVAL` even if the watermark alone would have allowed a call — the belt-and-suspenders case of a turn-scoped watermark having reset while a fingerprint match still ties an argument to an untrusted source) or to justify a documented *downgrade* within an already-gated tier (see §6). It is never consulted to decide whether to gate a call in the first place; that decision belongs to the watermark alone.

### 4.3 Layer 1 — In-Process Wrapper (best-effort fast path)

`TaintedValue<T>` (boxed value + `level`/`sources`) is returned by `broker.wrap(executor)` to callers who want cheap, exact, same-object-identity propagation. Broker-supplied helpers (`concatTainted`, `taintAwareJSONStringify`, `spreadTainted`, `mapTainted`) propagate it through concatenation, JSON round-trips, spread, and map. This layer is documented as **degrading silently** the moment code uses raw `+`, untagged template literals, `JSON.stringify` directly, or — by construction — the moment content passes through the LLM (a fresh generation shares no object identity with anything). None of this matters for soundness: Layer 0 already committed the watermark before any of these operations could run. Layer 1 exists purely so that code which *does* use the helpers gets fast, precise, zero-lookup attribution instead of falling through to Layer 2's scan.

## 5. Propagation Rules for Ordinary Operations

These rules govern Layers 1 and 2 only (explainability/precision); Layer 0's guarantee does not depend on any of them succeeding.

- **String concat / template literals**: `concatTainted`/the `tainted` tagged-template helper union parent levels (`maxLevel`) and sources, registering a derived `TaintRecord`. Raw `+`/untagged template literals bypass Layer 1 silently, but Layer 2's fallback scan still matches the resulting text's exact/near-duplicate content against the registry.
- **`JSON.stringify`/`JSON.parse`**: `taintAwareJSONStringify` walks the object tree, unions leaf taint, registers the serialized form as derived — but since `JSON.stringify` only escapes, never rewrites, string content, Layer 2 fingerprinting still matches embedded original substrings even when the helper isn't used. `JSON.parse` produces a fresh untainted object at the JS level (Layer 1 fully lost); Layer 2 catches it because the parsed leaves are byte-identical or near-identical to already-registered text.
- **Object spread / array map / filter**: `spreadTainted`/`mapTainted` re-register outputs whose value hash is unchanged as continuing the same record (identity fast path); outputs that differ are re-fingerprinted and fuzzy-matched. Raw spread/map bypass Layer 1 (a documented ergonomic gap) but are still caught by the Layer 2 fallback since spread/map only change shape, not the leaf text.
- **Numbers/booleans/enums extracted from tainted text**: cannot carry a useful fingerprint (nothing to hash usefully). These can only be covered by Layer 0 (scope watermark) or explicit `DERIVED_UNTRUSTED`-tier extraction — this is precisely why boolean/enum decision-laundering is closed by the watermark rather than by fingerprinting (§3.3, §10).
- **Fallback path, always runs**: `scanArgsForTaint(args)` executes before every tool dispatch regardless of whether any helper was used upstream — this is what makes propagation non-manual: even code that never touches a broker helper is still scanned at the one moment that matters, immediately before a real side effect.

## 6. Surviving LLM Summarization/Rewrite — The Load-Bearing Mechanism

This is the mechanism the design is judged hardest on, so it is stated in full, twice: once as the *default* (no sanctioned path used) and once as the *sanctioned* quarantine path.

### 6.1 Default: the watermark gates regardless of what the model writes

When a source tool (`isSource: true`) returns, `ToolCallBroker.call()`:

1. Captures the result, computes its fingerprint, and registers a `TaintRecord` at `level: RAW_UNTRUSTED`.
2. **Atomically, in the same step**, raises the active scope's watermark to `maxLevel(current, RAW_UNTRUSTED)` and appends a `ProvenanceTag`.
3. Only then returns the (optionally wrapped) result to the caller for the model to read.

Every subsequent privileged-sink call in that scope is checked against `scope.watermark.level`, not against the literal content of its own arguments. So when the model later emits a tool call whose arguments are its own hand-written summary, paraphrase, translation, or re-encoding of that content — with zero literal overlap with the source — the sink check still sees `RAW_UNTRUSTED`, because that is what the scope *is*, independent of what the model chose to write. "Please summarize this page and then act on the summary" is caught by construction: the gate never depended on recognizing the summary's content in the first place. The same reasoning closes decision-laundering: a tool call whose arguments are entirely clean strings/booleans, but which was authored in a scope where untrusted content is live, is still gated, because gating never inspected those arguments for tainted text to begin with.

### 6.2 The sanctioned path: `broker.summarize()` / quarantine extraction

Blanket gating of every post-exposure privileged call is a real usability tax (§10). The escape valve — mirroring CaMeL's quarantined Q-LLM — is a single sanctioned tool, `broker.summarize(text, opts)`, registered internally as an ordinary sink-free `ToolExecutor` (`__tttb_summarize`), so it is auditable and policy-visible like any other call:

1. Requires the input to be a registry-known string (a live `TaintedValue`, or a `taintRecordId` the caller passes) — not arbitrary text the agent retyped from memory. This closes the trivial "just retype it as a fresh string and call summarize on that" loophole, though not fully (see §10).
2. Runs the condensation as a **separate, capability-less LLM invocation**, supplied by the integrator (`QuarantineImpl`) — no tool access, no conversation history beyond the input text and instructions — optionally constrained to a caller-supplied schema (enum/bounded/typed fields shrink both the injection surface of the output and the value the operator has to trust).
3. **The broker's own code — not the summarizing LLM — unconditionally registers the output as a new `TaintRecord` with `derivedFrom: [sourceRecordId]`.** This edge cannot be suppressed or spoofed even if the quarantine call itself is prompt-injected, because the registration happens after the LLM call returns, in broker-controlled code.
4. **Raises the scope watermark to `maxLevel(current, DERIVED_UNTRUSTED)`** — never all the way back to `CLEAN`. The quarantine path buys a lower tier, not a clean bill of health.

**Cost, stated plainly**: every large/sensitive tool result now costs one extra LLM round trip to legally condense; a schema-constrained `summarize()` call limits what the agent can say about quarantined content (typed extraction, not free riffing) in exchange for exact rather than fuzzy provenance at exactly the step where fuzzy matching is weakest. Skipping the sanctioned path does not buy a clean result — the scope simply stays at `RAW_UNTRUSTED` and every non-`NONE`-class sink is gated at the stricter tier, so the incentive design rewards routing through quarantine rather than punishing it as extra friction with no payoff.

**Implementation note — landing at `DERIVED_UNTRUSTED`, not `RAW_UNTRUSTED`.** The watermark is monotonic (§4.1): once it reaches `RAW_UNTRUSTED`, no later `summarize()` call can bring it back down to `DERIVED_UNTRUSTED`. So a composite tool meant to demonstrate the quarantine path's lighter tier — "fetch this page, then only ever hand the agent a quarantined summary of it" — must not itself be a broker-registered `isSource: true` tool whose raw result is returned to the caller (that would raise the watermark to `RAW_UNTRUSTED` before `summarize()` ever runs, per §6.1). Instead, such a tool fetches raw content as an internal implementation detail, registers it directly via `broker.registry.register(text, provenance, 'RAW_UNTRUSTED', sensitivity)` (which creates a `TaintRecord` for `summarize()` to reference but — unlike `applyPostExecutionEffects` in `broker.ts` — does **not** touch the watermark), and only then calls `broker.summarize()`, whose own effect raises the watermark straight to `DERIVED_UNTRUSTED`. The raw text is registry-known (so `summarize()`'s input-provenance check in §6.2 step 1 accepts it) without ever having been "returned to the caller for the model to read" in the sense that matters for §6.1. See `corpus/cases.ts` (`summarize-then-act-write-file`) for a worked example.

## 7. Sink & Policy Model

### 7.1 Sink declaration

```typescript
type SinkClass = 'EXEC' | 'MUTATE' | 'EXFIL' | 'NONE';
type SinkCapability =
  | 'exec:shell' | 'exec:code'                                          // -> EXEC
  | 'write:fs' | 'write:external-account' | 'finance:purchase'
  | 'irreversible:other'                                                // -> MUTATE
  | 'net:outbound' | 'net:email' | 'net:api-call' | 'net:post-message'; // -> EXFIL
```

Every `ToolExecutor` declares `capabilities: SinkCapability[]` (empty ⇒ `NONE`) and `readsPrivateData?: {categories: string[]} | false`. A tool with any non-empty `capabilities` is a sink; one with `readsPrivateData` sets `scope.watermark.privateDataSeen = true` on any call, independent of that call's own taint.

### 7.2 Default policy matrix

`privateDataSeen` is an **escalator**, never a **gate** — this is the fix to the soundness hole both source proposals shared.

| Scope watermark | EXEC sink | MUTATE sink | EXFIL sink |
|---|---|---|---|
| `RAW_UNTRUSTED` | **BLOCK**, unconditionally | `REQUIRE_APPROVAL`; escalates to `BLOCK` if `privateDataSeen` | `REQUIRE_APPROVAL`, unconditionally; escalates to `BLOCK` if `privateDataSeen` (full trifecta) |
| `DERIVED_UNTRUSTED` | `REQUIRE_APPROVAL`, unconditionally (never gated only by the trifecta) | `REQUIRE_APPROVAL` if `privateDataSeen`, else `ALLOW_WITH_WARNING` | `REQUIRE_APPROVAL` if `privateDataSeen` (full trifecta), else `ALLOW_WITH_WARNING` |
| `CLEAN` | ALLOW (logged) | ALLOW (logged) | ALLOW (logged) |

Independent of the table: if `TaintContext.argFingerprintFloor` (Layer 2) reports a live exact/high-confidence match to an untrusted source, the decision is floored at `REQUIRE_APPROVAL` even if the table above would allow it (e.g. a turn-scoped watermark reset while a fingerprint chain still ties this argument to a prior-session untrusted result) — this only ever tightens a verdict, never loosens one.

`QUARANTINE_AND_RETRY` is offered, never auto-applied, whenever a `BLOCK`/`REQUIRE_APPROVAL` verdict is produced for a call whose arguments trace to a recent, identifiable untrusted result: the verdict includes a suggested rewrite ("re-run the source read through `summarize()` with schema X, then retry"), surfaced to whatever handles the verdict (human or supervising process). It is never auto-executed, because unconditional auto-retry-through-quarantine is itself an attacker-influenceable control-flow decision.

### 7.3 Decision function

```typescript
type PolicyFn = (call: ToolCall, taint: TaintContext) => Promise<PolicyDecision> | PolicyDecision;
```

`TaintContext` carries `{matchedRecords, scopeLevel, argFingerprintFloor, privateDataSeen, sinkClass}`. The shipped default implements the table above; it is a plain function and fully overridable per deployment. `ToolCallBroker.call()` is the **only** path from the agent loop to `ToolExecutor.execute()`; integrators are told, as a hard requirement, that no other code path may invoke a registered executor directly, since the broker enforces nothing it is bypassed for (see §10).

## 8. TypeScript Core Interfaces

The full, precise contract lives in `src/types.ts` and is authoritative for implementation — it defines `TaintLevel`, `TaintWatermark`/`TaintScope`, `TaintRecord`/`TaintRegistry`/`TaintedValue`, `SinkCapabilities`/`ToolExecutor`, `PolicyDecision`/`PolicyFn`/`TaintContext`, `ApprovalChannel`/`AuditSink`, the `QuarantineFn` (`summarize`) signature, and `ToolCallBroker`.

## 9. Corpus Test Harness

A corpus case pairs a scripted call sequence with an expected verdict and expected final watermark state. See `corpus/schema.ts` for the `CorpusCase` type and `corpus/cases/` for the eleven canonical attack classes (two of which — `untracked-context-channel` and `cross-turn-latent-influence` — are true, asserted known gaps, not silent misses: the corpus proves the library is honest about them, not that it catches them).

A test runner replays `setupCalls` through mock source/sink tools to seed the registry and raise the watermark as real calls would, then replays `agentActions` in order (routing any `viaQuarantine` step through `broker.summarize()`), and asserts the recorded `PolicyDecision` and final watermark state match `expected`. Cases tagged with a known-gap `attackClass` assert the **documented** outcome, not an idealized one — so the corpus doubles as a regression check against silently overclaiming coverage.

## 10. Known Gaps & Non-Goals

This library does not achieve soundness in the information-flow-control sense — it achieves a conservative, structural approximation with named, honest limits. See `GAPS.md` for the full, specific enumeration. The single most important non-goal to state plainly: **this design gates on "was untrusted content live in this scope's tracked context," which is a sound, conservative proxy for "did the model act on it," not proof of causal influence** — every claim in this document about "catching summarize-then-act" should be read against that proxy, not as evidence of true interpretability into the model's reasoning.

## 11. Appendix: Optional Strict Mode (Plan-Freeze)

For deployments wanting CaMeL-level control-flow protection (untrusted data cannot introduce a *new* privileged call shape, not just supply values to an existing one), TTTB optionally supports `broker.declarePlan(steps: PlanStep[])`: an ordered list of tool/argument-shape commitments made before any untrusted read. Once the scope's watermark leaves `CLEAN`, an incoming privileged call that does not match the next committed step is treated as `UNPLANNED_PRIVILEGED_ACTION_AFTER_EXPOSURE` and escalated. This is **not** the default — committing to full call shape and count before seeing the data that determines how many calls are needed is a poor fit for standard single-step ReAct-style tool calling and imposes a real practicality cost — but it is available as an additive, stricter layer for high-stakes autonomous agents that can tolerate it. (Not implemented in v0.1 — tracked as a follow-up; see GAPS.md.)
