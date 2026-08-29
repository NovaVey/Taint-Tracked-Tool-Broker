# GAPS.md — Known Limitations of the Taint-Tracked Tool Broker

This library gates privileged tool calls on a conservative, structural proxy: **"was untrusted content live in this scope's tracked context when this call was made"** — not on "did the model's reasoning actually depend on that content." That proxy is sound and cheap to compute, and it is why the broker survives paraphrase, translation, and decision-laundering (see `DESIGN.md` §6) without needing to interpret the model's reasoning. But it is still a proxy, with real, specific edges where it does not help. This document names them plainly rather than leaving them to be discovered in production.

Every case below has a corresponding entry in the injection corpus (`corpus/cases/`) — the two marked **TRUE KNOWN GAP** are asserted in the corpus as gaps, not silently passing tests.

## 1. Untracked context-injection channels — **TRUE KNOWN GAP**

The watermark is raised only by `ToolCallBroker.call()` observing a tracked tool result or a sanctioned quarantine call. Untrusted content that reaches the model's context any other way — a poisoned MCP/tool/plugin description, an untrusted system-prompt fragment, or content the user pastes directly into a turn — never raises the watermark and is invisible to every downstream check. Integrators must call the exposed `markContextExposure()` escape hook for any such channel; the library cannot discover it automatically.

## 2. Cross-turn / cross-session latent influence — **TRUE KNOWN GAP**

Under `resetScope: 'turn'` (the lower-friction mode), content read in turn N that shapes model behavior in turn N+2 with no new tool result in between is invisible once the turn boundary clears the watermark. `resetScope: 'session'` closes this but pays a larger blanket-gating cost across the whole session; this is a deliberate, named trade the operator must choose, not something the library resolves for them.

## 3. Blanket post-exposure friction is the core usability cost, not a side effect

Once `RAW_UNTRUSTED` (or, for `EXEC` sinks, even `DERIVED_UNTRUSTED`) is set in a scope, every privileged call in that scope is gated regardless of whether it has any real relationship to the untrusted content that triggered the watermark. Long sessions that read one untrusted page early can face approval friction for many unrelated later actions. The only mitigations are disciplined use of the `summarize()`/quarantine path and narrower scoping, both of which are adoption costs, not automatic fixes.

## 4. The quarantine path only bounds risk if the extraction schema is actually narrow

A `summarize()` call with an unconstrained free-text field lets an injected payload ride through largely intact, and `DERIVED_UNTRUSTED` policy is deliberately lighter than `RAW_UNTRUSTED` for `MUTATE`/`EXFIL` sinks — so a wide-open schema quietly reintroduces much of the risk the tier distinction exists to reduce. Narrow, typed schemas are the safety property; this is a documented usage discipline, not something the type system enforces.

`summarize()`'s own input-provenance check (§6.2 step 1) requires `text` to be substantially derived from the claimed `sourceTaintRecordId` — a length-ratio cap plus an asymmetric shingle-coverage check (`quarantine.ts`), not a spoofing-proof verification. An adversarial input crafted to sit just inside both thresholds (e.g. a large genuine quote from the source padded with a modest amount of fabricated content, still under the length cap) can still pass. This closed a real, reproduced bypass found during review — a huge fabricated payload could ride through by borrowing a single shingle from a tiny source, because the original check used a symmetric overlap coefficient dominated by whichever side was smaller — but "closed the reproduced exploit" is not the same claim as "unspoofable."

## 5. Implicit/covert channels through an already-approved option set

If a sink accepts a choice among a small number of pre-approved values (e.g. five hardcoded email templates) and only the choice itself is influenced by untrusted content, the watermark still gates the call correctly — but a design that allowlists specific argument values as always-safe (a common performance/usability optimization operators may add) can reopen a narrow signaling channel this library does not close.

## 6. Steganographic / timing covert channels on already-permitted traffic

Message timing, casing/whitespace patterns in an allowed response, or selection among allowed low-stakes options are out of scope for any taint-tracking design, including this one. No content- or context-level mechanism stops a sufficiently patient covert channel riding on approved traffic.

## 7. Human-approval fatigue and social engineering are unsolved human-factors problems

A conservative default policy that frequently returns `REQUIRE_APPROVAL` after any untrusted exposure creates real pressure toward reflexive click-approval — and the same untrusted content that triggers the approval can also shape the surrounding context an approver sees. The broker surfaces the decision point, the taint sources, and the raw matched content, but cannot force genuine scrutiny.

## 8. Fingerprint (Layer 2) coverage has real, expected false negatives

Heavy paraphrase, cross-language translation, and encoding transforms (base64, hex, homoglyphs, zero-width characters) defeat exact-hash and shingle/simhash matching. This no longer breaks soundness in this design (the watermark still gates the sink regardless), but it does mean the *explanation* attached to a block/require-approval verdict degrades from a precise "this argument literally contains text from source X" to a coarse "this scope is tainted, source unknown" — an audit-quality cost, not a safety cost, as long as the content entered through a tracked channel.

## 9. Fingerprint false positives from coincidental overlap

Benign boilerplate, disclaimers, or common phrasing shared between trusted and untrusted sources can produce spurious Layer-2 fuzzy matches, adding noisy source attribution to a verdict — though this never independently causes a false `BLOCK`, since Layer 2 can only tighten a verdict the watermark already produced, never originate one on its own for an otherwise-`CLEAN` scope.

## 10. Sink/capability misclassification is the integrator's responsibility, unverified by the library

A tool that actually performs exfiltration (a DNS lookup embedded in an argument, a "read-only" API call with a logging side-channel) but is registered with an empty or wrong `capabilities` array is invisible to every policy check. Likewise a tool wrongly omitting `isSource`/`readsPrivateData` silently breaks watermark-raising or the private-data escalator.

## 11. The broker is only as sound as its position as the sole path to execution

Nothing prevents an integration from calling a registered `ToolExecutor`'s `execute()` directly, or from giving a code-execution sink sandboxed code that itself shells out or makes HTTP requests outside the broker entirely. This must be enforced structurally by the integrator (no direct executor references escape the broker, egress control around any sandbox); the library only mediates calls actually routed through `ToolCallBroker.call()`.

## 12. No cross-process, cross-agent, or cross-session taint persistence

Watermark and registry state live in one broker instance's memory. A sub-agent, a spawned worker, or a different tool ecosystem reading content written to a file/DB by this session re-enters as unmarked unless it shares the same broker/registry, or a sidecar persistence layer is added by the integrator — not part of this design.

## 13. Performance and cost are real and ongoing

Every large/sensitive tool result that needs condensing costs one extra LLM round trip through `summarize()`, and every outgoing call pays a fingerprint scan (exact hash plus LSH-banded fuzzy lookup) against a registry that grows across a session. Production deployments need indexed (not linear) registry lookups and a pruning/retention policy for long sessions — named here as an operational concern, not solved by this library.

## 14. Threshold tuning for Layer 2 fuzzy matching is an ongoing, adversarial problem

The same cat-and-mouse dynamic seen in plagiarism-detection and spam-filter fingerprinting applies here. Because it now only affects attribution precision and downgrade eligibility rather than the core block/allow soundness boundary, the blast radius of a badly tuned threshold is smaller than in a fingerprint-only design — but it still needs periodic revisiting against the injection corpus.

## 15. Overclaiming disclaimer

This design gates on "was untrusted content live in this scope's tracked context," which is a sound and conservative proxy for "did the model act on it" — but it is still a proxy. It cannot inspect the model's internal reasoning, so it cannot distinguish a privileged call the untrusted content genuinely influenced from one that happens to occur in the same scope but is entirely unrelated. Every claim of "catching summarize-then-act" in `DESIGN.md` should be read as "catching privileged actions taken while untrusted content was in tracked scope," not as evidence of true causal-influence detection.

## 16. Non-cloneable tool-call arguments fall back to a shared, mutable reference

`ToolCallBroker.call()` snapshots `args` (via `structuredClone`) so that what a human approves, what gets audited, and what actually executes can't silently diverge if something mutates the object in between (§ "Concurrency and args integrity" in `DESIGN.md`). `structuredClone` can't handle every JS value (functions, most class instances, etc.); when it throws, the broker falls back to the original live reference for that call, silently losing the isolation guarantee for that one call. Tool arguments are expected to be JSON-able in essentially all realistic tool-calling APIs, so this is a narrow edge case, but it is not enforced by the type system — a `ToolExecutor<A>` with a non-cloneable `A` re-opens the args-mutation risk item 16 exists to close.

## Not yet implemented (tracked, not silent)

- **Plan-freeze strict mode** (`DESIGN.md` §11): CaMeL-level control-flow protection where untrusted data cannot introduce a *new* privileged call shape. Designed, not built in v0.1.
- **Indexed/pruned registry storage** for long-running sessions (item 13 above uses a linear/in-memory registry in v0.1; fine for the corpus and typical sessions, not validated at scale).
