# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/), with the pre-1.0 caveat that a minor release may still include a breaking change while the public API stabilizes.

## [Unreleased]

### Added

- **Test coverage reporting** (`npm run coverage`, `vitest.config.ts`): v8-provider coverage over `src/**`, enforced in CI as a real gate (a dedicated `coverage` job, separate from the Node 20/22/24 test matrix) rather than just a report — thresholds are set a few points below the actual measured coverage as of this change (statements 96.32% / branches 91.82% / functions 99.21% / lines 98.03%) so a genuine regression fails CI without ordinary refactors tripping it.
- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `.github/ISSUE_TEMPLATE/`/`PULL_REQUEST_TEMPLATE.md` — standard public-OSS-package community files, added now that `v0.1.0` is published.

## [0.1.0] - 2026-08-30

First published release. Everything below was built and validated (typecheck, unit tests, injection corpus, build) before this tag was cut — see `.github/workflows/release.yml` for the tag-triggered publish process that re-validates all of it once more before publishing.

### Added

- **Core broker** (`createBroker()`, `broker.register()`/`wrap()`/`call()`): the scope watermark (`CLEAN < DERIVED_UNTRUSTED < RAW_UNTRUSTED`) as the load-bearing safety boundary, raised atomically the instant an untrusted source tool's result is captured — before the model ever reads it — so gating survives paraphrase, translation, and decision-laundering. Sinks are classified `EXEC`/`MUTATE`/`EXFIL`/`NONE` by declared capability; a default policy matrix gates by watermark level and sink class, with `privateDataSeen` as an escalator (the "lethal trifecta"), never a gate on its own.
- **Fingerprint registry** (`InMemoryTaintRegistry`): exact-hash + LSH-banded simhash + word-shingle overlap matching, secondary and never load-bearing — it can only tighten a policy verdict, never loosen one. Indexed (not a linear scan) for fuzzy lookup; optional `maxEntries` bounds memory for long-running sessions; `FuzzyLookupOpts.maxMatches` and a tree-wide cap in `scanArgsForTaint()` bound how many matches a single lookup/scan can return, without ever dropping the highest-severity match.
- **`broker.summarize()`** — the sanctioned quarantine/condense path: a capability-less LLM call you supply, whose output the broker itself registers as `DERIVED_UNTRUSTED`, with input-provenance validation (length-ratio + asymmetric shingle-coverage checks) against the claimed source record.
- **`broker.declarePlan(steps)`** — optional, additive plan-freeze strict mode: commit to a tool-identity sequence before any untrusted read; a later privileged call that doesn't match the next committed step is rejected on top of, never instead of, the normal policy check.
- **`broker.markContextExposure()`** (plus the `markToolDescriptionExposure`/`markSystemPromptExposure`/`markPastedContentExposure` specializations) — the manual escape hatch for untrusted content reaching the model outside any tracked tool call (a poisoned tool/plugin description, an untrusted system-prompt fragment, pasted content).
- **Cross-process persistence** (`serializeBrokerState()`/`restoreBrokerState()`, `serializeRegistry()`/`restoreRegistry()`) — export/import a broker's watermark and registry as JSON-safe state across a process boundary (e.g. for a sub-agent or a resumed session).
- **`createDeferredApprovalChannel()`** — an `ApprovalChannel` for `REQUIRE_APPROVAL` decisions that need a real human in the loop (a webhook, a Slack approval, an approval-queue UI) rather than a synchronous decision.
- **`jsonSafeClone()`** — an opt-in, faster alternative to `structuredClone` for args snapshotting when tool arguments are plain JSON; throws (rather than silently misrepresenting) on Date/Map/Set/RegExp/class instances/functions/symbols/bigints.
- **Convenience API surface**: `callSafe()` (a non-throwing `call()`), `registerAll()`/`wrapAll()` (bulk registration over a name -> tool record), `defineSource()`/`defineSink()` (pure `ToolExecutor`-building sugar), `registerRawForQuarantine()` (operationalizes the fetch-and-quarantine composite-tool pattern, returning `{ text, taintRecordId }` ready for `summarize()`).
- **`ToolExecutor.mayCallSummarize`** — declare `true` on a composite fetch-and-quarantine tool whose own `execute()` calls `broker.summarize()` internally, so it's correctly excluded from the lock-barrier-exemption optimization (GAPS.md #17).
- **`resetScope: 'turn-decay'`** — a third watermark-reset mode between `'session'` (never clears) and `'turn'` (clears at the next turn boundary): persists the watermark across a configurable `turnDecayWindow` of consecutive turns with no new exposure before clearing, narrowing (not closing) the cross-turn latent-influence gap (GAPS.md #2) to a chosen, quantified size. `turnDecayWindow: 1` is exactly `'turn'`.
- **Narrowed lock barrier**: `Broker.withLock`'s full-serialization cost is now scoped — a call that can neither be gated (`sinkClass === 'NONE'`) nor raise/mutate the watermark (not an untrusted source, no `readsPrivateData`, and, since GAPS.md #17, not `mayCallSummarize`) bypasses the lock entirely, since it's provably inert to the state the lock protects.
- **Injection corpus** (`npm run corpus`, also run under `npm test`): 15 cases across 12 attack classes, including two true, asserted known gaps (not silently-passing tests), a plan-freeze case, and a `resetScope: 'turn-decay'` case showing the cross-turn gap narrowed rather than closed.
- **Docs**: `DESIGN.md` (full architecture and rationale, including the soundness gap the original judge-panel design process found and closed), `GAPS.md` (17 named, honest limitations), `docs/classifying-tools.md` (a checklist and worked examples for classifying less-obvious tools).
- **Examples**: `examples/basic-usage.ts`, `examples/mcp-integration.ts` (MCP protocol-surface wiring plus a tool-description rug-pull guard), `examples/anthropic-tool-loop.ts` (a full tool-calling loop, including `startNewTurn()`'s correct call site and a deferred-approval scenario), plus framework-integration examples for `examples/langchain-integration.ts`, `examples/vercel-ai-sdk-integration.ts`, and `examples/openai-agents-sdk-integration.ts` (each a structural stand-in for that framework's `tool()`/`execute()` shape, no real framework dependency required).
- **`bench/args-clone.ts`** (`npm run bench`) — `structuredClone` vs `jsonSafeClone` benchmark across representative args shapes.
- **`bench/minhash-sketch-tradeoff.ts`** (`npm run bench:minhash`) — the reproducible Monte Carlo measurement behind the decision *not* to ship fixed-size MinHash sketches for the registry (see GAPS.md #13 and DESIGN.md's implementation note): 35-79% false-negative rates at realistic document-size ratios even at a generous sketch size.
- **`.github/workflows/release.yml`** — tag-triggered (`v*`) npm publish with provenance, gated on the tag matching `package.json`'s version and a full re-run of typecheck/build/test/corpus.

### Fixed

A number of real bugs were found and fixed during development (adversarial review passes, a multi-agent improvement-roadmap review, and tests written for new features catching design gaps before they shipped) — see `DESIGN.md`'s "Implementation note" sections for the full, specific history of each, including exactly what was found, why it mattered, and what was deliberately *not* fixed and why.

### Known limitations

Not a soundness guarantee — a conservative, structural approximation with named, honest limits. See `GAPS.md` for the full list. `broker.summarize()` is now serialized against `broker.call()` under concurrent dispatch (GAPS.md #17, fixed) — with one named residual risk: a composite fetch-and-quarantine tool whose `execute()` calls `broker.summarize()` internally must declare `mayCallSummarize: true` (see `docs/classifying-tools.md` question 5) or it stays wrongly eligible for the lock-barrier-exemption optimization and the original race reopens for that one tool.
