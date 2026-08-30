# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/), with the pre-1.0 caveat that a minor release may still include a breaking change while the public API stabilizes.

## [Unreleased]

Nothing has been published to npm yet — everything below describes the library's current state ahead of its first `0.1.0` release. See `.github/workflows/release.yml` for the tag-triggered publish process; when a maintainer cuts the first release, this section becomes `## [0.1.0] - <date>`.

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
- **Injection corpus** (`npm run corpus`, also run under `npm test`): 14 cases across 12 attack classes, including two true, asserted known gaps (not silently-passing tests) and a plan-freeze case.
- **Docs**: `DESIGN.md` (full architecture and rationale, including the soundness gap the original judge-panel design process found and closed), `GAPS.md` (17 named, honest limitations), `docs/classifying-tools.md` (a checklist and worked examples for classifying less-obvious tools).
- **Examples**: `examples/basic-usage.ts`, `examples/mcp-integration.ts` (MCP protocol-surface wiring plus a tool-description rug-pull guard), `examples/anthropic-tool-loop.ts` (a full tool-calling loop, including `startNewTurn()`'s correct call site and a deferred-approval scenario).
- **`bench/args-clone.ts`** (`npm run bench`) — `structuredClone` vs `jsonSafeClone` benchmark across representative args shapes.
- **`.github/workflows/release.yml`** — tag-triggered (`v*`) npm publish with provenance, gated on the tag matching `package.json`'s version and a full re-run of typecheck/build/test/corpus.

### Fixed

A number of real bugs were found and fixed during development (adversarial review passes, a multi-agent improvement-roadmap review, and tests written for new features catching design gaps before they shipped) — see `DESIGN.md`'s "Implementation note" sections for the full, specific history of each, including exactly what was found, why it mattered, and what was deliberately *not* fixed and why.

### Known limitations

Not a soundness guarantee — a conservative, structural approximation with named, honest limits. See `GAPS.md` for the full list. `broker.summarize()` is now serialized against `broker.call()` under concurrent dispatch (GAPS.md #17, fixed) — with one named residual risk: a composite fetch-and-quarantine tool whose `execute()` calls `broker.summarize()` internally must declare `mayCallSummarize: true` (see `docs/classifying-tools.md` question 5) or it stays wrongly eligible for the lock-barrier-exemption optimization and the original race reopens for that one tool.
