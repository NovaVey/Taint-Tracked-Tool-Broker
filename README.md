# Taint-Tracked Tool Broker

[![npm version](https://img.shields.io/npm/v/taint-tracked-tool-broker.svg)](https://www.npmjs.com/package/taint-tracked-tool-broker)
[![CI](https://github.com/NovaVey/Taint-Tracked-Tool-Broker/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaVey/Taint-Tracked-Tool-Broker/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Node.js >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178c6.svg)](https://www.typescriptlang.org/)
[![Module: ESM only](https://img.shields.io/badge/module-ESM%20only-informational.svg)](#install)

Provenance labeling for agent inputs, enforced at the tool-call boundary. Blocks untrusted data from reaching shell, filesystem, and network sinks — including when it arrives paraphrased, translated, re-encoded, or laundered through a boolean decision instead of copied verbatim. Ships with an injection corpus and a published list of known gaps.

## Contents

- [The problem](#the-problem)
- [Install](#install)
- [Quick start](#quick-start)
- [Core model](#core-model)
- [Examples](#examples)
- [Doctor CLI](#doctor-cli)
- [Observability](#observability)
- [Injection corpus](#injection-corpus)
- [Known gaps](#known-gaps)
- [Versioning](#versioning)
- [Language-neutral specification](#language-neutral-specification)
- [Development](#development)
- [License](#license)

## The problem

An LLM agent with tool-calling access is dangerous the moment it reads content it did not originate — a fetched page, an email, a file, another tool's output — because at the token level there is no boundary between *data* and *instructions* once both are in context. This is indirect prompt injection. Prompting the model to "be careful" doesn't fix it; enforcement has to sit at the boundary where the model's decisions become real side effects: the tool call.

Most naive defenses try to track *content* — does this argument contain text from that untrusted source? That approach is trivially defeated by "please summarize this page, then act on the summary": the paraphrase shares no literal substring with the source, so content-matching finds nothing.

This library gates on *exposure* instead of content. The moment untrusted content is read into an agent's context, a scope watermark is raised — atomically, before the model ever sees the result, so it can't be avoided by rewriting. Every privileged call in that scope is then checked against the watermark, not against what its own arguments say. See [`DESIGN.md`](./DESIGN.md) for the full architecture and rationale, and [`GAPS.md`](./GAPS.md) for what this does *not* catch.

## Install

```bash
npm install taint-tracked-tool-broker
```

Or, to work on the library itself (or install straight from a specific commit):

```bash
git clone https://github.com/NovaVey/Taint-Tracked-Tool-Broker.git
cd Taint-Tracked-Tool-Broker
npm install && npm run build
```

`dist/` is then importable directly (`import { createBroker } from './Taint-Tracked-Tool-Broker/dist/index.js'`), or link it into another project with `npm link`.

**ESM only** — this package ships as native ESM (`"type": "module"`, no CommonJS build). `import` it from an ESM project as normal. A CommonJS project on a Node version without [`require(esm)`](https://nodejs.org/api/modules.html#loading-ecmascript-modules-using-require) support can't `require()` it directly (`ERR_REQUIRE_ESM`) — use a dynamic `await import('taint-tracked-tool-broker')` instead. This is a deliberate, permanent design choice, not a gap to be filled later: ESM-only keeps the codebase simpler and matches the target audience of modern Node agent frameworks, which are themselves ESM-first.

**Requires Node.js >= 20** (see `engines` in `package.json`).

## Quick start

```ts
import { createBroker, ToolCallBlockedError } from 'taint-tracked-tool-broker';

const broker = createBroker();

const fetchUrl = broker.wrap({
  name: 'fetch_url',
  capabilities: { capabilities: [] }, // not a sink itself
  isSource: true,                     // its result can carry untrusted content
  async execute({ url }) {
    return realFetch(url);
  },
});

const shellExec = broker.wrap({
  name: 'shell_exec',
  capabilities: { capabilities: ['exec:shell'] }, // an EXEC-class sink
  async execute({ cmd }) {
    return realShell(cmd);
  },
});

// Wire fetchUrl / shellExec into your agent loop's tool list exactly as you
// would the unwrapped versions — .execute() now routes through the broker.

await fetchUrl.execute({ url: 'https://example.com' });
// watermark is now RAW_UNTRUSTED for this scope

await shellExec.execute({ cmd: 'anything the model writes, paraphrased or not' });
// throws ToolCallBlockedError — EXEC sinks are blocked unconditionally
// once untrusted content is live in scope, regardless of what the
// command text says
```

**Note the `createBroker()` above passes no `auditSink`.** That's a supported, fully-working configuration — every gate above is still enforced correctly — but it also means this exact snippet produces *zero* audit trail: the default `auditSink` is a silent no-op. Pass a real one (`createBroker({ auditSink: { record(e) { ... } } })`) for anything beyond a quick local check — see Core model below and GAPS.md #25.

**A more realistic session.** `shell_exec` above is an `EXEC` sink, unconditionally `BLOCK`ed once anything untrusted is live in scope — the clearest case to demonstrate first, but also the rare one: most real tools are `MUTATE`/`EXFIL` (`write_file`, `send_email`, an API call), which land on `REQUIRE_APPROVAL` instead of a flat `BLOCK`, and actually consulting that verdict means configuring `approvalChannel`, catching the resulting `ToolCallBlockedError`, and reading `auditSink`. This second example shows that full, common path:

```ts
import {
  createBroker,
  createDeferredApprovalChannel,
  formatAuditTrail,
  ToolCallBlockedError,
  type AuditEvent,
} from 'taint-tracked-tool-broker';

const events: AuditEvent[] = [];

// A real integration notifies a human here (Slack, an approval-queue UI, a
// webhook) and calls approvalChannel.resolve(token, granted) from whatever
// handler receives their decision — createDeferredApprovalChannel() just
// gives you the token-keyed pending-request bookkeeping for that. This
// simulates an approval arriving shortly after the request is made.
const approvalChannel = createDeferredApprovalChannel({
  onPending: (token) => {
    setTimeout(() => approvalChannel.resolve(token, true), 50);
  },
});

const broker = createBroker({
  approvalChannel,
  auditSink: { record(e) { events.push(e); } },
});

const fetchUrl = broker.wrap({
  name: 'fetch_url',
  capabilities: { capabilities: [] },
  isSource: true,
  async execute({ url }) {
    return realFetch(url);
  },
});

const writeFile = broker.wrap({
  name: 'write_file',
  capabilities: { capabilities: ['write:fs'] }, // a MUTATE-class sink
  async execute({ path, contents }) {
    return realWriteFile(path, contents);
  },
});

await fetchUrl.execute({ url: 'https://example.com' });
// watermark is now RAW_UNTRUSTED for this scope, same as the EXEC example.

try {
  await writeFile.execute({ path: '/tmp/notes.txt', contents: 'from the model' });
  // REQUIRE_APPROVAL, granted by the simulated approval above -> proceeds.
} catch (err) {
  if (err instanceof ToolCallBlockedError) {
    // err.taint is the exact TaintContext this decision was computed from —
    // which upstream content actually triggered it (err.taint.matchedRecords),
    // and the scope level at decision time (err.taint.scopeLevel) — without
    // separately wiring auditSink and correlating it back by call id.
    console.log(`blocked: ${err.message} (scope was ${err.taint.scopeLevel})`);
  } else {
    throw err;
  }
}

console.log(formatAuditTrail(events));
// one readable line per AuditEvent: timestamp, tool, args, verdict, scope
// level, executed?, and the policy's reason — see Core model below.
```

## Core model

- **A single trust lattice** — `CLEAN < DERIVED_UNTRUSTED < RAW_UNTRUSTED` — used for both the scope watermark and individual fingerprint records.
- **`ToolExecutor.sourceClass`** is a second, orthogonal axis alongside that lattice: a free-form, integrator-defined origin-type label (`'internal-mcp'`, `'public-web'`, `'user-pasted'`, ...) copied onto `ProvenanceTag.sourceClass` every time a source raises the watermark, and surfaced as `TaintContext.sourceClasses` — the distinct classes contributing to the current scope, deduplicated. `TaintLevel` orders trust *degree*; this expresses *why* something is untrusted, which the lattice deliberately collapses. `defaultPolicy` never reads it — it's plumbing for your own `PolicyFn`, not a built-in opinion on which classes are lower-risk. See GAPS.md #28 and `npm run example:source-class-policy`.
- **The scope watermark is the safety boundary.** It rises the instant a source tool (`isSource: true`) returns, before the model reads the result. It is monotonic; only `broker.declassify()` lowers it, and only as an explicit, audited action.
- **One broker instance = one session.** The watermark, the fingerprint registry, and the call-ordering lock are all per-instance in-memory state — `createBroker()` once per agent session and reuse that instance for its entire lifetime (across turns too); never share one instance across two concurrent, unrelated sessions, and never treat `BrokerOptions.sessionId` as a lookup key that isolates them for you — it's just a label copied into audit records. See GAPS.md #19.
- **Sinks are classified `EXEC` / `MUTATE` / `EXFIL` / `NONE`** by declared capability (`exec:shell`, `write:fs`, `net:email`, ...). `EXEC` is hard-gated by watermark level alone — it needs no private data to be catastrophic. `EXFIL`/`MUTATE` calls while untrusted content is live always require at least approval; a `readsPrivateData` tool having been called this scope *escalates* that to a hard block (the "lethal trifecta"), it never *gates* on its own.
- **The fingerprint registry is secondary.** Exact hash + simhash + word-shingle overlap gives precise "this argument literally contains text from source X" attribution when a literal or near-literal chain survives — but it can only ever *tighten* a policy verdict, never loosen one, and it is never the sole basis for allowing a call. Fuzzy lookup is indexed (LSH-banded simhash + a shingle inverted index), not a linear scan, and an optional `maxEntries` bounds memory for long-running sessions.
- **`broker.summarize()`** is the sanctioned way to condense/paraphrase untrusted content before it re-enters the model's context without staying at `RAW_UNTRUSTED`: a capability-less LLM call you supply, whose output the broker itself (not the LLM) registers as `DERIVED_UNTRUSTED` — never all the way back to clean.
- **`requireQuarantineSchema`** is an optional, additive strict mode for `broker.summarize()` (GAPS.md #4): `opts.schema` is normally optional and defaults to unconstrained free text, which quietly reintroduces much of the risk `DERIVED_UNTRUSTED` exists to reduce — set this `true` and a schema-less call is rejected outright (`QuarantineSchemaRequiredError`, audited as a `BLOCK`) rather than silently falling back to free text. Off by default; unaffected calls that already pass a schema.
- **`checkFieldGrounding()`** closes `broker.summarize()`'s own blind spot: nothing stops the Q-LLM you supply from hallucinating — or being manipulated into fabricating — a field value that never appeared anywhere in the source text it was asked to condense. This opt-in, standalone utility fuzzy-checks each extracted field against the original source(s) and reports which are traceable versus fabricated; your own `QuarantineImpl` decides what to do with an ungrounded field (reject the extraction, ask for re-extraction, flag for review) — this library doesn't decide that for you, the same "declares/enforces" split as tool classification. See GAPS.md #27.
- **`broker.declarePlan(steps)`** is an optional, additive strict mode (DESIGN.md §11): commit to the exact sequence of privileged tool calls *before* any untrusted read, and any later privileged call that doesn't match the next committed step is rejected — on top of, never instead of, the normal policy check above.
- **`allowedOutboundHosts`** is an optional, additive egress firewall (DESIGN.md §7.4): every `EXFIL`-class call's arguments are scanned for `http(s)` URLs *and* email addresses, and one whose destination host isn't allowlisted is blocked — a structural boundary independent of the taint-based policy, applied even to a `CLEAN` scope, rather than another approval prompt a human could rubber-stamp. Deliberately narrow in scope; see GAPS.md #18. A tool can declare `destinationKeys` on itself to scope the scan to just the argument key(s) that actually carry its destination, instead of the whole-tree scan, eliminating false positives from an unrelated field that merely happens to look like a URL.
- **`createToolDescriptorGuard(broker)`** closes one specific, named instance of GAPS.md #1 (untracked context-injection channels): a malicious or compromised MCP server can rewrite a tool's description or input schema between two `tools/list` calls to smuggle new instructions into whatever later reads it, a channel that never routes through `broker.call()` at all. The returned function fingerprints each tool's full descriptor (name + description + schema) and calls `broker.markToolDescriptionExposure()` — `ALLOW_WITH_WARNING` plus a taint raise, never a hard deny — the moment a previously-seen tool's descriptor changes. Doesn't decide whether a description is malicious, only whether it changed; the broader gap (arbitrary system-prompt fragments, pasted content, any other untracked channel) still needs an explicit `markContextExposure()` call.
- **`createBroker({ enforcement: 'observe' })`** is a standard adoption-ramp mode (CSP report-only, a WAF's detection mode) for measuring what `'enforce'` (the default) would have gated, against real traffic, before turning enforcement on: `policy()` still runs and every `AuditEvent` is populated identically, but a `BLOCK`/`REQUIRE_APPROVAL`/`QUARANTINE_AND_RETRY` verdict no longer prevents the call — it executes anyway, audited truthfully (`AuditEvent.enforcement: 'observe'`, and `formatAuditTrail()` marks the overridden ones `[OBSERVE MODE: NOT ENFORCED]`). Refuses to construct without a real `auditSink` (`ObserveModeRequiresAuditSinkError`) — a broker that never gates and has nowhere to record what it would have gated is strictly worse than the silent default no-op sink below. Plan-freeze and `allowedOutboundHosts` are hard structural boundaries independent of `policy()` and remain fully enforced regardless of this setting. See GAPS.md #31.
- **`QUARANTINE_AND_RETRY`** is a decision `defaultPolicy` can hand back alongside `ALLOW`/`ALLOW_WITH_WARNING`/`REQUIRE_APPROVAL`/`BLOCK`: when an otherwise-`BLOCK`/`REQUIRE_APPROVAL` verdict traces to a specifically identifiable untrusted source (a confident Layer 2 fingerprint match, not just a bare watermark taint), it replaces that verdict with a named suggestion to re-run the source through `broker.summarize()` and retry — never auto-executed, purely informational.
- **State can cross a process boundary.** `createBroker({ initialWatermark, registry })` plus `serializeBrokerState()`/`restoreBrokerState()` let one broker's watermark, registry, and any declared plan-freeze plan (resuming at the exact cursor it was at when exported) be exported (JSON-safe) and used to seed another — for a sub-agent, a worker, or a resumed session. Not automatic; an integrator still has to call these and pass the result along.
- **`createTaintEnvelope(value, taint)`** is the same idea at a narrower grain: not a whole broker's state, but one specific value's taint provenance (scope level, matched fingerprint records, a human-readable summary) — for handing that one value across a boundary where the live registry isn't reachable at all (a downstream service, a database row, a human-review UI). One-way, like the audit log below, not something this library restores a broker from.
- **Every gated decision reaches `BrokerOptions.auditSink` as an `AuditEvent` — but don't hand it to `JSON.stringify()` directly.** When a call's arguments fuzzy- or exact-match a previously-registered record (the ordinary case for a real attack, not an edge case), `event.taint.matchedRecords[].record.fingerprint` carries a `bigint` and a `Uint32Array`, which `JSON.stringify` throws on and silently mangles, respectively — so the single most obvious `AuditSink`, `record(e) { console.log(JSON.stringify(e)) }`, crashes on the first such event. Use `serializeAuditEvent()` (`src/persistence.ts`) first: `JSON.stringify(serializeAuditEvent(event))`. See `AuditSink`'s own doc comment (`src/types.ts`) for the full explanation.
- **`event.call.args` is the tool call's real, unredacted arguments, exactly as sent — a credential, an API key, a chunk of a private document can reach your `auditSink` verbatim.** `createBroker({ redactAuditArgs })` is an opt-in hook applied to `call.args` only, on every `AuditEvent`, before it reaches your sink — this library ships no default redaction logic (it can't know what counts as sensitive in your own tool arguments), just the seam. See [`docs/audit-redaction.md`](./docs/audit-redaction.md) for worked patterns and GAPS.md #24 for the gap this closes.
- **The default `auditSink` — what you get by configuring nothing, including by following Quick start above verbatim — is a silent no-op.** Every gate is still enforced correctly either way, but a broker built that way produces zero audit trail. `formatAuditTrail(events)`, `explainWatermark(scope)`, and `AggregatingAuditSink` (`src/debug.ts`, also exported from the package root) turn a configured sink's raw `AuditEvent`s into readable prose, a plain-language explanation of why the watermark is what it is, and a `snapshot(): Record<string, number>` of verdict/approval/latency counters, respectively — none of it new tracking, all of it rendering data this library already collects. See GAPS.md #25.

Read [`DESIGN.md`](./DESIGN.md) for why each of these choices was made, including the soundness gap the design's own judge-panel process found and closed before this was implemented.

## Examples

Runnable, offline (no API key, no real network calls — everything is mocked except the broker itself) walkthroughs in [`examples/`](./examples):

| Script | What it shows |
|---|---|
| `npm run example` | The core model end to end: verbatim injection, paraphrase bypass, the sanctioned `summarize()` path. |
| `npm run example:mcp` | All three MCP protocol surfaces (`tools/call`, `resources/read`, `tools/list`) and `createToolDescriptorGuard()`, the exported rug-pull guard (GAPS.md #1). |
| `npm run example:mcp-sdk` | The same MCP pattern against a real `@modelcontextprotocol/sdk` client/server pair (`InMemoryTransport.createLinkedPair()`, real JSON-RPC) instead of a mock. |
| `npm run example:tool-loop` | A full Anthropic Messages API-style tool loop — a blocked call recovering gracefully, `REQUIRE_APPROVAL` suspending the loop, and `startNewTurn()`'s one correct call site under `resetScope:'turn'`. |
| `npm run example:langchain` | Wiring `broker.wrap()` behind LangChain.js's `tool()`/`Runnable.invoke()` shape. |
| `npm run example:vercel-ai` | The same pattern behind the Vercel AI SDK's `tool()`/`execute()` shape. |
| `npm run example:openai-agents` | The same pattern behind the OpenAI Agents SDK's `tool()`/`execute()` shape, exercising the `REQUIRE_APPROVAL` path via `createDeferredApprovalChannel()`. |
| `npm run example:openai-tool-loop` | A *raw* OpenAI Chat Completions API-style tool loop (`tools`/`tool_choice`, a manual `while` loop feeding results back as `role:'tool'` messages) — distinct from `example:openai-agents` above, which wires the newer, higher-level Agents SDK instead. |
| `npm run example:mastra` | Wiring `broker.wrap()` behind Mastra's `createTool({ execute: ({ context }) => ... })` shape. |
| `npm run example:genkit` | Wiring `broker.wrap()` behind Google Genkit's `ai.defineTool()` handler shape. |
| `npm run example:agent-sdk` | Wiring `broker.wrap()` behind the (Claude) Agent SDK's in-process `tool()`/`createSdkMcpServer()` helper — a third, distinct Anthropic integration shape alongside `example:tool-loop` (the raw Messages API) and `example:mcp-sdk` (a real network MCP server). |
| `npm run example:llamaindex-ts` | Wiring `broker.wrap()` behind LlamaIndex.TS's `FunctionTool.from()`/`tool()` shape. |
| `npm run example:semantic-kernel-js` | Wiring `broker.wrap()` behind Semantic Kernel JS's `KernelFunction.from()`/plugin shape. |
| `npm run example:taint-envelope` | Packaging a blocked/quarantined call's `TaintContext` into a portable, JSON-safe `TaintEnvelope` (`createTaintEnvelope()`) and handing it off across a process boundary. |
| `npm run example:grounding-check` | Rejecting a `broker.summarize()` extraction whose Q-LLM fabricated a field absent from its source, using the standalone `checkFieldGrounding()` utility inside a `QuarantineImpl` wrapper. |
| `npm run example:source-class-policy` | A custom `PolicyFn` reading `TaintContext.sourceClasses` (GAPS.md #28) to downgrade `REQUIRE_APPROVAL` when every contributing source is a reviewed internal MCP server — and *not* when a public-web source is also in scope. |
| `npm run example:observe-mode` | `enforcement: 'observe'` (GAPS.md #31): the construction-time safeguard, a gated verdict executing anyway while still auditing truthfully, `formatAuditTrail()`'s `[OBSERVE MODE: NOT ENFORCED]` marker, and plan-freeze/`allowedOutboundHosts` staying fully enforced regardless. |

The framework examples above don't depend on the real `langchain`/`ai`/`@openai/agents`/`mastra`/`genkit`/`llamaindex`/`@microsoft/semantic-kernel` packages — each uses a small structural stand-in for that framework's real tool-definition shape, since the integration point (a `name`/`description`/schema object with an async execute function) is what matters, not fidelity to a fast-moving package's exact current types. Every framework's real dispatch loop calls that function the same way once `broker.wrap()` has interposed it. `example:mcp-sdk` is the one exception: it depends on the real `@modelcontextprotocol/sdk` (a devDependency, not a runtime dependency of this library) to confirm the stand-in pattern used by `example:mcp` actually holds against the genuine SDK's current shapes.

**AWS Bedrock Agents** isn't in the table above — its Action Group execution model (a Lambda/REST callout from AWS's own managed orchestrator, not an in-process function call) doesn't fit this shape, so a copy-paste mock would misrepresent the actual integration rather than simplify it. See [`docs/aws-bedrock-agents-pattern.md`](./docs/aws-bedrock-agents-pattern.md) for the correct pattern (wrapping inside the Lambda handler) and its one real limitation (watermark state does not survive a cold start without wiring in `serializeBrokerState()`/`restoreBrokerState()`, GAPS.md #12).

## Doctor CLI

`checkToolCatalog(tools)` / `checkBrokerConfig(config, tools)` / `runDoctor({ tools, brokerConfig })` (`src/doctor.ts`, exported from the package root; GAPS.md #30) are a CI-runnable preflight over a tool catalog and broker configuration — catching the same shapes an integrator would otherwise only discover the hard way, at runtime or in review:

- **Two deterministic `register()`/`wrap()` rejections** — a dual-role tool (`isSource: true` plus a non-empty `capabilities` array) and a reserved `__tttb_`-prefixed name — flagged before a live broker ever sees the catalog.
- **The same `warnOnLikelyUnclassifiedSink` keyword check** `docs/classifying-tools.md` already documents running as a manifest lint, packaged into one call.
- **Config-inertness**: a missing `auditSink` (silent no-op, GAPS.md #25), a missing/unconfigured `quarantineImpl` (escalated to an error the moment a tool declares `mayCallSummarize: true`), `requireQuarantineSchema` left off (GAPS.md #4), and an `EXFIL`-capable tool with no `allowedOutboundHosts` configured (GAPS.md #18).

```bash
npx tttb doctor ./dist/my-tools-config.js   # a plain, already-built JS module exporting `tools`/`brokerConfig`
```

Calling `checkToolCatalog()`/`checkBrokerConfig()`/`runDoctor()` directly from your own CI test suite works identically and needs no CLI, no separate config module, and no build step — usually the more natural fit for a TypeScript-first integration. See `docs/classifying-tools.md`'s "A packaged `doctor` preflight" section and `src/cli/doctor.ts`'s own header for the CLI's exact config-module contract, and — same honesty bar as everything else in `docs/classifying-tools.md` — what this still cannot catch (a deliberately-deceptive tool, or one whose real behavior doesn't show up in its name).

## Observability

The default `auditSink` — what `createBroker()` gets when you configure nothing, including by following Quick start above verbatim — is a silent no-op (GAPS.md #25). Every gate is still enforced correctly either way; you just get zero record of it. Configuring a real one turns this library's audit trail into something you can actually query, render, and alert on:

- **`formatAuditTrail(events)` / `explainWatermark(scope)`** (`src/debug.ts`, exported from the package root) — pure renderers over `AuditEvent[]`/`TaintScope.watermark.sources` you already have. No storage, no aggregation — just readable prose for a terminal or log line. See Quick start above for a working snippet.
- **`AggregatingAuditSink`** (`src/debug.ts`) — a small, dependency-free `AuditSink` wrapping an optional delegate, accumulating verdict-by-sink-class counts, `REQUIRE_APPROVAL` grant/deny counts and latency, and `QUARANTINE_AND_RETRY` offer counts into a plain `snapshot(): Record<string, number>`. `npm run example:audit-prometheus` renders that snapshot as real Prometheus text-exposition format (`# HELP`/`# TYPE`/labeled samples) — no `prom-client` dependency, pure string formatting.
- **Durable storage** — `serializeAuditEvent()` (`src/persistence.ts`) makes an `AuditEvent` JSON-safe (its `fingerprint.simhash`/`shingleHashes` fields are a `bigint`/`Uint32Array`, which `JSON.stringify` either throws on or silently mangles). `npm run example:audit-sqlite` writes events to a real SQL table via `node:sqlite`, queries them back with a real `GROUP BY`, and renders the revived events with `formatAuditTrail()` — proof the round trip is lossless, not just "doesn't throw."
- **Redaction before any of the above sees it** — `BrokerOptions.redactAuditArgs` strips or replaces `call.args` before it reaches your sink at all. See [`docs/audit-redaction.md`](./docs/audit-redaction.md) for worked patterns (by `sinkClass`, by `privateDataSeen`, a key denylist).

## Injection corpus

```bash
npm run corpus
```

Runs [`corpus/cases.ts`](./corpus/cases.ts): 22 cases across 15 attack classes — direct verbatim injection, light reformatting, inline paraphrase (the "summarize, then act" bypass), boolean decision-laundering, the sanctioned quarantine path (including an attempt to spoof its input-provenance check with fabricated text), lethal-trifecta escalation, translation/encoding evasion, plan-freeze catching an unplanned privileged action (both a single-step mismatch and a multi-step case where the cursor legitimately advances first), `resetScope: 'turn-decay'` narrowing (not closing) the cross-turn gap, the outbound-host allowlist blocking an unapproved-host call on an otherwise-`CLEAN` scope (both a URL-shaped and an email-address-shaped destination), and `QUARANTINE_AND_RETRY` being offered only when a specifically identifiable source backs it up — correctly withheld both when attribution is too weak to name one, and when a qualifying match exists but is a *decoy*: a strong fingerprint hit against an unrelated, harmless source that has nothing to do with the argument actually making the call dangerous — plus two *true, asserted* known gaps (untracked context-injection channels, and cross-turn latent influence under `resetScope: 'turn'`). The corpus is also run under `npm test`, so a change that silently narrows coverage — or silently starts overclaiming it — fails CI, not just a manual read of `GAPS.md`.

`npm run corpus`'s output isn't just "N/M passed" — that alone doesn't prove anything was actually at stake, since a case can pass by matching a documented expectation for a payload that was never going to do anything even if allowed. Every run also computes a **counterfactual baseline**: each case's sink call(s), replayed against the same fixtures with no broker mediating them at all (`corpus/schema.ts`'s `runUnprotectedCase`). The report's final line makes the real number visible — as of this corpus, 20 non-benign cases, all 20 of which would have executed their sink call unprotected; the broker actually prevents 17 of them, 1 is the sanctioned quarantine path's expected `ALLOW_WITH_WARNING` (not an attack payload by the time it reaches the sink), and 2 are the documented true known gaps where protection provides none. `test/corpus.spec.ts` locks the "would have executed unprotected" half in as a regression test, not just something visible by eyeballing the CLI output.

## Known gaps

This library does not achieve information-flow-control soundness — it achieves a conservative, structural approximation with named, honest limits. It gates on "was untrusted content live in this scope's tracked context," which is a sound proxy for "did the model act on it," not proof of causal influence. See [`GAPS.md`](./GAPS.md) for the full list, including the two true known gaps the corpus asserts rather than papers over.

Every gate rests on how you declare your own tools (`isSource`, `trusted`, `capabilities`, `readsPrivateData`) — get one wrong and that tool isn't gated incorrectly, it isn't gated at all, silently. See [`docs/classifying-tools.md`](./docs/classifying-tools.md) for a checklist and worked examples for the less-obvious cases.

Found a way past the gating logic that isn't already in that list? See [`SECURITY.md`](./SECURITY.md).

## Versioning

This project follows [SemVer](https://semver.org/). As of `1.0.0`, the exported API surface (everything reachable from [`src/index.ts`](./src/index.ts)) is stable — no more silent renames or shape changes without a major version bump. Before `1.0.0`, a minor release could still include a breaking change while the API stabilized (see [`CHANGELOG.md`](./CHANGELOG.md) for that history); that caveat no longer applies going forward. Check the changelog for what actually changed between any two versions before upgrading regardless.

That covenant is about API shape only. Behavioral limitations — what the broker does and doesn't catch — are tracked in [`GAPS.md`](./GAPS.md) and [`DESIGN.md`](./DESIGN.md) regardless of version number, and reaching 1.0 doesn't imply those gaps are closed.

## Language-neutral specification

This is a TypeScript/Node-only library, but the underlying model — the taint lattice, the watermark semantics, the sink-class taxonomy, the default policy decision table, the sanctioned quarantine path, and the audit-event shape — is published separately as [`PROTOCOL.md`](./PROTOCOL.md), in pseudocode/tables/prose rather than TypeScript. It exists for anyone wanting to implement or evaluate this model in a different language or runtime (a Python port, for instance) without requiring this repository to become a second security-critical codebase in a second language: this project is small and solo-maintained (see [`SECURITY.md`](./SECURITY.md)), and a full cross-language port of a security-critical library was deliberately rejected in favor of a shared specification an independent implementation can build against. This TypeScript implementation is the reference implementation of that specification — see `PROTOCOL.md`'s own Conformance section.

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest (unit tests + the injection corpus)
npm run corpus      # just the corpus, with a readable pass/fail table
npm run coverage    # vitest --coverage, enforced against vitest.config.ts's thresholds in CI
npm run lint        # eslint . — type-aware, enforced in CI
npm run format      # prettier --write over src/test/corpus/examples/bench
npm run build       # emit dist/
npm run bench       # structuredClone vs jsonSafeClone args-cloning benchmark
npm run bench:minhash  # why fixed-size MinHash sketches were investigated and NOT shipped for the registry (DESIGN.md)
```

See [`CHANGELOG.md`](./CHANGELOG.md) for what's changed, and [`CONTRIBUTING.md`](./CONTRIBUTING.md) for what a good PR looks like (this project is small/solo-maintained per [`SECURITY.md`](./SECURITY.md), but PRs are welcome). Participation is governed by the [Code of Conduct](./CODE_OF_CONDUCT.md).

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
