# Taint-Tracked Tool Broker

[![CI](https://github.com/NovaVey/Taint-Tracked-Tool-Broker/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaVey/Taint-Tracked-Tool-Broker/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Node.js >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178c6.svg)](https://www.typescriptlang.org/)
[![Module: ESM only](https://img.shields.io/badge/module-ESM%20only-informational.svg)](#install)

Provenance labeling for agent inputs, enforced at the tool-call boundary. Blocks untrusted data from reaching shell, filesystem, and network sinks — including when it arrives paraphrased, translated, re-encoded, or laundered through a boolean decision instead of copied verbatim. Ships with an injection corpus and a published list of known gaps.

**Status:** pre-`0.1.0`, not yet published to npm — the API and this README describe the library's current state ahead of its first release. See [Install](#install) for how to use it from source today, and [`CHANGELOG.md`](./CHANGELOG.md) for what's shipped so far.

## Contents

- [The problem](#the-problem)
- [Install](#install)
- [Quick start](#quick-start)
- [Core model](#core-model)
- [Examples](#examples)
- [Injection corpus](#injection-corpus)
- [Known gaps](#known-gaps)
- [Development](#development)
- [License](#license)

## The problem

An LLM agent with tool-calling access is dangerous the moment it reads content it did not originate — a fetched page, an email, a file, another tool's output — because at the token level there is no boundary between *data* and *instructions* once both are in context. This is indirect prompt injection. Prompting the model to "be careful" doesn't fix it; enforcement has to sit at the boundary where the model's decisions become real side effects: the tool call.

Most naive defenses try to track *content* — does this argument contain text from that untrusted source? That approach is trivially defeated by "please summarize this page, then act on the summary": the paraphrase shares no literal substring with the source, so content-matching finds nothing.

This library gates on *exposure* instead of content. The moment untrusted content is read into an agent's context, a scope watermark is raised — atomically, before the model ever sees the result, so it can't be avoided by rewriting. Every privileged call in that scope is then checked against the watermark, not against what its own arguments say. See [`DESIGN.md`](./DESIGN.md) for the full architecture and rationale, and [`GAPS.md`](./GAPS.md) for what this does *not* catch.

## Install

Once the first release is tagged, this will be:

```bash
npm install taint-tracked-tool-broker
```

Until then, install from source:

```bash
git clone https://github.com/NovaVey/Taint-Tracked-Tool-Broker.git
cd Taint-Tracked-Tool-Broker
npm install && npm run build
```

`dist/` is then importable directly (`import { createBroker } from './Taint-Tracked-Tool-Broker/dist/index.js'`), or link it into another project with `npm link`.

**ESM only** — this package ships as native ESM (`"type": "module"`, no CommonJS build). `import` it from an ESM project as normal. A CommonJS project on a Node version without [`require(esm)`](https://nodejs.org/api/modules.html#loading-ecmascript-modules-using-require) support can't `require()` it directly (`ERR_REQUIRE_ESM`) — use a dynamic `await import('taint-tracked-tool-broker')` instead.

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

## Core model

- **A single trust lattice** — `CLEAN < DERIVED_UNTRUSTED < RAW_UNTRUSTED` — used for both the scope watermark and individual fingerprint records.
- **The scope watermark is the safety boundary.** It rises the instant a source tool (`isSource: true`) returns, before the model reads the result. It is monotonic; only `broker.declassify()` lowers it, and only as an explicit, audited action.
- **Sinks are classified `EXEC` / `MUTATE` / `EXFIL` / `NONE`** by declared capability (`exec:shell`, `write:fs`, `net:email`, ...). `EXEC` is hard-gated by watermark level alone — it needs no private data to be catastrophic. `EXFIL`/`MUTATE` calls while untrusted content is live always require at least approval; a `readsPrivateData` tool having been called this scope *escalates* that to a hard block (the "lethal trifecta"), it never *gates* on its own.
- **The fingerprint registry is secondary.** Exact hash + simhash + word-shingle overlap gives precise "this argument literally contains text from source X" attribution when a literal or near-literal chain survives — but it can only ever *tighten* a policy verdict, never loosen one, and it is never the sole basis for allowing a call. Fuzzy lookup is indexed (LSH-banded simhash + a shingle inverted index), not a linear scan, and an optional `maxEntries` bounds memory for long-running sessions.
- **`broker.summarize()`** is the sanctioned way to condense/paraphrase untrusted content before it re-enters the model's context without staying at `RAW_UNTRUSTED`: a capability-less LLM call you supply, whose output the broker itself (not the LLM) registers as `DERIVED_UNTRUSTED` — never all the way back to clean.
- **`broker.declarePlan(steps)`** is an optional, additive strict mode (DESIGN.md §11): commit to the exact sequence of privileged tool calls *before* any untrusted read, and any later privileged call that doesn't match the next committed step is rejected — on top of, never instead of, the normal policy check above.
- **State can cross a process boundary.** `createBroker({ initialWatermark, registry })` plus `serializeBrokerState()`/`restoreBrokerState()` let one broker's watermark and registry be exported (JSON-safe) and used to seed another — for a sub-agent, a worker, or a resumed session. Not automatic; an integrator still has to call these and pass the result along.

Read [`DESIGN.md`](./DESIGN.md) for why each of these choices was made, including the soundness gap the design's own judge-panel process found and closed before this was implemented.

## Examples

Runnable, offline (no API key, no real network calls — everything is mocked except the broker itself) walkthroughs in [`examples/`](./examples):

| Script | What it shows |
|---|---|
| `npm run example` | The core model end to end: verbatim injection, paraphrase bypass, the sanctioned `summarize()` path. |
| `npm run example:mcp` | MCP protocol surfaces (`tools/call`, `tools/list`) and a tool-description rug-pull guard (GAPS.md #1). |
| `npm run example:tool-loop` | A full Anthropic Messages API-style tool loop — a blocked call recovering gracefully, `REQUIRE_APPROVAL` suspending the loop, and `startNewTurn()`'s one correct call site under `resetScope:'turn'`. |
| `npm run example:langchain` | Wiring `broker.wrap()` behind LangChain.js's `tool()`/`Runnable.invoke()` shape. |
| `npm run example:vercel-ai` | The same pattern behind the Vercel AI SDK's `tool()`/`execute()` shape. |
| `npm run example:openai-agents` | The same pattern behind the OpenAI Agents SDK's `tool()`/`execute()` shape, exercising the `REQUIRE_APPROVAL` path via `createDeferredApprovalChannel()`. |

The three framework examples don't depend on the real `langchain`/`ai`/`@openai/agents` packages — each uses a small structural stand-in for that framework's real tool-definition shape, since the integration point (a `name`/`description`/schema object with an async execute function) is what matters, not fidelity to a fast-moving package's exact current types. Every framework's real dispatch loop calls that function the same way once `broker.wrap()` has interposed it.

## Injection corpus

```bash
npm run corpus
```

Runs [`corpus/cases.ts`](./corpus/cases.ts): 15 cases across 12 attack classes — direct verbatim injection, light reformatting, inline paraphrase (the "summarize, then act" bypass), boolean decision-laundering, the sanctioned quarantine path, lethal-trifecta escalation, translation/encoding evasion, plan-freeze catching an unplanned privileged action, `resetScope: 'turn-decay'` narrowing (not closing) the cross-turn gap, and two *true, asserted* known gaps (untracked context-injection channels, and cross-turn latent influence under `resetScope: 'turn'`). The corpus is also run under `npm test`, so a change that silently narrows coverage — or silently starts overclaiming it — fails CI, not just a manual read of `GAPS.md`.

## Known gaps

This library does not achieve information-flow-control soundness — it achieves a conservative, structural approximation with named, honest limits. It gates on "was untrusted content live in this scope's tracked context," which is a sound proxy for "did the model act on it," not proof of causal influence. See [`GAPS.md`](./GAPS.md) for the full list, including the two true known gaps the corpus asserts rather than papers over.

Every gate rests on how you declare your own tools (`isSource`, `trusted`, `capabilities`, `readsPrivateData`) — get one wrong and that tool isn't gated incorrectly, it isn't gated at all, silently. See [`docs/classifying-tools.md`](./docs/classifying-tools.md) for a checklist and worked examples for the less-obvious cases.

Found a way past the gating logic that isn't already in that list? See [`SECURITY.md`](./SECURITY.md).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest (unit tests + the injection corpus)
npm run corpus      # just the corpus, with a readable pass/fail table
npm run build       # emit dist/
npm run bench       # structuredClone vs jsonSafeClone args-cloning benchmark
npm run bench:minhash  # why fixed-size MinHash sketches were investigated and NOT shipped for the registry (DESIGN.md)
```

See [`CHANGELOG.md`](./CHANGELOG.md) for what's changed.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
