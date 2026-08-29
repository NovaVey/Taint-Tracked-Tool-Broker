# Taint-Tracked Tool Broker

[![CI](https://github.com/NovaVey/Taint-Tracked-Tool-Broker/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaVey/Taint-Tracked-Tool-Broker/actions/workflows/ci.yml)

Provenance labeling for agent inputs, enforced at the tool-call boundary. Blocks untrusted data from reaching shell, filesystem, and network sinks — including when it arrives paraphrased, translated, re-encoded, or laundered through a boolean decision instead of copied verbatim. Ships with an injection corpus and a published list of known gaps.

## The problem

An LLM agent with tool-calling access is dangerous the moment it reads content it did not originate — a fetched page, an email, a file, another tool's output — because at the token level there is no boundary between *data* and *instructions* once both are in context. This is indirect prompt injection. Prompting the model to "be careful" doesn't fix it; enforcement has to sit at the boundary where the model's decisions become real side effects: the tool call.

Most naive defenses try to track *content* — does this argument contain text from that untrusted source? That approach is trivially defeated by "please summarize this page, then act on the summary": the paraphrase shares no literal substring with the source, so content-matching finds nothing.

This library gates on *exposure* instead of content. The moment untrusted content is read into an agent's context, a scope watermark is raised — atomically, before the model ever sees the result, so it can't be avoided by rewriting. Every privileged call in that scope is then checked against the watermark, not against what its own arguments say. See [`DESIGN.md`](./DESIGN.md) for the full architecture and rationale, and [`GAPS.md`](./GAPS.md) for what this does *not* catch.

## Install

```bash
npm install taint-tracked-tool-broker
```

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
- **The fingerprint registry is secondary.** Exact hash + simhash + word-shingle overlap gives precise "this argument literally contains text from source X" attribution when a literal or near-literal chain survives — but it can only ever *tighten* a policy verdict, never loosen one, and it is never the sole basis for allowing a call.
- **`broker.summarize()`** is the sanctioned way to condense/paraphrase untrusted content before it re-enters the model's context without staying at `RAW_UNTRUSTED`: a capability-less LLM call you supply, whose output the broker itself (not the LLM) registers as `DERIVED_UNTRUSTED` — never all the way back to clean.

Read [`DESIGN.md`](./DESIGN.md) for why each of these choices was made, including the soundness gap the design's own judge-panel process found and closed before this was implemented.

## Injection corpus

```bash
npm run corpus
```

Runs [`corpus/cases.ts`](./corpus/cases.ts): 14 cases across 11 attack classes — direct verbatim injection, light reformatting, inline paraphrase (the "summarize, then act" bypass), boolean decision-laundering, the sanctioned quarantine path, lethal-trifecta escalation, translation/encoding evasion, and two *true, asserted* known gaps (untracked context-injection channels, and cross-turn latent influence under `resetScope: 'turn'`). The corpus is also run under `npm test`, so a change that silently narrows coverage — or silently starts overclaiming it — fails CI, not just a manual read of `GAPS.md`.

## Known gaps

This library does not achieve information-flow-control soundness — it achieves a conservative, structural approximation with named, honest limits. It gates on "was untrusted content live in this scope's tracked context," which is a sound proxy for "did the model act on it," not proof of causal influence. See [`GAPS.md`](./GAPS.md) for the full list, including the two true known gaps the corpus asserts rather than papers over.

Found a way past the gating logic that isn't already in that list? See [`SECURITY.md`](./SECURITY.md).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest (unit tests + the injection corpus)
npm run corpus      # just the corpus, with a readable pass/fail table
npm run build        # emit dist/
```

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
