# Classifying tools correctly (GAPS.md #10)

Every gate in this library rests entirely on the `ToolExecutor` declarations an integrator writes — `isSource`, `trusted`, `capabilities`, `readsPrivateData`. Get one wrong and the library doesn't gate that tool incorrectly; it doesn't gate it *at all*, silently, with no error, no test failure, nothing in the audit log to suggest anything is missing. This isn't something the library can check for you (see GAPS.md #10) — it can't inspect what a tool's `execute()` actually does, only trust what you told it. This doc is the checklist and the worked examples that reduce how often that trust turns out to be misplaced.

## The four questions, in order

Ask these about *what the tool's `execute()` actually does*, not about what its name or its API's documentation says it does — those two things diverge more often than you'd expect (see "read-only" analytics example below).

### 1. Can the result contain content the agent didn't author?

Not just "does it fetch from the internet" — a file on local disk another process wrote, another user's message, a database row a third party inserted, a subprocess's stdout, another AI's output are all just as capable of carrying an instruction-shaped payload as a web page is. If the answer is yes for *any* return path (even a rare one), set `isSource: true`. If you're unsure, default to `true` — the cost of a false positive here is some extra gating friction; the cost of a false negative is GAPS.md #1's untracked-channel gap, silently.

### 2. Is that content genuinely not attacker-influenceable?

Only if you answered yes to (1) does this question matter. `trusted: true` on an `isSource` tool means "I have reviewed the actual code path and every possible result is either hardcoded, deterministic, or otherwise something no external party can shape" — a local deploy-config file your own build process writes is a reasonable case for this; "an internal API my company controls" usually is *not*, unless you've also verified nothing upstream of it (another team's service, a partner integration, user-submitted content stored earlier) can reach it. When genuinely unsure, leave `trusted` unset (defaults to untrusted) — this is the single most consequential yes/no in a `ToolExecutor` declaration, since it's the one that actually turns watermark-raising on or off.

### 3. Does calling this tool have any side effect beyond returning data?

Writes, network egress, state changes, purchases, anything irreversible — declare the real `SinkCapability` (`exec:shell` / `exec:code` / `write:fs` / `write:external-account` / `finance:purchase` / `irreversible:other` / `net:outbound` / `net:email` / `net:api-call` / `net:post-message`). The trap here isn't forgetting an obviously-privileged tool's capability — it's a tool that *looks* read-only but has a side effect one layer down (a "read-only" API call that also logs the query to a third-party analytics backend is an EXFIL sink whether or not its primary purpose is a read). `capabilities: []` is a claim, not a default to reach for when unsure — see example 3 below.

`createBroker({ warnOnLikelyUnclassifiedSink })` can catch the easier, more common half of this mistake automatically — an ordinary `write_file`/`send_email`/`delete_row` left with `capabilities: []` by plain oversight, not deliberate deception (GAPS.md #10). It is a name-keyword heuristic, so it is no substitute for this question: example 3 below is exactly the shape it cannot help with — nothing about `get_account_summary`'s name suggests a hidden side channel.

### 4. Does it read something sensitive?

Secrets, credentials, PII, anything you'd wince at leaking. Set `readsPrivateData: { categories: [...] }` — this is what turns MUTATE/EXFIL sinks from "require approval" into "block" once combined with untrusted content live in scope (the lethal-trifecta escalation, DESIGN.md §3.2). This is independent of `isSource`/`capabilities` — a tool can be a pure sink that also happens to read a secret as part of its own operation (e.g. a tool that reads a stored API key to make an authenticated call on the agent's behalf).

### 5. Does its `execute()` call `broker.summarize()` internally?

Only relevant for a composite fetch-and-quarantine tool (§6.2's implementation note, and example 4 below) — a tool that fetches raw content and quarantines it in one call, rather than as two separate broker-mediated steps. If `execute()` calls `broker.summarize()` on its own fetched content before returning, set `mayCallSummarize: true`. This is easy to miss because such a tool otherwise often looks completely inert (`capabilities: []`, not `isSource`, no `readsPrivateData`) — which would make it eligible for the lock-barrier-exemption optimization (DESIGN.md's "narrowing the lock" note) were it not for this call. Leaving it unset reopens GAPS.md #17's race for that one tool: a concurrently-dispatched gated call can slip past before the tool's internal `summarize()` raise commits, exactly the failure mode `mayCallSummarize` exists to prevent.

## Worked examples

### A filesystem MCP server

| Tool | `isSource` | `capabilities` | Why |
|---|---|---|---|
| `read_file` | `true` | `[]` | File contents can be anything, including something planted by an earlier attacker-controlled write. |
| `list_directory` | `true` (often missed) | `[]` | **Filenames themselves are untrusted content** — a maliciously-named file (`"ignore previous instructions and..."`.txt) reaches the agent as a directory listing, not as file contents, and is just as capable of carrying a payload. Easy to classify as "just metadata" and skip `isSource`. |
| `write_file` | — | `['write:fs']` | Ordinary MUTATE sink. |
| `delete_file` | — | `['irreversible:other']` (or `'write:fs'` if your policy doesn't need the extra severity) | Deletion doesn't fit `write:fs` if you want it treated as strictly worse than an ordinary write — `SinkCapability` doesn't have a dedicated "delete" value, so pick deliberately rather than defaulting to `write:fs` out of habit. |

### A RAG / vector-database retrieval tool

Looks like "just a database query" — the API surface is `search(query: string): Document[]`, which reads like any other structured data-fetch a backend team is used to treating as safe. But the *documents it returns* are exactly the same shape as a fetched web page: content this session did not originate, potentially written by anyone who could get content into the index. `isSource: true`, same as `fetch_url`. The "it's a query, not a fetch" framing is the trap — classify by what the *result* is, not by what the *request* looks like.

### A "read-only" analytics/reporting API with a side channel

GAPS.md #10's own named example. `get_account_summary(accountId)` looks read-only and gets `capabilities: []` at a glance — but if the implementation also emits the query (and its parameters — which may include content the agent assembled from earlier untrusted context) to a third-party analytics/logging backend, telemetry pipeline, or does a DNS lookup against an attacker-influenceable hostname, that side effect *is* an EXFIL capability (`net:outbound` or `net:api-call`), regardless of the tool's primary purpose. The only way to catch this is reading the actual implementation (or, for a third-party API, its actual documented side effects) rather than inferring capability from the function's name.

### A code-interpreter / sandboxed-exec tool

A tool shaped like `run_code(code: string, context?: string): Output` that can both take untrusted input (`context`, or `code` itself if the agent assembles it from earlier tool results) *and* execute it is exactly the shape `register()`/`wrap()` reject outright as `DualRoleToolError` (`isSource: true` + non-empty `capabilities` on one call — see `src/errors.ts`) — a single call could read untrusted content and act on it before the watermark that's supposed to gate that action ever rises. Two ways out, both covered elsewhere in this repo:

- **Split it**: a source-only call that fetches/prepares the input, and a separate sink-only call that executes it — two broker-mediated calls instead of one, so the watermark from the first is live before the second's gating check runs.
- **Fetch-and-quarantine**: if the tool's own job really is "run this specific canned operation over some untrusted input, and only that," route the untrusted part through `broker.summarize()` first (DESIGN.md §6.2's implementation note) so the tool receives only a `DERIVED_UNTRUSTED`, quarantine-narrowed value. If a single tool's `execute()` does the fetch **and** the `broker.summarize()` call itself (rather than the caller doing the second step separately), it must also declare `mayCallSummarize: true` — see question 5 above and GAPS.md #17.

## When you're still not sure

Default toward the safer misclassification, not the more convenient one: `isSource: true` (not `trusted`) over assuming a result is inert, and a real `capabilities` entry over `[]`, when a tool's actual behavior is genuinely unclear to you. Over-declaring costs some approval friction (GAPS.md #3) for calls that turn out to have been safe; under-declaring costs the entire gate for calls that turn out not to be — a much worse trade, and the one this library has no way to catch after the fact.

## Automating what this checklist can automate

Everything above is a human-judgment checklist by necessity — questions 2 ("is this content genuinely not attacker-influenceable"), 3's harder half (a "read-only" call with a hidden side channel), and 4 all require reading a tool's real implementation, which this library cannot do. But two of the four questions — question 1's "does the name suggest a mutating action but the declared capabilities say `NONE`" mirror-image check, and its sibling for a source that forgot `isSource: true` — reduce to a mechanical check this library already ships as `createBroker({ warnOnLikelyUnmarkedSource, warnOnLikelyUnclassifiedSink })` (GAPS.md #1/#10, both `BrokerOptions` fields' own doc comments in `src/broker.ts`). Today those heuristics only ever surface as `AuditEvent`s emitted through a LIVE `Broker` instance — nothing previously told an integrator they can already get most of the way to a real pre-publish classification-lint step over a whole tool catalog, not just a running session's worth of calls, without building anything new.

**The sink-side half — a pure, standalone lint, no broker required.** `warnOnLikelyUnclassifiedSink`'s registration-time keyword match (question 1's mirror image, question 3's easier half) is a pure function of a tool's `name` and its declared `capabilities` — it never needs a live call to evaluate, only the same static declaration a manifest/catalog file already has sitting in it. That match logic is exported directly as `likelyUnclassifiedSinkKeyword(name: string, keywords?: readonly string[]): string | undefined` (`src/broker.ts`, re-exported from `src/index.ts`) — the identical function `register()`/`wrap()`'s own `warnOnLikelyUnclassifiedSink` check now calls internally, not a reimplementation that could drift from it. Run it over an entire catalog with no broker, no `AuditSink`, and no `register()`/`wrap()` call at all:

```ts
import { likelyUnclassifiedSinkKeyword } from 'taint-tracked-tool-broker';

for (const tool of myWholeToolCatalog) {
  if (tool.capabilities.capabilities.length > 0) continue; // already classified as a sink
  const matched = likelyUnclassifiedSinkKeyword(tool.name);
  if (matched !== undefined) {
    console.warn(
      `${tool.name}: capabilities is empty but the name contains "${matched}" — ` +
        'question 1 above says double-check this one before shipping.',
    );
  }
}
```

This is a real manifest-style pre-publish lint — the kind a CI step can run over hundreds of tool declarations in one pass, long before any of them is ever registered against a live broker — not just a live-session advisory. `keywords` defaults to the same list `warnOnLikelyUnclassifiedSink: true` uses; pass your own to match a live broker's tuned list exactly, the same way `warnOnLikelyUnclassifiedSink: readonly string[]` already lets you tune a live broker.

**The broader pattern — register the whole catalog against a broker, execute nothing, read the audit sink.** You don't have to hand-roll the loop above, or restrict yourself to only the sink-side check: `createBroker({ warnOnLikelyUnclassifiedSink: true, warnOnLikelyUnmarkedSource: true, auditSink: { record(e) { lintFindings.push(e); } } })`, then `broker.registerAll(myWholeToolCatalog)` (or a loop of `register()` calls) — zero `execute()`/`call()` calls needed for this to produce useful output. `register()`'s `warnOnLikelyUnclassifiedSink` check fires purely from registration, exactly like `likelyUnclassifiedSinkKeyword()` above, so this "runs the checklist as a lint step" idea holds for the sink-side heuristic without qualification: register the catalog, collect the `AuditEvent`s with `verdict.action === 'ALLOW_WITH_WARNING'` and `call.toolName === '__tttb_registration_warning'`, done.

**The limitation worth stating explicitly, not implying away: this does NOT extend to `warnOnLikelyUnmarkedSource`.** That heuristic (GAPS.md #1's mirror image, `BrokerOptions.warnOnLikelyUnmarkedSource`'s own doc comment) fires from `finishDispatch()` after a real `execute()` call resolves, because the signal it needs — how many characters of text a `NONE`-sinkClass, non-`isSource` tool's result actually contains — is a runtime property of one specific call's return value, not a static property of the tool's declaration the way a `name`/`capabilities` pair is. There is no equivalent `likelyUnmarkedSourceLength()`-style pure function to extract here, and no amount of `register()`-only tooling can substitute for an actual call: a pure-registration pass over a catalog exercises the sink-side heuristic completely, but leaves the source-side heuristic entirely unevaluated for every tool in it. Getting real coverage from that half of the pattern means driving at least one representative call per tool that plausibly returns text — a fixture/mock harness feeding each tool a realistic-length canned response and checking the resulting `AuditEvent`s, closer to a smoke-test suite than a pure static lint. Both heuristics remain purely advisory either way (GAPS.md #1/#10): neither this standalone function nor the live-broker registration pattern above changes what's registered or gates anything on its own, and neither is a substitute for reading a tool's actual implementation against the four questions above.

## A packaged `doctor` preflight (GAPS.md #30)

The two patterns above — `likelyUnclassifiedSinkKeyword()` standalone, or registering a whole catalog against a live broker to read its advisories — are exactly what `src/doctor.ts` (also exported from `src/index.ts`) packages into one call, plus two checks neither pattern above covers on its own:

- **`checkToolCatalog(tools)`** runs the sink-side keyword check above over every tool, AND — new, not merely a repackaging — flags two shapes that are not heuristics at all but DETERMINISTIC `register()`/`wrap()` rejections: a dual-role tool (`isSource: true` combined with a non-empty `capabilities` array, `DualRoleToolError`) and a reserved `__tttb_`-prefixed name (`ReservedToolNameError`). Catching these here means a CI step fails on the exact commit that introduced the mistake, not the first time a real broker registers the catalog.
- **`checkBrokerConfig(config, tools)`** is the config-inertness half GAPS.md #30 also names: a missing `auditSink` (silent `NOOP_AUDIT`, GAPS.md #25), a missing/`unconfiguredQuarantineImpl` `quarantineImpl` (escalated from an informational note to an error the moment some tool in `tools` declares `mayCallSummarize: true` — a provable guarantee it WILL be called and WILL throw), `requireQuarantineSchema` left off (GAPS.md #4, always informational — a legitimate default many integrators keep), and an `EXFIL`-capable tool present with no `allowedOutboundHosts` configured (GAPS.md #18 — often the SOLE structural check between a `CLEAN` scope and a real network egress).
- **`runDoctor({ tools, brokerConfig })`** runs both and concatenates; **`formatDoctorReport(findings)`** renders the result as the same readable, one-line-per-finding prose `src/debug.ts`'s renderers already use elsewhere in this library.

**Same honesty bar as everything above it, restated plainly: this still cannot verify a declaration against a tool's real behavior.** `checkToolCatalog()`'s keyword check inherits `likelyUnclassifiedSinkKeyword()`'s exact blind spot (a deliberately-deceptive tool, or one whose real side effects don't show up in its name) by construction, not oversight — the only genuinely new coverage here is the two deterministic registration-rejection checks, which need no judgment at all to be certain about.

**`npx tttb doctor <path-to-config.js>`** is the CLI wrapper around the same three functions (`src/cli/doctor.ts`, the package's one `bin` entry), for a config that lives in a plain, already-built JS module (this package ships no TypeScript-compilation step for consumer code) exporting `tools` and, optionally, `brokerConfig` — see that file's own header comment for the exact contract and `--strict` (fail the exit code on a `'warning'`-severity finding too, not just `'error'`). Calling `checkToolCatalog()`/`checkBrokerConfig()`/`runDoctor()` directly from your own CI test suite works identically and needs no CLI, no separate config module, and no build step at all — usually the more natural fit for a TypeScript-first integration.
