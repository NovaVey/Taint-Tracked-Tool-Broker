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
