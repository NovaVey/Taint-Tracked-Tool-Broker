# Redacting audit args (GAPS.md #24)

`AuditEvent.call.args` is the tool call's real, cloned argument object — for a gated call, `BLOCK`ed or not, exactly what the tool was actually invoked with, no redaction, no truncation, unless you configure one. Whatever your registered tools' arguments actually carry — a credential, an API key, a chunk of a private document a `readsPrivateData` tool just fetched — reaches your configured `BrokerOptions.auditSink` exactly as it stood at call time. This isn't a bug: an audit trail that silently hid argument content wouldn't be much of an audit trail. But it means the same considerations apply here that already apply to logging any raw request payload — `auditSink` may write to a place with different access controls, retention policy, or export/backup exposure than "the process running the model." `createBroker({ redactAuditArgs })` is the seam this library provides so you can bring your own answer to "what should NOT be written there verbatim." It does not ship one for you, for the same reason `isSource`/`trusted`/`readsPrivateData`/`destinationKeys` don't classify your tools for you (see `docs/classifying-tools.md`): this library cannot inspect what your tool's arguments actually mean, only enforce whatever you declare.

## How it's applied

`redactAuditArgs(call, taint)` is called for `call.args` ONLY, on every `AuditEvent` this library constructs — a gated call's decision, the `NONE`-sinkClass escalator/advisory events, and every administrative event (`declassify()`, `startNewTurn()`, `markContextExposure()`, `broker.summarize()`) — immediately before it reaches `auditSink.record()`. Nothing else on the event (`verdict`, `taint`, `at`, `executed`, `requestedAt`) is touched, and nothing about the actual dispatch is touched either: `policy()`, `approvalChannel.requestApproval()`, and `execute()` all still see the real, unredacted arguments — this hook affects only what gets written to your audit sink, never what the broker itself does with a call. Leave it unset and `call.args` reaches your sink exactly as it does today; this is purely opt-in.

```ts
const broker = createBroker({
  auditSink: myDurableAuditSink,
  redactAuditArgs(call, taint) {
    // return whatever should actually be written to the sink in place of call.args
    return call.args;
  },
});
```

The function receives the same `call`/`taint` pair the resulting `AuditEvent` carries — at the point it runs, `call.args` is still the original, unredacted value, so you can inspect it to decide what to keep. Whatever you return replaces `call.args` on the recorded event; it does not need to be shaped anything like the original (a string summary, a fixed placeholder, a partially-masked copy of the same object are all fine — `auditSink.record()` only ever reads what you hand it).

## Pattern 1: redact by `taint.sinkClass`

The coarsest, cheapest pattern: some sink classes are more likely to carry something you don't want written to a log than others. An `EXEC` call's `cmd` argument can easily embed a secret via shell expansion (`$API_KEY`, a `-H "Authorization: Bearer ..."` flag); a `NONE`-sinkClass source/administrative event usually carries nothing worth hiding at all (an already-blocked call's reason string, a turn-reset's empty `{}`).

```ts
redactAuditArgs(call, taint) {
  if (taint.sinkClass === 'NONE') return call.args; // administrative/source events: nothing sink-shaped to hide
  if (taint.sinkClass === 'EXEC') return '[redacted: EXEC sink args may embed shell-expanded secrets]';
  return call.args; // MUTATE / EXFIL: pass through, or apply a finer-grained pattern below
}
```

This is a blunt instrument — it throws away the ENTIRE argument object for every matching call, including the ordinary, non-sensitive ones — but it costs nothing to reason about, and for a sink class where you genuinely can't predict what a secret might look like (arbitrary shell commands are the sharpest example: a secret can appear anywhere in the string, not under a predictable key), an all-or-nothing redaction is often the only one that's actually safe.

## Pattern 2: redact by `TaintContext.privateDataSeen`

`taint.privateDataSeen` (§3.2's lethal-trifecta escalator) is true once ANY `readsPrivateData` tool has been called this scope — independent of whether THIS particular call's own arguments touch that data directly. Once it's true, a later call's arguments are a real candidate for carrying private content the model copied forward (verbatim or lightly transformed) from that earlier read, even for a tool that itself declares no `readsPrivateData` capability of its own.

```ts
const SENSITIVE_KEY_PATTERN = /(password|secret|token|key|credential|auth)/i;

function maskSensitiveLeaves(value: unknown, path = ''): unknown {
  if (Array.isArray(value)) return value.map((v, i) => maskSensitiveLeaves(v, `${path}[${i}]`));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SENSITIVE_KEY_PATTERN.test(k) ? '[redacted]' : maskSensitiveLeaves(v, `${path}.${k}`);
    }
    return out;
  }
  return value;
}

redactAuditArgs(call, taint) {
  // Once private data has been read this scope, later calls' arguments are
  // a real candidate for carrying some of it forward — mask anything
  // shaped like a credential/secret field, leave the rest for context.
  return taint.privateDataSeen ? maskSensitiveLeaves(call.args) : call.args;
}
```

This is finer-grained than Pattern 1 — it keeps most of the call's shape intact (useful for later debugging/incident review) while masking the fields most likely to be the actual secret — at the cost of only catching what a key-name heuristic can recognize; a secret sitting in an oddly-named field, or embedded mid-string rather than as a whole leaf value, slips through. Combine it with Pattern 1 for `EXEC` calls specifically, where "the secret could be anywhere in the string" is the realistic threat model key-matching alone can't cover.

## Pattern 3: a simple key-denylist

The most predictable pattern, and often the right default: a fixed list of argument-key names you already know are sensitive for your own tool surface (an `apiKey` field on an authenticated-API tool, a `password` field on an account-management tool), applied uniformly regardless of sink class or scope state.

```ts
const DENYLISTED_KEYS = new Set(['password', 'apiKey', 'api_key', 'token', 'secret', 'authorization']);

function redactDenylistedKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactDenylistedKeys);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = DENYLISTED_KEYS.has(k) ? '[redacted]' : redactDenylistedKeys(v);
    }
    return out;
  }
  return value;
}

const broker = createBroker({
  auditSink: myDurableAuditSink,
  redactAuditArgs: (call) => redactDenylistedKeys(call.args),
});
```

Unlike Patterns 1 and 2, this one doesn't need `taint` at all — it's a fixed transform of `call.args`, independent of sink class or scope state, which makes it easy to unit-test in isolation and easy to keep in sync as you add tools: whenever a new tool gains an argument that carries something sensitive, add its key name here.

## Combining patterns

Nothing stops you from composing all three — `taint.sinkClass`/`taint.privateDataSeen` to decide HOW aggressively to redact, a key-denylist as the actual masking mechanism:

```ts
redactAuditArgs(call, taint) {
  if (taint.sinkClass === 'EXEC') {
    return '[redacted: EXEC sink]'; // can't trust key-based masking for arbitrary shell text
  }
  return redactDenylistedKeys(call.args); // Pattern 3, applied to everything else
}
```

## What this doesn't do for you

- **It never changes what the broker actually decides or executes.** `policy()`, `approvalChannel`, and `tool.execute()` all still receive the real, unredacted `argsSnapshot` — `redactAuditArgs` only ever touches what gets written to `auditSink`.
- **It doesn't touch `err.taint`.** A blocked call's `ToolCallBlockedError.taint` (GAPS.md #21) is populated independently of the audit path and is not passed through `redactAuditArgs` — if your own `catch` blocks log that error's `taint`/`call` directly rather than reading it back off `AuditSink`, you're responsible for redacting there yourself, the same way you would for any other error object your own code logs.
- **It can't redact what Layer 2 already summarized.** `taint.matchedRecords[].record.fingerprint` never carries raw plaintext to begin with (only `exactHash`/`simhash`/`shingleHashes` — see `TaintRegistry`'s own doc comment, `src/types.ts`), so there's nothing there for this hook to need to mask; `matchedRecords[].argPath` names WHERE a match was found (a dotted/bracketed path into the argument tree), not the matched content itself.
- **It isn't a PII/secret detector.** None of the three patterns above — or any combination of them — inspects argument VALUES for secret-shaped content the way a dedicated data-loss-prevention tool would; they all work by argument SHAPE (which sink class, which key name, whether private data was read this scope). A secret sitting in an unexpected field, under an unexpected key, in a call this hook wasn't tuned for, still reaches your sink unredacted. Treat this the same way `docs/classifying-tools.md`'s own closing advice treats tool classification: default toward the safer misclassification (redact more than you strictly need to) when a call's actual argument shape is genuinely unclear to you.
