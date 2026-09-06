# `vectors.json` — machine-readable conformance vectors

This is `PROTOCOL.md`'s specification made mechanically checkable: the same
injection corpus this repository's own test suite (`npm test`/`npm run
corpus`) runs, as plain JSON with no dependency on Node, TypeScript, or this
repository's own test harness. See `PROTOCOL.md` §6.1 for the full
rationale. This file documents the JSON shape field by field, for anyone
writing a conformance runner against it in another language.

`corpus/cases.ts` and `corpus/fixtures.ts` (this repository's own loaders)
are the canonical, tested example of consuming this file — read them
alongside this document if anything below is ambiguous.

## Top level

```jsonc
{
  "schemaVersion": 1,       // this file's own format version — bump on any breaking shape change
  "protocolVersion": "1.0", // the PROTOCOL.md version this vector set was authored against
  "trueGapIds": [...],      // case ids asserting a documented MISS (GAPS.md), not a catch — see below
  "tools": [...],           // the declarative tool catalog every case's "tool" fields reference by name
  "cases": [...]            // the corpus itself
}
```

## `tools[]` — the declarative tool catalog

Each entry is a `ToolExecutor` declaration (PROTOCOL.md §2, §5) with no
executable code at all:

```jsonc
{
  "name": "fetch_url",           // referenced by name from cases' setup/actions/quarantine.toolName
  "capabilities": [],            // SinkCapability[] — empty means sinkClass NONE (§2); non-empty means a sink
  "isSource": true,              // optional — does a successful call raise the watermark?
  "trusted": true,                // optional — exempts an isSource tool from raising the watermark AND fingerprinting (§4.1)
  "readsPrivateData": ["credentials"] // optional — string[] of sensitivity categories (§3.2's lethal-trifecta escalator)
}
```

A conformance runner synthesizes each tool's actual behavior generically,
since no case ever asserts on a tool's return VALUE — only on the broker's
resulting verdict/watermark/audit trail:

- **A source** (`isSource: true`) returns the call's own `args.mockResult`
  field when present, else `args` itself, completely unmodified — this is
  how a case controls exactly what content a "fetch" "found," deterministically
  and offline, without a real network/filesystem call.
- **A sink** (or a `capabilities: []` non-source, non-sink control tool)
  returns anything at all — no case ever inspects it.

## `cases[]` — the corpus

```jsonc
{
  "id": "direct-verbatim-shell",       // stable, unique identifier
  "description": "...",                 // human-readable summary of the attack/scenario
  "attackClass": "direct-instruction-verbatim", // one of PROTOCOL.md's named attack classes
  "resetScope": "session",              // optional, default "session" — see PROTOCOL.md's ResetScope
  "turnDecayWindow": 2,                  // optional — required (and only meaningful) when resetScope is "turn-decay"
  "allowedOutboundHosts": ["approved.example"], // optional — opts this case into the egress-allowlist check
  "plan": [{ "toolName": "write_file" }], // optional — opts this case into plan-freeze strict mode (declared before `setup`)
  "setup": [                              // ordered ops executed BEFORE any turn boundary/plan check, to seed taint state
    { "tool": "fetch_url", "args": { "url": "https://evil.example", "mockResult": "..." } }
  ],
  "turnBoundaryAfterSetup": true,        // optional — simulate one turn boundary (startNewTurn()) right after `setup`
  "quarantine": {                        // optional — models the sanctioned summarize()/quarantine path
    "rawText": "...",                     // text registered as a genuine RAW_UNTRUSTED source record
    "quarantineText": "...",              // optional — text actually passed to summarize(), if different from rawText (provenance-spoof modeling)
    "toolName": "fetch_url",              // optional — the tool name attributed as this record's source
    "schema": { "kind": "reviewed-with-length", "lengthField": "reviewedLength" }, // optional — see "Quarantine schema kinds" below
    "instructions": "..."                 // optional — QuarantineOpts.instructions passed to summarize()
  },
  "actions": [                            // ordered ops executed after setup/quarantine; the LAST one is the sink call under test
    { "tool": "shell_exec", "args": { "cmd": "..." } }
  ],
  "expected": {
    "decision": "QUARANTINE_AND_RETRY",        // the final action's expected PolicyDecision.action
    "expectedFinalWatermarkLevel": "RAW_UNTRUSTED", // optional — the scope watermark's expected level once every op has run
    "expectedPrivateDataSeen": false,          // optional — the scope watermark's expected privateDataSeen flag
    "minMatchType": "exact",                    // optional, Layer-2-only — see "Attribution strength" below
    "notes": "..."                              // human-readable rationale for this expectation
  }
}
```

### Attribution strength (`expected.minMatchType`)

PROTOCOL.md §5 makes Layer 2 (content-addressed fingerprint matching)
explicitly OPTIONAL — a conformant implementation may ship Layer 0 (the
watermark) alone. `minMatchType`, when present, names the MINIMUM match
confidence a Layer-2-equipped implementation's own attribution should
reach for this case's final action (`'exact'` > `'shingle'`/`'simhash'` >
`'wrapper'` > `'quarantine-derived'` > `'none'`) — it is never a
requirement a Layer-0-only implementation must satisfy. `expected.decision`
and the two watermark fields are the only REQUIRED conformance checks;
`minMatchType`'s absence on a case means this vector set makes no
attribution-strength claim for it either way.

### Quarantine schema kinds

`QuarantineOpts.schema` (PROTOCOL.md §3) is a `{ parse(x): S }` function in
the reference implementation — the one piece of a case this JSON format
cannot represent directly. `quarantine.schema.kind` names a small,
versioned transform instead; a conformance runner in any language
reconstructs the equivalent extraction from the kind name and its
parameters. Currently one kind exists:

- **`'reviewed-with-length'`** (`{ lengthField: string }`) — the extraction
  produces `{ status: 'reviewed', [lengthField]: input.length }` given the
  quarantined input text. Used across this vector set's four
  schema-bearing cases (two variants, differing only in the length field's
  name — `'reviewedLength'` or `'length'`).

A future case needing a genuinely different extraction shape should add a
new named kind here (and to `corpus/cases.ts`'s own `SCHEMA_KINDS` map),
not silently overload this one to mean something else.

### `trueGapIds`

Case ids asserting a TRUE, documented MISS (GAPS.md #1 and #2 as of this
writing) — the corpus proves the reference implementation is HONEST about
these, not that it catches them. A conformance runner checking "does my
implementation match the reference's behavior" should expect these cases'
`expected.decision` to be the PERMISSIVE outcome (e.g. `ALLOW`), not treat
a passing run against them as a security claim.
