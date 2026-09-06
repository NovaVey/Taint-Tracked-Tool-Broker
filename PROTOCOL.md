# PROTOCOL.md

**PROTOCOL.md v1 — as of `1.0.0` of this repository (2026-08-31).**

## 0. Status and scope

This document specifies the taint-tracked tool-broker **model** — the taint
lattice, the watermark semantics, the sink-class taxonomy, the default
policy decision table, the sanctioned quarantine path, and the audit-event
shape — independent of any programming language or runtime.

It exists so that an independently-maintained implementation in Python, Go,
Rust, or anything else can be built and owned by someone other than this
repository's maintainer, using this document as the reference semantics,
without requiring a second security-critical codebase to be forked and
maintained in lockstep here. See the repository root `README.md` for why:
this project is small and solo-maintained (`SECURITY.md`,
`CONTRIBUTING.md`), and a full port of a security-critical library — rather
than a specification another maintainer can build against — would double
the real attack surface one person has to hold correctly in their head,
not just the line count.

This document is derived from, and normatively subordinate to, `DESIGN.md`
(the full architecture and rationale) and `src/types.ts` (the authoritative
TypeScript type contract, per `DESIGN.md` §8). Where anything here appears
to conflict with either, `src/types.ts` wins for shape and `DESIGN.md` wins
for rationale — this document should be corrected, not treated as
authoritative over them. See §6 (Conformance) for how changes to this file
are expected to be governed going forward.

Everything in this document uses **MUST** / **MUST NOT** / **SHOULD** /
**MAY** in the ordinary informal sense (not a strict RFC 2119 reading):
MUST/MUST NOT mark a property a conformant implementation cannot drop
without losing the soundness property the model exists to provide;
SHOULD/MAY mark a recommendation or an explicitly optional refinement.

---

## 1. The taint level lattice

### 1.1 Levels

A conformant implementation MUST define a single, totally-ordered set of
exactly three taint levels, used consistently everywhere taint is
represented (both the per-scope watermark, §1.2, and any per-record
fingerprint/attribution metadata, if the implementation has one, §5):

```
CLEAN  <  DERIVED_UNTRUSTED  <  RAW_UNTRUSTED
```

| Level | Meaning |
|---|---|
| `CLEAN` | No untrusted content has contributed to the current scope — a developer-declared literal, or a scope immediately after an explicit declassify. |
| `DERIVED_UNTRUSTED` | Content reached the model exclusively through the sanctioned, schema-constrained quarantine path (§3) — bounded and typed, but not clean. |
| `RAW_UNTRUSTED` | Untrusted content is, or has been, live in the scope's tracked context via any other path. |

A single vocabulary for both roles (the scope-level gate and any
record-level attribution) is a deliberate design choice, not an
accident of the reference implementation: using two different trust
enumerations for "what gates a call" and "what a fingerprint match is
labeled" invites exactly the kind of definitional drift a security
boundary cannot afford.

### 1.2 Property 1 — monotonic non-decrease within a scope's lifetime

A scope's watermark level, and its associated `privateDataSeen` flag
(§2.3), MUST be monotonically non-decreasing for the lifetime of that
scope. The only permitted way to lower either is an explicit, out-of-band
**declassify** operation — a deliberate, audited, human-triggered action,
never an implicit side effect of anything else (in particular: approving
one gated call MUST NOT declassify the scope it was approved in).

A scope's lifetime boundary (session-scoped, turn-scoped, or a
bounded decayed variant across N turns with no new exposure) is an
implementation policy choice, not part of this property — what is
required is that **within** whatever lifetime the implementation defines,
level and `privateDataSeen` only ever move upward except via declassify.

### 1.3 Property 2 — the watermark-raise-before-model-reads-result ordering (the load-bearing property)

**This is the single property the entire design is judged on, and it is
the one a conforming implementation must get exactly right.**

When a source of untrusted content (a tool call, an external read, an
injected document — anything that returns content the agent did not
itself originate) produces a result, the implementation MUST:

1. Capture the result.
2. **Raise the active scope's watermark to at least the level that result
   warrants** (ordinarily `RAW_UNTRUSTED` for an untrusted source; see §3
   for the quarantine path's `DERIVED_UNTRUSTED` variant), and record it
   as having happened.
3. **Only then** hand the result back to whatever caller will pass it to
   the model — i.e., only after step 2 has fully completed and is durably
   visible to any later gating check on that scope.

**Why the ordering matters, not just that it exists.** The property this
buys is: *nothing the model does with content after reading it can ever
happen before the raise, because the raise already completed before the
model got the content in the first place.* Paraphrase, translation,
summarization, re-encoding, and decision-laundering (an untrusted value
causing the model to flip an unrelated boolean or pick an enum value, with
zero tainted text appearing anywhere in a later call's arguments) are all
different operations the model can perform *on already-read content* — but
every one of them necessarily happens strictly after the model has read
that content, which is strictly after the raise. A gate that checks the
watermark, rather than trying to recognize the (possibly now
unrecognizable) content itself, is therefore correct regardless of what
transformation the model applies, without needing to detect, anticipate,
or enumerate those transformations at all. This is what makes "please
summarize this page, then act on the summary" a solved case by
construction rather than a pattern that has to be specifically detected.

Get this ordering backwards — raise the watermark only *after* the model
has already been given the result, or make the raise conditional on
something that can be skipped — and the entire gate becomes bypassable by
the exact class of attack this design exists to stop, silently, with the
implementation still reporting that it is enforcing a taint policy.

**This property is not just "step 2 before step 3" for one call in
isolation — it must hold under whatever concurrency model the
implementation actually runs under.** If an implementation permits two
tool calls to be dispatched concurrently (a normal pattern once an agent
harness issues several tool calls from one model turn in parallel), it
MUST ensure that a sink call's gating check can never observe a watermark
state that is older than any source-call raise that, in real invocation
order, happened-before it. Concretely this means either: serializing the
gate-then-execute-then-raise sequence of every call through the scope
(the reference implementation's approach: a single async lock per broker
instance, so no two calls' gating-and-raising steps can interleave), or
some other mechanism that provides the same happens-before guarantee. A
per-call raise that is individually correct but not protected against
interleaving with a concurrently-dispatched sink call's gating check
reopens exactly the race this property exists to close.

A related requirement, for any implementation whose gating decision can
involve an asynchronous wait after the decision is computed (most
concretely: a human-approval step for a `REQUIRE_APPROVAL` verdict) — the
watermark can move *during* that wait. A conformant implementation SHOULD
revalidate the decision against the current watermark immediately before
actually executing the sink call, and treat a decision computed against a
now-stale watermark as invalid rather than trusting it blindly (never
silently re-prompting for a fresh human approval on the same original
request — a decision that requires a new approval and doesn't have one is
conservatively not approved). Holding an exclusive lock across an
unboundedly long human-timescale wait is not required and is a real
availability cost if done anyway; what is required is that the
scope's state cannot silently drift out from under a decision that has
not yet actually taken effect.

---

## 2. Sink classification and the default policy

### 2.1 Sink classes and capability taxonomy

A conformant implementation MUST classify every privileged action a tool
can perform into one of four sink classes, derived from a declared set of
capabilities:

| Sink class | Represents | Example capabilities |
|---|---|---|
| `EXEC` | Arbitrary code or shell execution | `exec:shell`, `exec:code` |
| `MUTATE` | Irreversible/state-changing actions that are not code execution or network egress | `write:fs`, `write:external-account`, `finance:purchase`, `irreversible:other` |
| `EXFIL` | Any capability that can move data to an external destination | `net:outbound`, `net:email`, `net:api-call`, `net:post-message` |
| `NONE` | No privileged capability declared | (empty capability set) |

A tool that declares capabilities spanning more than one class MUST be
classified by its single most severe declared class, in the order
`EXEC > EXFIL > MUTATE > NONE` — `EXEC` is the most severe because
arbitrary code execution needs no private data and no network access to be
catastrophic on its own; a tool able to run code should never be treated
as merely a `MUTATE`-class tool just because it also happens to write a
file.

Separately from sink class, every tool declaration MUST also state whether
a call reads private/sensitive data (an independent boolean-ish flag —
whether it is a sink at all is irrelevant to this flag; a pure read of
credentials with no other capability still sets it). A call to such a tool
sets the scope's `privateDataSeen` flag, regardless of that call's own
taint level.

### 2.2 Default decision matrix

The following table is the **default** policy. A conformant
implementation MAY expose a way to override it (the reference
implementation's `PolicyFn` is a plain, fully-replaceable function), but a
conformant *default* MUST reduce to this table, and any override MUST NOT
be advertised as conformant with this specification if it is strictly
weaker than this table for any cell (an override is free to be strictly
*stricter* than what follows).

The output of a decision is one of four verdicts:

| Verdict | Meaning |
|---|---|
| `ALLOW` | Proceed; logged, no warning. |
| `ALLOW_WITH_WARNING` | Proceed; logged with an explanatory reason. |
| `REQUIRE_APPROVAL` | Do not proceed without an explicit approval (human or otherwise) tied to this specific decision. |
| `BLOCK` | Do not proceed, unconditionally. |

| Scope watermark | `EXEC` sink | `MUTATE` sink | `EXFIL` sink |
|---|---|---|---|
| `RAW_UNTRUSTED` | **BLOCK**, unconditionally | `REQUIRE_APPROVAL`; escalates to `BLOCK` if `privateDataSeen` | `REQUIRE_APPROVAL`, unconditionally; escalates to `BLOCK` if `privateDataSeen` (full trifecta) |
| `DERIVED_UNTRUSTED` | `REQUIRE_APPROVAL`, unconditionally (never gated only by the trifecta) | `REQUIRE_APPROVAL` if `privateDataSeen`, else `ALLOW_WITH_WARNING` | `REQUIRE_APPROVAL` if `privateDataSeen` (full trifecta), else `ALLOW_WITH_WARNING` |
| `CLEAN` | `ALLOW` (logged) | `ALLOW` (logged) | `ALLOW` (logged) |

A `NONE`-class call is never gated by this table at all — it has nothing
in it to gate.

### 2.3 `privateDataSeen` — escalator, never a gate

**This is the specific soundness property this design exists to fix,
relative to prior-art proposals that treat the "lethal trifecta" (private
data + untrusted content + exfiltration capability) as the sole condition
for gating an exfiltration-class call.** `privateDataSeen` MUST only ever
be used as an **escalator** — moving an already-gated verdict
(`REQUIRE_APPROVAL`) to a stricter one (`BLOCK`) — and MUST NOT be used as
a gate on its own, i.e. it must never be the thing that determines
*whether* a call is gated at all.

Concretely: an `EXFIL`-class call made while untrusted content is live in
scope MUST require at least approval **regardless of whether
`privateDataSeen` is true or false**. `privateDataSeen` only decides
whether that requirement escalates further, to an unconditional block.

The failure mode this closes: a design that gates an exfiltration sink
*only* when both untrusted-content exposure *and* a separate private-data
read have both occurred in the same session lets a verbatim malicious
payload ride straight into an exfiltration sink under a bare
`ALLOW_WITH_WARNING` (or no gate at all) whenever no private-data tool
happened to fire first — even though nothing about "was a private-data
tool called" has any bearing on whether the untrusted content itself is
dangerous to exfiltrate. Two prior-art proposals this design was
synthesized from independently reproduced structurally the same bug (one
by making it the *only* gate on exfiltration; the other by extending the
same private-data-contingent trifecta check to cover `exec`/`write`-class
sinks too). The fix in both cases is the same: sink severity is keyed off
capability class **first**; `privateDataSeen` acts strictly as a severity
multiplier on top of a verdict the capability class and watermark level
have already produced, never as a precondition for gating in the first
place.

### 2.4 Layer 2 (attribution) may only ever tighten, never loosen

If an implementation maintains any secondary content-attribution signal
(§5) that can be consulted by policy, that signal MUST only ever be
permitted to floor a verdict at a stricter tier than the table above would
otherwise produce (e.g., a confident content match to a known untrusted
source tightens an `ALLOW` to at least `REQUIRE_APPROVAL`, covering the
case of a scope-lifetime boundary having reset while a content-level tie
to a prior untrusted source still exists) — it MUST NOT be used to loosen
or bypass a verdict the watermark-based table above would otherwise
produce. §5 covers why this signal is optional at all; this subsection is
about what it may do *if present*.

---

## 3. The quarantine / summarize sanctioned path

Gating every privileged call for the remainder of a scope's lifetime the
instant any untrusted content has been read is a real usability cost.
The sanctioned path is the escape valve: a way to legally condense or
extract from untrusted content, buying a lower (but never clean) taint
tier for the result, in exchange for going through a constrained,
broker-controlled process rather than an ordinary model-authored rewrite.

A conformant implementation is not required to offer this path — a
minimal implementation could ship Layer 0 alone (§5) and simply leave a
scope gated at `RAW_UNTRUSTED` for its full lifetime once exposed. But
**if an implementation offers a mechanism serving this role, its
semantics MUST follow this section.**

### 3.1 Input-provenance requirement

The mechanism's input MUST be content the implementation itself already
has on record as having come from a tracked source — not arbitrary text
the agent (or anything else) freely produced or retyped from memory. A
caller MUST supply a reference (an id, a handle — some already-registered
identifier) to previously-captured content, not a bare string the
implementation has no prior record of. This closes the trivial "just
retype the untrusted content as a fresh literal and pass it through
quarantine" loophole: if the mechanism accepted any text, an agent could
launder untrusted content into the quarantine path's lower output tier by
simply re-emitting it as though it were the agent's own clean input.

A conformant implementation SHOULD additionally validate that the
claimed-source content and the input actually presented are
substantively the same content (not merely that *some* identifier was
supplied) — e.g. a length-ratio and content-overlap check against the
referenced record — to resist a caller supplying a valid-but-unrelated
source id alongside fabricated text.

### 3.2 The landing tier — `DERIVED_UNTRUSTED`, never `CLEAN`

A successful run of the mechanism MUST raise the scope's watermark to at
least `DERIVED_UNTRUSTED` — never all the way back down to `CLEAN`. The
mechanism buys a lower tier, not a clean bill of health: its output is
condensed and typed, not proven harmless. Because the watermark is
monotonic (§1.2), if the scope is already at `RAW_UNTRUSTED` when the
mechanism runs, it MUST stay at `RAW_UNTRUSTED` — the mechanism can never
lower an existing higher watermark, only raise a lower one to
`DERIVED_UNTRUSTED`.

The condensation/extraction step itself SHOULD be performed by a
capability-less invocation — no ability to call further privileged
tools, no conversation history beyond the input content and instructions
— and MAY be constrained to a caller-supplied output schema (an
enum, a bounded/typed field set) to shrink both the injection surface of
the output and the space of things an operator has to trust it produced.

### 3.3 Who registers the output, and when

**The broker/library's own code — never the summarizing/extracting model
itself — MUST be the thing that registers the mechanism's output as a new
tracked record and raises the watermark, and it MUST do so
unconditionally after the underlying model call returns, not in response
to anything that model call's output claims.**

This ordering matters against a specific, concrete attack: the content
being quarantined is, by definition, untrusted — so the invocation doing
the condensing is itself operating on attacker-controlled input, and its
output cannot be trusted to accurately self-report its own provenance or
safety. If registration (and the associated watermark raise) depended on
something the summarizing model's own output said — a flag it set, a
field it filled in, a claim it made about its own trustworthiness — a
prompt-injected quarantine call could simply have its output omit or
falsify that claim, causing quarantined content to re-enter the model's
context with no tracked provenance and no watermark raise at all: a
strictly worse outcome than not having the quarantine mechanism in the
first place. Making the registration an unconditional side effect of
broker-controlled code that runs *after* the model call returns —
something the model's own output has no way to suppress or influence —
closes this regardless of what the model call's completion contains.

The newly-registered output SHOULD carry an explicit link back to the
input record(s) it was derived from, so later attribution/audit can trace
a quarantined value back to what it was quarantined from.

### 3.4 Cost, stated plainly

Every large or sensitive result now costs one extra model round trip to
legally condense, and a schema-constrained extraction limits what the
result can say (typed extraction, not free riffing) in exchange for
precise rather than reconstructed provenance at exactly the step where
attribution-by-content-matching is weakest. Skipping the sanctioned path
does not buy a clean result — the scope simply stays at its current tier
and every non-`NONE`-class sink is gated at that stricter level, so the
incentive structure rewards routing through quarantine rather than
punishing it as pure extra friction with no payoff.

---

## 4. Audit events

### 4.1 Minimum viable shape

A conformant implementation's audit facility MUST be able to represent, at
minimum, for every recorded event:

| Field | Meaning |
|---|---|
| verdict | The policy decision produced (one of `ALLOW` / `ALLOW_WITH_WARNING` / `REQUIRE_APPROVAL` / `BLOCK`, plus a reason string for any non-bare-`ALLOW` verdict) |
| call | What was called — at minimum a tool/action identifier and its arguments as they were actually evaluated (the same snapshot used for the gating decision and, if executed, for execution — never a separately-derived copy that could diverge from what was actually decided on or run) |
| taint context | The scope's taint state at decision time — at minimum the scope's watermark level, its `privateDataSeen` flag, and the sink class the call was evaluated against |
| timestamp | When the event was recorded |
| executed | Whether the underlying action actually ran (true for a plain `ALLOW`/`ALLOW_WITH_WARNING`, or a `REQUIRE_APPROVAL` that was in fact granted; false otherwise) |

An implementation MAY carry richer taint-context detail (e.g. matched
attribution records, if Layer 2 is implemented — §5) and MAY extend this
shape further; the fields above are a floor, not a ceiling.

### 4.2 Completeness requirement

**Every operation that mutates watermark-relevant scope state MUST reach
the audit facility, not only calls that go through the ordinary
sink-gating path.** A structural blind spot around exactly the events
that explain *why* a later call got gated defeats the audit facility's
purpose: an operator reviewing the log for "what happened in this
session" needs to see the exposure itself, not only its downstream
consequences.

At minimum, the following categories MUST each produce an audit event:

1. **Every gated policy decision on an actual sink call** — every
   `ALLOW` / `ALLOW_WITH_WARNING` / `REQUIRE_APPROVAL` / `BLOCK` verdict
   produced for a call with a non-`NONE` sink class.
2. **Every use of the quarantine/summarize mechanism** (§3), success or
   rejection — including an input that failed the provenance check.
3. **Every explicit declassify operation** (§1.2) — and the event MUST
   record the watermark state that was actually cleared (its level and
   `privateDataSeen` value immediately before the clear), not a value
   that is trivially true of every declassify call (e.g. hardcoding the
   post-clear state, which tells a reviewer nothing about what was
   actually cleared).
4. **Every use of a manual "context exposure" escape hatch**, if the
   implementation offers one — a way to tell the broker "untrusted
   content reached the model outside any call the broker observed"
   (a tool/plugin description read at discovery time, an untrusted
   system-prompt fragment, pasted content) MUST be audited exactly like
   an ordinary tracked-source exposure, since from the audit log's
   perspective it explains a later gating decision the same way.
5. **Any scope-lifetime boundary reset (turn boundary, decay expiry,
   etc.) that discards a non-`CLEAN` watermark** — the fact that a
   real, non-trivial exposure was discarded, and what was discarded,
   MUST be recorded. A reset of an already-`CLEAN` scope MAY be left
   silent (nothing safety-relevant happened).
6. **Any ordinary source-tool call that raises the watermark or sets
   `privateDataSeen`**, even when that call has sink class `NONE` and is
   therefore never policy-gated — the exposure itself is exactly the
   event later gating decisions need to be explained against, independent
   of whether that specific call was itself privileged.

A call that is a genuine no-op with respect to taint — `NONE` sink class,
does not raise the watermark, does not set `privateDataSeen` — is not
required to be audited; there is nothing safety-relevant to explain later.

---

## 5. What this specification does NOT require

**Layer 2 — any secondary, content-addressed attribution/fingerprint
matching mechanism (exact-hash lookup, simhash, shingle/overlap scoring,
or any other technique for recognizing that an argument's *content*
resembles a previously-seen untrusted source) is explicitly OPTIONAL. It
is never load-bearing for the core gate, and this is the single most
important scoping decision for anyone implementing this model in a new
language or runtime with a different available library ecosystem.**

The reason this can be optional at all is structural, not incidental: the
actual safety boundary (§1–§2) is the scope watermark, which is
content-agnostic by design — it gates on *whether untrusted content was
live in this scope*, never on recognizing *what* that content looks like
in a later argument. Every property this specification claims about
surviving paraphrase, translation, re-encoding, and decision-laundering
(§1.3) holds with zero content-matching machinery present at all, because
none of those properties were ever established by recognizing content in
the first place.

Concretely, a conformant implementation MAY ship **Layer 0 alone** — the
taint lattice, the watermark, the sink taxonomy, the default decision
table, and the quarantine mechanism's semantics (if offered) — and be
fully sound by this specification's standard. Doing so trades away
*precision in explanation*, not *safety*: without any content-attribution
layer, a `BLOCK`/`REQUIRE_APPROVAL` verdict can say "this scope is tainted
by an untrusted source" but cannot say "this specific argument literally
contains text from that source" the way a fingerprint match could. That
is a real, honest cost to the quality of the explanation a human reviewer
or an audit-log consumer sees — it is not a gap in what gets blocked.

An implementation that does add a Layer-2-equivalent attribution
mechanism MAY use whatever comparison technique fits its own language and
library ecosystem — exact hashing is nearly universal, but near-duplicate
detection (simhash, minhash, shingling, or anything else) is an
implementation choice with no required algorithm, no required parameters,
and no required data structure. The only normative constraint on such a
mechanism, if present, is §2.4: it may tighten a verdict, never loosen
one.

Other parts of the reference implementation described in `DESIGN.md` are
likewise explicitly optional extensions beyond the core this document
specifies, and are not otherwise covered here: an in-process fast-path
wrapper for same-object-identity propagation; a stricter "plan-freeze"
mode that additionally constrains *which* privileged tool-call shapes may
occur, not just their arguments; an opt-in outbound-host allowlist as a
separate, content-based (not exposure-based) egress firewall; a bounded
"turn-decay" scope-lifetime variant sitting between a scope that never
resets and one that resets at every turn boundary; and a policy verdict
variant that offers a suggested quarantine-and-retry action in place of
an outright block when a confident attribution match is available. None
of these change what §1–§4 require; they are refinements a conformant
implementation may add, skip, or replace freely.

---

## 6. Conformance

This repository's TypeScript implementation (`src/`, with `src/types.ts`
as the authoritative type contract per `DESIGN.md` §8) is the **reference
implementation** of this specification. Where this document and the
reference implementation's actual behavior diverge, that is treated as a
bug in one of the two — either this document needs correcting, or the
implementation does — not as two independently valid variants.

A change to this document's normative content (§1–§4; §5's scoping
boundary) SHOULD be treated with the same rigor as any other
public-API-shape change to this project: reviewed for backward
compatibility, recorded in `CHANGELOG.md`'s `[Unreleased]` section, and
subject to the same SemVer discipline the exported TypeScript surface
already follows (see `README.md`'s "Versioning" section). A future
independent implementation conforming to `PROTOCOL.md v1` should be able
to trust that this document's normative sections do not shift silently
out from under it between reads.

This document's own version marker (top of file) is independent of this
package's npm version — it tracks changes to the *specification text*,
not to the reference implementation's release cadence. A future revision
that changes normative content (rather than only clarifying wording)
SHOULD bump this document's version number and note what changed and why,
the same way `CHANGELOG.md` already does for the code.

### 6.1 Machine-readable conformance vectors

`conformance/vectors.json` is this section's own claim made mechanically
checkable rather than only prose-asserted. It carries the reference
implementation's full 22-case injection corpus and its 10-tool fixture
catalog as plain JSON: a `tools` array (each entry a declarative
`ToolExecutor` shape — `name`, `capabilities`, `isSource`, `trusted`,
`readsPrivateData` — with no executable code at all, since §5 already
establishes that a conformant implementation's OWN sink/source taxonomy is
what a tool's declared `capabilities`/`isSource` map onto, not anything
this format needs to prescribe) and a `cases` array, each entry an ordered
sequence of operations (register a source's exposure, call a sink with
given arguments, cross a turn boundary, declare a plan, quarantine a piece
of text under a named extraction-schema `kind`) paired with that sequence's
expected final verdict, expected final watermark level, expected
`privateDataSeen`, and — since §5 marks Layer 2 attribution as explicitly
OPTIONAL — an expected MINIMUM attribution strength a Layer-2-equipped
implementation's explanation should reach, never a requirement a
Layer-0-only implementation must satisfy to be conformant.

This is deliberately the reference implementation's OWN corpus,
data-lifted rather than independently authored: `corpus/cases.ts` and
`corpus/fixtures.ts` (the TypeScript files `npm test`/`npm run corpus`
actually run) now LOAD this JSON file at runtime and convert it into their
own internal shapes, rather than the JSON being a separate, hand-maintained
export that could silently drift from what `npm test` actually exercises.
Running this repository's own test suite green is, by construction, this
implementation conforming to `vectors.json` — there is no second copy of
the case data for the two to disagree about. A future independent
implementation can read `vectors.json` directly (a plain JSON parser, no
Node/TypeScript toolchain, and no dependency on this repository's own test
harness) and mechanically check its own decision function's output against
every case's `expected` block, rather than manually re-deriving each case
from this document's prose or from reading `corpus/cases.ts`'s TypeScript
by eye.

The one JSON cannot express directly is the sanctioned quarantine path's
extraction schema (§3, `QuarantineOpts.schema`) — genuinely a function in
the reference implementation. `vectors.json` encodes it as a small, named
`kind` descriptor instead (currently one kind exists,
`'reviewed-with-length'`, meaning "produce `{status: 'reviewed',
[lengthField]: input.length}`"); an implementation in any language
reconstructs the equivalent transform from the kind name and its
parameters, the same way this repository's own `corpus/cases.ts` does.
