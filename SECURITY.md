# Security Policy

## Scope

This is a security-relevant library — its whole job is to gate privileged tool calls against untrusted content. We're interested in:

- A way to get a privileged (`EXEC`/`MUTATE`/`EXFIL`-class) tool call executed without appropriate gating, that isn't already named in [`GAPS.md`](./GAPS.md).
- A way to bypass, spoof, or corrupt the taint watermark, the fingerprint registry, or the `summarize()`/quarantine path's input validation.
- Any other logic bug that weakens the guarantees described in [`DESIGN.md`](./DESIGN.md).

`GAPS.md` documents known, accepted limitations (including two true, corpus-asserted gaps) — those aren't news to us, but a **new** way to defeat the design, or a way to make one of the documented gaps worse than described, is exactly what we want reported here rather than filed as a public issue.

## Reporting a vulnerability

Please use **[GitHub's private vulnerability reporting](../../security/advisories/new)** for this repository rather than opening a public issue — this keeps the report private until a fix is ready. If that option isn't available on this repo yet, open a regular issue asking to establish a private reporting channel and we'll follow up.

Include, where you can:

- A concrete, reproducible scenario (a call sequence and arguments), ideally as a runnable script similar to `examples/basic-usage.ts` or a new `corpus/cases.ts` entry.
- What the library actually did versus what `DESIGN.md`/`GAPS.md` claim it should do.
- Whether you consider it an implementation bug (fixable) or an inherent design limitation worth documenting.

## Response

This is presently a small/solo-maintained project — there's no formal SLA, but security reports get priority over other work. In practice that means the private vulnerability reporting inbox is checked personally and reports get triaged as they come in, with anything that looks like a genuine Layer 0 watermark/gating bypass (as opposed to a Layer 2 attribution false-negative, already an accepted category in `GAPS.md`) jumping to the front of the queue. Once a fix lands, it'll ship as a patch release with the report credited (unless you'd rather stay anonymous), and — if it was a real gap — reflected honestly in `GAPS.md` or the corpus, not quietly dropped.
