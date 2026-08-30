# Contributing

Thanks for considering a contribution. This is presently a small/solo-maintained project (see `SECURITY.md`), so there's no formal process beyond what's below — just the same discipline the codebase already holds itself to.

## Before you start

Read these first; they're short and everything else here assumes them:

- [`README.md`](./README.md) — what this library does and why.
- [`DESIGN.md`](./DESIGN.md) — the actual architecture and rationale, including the implementation-note history of real bugs found and fixed.
- [`GAPS.md`](./GAPS.md) — named, honest limitations. If your change touches one of these, it needs to update this file too (see below).
- [`docs/classifying-tools.md`](./docs/classifying-tools.md) — if your change is about how integrators declare `ToolExecutor`s.

A security-relevant bypass — a way to get a privileged call through without correct gating — is **not** a regular contribution; see [`SECURITY.md`](./SECURITY.md) instead.

## Development setup

```bash
git clone https://github.com/NovaVey/Taint-Tracked-Tool-Broker.git
cd Taint-Tracked-Tool-Broker
npm install
```

```bash
npm run typecheck   # tsc --noEmit
npm test             # vitest — unit tests + the injection corpus
npm run corpus       # just the corpus, with a readable pass/fail table
npm run coverage     # vitest --coverage, enforced against vitest.config.ts's thresholds
npm run build        # emit dist/, exactly what CI and the release workflow run
```

All five must pass clean before opening a PR — CI runs typecheck/build/test/corpus on Node 20/22/24, plus a separate coverage job (see `.github/workflows/ci.yml`), so there's nothing hidden that only fails in CI. If your change lowers coverage below `vitest.config.ts`'s thresholds, either add the missing test coverage or, if the drop is deliberate and justified, lower the specific threshold in the same PR and say why in the PR description — don't leave CI red with no explanation.

## What a good PR looks like

- **Small and focused.** One logical change per PR. A drive-by fix you noticed while working on something else belongs in its own PR, not folded in.
- **Tested.** A behavior change needs a test that would fail without it — either in `test/*.spec.ts` or, for anything about the injection-gating behavior itself, a new case in `corpus/cases.ts`. A bug fix without a regression test is only half done.
- **Documented honestly.** If your change closes a gap, update `GAPS.md` to say so — including any *new*, narrower gap the fix turns out to have (this codebase's history has more than one example of a fix that closed one race and surfaced a smaller one; see `DESIGN.md`'s "Implementation note" sections). If it's a genuinely new, deliberate limitation, name it in `GAPS.md` rather than leaving it to be discovered later. Don't overclaim in `README.md`/`DESIGN.md` what a fix actually covers.
- **Consistent with the existing style.** This codebase favors precise, specific prose over marketing language, and it says what it does *not* do as plainly as what it does. Match that register in code comments and docs, not just code style.

## Adding a corpus case

If you're adding or changing behavior that affects how a call is gated, add a case to `corpus/cases.ts` (see the existing cases for the shape) rather than only covering it in `test/broker.spec.ts`. The corpus is the project's own claim about what it catches and what it doesn't — a case that silently passes when it shouldn't, or that's quietly dropped, is worse than not having it. If your case documents a genuine, accepted gap rather than a catch, mark it as a known-gap case the way the existing two are (see `GAPS.md` #1 and #2) — don't disguise a known miss as a pass.

## Commit messages and PRs

Explain *what* changed and *why*, not just *what*. If you found something while investigating (an existing bug, a stale doc, a design gap the fix doesn't fully close), say so explicitly — this project's own history treats that kind of finding as valuable, not something to bury in a terse commit message. Link to the relevant `GAPS.md`/`DESIGN.md` section when applicable.

Open the PR against `main`. If there's a `.github/PULL_REQUEST_TEMPLATE.md`, fill it in rather than deleting it — it exists to make sure the validation/docs points above actually get checked.

## Code of Conduct

Participation in this project is governed by [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree your contribution is licensed under this project's [Apache-2.0 license](./LICENSE).
