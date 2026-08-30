## What

<!-- What changed, and why. If this was found while working on something else, say so explicitly rather than folding it in silently. -->

## Which gap/doc, if any

<!--
If this closes, narrows, or worsens something in GAPS.md, name the item number and update GAPS.md in this PR.
If it's a new, deliberate limitation, name it in GAPS.md rather than leaving it undocumented.
If it's purely additive and doesn't touch gating behavior at all, delete this section.
-->

## Validation

- [ ] `npm run typecheck` — clean
- [ ] `npm test` — all passing (state the pass count, e.g. `189/189`)
- [ ] `npm run build` — clean
- [ ] `npm run corpus` — all passing (state the pass count)
- [ ] Added/updated a test that would fail without this change (`test/*.spec.ts` and/or a `corpus/cases.ts` entry)
- [ ] Docs updated where relevant (`README.md`, `DESIGN.md`, `GAPS.md`, `docs/classifying-tools.md`, `CHANGELOG.md`)

<!--
🤖 If you're Claude Code (or another agent) opening this PR: fill in the sections
above from the actual diff, run every command in Validation for real before
checking its box, and don't check a box you haven't verified.
-->
