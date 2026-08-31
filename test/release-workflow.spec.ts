import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Not a source-code test — .github/workflows/release.yml is what actually
// governs the release process, and there is no runtime here that can
// execute a GitHub Actions workflow, so this asserts on the file's raw
// structure the same way test/package-json.spec.ts asserts on package.json's
// raw `files` allowlist: by reading the real file and checking the specific
// properties that matter, rather than re-implementing YAML semantics.
//
// Regression covered: ci-release-atomicity (GAPS.md). Before the fix,
// `npm publish` ran unconditionally every time the job ran, and "Create
// GitHub Release" ran only after it. If "Create GitHub Release" failed on a
// run where `npm publish` had already succeeded, GitHub Actions' "re-run
// failed jobs" reran the whole job from the top — including `npm publish`
// again, which always fails with 403 against an already-published version,
// so the release step could never be reached again. The fix adds a
// registry-check step before publish and makes publish conditional on it,
// so a re-run in that state skips the redundant publish and reaches
// "Create GitHub Release" instead. These assertions fail against the
// pre-fix file (no check step, unconditional publish) and pass against the
// fixed one.
const workflowPath = fileURLToPath(new URL('../.github/workflows/release.yml', import.meta.url));
const workflow = readFileSync(workflowPath, 'utf8');

// Each top-level step in the `publish` job's `steps:` list is a line
// starting with exactly six spaces then "- " (see the indentation of
// `- uses: actions/checkout@v7` etc. in the real file). Splitting on that
// marker gives one chunk per step, in file order — enough to check step
// ordering and each step's own body without a YAML parser dependency.
//
// A chunk's *trailing* text runs up to (but not including) the next step's
// "- ", which means a doc comment sitting just above the NEXT step — like
// this file's own comments, which by house style narrate what's coming next
// and so legitimately mention later step names — is physically still part
// of the PREVIOUS chunk. Matching on a chunk's full text would therefore
// find "Create GitHub Release" inside the comment above the check step
// (which explains the recovery path) rather than inside the actual release
// step several chunks later. So step *identity* is keyed off only each
// chunk's first line — its real `name:`/`run:`/`uses:` — never its trailing
// comment prose; chunk bodies are only searched once the right chunk has
// already been found by head.
const stepChunks = workflow.split(/\n {6}- /).slice(1);

function stepHead(chunk: string): string {
  return chunk.split('\n', 1)[0] ?? '';
}

function findStepIndexByHead(needle: string): number {
  return stepChunks.findIndex((c) => stepHead(c).includes(needle));
}

function chunkWithHead(needle: string): string {
  const idx = findStepIndexByHead(needle);
  if (idx === -1) {
    throw new Error(`No workflow step's own name/run/uses line contains: ${needle}`);
  }
  return stepChunks[idx]!;
}

describe('release.yml recovery path when "Create GitHub Release" fails after npm publish succeeded', () => {
  it('checks the npm registry for the current version before attempting to publish', () => {
    const checkChunk = chunkWithHead('Check whether this version is already on npm');
    // Must actually query the registry for this exact package@version, and
    // record the result as a step output later steps can branch on.
    expect(checkChunk).toMatch(/npm view/);
    expect(checkChunk).toMatch(/GITHUB_OUTPUT/);
  });

  it('makes `npm publish` conditional on that check, instead of running unconditionally', () => {
    const publishChunk = chunkWithHead('npm publish');
    // This is the crux of the fix: pre-fix, this step chunk had no `if:` at
    // all, so a re-run always re-attempted publish (and always got a 403
    // once the version was already live). Post-fix it must be skippable.
    expect(publishChunk).toContain('npm publish --provenance --access public');
    expect(publishChunk).toMatch(
      /if:\s*steps\.npm-check\.outputs\.already-published\s*!=\s*'true'/,
    );
  });

  it('orders the registry check before publish, and publish before the release step', () => {
    // All three indices are positions in the same stepChunks array (file
    // order of the job's top-level steps), so they're directly comparable —
    // and, being keyed off each step's own head line (see findStepIndexByHead
    // above), immune to a doc comment above one step mentioning another
    // step's name.
    const checkIdx = findStepIndexByHead('Check whether this version is already on npm');
    const publishIdx = findStepIndexByHead('npm publish');
    const releaseIdx = findStepIndexByHead('Create GitHub Release');

    expect(checkIdx).toBeGreaterThanOrEqual(0);
    expect(publishIdx).toBeGreaterThanOrEqual(0);
    expect(releaseIdx).toBeGreaterThanOrEqual(0);
    expect(checkIdx).toBeLessThan(publishIdx);
    expect(publishIdx).toBeLessThan(releaseIdx);
  });

  it('does not gate "Create GitHub Release" on the publish step specifically, so a skipped publish still reaches it', () => {
    const releaseChunk = chunkWithHead('Create GitHub Release');
    // No explicit `if:` here at all: the step's implicit default condition
    // is success(), which is satisfied whether the prior npm publish step
    // actually ran or was skipped by the check above — skipped steps don't
    // count as failures. An explicit condition that named the publish step
    // (e.g. `if: steps.publish.outcome == 'success'`) would defeat the
    // recovery path by refusing to run when publish was correctly skipped.
    expect(releaseChunk).not.toMatch(/^\s*if:/m);
  });
});
