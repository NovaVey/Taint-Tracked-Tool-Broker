#!/usr/bin/env node
/**
 * Smoke-tests the actual COMPILED `tttb doctor` CLI bin entry
 * (`dist/cli/doctor.js`, what `package.json`'s `"bin"` field points a real
 * `npx tttb doctor ...` invocation at) — the same "test the thing npm
 * actually ships, not src/ through some other toolchain" rationale
 * `scripts/smoke-test-dist.mjs` already documents at length for the
 * library's main entry point (see that file's own header), applied to the
 * SEPARATE shipped artifact this package now also has: a bin script, not a
 * module export. `test/doctor.spec.ts`/`test/cli-doctor.spec.ts` already
 * cover `src/doctor.ts`'s pure functions and `src/cli/doctor.ts`'s own
 * logic in depth through vitest/tsx — this exists specifically to prove
 * that what `tsc` actually EMITS for the CLI, invoked exactly the way an
 * integrator's CI step would (`node`, a real subprocess, a real dynamic
 * `import()` of a plain `.mjs` config module, no tsx/esbuild in between),
 * still produces the right report and the right exit code.
 *
 * Deliberately small: one config module with a mix of clean/flagged tools
 * and an empty brokerConfig, checked for the two things that actually
 * matter for a CI-facing tool — the right findings appear in the printed
 * report, and the exit code reflects them (non-zero only because an
 * 'error'-severity finding is present, not merely because 'warning'/'info'
 * ones are). A second run over a genuinely clean catalog with no
 * brokerConfig confirms the exit-0/no-findings path.
 *
 * Run after `npm run build`:
 *
 *   node scripts/smoke-test-doctor-cli.mjs
 */

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const cliEntry = path.join(here, '..', 'dist', 'cli', 'doctor.js');

/** Runs the compiled CLI as a real subprocess, returning stdout/exit code without throwing on a non-zero exit (execFile's own reject-on-nonzero would otherwise hide the very stdout/exitCode this script asserts on). */
async function runCli(args) {
  try {
    const { stdout } = await execFileAsync('node', [cliEntry, ...args]);
    return { stdout, exitCode: 0 };
  } catch (err) {
    return { stdout: err.stdout ?? '', exitCode: err.code ?? 1 };
  }
}

const tmpDir = await mkdtemp(path.join(tmpdir(), 'tttb-doctor-smoke-'));
try {
  const flaggedConfigPath = path.join(tmpDir, 'flagged-config.mjs');
  await writeFile(
    flaggedConfigPath,
    `
    export const tools = [
      {
        name: 'fetch_and_run',
        capabilities: { capabilities: ['exec:shell'] },
        isSource: true,
        execute: async () => 'x',
      },
      {
        name: 'delete_record',
        capabilities: { capabilities: [] },
        execute: async () => 'x',
      },
    ];
    export const brokerConfig = {};
    `,
  );

  const flagged = await runCli(['doctor', flaggedConfigPath]);
  assert.equal(
    flagged.exitCode,
    1,
    `expected the CLI to exit non-zero for a catalog with a dual-role tool, got exit code ${flagged.exitCode}. stdout:\n${flagged.stdout}`,
  );
  assert.match(
    flagged.stdout,
    /\[ERROR\] dual-role-tool/,
    `expected the compiled CLI's report to flag "fetch_and_run" as dual-role-tool. stdout:\n${flagged.stdout}`,
  );
  assert.match(
    flagged.stdout,
    /\[WARN \] unclassified-sink-keyword/,
    `expected the compiled CLI's report to flag "delete_record" as unclassified-sink-keyword. stdout:\n${flagged.stdout}`,
  );
  assert.match(
    flagged.stdout,
    /\[WARN \] noop-audit-sink/,
    `expected the compiled CLI's report to flag the empty brokerConfig's missing auditSink. stdout:\n${flagged.stdout}`,
  );

  const cleanConfigPath = path.join(tmpDir, 'clean-config.mjs');
  await writeFile(
    cleanConfigPath,
    `
    export const tools = [
      {
        name: 'fetch_url',
        capabilities: { capabilities: [] },
        isSource: true,
        execute: async () => 'x',
      },
    ];
    `,
  );

  const clean = await runCli(['doctor', cleanConfigPath]);
  assert.equal(
    clean.exitCode,
    0,
    `expected the CLI to exit 0 for a clean catalog with no brokerConfig exported, got exit code ${clean.exitCode}. stdout:\n${clean.stdout}`,
  );
  assert.match(
    clean.stdout,
    /doctor: no findings\./,
    `expected "doctor: no findings." in the compiled CLI's report. stdout:\n${clean.stdout}`,
  );

  console.log(
    '[smoke-test-doctor-cli] OK — dist/cli/doctor.js (the compiled, published bin entry) reports ' +
      'findings and exit codes correctly against a real subprocess invocation with a plain .mjs config module.',
  );
} finally {
  await rm(tmpDir, { recursive: true, force: true });
}
