/**
 * src/cli/doctor.ts (`tttb doctor`) — exercised through `npx tsx` against a
 * set of small, real .mjs config-module fixtures, the same execFile/npx-tsx
 * pattern every examples/*.ts test already uses (see e.g.
 * test/quarantine-grounding-check-example.spec.ts's own header for why:
 * this file's top-level `main().catch(...)` calls `process.exit` on some
 * paths, so importing it directly would run/exit the whole CLI as an
 * unwanted side effect of loading the test file).
 *
 * This complements, rather than duplicates, scripts/smoke-test-doctor-cli.mjs:
 * that script proves the actual COMPILED dist/cli/doctor.js works at all
 * under a real Node ESM loader (run once, after `npm run build`, in CI);
 * this file exercises the CLI's own argument-parsing/error-message/exit-code
 * logic in depth (missing args, malformed config exports, --strict) through
 * the fast, always-available tsx path `npm test` already runs everywhere.
 */
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);
const cliScriptPath = fileURLToPath(new URL('../src/cli/doctor.ts', import.meta.url));
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

async function runCli(
  args: string[],
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const { stdout, stderr } = await execFileAsync('npx', ['tsx', cliScriptPath, ...args], {
      cwd: repoRoot,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', exitCode: e.code ?? 1 };
  }
}

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(path.join(tmpdir(), 'tttb-doctor-cli-test-'));
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe('tttb doctor — argument handling', () => {
  it('exits 2 with a usage message when the subcommand is missing', async () => {
    const result = await runCli([]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('missing subcommand');
    expect(result.stderr).toContain('Usage: tttb doctor');
  });

  it('exits 2 with a usage message for an unknown subcommand', async () => {
    const result = await runCli(['diagnose']);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('unknown subcommand "diagnose"');
  });

  it('exits 2 with a usage message when the config path is missing', async () => {
    const result = await runCli(['doctor']);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('missing <path-to-config.js> argument');
  });

  it('exits 2 with a clear message when the config module fails to import', async () => {
    const result = await runCli(['doctor', path.join(tmpDir, 'does-not-exist.mjs')]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('could not import');
  });

  it('exits 2 when the config module exports no "tools" array', async () => {
    const configPath = path.join(tmpDir, 'no-tools.mjs');
    await writeFile(configPath, 'export const brokerConfig = {};\n');
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('must export a "tools" array');
  });

  it('exits 2 when the config module exports a non-object brokerConfig', async () => {
    const configPath = path.join(tmpDir, 'bad-broker-config.mjs');
    await writeFile(configPath, 'export const tools = [];\nexport const brokerConfig = "nope";\n');
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(2);
    expect(result.stderr).toContain('must be an object if present');
  });

  it('accepts a default export carrying both tools and brokerConfig', async () => {
    const configPath = path.join(tmpDir, 'default-export.mjs');
    await writeFile(
      configPath,
      `export default {
        tools: [{ name: '__tttb_evil', capabilities: { capabilities: [] }, execute: async () => 'x' }],
        brokerConfig: {},
      };\n`,
    );
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('[ERROR] reserved-tool-name');
  });
});

describe('tttb doctor — findings and exit codes', () => {
  it('reports "no findings" and exits 0 for a clean catalog with no brokerConfig, printing the skip notice', async () => {
    const configPath = path.join(tmpDir, 'clean.mjs');
    await writeFile(
      configPath,
      `export const tools = [
        { name: 'fetch_url', capabilities: { capabilities: [] }, isSource: true, execute: async () => 'x' },
      ];\n`,
    );
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('no "brokerConfig" exported — skipping');
    expect(result.stdout).toContain('doctor: no findings.');
  });

  it('exits 1 when an error-severity finding is present', async () => {
    const configPath = path.join(tmpDir, 'dual-role.mjs');
    await writeFile(
      configPath,
      `export const tools = [
        { name: 'fetch_and_run', isSource: true, capabilities: { capabilities: ['exec:shell'] }, execute: async () => 'x' },
      ];\n`,
    );
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('[ERROR] dual-role-tool');
  });

  it('exits 0 for warning/info-only findings without --strict', async () => {
    const configPath = path.join(tmpDir, 'warnings-only.mjs');
    await writeFile(
      configPath,
      `export const tools = [
        { name: 'delete_record', capabilities: { capabilities: [] }, execute: async () => 'x' },
      ];
      export const brokerConfig = {};\n`,
    );
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('[WARN ] unclassified-sink-keyword');
  });

  it('exits 1 for warning-only findings WITH --strict', async () => {
    const configPath = path.join(tmpDir, 'warnings-only-strict.mjs');
    await writeFile(
      configPath,
      `export const tools = [
        { name: 'delete_record', capabilities: { capabilities: [] }, execute: async () => 'x' },
      ];
      export const brokerConfig = {};\n`,
    );
    const result = await runCli(['doctor', configPath, '--strict']);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('[WARN ] unclassified-sink-keyword');
  });

  it('does not run checkBrokerConfig() at all when brokerConfig is omitted, even with an EXFIL tool present', async () => {
    const configPath = path.join(tmpDir, 'no-broker-config-exfil.mjs');
    await writeFile(
      configPath,
      `export const tools = [
        { name: 'post_webhook', capabilities: { capabilities: ['net:outbound'] }, execute: async () => 'x' },
      ];\n`,
    );
    const result = await runCli(['doctor', configPath]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).not.toContain('exfil-without-allowlist');
  });
});
