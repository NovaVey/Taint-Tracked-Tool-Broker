import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/taint-envelope-handoff.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — its top level calls `main()` unconditionally,
// so importing it here would just run the whole example as an unwanted side
// effect of loading the test file. Running it exactly the way
// `npm run example:taint-envelope` does (`tsx` in a subprocess) is the only
// way to assert on what it actually demonstrates without duplicating its
// wiring by hand — same rationale as
// test/vercel-ai-sdk-integration-example.spec.ts and
// test/mcp-integration-example.spec.ts. This is also the ONLY way this
// example file is exercised by CI at all: CI runs `npm test` (vitest) and
// `npm run corpus`, never `npm run example:*`.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/taint-envelope-handoff.ts', import.meta.url),
);

describe('examples/taint-envelope-handoff.ts', () => {
  it('blocks/quarantines the call, builds a taint envelope from it, and round-trips it losslessly through a simulated process boundary', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // The gating actually happened — never silently allowed.
    expect(stdout).not.toContain('UNEXPECTED');
    expect(stdout).toMatch(/shell_exec blocked: (BLOCK|QUARANTINE_AND_RETRY)/);
    expect(stdout).toContain('scope watermark after fetch_url: RAW_UNTRUSTED');

    // The envelope actually captured real taint evidence, not an empty shell.
    expect(stdout).toContain('envelope.scopeLevel: RAW_UNTRUSTED');
    expect(stdout).toContain('envelope.matchedRecords.length: 1');
    expect(stdout).toContain('envelope.summary: RAW_UNTRUSTED; 1 fingerprint match');

    // The bigint/Uint32Array fingerprint fields were actually converted
    // before ever reaching JSON.stringify — the exact hazard
    // src/persistence.ts's header (and test/audit-json-safety.spec.ts)
    // documents for the sibling AuditEvent case.
    expect(stdout).toContain(
      'envelope.matchedRecords[0].record.fingerprint.simhash is a string: true',
    );

    // The core claim this example exists to demonstrate: the envelope
    // survives a real JSON.stringify -> JSON.parse round trip — simulating
    // an actual process/service boundary — with no data loss.
    expect(stdout).toContain('round-trip through JSON.stringify/JSON.parse lossless: true');

    // And a downstream consumer with no broker/registry reference at all can
    // still make an informed decision purely from the envelope's fields.
    expect(stdout).toContain('--- downstream side: no broker, no registry, only the envelope ---');
    expect(stdout).toContain(
      'decision: route to human review queue (RAW_UNTRUSTED, not auto-approved)',
    );
  }, 30_000);
});
