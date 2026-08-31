import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/semantic-kernel-js-integration.ts (like every file under
// examples/) is exercised by its own `npm run example:*` script, not
// imported into the library's own module graph — its top level calls
// main() unconditionally, so importing it here would just run the whole
// example as an unwanted side effect of loading the test file. Running it
// exactly the way `npm run example:semantic-kernel-js` does (`tsx` in a
// subprocess) is the only way to assert on what it actually demonstrates
// without duplicating its wiring by hand — same rationale as
// test/mastra-integration-example.spec.ts and
// test/vercel-ai-sdk-integration-example.spec.ts.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/semantic-kernel-js-integration.ts', import.meta.url),
);

describe('examples/semantic-kernel-js-integration.ts', () => {
  it('routes KernelFunction.from()/addFromObject() through broker.wrap() and actually gates the shell_exec call', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // fetch_page (isSource: true) ran and raised the scope watermark — proof
    // wrapAsKernelFunction's KernelFunction-shaped __fn is actually being
    // dispatched through the broker, not just passed through unchanged.
    expect(stdout).toContain('scope watermark: RAW_UNTRUSTED');

    // shell_exec's cmd argument verbatim-copies fetch_page's tainted result,
    // so defaultPolicy resolves this to QUARANTINE_AND_RETRY (a high-
    // confidence Layer 2 shingle match, DESIGN.md §7.2) rather than a bare
    // BLOCK — either way the call was gated, not executed.
    expect(stdout).toContain('blocked, same as any other integration: QUARANTINE_AND_RETRY');

    // Both ways this file's two-level (pluginName, functionName) addressing
    // can miss a lookup — a wrong function name, and a wrong plugin name —
    // must propagate as real errors and never be relabeled as allowed
    // calls, matching the convention every other framework-integration
    // example in this directory follows for an unrecognized tool name.
    expect(stdout).toContain(
      'unrecognized function name correctly propagated as a real error, not mislabeled as an allowed call: no such function: WebTools.shell_exce',
    );
    expect(stdout).toContain(
      'unrecognized plugin name correctly propagated as a real error, not mislabeled as an allowed call: no such function: WebToolz.shell_exec',
    );
    expect(stdout).not.toContain('UNEXPECTED');
  }, 30_000);
});
