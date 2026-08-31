import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/llamaindex-ts-integration.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — its top level calls `main()` unconditionally,
// so importing it here would just run the whole example as an unwanted side
// effect of loading the test file. Running it exactly the way
// `npm run example:llamaindex-ts` does (`tsx` in a subprocess) is the only
// way to assert on what it actually demonstrates without duplicating its
// wiring by hand — same rationale as
// test/vercel-ai-sdk-integration-example.spec.ts,
// test/mastra-integration-example.spec.ts, and
// test/google-genkit-integration-example.spec.ts.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/llamaindex-ts-integration.ts', import.meta.url),
);

describe('examples/llamaindex-ts-integration.ts', () => {
  it('routes both FunctionTool.from() and tool() through broker.wrap() and actually gates the shell_exec call', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // fetch_page (isSource: true, wired via the newer tool() helper) ran and
    // raised the scope watermark — proof wrapAsLlamaIndexTool's tool()-shaped
    // execute is actually being dispatched through the broker, not just
    // passed through unchanged.
    expect(stdout).toContain('fetch_page (tool() helper) ->');
    expect(stdout).toContain('scope watermark: RAW_UNTRUSTED');

    // shell_exec (wired via the OLDER FunctionTool.from(fn, metadata) API)
    // verbatim-copies fetch_page's tainted result as its cmd argument, so
    // defaultPolicy resolves this to QUARANTINE_AND_RETRY (a high-confidence
    // Layer 2 shingle match, DESIGN.md §7.2) rather than a bare BLOCK —
    // either way the call was gated, not executed. Asserting on the
    // "(FunctionTool.from() API)" label (not just the verdict) proves the
    // *other* declaration path was actually exercised too, not just claimed
    // in a comment.
    expect(stdout).toContain(
      'shell_exec (FunctionTool.from() API), blocked, same as any other integration: QUARANTINE_AND_RETRY',
    );

    // An unrecognized tool name must propagate as a real error and never be
    // relabeled as an allowed call, matching the convention every other
    // framework-integration example in this directory follows.
    expect(stdout).toContain(
      'unrecognized tool name correctly propagated as a real error, not mislabeled as an allowed call: no such tool: shell_exce',
    );
    expect(stdout).not.toContain('UNEXPECTED');
  }, 30_000);
});
