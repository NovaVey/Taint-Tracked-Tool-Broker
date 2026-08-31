import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/anthropic-agent-sdk-integration.ts (like every file under
// examples/) is exercised by its own `npm run example:*` script, not
// imported into the library's own module graph — its top level calls
// `main()` unconditionally, so importing it here would just run the whole
// example as an unwanted side effect of loading the test file. Running it
// exactly the way the recommended `example:agent-sdk` script would (`tsx`
// in a subprocess) is the only way to assert on what it actually
// demonstrates without duplicating its wiring by hand — same rationale as
// test/vercel-ai-sdk-integration-example.spec.ts and
// test/mastra-integration-example.spec.ts.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/anthropic-agent-sdk-integration.ts', import.meta.url),
);

describe('examples/anthropic-agent-sdk-integration.ts', () => {
  it("routes the (Claude) Agent SDK's tool() handler through broker.wrap() and actually gates both sink calls", async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // fetch_page (isSource: true) ran through its wrapped handler and raised
    // the scope watermark — proof the tool()-shaped handler is actually
    // dispatched through the broker, not just passed through unchanged.
    // Manually verified this assertion has teeth (not merely "does not
    // throw"): with wrapAsSdkMcpTool()'s `broker.wrap(executor)` temporarily
    // replaced by the raw, unwrapped `executor` (bypassing the broker
    // entirely, the exact bug this test exists to catch), the run instead
    // printed `scope watermark: CLEAN` and both sink calls below printed
    // `UNEXPECTED: not flagged as an error` — restored before this file was
    // committed, with the suite reconfirmed against the real wiring.
    expect(stdout).toContain('scope watermark: RAW_UNTRUSTED');

    // shell_exec's handler (composeErrorResult: true) catches
    // ToolCallBlockedError itself and composes the isError result — its cmd
    // verbatim-copies fetch_page's tainted result, so defaultPolicy resolves
    // this to QUARANTINE_AND_RETRY (a high-confidence Layer 2 shingle match,
    // DESIGN.md §7.2) rather than a bare BLOCK, but either way the call was
    // gated, not executed.
    expect(stdout).toContain(
      '[handler composed its own isError result] shell_exec: QUARANTINE_AND_RETRY',
    );
    expect(stdout).toContain('shell_exec -> isError: Tool call "shell_exec" was not executed');

    // run_cleanup's handler (composeErrorResult: false) does NOT catch
    // ToolCallBlockedError itself — mockDispatchSdkToolCall's own catch
    // (standing in for the SDK's in-process MCP server) is what converts it
    // to an isError result instead. Its cmd is unrelated to anything
    // fetched, so this is a plain BLOCK, not QUARANTINE_AND_RETRY — proof
    // the two composeErrorResult paths this file demonstrates both actually
    // gate the call, via two different mechanisms, not just one of them.
    expect(stdout).toContain(
      '[SDK\'s in-process MCP server auto-converted the uncaught exception to an isError result] Tool call "run_cleanup" was not executed (BLOCK)',
    );
    expect(stdout).toContain('run_cleanup -> isError: Tool call "run_cleanup" was not executed');

    // An unrecognized qualified tool name is a genuine dispatch bug, not a
    // gating outcome, and must be reported as { ok: false }, never
    // relabeled as a completed (let alone allowed) call — the same
    // "don't mislabel a real error as a normal blocked call" convention
    // every other framework-integration example in this directory follows
    // at its own dispatch boundary (see vercel-ai-sdk-integration.ts's and
    // mastra-integration.ts's own regression tests for this exact shape).
    expect(stdout).toContain(
      'unrecognized tool name correctly reported as a dispatch failure, not an isError result: no such tool: mcp__broker_tools__does_not_exist',
    );
    expect(stdout).not.toContain('UNEXPECTED');
  }, 30_000);
});
