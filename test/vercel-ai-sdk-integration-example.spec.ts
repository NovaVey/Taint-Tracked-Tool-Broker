import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/vercel-ai-sdk-integration.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — its top level calls `main()` unconditionally,
// so importing it here would just run the whole example as an unwanted side
// effect of loading the test file. Running it exactly the way
// `npm run example:vercel-ai` does (`tsx` in a subprocess) is the only way to
// assert on what it actually demonstrates without duplicating its wiring by
// hand — same rationale as test/mcp-integration-example.spec.ts.
//
// This regression test targets one specific finding: the file's final
// error-handling branch used to read
//   if (!shellOutcome.ok && shellOutcome.error instanceof ToolCallBlockedError) { ... }
//   else { console.log('UNEXPECTED: call was allowed'); }
// which mislabels ANY non-ToolCallBlockedError failure — not just an
// actually-allowed call — as 'UNEXPECTED: call was allowed', silently
// dropping the real error (it's caught inside mockDispatchToolCall and never
// reaches main().catch()). Reproduced by dispatching to a tool name that was
// never registered ('no such tool: ...'): the pre-fix branch printed
// 'UNEXPECTED: call was allowed' for that too, even though the call never
// ran at all. Every sibling framework-integration example in this directory
// (basic-usage.ts, openai-agents-sdk-integration.ts, langchain-integration.ts,
// mcp-integration.ts, mcp-sdk-integration.ts, anthropic-tool-loop.ts)
// re-throws/surfaces an unrecognized error instead of mischaracterizing it —
// this asserts the fixed example does too.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/vercel-ai-sdk-integration.ts', import.meta.url),
);

describe('examples/vercel-ai-sdk-integration.ts', () => {
  it('propagates a non-ToolCallBlockedError (unrecognized tool name) instead of mislabeling it as an allowed call', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // The genuinely-blocked shell_exec call still reports as blocked, same
    // as before this fix.
    expect(stdout).toContain('blocked, same as any other integration: BLOCK');

    // The dispatch to an unregistered tool name must be reported as the
    // real error it is...
    expect(stdout).toContain(
      'unrecognized tool name correctly propagated as a real error, not mislabeled as an allowed call: no such tool: shell_exce',
    );

    // ...and must NEVER be reported as an allowed call anywhere in the
    // run. This is the assertion that FAILS against the pre-fix branch
    // (which printed exactly this for the unrecognized-tool-name case)
    // and PASSES once the branch re-throws instead.
    expect(stdout).not.toContain('UNEXPECTED');
  }, 30_000);
});
