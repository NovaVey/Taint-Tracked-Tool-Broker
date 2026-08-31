import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/openai-tool-loop.ts (like every file under examples/) is exercised
// by its own `npm run example:*` script, not imported into the library's own
// module graph — its top level calls `main()` unconditionally, so importing
// it here would just run the whole example as an unwanted side effect of
// loading the test file. Running it exactly the way `npm run example:openai-
// tool-loop` does (`tsx` in a subprocess) is the only way to assert on what
// it actually demonstrates without duplicating its wiring by hand — same
// rationale as test/vercel-ai-sdk-integration-example.spec.ts and
// test/mcp-integration-example.spec.ts. This is also the ONLY way this
// example file is exercised by CI at all: CI runs `npm test` (vitest) and
// `npm run corpus`, never `npm run example:*`.
//
// Each assertion below was checked to have real teeth, not just to pass:
// with broker.wrap(...) temporarily stripped from Scenario 1's dispatch map
// (a plain unwrapped executor object in its place), the malicious fetch_page
// result reached shell_exec with nothing to stop it — no "[blocked]" line
// appeared, and the scope watermark stayed CLEAN instead of rising to
// RAW_UNTRUSTED — confirming these exact assertions fail against an
// integration that forgot to wrap, and pass once wrap() is restored.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/openai-tool-loop.ts', import.meta.url),
);

describe('examples/openai-tool-loop.ts', () => {
  it("gates a blocked tool_call, suspends for REQUIRE_APPROVAL, and resets the watermark across resetScope:'turn' boundaries", async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // --- Scenario 1: a tool_call gated by the broker becomes an error
    // role:'tool' message, not a crash -- the loop reaches its final
    // scripted assistant turn instead of throwing partway through.
    expect(stdout).toContain(
      '=== Scenario 1: a blocked tool_call becomes an error role:"tool" message, not a crash ===',
    );
    expect(stdout).toContain('[blocked] shell_exec: QUARANTINE_AND_RETRY');
    expect(stdout).toContain(
      'scope watermark at end of turn: RAW_UNTRUSTED — loop finished normally, nothing crashed.',
    );
    // shell_exec's own execute() body is never reached -- its "[would have
    // run] ..." return value must never appear, gated or not.
    expect(stdout).not.toContain('[would have run]');

    // --- Scenario 2: REQUIRE_APPROVAL suspends the loop for a human
    // decision (via createDeferredApprovalChannel), then resumes and
    // actually executes the approved write_file call.
    expect(stdout).toContain(
      '=== Scenario 2: REQUIRE_APPROVAL suspends tool handling for a real human decision ===',
    );
    expect(stdout).toContain('[approval requested] token=');
    expect(stdout).toContain('[human responds] approved.');
    expect(stdout).toContain('assistant: Saved the report to /tmp/report.txt.');

    // --- Scenario 3: resetScope:'turn' -- the SAME broker gates a write
    // inside the turn that raised the watermark, then starts the NEXT
    // message's turn clean, because runToolLoop() calls
    // broker.startNewTurn() once per invocation, not once per tool call.
    expect(stdout).toContain(
      "=== Scenario 3: resetScope:'turn' — startNewTurn()'s one correct call site ===",
    );
    expect(stdout).toContain('[blocked] write_file: REQUIRE_APPROVAL');
    expect(stdout).toContain('watermark at end of message 1: RAW_UNTRUSTED');
    expect(stdout).toContain('watermark at end of message 2: CLEAN');

    // Nothing in this run should ever report an unexpectedly-allowed call.
    expect(stdout).not.toContain('UNEXPECTED');
  }, 30_000);
});
