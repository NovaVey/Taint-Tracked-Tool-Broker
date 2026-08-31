import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/mcp-integration.ts (like every file under examples/) is exercised
// by its own `npm run example:*` script, not imported into the library's own
// module graph — its top level calls `main()` unconditionally, so importing
// it here would just run the whole example as an unwanted side effect of
// loading the test file. Running it exactly the way `npm run example:mcp`
// does (`tsx` in a subprocess) is the only way to assert on what it actually
// demonstrates without duplicating its wiring by hand.
//
// This regression test targets one specific finding: the file's header used
// to claim it "demonstrates all three [MCP protocol surfaces], plus a
// reusable guard for the third case" (tools/call, resources/read, tools/list
// descriptions), but resources/read was only ever described in a comment —
// no runnable code exercised it, and McpClient didn't even declare a
// read-resource method. A reader had nothing to point to for that surface.
// Asserting on demonstrateResourceRead()'s own console output — not just
// "the script exits 0", which the two-surface version already satisfied —
// is what actually pins the fix: this assertion FAILS against the pre-fix
// file (no such output exists) and PASSES once resources/read is wired and
// run for real.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(new URL('../examples/mcp-integration.ts', import.meta.url));

describe('examples/mcp-integration.ts', () => {
  it('actually runs a resources/read demonstration, not just tools/call and tools/list', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // demonstrateToolWiring() (tools/call) and demonstrateDescriptionGuard()
    // (tools/list) both ran, same as before this fix.
    expect(stdout).toContain('=== tools/call: wrap exactly like any other source/sink pair ===');
    expect(stdout).toContain('=== tools/list: the description rug-pull guard (GAPS.md #1) ===');

    // demonstrateResourceRead() (resources/read) — the surface the header
    // claimed but never actually exercised prior to this fix.
    expect(stdout).toContain(
      '=== resources/read: identical wrapping to tools/call, different transport ===',
    );
    expect(stdout).toContain('read via MCP resources/read, scope watermark now:');

    // It must exercise the SAME source/sink gating tools/call does above —
    // a resources/read result feeding a declared write:fs sink is gated
    // (default policy resolves this to REQUIRE_APPROVAL, same as the
    // tools/call case just above it), proving the resource was actually
    // wrapped with isSource: true and not just fetched and discarded.
    expect(stdout).toContain(
      'resources/read content gates a sink exactly like tools/call content did above: REQUIRE_APPROVAL',
    );
    expect(stdout).not.toContain('UNEXPECTED: call was allowed');
  }, 30_000);
});
