import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/observe-mode.ts (like every file under examples/) is exercised by
// its own `npm run example:*` script, not imported into the library's own
// module graph — its top level calls `main()` unconditionally, so importing
// it here would just run the whole example as an unwanted side effect of
// loading the test file. Running it exactly the way the script would (`tsx`
// in a subprocess) is the only way to assert on what it actually
// demonstrates without duplicating its wiring by hand — same rationale, and
// same execFile/npx-tsx pattern, as test/source-class-policy-example.spec.ts.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(new URL('../examples/observe-mode.ts', import.meta.url));

describe('examples/observe-mode.ts', () => {
  it("demonstrates enforcement: 'observe' (GAPS.md #31) end to end", async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // Section 1: construction refuses without a real auditSink.
    expect(stdout).toContain('=== 1. Construction guard');
    expect(stdout).toContain('refused to construct, as expected');

    // Section 2: the call actually ran, but the audited verdict is the true
    // one (QUARANTINE_AND_RETRY here — the exact Layer-2 match resolves the
    // otherwise-BLOCK to that more actionable verdict, DESIGN.md §7.2).
    expect(stdout).toContain("=== 2. A verdict that would gate the call under 'enforce'");
    expect(stdout).toContain('shell_exec actually ran (no throw)');
    expect(stdout).toContain('but the audited verdict is still the TRUE one: QUARANTINE_AND_RETRY');
    expect(stdout).toContain('enforcement: observe');

    // Section 3: formatAuditTrail()'s marker and the aggregator's counter.
    expect(stdout).toContain('[OBSERVE MODE: NOT ENFORCED');
    expect(stdout).toContain('observeMode.wouldHaveGated: 1');

    // Section 4: structural checks (allowedOutboundHosts) stay enforcing.
    expect(stdout).toContain('=== 4. Plan-freeze and allowedOutboundHosts remain fully enforced');
    expect(stdout).toContain('still rejected — allowedOutboundHosts is a structural check');

    // Neither of the two "UNEXPECTED" fallback branches should ever fire.
    expect(stdout).not.toContain('UNEXPECTED');
  });
});
