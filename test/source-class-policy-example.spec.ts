import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/source-class-policy.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — its top level calls `main()` unconditionally,
// so importing it here would just run the whole example as an unwanted side
// effect of loading the test file. Running it exactly the way the script
// would (`tsx` in a subprocess) is the only way to assert on what it
// actually demonstrates without duplicating its wiring by hand — same
// rationale, and same execFile/npx-tsx pattern, as
// test/quarantine-grounding-check-example.spec.ts.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/source-class-policy.ts', import.meta.url),
);

describe('examples/source-class-policy.ts', () => {
  it('demonstrates a custom PolicyFn reading TaintContext.sourceClasses (GAPS.md #28)', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // Section 1: a scope tainted only by an internal-mcp-classed source ->
    // the custom policy downgrades defaultPolicy's REQUIRE_APPROVAL to
    // ALLOW_WITH_WARNING, and the webhook call actually goes through.
    expect(stdout).toContain('=== 1. EXFIL sink, internal-mcp-only exposure ===');
    expect(stdout).toContain("sourceClasses in scope: [ 'internal-mcp' ]");
    expect(stdout).toContain('webhook call ALLOWED (downgraded from REQUIRE_APPROVAL)');

    // Section 2: the scope also saw a public-web-classed source -> the
    // custom policy falls through to defaultPolicy's ordinary
    // REQUIRE_APPROVAL, which is denied (no approvalChannel configured).
    expect(stdout).toContain(
      '=== 2. EXFIL sink, internal-mcp AND public-web exposure — no downgrade ===',
    );
    expect(stdout).toContain("sourceClasses in scope: [ 'internal-mcp', 'public-web' ]");
    expect(stdout).toContain('REQUIRE_APPROVAL, denied (no approvalChannel configured)');

    // Section 3: this policy never touches EXEC's unconditional
    // RAW_UNTRUSTED block, internal-mcp-only or not.
    expect(stdout).toContain(
      '=== 3. EXEC sink, internal-mcp-only — still an unconditional BLOCK ===',
    );
    expect(stdout).toContain('still BLOCK — this policy only ever downgrades REQUIRE_APPROVAL');

    // None of the three sections hit the "UNEXPECTED" fallback branches.
    expect(stdout).not.toContain('UNEXPECTED');
  });
});
