import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/irreversible-sink-policy.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — see test/source-class-policy-example.spec.ts's
// own header comment for the full rationale (same execFile/npx-tsx pattern).
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/irreversible-sink-policy.ts', import.meta.url),
);

describe('examples/irreversible-sink-policy.ts', () => {
  it('demonstrates a custom PolicyFn reading TaintContext.sinkIrreversible (GAPS.md #32)', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // Section 1: an irreversible finance:purchase sink at DERIVED_UNTRUSTED
    // -> the custom policy upgrades defaultPolicy's ALLOW_WITH_WARNING to
    // REQUIRE_APPROVAL, denied (no approvalChannel configured).
    expect(stdout).toContain(
      '=== 1. DERIVED_UNTRUSTED scope, irreversible finance:purchase sink ===',
    );
    expect(stdout).toContain(
      'REQUIRE_APPROVAL, denied (no approvalChannel configured) — upgraded from ALLOW_WITH_WARNING',
    );

    // Section 2: the identical scope, but a reversible write:fs sink instead
    // -> the custom policy defers to defaultPolicy unchanged, and the write
    // actually goes through.
    expect(stdout).toContain(
      '=== 2. Identical scope, reversible write:fs sink instead — no upgrade ===',
    );
    expect(stdout).toContain('write ALLOWED (defaultPolicy unchanged');

    // Section 3: an irreversible sink at RAW_UNTRUSTED — defaultPolicy
    // already reaches REQUIRE_APPROVAL on its own; this policy never
    // double-escalates an already-REQUIRE_APPROVAL verdict.
    expect(stdout).toContain(
      '=== 3. RAW_UNTRUSTED scope, irreversible sink — already REQUIRE_APPROVAL ===',
    );
    expect(stdout).toContain('still REQUIRE_APPROVAL — defaultPolicy already reached this verdict');

    // None of the three sections hit the "UNEXPECTED" fallback branches.
    expect(stdout).not.toContain('UNEXPECTED');
  });
});
