import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/rbac-policy.ts (like every file under examples/) is exercised by
// its own `npm run example:*` script, not imported into the library's own
// module graph — see test/source-class-policy-example.spec.ts's own header
// comment for the full rationale (same execFile/npx-tsx pattern).
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(new URL('../examples/rbac-policy.ts', import.meta.url));

describe('examples/rbac-policy.ts', () => {
  it('demonstrates a custom PolicyFn reading TaintContext.principal (GAPS.md #34) with timeout, cache, and fail-closed semantics (GAPS.md #35)', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
      timeout: 20_000,
    });

    // Section 1: a principal holding the required role -> RBAC authorizes.
    expect(stdout).toContain('=== 1. Principal holding the required role -> RBAC authorizes ===');
    expect(stdout).toContain('ALLOWED: approved:');

    // Section 2: a principal lacking the required role -> RBAC denies.
    expect(stdout).toContain('=== 2. Principal lacking the required role -> RBAC denies ===');
    expect(stdout).toContain('RBAC denied: this principal is not authorized');

    // Section 3: no principal bound at all -> BLOCK.
    expect(stdout).toContain('=== 3. No principal bound at all -> BLOCK (GAPS.md #34) ===');
    expect(stdout).toContain('No principal bound to this broker');

    // Section 4: the RBAC service hangs -> fails closed, and does so well
    // under the hung service's own (unref'd, 60s) delay.
    expect(stdout).toContain(
      '=== 4. RBAC service hangs past this policy’s own inner timeout -> fails closed ===',
    );
    expect(stdout).toContain('RBAC service unavailable (timeout or error)');
    expect(stdout).toContain('failed closed after');
    const failedClosedMatch = /failed closed after (\d+)ms/.exec(stdout);
    expect(failedClosedMatch).not.toBeNull();
    expect(Number(failedClosedMatch![1])).toBeLessThan(5_000); // well under the 60s hang and the 5s outer policyTimeoutMs

    // Section 5: a repeated call for the same (principal, tool) pair is
    // served from cache — the underlying lookup fires only once.
    expect(stdout).toContain(
      '=== 5. Repeated call, same (principal, tool) -> served from cache ===',
    );
    expect(stdout).toContain(
      'underlying RBAC lookups: 1 for the first call, 0 for the second (cached)',
    );

    // Section 6: the RBAC service throws -> fails closed to BLOCK, same
    // reason text as the timeout case (both are "unavailable").
    expect(stdout).toContain('=== 6. RBAC service throws -> fails closed to BLOCK ===');

    // Section 7: defaultPolicy already BLOCKs on taint grounds alone -> RBAC
    // is never even consulted (0 lookups).
    expect(stdout).toContain(
      '=== 7. defaultPolicy already BLOCKs on taint grounds (RAW_UNTRUSTED, EXEC) -> RBAC never consulted ===',
    );
    expect(stdout).toContain('RBAC never consulted (0 lookups)');

    // None of the seven sections hit the "UNEXPECTED" fallback branch.
    expect(stdout).not.toContain('UNEXPECTED');
  });
});
