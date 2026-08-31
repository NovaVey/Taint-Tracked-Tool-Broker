import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/quarantine-grounding-check.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — its top level calls `main()` unconditionally,
// so importing it here would just run the whole example as an unwanted side
// effect of loading the test file. Running it exactly the way the script
// would (`tsx` in a subprocess) is the only way to assert on what it
// actually demonstrates without duplicating its wiring by hand — same
// rationale, and same execFile/npx-tsx pattern, as
// test/vercel-ai-sdk-integration-example.spec.ts and
// test/mcp-integration-example.spec.ts. This is also the ONLY way this
// example file is exercised by CI at all — `npm test` runs this spec, but
// nothing runs `npm run example:*` scripts directly.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/quarantine-grounding-check.ts', import.meta.url),
);

describe('examples/quarantine-grounding-check.ts', () => {
  it('demonstrates checkFieldGrounding() accepting a faithful extraction and rejecting a fabricated field', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // Section 1: every field of the honest extraction is grounded, so
    // withGroundingCheck() lets summarize() return normally (never throws),
    // and the quarantined result reaches the caller at DERIVED_UNTRUSTED.
    expect(stdout).toContain('=== 1. Honest Q-LLM extraction');
    expect(stdout).toContain('scope watermark: DERIVED_UNTRUSTED');
    expect(stdout).toContain(
      "invoiceReference: 'invoice number 48221 for the March consulting engagement'",
    );

    // The wire_payment call is still separately gated by the broker's own
    // Layer 2 fingerprint matching -- this file's own header comment names
    // this as expected, not a bug in the grounding check.
    expect(stdout).toContain(
      'wire_payment gated by the broker itself (not by checkFieldGrounding): REQUIRE_APPROVAL',
    );

    // Section 2: the fabricated "paymentAmount" field must be caught and
    // must cause the WHOLE extraction to be rejected -- this is the actual
    // regression this example exists to demonstrate.
    expect(stdout).toContain('=== 2. Compromised/hallucinating Q-LLM');
    expect(stdout).toContain('extraction rejected by withGroundingCheck()');
    expect(stdout).toContain('ungrounded field(s) "paymentAmount"');

    // The rejected extraction must never have raised the watermark -- there
    // was no result for summarize() to register/raise with.
    expect(stdout).toContain(
      'scope watermark: CLEAN (never reached DERIVED_UNTRUSTED -- summarize() never returned a result to raise it with)',
    );

    // Never silently mislabeled as accepted anywhere in the run.
    expect(stdout).not.toContain('UNEXPECTED');
  }, 30_000);
});
