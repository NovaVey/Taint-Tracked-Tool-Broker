import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/screenshot-source-extract-text.ts (like every file under
// examples/) is exercised by its own `npm run example:*` script, not
// imported into the library's own module graph — see
// test/source-class-policy-example.spec.ts's own header comment for the
// full rationale (same execFile/npx-tsx pattern).
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/screenshot-source-extract-text.ts', import.meta.url),
);

describe('examples/screenshot-source-extract-text.ts', () => {
  it('demonstrates ToolExecutor.extractText for a non-text source result (GAPS.md #33)', async () => {
    const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
      cwd: fileURLToPath(new URL('..', import.meta.url)),
    });

    // Section 1: real OCR text -> registered, and later exact-matched.
    expect(stdout).toContain(
      '=== 1. Screenshot with real OCR text — registered and later exact-matched ===',
    );
    expect(stdout).toContain('Layer 2 record for the OCR text exists: true');
    expect(stdout).toContain(
      'BLOCKed with an exact Layer 2 attribution to the OCR text: exact true',
    );

    // Section 2: no OCR text found -> registration skipped, watermark
    // still raises and still gates on its own.
    expect(stdout).toContain(
      '=== 2. Screenshot with no OCR text found — registration skipped, watermark still raises ===',
    );
    expect(stdout).toContain('Registry size after the call (expect 0 — nothing registrable): 0');
    expect(stdout).toContain('Scope watermark level (Layer 0 unaffected): RAW_UNTRUSTED');
    expect(stdout).toContain(
      'still BLOCKed by the watermark alone — zero Layer 2 attribution available: true',
    );

    // Section 3: no extractText declared -> falls back to the unmatchable
    // stringified blob, shown for contrast.
    expect(stdout).toContain(
      '=== 3. No extractText declared — falls back to the unmatchable stringified blob ===',
    );
    expect(stdout).toContain(
      'Layer 2 record for the OCR text (never registered without extractText): false',
    );
    expect(stdout).toContain(
      'Registry instead holds a record for the useless stringified image payload: true',
    );

    expect(stdout).not.toContain('UNEXPECTED');
  });
});
