import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// Not a source-code test — package.json's own `files` allowlist is what
// actually determines what `npm publish` ships. A file existing in the repo
// (docs/classifying-tools.md, examples/*.ts) proves nothing about whether a
// real `npm install` of this package gets it too; only this list does. See
// GAPS.md's "trusted"/HIGH #5 fix note: docs/classifying-tools.md — the
// worked-examples checklist README.md itself links to — was previously
// missing from this list entirely, so an installed (not cloned) copy of
// this package silently could not resolve that link.
const packageJsonPath = fileURLToPath(new URL('../package.json', import.meta.url));
const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as { files: string[] };

describe('package.json files allowlist', () => {
  it('ships docs/ (classifying-tools.md — linked from README.md and ToolExecutor.trusted’s own doc comment)', () => {
    expect(pkg.files).toContain('docs');
  });

  it('ships examples/ (the worked integration walkthroughs linked from README.md)', () => {
    expect(pkg.files).toContain('examples');
  });
});
