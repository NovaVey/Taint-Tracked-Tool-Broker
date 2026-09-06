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
const pkg = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as {
  version: string;
  files: string[];
  bin?: Record<string, string>;
};

describe('package.json files allowlist', () => {
  it('ships docs/ (classifying-tools.md — linked from README.md and ToolExecutor.trusted’s own doc comment)', () => {
    expect(pkg.files).toContain('docs');
  });

  it('ships examples/ (the worked integration walkthroughs linked from README.md)', () => {
    expect(pkg.files).toContain('examples');
  });

  it('ships conformance/ (vectors.json — the machine-readable conformance vectors linked from README.md/PROTOCOL.md §6.1)', () => {
    expect(pkg.files).toContain('conformance');
  });

  // PROTOCOL.md itself used to be missing from this exact list — the same
  // "linked from the shipped README.md but not itself shipped" shape GAPS.md
  // #10 already found and fixed once for docs/classifying-tools.md (see this
  // file's own header comment above). README.md's "Language-neutral
  // specification" section links to ./PROTOCOL.md by relative path; without
  // it in `files`, that link dead-ended for anyone reading an installed (not
  // cloned) copy of the package, even though README.md itself IS shipped.
  it('ships PROTOCOL.md (the language-neutral specification linked from README.md)', () => {
    expect(pkg.files).toContain('PROTOCOL.md');
  });

  // README.md links to all three of these by relative path (./SECURITY.md,
  // ./CONTRIBUTING.md, ./CODE_OF_CONDUCT.md) — without them in `files`,
  // those links dead-end for anyone reading an installed (not cloned) copy
  // of the package offline, even though README.md itself IS shipped.
  it.each(['CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md'])(
    'ships %s (linked from the shipped README.md)',
    (file) => {
      expect(pkg.files).toContain(file);
    },
  );
});

describe("package.json bin entry (GAPS.md #30's `tttb doctor` CLI)", () => {
  it('points "tttb" at a path under dist/ — the one directory `files` above already covers recursively', () => {
    const tttbBin = pkg.bin?.tttb;
    expect(tttbBin).toBeDefined();
    // Not `startsWith('dist/')` — package.json conventionally (and this
    // one, for main/types too) writes bin paths with a leading "./", and
    // `files: ['dist', ...]` covers dist/cli/doctor.js either way; this
    // just confirms the two haven't drifted (e.g. a rename that moved the
    // CLI entry outside dist/ without updating `files`).
    expect(tttbBin).toMatch(/^\.?\/?dist\//);
  });
});

describe('package-lock.json stays in sync with package.json', () => {
  it("the lockfile's own recorded version matches package.json's — a stale lockfile version can mislead supply-chain tooling that inspects it", () => {
    const lockPath = fileURLToPath(new URL('../package-lock.json', import.meta.url));
    const lock = JSON.parse(readFileSync(lockPath, 'utf8')) as {
      version: string;
      packages: Record<string, { version?: string }>;
    };
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages['']?.version).toBe(pkg.version);
  });
});
