/**
 * conformance/vectors.json — the machine-readable conformance vectors
 * PROTOCOL.md §6.1 documents. corpus/cases.ts and corpus/fixtures.ts are
 * ALREADY exercised end to end by test/corpus.spec.ts (every case actually
 * runs through a real broker) — this file instead checks the JSON's own
 * internal consistency (no dangling tool references, unique ids, known
 * schema kinds) and, most importantly, that the TypeScript loaders
 * (corpus/cases.ts, corpus/fixtures.ts) genuinely derive from this file
 * rather than silently drifting back into an independently-maintained
 * second copy — the entire point PROTOCOL.md §6.1 makes.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CORPUS, TRUE_GAP_IDS } from '../corpus/cases.js';
import { FIXTURES } from '../corpus/fixtures.js';

interface VectorTool {
  name: string;
  capabilities: string[];
  isSource?: boolean;
  trusted?: boolean;
  readsPrivateData?: string[];
}

interface VectorCase {
  id: string;
  attackClass: string;
  setup: Array<{ tool: string; args?: Record<string, unknown> }>;
  actions: Array<{ tool: string; args?: Record<string, unknown> }>;
  plan?: Array<{ toolName: string }>;
  quarantine?: { toolName?: string; schema?: { kind: string } };
  expected: { decision: string };
}

interface VectorsFile {
  schemaVersion: number;
  protocolVersion: string;
  trueGapIds: string[];
  tools: VectorTool[];
  cases: VectorCase[];
}

const vectorsPath = fileURLToPath(new URL('../conformance/vectors.json', import.meta.url));
const raw = readFileSync(vectorsPath, 'utf8');
const vectors = JSON.parse(raw) as VectorsFile;

const KNOWN_SCHEMA_KINDS = new Set(['reviewed-with-length']);
const KNOWN_DECISIONS = new Set([
  'ALLOW',
  'ALLOW_WITH_WARNING',
  'REQUIRE_APPROVAL',
  'BLOCK',
  'QUARANTINE_AND_RETRY',
]);

describe('conformance/vectors.json — internal consistency', () => {
  it('is valid JSON with the documented top-level shape', () => {
    expect(vectors.schemaVersion).toBeTypeOf('number');
    expect(vectors.protocolVersion).toBeTypeOf('string');
    expect(Array.isArray(vectors.trueGapIds)).toBe(true);
    expect(Array.isArray(vectors.tools)).toBe(true);
    expect(Array.isArray(vectors.cases)).toBe(true);
  });

  it("has exactly 10 tools and 22 cases, matching README.md/DESIGN.md's own stated counts", () => {
    expect(vectors.tools).toHaveLength(10);
    expect(vectors.cases).toHaveLength(22);
  });

  it('every tool name is unique', () => {
    const names = vectors.tools.map((t) => t.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it('every case id is unique', () => {
    const ids = vectors.cases.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every case references only tool names present in the tools[] catalog', () => {
    const toolNames = new Set(vectors.tools.map((t) => t.name));
    for (const c of vectors.cases) {
      for (const step of [...c.setup, ...c.actions]) {
        expect(
          toolNames.has(step.tool),
          `case "${c.id}" references unknown tool "${step.tool}"`,
        ).toBe(true);
      }
      if (c.plan) {
        for (const step of c.plan) {
          expect(
            toolNames.has(step.toolName),
            `case "${c.id}"'s plan references unknown tool "${step.toolName}"`,
          ).toBe(true);
        }
      }
      if (c.quarantine?.toolName !== undefined) {
        expect(
          toolNames.has(c.quarantine.toolName),
          `case "${c.id}"'s quarantine.toolName references unknown tool "${c.quarantine.toolName}"`,
        ).toBe(true);
      }
    }
  });

  it('every quarantine.schema.kind is a known, implemented kind', () => {
    for (const c of vectors.cases) {
      if (c.quarantine?.schema !== undefined) {
        expect(
          KNOWN_SCHEMA_KINDS.has(c.quarantine.schema.kind),
          `case "${c.id}" references unknown schema kind "${c.quarantine.schema.kind}"`,
        ).toBe(true);
      }
    }
  });

  it('every case expects a real PolicyDecision action', () => {
    for (const c of vectors.cases) {
      expect(
        KNOWN_DECISIONS.has(c.expected.decision),
        `case "${c.id}" expects unknown decision "${c.expected.decision}"`,
      ).toBe(true);
    }
  });

  it('trueGapIds are all real case ids', () => {
    const ids = new Set(vectors.cases.map((c) => c.id));
    for (const gapId of vectors.trueGapIds) {
      expect(ids.has(gapId), `trueGapIds references unknown case id "${gapId}"`).toBe(true);
    }
  });
});

describe('corpus/cases.ts and corpus/fixtures.ts genuinely derive from vectors.json (no drift)', () => {
  it('CORPUS has exactly the same case ids, in the same order, as vectors.json', () => {
    expect(CORPUS.map((c) => c.id)).toEqual(vectors.cases.map((c) => c.id));
  });

  it('TRUE_GAP_IDS is exactly vectors.json.trueGapIds', () => {
    expect(TRUE_GAP_IDS).toEqual(vectors.trueGapIds);
  });

  it('FIXTURES has exactly the same tool names as vectors.json.tools', () => {
    expect(Object.keys(FIXTURES).sort()).toEqual(vectors.tools.map((t) => t.name).sort());
  });

  it("a source tool's isSource/trusted/readsPrivateData match the JSON declaration exactly", () => {
    for (const tool of vectors.tools) {
      const fixture = FIXTURES[tool.name]!;
      expect(fixture.isSource ?? false).toBe(tool.isSource ?? false);
      expect(fixture.trusted ?? false).toBe(tool.trusted ?? false);
      expect(fixture.capabilities.capabilities).toEqual(tool.capabilities);
      if (tool.readsPrivateData !== undefined) {
        expect(fixture.capabilities.readsPrivateData).toEqual({
          categories: tool.readsPrivateData,
        });
      } else {
        expect(fixture.capabilities.readsPrivateData).toBeUndefined();
      }
    }
  });
});
