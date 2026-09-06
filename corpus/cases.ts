/**
 * The injection corpus: loaded from `conformance/vectors.json`, the
 * language-neutral behavioral spec `PROTOCOL.md` §6 names as authoritative
 * alongside this TypeScript reference implementation — twenty-two cases
 * across fifteen attack classes (the eleven canonical classes from the
 * design panel's synthesis, plus plan-freeze-unplanned-privileged-action,
 * unapproved-egress-host, quarantine-provenance-spoof, and
 * quarantine-and-retry-offered, each added once the feature it exercises
 * shipped — see `vectors.json`'s own per-case `description`/`expected.notes`
 * fields for the full history each case used to carry as a hand-written
 * comment here).
 *
 * This module is now a thin loader/converter, not the source of the case
 * data itself: `vectors.json` is a plain JSON document any language's own
 * conformance runner can read directly, with no dependency on this file,
 * this module's types, or a JavaScript/TypeScript toolchain at all — making
 * drift between the documented spec and this reference implementation's own
 * test suite structurally impossible rather than merely discouraged (the
 * two are now, definitionally, the same data). The one thing JSON cannot
 * represent directly is `QuarantineOpts.schema`'s `{ parse(x): S }`
 * function — `vectors.json` encodes each case's schema as a small, named
 * `kind` descriptor instead (`SCHEMA_KINDS` below), and this loader is
 * responsible for reconstructing the actual parse function a real
 * `broker.summarize()` call needs. Only one kind currently exists —
 * `'reviewed-with-length'`: `{ status: 'reviewed', [lengthField]: input.length }`
 * — used across the corpus's four schema-bearing cases; a future case
 * introducing a genuinely different extraction shape would add a new named
 * kind here, not a bespoke inline closure the way this file used to define
 * one per case.
 *
 * Two cases are TRUE, asserted known gaps (see GAPS.md #1 and #2) — the
 * corpus proves the library is honest about them, not that it catches them.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { CorpusCase } from './schema.js';

/**
 * Reconstructs a real `{ parse(x: unknown): unknown }` function from
 * `vectors.json`'s declarative `{ kind, ...params }` schema descriptor — the
 * one piece of a `CorpusCase` JSON genuinely cannot represent directly. See
 * this module's own header for why there is currently exactly one kind.
 */
const SCHEMA_KINDS: Record<
  string,
  (params: Record<string, unknown>) => { parse(x: unknown): unknown }
> = {
  'reviewed-with-length': (params) => {
    const lengthField = params.lengthField as string;
    return {
      parse: (input: unknown) => ({
        status: 'reviewed',
        [lengthField]: (input as string).length,
      }),
    };
  },
};

function buildSchema(descriptor: { kind: string; [key: string]: unknown }): {
  parse(x: unknown): unknown;
} {
  const builder = SCHEMA_KINDS[descriptor.kind];
  if (!builder) {
    throw new Error(
      `conformance/vectors.json references unknown quarantine schema kind "${descriptor.kind}" — ` +
        `add it to corpus/cases.ts's own SCHEMA_KINDS map.`,
    );
  }
  return builder(descriptor);
}

interface VectorCase {
  id: string;
  description: string;
  attackClass: string;
  resetScope?: CorpusCase['resetScope'];
  allowedOutboundHosts?: readonly string[];
  turnDecayWindow?: number;
  plan?: CorpusCase['plan'];
  setup: CorpusCase['setup'];
  turnBoundaryAfterSetup?: boolean;
  quarantine?: {
    rawText: string;
    quarantineText?: string;
    toolName?: string;
    schema?: { kind: string; [key: string]: unknown };
    instructions?: string;
  };
  actions: CorpusCase['actions'];
  expected: CorpusCase['expected'];
}

interface VectorsFile {
  schemaVersion: number;
  protocolVersion: string;
  trueGapIds: readonly string[];
  cases: readonly VectorCase[];
}

function convertCase(v: VectorCase): CorpusCase {
  const out: CorpusCase = {
    id: v.id,
    description: v.description,
    attackClass: v.attackClass,
    setup: v.setup,
    actions: v.actions,
    expected: v.expected,
  };
  if (v.resetScope !== undefined) out.resetScope = v.resetScope;
  if (v.allowedOutboundHosts !== undefined) out.allowedOutboundHosts = v.allowedOutboundHosts;
  if (v.turnDecayWindow !== undefined) out.turnDecayWindow = v.turnDecayWindow;
  if (v.plan !== undefined) out.plan = v.plan;
  if (v.turnBoundaryAfterSetup !== undefined) out.turnBoundaryAfterSetup = v.turnBoundaryAfterSetup;
  if (v.quarantine !== undefined) {
    const q: NonNullable<CorpusCase['quarantine']> = { rawText: v.quarantine.rawText };
    if (v.quarantine.quarantineText !== undefined) q.quarantineText = v.quarantine.quarantineText;
    if (v.quarantine.toolName !== undefined) q.toolName = v.quarantine.toolName;
    if (v.quarantine.instructions !== undefined) q.instructions = v.quarantine.instructions;
    if (v.quarantine.schema !== undefined) q.schema = buildSchema(v.quarantine.schema);
    out.quarantine = q;
  }
  return out;
}

const vectorsPath = fileURLToPath(new URL('../conformance/vectors.json', import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as VectorsFile;

/**
 * Case ids for the two TRUE, asserted known gaps (GAPS.md #1 and #2) — as
 * opposed to any case whose `expected.notes` merely happens to mention
 * "KNOWN GAP" in passing (e.g. "turn-decay-narrows-cross-turn-gap", which
 * narrows but does not close one of these same two gaps, and says so in its
 * own notes). This is the single source of truth both run-corpus.ts's
 * summary line and test/corpus.spec.ts's "covers every documented true
 * known gap" test read from — loaded straight from `vectors.json.trueGapIds`
 * rather than hand-duplicated here, so a third true known gap added to the
 * JSON can't silently go unlisted in one copy while present in the other.
 */
export const TRUE_GAP_IDS: readonly string[] = vectors.trueGapIds;

export const CORPUS: CorpusCase[] = vectors.cases.map(convertCase);
