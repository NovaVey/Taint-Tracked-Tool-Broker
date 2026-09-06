/**
 * Shared mock tools used by the injection corpus (DESIGN.md §9) — loaded
 * from `conformance/vectors.json`'s `tools` array, the language-neutral
 * tool catalog every `PROTOCOL.md`-conformant implementation's own corpus
 * runner is expected to declare (PROTOCOL.md §6). This module is now a thin
 * loader/synthesizer over that JSON, not a second, independently-maintained
 * copy of the same declarations — see `vectors.json`'s own header comment
 * for the full "why JSON" rationale and `corpus/cases.ts`'s matching loader
 * for the case-data half.
 *
 * Every fixture's `execute()` is synthesized generically from the
 * declarative shape alone: a source (`isSource: true`) echoes back
 * `args.mockResult` (or `args` itself) — the corpus fully controls what a
 * "source" tool "found" without needing a real fetch/read, so cases are
 * deterministic and offline; a sink returns a fixed, uninspected placeholder
 * string, since NOTHING in this corpus (`corpus/schema.ts`'s
 * `runCorpusCase()`/`runUnprotectedCase()`, or `test/corpus.spec.ts`) ever
 * asserts on a sink's actual return VALUE — only on the broker's verdict,
 * watermark, and audit trail, which is exactly what makes the return value
 * safe to synthesize rather than needing its own JSON field.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { SinkCapabilities, SinkCapability, ToolExecutor } from '../src/index.js';

interface VectorTool {
  name: string;
  capabilities: readonly SinkCapability[];
  isSource?: boolean;
  trusted?: boolean;
  readsPrivateData?: readonly string[];
}

interface VectorsFile {
  tools: readonly VectorTool[];
}

const vectorsPath = fileURLToPath(new URL('../conformance/vectors.json', import.meta.url));
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8')) as VectorsFile;

/** `mockResultOf()` from the original hand-authored fixtures.ts, preserved verbatim — a source's execute() echoes `args.mockResult` when present, else `args` itself. */
function mockResultOf(args: unknown): unknown {
  if (args !== null && typeof args === 'object' && 'mockResult' in args) {
    return (args as { mockResult?: unknown }).mockResult;
  }
  return args;
}

function buildFixture(tool: VectorTool): ToolExecutor {
  const capabilities: SinkCapabilities = { capabilities: [...tool.capabilities] };
  if (tool.readsPrivateData !== undefined) {
    capabilities.readsPrivateData = { categories: [...tool.readsPrivateData] };
  }
  const executor: ToolExecutor = {
    name: tool.name,
    capabilities,
    async execute(args) {
      return tool.isSource ? mockResultOf(args) : `${tool.name}-result: ${JSON.stringify(args)}`;
    },
  };
  if (tool.isSource) executor.isSource = true;
  if (tool.trusted) executor.trusted = true;
  return executor;
}

export const FIXTURES: Record<string, ToolExecutor> = Object.fromEntries(
  vectors.tools.map((tool) => [tool.name, buildFixture(tool)]),
);
