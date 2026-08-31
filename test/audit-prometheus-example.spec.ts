import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/audit-prometheus.ts (like every file under examples/) is
// exercised by its own `npm run example:*` script, not imported into the
// library's own module graph — its top level calls `main()`
// unconditionally, and its renderer functions are module-private (not
// exported), so importing it here would both run the whole example as an
// unwanted side effect of loading the test file AND still leave nothing to
// call directly. Running it exactly the way `npm run example:audit-prometheus`
// would (`tsx` in a subprocess) and asserting on its real stdout is the only
// way to exercise it at all — same pattern every other `examples/*.ts`
// file's own regression test uses (e.g.
// test/vercel-ai-sdk-integration-example.spec.ts,
// test/audit-sqlite-example.spec.ts).
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(
  new URL('../examples/audit-prometheus.ts', import.meta.url),
);

/**
 * A Prometheus metric name (the text-exposition format's own "metric_name"
 * production): a leading letter, `_`, or `:`, then any number of letters,
 * digits, `_`, or `:`. In particular this can NEVER contain a `.` — the
 * exact character `AggregatingAuditSink#snapshot()`'s own keys use as a
 * namespacing separator (`"events.total"`, `"verdict.ALLOW.MUTATE"`, ...).
 */
const METRIC_NAME_PATTERN = '[a-zA-Z_:][a-zA-Z0-9_:]*';
const HELP_LINE_RE = new RegExp(`^# HELP (${METRIC_NAME_PATTERN}) (.*)$`);
const TYPE_LINE_RE = new RegExp(
  `^# TYPE (${METRIC_NAME_PATTERN}) (counter|gauge|histogram|summary|untyped)$`,
);
// A sample line's own metric name must satisfy the exact same production as
// the HELP/TYPE lines above — this is the assertion that actually fails if
// sanitization is broken: a name still carrying a literal "." (or any other
// disallowed character) does not match `METRIC_NAME_PATTERN` at all, so the
// whole line falls through every branch in classifyExpositionLines() below
// and trips its explicit "unrecognized line" throw.
const SAMPLE_LINE_RE = new RegExp(`^(${METRIC_NAME_PATTERN})(\\{[^}]*\\})?\\s+(\\S+)$`);

interface ExpositionLines {
  helpNames: Set<string>;
  typeNames: Map<string, string>;
  sampleNames: Set<string>;
  sampleLines: string[];
}

/**
 * A small, direct structural parser over one `/metrics`-shaped block of
 * text, built specifically to prove two things the task at hand cares
 * about: (1) every line is a syntactically valid Prometheus exposition line
 * (a `# HELP` comment, a `# TYPE` comment, or a sample — nothing else), and
 * (2) every metric NAME appearing anywhere in that text — in a `# HELP`
 * line, a `# TYPE` line, or a sample line — is itself a syntactically legal
 * Prometheus metric name (no literal `.`, in particular). A metric name
 * that still contains a `.` (the exact shape a raw, unsanitized
 * `AggregatingAuditSink#snapshot()` key would produce) matches NONE of the
 * three line shapes below, so this function throws with the offending line
 * quoted verbatim — this is deliberately not a lenient "best effort" parser.
 */
function classifyExpositionLines(text: string): ExpositionLines {
  const helpNames = new Set<string>();
  const typeNames = new Map<string, string>();
  const sampleNames = new Set<string>();
  const sampleLines: string[] = [];

  for (const line of text.split('\n')) {
    if (line.length === 0) continue;
    const help = HELP_LINE_RE.exec(line);
    if (help) {
      helpNames.add(help[1]!);
      continue;
    }
    const type = TYPE_LINE_RE.exec(line);
    if (type) {
      typeNames.set(type[1]!, type[2]!);
      continue;
    }
    const sample = SAMPLE_LINE_RE.exec(line);
    if (sample) {
      sampleNames.add(sample[1]!);
      sampleLines.push(line);
      continue;
    }
    throw new Error(
      `line does not match any valid Prometheus exposition line shape (HELP/TYPE comment or sample): ${JSON.stringify(line)}`,
    );
  }

  return { helpNames, typeNames, sampleNames, sampleLines };
}

/** Extracts the text strictly between a `--- BEGIN ... ---` and its matching `--- END ... ---` marker line, exclusive of both. */
function extractBlock(stdout: string, beginMarker: string, endMarker: string): string {
  const beginIndex = stdout.indexOf(beginMarker);
  const endIndex = stdout.indexOf(endMarker);
  expect(beginIndex, `expected to find "${beginMarker}" in stdout`).toBeGreaterThan(-1);
  expect(endIndex, `expected to find "${endMarker}" in stdout`).toBeGreaterThan(-1);
  expect(endIndex).toBeGreaterThan(beginIndex);
  return stdout.slice(beginIndex + beginMarker.length, endIndex);
}

describe('examples/audit-prometheus.ts', () => {
  it(
    'demonstrates a mixed gated session (ALLOW/ALLOW_WITH_WARNING/BLOCK/QUARANTINE_AND_RETRY/REQUIRE_APPROVAL granted+denied) ' +
      'and renders AggregatingAuditSink#snapshot() as syntactically valid, correctly sanitized Prometheus exposition text',
    async () => {
      const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
      });

      // --- Section 1: every verdict kind this scenario is built around actually occurred. ---
      expect(stdout).toContain('write_file (session start) -> ALLOWED');
      expect(stdout).toContain('scope watermark after fetch_page: RAW_UNTRUSTED');
      expect(stdout).toContain('shell_exec (unrelated cleanup command) -> BLOCK');
      expect(stdout).toContain(
        'send_email (forwarding the ticket, quoted verbatim) -> QUARANTINE_AND_RETRY',
      );
      expect(stdout).toContain('write_file (report draft, approval granted) -> ALLOWED');
      expect(stdout).toContain('write_file (report discard, approval denied) -> REQUIRE_APPROVAL');
      // Never mislabels a real block/deny as an allowed call.
      expect(stdout).not.toContain('UNEXPECTED');

      // --- Section 2: the raw snapshot() the renderer is fed, for a direct before/after comparison. ---
      expect(stdout).toContain('"events.total": 6');
      expect(stdout).toContain('"requireApproval.granted": 1');
      expect(stdout).toContain('"requireApproval.denied": 1');
      expect(stdout).toContain('"quarantineAndRetry.offered": 1');
      expect(stdout).toContain('"verdict.QUARANTINE_AND_RETRY.EXFIL": 1');

      // --- Section 3: the rendered /metrics text. ---
      const exposition = extractBlock(stdout, '--- BEGIN /metrics ---\n', '--- END /metrics ---');
      const parsed = classifyExpositionLines(exposition);

      // Every metric NAME this renderer produced is a syntactically legal
      // Prometheus metric name -- in particular, NONE of them still carry
      // the literal "." every underlying snapshot() key was built with.
      // (classifyExpositionLines() above already enforces this structurally
      // -- reaching this line at all means every line in the block matched
      // one of the three legal shapes -- but assert it directly too, for a
      // failure message that names the actual offending character rather
      // than just "some line didn't parse".)
      for (const name of [...parsed.helpNames, ...parsed.typeNames.keys(), ...parsed.sampleNames]) {
        expect(name).not.toContain('.');
        expect(name).toMatch(new RegExp(`^${METRIC_NAME_PATTERN}$`));
      }

      // Every sample's metric name was actually declared via a preceding
      // "# TYPE" line (and has "# HELP" text too) -- a real Prometheus
      // scraper treats a sample with no matching TYPE as implicitly
      // "untyped", which is valid, but this renderer always emits both, so
      // their absence would itself be a regression.
      for (const name of parsed.sampleNames) {
        expect(parsed.typeNames.has(name), `expected a "# TYPE ${name} ..." line`).toBe(true);
        expect(parsed.helpNames.has(name), `expected a "# HELP ${name} ..." line`).toBe(true);
      }

      // The seven always-present scalar metrics, correctly sanitized
      // (".", the only disallowed character any real snapshot() key
      // contains today, replaced with "_") and correctly typed.
      expect(parsed.typeNames.get('tttb_events_total')).toBe('counter');
      expect(parsed.typeNames.get('tttb_requireApproval_granted')).toBe('counter');
      expect(parsed.typeNames.get('tttb_requireApproval_denied')).toBe('counter');
      expect(parsed.typeNames.get('tttb_requireApproval_total')).toBe('counter');
      expect(parsed.typeNames.get('tttb_requireApproval_latencyTotalMs')).toBe('counter');
      // latencyAvgMs is the one gauge -- a computed average, not an
      // ever-accumulating count (the renderer's own doc comment on
      // SCALAR_METRICS explains why).
      expect(parsed.typeNames.get('tttb_requireApproval_latencyAvgMs')).toBe('gauge');
      expect(parsed.typeNames.get('tttb_quarantineAndRetry_offered')).toBe('counter');

      expect(parsed.sampleLines).toContain('tttb_events_total 6');
      expect(parsed.sampleLines).toContain('tttb_requireApproval_granted 1');
      expect(parsed.sampleLines).toContain('tttb_requireApproval_denied 1');
      expect(parsed.sampleLines).toContain('tttb_requireApproval_total 2');
      expect(parsed.sampleLines).toContain('tttb_quarantineAndRetry_offered 1');
      // requestApproval's own artificial 15ms delay, granted once + denied
      // once -- total should be roughly 2x that (with scheduling
      // tolerance), average roughly 1x, and NEVER the literal string "NaN"
      // rendered as a bare identifier (that would itself fail
      // SAMPLE_LINE_RE's \S+ value capture in a way worth distinguishing
      // from a real numeric miss) or 0.
      const latencyTotalLine = parsed.sampleLines.find((l) =>
        l.startsWith('tttb_requireApproval_latencyTotalMs '),
      );
      const latencyAvgLine = parsed.sampleLines.find((l) =>
        l.startsWith('tttb_requireApproval_latencyAvgMs '),
      );
      expect(latencyTotalLine).toBeDefined();
      expect(latencyAvgLine).toBeDefined();
      const latencyTotalMs = Number(latencyTotalLine!.split(' ')[1]);
      const latencyAvgMs = Number(latencyAvgLine!.split(' ')[1]);
      expect(Number.isFinite(latencyTotalMs)).toBe(true);
      expect(Number.isFinite(latencyAvgMs)).toBe(true);
      expect(latencyTotalMs).toBeGreaterThanOrEqual(20); // >= ~2 * 15ms, minus jitter tolerance
      expect(latencyAvgMs).toBeGreaterThan(0);

      // The dynamic verdict.<ACTION>.<SINK_CLASS> breakdown, rendered as
      // ONE labeled counter family rather than five separate metric names.
      expect(parsed.typeNames.get('tttb_verdict_total')).toBe('counter');
      expect(parsed.sampleLines).toContain(
        'tttb_verdict_total{action="ALLOW",sink_class="MUTATE"} 1',
      );
      expect(parsed.sampleLines).toContain(
        'tttb_verdict_total{action="ALLOW_WITH_WARNING",sink_class="NONE"} 1',
      );
      expect(parsed.sampleLines).toContain(
        'tttb_verdict_total{action="BLOCK",sink_class="EXEC"} 1',
      );
      expect(parsed.sampleLines).toContain(
        'tttb_verdict_total{action="QUARANTINE_AND_RETRY",sink_class="EXFIL"} 1',
      );
      expect(parsed.sampleLines).toContain(
        'tttb_verdict_total{action="REQUIRE_APPROVAL",sink_class="MUTATE"} 2',
      );
      // A combination that never occurred (e.g. BLOCK.MUTATE, matching
      // AggregatingAuditSink's own "absent key, not a key holding 0"
      // design) never appears as a sample line at all.
      expect(exposition).not.toContain('action="BLOCK",sink_class="MUTATE"');

      // --- Section 4: an unrecognized snapshot() key is sanitized, not dropped. ---
      const expositionWithUnknownKey = extractBlock(
        stdout,
        '--- BEGIN /metrics (with a synthetic unrecognized key) ---\n',
        '--- END /metrics (with a synthetic unrecognized key) ---',
      );
      const parsedWithUnknownKey = classifyExpositionLines(expositionWithUnknownKey);
      // The raw key "integration.custom/metric!!" carries three different
      // disallowed characters (".", "/", "!") -- every one of them must be
      // gone from the rendered metric name, which must still be present
      // (never silently dropped) and correctly typed as a gauge.
      expect(parsedWithUnknownKey.sampleNames.has('tttb_integration_custom_metric__')).toBe(true);
      expect(parsedWithUnknownKey.typeNames.get('tttb_integration_custom_metric__')).toBe('gauge');
      expect(parsedWithUnknownKey.sampleLines).toContain('tttb_integration_custom_metric__ 42');
      // The original raw key is still named in the HELP text -- readable,
      // just not used as the metric name itself.
      expect(expositionWithUnknownKey).toContain('"integration.custom/metric!!"');
    },
    30_000,
  );
});
