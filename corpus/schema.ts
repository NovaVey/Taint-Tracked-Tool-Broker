/**
 * The injection-corpus test harness (DESIGN.md §9).
 *
 * A CorpusCase pairs a scripted call sequence with an expected verdict and
 * (optionally) an expected final watermark state and match-attribution
 * strength. Cases tagged with a known-gap attackClass assert the
 * *documented* outcome (see GAPS.md), not an idealized one — so running the
 * corpus is a regression check against silently overclaiming coverage, not
 * just a check that "the broker blocks bad things".
 */

import type { AuditEvent, MatchType, PlanStep, PolicyDecision, QuarantineImpl, ResetScope, TaintLevel, ToolCallBroker } from '../src/index.js';
import { createBroker, exactHash, NOT_SENSITIVE, ToolCallBlockedError, UnplannedPrivilegedActionError } from '../src/index.js';
import { FIXTURES } from './fixtures.js';

export interface CorpusCase {
  id: string;
  description: string;
  /** One of the canonical attack classes documented in corpus/cases.ts / GAPS.md. */
  attackClass: string;
  resetScope?: ResetScope; // default 'session'
  /** Required (and only meaningful) when resetScope is 'turn-decay' — see BrokerOptions.turnDecayWindow. */
  turnDecayWindow?: number;
  /**
   * If set, calls broker.declarePlan() immediately after registering
   * fixtures — i.e. before `setup`, so the scope is still guaranteed CLEAN
   * (declarePlan() throws otherwise). Opts this case into plan-freeze
   * strict mode (DESIGN.md §11).
   */
  plan?: PlanStep[];
  /** Executed in order via broker.call() to seed taint state, using the named fixtures in fixtures.ts. */
  setup: Array<{ tool: keyof typeof FIXTURES; args?: Record<string, unknown> }>;
  /** If set, simulates a turn boundary right after `setup` (and before `quarantine`/`actions`) — see 'turn' resetScope cases. */
  turnBoundaryAfterSetup?: boolean;
  /**
   * If set, models a composite "fetch-and-summarize" tool: raw untrusted
   * text is registered directly (without going through a broker-tracked
   * isSource call, so the watermark is untouched by registration itself —
   * see DESIGN.md §6.2 "Implementation note"), then routed through
   * broker.summarize(). The final watermark lands at DERIVED_UNTRUSTED, not
   * RAW_UNTRUSTED, because the raw text was never returned to the caller
   * for the model to read.
   */
  quarantine?: {
    rawText: string;
    toolName?: string;
    schema?: { parse(x: unknown): unknown };
    instructions?: string;
  };
  /** Executed in order via broker.call(); the LAST entry is the sink call under test. */
  actions: Array<{ tool: keyof typeof FIXTURES; args?: Record<string, unknown> }>;
  expected: {
    decision: PolicyDecision['action'];
    expectedFinalWatermarkLevel?: TaintLevel;
    expectedPrivateDataSeen?: boolean;
    /** Minimum Layer-2 attribution strength the final action's audit record must show. */
    minMatchType?: MatchType | 'none';
    notes?: string;
  };
}

export interface CorpusOutcome {
  case: CorpusCase;
  actualDecision: PolicyDecision['action'] | 'ERROR';
  actualReason: string | undefined;
  finalWatermarkLevel: TaintLevel;
  finalPrivateDataSeen: boolean;
  bestMatchType: MatchType | 'none';
  pass: boolean;
  failureDetail: string | undefined;
  error: unknown;
}

const MATCH_STRENGTH: Record<MatchType | 'none', number> = {
  none: 0,
  wrapper: 1,
  simhash: 2,
  shingle: 3,
  'quarantine-derived': 3,
  exact: 4,
};

/**
 * A schema-aware stub: real deployments supply an actual LLM call here.
 * For the corpus we only need *some* deterministic value the given schema
 * accepts — the point under test is the broker's plumbing (does the
 * watermark move to DERIVED_UNTRUSTED, does the record register as
 * derivedFrom the source), not summarization quality.
 */
const stubQuarantineImpl: QuarantineImpl = async function stubQuarantineImpl<S = string>(
  text: string,
  opts: { instructions?: string; schema?: { parse(x: unknown): S } },
): Promise<S> {
  const value = opts.schema ? opts.schema.parse(text) : `SUMMARY: ${text.slice(0, 60)}`;
  return value as S;
};

function registerFixtures(broker: ToolCallBroker): void {
  for (const fixture of Object.values(FIXTURES)) broker.register(fixture);
}

export async function runCorpusCase(c: CorpusCase): Promise<CorpusOutcome> {
  const auditLog: AuditEvent[] = [];
  const broker = createBroker({
    resetScope: c.resetScope ?? 'session',
    ...(c.turnDecayWindow !== undefined ? { turnDecayWindow: c.turnDecayWindow } : {}),
    auditSink: { record: (e) => auditLog.push(e) },
    // No human present by default: REQUIRE_APPROVAL always denies in the
    // corpus, so "was this call ever safe to auto-execute" is exactly what
    // gets asserted. Approval-granted behavior is covered by broker.spec.ts.
    approvalChannel: { requestApproval: async () => false },
    quarantineImpl: stubQuarantineImpl,
  });
  registerFixtures(broker);

  if (c.plan) {
    broker.declarePlan(c.plan);
  }

  const setupResults: unknown[] = [];
  for (const step of c.setup) {
    setupResults.push(await broker.call(step.tool, step.args ?? {}));
  }

  if (c.turnBoundaryAfterSetup) {
    broker.startNewTurn();
  }

  if (c.quarantine) {
    const { rawText } = c.quarantine;
    // Register directly rather than via broker.call(): this models a
    // composite tool whose raw fetch is an internal implementation detail,
    // never returned to its own caller — so the watermark stays untouched
    // here and is raised only by summarize() itself, landing at
    // DERIVED_UNTRUSTED rather than RAW_UNTRUSTED. See DESIGN.md §6.2.
    const record = broker.registry.register(
      rawText,
      {
        id: exactHash(rawText),
        sourceCallId: 'corpus-internal-fetch',
        toolName: c.quarantine.toolName ?? '__pre_registered__',
        sessionId: 'corpus-session',
        capturedAt: 0,
      },
      'RAW_UNTRUSTED',
      NOT_SENSITIVE,
    );
    const opts: Parameters<typeof broker.summarize>[1] = { sessionId: 'corpus-session', sourceTaintRecordId: record.id };
    if (c.quarantine.schema) opts.schema = c.quarantine.schema;
    if (c.quarantine.instructions) opts.instructions = c.quarantine.instructions;
    await broker.summarize(rawText, opts);
  }

  let actualDecision: PolicyDecision['action'] | 'ERROR' = 'ERROR';
  let actualReason: string | undefined;
  let error: unknown;

  try {
    for (const step of c.actions) {
      await broker.call(step.tool, step.args ?? {});
    }
    const last = auditLog[auditLog.length - 1];
    actualDecision = last ? last.verdict.action : 'ALLOW'; // no audit entries only if every action was a NONE-class sink
    actualReason = last && 'reason' in last.verdict ? last.verdict.reason : undefined;
  } catch (err) {
    error = err;
    if (err instanceof ToolCallBlockedError) {
      actualDecision = err.decision.action;
      actualReason = 'reason' in err.decision ? err.decision.reason : undefined;
    } else if (err instanceof UnplannedPrivilegedActionError) {
      // Plan-freeze strict mode (§11) rejects before the normal policy
      // check ever runs, so there's no PolicyDecision object on the error
      // itself the way ToolCallBlockedError carries one — but dispatch()
      // always records an equivalent BLOCK AuditEvent immediately before
      // throwing this error (broker.ts), so the outcome is represented the
      // same way a normal policy BLOCK is.
      const last = auditLog[auditLog.length - 1];
      actualDecision = 'BLOCK';
      actualReason = last && 'reason' in last.verdict ? last.verdict.reason : undefined;
    }
  }

  const lastTaint = auditLog[auditLog.length - 1]?.taint;
  const bestMatchType: MatchType | 'none' = lastTaint
    ? lastTaint.matchedRecords.reduce<MatchType | 'none'>(
        (best, m) => (MATCH_STRENGTH[m.matchType] > MATCH_STRENGTH[best] ? m.matchType : best),
        'none',
      )
    : 'none';

  const failures: string[] = [];
  if (actualDecision !== c.expected.decision) {
    failures.push(`decision: expected ${c.expected.decision}, got ${actualDecision}${actualReason ? ` (${actualReason})` : ''}`);
  }
  if (c.expected.expectedFinalWatermarkLevel !== undefined && broker.scope.watermark.level !== c.expected.expectedFinalWatermarkLevel) {
    failures.push(`watermark: expected ${c.expected.expectedFinalWatermarkLevel}, got ${broker.scope.watermark.level}`);
  }
  if (c.expected.expectedPrivateDataSeen !== undefined && broker.scope.watermark.privateDataSeen !== c.expected.expectedPrivateDataSeen) {
    failures.push(`privateDataSeen: expected ${c.expected.expectedPrivateDataSeen}, got ${broker.scope.watermark.privateDataSeen}`);
  }
  if (c.expected.minMatchType !== undefined && MATCH_STRENGTH[bestMatchType] < MATCH_STRENGTH[c.expected.minMatchType]) {
    failures.push(`matchType: expected at least ${c.expected.minMatchType}, got ${bestMatchType}`);
  }

  return {
    case: c,
    actualDecision,
    actualReason,
    finalWatermarkLevel: broker.scope.watermark.level,
    finalPrivateDataSeen: broker.scope.watermark.privateDataSeen,
    bestMatchType,
    pass: failures.length === 0,
    failureDetail: failures.length > 0 ? failures.join('; ') : undefined,
    error,
  };
}
