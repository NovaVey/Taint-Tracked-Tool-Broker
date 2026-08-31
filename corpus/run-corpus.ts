#!/usr/bin/env node
/**
 * CLI runner for the injection corpus: `npm run corpus`.
 * Prints a pass/fail table and exits non-zero if any case's *documented*
 * expectation was not met (a known-gap case "failing" to be blocked is a
 * pass — it's asserting the gap, not fighting it).
 *
 * Also runs each case's counterfactual baseline (schema.ts's
 * runUnprotectedCase) and prints a summary of it: "N/M passed" on its own
 * doesn't establish that the broker actually stopped anything — a case
 * could pass by matching a documented expectation for a payload that was
 * never going to do anything even if allowed. The counterfactual makes that
 * falsifiable by reporting, separately, what each sink call would have done
 * against the same fixtures with no broker mediating it at all.
 */

import { CORPUS, TRUE_GAP_IDS } from './cases.js';
import { runCorpusCase, runUnprotectedCase } from './schema.js';

/**
 * Decisions that, in this harness (no human present — see schema.ts's
 * approvalChannel), functionally stop the call. Real deployments'
 * REQUIRE_APPROVAL depends on a human; corpus always denies, so within THIS
 * report it counts as prevented. QUARANTINE_AND_RETRY belongs here too:
 * DESIGN.md §7.2 and broker.ts's finalizeGated() treat it identically to
 * BLOCK — never auto-executed, always throws ToolCallBlockedError — it is
 * only a more actionable verdict (it names a specific source to
 * re-summarize), never a weaker one. Omitting it here would misreport a
 * "quarantine-and-retry-offered" case as having "gone through" in the
 * sanctionedAllowed bucket below, which is not what happened.
 */
const PREVENTING_DECISIONS = new Set(['BLOCK', 'REQUIRE_APPROVAL', 'QUARANTINE_AND_RETRY']);

/** CorpusOutcome.error is `unknown` (whatever a case's try/catch caught) — almost always one of this library's Error subclasses, but String() on a non-Error object would silently print '[object Object]' and hide the real diagnostic. */
function formatError(error: unknown): string {
  if (error instanceof Error) return error.stack ?? error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return '[unstringifiable error value]';
  }
}

async function main(): Promise<void> {
  const [outcomes, unprotectedOutcomes] = await Promise.all([
    Promise.all(CORPUS.map(runCorpusCase)),
    Promise.all(CORPUS.map(runUnprotectedCase)),
  ]);
  const pairs = outcomes.map((o, i) => ({ o, u: unprotectedOutcomes[i]! }));

  const idWidth = Math.max(...outcomes.map((o) => o.case.id.length), 'id'.length);
  const classWidth = Math.max(
    ...outcomes.map((o) => o.case.attackClass.length),
    'attackClass'.length,
  );

  console.log(
    `${'STATUS'.padEnd(6)} ${'id'.padEnd(idWidth)} ${'attackClass'.padEnd(classWidth)} ${'unprotected'.padEnd(11)} decision`,
  );
  console.log('-'.repeat(6 + 1 + idWidth + 1 + classWidth + 1 + 11 + 1 + 20));

  let failures = 0;
  for (const { o, u } of pairs) {
    const status = o.pass ? 'PASS' : 'FAIL';
    if (!o.pass) failures++;
    const unprotectedLabel = u.sinkExecuted ? 'would run' : 'would fail';
    console.log(
      `${status.padEnd(6)} ${o.case.id.padEnd(idWidth)} ${o.case.attackClass.padEnd(classWidth)} ${unprotectedLabel.padEnd(11)} ${o.actualDecision}`,
    );
    if (!o.pass) {
      console.log(`       ${o.failureDetail}`);
      if (o.error) console.log(`       error: ${formatError(o.error)}`);
    }
  }

  console.log('-'.repeat(6 + 1 + idWidth + 1 + classWidth + 1 + 11 + 1 + 20));
  console.log(`${outcomes.length - failures}/${outcomes.length} passed`);

  // Substring search over freeform prose notes is the ONLY signal here —
  // deliberately not also checking attackClass for an "-known-gap" suffix:
  // no attackClass ever assigned in cases.ts uses that suffix (a stale
  // naming convention that survives only in a few old comments there), so
  // that half of the check was always dead code that could never match.
  // This substring search has no test coverage of its own — a future
  // case's notes could be reworded without the literal substring "KNOWN
  // GAP" and silently disappear from this count with no CI failure — unlike
  // TRUE_GAP_IDS just below, which IS enforced (test/corpus.spec.ts's
  // "covers every documented true known gap" test).
  const knownGapCount = outcomes.filter((o) => o.case.expected.notes?.includes('KNOWN GAP')).length;
  const trueGaps = outcomes.filter((o) => TRUE_GAP_IDS.includes(o.case.id));
  console.log(
    `(${trueGaps.length} true known-gap case(s) asserted as documented misses; see GAPS.md. ${knownGapCount} case(s) reference a gap in their notes.)`,
  );

  // Counterfactual baseline (see schema.ts's runUnprotectedCase doc comment):
  // "N/M passed" alone doesn't establish that anything was actually at stake.
  // This does — split every non-benign case by whether the SAME sink call,
  // with the SAME arguments, would have gone through against an agent with
  // no broker in front of it at all, and whether the broker's actual
  // decision would have stopped that.
  const attackPairs = pairs.filter(({ o }) => o.case.attackClass !== 'benign-no-taint');
  const wouldHaveRun = attackPairs.filter(({ u }) => u.sinkExecuted).length;
  const prevented = attackPairs.filter(({ o }) =>
    PREVENTING_DECISIONS.has(o.actualDecision),
  ).length;
  const trueGapsAllowed = attackPairs.filter(({ o }) => TRUE_GAP_IDS.includes(o.case.id)).length;
  const sanctionedAllowed = attackPairs.filter(
    ({ o }) => !PREVENTING_DECISIONS.has(o.actualDecision) && !TRUE_GAP_IDS.includes(o.case.id),
  ).length;
  console.log(
    `Counterfactual baseline: of ${attackPairs.length} non-benign case(s), ${wouldHaveRun} sink call(s) would have executed unprotected (no broker mediating the call at all). ` +
      `Protected, the broker prevented ${prevented} (BLOCK, REQUIRE_APPROVAL with no human present, or QUARANTINE_AND_RETRY — see schema.ts); ` +
      `${sanctionedAllowed} went through as the sanctioned quarantine path's expected ALLOW_WITH_WARNING (not an attack payload by the time it reached the sink — see "summarize-then-act-write-file"); ` +
      `${trueGapsAllowed} are the documented true known gaps (GAPS.md #1/#2) where protection provides none.`,
  );

  if (failures > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
