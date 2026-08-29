#!/usr/bin/env node
/**
 * CLI runner for the injection corpus: `npm run corpus`.
 * Prints a pass/fail table and exits non-zero if any case's *documented*
 * expectation was not met (a known-gap case "failing" to be blocked is a
 * pass — it's asserting the gap, not fighting it).
 */

import { CORPUS } from './cases.js';
import { runCorpusCase } from './schema.js';

async function main(): Promise<void> {
  const outcomes = await Promise.all(CORPUS.map(runCorpusCase));

  const idWidth = Math.max(...outcomes.map((o) => o.case.id.length), 'id'.length);
  const classWidth = Math.max(...outcomes.map((o) => o.case.attackClass.length), 'attackClass'.length);

  console.log(`${'STATUS'.padEnd(6)} ${'id'.padEnd(idWidth)} ${'attackClass'.padEnd(classWidth)} decision`);
  console.log('-'.repeat(6 + 1 + idWidth + 1 + classWidth + 1 + 20));

  let failures = 0;
  for (const o of outcomes) {
    const status = o.pass ? 'PASS' : 'FAIL';
    if (!o.pass) failures++;
    console.log(`${status.padEnd(6)} ${o.case.id.padEnd(idWidth)} ${o.case.attackClass.padEnd(classWidth)} ${o.actualDecision}`);
    if (!o.pass) {
      console.log(`       ${o.failureDetail}`);
      if (o.error) console.log(`       error: ${String(o.error)}`);
    }
  }

  console.log('-'.repeat(6 + 1 + idWidth + 1 + classWidth + 1 + 20));
  console.log(`${outcomes.length - failures}/${outcomes.length} passed`);

  const knownGapCount = outcomes.filter((o) => o.case.attackClass.endsWith('-known-gap') || o.case.expected.notes?.includes('KNOWN GAP')).length;
  const trueGaps = outcomes.filter((o) => o.case.id === 'untracked-tool-description-injection' || o.case.id === 'cross-turn-latent-influence');
  console.log(`(${trueGaps.length} true known-gap case(s) asserted as documented misses; see GAPS.md. ${knownGapCount} case(s) reference a gap in their notes.)`);

  if (failures > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
