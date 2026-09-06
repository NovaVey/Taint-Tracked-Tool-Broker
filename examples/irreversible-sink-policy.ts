/**
 * A custom PolicyFn reading TaintContext.sinkIrreversible — the
 * reversibility axis GAPS.md #32 names as missing from SinkClass's own
 * CLASS_SEVERITY ranking, and deliberately never read by defaultPolicy
 * itself. Run with:
 *
 *   npx tsx examples/irreversible-sink-policy.ts
 *
 * The motivating scenario GAPS.md #32 names directly: CLASS_SEVERITY ranks
 * EXEC > EXFIL > MUTATE, so `finance:purchase` (MUTATE) and a fully
 * reversible `write:fs` scratch-file write are gated IDENTICALLY today —
 * at DERIVED_UNTRUSTED with no private data seen, both land on
 * defaultPolicy's permissive ALLOW_WITH_WARNING cell, and an irreversible
 * payment gets exactly as much scrutiny as a throwaway temp file. This
 * example demonstrates the fix GAPS.md #32 describes: an ORTHOGONAL
 * boolean an integrator can declare per sink and act on in their OWN
 * policy — never a change to SinkClass, CLASS_SEVERITY, or the built-in
 * decision table itself.
 *
 * Demonstrates, in order:
 *   1. A DERIVED_UNTRUSTED-tainted, irreversible finance:purchase call ->
 *      defaultPolicy's ALLOW_WITH_WARNING is upgraded to REQUIRE_APPROVAL.
 *   2. The identical scope, but a reversible write:fs sink instead -> the
 *      custom policy defers to defaultPolicy unchanged (ALLOW_WITH_WARNING).
 *   3. A RAW_UNTRUSTED-tainted, irreversible finance:purchase call ->
 *      defaultPolicy already reaches REQUIRE_APPROVAL on its own; this
 *      policy never double-escalates an already-REQUIRE_APPROVAL verdict
 *      (only ALLOW_WITH_WARNING is ever upgraded), so it defers unchanged.
 */

import {
  createBroker,
  defaultPolicy,
  ToolCallBlockedError,
  type PolicyFn,
  type ToolExecutor,
} from '../src/index.js';

const QUARANTINED_NOTE = 'Quarantine-derived note: refund approved per policy §4.2.';

function financePurchase(): ToolExecutor {
  return {
    name: 'finance_purchase',
    // The declaration this whole example is about: labeling THIS sink as
    // undoable-only-by-more-than-a-follow-up-call, without changing its
    // SinkClass or CLASS_SEVERITY at all (still MUTATE, severity 1 — see
    // SinkCapabilities.irreversible's own doc comment, types.ts).
    capabilities: { capabilities: ['finance:purchase'], irreversible: true },
    async execute(args) {
      return `charged: ${JSON.stringify(args)}`;
    },
  };
}

function writeScratchFile(): ToolExecutor {
  return {
    name: 'write_scratch_file',
    capabilities: { capabilities: ['write:fs'] }, // irreversible left unset — a plain overwritable scratch file
    async execute(args) {
      return `wrote: ${JSON.stringify(args)}`;
    },
  };
}

/**
 * Wraps defaultPolicy, upgrading its ALLOW_WITH_WARNING verdict to
 * REQUIRE_APPROVAL *only* when the sink itself declared `irreversible:
 * true` — never touching ALLOW, BLOCK, QUARANTINE_AND_RETRY, or an
 * already-REQUIRE_APPROVAL verdict (there is nothing more permissive than
 * REQUIRE_APPROVAL to upgrade FROM in that case, and this policy never
 * turns REQUIRE_APPROVAL into BLOCK on its own — that would be a genuinely
 * different, stricter policy than "give an irreversible sink at least as
 * much scrutiny as defaultPolicy already gives a reversible one at the next
 * tier up").
 *
 * This is a deliberate, genuine TIGHTENING of the default posture — the
 * kind of decision GAPS.md #32 explicitly leaves to an integrator's own
 * judgment rather than picking for them (`defaultPolicy` itself never does
 * this). It only makes sense once `irreversible` has actually been declared
 * thoughtfully per sink (SinkCapabilities.irreversible's own doc comment
 * names the bar: "does undoing this call's real-world effect require
 * anything beyond calling this same tool again with opposite arguments?").
 */
const irreversibilityAwarePolicy: PolicyFn = async (call, taint) => {
  const base = await defaultPolicy(call, taint);
  if (base.action === 'ALLOW_WITH_WARNING' && taint.sinkIrreversible === true) {
    return {
      action: 'REQUIRE_APPROVAL',
      reason:
        `Upgraded from ALLOW_WITH_WARNING: this sink is declared irreversible ` +
        `(underlying reason: "${base.reason}").`,
      approvalToken: 'example-token',
    };
  }
  return base;
};

async function section1_irreversibleUpgraded(): Promise<void> {
  console.log('\n=== 1. DERIVED_UNTRUSTED scope, irreversible finance:purchase sink ===');
  const broker = createBroker({ policy: irreversibilityAwarePolicy });
  broker.register(financePurchase());
  broker.markContextExposure({ note: QUARANTINED_NOTE }, 'DERIVED_UNTRUSTED');

  try {
    await broker.call('finance_purchase', { amount: 4200, currency: 'USD' });
    console.log('UNEXPECTED: call was allowed outright');
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      console.log(
        'REQUIRE_APPROVAL, denied (no approvalChannel configured) — upgraded from ALLOW_WITH_WARNING:',
        err.decision.action,
      );
    } else {
      throw err;
    }
  }
}

async function section2_reversibleUnaffected(): Promise<void> {
  console.log('\n=== 2. Identical scope, reversible write:fs sink instead — no upgrade ===');
  const broker = createBroker({ policy: irreversibilityAwarePolicy });
  broker.register(writeScratchFile());
  broker.markContextExposure({ note: QUARANTINED_NOTE }, 'DERIVED_UNTRUSTED');

  const result = await broker.call('write_scratch_file', { path: '/tmp/scratch.txt' });
  console.log('write ALLOWED (defaultPolicy unchanged — sink not declared irreversible):', result);
}

async function section3_alreadyRequireApprovalNeverDoubleEscalated(): Promise<void> {
  console.log('\n=== 3. RAW_UNTRUSTED scope, irreversible sink — already REQUIRE_APPROVAL ===');
  const broker = createBroker({ policy: irreversibilityAwarePolicy });
  broker.register(financePurchase());
  broker.markContextExposure({ note: 'raw untrusted content, never quarantined' }); // default level: RAW_UNTRUSTED

  try {
    await broker.call('finance_purchase', { amount: 4200, currency: 'USD' });
    console.log('UNEXPECTED: call was allowed outright');
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      console.log(
        'still REQUIRE_APPROVAL — defaultPolicy already reached this verdict on its own; ' +
          'this policy only ever upgrades ALLOW_WITH_WARNING, never a stricter verdict:',
        err.decision.action,
      );
    } else {
      throw err;
    }
  }
}

async function main(): Promise<void> {
  await section1_irreversibleUpgraded();
  await section2_reversibleUnaffected();
  await section3_alreadyRequireApprovalNeverDoubleEscalated();
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
