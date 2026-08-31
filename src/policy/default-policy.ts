/**
 * The default policy matrix (DESIGN.md §7.2), table-driven so the two
 * structural rules the panel's synthesis specifically fixed relative to the
 * source proposals (see DESIGN.md §3) are each expressed exactly once
 * instead of being hand-repeated across near-identical if/else branches:
 *
 *   1. Sink severity is keyed off capability class FIRST: EXEC is hard-gated
 *      by watermark level alone — the table's EXEC rows use the SAME action
 *      for both the with- and without-private-data columns.
 *   2. `privateDataSeen` is an ESCALATOR (REQUIRE_APPROVAL -> BLOCK), never a
 *      GATE — every RAW_UNTRUSTED/MUTATE and RAW_UNTRUSTED/EXFIL cell's
 *      "without" column is REQUIRE_APPROVAL, never ALLOW*.
 *
 * This function only ever reads `taint.scopeLevel` to decide the base
 * verdict; `taint.argFingerprintFloor` (Layer 2) is applied afterwards, and
 * only ever to TIGHTEN — see the final block below and DESIGN.md §4.2/§7.2.
 */

import { randomUUID } from 'node:crypto';
import type { PolicyDecision, PolicyFn, SinkClass, TaintContext, TaintLevel } from '../types.js';
import { LEVEL_ORDER } from '../types.js';

type Verdict = PolicyDecision['action'];

interface MatrixCell {
  /** Verdict when privateDataSeen is false. */
  without: Verdict;
  /** Verdict when privateDataSeen is true — equal to `without` for EXEC (never escalated further; already at its ceiling for that tier). */
  withPrivateData: Verdict;
  reasonWithout: string;
  reasonWithPrivateData: string;
}

const MATRIX: Record<
  Exclude<TaintLevel, 'CLEAN'>,
  Record<Exclude<SinkClass, 'NONE'>, MatrixCell>
> = {
  RAW_UNTRUSTED: {
    EXEC: {
      without: 'BLOCK',
      withPrivateData: 'BLOCK',
      reasonWithout:
        'EXEC sink while untrusted content is live in this scope — unconditional block regardless of private-data exposure.',
      reasonWithPrivateData:
        'EXEC sink while untrusted content is live in this scope — unconditional block regardless of private-data exposure.',
    },
    MUTATE: {
      without: 'REQUIRE_APPROVAL',
      withPrivateData: 'BLOCK',
      reasonWithout: 'MUTATE sink while untrusted content is live in this scope.',
      reasonWithPrivateData:
        'MUTATE sink while untrusted content is live in scope AND private data has been read this scope (lethal-trifecta escalation).',
    },
    EXFIL: {
      without: 'REQUIRE_APPROVAL',
      withPrivateData: 'BLOCK',
      reasonWithout: 'EXFIL sink while untrusted content is live in this scope.',
      reasonWithPrivateData:
        'EXFIL sink with untrusted content live in scope AND private data read this scope — full lethal trifecta.',
    },
  },
  DERIVED_UNTRUSTED: {
    EXEC: {
      without: 'REQUIRE_APPROVAL',
      withPrivateData: 'REQUIRE_APPROVAL',
      reasonWithout:
        'EXEC sink after content was only quarantine-derived — still requires approval unconditionally, never gated only by the trifecta.',
      reasonWithPrivateData:
        'EXEC sink after content was only quarantine-derived — still requires approval unconditionally, never gated only by the trifecta.',
    },
    MUTATE: {
      without: 'ALLOW_WITH_WARNING',
      withPrivateData: 'REQUIRE_APPROVAL',
      reasonWithout:
        'MUTATE sink after quarantine-derived exposure only; no private data read this scope.',
      reasonWithPrivateData:
        'MUTATE sink after quarantine-derived exposure, with private data also read this scope.',
    },
    EXFIL: {
      without: 'ALLOW_WITH_WARNING',
      withPrivateData: 'REQUIRE_APPROVAL',
      reasonWithout:
        'EXFIL sink after quarantine-derived exposure only; no private data read this scope.',
      reasonWithPrivateData:
        'EXFIL sink after quarantine-derived exposure, with private data also read this scope (full trifecta).',
    },
  },
};

function toDecision(verdict: Verdict, reason: string): PolicyDecision {
  switch (verdict) {
    case 'ALLOW':
      return { action: 'ALLOW' };
    case 'ALLOW_WITH_WARNING':
      return { action: 'ALLOW_WITH_WARNING', reason };
    case 'REQUIRE_APPROVAL':
      return { action: 'REQUIRE_APPROVAL', reason, approvalToken: randomUUID() };
    case 'BLOCK':
      return { action: 'BLOCK', reason };
    case 'QUARANTINE_AND_RETRY':
      // NOTE: this case exists so toDecision() stays exhaustive over the
      // PolicyDecision['action'] union (types.ts), and so a hand-written
      // PolicyFn is free to route through this same helper if it wants to
      // construct a QUARANTINE_AND_RETRY verdict of its own. But nothing in
      // MATRIX or baseDecision() above — i.e. nothing defaultPolicy itself
      // does — ever selects 'QUARANTINE_AND_RETRY' as a Verdict, so this
      // branch is unreachable from defaultPolicy's own decision path and the
      // shipped default policy never returns this action. Do not take
      // QUARANTINE_AND_RETRY's presence here as evidence that defaultPolicy
      // implements it; see GAPS.md for the tracked gap between this and the
      // DESIGN.md §7.2 description of it as an active default-policy
      // behavior.
      return { action: 'QUARANTINE_AND_RETRY', reason };
  }
}

function baseDecision(taint: TaintContext): PolicyDecision {
  const { scopeLevel, sinkClass, privateDataSeen } = taint;

  if (sinkClass === 'NONE' || scopeLevel === 'CLEAN') {
    return { action: 'ALLOW' };
  }

  const cell = MATRIX[scopeLevel][sinkClass];
  return privateDataSeen
    ? toDecision(cell.withPrivateData, cell.reasonWithPrivateData)
    : toDecision(cell.without, cell.reasonWithout);
}

export const defaultPolicy: PolicyFn = (_call, taint) => {
  const decision = baseDecision(taint);

  // Layer 2 belt-and-suspenders (§4.2, §7.2): a live fingerprint match to an
  // untrusted source floors the verdict at REQUIRE_APPROVAL when it reports
  // a HIGHER level than the watermark alone would (e.g. after a turn-
  // boundary reset masked residual taint the fingerprint still remembers).
  // Deliberately compares levels, not just "is the floor non-CLEAN": when
  // the floor merely corroborates what scopeLevel already reflects, the
  // base decision above already accounts for that risk correctly and must
  // not be tightened again on top of it. Only ever tightens — a decision
  // that is already REQUIRE_APPROVAL or BLOCK is left untouched.
  if (
    LEVEL_ORDER[taint.argFingerprintFloor] > LEVEL_ORDER[taint.scopeLevel] &&
    (decision.action === 'ALLOW' || decision.action === 'ALLOW_WITH_WARNING')
  ) {
    return toDecision(
      'REQUIRE_APPROVAL',
      'A fingerprint match ties this argument to an untrusted source at a higher level than the current scope watermark reports (e.g. after a turn reset).',
    );
  }

  return decision;
};
