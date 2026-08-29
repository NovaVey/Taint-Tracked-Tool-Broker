/**
 * The default policy matrix (DESIGN.md §7.2).
 *
 * Two structural rules the panel's synthesis specifically fixed relative to
 * the source proposals — see DESIGN.md §3:
 *
 *   1. Sink severity is keyed off capability class FIRST: EXEC is hard-gated
 *      by watermark level alone, never contingent on `privateDataSeen`.
 *   2. `privateDataSeen` is an ESCALATOR (REQUIRE_APPROVAL -> BLOCK), never a
 *      GATE — an EXFIL/MUTATE call while untrusted content is live always
 *      requires at least approval, even with no private-data leg at all.
 *
 * This function only ever reads `taint.scopeLevel` to decide the base
 * verdict; `taint.argFingerprintFloor` (Layer 2) is applied afterwards, and
 * only ever to TIGHTEN — see the final block below and DESIGN.md §4.2/§7.2.
 */

import { randomUUID } from 'node:crypto';
import type { PolicyDecision, PolicyFn, TaintContext } from '../types.js';
import { LEVEL_ORDER } from '../types.js';

function requireApproval(reason: string): PolicyDecision {
  return { action: 'REQUIRE_APPROVAL', reason, approvalToken: randomUUID() };
}

function block(reason: string): PolicyDecision {
  return { action: 'BLOCK', reason };
}

function allowWithWarning(reason: string): PolicyDecision {
  return { action: 'ALLOW_WITH_WARNING', reason };
}

function baseDecision(taint: TaintContext): PolicyDecision {
  const { scopeLevel, sinkClass, privateDataSeen } = taint;

  if (sinkClass === 'NONE' || scopeLevel === 'CLEAN') {
    return { action: 'ALLOW' };
  }

  if (scopeLevel === 'RAW_UNTRUSTED') {
    if (sinkClass === 'EXEC') {
      return block('EXEC sink while untrusted content is live in this scope — unconditional block regardless of private-data exposure.');
    }
    if (sinkClass === 'MUTATE') {
      return privateDataSeen
        ? block('MUTATE sink while untrusted content is live in scope AND private data has been read this scope (lethal-trifecta escalation).')
        : requireApproval('MUTATE sink while untrusted content is live in this scope.');
    }
    // EXFIL
    return privateDataSeen
      ? block('EXFIL sink with untrusted content live in scope AND private data read this scope — full lethal trifecta.')
      : requireApproval('EXFIL sink while untrusted content is live in this scope.');
  }

  // scopeLevel === 'DERIVED_UNTRUSTED' — content only reached the model via the sanctioned quarantine path.
  if (sinkClass === 'EXEC') {
    return requireApproval('EXEC sink after content was only quarantine-derived — still requires approval unconditionally, never gated only by the trifecta.');
  }
  if (sinkClass === 'MUTATE') {
    return privateDataSeen
      ? requireApproval('MUTATE sink after quarantine-derived exposure, with private data also read this scope.')
      : allowWithWarning('MUTATE sink after quarantine-derived exposure only; no private data read this scope.');
  }
  // EXFIL
  return privateDataSeen
    ? requireApproval('EXFIL sink after quarantine-derived exposure, with private data also read this scope (full trifecta).')
    : allowWithWarning('EXFIL sink after quarantine-derived exposure only; no private data read this scope.');
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
    return requireApproval(
      'A fingerprint match ties this argument to an untrusted source at a higher level than the current scope watermark reports (e.g. after a turn reset).',
    );
  }

  return decision;
};
