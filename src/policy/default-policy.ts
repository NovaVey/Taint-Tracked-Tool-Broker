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
 * only ever to TIGHTEN — see the Layer-2 block in `defaultPolicy` below and
 * DESIGN.md §4.2/§7.2. A THIRD and final pass, also in `defaultPolicy`,
 * substitutes `QUARANTINE_AND_RETRY` for an otherwise-BLOCK/REQUIRE_APPROVAL
 * verdict when `taint.matchedRecords` names a specifically-identifiable
 * untrusted source (`bestQuarantineCandidate()` below) — see its own doc
 * comment for the exact eligibility bar.
 */

import { randomUUID } from 'node:crypto';
import type {
  PolicyDecision,
  PolicyFn,
  SinkClass,
  TaintContext,
  TaintLevel,
  TaintMatch,
} from '../types.js';
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
      // NOTE: MATRIX/baseDecision() never select 'QUARANTINE_AND_RETRY' as a
      // Verdict — this Verdict type only ever carries the five BASE-MATRIX
      // outcomes (ALLOW/ALLOW_WITH_WARNING/REQUIRE_APPROVAL/BLOCK, plus this
      // case). QUARANTINE_AND_RETRY is a real, reachable defaultPolicy
      // outcome (DESIGN.md §7.2), but it is constructed by a SEPARATE, final
      // pass in defaultPolicy below (bestQuarantineCandidate()), which
      // substitutes it for an already-computed BLOCK/REQUIRE_APPROVAL
      // PolicyDecision rather than routing through this Verdict-keyed
      // helper — a plain `reason` string is all toDecision() has to work
      // with here, and QUARANTINE_AND_RETRY's actionable suggestion needs
      // the matched TaintMatch itself (see buildQuarantineReason()), which
      // this function's signature has no way to receive. This branch exists
      // so toDecision() stays exhaustive over PolicyDecision['action'] for a
      // hand-written PolicyFn that wants to route a QUARANTINE_AND_RETRY
      // verdict of its own through this same helper; it is not the path
      // defaultPolicy itself takes to produce one.
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

/**
 * The minimum `TaintMatch.score` this module treats as "specifically
 * identifiable" for QUARANTINE_AND_RETRY eligibility (DESIGN.md §7.2),
 * applying only to the two SCORED match types ('simhash'/'shingle') — an
 * 'exact' match needs no threshold, it is unambiguous by construction.
 * Deliberately set well above `InMemoryTaintRegistry`'s own
 * `DEFAULT_OVERLAP_MIN` (0.6, `taint/registry.ts`): a bare pass of that
 * default threshold is a genuine Layer 2 match worth gating on (that's what
 * the argFingerprintFloor tightening block above already does with it), but
 * it is not, on its own, confident enough attribution to name a single
 * source in a QUARANTINE_AND_RETRY reason string and imply a targeted
 * re-summarize of THAT source would actually fix the problem — retrying
 * against the wrong source on a marginal 0.6-0.7 overlap gains nothing and
 * only adds a false sense of precision to the verdict. A simhash match
 * under the registry's own default `simhashMaxDistance` (3 of 64 bits)
 * always scores >= 1 - 3/64 ≈ 0.953, so it comfortably clears this bar
 * under default settings; only a caller who has deliberately widened
 * `simhashMaxDistance` well past the default (trading precision for recall)
 * could produce a simhash match this filters out — exactly the case this
 * bar exists to exclude from a "specifically identifiable" claim.
 */
const QUARANTINE_MIN_FUZZY_SCORE = 0.85;

/**
 * Finds the strongest `taint.matchedRecords` entry eligible to justify
 * offering QUARANTINE_AND_RETRY in place of an otherwise-BLOCK/
 * REQUIRE_APPROVAL verdict (DESIGN.md §7.2): an `'exact'` match (unambiguous
 * by construction — the argument literally contains the source record's own
 * byte-identical text), or a `'simhash'`/`'shingle'` fuzzy match scoring at
 * or above `QUARANTINE_MIN_FUZZY_SCORE`.
 *
 * Deliberately does NOT count a `'wrapper'` match (Layer 1's in-process
 * `TaintedValue` fast path, §4.3 — best-effort and never load-bearing, and
 * this feature is about attribution confidence Layer 1's own presence says
 * nothing about) or a `'quarantine-derived'` match (content that has
 * ALREADY been through `summarize()` once — offering to quarantine-and-retry
 * something that IS already the quarantined output would be circular and
 * would not narrow anything a second pass could improve on) — only the two
 * match kinds the design decision behind this feature actually named as
 * "genuinely identifiable single source" evidence.
 *
 * Returns `undefined` when `matchedRecords` is empty — the bare-watermark-
 * only case (the scope is tainted, but nothing ties THIS argument to a
 * specific prior source) has nothing concrete to suggest quarantining, so
 * QUARANTINE_AND_RETRY must never be offered for it — or when every entry
 * present is below the bar. Ties are not resolved by strength: the first
 * qualifying entry in `matchedRecords` is used, since any qualifying match
 * is, by construction, confident enough to name in a reason string — which
 * one is picked among several equally-qualifying matches changes only which
 * source name appears in that reason, never the verdict itself.
 */
function bestQuarantineCandidate(taint: TaintContext): TaintMatch | undefined {
  return taint.matchedRecords.find(
    (m) =>
      m.record.level !== 'CLEAN' &&
      (m.matchType === 'exact' ||
        ((m.matchType === 'simhash' || m.matchType === 'shingle') &&
          m.score >= QUARANTINE_MIN_FUZZY_SCORE)),
  );
}

/**
 * Composes the QUARANTINE_AND_RETRY `reason` string: the underlying
 * BLOCK/REQUIRE_APPROVAL verdict this is replacing (so nothing about why
 * the call was gated in the first place is lost), plus the actionable
 * suggestion itself — naming the specific matched source and telling
 * whatever handles the verdict to re-run that source's read through
 * `broker.summarize()` and retry against the summarized result. This is
 * where `PolicyDecision`'s `suggestedSchemaId` field would go if this
 * library had a schema-registry concept to name a schema by id — it
 * doesn't (see that field's own doc comment in `types.ts`), so the entire
 * suggestion lives here in prose instead.
 */
function buildQuarantineReason(
  underlying: Extract<PolicyDecision, { action: 'BLOCK' } | { action: 'REQUIRE_APPROVAL' }>,
  candidate: TaintMatch,
): string {
  const sourceLabel = candidate.record.provenance.toolName;
  const matchDescription =
    candidate.matchType === 'exact'
      ? 'an exact match'
      : `a high-confidence ${candidate.matchType} match (score ${candidate.score.toFixed(2)})`;
  return (
    `Would otherwise ${underlying.action} (${underlying.reason}) — offered as QUARANTINE_AND_RETRY instead because ` +
    `the call's argument at "${candidate.argPath || '(root)'}" traces to ${matchDescription} against a ` +
    `specifically identifiable untrusted source registered by "${sourceLabel}". Re-run that source's read through ` +
    'broker.summarize() with a narrow schema, then retry this call against the summarized DERIVED_UNTRUSTED result, ' +
    'rather than retrying the raw content verbatim. Never auto-executed by the broker (DESIGN.md §7.2) — purely ' +
    'informational for whatever handles the verdict, exactly like BLOCK/REQUIRE_APPROVAL.'
  );
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
  const tightened =
    LEVEL_ORDER[taint.argFingerprintFloor] > LEVEL_ORDER[taint.scopeLevel] &&
    (decision.action === 'ALLOW' || decision.action === 'ALLOW_WITH_WARNING')
      ? toDecision(
          'REQUIRE_APPROVAL',
          'A fingerprint match ties this argument to an untrusted source at a higher level than the current scope watermark reports (e.g. after a turn reset).',
        )
      : decision;

  // QUARANTINE_AND_RETRY (DESIGN.md §7.2): a final, independent pass that
  // SUBSTITUTES for an otherwise-BLOCK/REQUIRE_APPROVAL verdict — never an
  // add-on to it — when taint.matchedRecords names a specifically
  // identifiable untrusted source a summarize()-then-retry could plausibly
  // neutralize (bestQuarantineCandidate() above). Deliberately runs AFTER
  // the Layer-2 tightening block above, against `tightened` rather than the
  // raw `decision`, so it also applies to a verdict that only became
  // REQUIRE_APPROVAL because of that same tightening (the fingerprint match
  // that justified the escalation is, in that case, exactly the match this
  // block would point to anyway) — not just to a verdict baseDecision()
  // alone already produced. Runs regardless of sinkClass: the actionable
  // suggestion ("re-run the source through summarize(), then retry") is
  // equally meaningful whether the gated sink is EXEC, MUTATE, or EXFIL.
  if (tightened.action === 'BLOCK' || tightened.action === 'REQUIRE_APPROVAL') {
    const candidate = bestQuarantineCandidate(taint);
    if (candidate) {
      // suggestedSchemaId deliberately left unset — see its own doc comment
      // in types.ts. There is no schema-registry concept in this library for
      // a policy to name a schema by id; the actionable suggestion lives
      // entirely in `reason` instead.
      return {
        action: 'QUARANTINE_AND_RETRY',
        reason: buildQuarantineReason(tightened, candidate),
      };
    }
  }

  return tightened;
};
