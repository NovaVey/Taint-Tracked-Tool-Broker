/**
 * The sanctioned quarantine/summarize path (DESIGN.md §6.2) — the only way
 * free-form untrusted text may be condensed/paraphrased before re-entering
 * the primary agent's context without the scope staying at RAW_UNTRUSTED.
 *
 * `impl` is supplied by the integrator and must itself be capability-less:
 * no tool access, no conversation history beyond the input text and
 * instructions. This module does not call any LLM provider itself — TTTB
 * has no opinion on which model you use for quarantine extraction.
 */

import { randomUUID } from 'node:crypto';
import type { ProvenanceTag, QuarantineFn, QuarantineImpl, QuarantineOpts, QuarantineResult, TaintRegistry } from './types.js';
import { buildFingerprint, exactHash, shingleIntersectionSize, toRegistrableText } from './taint/fingerprint.js';
import { QuarantineInputMismatchError, QuarantineInputUnknownError } from './errors.js';

// Two independent, asymmetric checks — text must be substantially DERIVED
// FROM the claimed source, not merely similar to it. Neither alone is
// enough: a min()-based overlap coefficient (the general-purpose Layer 2
// matcher in fingerprint.ts) lets a large fabricated `text` inherit a tiny
// source's high score just by borrowing one shared shingle, since min()
// picks the smaller (source's) shingle count as the denominator. Both
// checks below are deliberately relative to `text`'s OWN size instead:
//
//   1. Length ratio — a genuine quarantine input is not many times LONGER
//      than its claimed source. This alone rejects "borrow one shingle
//      from a tiny source, pad with 90KB of fabricated content" before
//      even building a fingerprint for it.
//   2. Source coverage — what fraction of TEXT's own shingles are
//      accounted for by the source, i.e. intersection / |text's shingles|
//      (not min(|text|,|source|)). A genuine excerpt of the source scores
//      close to 1.0 here; a mostly-fabricated payload with a few borrowed
//      shingles scores close to 0.
//
// Still not a spoofing-proof check (a sufficiently large verbatim quote
// padded with a small amount of fabricated content still passes) — see
// DESIGN.md §6.2 step 1 and GAPS.md #4.
const MAX_LENGTH_EXPANSION = 2; // text may be at most this many times longer than its claimed source
// Deliberately loose: a short claimed excerpt can lose a large FRACTION of
// its shingles to a single small edit (inserting one word near the middle
// of a 12-word text can shift half its 5-word windows) even though it is
// obviously still substantially the same content. The length-ratio check
// above is the primary defense against the "large fabricated payload"
// shape this exists to catch; this is a secondary, coarser check for
// same-sized-but-unrelated text.
const MIN_SOURCE_COVERAGE = 0.3; // fraction of text's own shingles that must trace back to the source

export function createQuarantine(impl: QuarantineImpl, registry: TaintRegistry, raiseToDerivedUntrusted: (tag: ProvenanceTag) => void): QuarantineFn {
  return async function summarize<S = string>(text: string, opts: QuarantineOpts<S>): Promise<QuarantineResult<S>> {
    const sourceRecord = registry.getById(opts.sourceTaintRecordId);
    if (!sourceRecord) {
      throw new QuarantineInputUnknownError(opts.sourceTaintRecordId);
    }

    if (exactHash(text) !== sourceRecord.id) {
      if (text.length > sourceRecord.fingerprint.length * MAX_LENGTH_EXPANSION) {
        throw new QuarantineInputMismatchError(opts.sourceTaintRecordId);
      }
      const inputFingerprint = buildFingerprint(text);
      const coverage =
        inputFingerprint.shingleHashes.length === 0
          ? 0
          : shingleIntersectionSize(inputFingerprint.shingleHashes, sourceRecord.fingerprint.shingleHashes) / inputFingerprint.shingleHashes.length;
      if (coverage < MIN_SOURCE_COVERAGE) {
        throw new QuarantineInputMismatchError(opts.sourceTaintRecordId);
      }
    }

    const implOpts: { instructions?: string; schema?: { parse(x: unknown): S } } = {};
    if (opts.instructions !== undefined) implOpts.instructions = opts.instructions;
    if (opts.schema !== undefined) implOpts.schema = opts.schema;
    const value = await impl<S>(text, implOpts);
    const outText = toRegistrableText(value);

    // The broker's own code — not the summarizing LLM — unconditionally
    // registers the result. This edge cannot be suppressed or spoofed even
    // if the quarantine call itself is prompt-injected, because
    // registration happens after impl() returns, in broker-controlled code
    // (§6.2 step 3).
    const provenance: ProvenanceTag = {
      id: exactHash(outText),
      sourceCallId: `quarantine:${randomUUID()}`,
      toolName: '__tttb_summarize',
      sessionId: opts.sessionId,
      capturedAt: Date.now(),
      note: `derived from ${sourceRecord.id}`,
    };
    const record = registry.register(outText, provenance, 'DERIVED_UNTRUSTED', sourceRecord.sensitivity, [sourceRecord.id]);

    // §6.2 step 4: raises the scope watermark to at least DERIVED_UNTRUSTED
    // — never all the way back to CLEAN. The quarantine path buys a lower
    // tier, not a clean bill of health, and (being monotonic, §4.1) cannot
    // undo an already-RAW_UNTRUSTED scope.
    raiseToDerivedUntrusted(provenance);

    return { text: outText, value, taintRecordId: record.id, level: 'DERIVED_UNTRUSTED' };
  };
}

/** The default when no quarantineImpl is configured: fails loudly rather than silently no-op'ing a security-relevant path. */
export const unconfiguredQuarantineImpl: QuarantineImpl = async () => {
  throw new Error(
    'broker.summarize() was called but no quarantineImpl was configured. Pass { quarantineImpl } to createBroker() — ' +
      'TTTB ships no default LLM call; the quarantine step is a capability-less LLM invocation your integration must supply. See DESIGN.md §6.2.',
  );
};
