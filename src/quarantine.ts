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
import { buildFingerprint, exactHash, overlapCoefficient } from './taint/fingerprint.js';
import { QuarantineInputMismatchError, QuarantineInputUnknownError } from './errors.js';

// Deliberately loose: a real summarize() call may legitimately use only a
// slice of the source. This only catches "claims a source it bears no
// relation to at all" abuse — it is not a spoofing-proof check. See
// DESIGN.md §6.2 step 1 and GAPS.md #4.
const MIN_OVERLAP_WITH_CLAIMED_SOURCE = 0.15;

export function createQuarantine(impl: QuarantineImpl, registry: TaintRegistry, raiseToDerivedUntrusted: (tag: ProvenanceTag) => void): QuarantineFn {
  return async function summarize<S = string>(text: string, opts: QuarantineOpts<S>): Promise<QuarantineResult<S>> {
    const sourceRecord = registry.getById(opts.sourceTaintRecordId);
    if (!sourceRecord) {
      throw new QuarantineInputUnknownError(opts.sourceTaintRecordId);
    }

    if (exactHash(text) !== sourceRecord.id) {
      const inputFingerprint = buildFingerprint(text);
      const overlap = overlapCoefficient(inputFingerprint.shingleHashes, sourceRecord.fingerprint.shingleHashes);
      if (overlap < MIN_OVERLAP_WITH_CLAIMED_SOURCE) {
        throw new QuarantineInputMismatchError(opts.sourceTaintRecordId);
      }
    }

    const implOpts: { instructions?: string; schema?: { parse(x: unknown): S } } = {};
    if (opts.instructions !== undefined) implOpts.instructions = opts.instructions;
    if (opts.schema !== undefined) implOpts.schema = opts.schema;
    const value = await impl<S>(text, implOpts);
    const outText = typeof value === 'string' ? value : JSON.stringify(value);

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
