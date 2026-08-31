/**
 * A single value's taint provenance, packaged for handoff across a
 * process/service boundary where this broker's own live `TaintScope`/
 * `TaintRegistry` is not reachable — a downstream microservice, a database
 * row, a UI a human reviews.
 *
 * `persistence.ts` already solves the two adjacent serialization problems:
 * `serializeBrokerState()`/`restoreBrokerState()` move a WHOLE broker's
 * state (watermark, registry, declared plan) across a boundary (GAPS.md
 * #12), and `serializeAuditEvent()` makes a WHOLE `AuditEvent` JSON-safe for
 * a durable log/log shipper. Neither is purpose-built for "attach what THIS
 * one value's taint status was, right now, to the specific downstream
 * payload it is riding along with" — an integrator wanting that currently
 * has to hand-assemble it from a `TaintContext` themselves, including
 * rediscovering the same `bigint`/`Uint32Array` fingerprint fields
 * `persistence.ts`'s own header already documents as a JSON-safety trap.
 *
 * `createTaintEnvelope(value, taint)` below closes that gap: it packages
 * `value` together with a JSON-safe snapshot of the `TaintContext` that was
 * in hand for it — most directly, `ToolCallBlockedError.taint` (`errors.ts`)
 * from a call `broker.call()` just blocked or quarantined, but equally any
 * other `TaintContext` an integrator has in scope (a `PolicyFn`'s own
 * parameter, an `AuditEvent.taint` pulled back out of an `AuditSink`). It
 * reuses `persistence.ts`'s own `serializeTaintRecord()` conversion for the
 * fingerprint fields rather than a third independently-maintained copy of
 * the same mapping — see that function's own doc comment.
 *
 * **Deliberately one-way**, matching `serializeAuditEvent()`'s stance, not
 * `serializeRegistry()`'s: a `TaintEnvelope` is for EXTERNAL consumption, not
 * something this library ever reconstructs a live scope/registry FROM. There
 * is no `restoreTaintEnvelope()` — restoring a broker's state across a
 * process boundary is already `restoreBrokerState()`'s job, and an envelope
 * carries far less than a full registry export would need for that anyway
 * (this one value's matched records, not the registry's whole corpus). An
 * integrator who wants the downstream side to be able to reason further
 * about this value's provenance reads the envelope's fields directly; they
 * do not feed it back into `createBroker()`.
 */

import type { TaintContext, TaintLevel } from './types.js';
import { serializeTaintRecord, type SerializedTaintMatch } from './persistence.js';

/**
 * A value plus a portable, JSON-safe snapshot of its taint provenance at the
 * moment `createTaintEnvelope()` was called — see this file's header for
 * what this is for and how it differs from `SerializedBrokerState`/
 * `SerializedAuditEvent` (`persistence.ts`).
 *
 * Field names deliberately mirror `TaintContext`'s own (`scopeLevel`,
 * `privateDataSeen`, `matchedRecords`, `scopeId`) rather than inventing
 * parallel names for the same concepts — an integrator already familiar
 * with `TaintContext` should recognize this shape immediately.
 * `argFingerprintFloor`/`sinkClass`/`hasUnattributedSubstantialContent` are
 * deliberately NOT carried over: those describe the specific CALL a
 * `TaintContext` was computed for (which sink class it was about to hit,
 * how Layer 2 would have tightened that one decision), not `value`'s own
 * taint story, which is what an envelope is scoped to.
 */
export interface TaintEnvelope<T = unknown> {
  /**
   * The payload being handed off. Carried through completely unchanged — this
   * module never clones, redacts, or otherwise inspects it, the same "not
   * this library's concern" stance `serializeAuditEvent()`'s own doc comment
   * already takes for `AuditEvent.call.args`. If `value` itself needs to be
   * JSON-safe (e.g. it contains a `bigint` from some other source), that is
   * the caller's responsibility — `jsonSafeClone()` (`json-safe-clone.ts`) is
   * available for exactly that if a defensive, JSON-safe copy is wanted
   * before or after wrapping it here.
   */
  value: T;
  /** `TaintContext.scopeLevel` at capture time — see that field's own doc comment (types.ts). */
  scopeLevel: TaintLevel;
  /** `TaintContext.privateDataSeen` at capture time. */
  privateDataSeen: boolean;
  /** `TaintContext.matchedRecords`, JSON-safe — see `SerializedTaintMatch` (persistence.ts) for what the conversion touches. */
  matchedRecords: SerializedTaintMatch[];
  /**
   * `TaintContext.scopeId` at capture time, when the source `TaintContext`
   * carried one. Optional for the identical reason it's optional on
   * `TaintContext` itself (API stability for a field added after `1.0.0` —
   * see that field's own doc comment, types.ts): a hand-built `TaintContext`
   * fixture predating `scopeId` has none to copy, and this envelope should
   * not invent one.
   */
  scopeId?: string;
  /** `Date.now()` at the moment this envelope was built — when the snapshot below was taken, not when `value` itself was produced (that provenance, if any, lives inside `matchedRecords[].record.provenance.capturedAt`). */
  capturedAt: number;
  /** A human-readable, one-line rendering of the fields above — see `summarizeTaintContext()` below. Not meant to be parsed; a durable consumer should read the structured fields instead. */
  summary: string;
}

/**
 * Renders a `TaintContext` into the one-line `summary` every `TaintEnvelope`
 * carries — a smaller-scoped sibling of `debug.ts`'s `formatAuditTrail()`/
 * `explainWatermark()` (same "readable, timestamp-free, one line" register),
 * not a call into either: both of those render a whole `AuditEvent[]` or a
 * live `TaintScope`, neither of which this function has — a standalone
 * `TaintContext` is all `createTaintEnvelope()` is ever given. Kept private
 * to this module rather than exported: nothing outside `createTaintEnvelope()`
 * currently needs a bare one-line `TaintContext` summary on its own.
 */
function summarizeTaintContext(taint: TaintContext): string {
  const privateNote = taint.privateDataSeen ? '; private data seen' : '';
  if (taint.matchedRecords.length === 0) {
    return `${taint.scopeLevel}${privateNote}; no fingerprint matches`;
  }
  const matchList = taint.matchedRecords
    .map(
      (match) =>
        `${match.matchType} match on "${match.record.provenance.toolName}" @ ${match.argPath}`,
    )
    .join(', ');
  return (
    `${taint.scopeLevel}${privateNote}; ${taint.matchedRecords.length} fingerprint ` +
    `match${taint.matchedRecords.length === 1 ? '' : 'es'}: ${matchList}`
  );
}

/**
 * Packages `value` with a JSON-safe snapshot of `taint` — see this file's
 * header for what this is for. Typical use, catching a blocked/quarantined
 * call and handing the envelope to a downstream boundary:
 *
 *   try {
 *     await shellExec.execute({ cmd });
 *   } catch (err) {
 *     if (err instanceof ToolCallBlockedError) {
 *       const envelope = createTaintEnvelope(err.call.args, err.taint);
 *       await downstreamQueue.publish(JSON.stringify(envelope));
 *     }
 *   }
 *
 * Pure: never mutates `taint`, never touches a broker/registry/watermark,
 * and (like `serializeAuditEvent()`) has no restore-side counterpart — see
 * this file's header for why. `capturedAt` is stamped as `Date.now()`
 * inside this call, not read off `taint`, since a `TaintContext` carries no
 * timestamp of its own (individual `matchedRecords[].record.provenance`
 * entries do, but a `TaintContext` as a whole is a point-in-time decision
 * snapshot, not a provenance record).
 */
export function createTaintEnvelope<T>(value: T, taint: TaintContext): TaintEnvelope<T> {
  return {
    value,
    scopeLevel: taint.scopeLevel,
    privateDataSeen: taint.privateDataSeen,
    matchedRecords: taint.matchedRecords.map((match) => ({
      ...match,
      record: serializeTaintRecord(match.record),
    })),
    ...(taint.scopeId !== undefined ? { scopeId: taint.scopeId } : {}),
    capturedAt: Date.now(),
    summary: summarizeTaintContext(taint),
  };
}
