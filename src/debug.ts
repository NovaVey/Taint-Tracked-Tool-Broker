/**
 * Debugging & observability helpers built entirely over data this library
 * already collects — no new tracking, no new mechanism (GAPS.md #25).
 *
 * Two real, previously-undocumented gaps motivate this file:
 *
 *   - There was no tooling to explain, in plain language, why a session got
 *     gated the way it did. `AuditEvent` (`types.ts`) and
 *     `TaintWatermark.sources` (§4.1) were always faithfully populated, but
 *     rendering either into something a human can read at a glance meant
 *     hand-correlating raw objects yourself. `formatAuditTrail()` and
 *     `explainWatermark()` below are pure renderers over exactly that
 *     already-collected data.
 *   - The default `AuditSink` an integrator gets by configuring nothing —
 *     including by following README.md's own Quick start verbatim, which
 *     calls `createBroker()` with no `auditSink` at all — is `broker.ts`'s
 *     `NOOP_AUDIT`, a silent no-op. Every gated decision this library makes
 *     is still enforced correctly either way (auditing is observability,
 *     never part of the gate itself), but an integrator who never
 *     configures one gets a broker that works exactly as documented and
 *     produces zero audit trail, with nothing surfacing that fact. See
 *     `AuditSink`'s own doc comment (`types.ts`) and README.md's Core model
 *     section, both updated alongside this file to name it explicitly.
 *
 * `AggregatingAuditSink` is a third, narrower piece: a small,
 * dependency-free `AuditSink` that turns a stream of `AuditEvent`s into
 * plain arithmetic counters — see its own doc comment for what it tracks
 * and why it ships no metrics/telemetry dependency of its own.
 */

import type { AuditEvent, AuditSink, PolicyDecision, TaintScope } from './types.js';

/**
 * Best-effort, human-legible rendering of `event.call.args` for one line of
 * `formatAuditTrail()`'s output. Deliberately NOT the same contract as
 * `serializeAuditEvent()` (`persistence.ts`), which exists to make a
 * *whole* `AuditEvent` losslessly round-trippable through `JSON.stringify`
 * (a durable-log / cross-process concern) — this only needs one short,
 * readable summary string per event for a terminal/log line, so a `bigint`
 * is rendered inline via a `JSON.stringify` replacer (mirroring
 * `serializeAuditEvent()`'s own bigint-to-decimal-string convention)
 * instead of throwing, and anything `JSON.stringify` still can't handle (a
 * circular object, most obviously — `call.args` is under the calling
 * integrator's own tool's control, not this library's, so it is not
 * guaranteed JSON-safe at all; see `SerializedAuditEvent`'s own doc
 * comment, `persistence.ts`) degrades to a fixed placeholder rather than
 * aborting the whole trail over one unrenderable event.
 *
 * `call.args` reaches here exactly as it reached `AuditSink.record()` —
 * unredacted, unless the caller already configured
 * `BrokerOptions.redactAuditArgs` upstream, or filtered/mapped `events`
 * before calling `formatAuditTrail()` themselves. This function applies no
 * redaction of its own; it renders whatever `AuditEvent`s it is handed.
 */
function summarizeArgs(args: unknown, maxLength = 100): string {
  let text: string;
  try {
    text =
      JSON.stringify(args, (_key, value) =>
        typeof value === 'bigint' ? `${value.toString()}n` : (value as unknown),
      ) ?? String(args);
  } catch {
    text = '[unrenderable args]';
  }
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
}

/** Every `PolicyDecision` variant but plain `ALLOW` carries a `reason` — see `types.ts`'s `PolicyDecision` union. */
function reasonOf(decision: PolicyDecision): string | undefined {
  return decision.action === 'ALLOW' ? undefined : decision.reason;
}

function formatOneEvent(event: AuditEvent): string {
  const timestamp = new Date(event.at).toISOString();
  const args = summarizeArgs(event.call.args);
  const executedNote = event.executed ? ', executed' : '';
  const reason = reasonOf(event.verdict);
  const reasonNote = reason !== undefined ? ` — reason: "${reason}"` : '';
  return (
    `${timestamp}  ${event.call.toolName}(${args}) -> ${event.verdict.action}` +
    ` [scope: ${event.taint.scopeLevel}${executedNote}]${reasonNote}`
  );
}

/**
 * Renders a session's `AuditEvent`s as readable, timestamped,
 * one-line-per-event plain-language prose — "what actually happened, and
 * why," for a human staring at a gated/blocked session, without having to
 * hand-correlate raw `AuditEvent` objects themselves. Pure and
 * side-effect-free: `events` is read only, never mutated, and this never
 * touches a live broker/registry/watermark — it works identically over a
 * live `AuditSink`'s captured events, a durable log read back later, or
 * `AuditEvent`s reconstructed via `serializeAuditEvent()`'s round trip.
 *
 * One line per event, in the order given (typically arrival/`at` order,
 * since that is how a real `AuditSink.record()` receives them — this
 * function does not itself sort): an ISO-8601 timestamp (`event.at`), the
 * tool name and a best-effort argument summary (`summarizeArgs()` above —
 * truncated, never throwing), the verdict action, the scope watermark
 * level the decision was made against (`event.taint.scopeLevel`), whether
 * the call actually executed, and — for every verdict but plain `ALLOW`,
 * which carries none — the policy's own `reason` text. Deliberately does
 * NOT render `event.taint.matchedRecords`/`argFingerprintFloor`/
 * `hasUnattributedSubstantialContent` or `event.call.sessionId`/`id`: this
 * is a skimmable one-line-per-event overview, not a full field dump — an
 * integrator who needs the full `TaintContext` for one specific event
 * still has the real `AuditEvent` object this was built from.
 *
 * An empty `events` list renders as a single explanatory line rather than
 * an empty string, so a caller piping this straight to a log/terminal
 * never sees blank output that looks like something went wrong.
 */
export function formatAuditTrail(events: readonly AuditEvent[]): string {
  if (events.length === 0) return '(no audit events)';
  return events.map(formatOneEvent).join('\n');
}

/**
 * Renders `scope.watermark.sources` — the `ProvenanceTag[]` every watermark
 * raise already appends to (`taint/scope.ts`'s `raiseWatermark()`,
 * DESIGN.md §4.1) — into one or a few human-readable sentences explaining
 * WHY the current watermark level is what it is: which tool call(s) raised
 * it, and when. Purely a renderer over data this library already
 * faithfully tracks on every scope; it introduces no new tracking, and
 * reading it never mutates `scope` (GAPS.md #25).
 *
 * `sources` is an append-only history of every raise call site that
 * supplied a `ProvenanceTag` — an ordinary source-tool call
 * (`sourceCallId` is the real `ToolCall.id`), or one of
 * `markContextExposure()`'s three specializations (`sourceCallId` is a
 * synthetic `context-exposure:<uuid>`, `broker.ts`) — and it is NOT
 * deduplicated by level: a later exposure that doesn't actually raise the
 * level past what an earlier one already reached is still appended
 * (`raiseWatermark()` pushes `tag` unconditionally whenever one is
 * supplied, `taint/scope.ts`). This function reports the whole history —
 * "raised by N exposure(s)" when there is more than one — rather than
 * naming only whichever tag happened to be first to reach the final
 * level, since a human debugging a gated call usually wants to know
 * everything that contributed to the current level, not just the
 * technically-earliest cause.
 */
export function explainWatermark(scope: TaintScope): string {
  const { level, sources, privateDataSeen } = scope.watermark;

  if (sources.length === 0) {
    const base =
      level === 'CLEAN'
        ? `Scope "${scope.id}" watermark is CLEAN — no untrusted content has been read in this scope yet.`
        : `Scope "${scope.id}" watermark is ${level}, but no individual tool call is recorded as the ` +
          'source: it was raised with no ProvenanceTag attached (an internal raiseWatermark() call with no ' +
          'tag), not through an ordinary source-tool call or markContextExposure().';
    return privateDataSeen
      ? `${base} Private data has also been read in this scope, which escalates (never gates on its own) ` +
          'EXFIL/MUTATE sink decisions — DESIGN.md §7.2.'
      : base;
  }

  const sentences: string[] = [];
  if (sources.length === 1) {
    const source = sources[0]!;
    const at = new Date(source.capturedAt).toISOString();
    sentences.push(
      `Scope "${scope.id}" watermark is ${level} because tool call "${source.toolName}" ` +
        `(call ${source.sourceCallId}) exposed untrusted content at ${at}` +
        `${source.note ? ` — ${source.note}` : ''}.`,
    );
  } else {
    const first = sources[0]!;
    const last = sources[sources.length - 1]!;
    const toolNames = [...new Set(sources.map((source) => source.toolName))];
    const toolsPhrase =
      toolNames.length === 1
        ? `tool "${toolNames[0]}"`
        : `tools ${toolNames.map((name) => `"${name}"`).join(', ')}`;
    sentences.push(
      `Scope "${scope.id}" watermark is ${level}, raised by ${sources.length} exposure(s) from ${toolsPhrase}: ` +
        `first "${first.toolName}" (call ${first.sourceCallId}) at ${new Date(first.capturedAt).toISOString()}, ` +
        `most recently "${last.toolName}" (call ${last.sourceCallId}) at ${new Date(last.capturedAt).toISOString()}.`,
    );
  }

  if (privateDataSeen) {
    sentences.push(
      'Private data has also been read in this scope, which escalates (never gates on its own) EXFIL/MUTATE ' +
        'sink decisions — DESIGN.md §7.2.',
    );
  }

  return sentences.join(' ');
}

/**
 * Small, dependency-free `AuditSink` that accumulates plain arithmetic
 * counters over the `AuditEvent`s it sees — a metrics-from-audit-events
 * utility closing the observability half of GAPS.md #25 (the explaining
 * half being `formatAuditTrail()`/`explainWatermark()` above): without
 * this, an integrator wanting "how many calls were blocked," "what's our
 * REQUIRE_APPROVAL grant rate," or "how long is approval actually taking"
 * has to build it themselves over raw `AuditEvent`s. Ships no
 * metrics/telemetry dependency at all — `package.json` has none, and this
 * file adds none — `snapshot()` returns a plain `Record<string, number>`
 * an integrator renders however their own stack wants (a hand-built
 * Prometheus text-exposition line, a Datadog client call, a plain log
 * line), matching this library's zero-runtime-dependency design
 * principle (README.md's "Install" section).
 *
 * Wraps an optional `delegate` `AuditSink`: every `record()` call both
 * updates this sink's own counters AND forwards the event to `delegate`
 * unchanged (if one was supplied) — so this can be dropped in as
 * `createBroker({ auditSink: new AggregatingAuditSink(myRealSink) })`
 * without giving up whatever `myRealSink` already does, the same
 * "wrap, don't replace" shape `broker.ts`'s own internal
 * `withRedactedAuditArgs()` already uses for `BrokerOptions.redactAuditArgs`.
 * Omitting `delegate` is equally supported — a bare
 * `new AggregatingAuditSink()` is a metrics-only sink with nowhere else
 * `AuditEvent`s go.
 *
 * Counts tracked:
 *
 *   - Every `verdict.action` broken down by `taint.sinkClass`, as
 *     `verdict.<ACTION>.<SINK_CLASS>` keys in `snapshot()`'s output — but
 *     ONLY for combinations that have actually occurred; a combination
 *     that never happened has no key at all, not a key holding `0`.
 *     Deliberate: eagerly pre-populating every action × sink-class
 *     combination on every snapshot, most of which will never fire in a
 *     given deployment, would clutter every consumer's rendering far more
 *     than an absent key costs — an integrator building a Prometheus
 *     exposition already has to treat "this label combination has no
 *     samples yet" as the normal case for a counter that simply hasn't
 *     been emitted.
 *   - `requireApproval.granted` / `requireApproval.denied` — derived from
 *     `AuditEvent.executed` on `REQUIRE_APPROVAL` events specifically, per
 *     `AuditEvent.executed`'s own doc comment (`types.ts`): "Set when the
 *     underlying tool actually ran (ALLOW*, or REQUIRE_APPROVAL that was
 *     granted)" — so `executed` on a `REQUIRE_APPROVAL` event is exactly
 *     "was this granted."
 *   - `quarantineAndRetry.offered` — a count of `QUARANTINE_AND_RETRY`
 *     verdicts. Also reflected in the per-sinkClass breakdown above, but
 *     kept as its own fixed key too since it names one of this library's
 *     more load-bearing signals (DESIGN.md §7.2) — worth a stable key an
 *     integrator's dashboard doesn't have to reconstruct from the dynamic
 *     breakdown's key shape.
 *   - `requireApproval.latencyTotalMs` / `requireApproval.latencyAvgMs` —
 *     `event.at - event.requestedAt` (`AuditEvent.requestedAt`'s own
 *     documented latency computation, `types.ts`), summed/averaged across
 *     every `REQUIRE_APPROVAL` event that actually carries a
 *     `requestedAt`. This library's own dispatch path always sets
 *     `requestedAt` on that verdict (see that field's own doc comment),
 *     but it is typed optional for `1.0.0` API stability, so a hand-built
 *     `AuditEvent` fixture predating the field — or any `AuditEvent` fed
 *     to this sink from outside a real broker — is silently excluded from
 *     the latency average rather than corrupting it with a bogus
 *     `NaN`/negative subtraction. `latencyAvgMs` is `0` when no sample has
 *     landed yet, not `NaN` — dividing by a zero sample count would
 *     otherwise poison a naive consumer's dashboard the first time it
 *     renders before any `REQUIRE_APPROVAL` event has landed.
 *
 * `events.total` counts every `record()` call regardless of verdict —
 * including administrative events (`__tttb_declassify`,
 * `__tttb_turn_reset`, `__tttb_context_exposure`, `__tttb_summarize`,
 * `internal-audit.ts`'s reserved-name convention) exactly like any other
 * `AuditSink` receives them; this sink does not filter or special-case
 * those, matching `AuditSink.record()`'s own contract of "every audited
 * event, gated or administrative, reaches this."
 */
export class AggregatingAuditSink implements AuditSink {
  private readonly delegate: AuditSink | undefined;
  private eventsTotal = 0;
  private readonly verdictBySinkClass = new Map<string, number>();
  private requireApprovalGranted = 0;
  private requireApprovalDenied = 0;
  private requireApprovalLatencyTotalMs = 0;
  private requireApprovalLatencySamples = 0;
  private quarantineAndRetryOffered = 0;

  constructor(delegate?: AuditSink) {
    this.delegate = delegate;
  }

  record(event: AuditEvent): void {
    this.eventsTotal += 1;

    const key = `verdict.${event.verdict.action}.${event.taint.sinkClass}`;
    this.verdictBySinkClass.set(key, (this.verdictBySinkClass.get(key) ?? 0) + 1);

    if (event.verdict.action === 'REQUIRE_APPROVAL') {
      if (event.executed) {
        this.requireApprovalGranted += 1;
      } else {
        this.requireApprovalDenied += 1;
      }
      if (event.requestedAt !== undefined) {
        this.requireApprovalLatencyTotalMs += event.at - event.requestedAt;
        this.requireApprovalLatencySamples += 1;
      }
    } else if (event.verdict.action === 'QUARANTINE_AND_RETRY') {
      this.quarantineAndRetryOffered += 1;
    }

    this.delegate?.record(event);
  }

  /**
   * A flat, `Record<string, number>`-shaped point-in-time snapshot of every
   * counter above — safe to call repeatedly (never resets state, and
   * calling it has no effect on subsequent counting) and cheap (proportional
   * to the number of DISTINCT verdict/sinkClass combinations seen, not the
   * number of events — nothing here re-scans a stored event list, since
   * none is kept; every counter above is updated incrementally in
   * `record()`). See this class's own doc comment for exactly which keys
   * are always present versus only present once a matching event has
   * occurred.
   */
  snapshot(): Record<string, number> {
    const snapshot: Record<string, number> = {
      'events.total': this.eventsTotal,
      'requireApproval.granted': this.requireApprovalGranted,
      'requireApproval.denied': this.requireApprovalDenied,
      'requireApproval.total': this.requireApprovalGranted + this.requireApprovalDenied,
      'requireApproval.latencyTotalMs': this.requireApprovalLatencyTotalMs,
      'requireApproval.latencyAvgMs':
        this.requireApprovalLatencySamples === 0
          ? 0
          : this.requireApprovalLatencyTotalMs / this.requireApprovalLatencySamples,
      'quarantineAndRetry.offered': this.quarantineAndRetryOffered,
    };
    for (const [key, count] of this.verdictBySinkClass) {
      snapshot[key] = count;
    }
    return snapshot;
  }
}
