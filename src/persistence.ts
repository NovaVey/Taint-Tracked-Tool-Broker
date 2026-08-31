/**
 * Cross-process / cross-agent persistence helpers (GAPS.md #12).
 *
 * Neither half of a broker's exportable state needs a database or special
 * runtime to survive a process boundary:
 *
 *   - `TaintWatermark` (broker.scope.watermark) is already a plain JSON-able
 *     object — level/privateDataSeen/sources are strings, a boolean, and an
 *     array of plain-field ProvenanceTags. `createBroker({ initialWatermark })`
 *     takes it directly; no helper is needed for this half.
 *   - `TaintRecord` is almost JSON-able, except two fields on its
 *     fingerprint: `simhash` is a `bigint` and `shingleHashes` is a
 *     `Uint32Array`, neither of which `JSON.stringify` round-trips. The
 *     functions below convert a registry's `entries()` to a JSON-safe shape
 *     and back via `restore()` — the registry deliberately never stores raw
 *     plaintext (only fingerprints derived from it), so restoring is always
 *     from exported records, never by re-deriving fingerprints from a text
 *     corpus the target process may not even have.
 *
 * What this does NOT solve (see GAPS.md #1, #12): a sub-agent, a spawned
 * worker, or a different tool ecosystem that independently reads content
 * this session wrote to a file/DB sees a **fresh, unmarked** read unless
 * that read itself goes through a broker seeded with this exported state.
 * Persistence moves one broker's state across a process boundary; it does
 * not, by itself, propagate taint to every downstream reader of written
 * content — that still requires the receiving side to actually restore and
 * use this state (or to call `markContextExposure()` itself).
 *
 * A third, narrower JSON-safety gotcha shares this file's fingerprint
 * conversion but is NOT about crossing a process boundary at all:
 * `AuditEvent.taint.matchedRecords[].record.fingerprint` (`types.ts`) can
 * carry the exact same `bigint`/`Uint32Array` fields the moment a gated
 * call's arguments fuzzy- or exact-match a previously-registered record —
 * which is precisely the ordinary, expected case for a real attack, not an
 * edge case. The single most obvious thing an integrator does with
 * `AuditSink.record(event)` — hand `event` to `JSON.stringify` directly, or
 * to any JSON-based log shipper (pino, Winston-JSON, a Datadog/CloudWatch
 * agent) — THROWS (`TypeError: Do not know how to serialize a BigInt`) on
 * the very first audited event carrying a fuzzy-matched record, not merely
 * mangles it the way `shingleHashes` alone would. `serializeAuditEvent()`
 * below closes this the same way `serializeRegistry()` closes it for a
 * registry export, reusing the identical per-record conversion (see
 * `AuditSink`'s own doc comment in `types.ts` for the integrator-facing
 * warning this fixes).
 *
 * A declared plan (`broker.declarePlan()`, DESIGN.md §11) DOES survive
 * `serializeBrokerState()`/`restoreBrokerState()`, including the exact
 * cursor position it was at when exported — see
 * `SerializedBrokerState.plan`/`.planCursor` and `restoreBrokerState()`'s
 * own doc comment for the full mechanism and the safety-property argument
 * (restoring a plan, even a tampered one, can only ever make future
 * privileged calls MORE restrictive, never less). This closes the
 * plan-persistence sub-gap GAPS.md #12 and DESIGN.md §11 used to describe
 * here as unimplemented — a broker restored from another's exported state
 * now resumes any live plan-freeze protection exactly where the original
 * left off, instead of silently starting with plan-freeze disengaged and
 * no way to re-establish it (the old behavior `test/persistence.spec.ts`
 * used to pin down as a known gap now pins down the fix instead).
 *
 * One more piece of private in-memory state falls into the same
 * "not part of SerializedBrokerState" category as the declared plan above:
 * `resetScope: 'turn-decay'` mode's internal `turnsSinceExposure` counter
 * (broker.ts) — how many turns have elapsed since the watermark was last
 * raised, counted toward `turnDecayWindow` before the watermark auto-clears.
 * It is not exported, so a broker restored via `restoreBrokerState()`
 * always starts that counter at 0, exactly as if the watermark had just
 * been raised on THIS broker, even if the original was most of the way
 * through its decay window. Unlike the plan-freeze gap, this is NOT a
 * security regression: restarting the counter at 0 can only make the
 * restored broker wait a full fresh `turnDecayWindow` before the watermark
 * clears — strictly more conservative than the original, never less, so it
 * cannot reopen a gate early. It is purely a usability surprise for an
 * integrator combining `resetScope: 'turn-decay'` with persistence — the
 * decay clock silently restarts across a restore, with no warning.
 */

import type {
  AuditEvent,
  PlanState,
  PlanStep,
  TaintContext,
  TaintMatch,
  TaintRecord,
  TaintRegistry,
  TaintWatermark,
  ToolCallBroker,
} from './types.js';
import { LEVEL_ORDER } from './types.js';
import { InMemoryTaintRegistry } from './taint/registry.js';
import { TaintBrokerError } from './errors.js';

/** JSON-safe encoding of a TaintRecord's fingerprint — see the file header for why bigint/Uint32Array need explicit conversion. */
export interface SerializedTaintRecord extends Omit<TaintRecord, 'fingerprint'> {
  fingerprint: {
    exactHash: string;
    /** `Fingerprint.simhash` (a bigint), stringified in decimal. */
    simhash: string;
    /** `Fingerprint.shingleHashes` (a Uint32Array) as a plain number array. */
    shingleHashes: number[];
    length: number;
  };
}

/**
 * The current `SerializedBrokerState` wire-format version —
 * `serializeBrokerState()` always stamps its output with this. A plain,
 * monotonically-incrementing integer, not a semver string: this versions
 * ONE specific interchange shape (`SerializedBrokerState`), not this
 * package's own semver (`package.json`'s `version`), which tracks the
 * whole library's public API surface and would change for reasons having
 * nothing to do with this wire format. Bump this — and give
 * `restoreBrokerState()` a real value to branch on — the next time
 * `SerializedBrokerState`'s shape changes in a way that isn't safely
 * backward-compatible on its own; see `schemaVersion`'s own doc comment
 * below for why version 1 itself didn't need a hard compatibility check.
 */
export const SERIALIZED_BROKER_STATE_SCHEMA_VERSION = 1;

/** Everything `serializeBrokerState()` exports: a broker's scope watermark, registry, and (if any) declared plan, as one JSON-safe object. */
export interface SerializedBrokerState {
  /**
   * Wire-format version marker — see `SERIALIZED_BROKER_STATE_SCHEMA_VERSION`.
   * Optional on the TYPE, but not because a state THIS library produces
   * ever omits it: `serializeBrokerState()` always sets it. It's optional
   * because every `SerializedBrokerState` this library exported *before*
   * this field (and the `plan`/`planCursor` fields below) existed — any
   * 0.x-series blob, from before plan-freeze persistence shipped — has no
   * such field at all, and `restoreBrokerState()` must keep accepting
   * those unchanged.
   *
   * A missing `schemaVersion` is therefore not an error — it's the one
   * signal `restoreBrokerState()` has that `state` predates this field
   * altogether, and it is treated exactly as `schemaVersion: 0` would be:
   * "no plan was ever exported" (on a genuinely old blob, `plan`/
   * `planCursor` are — and always were — absent too), which is precisely
   * the safe no-op `restoreBrokerState()` already performed before this
   * feature existed: watermark/registry restore as before, plan-freeze
   * simply starts disengaged. This is why `plan`/`planCursor` are
   * themselves optional too, rather than this field being required to opt
   * out of them: an old blob restoring "no plan" needs no explicit marker
   * for that, it's simply the shape it already had.
   *
   * Exists so THIS extension — and any future one — has something to
   * actually version against, rather than repeating the "add an optional
   * field and hope every consumer copes" pattern with no anchor at all. A
   * future breaking wire-format change can bump
   * `SERIALIZED_BROKER_STATE_SCHEMA_VERSION` and give `restoreBrokerState()`
   * a real value to branch its handling on, instead of trying to infer
   * intent purely from which optional fields happen to be present.
   * Version 1 (this one) doesn't itself need a hard version check —
   * `plan`/`planCursor` are purely additive and every consumer old enough
   * to predate them simply doesn't look for them — but the marker is laid
   * down now specifically so the NEXT change doesn't have to invent it
   * under time pressure.
   */
  schemaVersion?: number;
  watermark: TaintWatermark;
  registry: SerializedTaintRecord[];
  /**
   * The declared plan (`broker.declarePlan()`, DESIGN.md §11) captured at
   * export time, or absent if the exporting broker had none in effect —
   * mirroring `Broker`'s own private `plan` field, `undefined` in exactly
   * the same circumstances (never declared, or discarded by a turn reset
   * or `declassify()` — see broker.ts's `clearScopeForTurnReset()`/
   * `declassify()`, both of which drop a plan alongside the watermark it
   * was committed against). Restoring `plan` resumes it on the receiving
   * broker at the SAME cursor position captured in `planCursor` below —
   * not from step 0 — matching what "resuming a session" should mean; see
   * `restoreBrokerState()`'s own doc comment for the full mechanism and
   * the safety-property argument for why this is sound even for a
   * tampered `plan`.
   */
  plan?: PlanStep[];
  /**
   * The plan's cursor position at export time: the index into `plan` of
   * the next step a privileged call must match (`plan.length` once the
   * plan had already been fully consumed). Meaningless without `plan` —
   * `validateSerializedBrokerState()` rejects a `planCursor` present
   * without a `plan` as malformed rather than silently ignoring it, and
   * bounds it to a non-negative integer no greater than `plan.length`
   * when `plan` IS present. `restoreBrokerState()` defaults this to `0`
   * only for the (non-`serializeBrokerState()`-produced) case of a `plan`
   * present with this field itself absent, matching "nothing consumed
   * yet" — `serializeBrokerState()` itself always writes both together.
   */
  planCursor?: number;
}

/**
 * Thrown by `restoreBrokerState()` when `state` does not actually have the
 * shape of a `SerializedBrokerState`.
 *
 * `state` typically arrives via `JSON.parse()` (see this file's header for
 * the sanctioned `const state: SerializedBrokerState = JSON.parse(...)`
 * usage) — and `JSON.parse()`'s return type is `any`, so TypeScript trusts
 * whatever shape comes back with zero runtime check. Without this
 * validation, a hand-edited, corrupted, or version-skewed `session.json`
 * (e.g. a `watermark.level` string from a future/renamed `TaintLevel`, or
 * plain file corruption) would restore "successfully" and produce a broker
 * that looks fine until some LATER, entirely unrelated gated call reads
 * that bogus watermark and crashes with a raw, uncorrelated `TypeError`
 * deep inside `policy/default-policy.ts`'s `MATRIX[scopeLevel][sinkClass]`
 * lookup (`MATRIX[undefined-key]` is `undefined`). That is exactly the
 * silent-now/opaque-crash-later failure mode this codebase otherwise
 * refuses to allow anywhere else — compare `createBroker()`'s own
 * `turnDecayWindow` `RangeError` (broker.ts), or `QuarantineInputUnknownError`.
 * Validating here, at restore time, turns that into an immediate,
 * descriptive, catchable error that points straight at the corrupt input
 * instead of at whatever tool call happens to run next.
 */
export class InvalidBrokerStateError extends TaintBrokerError {
  constructor(reason: string) {
    super(
      `restoreBrokerState() was given a value that is not a valid SerializedBrokerState: ${reason}. This usually ` +
        "means a hand-edited, corrupted, or version-skewed session.json — see this file's header for the sanctioned " +
        'JSON.parse() usage. Restoring it anyway would silently produce a broker whose watermark crashes some later, ' +
        'unrelated gated call with an opaque TypeError instead of failing here, at the point of restore.',
    );
    this.name = 'InvalidBrokerStateError';
  }
}

const VALID_TAINT_LEVELS = new Set<string>(Object.keys(LEVEL_ORDER));

function isTaintLevel(value: unknown): value is TaintWatermark['level'] {
  return typeof value === 'string' && VALID_TAINT_LEVELS.has(value);
}

/**
 * Cheap, structural runtime check that `state` actually has the shape
 * `SerializedBrokerState` claims at compile time — see
 * `InvalidBrokerStateError` for why this exists. This is deliberately NOT a
 * full schema validator (it does not, for instance, walk every registry
 * record's fingerprint fields): it checks the top-level shape and, in
 * particular, that `watermark.level` is one of the three real `TaintLevel`
 * strings, since that is the field whose corruption produces the delayed,
 * opaque `TypeError` described above. Throws `InvalidBrokerStateError` on
 * the first problem found; returns normally (no return value) when `state`
 * is safe to hand to `restoreRegistry()` / `createBroker({ initialWatermark })`.
 */
function validateSerializedBrokerState(state: SerializedBrokerState): void {
  if (state === null || typeof state !== 'object') {
    throw new InvalidBrokerStateError(
      `expected an object, got ${state === null ? 'null' : typeof state}`,
    );
  }
  const watermark: unknown = (state as { watermark?: unknown }).watermark;
  if (watermark === null || typeof watermark !== 'object') {
    throw new InvalidBrokerStateError(
      `"watermark" must be an object, got ${watermark === null ? 'null' : typeof watermark}`,
    );
  }
  const { level, privateDataSeen, sources } = watermark as Record<string, unknown>;
  if (!isTaintLevel(level)) {
    const validLevels = Object.keys(LEVEL_ORDER)
      .map((l) => `"${l}"`)
      .join(', ');
    throw new InvalidBrokerStateError(
      `"watermark.level" must be one of ${validLevels}, got ${JSON.stringify(level)}`,
    );
  }
  if (typeof privateDataSeen !== 'boolean') {
    throw new InvalidBrokerStateError(
      `"watermark.privateDataSeen" must be a boolean, got ${typeof privateDataSeen}`,
    );
  }
  if (!Array.isArray(sources)) {
    throw new InvalidBrokerStateError(
      `"watermark.sources" must be an array, got ${typeof sources}`,
    );
  }
  if (!Array.isArray((state as { registry?: unknown }).registry)) {
    throw new InvalidBrokerStateError(
      `"registry" must be an array, got ${typeof (state as { registry?: unknown }).registry}`,
    );
  }
  const schemaVersion: unknown = (state as { schemaVersion?: unknown }).schemaVersion;
  if (
    schemaVersion !== undefined &&
    (!Number.isInteger(schemaVersion) || (schemaVersion as number) < 0)
  ) {
    throw new InvalidBrokerStateError(
      `"schemaVersion" must be a non-negative integer if present, got ${JSON.stringify(schemaVersion)}`,
    );
  }
  // `plan`/`planCursor` (§11, GAPS.md #12's plan-persistence sub-gap): both
  // optional — absent on any pre-plan-persistence 0.x blob, or on a broker
  // that simply never declared a plan — but validated together, since a
  // cursor is meaningless without the plan it indexes into. See
  // SerializedBrokerState's own doc comments for the full field semantics.
  const plan: unknown = (state as { plan?: unknown }).plan;
  if (plan !== undefined) {
    if (!Array.isArray(plan)) {
      throw new InvalidBrokerStateError(
        `"plan" must be an array of plan steps, got ${typeof plan}`,
      );
    }
    plan.forEach((step: unknown, index: number) => {
      if (step === null || typeof step !== 'object' || Array.isArray(step)) {
        throw new InvalidBrokerStateError(
          `"plan[${index}]" must be an object with a "toolName" string, got ${JSON.stringify(step)}`,
        );
      }
      const { toolName, note } = step as Record<string, unknown>;
      if (typeof toolName !== 'string') {
        throw new InvalidBrokerStateError(
          `"plan[${index}].toolName" must be a string, got ${typeof toolName}`,
        );
      }
      if (note !== undefined && typeof note !== 'string') {
        throw new InvalidBrokerStateError(
          `"plan[${index}].note" must be a string if present, got ${typeof note}`,
        );
      }
    });
  }
  const planCursor: unknown = (state as { planCursor?: unknown }).planCursor;
  if (planCursor !== undefined) {
    if (plan === undefined) {
      throw new InvalidBrokerStateError(
        '"planCursor" is present without "plan" — a cursor position is meaningless without the plan it indexes into',
      );
    }
    if (!Number.isInteger(planCursor) || (planCursor as number) < 0) {
      throw new InvalidBrokerStateError(
        `"planCursor" must be a non-negative integer, got ${JSON.stringify(planCursor)}`,
      );
    }
    if ((planCursor as number) > (plan as unknown[]).length) {
      throw new InvalidBrokerStateError(
        `"planCursor" (${planCursor as number}) must not exceed "plan"'s length (${(plan as unknown[]).length})`,
      );
    }
  }
}

/**
 * Converts one `TaintRecord` to its JSON-safe `SerializedTaintRecord` shape —
 * the one place that actually knows how to turn `fingerprint.simhash`
 * (`bigint`) and `fingerprint.shingleHashes` (`Uint32Array`) into JSON-safe
 * values. Factored out of `serializeRegistry()` (the original, and still the
 * primary, caller) so `serializeAuditEvent()` below can reuse the identical
 * conversion for a `TaintRecord` reached via `AuditEvent.taint.matchedRecords`
 * instead of via `TaintRegistry.entries()`, rather than a second,
 * independently-maintained copy of the same three-field mapping drifting out
 * of sync with this one. Exported (module-level only — not re-exported from
 * `src/index.ts`, the same "internal cross-module reuse, not public API"
 * convention `internal-audit.ts`'s `trivialTaintContext()` already uses) so
 * `envelope.ts`'s `createTaintEnvelope()` can reuse this exact conversion a
 * third time for a single `TaintMatch` reached via a standalone
 * `TaintContext`, instead of a third independently-maintained copy of the
 * same mapping.
 */
export function serializeTaintRecord(record: TaintRecord): SerializedTaintRecord {
  return {
    ...record,
    fingerprint: {
      exactHash: record.fingerprint.exactHash,
      simhash: record.fingerprint.simhash.toString(),
      shingleHashes: Array.from(record.fingerprint.shingleHashes),
      length: record.fingerprint.length,
    },
  };
}

/** Exports every record in `registry` to a JSON-safe array. Counterpart: restoreRegistry(). */
export function serializeRegistry(registry: TaintRegistry): SerializedTaintRecord[] {
  return registry.entries().map(serializeTaintRecord);
}

/** JSON-safe encoding of a `TaintMatch` — same idea as `SerializedTaintRecord`, one level up: only `record` needs conversion, `matchType`/`argPath`/`score` are already JSON-safe. */
export interface SerializedTaintMatch extends Omit<TaintMatch, 'record'> {
  record: SerializedTaintRecord;
}

/**
 * JSON-safe encoding of an `AuditEvent` — see this file's header for why
 * this is needed at all: `event.taint.matchedRecords[].record.fingerprint`
 * carries the same non-JSON-safe `simhash`/`shingleHashes` fields
 * `SerializedTaintRecord` exists to convert, and unlike the registry-export
 * path above, an `AuditEvent` reaches an integrator's own `AuditSink`
 * whether or not they ever call `serializeRegistry()`/`serializeBrokerState()`
 * at all — every gated call produces one. Every other `AuditEvent` field
 * (`verdict`, `call.id`/`toolName`/`sessionId`, `taint.scopeLevel`/
 * `argFingerprintFloor`/`privateDataSeen`/`sinkClass`/
 * `hasUnattributedSubstantialContent`/`scopeId`, `at`, `executed`,
 * `requestedAt`) is already a plain string/number/boolean/plain-object
 * value with no conversion need — see
 * `types.ts`'s `AuditEvent`/`TaintContext`/`ToolCall`/`PolicyDecision` for
 * the full shape. `call.args` is deliberately left untouched: it is
 * `unknown`, under the calling integrator's own tool's control, not this
 * library's — the same reasoning `BrokerOptions.cloneArgs`/
 * `NonCloneableArgsError` (`json-safe-clone.ts`) already applies to it
 * elsewhere; an integrator whose own tool args carry a non-JSON-safe value
 * needs their own handling for that, orthogonal to the gotcha this function
 * closes.
 */
export interface SerializedAuditEvent extends Omit<AuditEvent, 'taint'> {
  taint: Omit<TaintContext, 'matchedRecords'> & { matchedRecords: SerializedTaintMatch[] };
}

/**
 * Converts `event` into a JSON-safe `SerializedAuditEvent` — the fix for the
 * confirmed production footgun this file's header describes: `AuditSink`'s
 * own doc comment (`types.ts`) documents `JSON.stringify(event)` as unsafe
 * and points here. Typical use, mirroring `serializeRegistry()`'s own
 * `JSON.stringify(state)` idiom above:
 *
 *   const auditSink: AuditSink = {
 *     record(event) {
 *       console.log(JSON.stringify(serializeAuditEvent(event)));
 *     },
 *   };
 *
 * Deliberately returns a JSON-safe VALUE, not an already-stringified
 * `string` — consistent with `serializeRegistry()`/`serializeBrokerState()`
 * above, which do the same and leave the actual `JSON.stringify()` call to
 * the caller. That keeps this useful beyond a bare `console.log`: a caller
 * that wants pretty-printing (`JSON.stringify(x, null, 2)`), a replacer, or
 * to hand the object to a structured (not string) log sink can do so without
 * an unnecessary stringify-then-reparse round trip.
 *
 * Purely a converter — never mutates `event`, never touches the broker,
 * registry, or watermark, and (unlike `serializeRegistry()`/
 * `restoreRegistry()`) has no restore-side counterpart: an `AuditEvent` is a
 * one-way, write-only log record, not state a broker is ever reconstructed
 * from, so there is nothing to round-trip back INTO a `TaintRecord`/
 * `TaintRegistry` the way `restoreRegistry()` does for a genuine export.
 */
export function serializeAuditEvent(event: AuditEvent): SerializedAuditEvent {
  return {
    ...event,
    taint: {
      ...event.taint,
      matchedRecords: event.taint.matchedRecords.map((match) => ({
        ...match,
        record: serializeTaintRecord(match.record),
      })),
    },
  };
}

/**
 * Rehydrates `records` (as produced by serializeRegistry(), typically after
 * a round trip through `JSON.stringify`/`JSON.parse` across a process
 * boundary) into `into` — e.g. a fresh registry about to be handed to
 * `createBroker({ registry })`. Existing entries already in `into` that
 * aren't among `records` are left alone; an id present in both is replaced
 * in place (see `TaintRegistry.restore()`).
 */
export function restoreRegistry(
  records: readonly SerializedTaintRecord[],
  into: TaintRegistry,
): void {
  for (const record of records) {
    into.restore({
      ...record,
      fingerprint: {
        exactHash: record.fingerprint.exactHash,
        simhash: BigInt(record.fingerprint.simhash),
        shingleHashes: Uint32Array.from(record.fingerprint.shingleHashes),
        length: record.fingerprint.length,
      },
    });
  }
}

/**
 * Exports every persistable piece of a broker's state — its scope
 * watermark, its registry's records, and (if any) its declared plan
 * (`declarePlan()`, §11, via `broker.planState`) — as one JSON-safe
 * object, stamped with the current `SERIALIZED_BROKER_STATE_SCHEMA_VERSION`.
 * Pair with `restoreBrokerState()` on the receiving side. Typical use:
 *
 *   const state = serializeBrokerState(broker);
 *   await fs.writeFile('session.json', JSON.stringify(state));
 *
 * `plan`/`planCursor` are only present in the output when
 * `broker.planState` is defined (a plan is actually in effect) —
 * `serializeBrokerState()` never writes an empty/placeholder plan, exactly
 * mirroring `Broker`'s own `plan === undefined` "no plan declared" state.
 */
export function serializeBrokerState(
  broker: Pick<ToolCallBroker, 'scope' | 'registry' | 'planState'>,
): SerializedBrokerState {
  const planState = broker.planState;
  return {
    schemaVersion: SERIALIZED_BROKER_STATE_SCHEMA_VERSION,
    watermark: {
      level: broker.scope.watermark.level,
      privateDataSeen: broker.scope.watermark.privateDataSeen,
      sources: [...broker.scope.watermark.sources],
    },
    registry: serializeRegistry(broker.registry),
    ...(planState !== undefined
      ? {
          plan: planState.steps.map((step) => ({ ...step })),
          planCursor: planState.cursor,
        }
      : {}),
  };
}

/**
 * The other half of `serializeBrokerState()`: rehydrates a fresh registry
 * from `state.registry` and returns options ready to spread straight into
 * `createBroker()`:
 *
 *   const state: SerializedBrokerState = JSON.parse(await fs.readFile('session.json', 'utf8'));
 *   const broker = createBroker({ ...restoreBrokerState(state), auditSink });
 *
 * `makeRegistry` lets you restore into something other than a plain
 * `InMemoryTaintRegistry` — e.g. one configured with `maxEntries` (GAPS.md
 * #13) — and defaults to `() => new InMemoryTaintRegistry()`.
 *
 * `state` is validated at runtime before anything else happens — see
 * `InvalidBrokerStateError`. `state` typically arrived via `JSON.parse()`,
 * which TypeScript trusts at the declared `SerializedBrokerState` type with
 * no actual check; a malformed `watermark.level` (a corrupted or
 * version-skewed `session.json`) would otherwise pass through silently and
 * only surface as an opaque `TypeError` from deep inside
 * `policy/default-policy.ts` on some later, unrelated gated call. Throwing
 * here instead means restoring a bad state fails loud, immediately, with a
 * descriptive and catchable error — not a delayed crash on an unrelated
 * later call.
 *
 * **Plan-freeze restore (§11, GAPS.md #12's plan-persistence sub-gap).**
 * When `state.plan` is present, the returned object also carries
 * `initialPlan: { steps, cursor }`, meant to be spread straight into
 * `createBroker()` exactly like `initialWatermark`/`registry` above (the
 * example above already does this via the object spread) —
 * `BrokerOptions.initialPlan` (broker.ts) seeds `this.plan`/
 * `this.planCursor` on the freshly-constructed broker at the SAME cursor
 * position captured at export time, so the restored broker resumes
 * exactly where the exporting one left off, not from step 0. `cursor`
 * defaults to `0` only if `state.plan` is present but `state.planCursor`
 * itself is absent (a hand-authored state that only set `plan`) —
 * `serializeBrokerState()` itself always writes both together.
 *
 * This is a genuinely different operation from calling `declarePlan()` on
 * the restored broker directly. `declarePlan()` itself is completely
 * untouched by this feature and still throws `PlanNotDeclarableError` once
 * the scope has left `CLEAN` (see its own doc comment) — which is exactly
 * the state a restored non-`CLEAN` watermark usually is in, so
 * `declarePlan()` remains just as unable to (re-)establish a plan on a
 * restored broker as it always was. `BrokerOptions.initialPlan` is a
 * separate, construction-time-only path specifically because restoring an
 * already-legitimately-declared plan is not the same trust question
 * `declarePlan()`'s guard protects against: that guard exists to stop
 * untrusted content that is ALREADY LIVE IN THIS SCOPE, RIGHT NOW, from
 * shaping a plan being declared now. Restoring here carries forward a
 * commitment that was made validly, on the ORIGINAL broker, while ITS
 * scope was still `CLEAN` — before that broker's own exposure ever
 * happened; nothing about this path lets any NEW untrusted content shape
 * anything.
 *
 * **Safety property** (this reasoning should be re-verified against
 * `broker.ts`'s `gateDecision()` if either side of this ever changes):
 * restoring a plan — even a fully adversarially-tampered `state.plan` from
 * a corrupted or hand-edited `session.json`, since `SerializedBrokerState`
 * is externally-sourced input exactly like the rest of this validation
 * boundary — can only ever make FUTURE privileged calls MORE restrictive,
 * never less. Plan-freeze itself is strictly additive (DESIGN.md §11:
 * "this check is strictly additive: it runs in addition to, never instead
 * of, the normal policy decision") and this restore path changes nothing
 * about how that check is enforced, only what it starts pre-loaded with:
 * a call whose tool matches the (possibly bogus) next plan step still has
 * to clear the ordinary policy/outbound-allowlist checks exactly as if no
 * plan had been restored at all, and a call that does NOT match is
 * rejected as unplanned regardless of what a tampered plan "intended".
 * There is no shape of `state.plan` content that grants a call any
 * permission it would not otherwise have had — the worst a tampered plan
 * can do is cause spurious `UnplannedPrivilegedActionError` blocking of a
 * call the ordinary policy would have allowed, which is an availability
 * cost, never a soundness one. `test/persistence.spec.ts` exercises this
 * directly with a deliberately tampered `state.plan`, rather than leaving
 * it as an unverified claim.
 *
 * `validateSerializedBrokerState()` still checks `state.plan`'s shape (an
 * array of plan-step-shaped objects) and `state.planCursor`'s bounds (a
 * non-negative integer no greater than `state.plan.length`) before any of
 * this runs — but that validation is only about SHAPE, not content: a
 * well-shaped but semantically-nonsensical plan (tool names that don't
 * exist, or that don't match what the receiving broker will actually see)
 * is accepted and simply behaves as described above, since — per the
 * safety property — no plan CONTENT can turn into a policy bypass, only
 * malformed SHAPE needs rejecting up front (the same "fail loud at the
 * trust boundary, not with a delayed opaque crash" reasoning
 * `InvalidBrokerStateError` already applies to `watermark.level`).
 */
export function restoreBrokerState(
  state: SerializedBrokerState,
  makeRegistry: () => TaintRegistry = () => new InMemoryTaintRegistry(),
): { initialWatermark: TaintWatermark; registry: TaintRegistry; initialPlan?: PlanState } {
  validateSerializedBrokerState(state);
  const registry = makeRegistry();
  restoreRegistry(state.registry, registry);
  const restored: {
    initialWatermark: TaintWatermark;
    registry: TaintRegistry;
    initialPlan?: PlanState;
  } = { initialWatermark: state.watermark, registry };
  if (state.plan !== undefined) {
    restored.initialPlan = {
      steps: state.plan.map((step) => ({ ...step })),
      cursor: state.planCursor ?? 0,
    };
  }
  return restored;
}
