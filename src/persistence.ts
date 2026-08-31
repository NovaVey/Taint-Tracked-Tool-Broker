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
 * Also NOT included: a declared plan (`broker.declarePlan()`, DESIGN.md
 * §11). `SerializedBrokerState` carries only the watermark and the
 * registry — a broker restored from another one's exported state starts
 * with plan-freeze disengaged even if the original had a live plan, and
 * `declarePlan()` can't re-establish one afterward if the restored
 * watermark is already non-CLEAN (it requires CLEAN). See DESIGN.md §11's
 * own note on this for the concrete consequence.
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

import type { TaintRecord, TaintRegistry, TaintWatermark, ToolCallBroker } from './types.js';
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

/** Everything `serializeBrokerState()` exports: a broker's scope watermark plus its registry's records, as one JSON-safe object. */
export interface SerializedBrokerState {
  watermark: TaintWatermark;
  registry: SerializedTaintRecord[];
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
}

/** Exports every record in `registry` to a JSON-safe array. Counterpart: restoreRegistry(). */
export function serializeRegistry(registry: TaintRegistry): SerializedTaintRecord[] {
  return registry.entries().map((record) => ({
    ...record,
    fingerprint: {
      exactHash: record.fingerprint.exactHash,
      simhash: record.fingerprint.simhash.toString(),
      shingleHashes: Array.from(record.fingerprint.shingleHashes),
      length: record.fingerprint.length,
    },
  }));
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
 * Exports both halves of a broker's persistable state — its scope watermark
 * and its registry's records — as one JSON-safe object. Pair with
 * `restoreBrokerState()` on the receiving side. Typical use:
 *
 *   const state = serializeBrokerState(broker);
 *   await fs.writeFile('session.json', JSON.stringify(state));
 */
export function serializeBrokerState(
  broker: Pick<ToolCallBroker, 'scope' | 'registry'>,
): SerializedBrokerState {
  return {
    watermark: {
      level: broker.scope.watermark.level,
      privateDataSeen: broker.scope.watermark.privateDataSeen,
      sources: [...broker.scope.watermark.sources],
    },
    registry: serializeRegistry(broker.registry),
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
 */
export function restoreBrokerState(
  state: SerializedBrokerState,
  makeRegistry: () => TaintRegistry = () => new InMemoryTaintRegistry(),
): { initialWatermark: TaintWatermark; registry: TaintRegistry } {
  validateSerializedBrokerState(state);
  const registry = makeRegistry();
  restoreRegistry(state.registry, registry);
  return { initialWatermark: state.watermark, registry };
}
