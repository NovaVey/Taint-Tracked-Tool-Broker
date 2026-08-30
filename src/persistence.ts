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
 */

import type { TaintRecord, TaintRegistry, TaintWatermark, ToolCallBroker } from './types.js';
import { InMemoryTaintRegistry } from './taint/registry.js';

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
export function restoreRegistry(records: readonly SerializedTaintRecord[], into: TaintRegistry): void {
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
export function serializeBrokerState(broker: Pick<ToolCallBroker, 'scope' | 'registry'>): SerializedBrokerState {
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
 */
export function restoreBrokerState(
  state: SerializedBrokerState,
  makeRegistry: () => TaintRegistry = () => new InMemoryTaintRegistry(),
): { initialWatermark: TaintWatermark; registry: TaintRegistry } {
  const registry = makeRegistry();
  restoreRegistry(state.registry, registry);
  return { initialWatermark: state.watermark, registry };
}
