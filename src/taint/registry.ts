/**
 * In-memory implementation of the Layer 2 content-addressed fingerprint
 * registry (DESIGN.md §4.2).
 *
 * Fuzzy lookup is indexed, not a linear scan over every registered record
 * (GAPS.md #13):
 *
 *   - Simhash: LSH banding. The 64-bit simhash is split into SIMHASH_BANDS
 *     equal-width bands; each record is bucketed under every (band index,
 *     band value) pair it produces. A query only has to probe its own
 *     SIMHASH_BANDS bucket keys to gather every candidate that could
 *     possibly be within `simhashMaxDistance` of it — guaranteed by
 *     pigeonhole for any distance < SIMHASH_BANDS (bits that differ can
 *     spoil at most one band each, so a hamming distance smaller than the
 *     band count leaves at least one band identical). That comfortably
 *     covers the library's default threshold (3); a caller-supplied
 *     `simhashMaxDistance` at or above SIMHASH_BANDS can, in principle,
 *     miss a candidate the old linear scan would have found — same
 *     already-documented approximate-matching territory as GAPS.md #8/#14,
 *     not a new soundness concern (Layer 2 is never load-bearing).
 *   - Shingles: a plain inverted index (shingle hash -> record ids). Since
 *     overlapCoefficient() is 0 whenever two texts share no shingle, this
 *     index is exact, not approximate — it cannot miss a real candidate.
 *
 * Either index only narrows *which* records get the real, exact
 * hammingDistance()/overlapCoefficient() comparison below — scoring and
 * thresholding are byte-for-byte the same as a linear scan; only the
 * candidate set that has to be evaluated shrinks.
 *
 * Optional `maxEntries` bounds memory for long-running sessions (the
 * "pruning/retention policy" half of GAPS.md #13) by evicting the
 * oldest record — by `provenance.capturedAt`, true chronological age, not
 * Map insertion order — once the bound is exceeded. Those two usually
 * coincide (an ordinary `register()` call's `capturedAt` is set at roughly
 * the moment it's inserted), but they can genuinely diverge once
 * `restore()` (persistence.ts) is in the picture: restoring an old
 * snapshot's records into a registry that already has newer live entries
 * inserts the old records LAST by Map order despite them being oldest by
 * wall-clock time, and evicting by Map order there would evict the wrong
 * (actually-newer) records first. FIFO by first-registration order, not
 * LRU by lookup recency — re-registering already-known content (the dedup
 * path below) deliberately does not refresh a record's `capturedAt` or its
 * eviction priority. That keeps eviction easy to reason about and audit
 * ("content ages out by when it first entered the system") rather than
 * silently reshuffled by read traffic. Unbounded (no eviction) by default,
 * so existing callers see no behavior change.
 *
 * Eviction only ever removes a record from Layer 2's fuzzy/attribution
 * index; it never touches the Layer 0 scope watermark (DESIGN.md §4.1),
 * which is what soundness actually rests on — an evicted record can only
 * cost some future attribution precision or fingerprint-tightening
 * opportunity (GAPS.md #8), never open a hole in the core gate.
 */

import type { Fingerprint, FuzzyLookupOpts, ProvenanceTag, SensitivityLabel, TaintLevel, TaintMatch, TaintRecord, TaintRegistry } from '../types.js';
import { LEVEL_ORDER, maxLevel } from '../types.js';
import { buildFingerprint, exactHash, hammingDistance, overlapCoefficient } from './fingerprint.js';

const DEFAULT_SIMHASH_MAX_DISTANCE = 3; // out of 64 bits
const DEFAULT_OVERLAP_MIN = 0.6;
const MIN_TEXT_LEN_FOR_FUZZY = 40; // §4.2: "≥40-char substring window"
const DEFAULT_MAX_FUZZY_MATCHES = 20; // FuzzyLookupOpts.maxMatches default — see its doc comment in types.ts

const SIMHASH_BANDS = 8; // 64 / 8 = 8 bits/band; guarantees candidate recall for any simhashMaxDistance < 8 (see file header)
const SIMHASH_BAND_BITS = 64 / SIMHASH_BANDS;
const SIMHASH_BAND_MASK = (1n << BigInt(SIMHASH_BAND_BITS)) - 1n;

/** Splits a 64-bit simhash into SIMHASH_BANDS band values, low bits first. */
function simhashBands(simhash: bigint): number[] {
  const bands = new Array<number>(SIMHASH_BANDS);
  for (let i = 0; i < SIMHASH_BANDS; i++) {
    bands[i] = Number((simhash >> BigInt(i * SIMHASH_BAND_BITS)) & SIMHASH_BAND_MASK);
  }
  return bands;
}

export interface InMemoryTaintRegistryOpts {
  /**
   * Evict the oldest-registered record once a new registration would push
   * the registry past this many entries. Must be a positive integer when
   * given. Omit for unbounded growth (the default — fine for corpus/session
   * scale; see GAPS.md #13 for when a long-running deployment should set
   * this).
   */
  maxEntries?: number;
}

export class InMemoryTaintRegistry implements TaintRegistry {
  private readonly maxEntries: number | undefined;
  /** Also the source of truth for insertion order — Map preserves it, and FIFO eviction reads straight off it. */
  private readonly byExactHash = new Map<string, TaintRecord>();
  /** band index -> band value -> candidate record ids sharing that band. */
  private readonly simhashIndex: Array<Map<number, Set<string>>> = Array.from({ length: SIMHASH_BANDS }, () => new Map());
  /** shingle hash -> candidate record ids sharing that shingle. */
  private readonly shingleIndex = new Map<number, Set<string>>();

  constructor(opts: InMemoryTaintRegistryOpts = {}) {
    if (opts.maxEntries !== undefined && (!Number.isInteger(opts.maxEntries) || opts.maxEntries < 1)) {
      throw new RangeError(`InMemoryTaintRegistry maxEntries must be a positive integer, got ${opts.maxEntries}.`);
    }
    this.maxEntries = opts.maxEntries;
  }

  get size(): number {
    return this.byExactHash.size;
  }

  register(
    text: string,
    provenance: ProvenanceTag,
    level: TaintLevel,
    sensitivity: SensitivityLabel,
    derivedFrom?: string[],
  ): TaintRecord {
    const fingerprint = buildFingerprint(text);
    const existing = this.byExactHash.get(fingerprint.exactHash);
    if (existing) {
      // Same content seen again (e.g. re-fetched page, or a second source
      // exposing identical text): the record's level and sensitivity are
      // monotonic across re-registration — never let a later, weaker
      // registration silently downgrade what's already known. Provenance
      // intentionally stays first-seen (stable attribution for "where did
      // this first enter the system"); level/sensitivity are the safety-
      // relevant fields and must only ever strengthen.
      existing.level = maxLevel(existing.level, level);
      existing.sensitivity = {
        containsPrivateData: existing.sensitivity.containsPrivateData || sensitivity.containsPrivateData,
        categories: Array.from(new Set([...existing.sensitivity.categories, ...sensitivity.categories])),
      };
      return existing;
    }
    const record: TaintRecord = {
      id: fingerprint.exactHash,
      provenance,
      level,
      sensitivity,
      fingerprint,
      confidence: 1.0,
      ...(derivedFrom !== undefined ? { derivedFrom } : {}),
    };
    this.insert(record);
    return record;
  }

  private insert(record: TaintRecord): void {
    this.byExactHash.set(record.id, record);
    this.indexRecord(record);
    this.evictIfNeeded();
  }

  private indexRecord(record: TaintRecord): void {
    const bands = simhashBands(record.fingerprint.simhash);
    for (let i = 0; i < SIMHASH_BANDS; i++) {
      const bucket = this.simhashIndex[i]!;
      let ids = bucket.get(bands[i]!);
      if (!ids) {
        ids = new Set();
        bucket.set(bands[i]!, ids);
      }
      ids.add(record.id);
    }
    for (const shingle of record.fingerprint.shingleHashes) {
      let ids = this.shingleIndex.get(shingle);
      if (!ids) {
        ids = new Set();
        this.shingleIndex.set(shingle, ids);
      }
      ids.add(record.id);
    }
  }

  private unindexRecord(record: TaintRecord): void {
    const bands = simhashBands(record.fingerprint.simhash);
    for (let i = 0; i < SIMHASH_BANDS; i++) {
      const bucket = this.simhashIndex[i]!;
      const ids = bucket.get(bands[i]!);
      if (!ids) continue;
      ids.delete(record.id);
      if (ids.size === 0) bucket.delete(bands[i]!);
    }
    for (const shingle of record.fingerprint.shingleHashes) {
      const ids = this.shingleIndex.get(shingle);
      if (!ids) continue;
      ids.delete(record.id);
      if (ids.size === 0) this.shingleIndex.delete(shingle);
    }
  }

  private evictIfNeeded(): void {
    if (this.maxEntries === undefined) return;
    while (this.byExactHash.size > this.maxEntries) {
      // O(size) per eviction — deliberately not a min-heap. Eviction only
      // runs at capacity, at most once per new registration, and size is
      // itself bounded by maxEntries; a heap would only pay for itself at
      // maxEntries values far larger than what "bound memory for a
      // long-running session" (the actual use case) calls for. Ties broken
      // by Map/insertion order (the first-encountered record wins), which
      // reproduces plain FIFO whenever every record's capturedAt happens to
      // coincide with its registration order — the common case.
      let oldestId: string | undefined;
      let oldestCapturedAt = Infinity;
      for (const [id, record] of this.byExactHash) {
        if (record.provenance.capturedAt < oldestCapturedAt) {
          oldestCapturedAt = record.provenance.capturedAt;
          oldestId = id;
        }
      }
      if (oldestId === undefined) break; // unreachable (size > maxEntries >= 1), just in case
      const record = this.byExactHash.get(oldestId);
      this.byExactHash.delete(oldestId);
      if (record) this.unindexRecord(record);
    }
  }

  lookupExact(text: string): TaintRecord | undefined {
    return this.byExactHash.get(exactHash(text));
  }

  lookupFuzzy(text: string, opts: FuzzyLookupOpts = {}): TaintMatch[] {
    if (text.length < MIN_TEXT_LEN_FOR_FUZZY) return [];
    return this.fuzzyMatchesForFingerprint(buildFingerprint(text), opts);
  }

  /**
   * lookupExact() + lookupFuzzy() sharing one buildFingerprint() call — see
   * the interface doc comment (types.ts) for why this exists. Behaviorally
   * identical to calling both separately: the exact check and the fuzzy
   * candidate scan are unchanged, only the redundant second fingerprint
   * computation is removed.
   */
  lookupCombined(text: string, opts: FuzzyLookupOpts = {}): { exact: TaintRecord | undefined; fuzzy: TaintMatch[] } {
    if (text.length < MIN_TEXT_LEN_FOR_FUZZY) {
      // Below the fuzzy floor, lookupFuzzy() always returns [] without ever
      // building a fingerprint — mirror that here too rather than paying for
      // one just to compute an exact hash lookupExact() can get more cheaply.
      return { exact: this.lookupExact(text), fuzzy: [] };
    }
    const fp = buildFingerprint(text);
    const exact = this.byExactHash.get(fp.exactHash);
    return { exact, fuzzy: this.fuzzyMatchesForFingerprint(fp, opts) };
  }

  private fuzzyMatchesForFingerprint(fp: Fingerprint, opts: FuzzyLookupOpts): TaintMatch[] {
    const simhashMaxDistance = opts.simhashMaxDistance ?? DEFAULT_SIMHASH_MAX_DISTANCE;
    const overlapMin = opts.jaccardMin ?? DEFAULT_OVERLAP_MIN;
    const maxMatches = opts.maxMatches ?? DEFAULT_MAX_FUZZY_MATCHES;

    // Candidate generation: union of every record sharing an LSH band with
    // this simhash, plus every record sharing at least one shingle. Exact
    // scoring below is unchanged from a full linear scan — only evaluated
    // against this narrowed set instead of every record in the registry.
    const candidateIds = new Set<string>();
    const bands = simhashBands(fp.simhash);
    for (let i = 0; i < SIMHASH_BANDS; i++) {
      const ids = this.simhashIndex[i]!.get(bands[i]!);
      if (ids) for (const id of ids) candidateIds.add(id);
    }
    for (const shingle of fp.shingleHashes) {
      const ids = this.shingleIndex.get(shingle);
      if (ids) for (const id of ids) candidateIds.add(id);
    }

    const matches: TaintMatch[] = [];
    for (const id of candidateIds) {
      if (id === fp.exactHash) continue; // exact matches are handled by lookupExact
      const record = this.byExactHash.get(id);
      if (!record) continue; // defensive: evicted between indexing and this lookup

      const distance = hammingDistance(fp.simhash, record.fingerprint.simhash);
      const simhashScore = 1 - distance / 64;
      const overlap = overlapCoefficient(fp.shingleHashes, record.fingerprint.shingleHashes);

      // Prefer whichever signal fired more strongly for this record; simhash
      // is cheaper to reason about (single distance number) but overlap is
      // what actually catches the substring/containment case (§4.2).
      if (distance <= simhashMaxDistance && simhashScore >= overlap) {
        matches.push({ record, matchType: 'simhash', argPath: '', score: simhashScore });
      } else if (overlap >= overlapMin) {
        matches.push({ record, matchType: 'shingle', argPath: '', score: overlap });
      }
    }
    // Level first, score second — a pathological registry (many
    // attacker-chosen near-duplicates) can produce far more candidates than
    // any caller wants back; maxMatches bounds that. Sorting by level first
    // guarantees the single highest-severity match always survives the cap
    // (FuzzyLookupOpts.maxMatches's doc comment), so truncating here can
    // only ever drop lower-value explainability, never a floor-raising match.
    matches.sort((a, b) => LEVEL_ORDER[b.record.level] - LEVEL_ORDER[a.record.level] || b.score - a.score);
    if (matches.length > maxMatches) matches.length = maxMatches;
    return matches;
  }

  getById(id: string): TaintRecord | undefined {
    return this.byExactHash.get(id);
  }

  entries(): readonly TaintRecord[] {
    return Array.from(this.byExactHash.values());
  }

  restore(record: TaintRecord): void {
    const existing = this.byExactHash.get(record.id);
    if (existing) {
      // Merge monotonically — mirrors register()'s own dedup path (above):
      // restoring an exported snapshot must never let a weaker incoming
      // record silently downgrade what this registry already has live,
      // e.g. a record re-confirmed at a stronger level via a real
      // register() call sometime after the snapshot being restored was
      // taken. Provenance/fingerprint/confidence/derivedFrom stay
      // `existing`'s — level/sensitivity are the only safety-relevant
      // fields, and are the only ones that get merged rather than kept.
      const merged: TaintRecord = {
        ...existing,
        level: maxLevel(existing.level, record.level),
        sensitivity: {
          containsPrivateData: existing.sensitivity.containsPrivateData || record.sensitivity.containsPrivateData,
          categories: Array.from(new Set([...existing.sensitivity.categories, ...record.sensitivity.categories])),
        },
      };
      this.unindexRecord(existing);
      this.byExactHash.set(record.id, merged);
      this.indexRecord(merged);
      return;
    }
    this.insert(record);
  }
}
