/**
 * In-memory implementation of the Layer 2 content-addressed fingerprint
 * registry (DESIGN.md §4.2).
 *
 * Fuzzy lookup is a linear scan over all registered records. That's fine at
 * corpus/session scale; GAPS.md #13 names indexed (LSH-banded) lookup as a
 * follow-up for long-running production sessions — swapping this class for
 * one backed by an index is meant to be a drop-in replacement, since callers
 * only depend on the `TaintRegistry` interface.
 */

import type { FuzzyLookupOpts, ProvenanceTag, SensitivityLabel, TaintLevel, TaintMatch, TaintRecord, TaintRegistry } from '../types.js';
import { maxLevel } from '../types.js';
import { buildFingerprint, exactHash, hammingDistance, overlapCoefficient } from './fingerprint.js';

const DEFAULT_SIMHASH_MAX_DISTANCE = 3; // out of 64 bits
const DEFAULT_OVERLAP_MIN = 0.6;
const MIN_TEXT_LEN_FOR_FUZZY = 40; // §4.2: "≥40-char substring window"

export class InMemoryTaintRegistry implements TaintRegistry {
  private readonly byExactHash = new Map<string, TaintRecord>();
  private readonly all: TaintRecord[] = [];

  get size(): number {
    return this.all.length;
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
    this.byExactHash.set(record.id, record);
    this.all.push(record);
    return record;
  }

  lookupExact(text: string): TaintRecord | undefined {
    return this.byExactHash.get(exactHash(text));
  }

  lookupFuzzy(text: string, opts: FuzzyLookupOpts = {}): TaintMatch[] {
    if (text.length < MIN_TEXT_LEN_FOR_FUZZY) return [];
    const simhashMaxDistance = opts.simhashMaxDistance ?? DEFAULT_SIMHASH_MAX_DISTANCE;
    const overlapMin = opts.jaccardMin ?? DEFAULT_OVERLAP_MIN;
    const fp = buildFingerprint(text);

    const matches: TaintMatch[] = [];
    for (const record of this.all) {
      if (record.id === fp.exactHash) continue; // exact matches are handled by lookupExact

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
    matches.sort((a, b) => b.score - a.score);
    return matches;
  }

  getById(id: string): TaintRecord | undefined {
    return this.byExactHash.get(id);
  }
}
