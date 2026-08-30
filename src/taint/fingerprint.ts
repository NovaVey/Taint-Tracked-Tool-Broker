/**
 * Content-addressed fingerprinting for the Layer 2 registry (DESIGN.md §4.2).
 *
 * Three signals, cheapest/most-precise first:
 *   1. Exact hash (SHA-256)            — byte-identical text.
 *   2. Simhash (64-bit)                — survives small edits, case/whitespace
 *                                         changes, minor rewording.
 *   3. Word-shingle overlap coefficient — survives reordering and, critically,
 *                                         survives one text being a *substring*
 *                                         of the other (a short malicious
 *                                         excerpt pasted into a large blob, or
 *                                         a large source condensed to a short
 *                                         quoted line). Deliberately an
 *                                         overlap coefficient rather than a
 *                                         plain Jaccard index — Jaccard is
 *                                         dominated by whichever set is larger
 *                                         and misses exactly the containment
 *                                         case above.
 *
 * None of this is load-bearing for safety (see types.ts TaintContext /
 * DESIGN.md §4.2) — it only affects attribution precision and a verdict's
 * eligibility to be *tightened* or *downgraded within an already-gated tier*.
 * A badly-tuned threshold here degrades explanations, not the gate itself.
 */

import { createHash } from 'node:crypto';
import type { Fingerprint } from '../types.js';

const SHINGLE_WIDTH = 5; // words per shingle
const SIMHASH_BITS = 64;

/** Lowercase, collapse whitespace, drop punctuation — normalization shared by shingling and simhash. */
function normalize(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Deterministic 32-bit FNV-1a hash — fast, dependency-free, stable across runs/platforms. */
export function fnv1a32(str: string, seed = 0x811c9dc5): number {
  let hash = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

/**
 * Word-shingles of a normalized text, as overlapping `width`-word windows.
 *
 * Short texts (< `width` words) do NOT fall back to treating the whole
 * text as a single shingle — that used to be this function's behavior, and
 * it silently defeated the "survives reordering" and "survives one text
 * being a substring of the other" properties the module doc comment above
 * claims, for exactly the shortest, most common realistic payloads (a URL,
 * an account number, a short instruction): two short texts differing only
 * by word order, or by a single word, produced two completely different
 * single-shingle strings and so scored ZERO overlap — a full miss, not a
 * partial one — even though the texts were near-identical. Instead, a
 * short text uses the largest narrower width that still yields at least 2
 * overlapping windows (`words.length - 1`, floored at 1 for a single-word
 * text), restoring partial-overlap detection for short-text near-
 * duplicates and reorderings.
 *
 * This does NOT fix the separate, still-open cross-length case: a short
 * excerpt narrow enough to hit this path, embedded verbatim in a MUCH
 * longer document that itself is always shingled at the full `width`
 * (never narrowed — see the `words.length >= width` branch below), still
 * shares no shingle string with it, since a shingle is a whole joined
 * n-gram string, not a bag of words — two different widths simply never
 * produce equal strings. Doing so would require multi-width shingling on
 * long documents too, at a real, roughly-multiplicative storage/indexing
 * cost this library has not made (see GAPS.md #8's false-negative note and
 * DESIGN.md's fixed-size-sketch implementation note for the related
 * cost/accuracy tradeoff already measured and rejected once here).
 */
export function wordShingles(text: string, width: number = SHINGLE_WIDTH): string[] {
  const words = normalize(text).split(' ').filter(Boolean);
  if (words.length === 0) return [];
  const effectiveWidth = words.length >= width ? width : Math.max(1, words.length - 1);
  const shingles: string[] = [];
  for (let i = 0; i <= words.length - effectiveWidth; i++) {
    shingles.push(words.slice(i, i + effectiveWidth).join(' '));
  }
  return shingles;
}

/** Deduplicated, sorted hashes of a text's word-shingles — the basis for overlap-coefficient matching. */
export function shingleHashesOf(text: string): Uint32Array {
  const hashes = new Set<number>();
  for (const s of wordShingles(text)) hashes.add(fnv1a32(s));
  return Uint32Array.from(Array.from(hashes).sort((a, b) => a - b));
}

/**
 * |A∩B| between two sorted, deduplicated hash sets. Both inputs are sorted
 * ascending, so this is a linear merge — no quadratic scan even for large
 * shingle sets.
 */
export function shingleIntersectionSize(a: Uint32Array, b: Uint32Array): number {
  let i = 0;
  let j = 0;
  let intersection = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      intersection++;
      i++;
      j++;
    } else if (a[i]! < b[j]!) {
      i++;
    } else {
      j++;
    }
  }
  return intersection;
}

/**
 * Overlap coefficient |A∩B| / min(|A|,|B|) — symmetric containment: high
 * whenever EITHER set is (almost) fully covered by the other, which is what
 * catches a short excerpt embedded in a large blob just as well as a large
 * source condensed to a short quote. This is the right measure for Layer 2
 * fuzzy *matching* (registry.ts), where either direction is a legitimate hit.
 *
 * It is deliberately NOT used for validating quarantine input provenance
 * (quarantine.ts) — there the question is asymmetric ("is `text` mostly
 * accounted for by `source`?"), and min()-based scoring is exactly what lets
 * a large fabricated `text` borrow a tiny source's high score. See
 * quarantine.ts's own asymmetric check.
 */
export function overlapCoefficient(a: Uint32Array, b: Uint32Array): number {
  if (a.length === 0 || b.length === 0) return 0;
  return shingleIntersectionSize(a, b) / Math.min(a.length, b.length);
}

/**
 * Classic weighted-bit-voting simhash: each shingle votes +1/-1 on every bit
 * of its own hash; the final hash's bit is 1 wherever the vote total is
 * positive. Two 32-bit FNV hashes (different seeds) are combined into one
 * 64-bit value per shingle to lower collision risk over the 32-bit variant.
 */
export function computeSimhash(text: string): bigint {
  const shingles = wordShingles(text);
  if (shingles.length === 0) return 0n;

  const weights = new Array<number>(SIMHASH_BITS).fill(0);
  for (const shingle of shingles) {
    const high = fnv1a32(shingle, 0x811c9dc5);
    const low = fnv1a32(shingle, 0x9e3779b9);
    const h = (BigInt(high) << 32n) | BigInt(low >>> 0);
    for (let bit = 0; bit < SIMHASH_BITS; bit++) {
      const set = ((h >> BigInt(bit)) & 1n) === 1n;
      weights[bit] = (weights[bit] ?? 0) + (set ? 1 : -1);
    }
  }

  let result = 0n;
  for (let bit = 0; bit < SIMHASH_BITS; bit++) {
    if ((weights[bit] ?? 0) > 0) result |= 1n << BigInt(bit);
  }
  return result;
}

/** Popcount of a^b, i.e. how many of the 64 bits differ. 0 = identical simhash. */
export function hammingDistance(a: bigint, b: bigint): number {
  let x = a ^ b;
  let count = 0;
  while (x !== 0n) {
    x &= x - 1n; // clear the lowest set bit
    count++;
  }
  return count;
}

export function exactHash(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function buildFingerprint(text: string): Fingerprint {
  return {
    exactHash: exactHash(text),
    simhash: computeSimhash(text),
    shingleHashes: shingleHashesOf(text),
    length: text.length,
  };
}

/** Shared text-coercion for anything that gets registered/hashed: strings pass through, everything else is JSON-stringified. */
export function toRegistrableText(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
