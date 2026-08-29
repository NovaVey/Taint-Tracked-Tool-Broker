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

/** Word-shingles of a normalized text. Short texts (< SHINGLE_WIDTH words) fall back to the whole text as one shingle. */
export function wordShingles(text: string, width: number = SHINGLE_WIDTH): string[] {
  const words = normalize(text).split(' ').filter(Boolean);
  if (words.length === 0) return [];
  if (words.length < width) return [words.join(' ')];
  const shingles: string[] = [];
  for (let i = 0; i <= words.length - width; i++) {
    shingles.push(words.slice(i, i + width).join(' '));
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
 * Overlap coefficient |A∩B| / min(|A|,|B|) between two sorted, deduplicated
 * hash sets. Both inputs are sorted ascending, so intersection is a linear
 * merge — no quadratic scan even for large shingle sets.
 */
export function overlapCoefficient(a: Uint32Array, b: Uint32Array): number {
  if (a.length === 0 || b.length === 0) return 0;
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
  return intersection / Math.min(a.length, b.length);
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
