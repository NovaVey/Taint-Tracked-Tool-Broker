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
  if (words.length === 0) return charShingles(text, width);
  const effectiveWidth = words.length >= width ? width : Math.max(1, words.length - 1);
  const shingles: string[] = [];
  for (let i = 0; i <= words.length - effectiveWidth; i++) {
    shingles.push(words.slice(i, i + effectiveWidth).join(' '));
  }
  return shingles;
}

/**
 * Character-level (code-point) shingling fallback for text that normalize()
 * reduces to nothing.
 *
 * normalize() (see its doc comment above) strips every character outside
 * `\p{L}\p{N}\s` — so a text made *entirely* of punctuation/symbols/emoji
 * (a decorative "=====" or "★•☆•★" separator banner, a message that's
 * nothing but emoji reactions, ...) normalizes to the empty string even
 * though it's meaningfully long, real content. Before this fallback existed,
 * `wordShingles()` returned `[]` for every such text regardless of what
 * symbols it actually contained, which made `computeSimhash()` return the
 * fixed sentinel `0n` and `shingleHashesOf()` return an empty set for *any*
 * symbol-only input — so two completely unrelated symbol-only texts (two
 * different decorative banners, say) both fingerprinted identically and
 * `fuzzyMatchesForFingerprint()` (registry.ts) reported them as a
 * `matchType: 'simhash'`, `score: 1` *perfect* match despite sharing no real
 * content whatsoever.
 *
 * Falling back to shingles over the RAW, un-normalized text's own code
 * points (not UTF-16 code units — `Array.from` splits on code points, so a
 * surrogate-pair emoji is one shingle-able unit, not two half-characters)
 * restores genuine content-sensitivity for exactly this case, using the
 * same width-narrowing rule the word-based path above uses for short input
 * (`words.length - 1`, floored at 1) so a short symbol run still yields
 * >=2 overlapping windows instead of collapsing to one whole-text blob.
 *
 * This path is reached ONLY when `normalize(text)` yields zero words — an
 * ordinary text with any letters/numbers in it takes the word-shingling
 * path above, completely unaffected by this fallback's existence.
 */
function charShingles(text: string, width: number): string[] {
  const chars = Array.from(text);
  if (chars.length === 0) return [];
  const effectiveWidth = chars.length >= width ? width : Math.max(1, chars.length - 1);
  const shingles: string[] = [];
  for (let i = 0; i <= chars.length - effectiveWidth; i++) {
    shingles.push(chars.slice(i, i + effectiveWidth).join(''));
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

/**
 * A "lone" (unpaired) UTF-16 surrogate: a high surrogate (D800-DBFF) not
 * immediately followed by a low surrogate (DC00-DFFF), or a low surrogate
 * not immediately preceded by a high surrogate. Well-formed JS strings never
 * contain one — they only show up from malformed input: truncating a tool
 * result mid-character, a buggy upstream encoder, or `JSON.parse` on text
 * that embeds a raw `\uD800`-style escape with no matching partner.
 *
 * These two regexes intentionally do NOT use the `u` (unicode) flag: with
 * `u`, `.` and character classes operate on whole code points and an
 * unpaired surrogate becomes its own code point, which is a different (and
 * here unwanted) matching model — we specifically want raw UTF-16 code-unit
 * matching so "is the following/preceding code unit a surrogate of the
 * other half" is exactly what the lookaround checks.
 */
const LONE_HIGH_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g;
const LONE_LOW_SURROGATE = /(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Rewrites every lone/unpaired surrogate code unit in `text` into a distinct,
 * deterministic, all-ASCII marker that encodes exactly which surrogate it
 * was — used ONLY as exactHash()'s pre-processing step, to close a real hash
 * collision without changing the hash of any well-formed string.
 *
 * Why this is needed: `Buffer`/`TextEncoder`'s UTF-8 encoder (which
 * `createHash(...).update(text, 'utf8')` goes through below) is lossy for
 * lone surrogates — by the WHATWG encoding spec it silently substitutes
 * U+FFFD (the replacement character) for each one. That means two distinct
 * JS strings differing only in *which* lone surrogate they contain —
 * `'\uD800X'` vs `'\uD801X'`, for example — encode to byte-identical UTF-8
 * and therefore hash identically, even though they are different strings.
 * Since `TaintRecord.id` *is* `exactHash()`'s output (see registry.ts), that
 * collision is a real registry-key collision between genuinely different
 * content, not merely a cosmetic hashing quirk.
 *
 * Why not just switch encodings (e.g. to UTF-16LE) instead: that would
 * change the hash — and therefore `TaintRecord.id` — of literally *every*
 * well-formed string this library has ever hashed, a far larger and
 * unnecessary breaking change for a bug that only bites the narrow lone-
 * surrogate case. Escaping only the specific lone code units, and leaving
 * every other code unit (including both halves of every well-formed
 * surrogate pair) completely untouched, keeps this a true no-op for
 * well-formed input: this function returns its argument unchanged, byte for
 * byte, for any string with no lone surrogates in it — see the "unchanged
 * for well-formed strings" case in fingerprint.spec.ts, which pins this for
 * ASCII, emoji (surrogate-pair), and CJK (non-surrogate, non-BMP-adjacent)
 * text alike.
 *
 * The marker text itself doesn't need to be unforgeable against a
 * deliberately-crafted well-formed string that happens to contain the same
 * literal substring — this closes a narrow, low-severity correctness gap
 * (two *accidentally* colliding malformed inputs), not an adversarial-
 * collision-resistance guarantee, and the exact hash was never meant to
 * carry that guarantee for arbitrary crafted input in the first place.
 */
function escapeLoneSurrogatesForHashing(text: string): string {
  if (!/[\uD800-\uDFFF]/.test(text)) return text; // fast path: no surrogates at all
  const mark = (m: string): string =>
    `\uFFFD<lone-surrogate:${m.charCodeAt(0).toString(16).padStart(4, '0')}>`;
  return text.replace(LONE_HIGH_SURROGATE, mark).replace(LONE_LOW_SURROGATE, mark);
}

export function exactHash(text: string): string {
  return createHash('sha256').update(escapeLoneSurrogatesForHashing(text), 'utf8').digest('hex');
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
