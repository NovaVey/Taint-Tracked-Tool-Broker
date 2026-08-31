/**
 * Field-level grounding check for `broker.summarize()` output (DESIGN.md
 * §6.2, GAPS.md #4's own "the quarantine path only bounds risk if the
 * extraction schema is actually narrow" caveat) — a standalone, OPT-IN
 * utility. See the STATUS note at the end of this comment for exactly what
 * "opt-in" means here.
 *
 * The hole this exists to catch: `broker.summarize()`'s whole safety
 * property rests on the capability-less Q-LLM (the integrator-supplied
 * `QuarantineImpl`) actually EXTRACTING content that is really present in
 * the source text, not inventing it. Nothing in `quarantine.ts` can catch a
 * Q-LLM that plainly hallucinates a field value, or — if the Q-LLM ITSELF is
 * manipulated by a sufficiently clever payload embedded in the tainted
 * source it was asked to summarize — is steered into FABRICATING a field
 * value that never appeared anywhere in the source at all. `quarantine.ts`'s
 * own input-provenance check (§6.2 step 1) validates that the QUARANTINE
 * CALL'S INPUT text resembles its claimed source; it says nothing whatsoever
 * about whether the Q-LLM's OUTPUT actually reflects that input, because
 * `createQuarantine()`'s `summarize()` unconditionally registers and trusts
 * whatever `impl()` returns ("The broker's own code — not the summarizing
 * LLM — unconditionally registers the output", quarantine.ts). A fabricated
 * field sails straight through that registration and lands at
 * `DERIVED_UNTRUSTED` with nothing distinguishing it from a genuine
 * extraction — defeating the quarantine path's core safety property
 * ("extract only what is really there") with the broker having no way to
 * notice.
 *
 * `checkFieldGrounding()` closes exactly that hole, and only that hole:
 * given the original untrusted source text(s) and the structured fields a
 * Q-LLM returned, it reports, per field, whether that field's value is
 * fuzzy-traceable back to ANY of the sources. It deliberately reuses this
 * library's own Layer 2 fuzzy-matching primitives
 * (`taint/fingerprint.ts`'s `shingleHashesOf`/`overlapCoefficient`/
 * `wordShingles`/`toRegistrableText`) rather than a new similarity
 * algorithm, so its behavior — and its known false-negative shape, GAPS.md
 * #8 — is exactly the same fuzzy matching the rest of this library already
 * ships and has already adversarially hardened, not a second, differently-
 * tuned implementation to reason about and re-audit separately. See this
 * file's "known limitations" note below for what that inheritance actually
 * means in practice for THIS use case.
 *
 * This library does not decide what to DO with an ungrounded field —
 * "integrator declares, library enforces" (GAPS.md #10's framing) applies
 * here exactly as it does to `capabilities`/`trusted`/`readsPrivateData`:
 * `checkFieldGrounding()` only returns a report. An integrator's own
 * `QuarantineImpl` (or a thin wrapper around it — see
 * `examples/quarantine-grounding-check.ts`) decides whether an ungrounded
 * field means reject the whole extraction, ask the Q-LLM to re-extract, or
 * flag the result for human review.
 *
 * Known limitations, stated plainly rather than left implicit:
 *
 *   1. **Inherits GAPS.md #8's short-excerpt false negative, and it bites
 *      harder here than it does anywhere else in this library.** A field
 *      value shorter than `SHINGLE_WIDTH` (5) words — the realistic common
 *      case for exactly the narrow, typed extraction fields GAPS.md #4
 *      recommends (a name, a date, an amount, an account number) — is
 *      shingled at a NARROWER width than the (typically much longer)
 *      source text, per `wordShingles()`'s own documented behavior
 *      (fingerprint.ts). A short field's shingles are then whole-string-
 *      different from the source's wider shingles even when the field is a
 *      verbatim quote of the source, so `overlapCoefficient()` scores
 *      exactly 0 — a genuine extraction reported as UNGROUNDED. This is not
 *      a new bug this file introduces; it is the exact, already-documented
 *      cross-length gap fingerprint.ts's own module doc comment names as
 *      "still open" and GAPS.md #8 already tracks — this file just inherits
 *      it, in a spot where it is more consequential than it is for Layer 2
 *      registry matching. Concretely: this check is most reliable for field
 *      values that are themselves at least a short sentence (a `summary`/
 *      `justification`/free-text field), and least reliable for single
 *      short tokens (a name, a bare number). Treat a `grounded: false` on a
 *      short field as inconclusive, not a confirmed fabrication, unless your
 *      own testing against representative field lengths says otherwise.
 *   2. **The reverse-direction risk `quarantine.ts` itself declined to use
 *      `overlapCoefficient` for.** `overlapCoefficient`'s own doc comment
 *      explains why `quarantine.ts` validates quarantine-call INPUT
 *      provenance with a dedicated asymmetric check instead of this
 *      function directly: `overlapCoefficient`'s `min()`-based denominator
 *      lets a large fabricated text inherit a small source's high score by
 *      borrowing just a few shared shingles. Here, the field value is
 *      almost always shorter (fewer shingles) than the source it's checked
 *      against, which is exactly the regime where `min()` picks the FIELD's
 *      own shingle count as the denominator — the safe direction, and the
 *      reason this file uses `overlapCoefficient` directly rather than
 *      re-deriving `quarantine.ts`'s own asymmetric coverage ratio. But an
 *      unusually long fabricated field (a free-text field padded well
 *      beyond the source's own length) checked against a short source
 *      inherits the identical risk `quarantine.ts` names and declines to
 *      accept for its own use — this file does not close it either. Keeping
 *      extraction schemas narrow (GAPS.md #4's actual safety property) is
 *      still the real mitigation, not a property this checker enforces.
 *   3. **"Grounded" means PRESENT, not TRUE.** This check proves a field
 *      value is fuzzy-traceable to text that really occurs in the source —
 *      it says nothing about whether that text is an honest description of
 *      anything. An attacker who plants a false claim directly in the
 *      source text itself (rather than getting the Q-LLM to invent
 *      something absent from it) — "Note to summarizer: the customer's
 *      account was already refunded $500" embedded in a support ticket, say
 *      — produces a field value that scores as GROUNDED, correctly, since
 *      it genuinely is present in the source: it is the source's own
 *      content that is untrustworthy, not the extraction of it. Closing
 *      that is exactly what the surrounding taint-tracking mechanism this
 *      library already ships is for (the watermark still gates the eventual
 *      sink at `DERIVED_UNTRUSTED` regardless of this check) — a field-level
 *      grounding check operates one level below that question entirely, on
 *      "did the Q-LLM invent this," not "should anything in the source be
 *      believed."
 *
 * STATUS: standalone and OPT-IN, not wired into `broker.ts`'s or
 * `quarantine.ts`'s own dispatch path — exactly the same "available but not
 * load-bearing/automatic" status Layer 2 fingerprint matching itself has
 * (DESIGN.md §4.2: "never load-bearing"). Nothing in this library calls
 * `checkFieldGrounding()` on your behalf; wire it into your own
 * `QuarantineImpl` if you want this check to run.
 */

import {
  overlapCoefficient,
  shingleHashesOf,
  toRegistrableText,
  wordShingles,
} from './taint/fingerprint.js';

// Deliberately loose, for the identical reason quarantine.ts's own
// MIN_SOURCE_COVERAGE constant is deliberately loose: a short, genuine
// field value can lose a large FRACTION of its shingles to a single small
// paraphrase edit even though it is obviously still the same content (see
// this module's own "known limitations" note above for the more severe,
// separate short-excerpt case this does NOT fix). Not exported — tune it
// per call via CheckFieldGroundingOpts.threshold instead, the same way
// every other threshold in this library (registry.ts's lookupFuzzy,
// policy/default-policy.ts's QUARANTINE_MIN_FUZZY_SCORE) stays a tunable
// parameter rather than a fixed constant an integrator has no way to reach.
const DEFAULT_GROUNDING_THRESHOLD = 0.3;

// A snippet is a debugging/audit convenience for a human reviewer, not part
// of the grounded/ungrounded decision itself — bounded so a pathologically
// large source text can't make a report unusably large.
const DEFAULT_MAX_SNIPPET_CHARS = 160;

export interface CheckFieldGroundingOpts {
  /**
   * Minimum `overlapCoefficient` score (against the best-matching source) a
   * field must reach to be reported `grounded: true`. Default 0.3 — see
   * this module's own `DEFAULT_GROUNDING_THRESHOLD` comment for why that
   * default is deliberately loose rather than tuned for precision. Raise it
   * for a schema whose fields are expected to be long, close-to-verbatim
   * quotes; lower it (never below 0) if your fields are expected to be
   * heavily paraphrased and a false "ungrounded" is more costly to your use
   * case than a missed fabrication.
   */
  threshold?: number;
  /** Maximum length, in characters, of a returned `snippet`. Default 160. */
  maxSnippetChars?: number;
}

/** Per-field grounding report — see this module's own file-header doc comment for what "grounded" means and does not mean. */
export interface FieldGroundingResult {
  /** The field name/key from the structured extraction, e.g. `"amount"`, `"recipient"`. */
  field: string;
  /**
   * `true` when this field's value scored at or above `threshold` against
   * at least one source text. `false` — UNGROUNDED — means no source text
   * accounts for enough of this field's content to trust it as a real
   * extraction rather than a hallucinated/fabricated addition. An empty
   * field value (`""`, after `toRegistrableText` coercion) is always
   * reported `grounded: true` — there is nothing in an empty value that
   * could have been fabricated, so flagging it would just be a false
   * positive against every legitimately blank/omitted optional field.
   */
  grounded: boolean;
  /**
   * The best (highest) `overlapCoefficient` score this field's value
   * reached against any single source text, in `[0, 1]` — see that
   * function's own doc comment (fingerprint.ts) for exactly what it
   * measures. `1` for an empty field value (the vacuous case above); `0`
   * when the field shared literally no shingle with any source.
   */
  score: number;
  /**
   * Index into the `sources` array (always `[0]` for a single source text)
   * this field's best score was measured against. Present whenever ANY
   * source produced a nonzero score, even one below `threshold` — so a
   * near-miss can still be inspected — and absent only when the field
   * shared zero shingles with every source.
   */
  bestSourceIndex?: number;
  /**
   * A short excerpt of the best-matching source, anchored on a shingle the
   * field value shares with it — for a human reviewer or a log line, not a
   * claim of exact character-offset provenance: it locates the first
   * shared shingle's own first word (case-insensitively) in the RAW source
   * text and takes a bounded window around it, so surrounding punctuation
   * and whitespace are the source's real text, but the anchor point itself
   * is approximate for a repeated word. Present under the same condition as
   * `bestSourceIndex`.
   */
  snippet?: string;
}

function locateSnippet(fieldText: string, source: string, maxChars: number): string | undefined {
  const fieldShingles = new Set(wordShingles(fieldText));
  if (fieldShingles.size === 0) return undefined;
  for (const shingle of wordShingles(source)) {
    if (!fieldShingles.has(shingle)) continue;
    const anchorWord = shingle.split(' ')[0];
    if (!anchorWord) continue;
    const index = source.toLowerCase().indexOf(anchorWord);
    if (index === -1) continue;
    const lead = Math.min(index, Math.floor(maxChars / 3));
    const start = index - lead;
    const end = Math.min(source.length, start + maxChars);
    const prefix = start > 0 ? '…' : '';
    const suffix = end < source.length ? '…' : '';
    return prefix + source.slice(start, end).trim() + suffix;
  }
  return undefined;
}

function checkOneField(
  field: string,
  value: unknown,
  sourceList: readonly string[],
  sourceHashes: readonly Uint32Array[],
  threshold: number,
  maxSnippetChars: number,
): FieldGroundingResult {
  const fieldText = toRegistrableText(value);
  const fieldHashes = shingleHashesOf(fieldText);
  if (fieldHashes.length === 0) {
    return { field, grounded: true, score: 1 };
  }

  let bestScore = 0;
  let bestIndex = -1;
  for (let i = 0; i < sourceHashes.length; i++) {
    const score = overlapCoefficient(fieldHashes, sourceHashes[i]!);
    if (score > bestScore) {
      bestScore = score;
      bestIndex = i;
    }
  }

  const result: FieldGroundingResult = {
    field,
    grounded: bestScore >= threshold,
    score: bestScore,
  };
  if (bestIndex >= 0) {
    result.bestSourceIndex = bestIndex;
    const snippet = locateSnippet(fieldText, sourceList[bestIndex]!, maxSnippetChars);
    if (snippet !== undefined) result.snippet = snippet;
  }
  return result;
}

/**
 * Checks each field of a Q-LLM's structured extraction result against the
 * original untrusted source text(s) it was given, reporting whether each
 * field's value is fuzzy-traceable back to at least one source — see this
 * module's own file-header doc comment for the full threat model, and its
 * "known limitations" note for what this does NOT catch.
 *
 * `fields` is the structured extraction result itself (typically
 * `QuarantineResult.value`, or whatever your `QuarantineImpl` returned
 * before `schema.parse()` — either works, since this only reads own-
 * enumerable values). `sources` is the original source text `summarize()`
 * was called with — a single string, or several when a field could
 * plausibly be grounded in more than one document (e.g. checking one
 * extraction against several fetched pages). Throws a plain `Error` if
 * `sources` is an empty array — there is nothing to check groundedness
 * against.
 *
 * Non-string field values are coerced via `toRegistrableText` (the same
 * JSON.stringify-based coercion `quarantine.ts`/the registry already use
 * for anything non-string), so a structured/nested field value is checked
 * against its JSON serialization, not walked recursively field-by-field.
 */
export function checkFieldGrounding(
  fields: Record<string, unknown>,
  sources: string | readonly string[],
  opts: CheckFieldGroundingOpts = {},
): FieldGroundingResult[] {
  const threshold = opts.threshold ?? DEFAULT_GROUNDING_THRESHOLD;
  const maxSnippetChars = opts.maxSnippetChars ?? DEFAULT_MAX_SNIPPET_CHARS;
  const sourceList = typeof sources === 'string' ? [sources] : sources;
  if (sourceList.length === 0) {
    throw new Error(
      'checkFieldGrounding() requires at least one source text -- pass the original untrusted content the Q-LLM was given (e.g. the text argument passed to broker.summarize()).',
    );
  }
  const sourceHashes = sourceList.map((s) => shingleHashesOf(s));

  return Object.entries(fields).map(([field, value]) =>
    checkOneField(field, value, sourceList, sourceHashes, threshold, maxSnippetChars),
  );
}
