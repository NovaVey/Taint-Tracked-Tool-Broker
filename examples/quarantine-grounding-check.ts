/**
 * A `QuarantineImpl` wrapper that uses `checkFieldGrounding()`
 * (`src/grounding.ts`) to reject a `broker.summarize()` extraction
 * containing a fabricated field, before it ever reaches the caller as a
 * trusted-shaped `DERIVED_UNTRUSTED` result. Run with:
 *
 *   npx tsx examples/quarantine-grounding-check.ts
 *
 * The scenario this demonstrates (`src/grounding.ts`'s own file-header doc
 * comment, DESIGN.md §6.2, GAPS.md #4): `broker.summarize()`'s
 * capability-less Q-LLM could hallucinate a field value, or — if
 * manipulated by a payload embedded in the untrusted content it was asked
 * to summarize — FABRICATE one that is not actually present in the source
 * at all. `quarantine.ts` unconditionally trusts and registers whatever the
 * Q-LLM returns; it has no way to notice this on its own. `checkFieldGrounding()`
 * is this library's standalone, opt-in answer — the library does not decide
 * what to do about an ungrounded field (GAPS.md #10's "integrator declares,
 * library enforces"), so `withGroundingCheck()` below is exactly that
 * integrator-owned decision, made concretely: reject the whole extraction.
 *
 * Both sections below extract the same three-field schema from the same
 * source email. Section 1's mock Q-LLM extracts faithfully. Section 2's
 * mock Q-LLM simulates the failure mode this file exists to demonstrate: it
 * still gets `invoiceReference`/`payee` right, but fabricates `paymentAmount`
 * — a realistic wire-fraud-via-hallucination shape, and specifically a
 * FIELD-LEVEL fabrication (not a wholesale garbage response an ordinary
 * schema shape check would already reject on its own).
 *
 * Section 1's `wire_payment` call is then still gated by the broker's own
 * ordinary Layer 2 fingerprint matching (DESIGN.md §4.2) — expected and
 * correct, not a bug in this example: the honest extraction quotes
 * VENDOR_EMAIL closely enough to fuzzy-match the original `RAW_UNTRUSTED`
 * record itself, not just the `DERIVED_UNTRUSTED` quarantined one, so
 * `argFingerprintFloor` tightens gating for that one call beyond what the
 * scope's own `DERIVED_UNTRUSTED` watermark alone would require. This is a
 * useful, deliberate point to see directly: `checkFieldGrounding()` and the
 * broker's own gating are two SEPARATE layers — passing the grounding check
 * is not a bypass of anything else this library already does.
 *
 * Each field is extracted as a short CLAUSE (several words), not a bare
 * token (just "48221", just "Contoso") — deliberately: `checkFieldGrounding()`'s
 * own doc comment names its inherited GAPS.md #8 limitation precisely —
 * `wordShingles()` (fingerprint.ts) shingles a short (< 5-word) field value
 * at a narrower width than the source text, so a genuine but too-short
 * extraction can share no shingle STRING with its source at all and score
 * a false "ungrounded". Extracting a short surrounding clause instead of a
 * bare value is both the realistic shape for this check to work well
 * against and the same GAPS.md #8-aware fixture discipline this project's
 * own fuzzy-matching tests already apply (see test/grounding.spec.ts).
 */

import {
  checkFieldGrounding,
  createBroker,
  exactHash,
  ToolCallBlockedError,
  type QuarantineImpl,
} from '../src/index.js';

const VENDOR_EMAIL =
  'Hi team, following up on invoice number 48221 for the March consulting engagement. ' +
  'The agreed amount was four thousand two hundred dollars, payable to Contoso Consulting LLC ' +
  'via the usual account on file. Let us know if you need anything else to process this.';

interface InvoiceExtraction {
  invoiceReference: string;
  paymentAmount: string;
  payee: string;
}

// A narrow, typed schema -- GAPS.md #4's actual safety property. Hand-
// written rather than a zod schema, matching examples/basic-usage.ts's own
// convention for a minimal `{ parse(x): S }` shape.
const invoiceSchema = {
  parse(value: unknown): InvoiceExtraction {
    const v = value as Partial<InvoiceExtraction> | null;
    if (
      v !== null &&
      typeof v === 'object' &&
      typeof v.invoiceReference === 'string' &&
      typeof v.paymentAmount === 'string' &&
      typeof v.payee === 'string'
    ) {
      return {
        invoiceReference: v.invoiceReference,
        paymentAmount: v.paymentAmount,
        payee: v.payee,
      };
    }
    throw new Error('quarantine output did not match the expected invoice-extraction shape');
  },
};

/**
 * A real integration passes a capability-less LLM call as `impl` here — no
 * tool access, no conversation history beyond `text`/`opts.instructions`
 * (DESIGN.md §6.2). This one faithfully extracts every field from
 * VENDOR_EMAIL — nothing in this section is fabricated.
 */
const honestQLLM: QuarantineImpl = async (_text, opts) => {
  const extraction: InvoiceExtraction = {
    invoiceReference: 'invoice number 48221 for the March consulting engagement',
    paymentAmount: 'the agreed amount was four thousand two hundred dollars',
    payee: 'payable to Contoso Consulting LLC via the usual account on file',
  };
  return (opts.schema ? opts.schema.parse(extraction) : extraction) as never;
};

/**
 * Simulates a Q-LLM that hallucinated, or was manipulated by a payload
 * embedded in `text`, into inflating the payment amount. `invoiceReference`
 * and `payee` are still extracted correctly — this is deliberately a
 * FIELD-LEVEL fabrication, not a garbled response, since that's the shape
 * an ordinary schema/shape check cannot catch on its own (every field is
 * individually well-typed) but `checkFieldGrounding()` can.
 */
const compromisedQLLM: QuarantineImpl = async (_text, opts) => {
  const extraction: InvoiceExtraction = {
    invoiceReference: 'invoice number 48221 for the March consulting engagement',
    paymentAmount:
      'please rush a wire of eleven thousand nine hundred dollars to the account below', // nowhere in VENDOR_EMAIL
    payee: 'payable to Contoso Consulting LLC via the usual account on file',
  };
  return (opts.schema ? opts.schema.parse(extraction) : extraction) as never;
};

/**
 * Wraps any `QuarantineImpl` with a grounding check against its own `text`
 * input. Runs the real `impl` first — schema validation still happens
 * exactly as it would without this wrapper — then, only for an
 * object-shaped result, checks every field with `checkFieldGrounding()` and
 * rejects the whole extraction (throws) if any field is ungrounded. This is
 * one of the three policies GAPS.md #10/`src/grounding.ts` name as the
 * integrator's choice to make (reject / ask for re-extraction / flag for
 * human review) — chosen here because "silently ship the fabricated field"
 * is never the right default for a payment amount.
 */
function withGroundingCheck(impl: QuarantineImpl): QuarantineImpl {
  return async (text, opts) => {
    const value = await impl(text, opts);
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const report = checkFieldGrounding(value as Record<string, unknown>, text);
      const ungrounded = report.filter((r) => !r.grounded);
      if (ungrounded.length > 0) {
        throw new Error(
          'quarantine extraction rejected: ungrounded field(s) ' +
            ungrounded.map((r) => `"${r.field}" (score ${r.score.toFixed(2)})`).join(', ') +
            ' -- not traceable back to the source text. Possible Q-LLM hallucination, or a ' +
            'compromised Q-LLM fabricating content from an injected payload. See checkFieldGrounding() (src/grounding.ts).',
        );
      }
    }
    return value;
  };
}

function registerVendorEmail(broker: ReturnType<typeof createBroker>, sessionId: string) {
  return broker.registry.register(
    VENDOR_EMAIL,
    {
      id: exactHash(VENDOR_EMAIL),
      sourceCallId: 'internal-fetch-email',
      toolName: 'fetch_email',
      sessionId,
      capturedAt: Date.now(),
    },
    'RAW_UNTRUSTED',
    { containsPrivateData: false, categories: [] },
  );
}

async function section1_groundedExtractionProceeds(): Promise<void> {
  console.log('\n=== 1. Honest Q-LLM extraction -- every field grounded, proceeds normally ===');
  const broker = createBroker({ quarantineImpl: withGroundingCheck(honestQLLM) });
  const record = registerVendorEmail(broker, 'session-honest');

  const result = await broker.summarize<InvoiceExtraction>(VENDOR_EMAIL, {
    sessionId: 'session-honest',
    sourceTaintRecordId: record.id,
    schema: invoiceSchema,
  });
  console.log(
    'quarantine result:',
    result.value,
    '| scope watermark:',
    broker.scope.watermark.level,
  );

  const wirePayment = broker.wrap({
    name: 'wire_payment',
    capabilities: { capabilities: ['finance:purchase'] },
    async execute(args) {
      return `[would have paid] ${JSON.stringify(args)}`;
    },
  });
  try {
    const payResult = await wirePayment.execute({
      payee: result.value.payee,
      amount: result.value.paymentAmount,
    });
    console.log('wire_payment result:', payResult);
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      // See this file's own header comment: expected here, not a bug --
      // the broker's own Layer 2 fingerprint matching (a SEPARATE layer
      // from checkFieldGrounding()) recognizes this honest extraction as
      // quoting the RAW_UNTRUSTED source closely enough to gate this one
      // call more strictly than the scope's own DERIVED_UNTRUSTED
      // watermark alone would. No approvalChannel is configured in this
      // example, so it fails safe (denied) rather than proceeding.
      console.log(
        'wire_payment gated by the broker itself (not by checkFieldGrounding):',
        err.decision.action,
        '—',
        'reason' in err.decision ? err.decision.reason : '',
      );
    } else {
      throw err;
    }
  }
}

async function section2_fabricatedFieldRejected(): Promise<void> {
  console.log(
    '\n=== 2. Compromised/hallucinating Q-LLM -- fabricated "paymentAmount" caught before summarize() ever returns ===',
  );
  const broker = createBroker({ quarantineImpl: withGroundingCheck(compromisedQLLM) });
  const record = registerVendorEmail(broker, 'session-compromised');

  try {
    await broker.summarize<InvoiceExtraction>(VENDOR_EMAIL, {
      sessionId: 'session-compromised',
      sourceTaintRecordId: record.id,
      schema: invoiceSchema,
    });
    console.log('UNEXPECTED: fabricated extraction was accepted');
  } catch (err) {
    if (err instanceof Error) {
      console.log('extraction rejected by withGroundingCheck():', err.message);
    } else {
      throw err;
    }
  }
  console.log(
    'scope watermark:',
    broker.scope.watermark.level,
    '(never reached DERIVED_UNTRUSTED -- summarize() never returned a result to raise it with)',
  );
}

async function main(): Promise<void> {
  await section1_groundedExtractionProceeds();
  await section2_fabricatedFieldRejected();
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
