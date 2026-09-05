/**
 * A custom PolicyFn reading TaintContext.sourceClasses — the source-CLASS
 * axis GAPS.md #28 names as missing from TaintLevel, and deliberately never
 * read by defaultPolicy itself. Run with:
 *
 *   npx tsx examples/source-class-policy.ts
 *
 * The motivating scenario GAPS.md #28 names directly: "our internal MCP
 * server is untrusted but not random-web-page untrusted." TaintLevel alone
 * cannot express that — both sources collapse to the identical
 * RAW_UNTRUSTED level the instant either is read by an untrusted (non-
 * `trusted`) source tool. Declaring the internal server `trusted: true`
 * would "fix" this by dropping taint tracking for it entirely — one of the
 * two bad workarounds GAPS.md #28 names — which is a materially different
 * (and riskier) choice than what this example does: keep the content fully
 * tracked, untrusted, and fingerprinted, and use its declared *class* only
 * to decide how MUCH friction a later privileged call sees.
 *
 * Demonstrates, in order:
 *   1. An EXFIL sink call gated only by an internal-mcp-classed source ->
 *      the custom policy downgrades defaultPolicy's REQUIRE_APPROVAL to
 *      ALLOW_WITH_WARNING.
 *   2. The identical call, but the scope ALSO saw a public-web-classed
 *      source in between -> the custom policy defers to defaultPolicy
 *      unchanged (REQUIRE_APPROVAL, denied — no approvalChannel configured).
 *   3. An EXEC sink call, internal-mcp-only -> still BLOCK. This policy only
 *      ever loosens an otherwise-REQUIRE_APPROVAL verdict; it never touches
 *      EXEC's unconditional RAW_UNTRUSTED BLOCK (DESIGN.md §7.2) or an
 *      already-BLOCK verdict for any sink class.
 */

import {
  createBroker,
  defaultPolicy,
  ToolCallBlockedError,
  type PolicyFn,
  type ToolExecutor,
} from '../src/index.js';

const INTERNAL_PAGE = 'Quarterly roadmap notes: ship the Q3 release by the 15th.';
const PUBLIC_PAGE = 'Some unrelated public blog post about gardening.';

function fetchInternal(): ToolExecutor {
  return {
    name: 'fetch_internal_wiki',
    capabilities: { capabilities: [] },
    isSource: true,
    // The declaration this whole example is about: labeling WHICH kind of
    // untrusted source this is, without making it `trusted` (still fully
    // tracked, still fingerprinted, still RAW_UNTRUSTED — see
    // ToolExecutor.sourceClass's own doc comment, types.ts).
    sourceClass: 'internal-mcp',
    async execute() {
      return INTERNAL_PAGE;
    },
  };
}

function fetchPublicPage(): ToolExecutor {
  return {
    name: 'fetch_public_page',
    capabilities: { capabilities: [] },
    isSource: true,
    sourceClass: 'public-web',
    async execute() {
      return PUBLIC_PAGE;
    },
  };
}

function postToWebhook(): ToolExecutor {
  return {
    name: 'post_to_webhook',
    capabilities: { capabilities: ['net:outbound'] },
    async execute(args) {
      return `posted: ${JSON.stringify(args)}`;
    },
  };
}

function shellExec(): ToolExecutor {
  return {
    name: 'shell_exec',
    capabilities: { capabilities: ['exec:shell'] },
    async execute(args) {
      return `[would have run] ${JSON.stringify(args)}`;
    },
  };
}

/**
 * Wraps defaultPolicy, downgrading its REQUIRE_APPROVAL verdict to
 * ALLOW_WITH_WARNING *only* when every source class contributing to the
 * current scope's watermark is 'internal-mcp' — never touching ALLOW,
 * BLOCK, or QUARANTINE_AND_RETRY, and never touching a scope that has seen
 * even one source of any other class (including an unclassified one:
 * `taint.sourceClasses` containing anything other than exactly
 * `['internal-mcp']` falls straight through to defaultPolicy unchanged).
 *
 * This is a genuine, deliberate loosening of the default posture — the
 * kind of decision GAPS.md #28 explicitly leaves to an integrator's own
 * judgment rather than picking for them (`defaultPolicy` itself never does
 * this). It only makes sense when 'internal-mcp' is a source an integrator
 * has actually reviewed and is willing to stand behind as lower-risk than
 * an arbitrary fetched page — labeling a source 'internal-mcp' does not
 * make its CONTENT any less attacker-influenceable than before.
 */
const sourceClassAwarePolicy: PolicyFn = async (call, taint) => {
  const base = await defaultPolicy(call, taint);
  const onlyInternalMcp =
    taint.sourceClasses !== undefined &&
    taint.sourceClasses.length > 0 &&
    taint.sourceClasses.every((sourceClass) => sourceClass === 'internal-mcp');

  if (base.action === 'REQUIRE_APPROVAL' && onlyInternalMcp) {
    return {
      action: 'ALLOW_WITH_WARNING',
      reason:
        `Downgraded from REQUIRE_APPROVAL: every contributing source is our own reviewed ` +
        `internal-mcp deployment (underlying reason: "${base.reason}").`,
    };
  }
  return base;
};

async function section1_internalOnly(): Promise<void> {
  console.log('\n=== 1. EXFIL sink, internal-mcp-only exposure ===');
  const broker = createBroker({ policy: sourceClassAwarePolicy });
  const fetchWiki = broker.wrap(fetchInternal());
  const webhook = broker.wrap(postToWebhook());

  await fetchWiki.execute({});
  console.log(
    'sourceClasses in scope:',
    broker.scope.watermark.sources.map((s) => s.sourceClass),
  );

  const result = await webhook.execute({ url: 'https://internal.example/status', body: 'ok' });
  console.log('webhook call ALLOWED (downgraded from REQUIRE_APPROVAL):', result);
}

async function section2_mixedSources(): Promise<void> {
  console.log('\n=== 2. EXFIL sink, internal-mcp AND public-web exposure — no downgrade ===');
  const broker = createBroker({ policy: sourceClassAwarePolicy });
  const fetchWiki = broker.wrap(fetchInternal());
  const fetchPublic = broker.wrap(fetchPublicPage());
  const webhook = broker.wrap(postToWebhook());

  await fetchWiki.execute({});
  await fetchPublic.execute({});
  console.log(
    'sourceClasses in scope:',
    broker.scope.watermark.sources.map((s) => s.sourceClass),
  );

  try {
    await webhook.execute({ url: 'https://internal.example/status', body: 'ok' });
    console.log('UNEXPECTED: call was allowed');
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      console.log(
        'REQUIRE_APPROVAL, denied (no approvalChannel configured) — defaultPolicy unchanged:',
        err.decision.action,
      );
    } else {
      throw err;
    }
  }
}

async function section3_execNeverDowngraded(): Promise<void> {
  console.log('\n=== 3. EXEC sink, internal-mcp-only — still an unconditional BLOCK ===');
  const broker = createBroker({ policy: sourceClassAwarePolicy });
  const fetchWiki = broker.wrap(fetchInternal());
  const shell = broker.wrap(shellExec());

  await fetchWiki.execute({});

  try {
    await shell.execute({ cmd: 'rm -rf /tmp/scratch' });
    console.log('UNEXPECTED: call was allowed');
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      console.log(
        "still BLOCK — this policy only ever downgrades REQUIRE_APPROVAL, never EXEC's unconditional block:",
        err.decision.action,
      );
    } else {
      throw err;
    }
  }
}

async function main(): Promise<void> {
  await section1_internalOnly();
  await section2_mixedSources();
  await section3_execNeverDowngraded();
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
