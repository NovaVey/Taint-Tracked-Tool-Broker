/**
 * Wiring TTTB into the OpenAI Agents SDK (`@openai/agents`'s `tool()` +
 * `Agent`/`run()`). Run with:
 *
 *   npx tsx examples/openai-agents-sdk-integration.ts
 *
 * Like the other two framework examples in this session, this does NOT
 * depend on the real `@openai/agents` package — `MockAgentsSdkTool`/
 * `mockRun` below are minimal structural stands-ins for the SDK's real
 * `tool()`/`Agent`/`run()` shapes, just enough to demonstrate the wiring
 * without an extra dependency or a live model call.
 *
 * Where `examples/langchain-integration.ts` and
 * `examples/vercel-ai-sdk-integration.ts` both show a BLOCK verdict (an
 * EXEC sink, unconditionally gated), this one deliberately exercises the
 * REQUIRE_APPROVAL path instead — via `createDeferredApprovalChannel()`
 * (`src/approval.ts`, also used by `examples/anthropic-tool-loop.ts`'s
 * Scenario 2) — since a real agent-framework integration needs to handle
 * BOTH outcomes, and every other framework example already covers BLOCK.
 */

import { createBroker, createDeferredApprovalChannel, ToolCallBlockedError, type ToolCallBroker, type ToolExecutor } from '../src/index.js';

// ---------------------------------------------------------------------------
// A minimal stand-in for @openai/agents' tool() + Agent/run() shapes.
// ---------------------------------------------------------------------------

interface MockAgentsSdkTool<A = unknown, R = unknown> {
  name: string;
  description: string;
  /** Real @openai/agents uses a zod schema here — `{ parse(x: unknown): A }` is structurally compatible with one. */
  parameters: { parse(input: unknown): A };
  execute(args: A): Promise<R>;
}

/** Stands in for `import { tool } from '@openai/agents'`. */
function tool<A, R>(config: { name: string; description: string; parameters: { parse(input: unknown): A }; execute(args: A): Promise<R> }): MockAgentsSdkTool<A, R> {
  return config;
}

/** Stands in for `Agent`'s tool registry + `run(agent, input)`'s own dispatch loop calling a requested tool's execute(). */
async function mockRun(tools: MockAgentsSdkTool[], toolName: string, rawArgs: unknown): Promise<{ ok: true; result: unknown } | { ok: false; error: unknown }> {
  const t = tools.find((candidate) => candidate.name === toolName);
  if (!t) return { ok: false, error: new Error(`no such tool: ${toolName}`) };
  try {
    return { ok: true, result: await t.execute(t.parameters.parse(rawArgs)) };
  } catch (error) {
    return { ok: false, error };
  }
}

// ---------------------------------------------------------------------------
// The wiring: broker.wrap() first, the Agents SDK's tool() wraps the result.
// ---------------------------------------------------------------------------

/** Registers `executor` with the broker and returns an `@openai/agents`-shaped tool whose `execute` routes through `broker.call()`. */
function wrapAsAgentsSdkTool<A, R>(
  broker: ToolCallBroker,
  executor: ToolExecutor<A, R>,
  description: string,
  parameters: { parse(input: unknown): A },
): MockAgentsSdkTool<A, R> {
  const wrapped = broker.wrap(executor);
  return tool<A, R>({ name: executor.name, description, parameters, execute: (args) => wrapped.execute(args) });
}

async function main(): Promise<void> {
  console.log('=== OpenAI Agents SDK integration: broker.wrap() behind tool()/execute(), REQUIRE_APPROVAL path ===\n');

  const approvalChannel = createDeferredApprovalChannel({
    onPending: (token) => {
      console.log(`  [approval requested] token=${token} — in a real integration this is where you'd notify a human (Slack, an approval-queue UI, ...).`);
      setTimeout(() => {
        console.log('  [human responds] approved.');
        approvalChannel.resolve(token, true);
      }, 50);
    },
  });
  const broker = createBroker({ approvalChannel });

  const tools: MockAgentsSdkTool[] = [
    wrapAsAgentsSdkTool(
      broker,
      { name: 'fetch_page', capabilities: { capabilities: [] }, isSource: true, async execute({ url }: { url: string }) { return 'Here is the quarterly report content.'; } },
      'Fetches the raw text content of a web page by URL.',
      { parse: (x) => x as { url: string } },
    ),
    wrapAsAgentsSdkTool(
      broker,
      { name: 'write_file', capabilities: { capabilities: ['write:fs'] }, async execute({ path, contents }: { path: string; contents: string }) { return `wrote: ${path}`; } },
      'Writes contents to a local file path.',
      { parse: (x) => x as { path: string; contents: string } },
    ),
  ];

  // run(agent, input) drives a loop that calls each requested tool exactly
  // like this when the model requests it — the broker sees this
  // identically to any other integration.
  const fetchOutcome = await mockRun(tools, 'fetch_page', { url: 'https://example.com/report' });
  console.log('fetch_page ->', fetchOutcome.ok ? fetchOutcome.result : fetchOutcome.error);
  console.log('scope watermark:', broker.scope.watermark.level);

  // write_file is a MUTATE sink under a RAW_UNTRUSTED scope -> REQUIRE_APPROVAL
  // (not BLOCK) — createDeferredApprovalChannel() suspends this call until
  // the onPending hook's simulated human decision resolves it.
  const writeOutcome = await mockRun(tools, 'write_file', { path: '/tmp/report.txt', contents: 'saved' });
  if (writeOutcome.ok) {
    console.log('write_file ->', writeOutcome.result, '(approved — REQUIRE_APPROVAL resolved true, execution proceeded)');
  } else if (writeOutcome.error instanceof ToolCallBlockedError) {
    console.log('UNEXPECTED: denied —', writeOutcome.error.decision.action);
  } else {
    throw writeOutcome.error;
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
