# AWS Bedrock Agents: the Lambda-handler pattern (GAPS.md #12)

Every other integration point this repository documents — LangChain, the Vercel AI SDK, the OpenAI Agents SDK, Genkit, Mastra, LlamaIndex.TS, Semantic Kernel, MCP, a raw Anthropic/OpenAI tool-calling loop — shares one structural property that makes an `examples/*.ts` file the right way to show it: somewhere in code you write and control, your own agent loop calls a tool-implementation function directly, in-process, and awaits its result before deciding what happens next. `broker.wrap()` sits exactly at that call site, in every one of those examples, regardless of how different each framework's tool-declaration syntax looks on the surface (`tool()`, `createTool()`, `defineTool()`, `KernelFunction.from()`, ...). That's not incidental — it's the one thing all of those integration shapes have in common, and it's the reason a small structural mock of each framework (never the real package — see any file in `examples/` for why) is enough to demonstrate the wiring honestly.

A Lambda- or REST-backed AWS Bedrock Agent Action Group does not have that property, and pretending it does — by writing an `examples/bedrock-agents-integration.ts` shaped like every other file in that directory, with a mocked "Bedrock orchestrator" calling a `broker.wrap()`-wrapped function directly in the same process — would assert something false about the actual integration. This document explains why, and what the honest pattern actually looks like instead. It is deliberately prose, not a runnable example, for the reason stated in its own first section.

## Why this isn't an `examples/*.ts` file

In every framework example in this repository, the entity making tool-calling *decisions* — which tool to call, when, how to fold the result back into the next model turn — is code you wrote, running in the same Node.js process as the broker. That's true even for MCP (`examples/mcp-integration.ts`, `examples/mcp-sdk-integration.ts`): the MCP *server* may be a separate process reached over a real transport, but the *client*-side agent loop that decides to call a tool, and the `broker.wrap()`-wrapped function that loop calls to do it, are still yours, still local, still one continuously-running process for the life of the session.

A Bedrock Agent's orchestration loop is not your process. It is AWS's own managed service — you never write it, and you cannot put a broker instance inside it. What you own is only the Action Group: a Lambda function ARN, or an HTTP endpoint described by an OpenAPI schema, that Bedrock's managed orchestrator *calls out to*, once per operation the model decided to invoke, over the network, and waits on a response from before it continues. There is no line of TypeScript anywhere that reads `await tool.execute(args)` and is called directly by Bedrock's decision loop — the boundary between "the model decided to call a tool" and "your code that services that call" is a wire protocol (a Lambda invocation event/response, or an HTTP request/response), not a function reference in a process you control.

A copy-paste example written the way this directory's other files are would have to fake that boundary — a `mockBedrockOrchestrator()` in the same file calling `wrappedTool.execute(args)` directly, the same shape as `mockDispatchToolCall()` in `examples/vercel-ai-sdk-integration.ts`. But `MockAiSdkTool` is an honest stand-in for the real `ai` package specifically *because* the real package also calls `execute()` directly, in-process — the mock's topology matches reality even though its types are simplified. A mocked Bedrock orchestrator calling a wrapped function directly would get the topology itself wrong, not just the fidelity of the types: it would show `broker.wrap()` sitting at a call site that does not exist in a real Bedrock/Lambda deployment, which is a materially worse thing for an integrator to copy than an imperfect mock of a real SDK. (One configuration of Bedrock Agents genuinely *does* have this shape — see "Scope: this is about Lambda/REST Action Groups specifically" below.)

There's a second problem a runnable example can't paper over either: unlike a framework package's `tool()`/`execute()` signature, which is fixed and importable, "how does one Lambda handler dispatch an incoming Action Group invocation to the right tool implementation" has no single canonical shape to mock — it depends on whether the Action Group uses the simpler function-details schema or a full OpenAPI schema, and on how you've structured your own handler. A single small `.ts` file claiming to be *the* pattern would be asserting more specificity than the integration actually has.

## The correct pattern: `broker.wrap()` inside the Lambda handler

The in-process boundary hasn't disappeared — it has just moved to a place none of the other examples needed to reach for: **the Lambda function that backs the Action Group.** Bedrock's managed orchestrator never sees your TypeScript source, but one Lambda invocation *is* one ordinary Node.js process running your handler function, synchronously (from that invocation's point of view) calling whatever tool-implementation code lives inside it. That handler function is exactly the same kind of "the function that actually does the tool call" that `broker.wrap()` interposes on everywhere else in this repository — it's just invoked by AWS's runtime instead of by a `while` loop you wrote.

The pattern: construct the broker and `broker.wrap()` your real tool executor(s) inside the handler (or at module scope — see the limitation below for why that changes less than it looks like it does), dispatch the incoming event to the matching wrapped executor by name, call it, and translate the result — or a caught `ToolCallBlockedError` — into the response shape Bedrock expects.

```ts
import {
  createBroker,
  ToolCallBlockedError,
  type ToolExecutor,
} from 'taint-tracked-tool-broker';

// This is the "function details" Action Group schema — the simpler of the
// two Bedrock supports. An OpenAPI-schema Action Group carries the same
// call shape under event.apiPath/event.httpMethod/event.requestBody instead
// of event.function/event.parameters, and the response envelope differs to
// match (apiPath/httpMethod/httpStatusCode instead of function). Field
// names sketched here match AWS's documented Lambda contract as of this
// writing — check AWS's own Action Group Lambda docs before shipping, this
// is not reproduced from a schema this library validates against.
interface BedrockActionGroupEvent {
  actionGroup: string;
  function: string;
  parameters?: { name: string; type: string; value: string }[];
  sessionId: string;
  sessionAttributes?: Record<string, string>;
}

// Built once per invocation, exactly the same tool declarations — isSource,
// capabilities, readsPrivateData — every other example in this repository
// uses (docs/classifying-tools.md's checklist applies here unchanged; the
// broker has no idea it's running inside a Lambda handler).
function buildTools(broker: ReturnType<typeof createBroker>) {
  return {
    fetch_ticket: broker.wrap({
      name: 'fetch_ticket',
      capabilities: { capabilities: [] },
      isSource: true, // a support ticket's body is content the agent didn't author
      async execute(args: { ticketId: string }) {
        return fetchTicketBodyFromYourSystem(args.ticketId);
      },
    }),
    post_comment: broker.wrap({
      name: 'post_comment',
      capabilities: { capabilities: ['write:external-account'] },
      async execute(args: { ticketId: string; body: string }) {
        await postCommentToYourSystem(args.ticketId, args.body);
      },
    }),
  } satisfies Record<string, ToolExecutor>;
}

function paramsToArgs(parameters: BedrockActionGroupEvent['parameters']): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  // Bedrock sends every parameter value as a string regardless of its
  // declared type — coerce per your own schema if a tool needs a number/bool.
  for (const p of parameters ?? []) args[p.name] = p.value;
  return args;
}

export const handler = async (event: BedrockActionGroupEvent) => {
  const broker = createBroker(); // see "what doesn't survive a cold start" below
  const tools = buildTools(broker);
  const tool = tools[event.function as keyof typeof tools];

  let responseBody: string;
  try {
    if (!tool) throw new Error(`unknown function: ${event.function}`);
    const result = await tool.execute(paramsToArgs(event.parameters));
    responseBody = typeof result === 'string' ? result : JSON.stringify(result);
  } catch (err) {
    // A ToolCallBlockedError here is the gate working, not a bug — report
    // it back to the model as an ordinary function result (the same thing
    // every agent-loop example in this repository does with a caught
    // ToolCallBlockedError) so the model can react, instead of letting the
    // Lambda invocation itself fail and Bedrock retry blind.
    responseBody =
      err instanceof ToolCallBlockedError
        ? `Blocked: ${'reason' in err.decision ? err.decision.reason : err.decision.action}`
        : `Error: ${(err as Error).message}`;
  }

  return {
    messageVersion: '1.0',
    response: {
      actionGroup: event.actionGroup,
      function: event.function,
      functionResponse: { responseBody: { TEXT: { body: responseBody } } },
    },
  };
};
```

This is the same interposition every other example demonstrates — `broker.wrap()` around the real tool implementation, gating every call before it executes — just relocated to the one place in a Bedrock/Lambda deployment where an in-process function call to a tool implementation genuinely exists.

**Scope: this is about Lambda/REST Action Groups specifically.** Bedrock Agents also supports a `RETURN_CONTROL` invocation mode, where the agent hands the requested tool call *back to your own calling application* to execute, rather than invoking a Lambda itself — your client receives the invocation request, runs the tool, and sends the result back on the next `InvokeAgent` call. That mode is the ordinary in-process shape every other example in this directory already covers (your own client-side loop calls a `broker.wrap()`-wrapped function directly, same as `examples/anthropic-tool-loop.ts`); nothing in this document applies to it. This document is specifically about the case where Bedrock's own managed orchestrator invokes your Action Group directly, which is the Lambda/REST case above.

## What doesn't survive a cold start

`createBroker()`'s watermark and `TaintRegistry` live in that broker instance's own process memory (GAPS.md #12) — true everywhere in this library, but everywhere else in this repository, one broker instance lives for the whole session, so it's not a practical concern. A Lambda-backed Action Group breaks that assumption structurally, not incidentally: **each invocation is typically a fresh execution environment**, and even when AWS reuses a warm one, that reuse is an optimization Lambda makes for you, not a contract you can build correctness on. A broker constructed inside the handler, as sketched above, starts every invocation at a clean watermark — which means a first Action Group call that fetches untrusted content (raising the watermark to `RAW_UNTRUSTED`) and a second Action Group call, moments later in the *same Bedrock agent session*, that would need to see that raised watermark to gate correctly, do not actually share any state at all. The second call sees `CLEAN`, and gates as if the untrusted content the model is very possibly still reasoning over in this same conversation had never been fetched.

The trap here is specifically the silent-then-broken failure mode this project is allergic to elsewhere: hoisting `createBroker()` to module scope (outside the handler function) *looks* like a fix during testing, because a warm Lambda container really does reuse module-scope state across invocations — the watermark appears to persist, tests pass, a demo works. It is not a fix. The moment AWS spins up a fresh container for the next invocation — under load, after a cold period, or simply because Lambda decided to — that state silently resets to `CLEAN` with nothing in the response or the audit log distinguishing "this really is a clean turn" from "this container just doesn't remember the last one." That is exactly GAPS.md #12's gap, arriving disguised as a performance optimization instead of an obvious cross-process boundary.

This library's answer to that gap is not specific to Bedrock: `serializeBrokerState()`/`restoreBrokerState()` (`src/persistence.ts`) already give an integrator a supported way to export a broker's watermark, registry, and any declared plan as one JSON-safe object and restore it into a fresh broker elsewhere — see GAPS.md #12 for the full mechanism, what it does and doesn't cover, and why the propagation itself is never automatic. What Bedrock specifically requires, that a single-process session never does, is a *store both invocations can actually reach* — a Lambda invocation has no way to hand state directly to whichever future invocation (possibly a different container entirely) services this same agent session's next Action Group call. DynamoDB (keyed by Bedrock's own `sessionId`), ElastiCache, or S3 are the ordinary choices: call `serializeBrokerState(broker)` and write it out before the handler returns, `restoreBrokerState(state)` and feed its result into `createBroker({ ...restored })` at the top of the next invocation, keyed by `event.sessionId`. Bedrock's own `sessionAttributes` (a plain string-keyed map the managed orchestrator round-trips back to your Lambda on the next invocation within the same session, visible in the event shape above) is worth naming as an AWS-native alternative to standing up a separate store — but it's a small attribute bag with a real, AWS-enforced size ceiling, realistically roomy enough for the watermark alone, not for a full registry export whose fingerprint records can be numerous and each carry a full simhash/shingle array; treat it as an option for the watermark-only case, not a substitute for DynamoDB/ElastiCache/S3 when registry-level fingerprint precision needs to survive too.

None of this makes the propagation automatic — per GAPS.md #12, it never is, in any deployment. Wiring in `serializeBrokerState()`/`restoreBrokerState()` against a real cross-invocation store closes the "how would I even do this" half of the gap for a Bedrock Action Group exactly the way it does for any other cross-process handoff; it does not create ambient state-sharing you don't have to think about. Skipping it — constructing a bare `createBroker()` per invocation, as the sketch above does for simplicity — is a legitimate choice for a single-call Action Group with no meaningful cross-call taint to track, but it is a choice, and one worth making deliberately rather than by omission.
