/**
 * A custom PolicyFn reading TaintContext.principal (GAPS.md #34) to consult
 * an external, network-backed RBAC service before letting a gated call
 * through — with the timeout, cache, and fail-closed semantics GAPS.md #34
 * and #35 both name as the integrator's own responsibility once this axis
 * exists. Run with:
 *
 *   npx tsx examples/rbac-policy.ts
 *
 * `principal` is deliberately the SMALLEST possible answer to "who is
 * asking": an opaque value this library never verifies, interprets, or acts
 * on itself (`defaultPolicy` never reads it). Everything below — what a
 * principal "means," how it maps to permissions, how a real RBAC client is
 * called — is entirely this example's own construction, standing in for
 * whatever authorization service a real integration would actually call
 * (Okta, an internal permissions service, OPA, ...). None of it ships from
 * `src/index.ts`; a `PolicyFn` this specific belongs in an integrator's own
 * codebase, not this library's public API.
 *
 * Demonstrates, in order:
 *   1. A principal holding the required role -> RBAC authorizes, and the
 *      call proceeds exactly as defaultPolicy's own taint-based verdict
 *      already allowed.
 *   2. A principal lacking the required role -> RBAC denies -> BLOCK,
 *      regardless of how permissive defaultPolicy's own verdict was.
 *   3. No principal bound to the broker at all -> BLOCK. This is GAPS.md
 *      #34's own motivating scenario made concrete: an unidentified caller
 *      cannot be authorized, so this policy fails closed rather than
 *      silently deferring to defaultPolicy's taint-only verdict.
 *   4. The RBAC service hangs past this policy's own inner timeout -> fails
 *      closed to BLOCK rather than treating "no answer yet" as permission.
 *   5. Two calls for the identical (principal, tool) pair -> the second is
 *      served from cache; the underlying RBAC lookup is invoked only once.
 *   6. The RBAC service throws (a network/service error) -> fails closed to
 *      BLOCK, exactly like the timeout case.
 *   7. defaultPolicy already reaches BLOCK on taint grounds alone (RAW_
 *      UNTRUSTED, EXEC) -> RBAC is never even consulted: this policy can
 *      only ADD restriction on top of defaultPolicy's own verdict, never
 *      loosen it, so there is nothing useful an authorization check could
 *      add to an already-maximal denial (and no reason to spend a network
 *      round trip finding that out).
 */

import {
  createBroker,
  defaultPolicy,
  ToolCallBlockedError,
  type PolicyFn,
  type ToolExecutor,
} from '../src/index.js';

/** Stands in for whatever shape a real integration's principal actually has — this library imposes none (TaintContext.principal's own doc comment, types.ts). */
interface ExampleRbacPrincipal {
  userId: string;
  roles: readonly string[];
}

function isExampleRbacPrincipal(value: unknown): value is ExampleRbacPrincipal {
  return (
    typeof value === 'object' &&
    value !== null &&
    'userId' in value &&
    'roles' in value &&
    Array.isArray((value as ExampleRbacPrincipal).roles)
  );
}

const ROLE_PERMISSIONS: Record<string, readonly string[]> = {
  finance_ops: ['finance_approve'],
  read_only: [],
};

/** Toggled between sections to script the mock service's behavior — a real RBAC client has no such knob; this exists purely to demonstrate this example's failure-mode handling on demand. */
type RbacServiceBehavior = 'normal' | 'hangs' | 'throws';
let rbacServiceBehavior: RbacServiceBehavior = 'normal';
let rbacLookupCount = 0;

/**
 * Stands in for a real network call to an authorization service (a REST
 * call to Okta/OPA/an internal permissions service). `rbacLookupCount` and
 * `rbacServiceBehavior` exist only so this example can demonstrate its own
 * cache/timeout/fail-closed handling deterministically — neither has any
 * counterpart in a real `PolicyFn`.
 */
async function rbacServiceLookup(principal: unknown, toolName: string): Promise<boolean> {
  rbacLookupCount++;
  if (rbacServiceBehavior === 'throws') {
    throw new Error('rbac-service: connection reset');
  }
  const latencyMs = rbacServiceBehavior === 'hangs' ? 60_000 : 15;
  await new Promise((resolve) => {
    const timer = setTimeout(resolve, latencyMs);
    // unref(): this stands in for a service call that genuinely never
    // responds — createRbacCheck()'s own timeout above already resolves
    // the RACE long before this fires, but the underlying lookup() promise
    // this timer belongs to is intentionally left dangling (a real network
    // call has no cancellation either), and Node would otherwise hold the
    // whole process open for the full 60s waiting on it to settle.
    timer.unref();
  });
  if (!isExampleRbacPrincipal(principal)) return false;
  return principal.roles.some((role) => (ROLE_PERMISSIONS[role] ?? []).includes(toolName));
}

type RbacOutcome = 'authorized' | 'denied' | 'unavailable';

/**
 * Wraps a raw RBAC lookup with the two pieces of network-hygiene GAPS.md
 * #34/#35 both call out as belonging to the integrator, not this library:
 *
 *   - A bounded timeout (mirrors `BrokerOptions.policyTimeoutMs`'s own
 *     GAPS.md #35 fail-closed design at the broker level, applied here
 *     inside a single `PolicyFn` instead — see this file's own use of
 *     `policyTimeoutMs` below for why both layers are worth having at once).
 *   - A small TTL cache, so an ordinary multi-call turn doesn't cost one
 *     network round trip per gated call for a principal/permission pair
 *     that isn't changing turn to turn.
 *
 * Returns a three-state `RbacOutcome`, not a boolean: collapsing "the
 * service said no" and "the service never answered" into a single `false`
 * would be the exact category of conflation DESIGN.md §7.3's own
 * `approvalChannel`-omitted note (GAPS.md #20) already flags as a real
 * production debugging trap — an operator reading an audit log needs to
 * tell "authorization was actually checked and denied" apart from
 * "authorization could not be checked at all" to know what to act on.
 * `'unavailable'` is deliberately never cached: caching a transient outage
 * would turn one bad network blip into either a standing false denial or
 * (far worse) a standing false grant for the rest of the TTL.
 */
function createRbacCheck(
  lookup: (principal: unknown, toolName: string) => Promise<boolean>,
  opts: { ttlMs: number; timeoutMs: number },
): (principal: unknown, toolName: string) => Promise<RbacOutcome> {
  const cache = new Map<string, { outcome: RbacOutcome; expiresAt: number }>();
  return async function checkAuthorized(
    principal: unknown,
    toolName: string,
  ): Promise<RbacOutcome> {
    const cacheKey = `${JSON.stringify(principal)}::${toolName}`;
    const cached = cache.get(cacheKey);
    if (cached !== undefined && cached.expiresAt > Date.now()) {
      return cached.outcome;
    }

    const TIMED_OUT = Symbol('rbacTimeout');
    let timer: ReturnType<typeof setTimeout>;
    const timeout = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMED_OUT), opts.timeoutMs);
    });

    let outcome: RbacOutcome;
    try {
      const raced = await Promise.race([lookup(principal, toolName), timeout]);
      outcome = raced === TIMED_OUT ? 'unavailable' : raced ? 'authorized' : 'denied';
    } catch {
      outcome = 'unavailable';
    } finally {
      clearTimeout(timer!);
    }

    if (outcome !== 'unavailable') {
      cache.set(cacheKey, { outcome, expiresAt: Date.now() + opts.ttlMs });
    }
    return outcome;
  };
}

const checkRbacAuthorization = createRbacCheck(rbacServiceLookup, {
  ttlMs: 60_000,
  timeoutMs: 200,
});

/**
 * Wraps defaultPolicy, additionally requiring RBAC authorization for
 * `taint.principal` before letting an otherwise-permitted verdict through —
 * never loosening defaultPolicy's own taint-based verdict, only narrowing
 * it further. Mirrors examples/irreversible-sink-policy.ts's and
 * examples/source-class-policy.ts's own "wrap defaultPolicy, defer for
 * everything this axis doesn't apply to" shape for their sibling axes.
 */
const rbacAwarePolicy: PolicyFn = async (call, taint) => {
  const base = await defaultPolicy(call, taint);
  if (base.action === 'BLOCK') {
    // Nothing an authorization check could add on top of an already-maximal
    // denial — and no reason to spend a network round trip finding that out.
    return base;
  }

  if (taint.principal === undefined) {
    return {
      action: 'BLOCK',
      reason:
        `No principal bound to this broker (BrokerOptions.principal) — cannot authorize ` +
        `"${call.toolName}" for an unidentified caller. See GAPS.md #34.`,
    };
  }

  const authz = await checkRbacAuthorization(taint.principal, call.toolName);
  if (authz === 'denied') {
    return {
      action: 'BLOCK',
      reason: `RBAC denied: this principal is not authorized to call "${call.toolName}".`,
    };
  }
  if (authz === 'unavailable') {
    return {
      action: 'BLOCK',
      reason:
        `RBAC service unavailable (timeout or error) while authorizing "${call.toolName}" — ` +
        `failing closed rather than treating an unanswered check as permission. See GAPS.md #35.`,
    };
  }
  return base; // authorized -- defer to defaultPolicy's own taint-based verdict, unchanged
};

function financeApprove(): ToolExecutor {
  return {
    name: 'finance_approve',
    capabilities: { capabilities: ['finance:purchase'] },
    async execute(args) {
      return `approved: ${JSON.stringify(args)}`;
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
 * `createBroker({ policyTimeoutMs })` is a SECOND, independent bound —
 * belt-and-suspenders on top of `checkRbacAuthorization`'s own inner
 * timeout above, not a substitute for it. `rbacAwarePolicy` itself could
 * still hang the whole broker if it had a bug the inner timeout didn't
 * catch (a lookup path that bypasses `createRbacCheck` entirely, say); this
 * outer bound (GAPS.md #35) is the broker's own backstop against exactly
 * that, deliberately set well above the inner 200ms timeout so it is never
 * the one that actually fires in this example — see test/policy-timeout.spec.ts
 * for that boundary exercised directly.
 */
function makeBroker(): ReturnType<typeof createBroker> {
  return createBroker({ policy: rbacAwarePolicy, policyTimeoutMs: 5_000 });
}

async function callFinanceApprove(broker: ReturnType<typeof createBroker>): Promise<void> {
  try {
    const result = await broker.call('finance_approve', { amount: 4200, currency: 'USD' });
    console.log('ALLOWED:', result);
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      console.log(
        `BLOCKED (${err.decision.action}):`,
        'reason' in err.decision ? err.decision.reason : '',
      );
    } else {
      throw err;
    }
  }
}

async function section1_authorizedPrincipal(): Promise<void> {
  console.log('\n=== 1. Principal holding the required role -> RBAC authorizes ===');
  rbacServiceBehavior = 'normal';
  const broker = createBroker({
    policy: rbacAwarePolicy,
    policyTimeoutMs: 5_000,
    principal: { userId: 'alice', roles: ['finance_ops'] } satisfies ExampleRbacPrincipal,
  });
  broker.register(financeApprove());
  await callFinanceApprove(broker);
}

async function section2_unauthorizedPrincipal(): Promise<void> {
  console.log('\n=== 2. Principal lacking the required role -> RBAC denies ===');
  rbacServiceBehavior = 'normal';
  const broker = createBroker({
    policy: rbacAwarePolicy,
    policyTimeoutMs: 5_000,
    principal: { userId: 'bob', roles: ['read_only'] } satisfies ExampleRbacPrincipal,
  });
  broker.register(financeApprove());
  await callFinanceApprove(broker);
}

async function section3_noPrincipalBound(): Promise<void> {
  console.log('\n=== 3. No principal bound at all -> BLOCK (GAPS.md #34) ===');
  const broker = makeBroker(); // no `principal` option at all
  broker.register(financeApprove());
  await callFinanceApprove(broker);
}

async function section4_rbacServiceHangs(): Promise<void> {
  console.log(
    '\n=== 4. RBAC service hangs past this policy’s own inner timeout -> fails closed ===',
  );
  rbacServiceBehavior = 'hangs';
  const broker = createBroker({
    policy: rbacAwarePolicy,
    policyTimeoutMs: 5_000,
    principal: { userId: 'carol', roles: ['finance_ops'] } satisfies ExampleRbacPrincipal,
  });
  broker.register(financeApprove());
  const start = Date.now();
  await callFinanceApprove(broker);
  console.log(
    `(failed closed after ${Date.now() - start}ms — well under the hung service's own delay)`,
  );
  rbacServiceBehavior = 'normal';
}

async function section5_cacheAvoidsRepeatLookup(): Promise<void> {
  console.log('\n=== 5. Repeated call, same (principal, tool) -> served from cache ===');
  rbacServiceBehavior = 'normal';
  const broker = createBroker({
    policy: rbacAwarePolicy,
    policyTimeoutMs: 5_000,
    principal: { userId: 'dave', roles: ['finance_ops'] } satisfies ExampleRbacPrincipal,
  });
  broker.register(financeApprove());
  const before = rbacLookupCount;
  await callFinanceApprove(broker);
  const afterFirst = rbacLookupCount;
  await callFinanceApprove(broker);
  const afterSecond = rbacLookupCount;
  console.log(
    `underlying RBAC lookups: ${afterFirst - before} for the first call, ` +
      `${afterSecond - afterFirst} for the second (cached)`,
  );
}

async function section6_rbacServiceThrows(): Promise<void> {
  console.log('\n=== 6. RBAC service throws -> fails closed to BLOCK ===');
  rbacServiceBehavior = 'throws';
  const broker = createBroker({
    policy: rbacAwarePolicy,
    policyTimeoutMs: 5_000,
    principal: { userId: 'erin', roles: ['finance_ops'] } satisfies ExampleRbacPrincipal,
  });
  broker.register(financeApprove());
  await callFinanceApprove(broker);
  rbacServiceBehavior = 'normal';
}

async function section7_alreadyBlockNeverConsultsRbac(): Promise<void> {
  console.log(
    '\n=== 7. defaultPolicy already BLOCKs on taint grounds (RAW_UNTRUSTED, EXEC) -> RBAC never consulted ===',
  );
  const broker = createBroker({
    policy: rbacAwarePolicy,
    policyTimeoutMs: 5_000,
    principal: { userId: 'frank', roles: ['finance_ops'] } satisfies ExampleRbacPrincipal,
  });
  broker.register(shellExec());
  broker.markContextExposure({ note: 'raw untrusted content, never quarantined' }); // default level: RAW_UNTRUSTED
  const before = rbacLookupCount;
  try {
    await broker.call('shell_exec', { cmd: 'echo hi' });
    console.log('UNEXPECTED: call was allowed');
  } catch (err) {
    if (err instanceof ToolCallBlockedError) {
      console.log(
        `still BLOCK — defaultPolicy's own EXEC/RAW_UNTRUSTED rule, RBAC never consulted (${rbacLookupCount - before} lookups):`,
        err.decision.action,
      );
    } else {
      throw err;
    }
  }
}

async function main(): Promise<void> {
  await section1_authorizedPrincipal();
  await section2_unauthorizedPrincipal();
  await section3_noPrincipalBound();
  await section4_rbacServiceHangs();
  await section5_cacheAvoidsRepeatLookup();
  await section6_rbacServiceThrows();
  await section7_alreadyBlockNeverConsultsRbac();
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
