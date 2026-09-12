/**
 * `BrokerOptions.policyTimeoutMs` / the private `callPolicy()` wrapper
 * (GAPS.md #35): a network-dependent `PolicyFn` has no bounded timeout by
 * default, and both real `policy()` call sites (`gateDecision()`'s primary
 * decision, `revalidateBeforeExecute()`'s conditional re-decision) run
 * under the broker's own instance-wide lock, so an unbounded hang there
 * blocks the whole broker, not just one caller. `policyTimeoutMs` is an
 * opt-in fix: unset, this is byte-for-byte the pre-existing unbounded
 * `await this.policy(call, taint)` (no timer, no catch — an uncaught
 * throw/rejection propagates exactly as before); once configured, both a
 * hang past the timeout and a throw/rejection resolve to the same
 * fail-closed `BLOCK`, mirroring the existing "never silently ALLOW"
 * precedent for a `REQUIRE_APPROVAL` with no configured `approvalChannel`
 * (GAPS.md #20).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createBroker,
  ToolCallBlockedError,
  type AuditEvent,
  type PolicyFn,
  type ToolExecutor,
} from '../src/index.js';

function writeFile(): ToolExecutor {
  return {
    name: 'write_file',
    capabilities: { capabilities: ['write:fs'] },
    async execute(args) {
      return `wrote: ${JSON.stringify(args)}`;
    },
  };
}

/** Always ALLOW, resolving on the next microtask — a stand-in for a fast, healthy PolicyFn. */
const fastAllow: PolicyFn = async () => ({ action: 'ALLOW' });

/** Never settles — models a hung network-backed PolicyFn (e.g. a stalled RBAC lookup). */
const hangsForever: PolicyFn = () => new Promise<never>(() => {});

describe('createBroker({ policyTimeoutMs }) validation', () => {
  it('accepts undefined (default), 0, and any positive finite number', () => {
    expect(() => createBroker({ policy: fastAllow })).not.toThrow();
    expect(() => createBroker({ policy: fastAllow, policyTimeoutMs: 0 })).not.toThrow();
    expect(() => createBroker({ policy: fastAllow, policyTimeoutMs: 5000 })).not.toThrow();
  });

  it('throws RangeError for a negative, NaN, or non-finite value', () => {
    expect(() => createBroker({ policy: fastAllow, policyTimeoutMs: -1 })).toThrow(RangeError);
    expect(() => createBroker({ policy: fastAllow, policyTimeoutMs: NaN })).toThrow(RangeError);
    expect(() => createBroker({ policy: fastAllow, policyTimeoutMs: Infinity })).toThrow(
      RangeError,
    );
  });
});

describe('policyTimeoutMs unset — byte-for-byte unchanged (GAPS.md #35)', () => {
  it('a fast PolicyFn’s decision passes through exactly as before', async () => {
    const broker = createBroker({ policy: fastAllow });
    broker.register(writeFile());
    await expect(broker.call('write_file', {})).resolves.toContain('wrote:');
  });

  it('a PolicyFn that throws synchronously propagates uncaught, not converted to BLOCK', async () => {
    const policy: PolicyFn = () => {
      throw new Error('boom: rbac service misconfigured');
    };
    const broker = createBroker({ policy });
    broker.register(writeFile());
    await expect(broker.call('write_file', {})).rejects.toThrow('boom: rbac service misconfigured');
  });

  it('a PolicyFn that returns a rejected promise propagates uncaught, not converted to BLOCK', async () => {
    const policy: PolicyFn = async () => {
      throw new Error('boom: rbac lookup rejected');
    };
    const broker = createBroker({ policy });
    broker.register(writeFile());
    await expect(broker.call('write_file', {})).rejects.toThrow('boom: rbac lookup rejected');
  });
});

describe('policyTimeoutMs configured — fail-closed on timeout or throw (GAPS.md #35)', () => {
  it('a fast PolicyFn is unaffected by a configured timeout it never comes close to', async () => {
    const broker = createBroker({ policy: fastAllow, policyTimeoutMs: 5000 });
    broker.register(writeFile());
    await expect(broker.call('write_file', {})).resolves.toContain('wrote:');
  });

  describe('a hung PolicyFn', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('resolves to a fail-closed BLOCK naming policyTimeoutMs once the timer fires', async () => {
      const events: AuditEvent[] = [];
      const broker = createBroker({
        policy: hangsForever,
        policyTimeoutMs: 5000,
        auditSink: { record: (e) => events.push(e) },
      });
      broker.register(writeFile());

      const callPromise = broker.call('write_file', {});
      const assertion = expect(callPromise).rejects.toBeInstanceOf(ToolCallBlockedError);
      await vi.advanceTimersByTimeAsync(5000);
      await assertion;

      const last = events.at(-1)!;
      expect(last.verdict.action).toBe('BLOCK');
      expect(last.verdict.action === 'BLOCK' && last.verdict.reason).toContain('policyTimeoutMs');
      expect(last.verdict.action === 'BLOCK' && last.verdict.reason).toContain('5000ms');
    });

    it('does not fire the timeout if the PolicyFn resolves first — no leaked timer', async () => {
      let resolvePolicy!: (d: { action: 'ALLOW' }) => void;
      const policy: PolicyFn = () => new Promise((resolve) => (resolvePolicy = resolve));
      const broker = createBroker({ policy, policyTimeoutMs: 5000 });
      broker.register(writeFile());

      const callPromise = broker.call('write_file', {});
      await vi.advanceTimersByTimeAsync(0); // let dispatch() start, same reasoning as approval.spec.ts's letDispatchStart()
      resolvePolicy({ action: 'ALLOW' });
      await expect(callPromise).resolves.toContain('wrote:');

      expect(vi.getTimerCount()).toBe(0); // the race's timer was cleared in callPolicy()'s finally, not left dangling
    });
  });

  it('a PolicyFn that throws synchronously resolves to a fail-closed BLOCK naming the error', async () => {
    const events: AuditEvent[] = [];
    const policy: PolicyFn = () => {
      throw new Error('rbac service misconfigured');
    };
    const broker = createBroker({
      policy,
      policyTimeoutMs: 5000,
      auditSink: { record: (e) => events.push(e) },
    });
    broker.register(writeFile());

    await expect(broker.call('write_file', {})).rejects.toBeInstanceOf(ToolCallBlockedError);
    const last = events.at(-1)!;
    expect(last.verdict.action).toBe('BLOCK');
    expect(last.verdict.action === 'BLOCK' && last.verdict.reason).toContain(
      'rbac service misconfigured',
    );
  });

  it('a PolicyFn that returns a rejected promise resolves to a fail-closed BLOCK naming the error', async () => {
    const policy: PolicyFn = async () => {
      throw new Error('rbac lookup rejected');
    };
    const broker = createBroker({ policy, policyTimeoutMs: 5000 });
    broker.register(writeFile());

    await expect(broker.call('write_file', {})).rejects.toBeInstanceOf(ToolCallBlockedError);
  });

  it('a non-Error throw (a plain string) still fails closed with a readable reason', async () => {
    const events: AuditEvent[] = [];
    const policy: PolicyFn = () => {
      // eslint-disable-next-line @typescript-eslint/only-throw-error -- deliberately modeling a misbehaving PolicyFn
      throw 'not an Error instance';
    };
    const broker = createBroker({
      policy,
      policyTimeoutMs: 5000,
      auditSink: { record: (e) => events.push(e) },
    });
    broker.register(writeFile());

    await expect(broker.call('write_file', {})).rejects.toBeInstanceOf(ToolCallBlockedError);
    const last = events.at(-1)!;
    expect(last.verdict.action === 'BLOCK' && last.verdict.reason).toContain(
      'not an Error instance',
    );
  });
});

describe('revalidateBeforeExecute()’s re-decision path also respects policyTimeoutMs (not just gateDecision()’s primary call)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('a PolicyFn that hangs only on the post-escalation re-decision still fails closed via the same timeout', async () => {
    // Reuses test/irreversible-axis.spec.ts's own proven "revalidation before
    // execute" escalation shape: an approvalChannel that escalates the scope
    // watermark mid-wait (markContextExposure(), a lock-free escape hatch by
    // design, GAPS.md #1) forces gateDecision()'s ALREADY-computed decision
    // to be discarded and re-decided fresh in revalidateBeforeExecute() —
    // the SECOND real `policy()` call site. Here the configured PolicyFn
    // answers fast on the first (pre-escalation) call so the approval flow
    // gets underway, then hangs forever on the second (post-escalation,
    // freshTaint) call, proving `callPolicy()`'s timeout wrapper is reached
    // from BOTH call sites, not just gateDecision()'s.
    let calls = 0;
    const policy: PolicyFn = () => {
      calls += 1;
      if (calls === 1) {
        return { action: 'REQUIRE_APPROVAL', reason: 'first pass', approvalToken: 'tok-1' };
      }
      return new Promise<never>(() => {}); // hang forever on the revalidation pass
    };

    const events: AuditEvent[] = [];
    const broker = createBroker({
      policy,
      policyTimeoutMs: 5000,
      auditSink: { record: (e) => events.push(e) },
      approvalChannel: {
        requestApproval: async () => {
          broker.markContextExposure({ note: 'poisoned content arrives mid-approval-wait' });
          return true;
        },
      },
    });
    broker.register({
      name: 'shell_exec',
      capabilities: { capabilities: ['exec:shell'] },
      async execute() {
        return 'ran';
      },
    });

    const callPromise = broker.call('shell_exec', { cmd: 'echo hi' });
    const assertion = expect(callPromise).rejects.toBeInstanceOf(ToolCallBlockedError);
    await vi.advanceTimersByTimeAsync(5000);
    await assertion;

    expect(calls).toBe(2); // confirms the revalidation pass genuinely happened, not just the first
    const last = events.at(-1)!;
    expect(last.verdict.action).toBe('BLOCK');
    expect(last.verdict.action === 'BLOCK' && last.verdict.reason).toContain('policyTimeoutMs');
  });
});
