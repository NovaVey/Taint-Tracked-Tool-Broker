import { describe, expect, it } from 'vitest';
import {
  defaultPolicy,
  type PolicyDecision,
  type SinkClass,
  type TaintContext,
  type TaintLevel,
  type ToolCall,
} from '../src/index.js';

const CALL: ToolCall = { id: 'c1', toolName: 'test_sink', args: {}, sessionId: 's1' };

function ctx(
  scopeLevel: TaintLevel,
  sinkClass: SinkClass,
  privateDataSeen: boolean,
  argFingerprintFloor: TaintLevel = 'CLEAN',
): TaintContext {
  return { matchedRecords: [], scopeLevel, argFingerprintFloor, privateDataSeen, sinkClass };
}

async function decide(...args: Parameters<typeof ctx>): Promise<PolicyDecision['action']> {
  const d = await defaultPolicy(CALL, ctx(...args));
  return d.action;
}

describe('defaultPolicy matrix (DESIGN.md §7.2)', () => {
  it('NONE sinks are always ALLOW regardless of scope', async () => {
    expect(await decide('RAW_UNTRUSTED', 'NONE', true)).toBe('ALLOW');
  });

  it('CLEAN scope is always ALLOW regardless of sink class', async () => {
    expect(await decide('CLEAN', 'EXEC', false)).toBe('ALLOW');
    expect(await decide('CLEAN', 'MUTATE', true)).toBe('ALLOW');
    expect(await decide('CLEAN', 'EXFIL', true)).toBe('ALLOW');
  });

  describe('RAW_UNTRUSTED', () => {
    it('EXEC is unconditional BLOCK, with or without private data', async () => {
      expect(await decide('RAW_UNTRUSTED', 'EXEC', false)).toBe('BLOCK');
      expect(await decide('RAW_UNTRUSTED', 'EXEC', true)).toBe('BLOCK');
    });

    it('MUTATE requires approval, escalating to BLOCK with private data', async () => {
      expect(await decide('RAW_UNTRUSTED', 'MUTATE', false)).toBe('REQUIRE_APPROVAL');
      expect(await decide('RAW_UNTRUSTED', 'MUTATE', true)).toBe('BLOCK');
    });

    it('EXFIL always requires at least approval, never a bare allow, escalating to BLOCK with private data', async () => {
      expect(await decide('RAW_UNTRUSTED', 'EXFIL', false)).toBe('REQUIRE_APPROVAL');
      expect(await decide('RAW_UNTRUSTED', 'EXFIL', true)).toBe('BLOCK');
    });
  });

  describe('DERIVED_UNTRUSTED', () => {
    it('EXEC always requires approval, never escalating to BLOCK from private data alone', async () => {
      expect(await decide('DERIVED_UNTRUSTED', 'EXEC', false)).toBe('REQUIRE_APPROVAL');
      expect(await decide('DERIVED_UNTRUSTED', 'EXEC', true)).toBe('REQUIRE_APPROVAL');
    });

    it('MUTATE is ALLOW_WITH_WARNING without private data, REQUIRE_APPROVAL with it', async () => {
      expect(await decide('DERIVED_UNTRUSTED', 'MUTATE', false)).toBe('ALLOW_WITH_WARNING');
      expect(await decide('DERIVED_UNTRUSTED', 'MUTATE', true)).toBe('REQUIRE_APPROVAL');
    });

    it('EXFIL is ALLOW_WITH_WARNING without private data, REQUIRE_APPROVAL with it (full trifecta)', async () => {
      expect(await decide('DERIVED_UNTRUSTED', 'EXFIL', false)).toBe('ALLOW_WITH_WARNING');
      expect(await decide('DERIVED_UNTRUSTED', 'EXFIL', true)).toBe('REQUIRE_APPROVAL');
    });
  });

  describe('Layer 2 fingerprint floor — tightens only, and only when it exceeds scopeLevel', () => {
    it('floors an otherwise-ALLOW CLEAN scope to REQUIRE_APPROVAL when a fingerprint outranks it (e.g. post turn-reset)', async () => {
      expect(await decide('CLEAN', 'EXFIL', false, 'RAW_UNTRUSTED')).toBe('REQUIRE_APPROVAL');
    });

    it('does not re-tighten when the floor merely matches what scopeLevel already reflects', async () => {
      // scopeLevel already DERIVED_UNTRUSTED; a same-level fingerprint match adds no new information.
      expect(await decide('DERIVED_UNTRUSTED', 'MUTATE', false, 'DERIVED_UNTRUSTED')).toBe(
        'ALLOW_WITH_WARNING',
      );
    });

    it('never loosens an already-BLOCK verdict', async () => {
      expect(await decide('RAW_UNTRUSTED', 'EXEC', false, 'CLEAN')).toBe('BLOCK');
    });
  });

  describe('QUARANTINE_AND_RETRY (doc/code gap — see GAPS.md)', () => {
    // DESIGN.md §7.2 describes QUARANTINE_AND_RETRY as an active default-
    // policy behavior, but MATRIX/baseDecision() never select it as a
    // Verdict — the case in toDecision() exists only so that helper stays
    // exhaustive over PolicyDecision['action'] for a hand-written PolicyFn,
    // not because defaultPolicy itself ever returns it. This test
    // exhaustively walks every (scopeLevel, sinkClass, privateDataSeen,
    // argFingerprintFloor) combination defaultPolicy can be driven through
    // and asserts none of them ever comes out as QUARANTINE_AND_RETRY, so
    // that if a future edit to MATRIX or the Layer-2 tightening block ever
    // starts constructing one, this fails loudly rather than silently
    // shipping a behavior GAPS.md/DESIGN.md have not been updated to match.
    it('is never produced by defaultPolicy for any reachable TaintContext', async () => {
      const scopeLevels: TaintLevel[] = ['CLEAN', 'DERIVED_UNTRUSTED', 'RAW_UNTRUSTED'];
      const sinkClasses: SinkClass[] = ['NONE', 'MUTATE', 'EXFIL', 'EXEC'];

      for (const scopeLevel of scopeLevels) {
        for (const sinkClass of sinkClasses) {
          for (const privateDataSeen of [false, true]) {
            for (const argFingerprintFloor of scopeLevels) {
              const action = await decide(
                scopeLevel,
                sinkClass,
                privateDataSeen,
                argFingerprintFloor,
              );
              expect(action).not.toBe('QUARANTINE_AND_RETRY');
            }
          }
        }
      }
    });
  });
});
