import { describe, expect, it } from 'vitest';
import {
  defaultPolicy,
  type MatchType,
  type PolicyDecision,
  type SinkClass,
  type TaintContext,
  type TaintLevel,
  type TaintMatch,
  type TaintRecord,
  type ToolCall,
} from '../src/index.js';

const CALL: ToolCall = { id: 'c1', toolName: 'test_sink', args: {}, sessionId: 's1' };

function ctx(
  scopeLevel: TaintLevel,
  sinkClass: SinkClass,
  privateDataSeen: boolean,
  argFingerprintFloor: TaintLevel = 'CLEAN',
  matchedRecords: TaintMatch[] = [],
): TaintContext {
  return { matchedRecords, scopeLevel, argFingerprintFloor, privateDataSeen, sinkClass };
}

async function decide(...args: Parameters<typeof ctx>): Promise<PolicyDecision['action']> {
  const d = await defaultPolicy(CALL, ctx(...args));
  return d.action;
}

/** A minimal, otherwise-irrelevant TaintRecord for building TaintMatch fixtures below — every field the QUARANTINE_AND_RETRY eligibility check doesn't itself read is filled with an inert placeholder. */
function record(level: TaintLevel, toolName = 'fetch_url'): TaintRecord {
  return {
    id: 'rec-1',
    provenance: {
      id: 'rec-1',
      sourceCallId: 'call-1',
      toolName,
      sessionId: 's1',
      capturedAt: 0,
    },
    level,
    sensitivity: { containsPrivateData: false, categories: [] },
    fingerprint: { exactHash: 'rec-1', simhash: 0n, shingleHashes: new Uint32Array(), length: 0 },
    confidence: 1,
  };
}

function match(
  matchType: MatchType,
  score: number,
  level: TaintLevel = 'RAW_UNTRUSTED',
  argPath = 'cmd',
): TaintMatch {
  return { record: record(level), matchType, argPath, score };
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

  describe('QUARANTINE_AND_RETRY (DESIGN.md §7.2)', () => {
    // With NO matchedRecords at all (the bare-watermark-only case — the
    // scope is tainted, but nothing ties THIS argument to a specific prior
    // source), QUARANTINE_AND_RETRY must never be offered: there is nothing
    // concrete to suggest quarantining. This exhaustively walks every
    // (scopeLevel, sinkClass, privateDataSeen, argFingerprintFloor)
    // combination defaultPolicy can be driven through with matchedRecords
    // empty and asserts none of them ever comes out as QUARANTINE_AND_RETRY
    // — the direct descendant of the old characterization test this replaces
    // (which asserted defaultPolicy never produced this action AT ALL,
    // before it was wired up; see CHANGELOG.md). It still pins real,
    // load-bearing behavior post-wiring: a bare watermark taint alone is
    // never sufficient.
    it('is never produced when matchedRecords is empty, for any reachable TaintContext', async () => {
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
                [],
              );
              expect(action).not.toBe('QUARANTINE_AND_RETRY');
            }
          }
        }
      }
    });

    it('replaces an otherwise-BLOCK verdict when matchedRecords carries an exact match, naming the matched source in reason', async () => {
      const decision = await defaultPolicy(
        CALL,
        ctx('RAW_UNTRUSTED', 'EXEC', false, 'CLEAN', [match('exact', 1, 'RAW_UNTRUSTED')]),
      );
      expect(decision.action).toBe('QUARANTINE_AND_RETRY');
      if (decision.action === 'QUARANTINE_AND_RETRY') {
        expect(decision.reason).toContain('fetch_url');
        expect(decision.reason).toContain('BLOCK');
        expect(decision.suggestedSchemaId).toBeUndefined();
      }
    });

    it('replaces an otherwise-REQUIRE_APPROVAL verdict when matchedRecords carries a high-scoring simhash match', async () => {
      const decision = await defaultPolicy(
        CALL,
        ctx('RAW_UNTRUSTED', 'MUTATE', false, 'CLEAN', [match('simhash', 0.97, 'RAW_UNTRUSTED')]),
      );
      expect(decision.action).toBe('QUARANTINE_AND_RETRY');
      if (decision.action === 'QUARANTINE_AND_RETRY') {
        expect(decision.reason).toContain('fetch_url');
        expect(decision.reason).toContain('REQUIRE_APPROVAL');
      }
    });

    it('replaces a REQUIRE_APPROVAL verdict produced purely by the Layer-2 tightening block, using that same match', async () => {
      // scopeLevel alone (CLEAN + EXFIL) would ALLOW; argFingerprintFloor
      // tightens it to REQUIRE_APPROVAL first (the existing Layer-2 block
      // above), and the QUARANTINE_AND_RETRY pass runs AFTER that tightening
      // — this is the case that only exists because of it.
      const decision = await defaultPolicy(
        CALL,
        ctx('CLEAN', 'EXFIL', false, 'RAW_UNTRUSTED', [match('exact', 1, 'RAW_UNTRUSTED')]),
      );
      expect(decision.action).toBe('QUARANTINE_AND_RETRY');
    });

    it('does NOT replace a low-scoring shingle match (below the "specifically identifiable" bar)', async () => {
      const action = await decide('RAW_UNTRUSTED', 'EXEC', false, 'CLEAN', [
        match('shingle', 0.62, 'RAW_UNTRUSTED'),
      ]);
      expect(action).toBe('BLOCK');
    });

    it('does NOT replace a match whose matchType is "wrapper" or "quarantine-derived", even at score 1', async () => {
      const wrapperAction = await decide('RAW_UNTRUSTED', 'EXEC', false, 'CLEAN', [
        match('wrapper', 1, 'RAW_UNTRUSTED'),
      ]);
      expect(wrapperAction).toBe('BLOCK');

      const quarantineDerivedAction = await decide('DERIVED_UNTRUSTED', 'EXEC', false, 'CLEAN', [
        match('quarantine-derived', 1, 'DERIVED_UNTRUSTED'),
      ]);
      expect(quarantineDerivedAction).toBe('REQUIRE_APPROVAL');
    });

    it('does NOT trigger for an otherwise-ALLOW/ALLOW_WITH_WARNING verdict, even with an exact match present', async () => {
      expect(await decide('CLEAN', 'EXEC', false, 'CLEAN', [match('exact', 1, 'CLEAN')])).toBe(
        'ALLOW',
      );
      expect(
        await decide('DERIVED_UNTRUSTED', 'MUTATE', false, 'CLEAN', [
          match('exact', 1, 'DERIVED_UNTRUSTED'),
        ]),
      ).toBe('ALLOW_WITH_WARNING');
    });
  });
});
