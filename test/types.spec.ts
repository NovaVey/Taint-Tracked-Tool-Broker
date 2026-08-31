import { describe, expect, it } from 'vitest';
import { sinkClassOf, type SinkCapability } from '../src/index.js';

describe('sinkClassOf', () => {
  it('returns NONE for an empty capability list', () => {
    expect(sinkClassOf([])).toBe('NONE');
  });

  it('maps each single capability to its documented class', () => {
    const cases: Array<[SinkCapability, ReturnType<typeof sinkClassOf>]> = [
      ['exec:shell', 'EXEC'],
      ['exec:code', 'EXEC'],
      ['write:fs', 'MUTATE'],
      ['write:external-account', 'MUTATE'],
      ['finance:purchase', 'MUTATE'],
      ['irreversible:other', 'MUTATE'],
      ['net:outbound', 'EXFIL'],
      ['net:email', 'EXFIL'],
      ['net:api-call', 'EXFIL'],
      ['net:post-message', 'EXFIL'],
    ];
    for (const [capability, expected] of cases) {
      expect(sinkClassOf([capability])).toBe(expected);
    }
  });

  // The precedence this whole suite exists to pin down: sinkClassOf()'s own
  // doc comment in types.ts promises "a tool with multiple capabilities
  // spanning classes is gated by its most severe declared class" —
  // EXEC > EXFIL > MUTATE > NONE (CLASS_SEVERITY). Nothing elsewhere in the
  // repo exercises a tool declaring capabilities from more than one class
  // (every registered test/corpus tool declares at most one sink
  // capability), so a regression here — e.g. "last capability wins" instead
  // of "most severe wins" — would silently under-gate a real tool and go
  // uncaught by every other test in the suite.
  describe('multi-class precedence — "most severe capability wins"', () => {
    it('a tool declaring both write:fs (MUTATE) and exec:shell (EXEC) is classified EXEC, not MUTATE', () => {
      // This is the exact under-gating regression the finding names: if
      // sinkClassOf() regressed to "last capability wins", this ordering
      // (MUTATE listed AFTER EXEC) would silently produce MUTATE instead of
      // the correct, more restrictive EXEC.
      expect(sinkClassOf(['write:fs', 'exec:shell'])).toBe('EXEC');
      // Order-independence: severity, not list position, must decide it.
      expect(sinkClassOf(['exec:shell', 'write:fs'])).toBe('EXEC');
    });

    it('EXEC wins over EXFIL', () => {
      expect(sinkClassOf(['net:outbound', 'exec:code'])).toBe('EXEC');
      expect(sinkClassOf(['exec:code', 'net:outbound'])).toBe('EXEC');
    });

    it('EXFIL wins over MUTATE', () => {
      expect(sinkClassOf(['write:fs', 'net:email'])).toBe('EXFIL');
      expect(sinkClassOf(['net:email', 'write:fs'])).toBe('EXFIL');
    });

    it('EXEC wins over a mix of EXFIL and MUTATE capabilities declared together', () => {
      expect(sinkClassOf(['write:fs', 'net:api-call', 'exec:shell'])).toBe('EXEC');
    });

    it('multiple capabilities within the same class still resolve to that one class', () => {
      expect(sinkClassOf(['write:fs', 'finance:purchase', 'irreversible:other'])).toBe('MUTATE');
    });
  });
});
