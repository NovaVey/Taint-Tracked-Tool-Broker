import { describe, expect, it } from 'vitest';
import { findOutboundHosts, isAllowedOutboundHost } from '../src/index.js';

describe('findOutboundHosts', () => {
  it('finds the hostname of a genuine http(s) URL in a plain string value', () => {
    expect(findOutboundHosts({ url: 'https://attacker.example/collect' })).toEqual([
      'attacker.example',
    ]);
  });

  it('finds hosts nested at any depth, across arrays and objects', () => {
    expect(
      findOutboundHosts({
        outer: [{ inner: 'https://a.example/x' }, 'http://b.example/y'],
      }),
    ).toEqual(['a.example', 'b.example']);
  });

  it('does not treat a non-URL string as a host', () => {
    expect(findOutboundHosts({ body: 'not a url, just some text' })).toEqual([]);
  });

  it('skips null/undefined leaves without erroring, and still finds a genuine host alongside them', () => {
    expect(findOutboundHosts({ a: null, b: undefined, c: 'https://a.example' })).toEqual([
      'a.example',
    ]);
  });

  it('does not treat a URL-shaped object KEY as a host — only values are scanned', () => {
    expect(findOutboundHosts({ 'https://attacker.example': true })).toEqual([]);
  });

  it('ignores a non-http(s), non-email URL scheme (e.g. file:) — this check is scoped to http(s) and email egress only', () => {
    expect(findOutboundHosts({ target: 'file:///etc/passwd' })).toEqual([]);
  });

  it('tolerates a cyclic args object without infinite-looping', () => {
    const args: Record<string, unknown> = { url: 'https://a.example' };
    args.self = args;
    expect(findOutboundHosts(args)).toEqual(['a.example']);
  });

  it('finds a host inside a Layer-1 TaintedValue-wrapped object without needing special-case handling — it is walked generically like any other object', () => {
    // A minimal stand-in for TaintedValue's actual shape (src/taint/wrapper.ts)
    // — the point under test is that a plain object walk reaches `.value`
    // without this module needing to know about the taint-wrapper brand.
    const wrapped = { value: 'https://c.example/z', level: 'RAW_UNTRUSTED', sources: [] };
    expect(findOutboundHosts(wrapped)).toEqual(['c.example']);
  });

  // GAPS.md #18's own flagship named example of what used to be invisible:
  // a net:email sink's recipient carries no http(s):// scheme at all.
  describe('email-address destinations (GAPS.md #18)', () => {
    it('finds the domain of a genuine email address in a plain string value', () => {
      expect(findOutboundHosts({ to: 'someone@attacker.example' })).toEqual(['attacker.example']);
    });

    it('lowercases the extracted domain, matching the convention URL.hostname already normalizes to', () => {
      expect(findOutboundHosts({ to: 'Someone@ATTACKER.Example' })).toEqual(['attacker.example']);
    });

    it('a mailto: URI is caught via the email path even though its scheme is not http(s)', () => {
      // Its local part happens to include the "mailto:" prefix text, which
      // is harmless — the destination domain extracted is still correct.
      expect(findOutboundHosts({ target: 'mailto:someone@example.com' })).toEqual(['example.com']);
    });

    it('does not match prose that merely contains an "@" — the whole string must be email-shaped (anchored match)', () => {
      expect(findOutboundHosts({ body: 'reach me at someone@example.com please' })).toEqual([]);
    });

    it('does not match a bare "@handle" or a domain with no dot (e.g. an internal hostname) — avoids over-eager false positives on a hard-blocking check', () => {
      expect(findOutboundHosts({ handle: '@someone' })).toEqual([]);
      expect(findOutboundHosts({ to: 'user@localhost' })).toEqual([]);
    });

    it('does not treat an email-shaped object KEY as a host — only values are scanned, same as the URL case', () => {
      expect(findOutboundHosts({ 'someone@attacker.example': true })).toEqual([]);
    });

    it('finds an email domain nested at any depth, across arrays and objects', () => {
      expect(
        findOutboundHosts({
          recipients: [{ email: 'a@a.example' }, 'b@b.example'],
        }),
      ).toEqual(['a.example', 'b.example']);
    });
  });
});

describe('isAllowedOutboundHost', () => {
  it('matches an array entry exactly, case-insensitively', () => {
    expect(isAllowedOutboundHost('Example.com', ['example.com'])).toBe(true);
    expect(isAllowedOutboundHost('example.com', ['EXAMPLE.COM'])).toBe(true);
  });

  it('does not match a subdomain of an allowlisted host — no implicit suffix/wildcard matching', () => {
    expect(isAllowedOutboundHost('sub.example.com', ['example.com'])).toBe(false);
  });

  it('does not match a host that merely contains an allowlisted one as a substring', () => {
    expect(isAllowedOutboundHost('notexample.com', ['example.com'])).toBe(false);
  });

  it('delegates to a predicate function, passed the lowercased hostname', () => {
    const seen: string[] = [];
    const allowed = isAllowedOutboundHost('Example.COM', (h) => {
      seen.push(h);
      return h.endsWith('.com');
    });
    expect(allowed).toBe(true);
    expect(seen).toEqual(['example.com']);
  });

  it('an empty allowlist array allows nothing', () => {
    expect(isAllowedOutboundHost('example.com', [])).toBe(false);
  });
});
