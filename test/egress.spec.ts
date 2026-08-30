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

  it('does not treat a URL-shaped object KEY as a host — only values are scanned', () => {
    expect(findOutboundHosts({ 'https://attacker.example': true })).toEqual([]);
  });

  it('ignores non-http(s) URL schemes (e.g. mailto:, file:) — this check is scoped to http(s) egress only', () => {
    expect(findOutboundHosts({ target: 'mailto:someone@example.com' })).toEqual([]);
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
