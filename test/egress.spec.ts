import { describe, expect, it } from 'vitest';
import { ArgsTooDeepError, findOutboundHosts, isAllowedOutboundHost } from '../src/index.js';

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

  it('throws a clean, catchable ArgsTooDeepError instead of overflowing the call stack on a pathologically deep args tree', () => {
    let deep: unknown = 'bottom';
    for (let i = 0; i < 10_000; i++) deep = { nested: deep };
    expect(() => findOutboundHosts({ payload: deep })).toThrow(ArgsTooDeepError);
  });

  it('does not reject an ordinary, realistically-nested args tree', () => {
    let ok: unknown = 'https://a.example';
    for (let i = 0; i < 50; i++) ok = { nested: ok };
    expect(() => findOutboundHosts({ payload: ok })).not.toThrow();
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

  // Regression coverage for the per-array-reference normalization cache
  // (`normalizedAllowlistSet` in taint/egress.ts): repeated lookups against
  // the SAME allowlist array reference must keep matching/rejecting exactly
  // as an uncached linear scan would — a caching layer that got its
  // membership logic wrong on the cached path, or leaked a stale cache
  // across calls, would silently corrupt broker.ts's hard-BLOCK egress gate.
  describe('repeated-lookup and cache-isolation regression coverage', () => {
    it('a stable allowlist array reference matches/rejects identically across many repeated lookups', () => {
      const allowlist = ['example.com', 'ok.example', 'Mixed-Case.example'];
      for (let i = 0; i < 25; i++) {
        expect(isAllowedOutboundHost('example.com', allowlist)).toBe(true);
        expect(isAllowedOutboundHost('OK.EXAMPLE', allowlist)).toBe(true);
        expect(isAllowedOutboundHost('mixed-case.example', allowlist)).toBe(true);
        expect(isAllowedOutboundHost('attacker.example', allowlist)).toBe(false);
      }
    });

    it('a different allowlist array reference gets its own independent result, not a stale hit/miss carried over from a prior array', () => {
      const first = ['a.example'];
      const second = ['b.example'];

      // Prime a cache entry for `first`, then probe `second` for a host
      // that is allowed under `second` but NOT under `first` — and vice
      // versa — to catch a broken cache keying by array contents/hash
      // instead of by reference identity (or one that simply returns the
      // previous array's cached Set regardless of which array was passed).
      expect(isAllowedOutboundHost('a.example', first)).toBe(true);
      expect(isAllowedOutboundHost('b.example', second)).toBe(true);
      expect(isAllowedOutboundHost('b.example', first)).toBe(false);
      expect(isAllowedOutboundHost('a.example', second)).toBe(false);

      // Re-check both again, after both caches are warm, to confirm neither
      // entry was clobbered by populating the other.
      expect(isAllowedOutboundHost('a.example', first)).toBe(true);
      expect(isAllowedOutboundHost('b.example', second)).toBe(true);
    });

    it('two array instances with identical contents are cached independently — cache key is reference identity, not value equality', () => {
      const allowlistA = ['shared.example'];
      const allowlistB = ['shared.example'];
      expect(isAllowedOutboundHost('shared.example', allowlistA)).toBe(true);
      expect(isAllowedOutboundHost('shared.example', allowlistB)).toBe(true);
      expect(isAllowedOutboundHost('other.example', allowlistA)).toBe(false);
      expect(isAllowedOutboundHost('other.example', allowlistB)).toBe(false);
    });

    it('mutating an allowlist array in place after first use is not picked up by the cache (same "reconfigure via a new reference" contract as the rest of BrokerOptions)', () => {
      const allowlist = ['first.example'];
      expect(isAllowedOutboundHost('first.example', allowlist)).toBe(true);
      expect(isAllowedOutboundHost('second.example', allowlist)).toBe(false);

      allowlist.push('second.example');

      // Documented, intentional: this reflects the doc comment on
      // `allowlistCache` in taint/egress.ts, not a bug under test.
      expect(isAllowedOutboundHost('second.example', allowlist)).toBe(false);
    });
  });
});

describe('findOutboundHosts destinationKeys scoping (additive, opt-in)', () => {
  it('omitting destinationKeys reproduces the original whole-tree scan exactly', () => {
    const args = { channel: '#eng', text: 'https://internal-wiki.example/kb/42' };
    expect(findOutboundHosts(args)).toEqual(['internal-wiki.example']);
  });

  // This is the finding's own concrete repro: a benign field (e.g. a Slack
  // `text` body) whose value happens to BE, in full, a bare URL is
  // indistinguishable from a real destination under the default whole-tree
  // scan, and would trip broker.ts's unconditional hard BLOCK even though
  // the tool only ever actually contacts its fixed webhook/API endpoint.
  it('without destinationKeys, a benign field that is exactly a URL is (mis)detected as an outbound host', () => {
    const args = { channel: '#eng', text: 'https://internal-wiki.example/kb/42' };
    expect(findOutboundHosts(args)).toContain('internal-wiki.example');
  });

  it("with destinationKeys supplied, only the named key's subtree is scanned — a benign field with a URL-shaped value outside it is ignored", () => {
    const args = { channel: '#eng', text: 'https://internal-wiki.example/kb/42' };
    expect(findOutboundHosts(args, { destinationKeys: ['url'] })).toEqual([]);
  });

  it('with destinationKeys supplied, a URL under the named key is still found', () => {
    const args = {
      url: 'https://webhook.example/post',
      text: 'https://internal-wiki.example/kb/42',
    };
    expect(findOutboundHosts(args, { destinationKeys: ['url'] })).toEqual(['webhook.example']);
  });

  it("a destination key's subtree is fully scanned even when nested — an array or object under the matched key does not need every inner key re-listed", () => {
    const args = {
      destinations: { primary: 'https://a.example', backups: ['https://b.example', 'not a url'] },
      text: 'https://internal-wiki.example/kb/42',
    };
    expect(findOutboundHosts(args, { destinationKeys: ['destinations'] })).toEqual([
      'a.example',
      'b.example',
    ]);
  });

  it('a destinationKeys entry that never appears in args is inert, not an error', () => {
    const args = { text: 'https://internal-wiki.example/kb/42' };
    expect(findOutboundHosts(args, { destinationKeys: ['url', 'endpoint'] })).toEqual([]);
  });

  it('still throws ArgsTooDeepError on a pathologically deep tree even when destinationKeys is supplied', () => {
    let deep: unknown = 'bottom';
    for (let i = 0; i < 10_000; i++) deep = { nested: deep };
    expect(() => findOutboundHosts({ payload: deep }, { destinationKeys: ['payload'] })).toThrow(
      ArgsTooDeepError,
    );
  });
});
