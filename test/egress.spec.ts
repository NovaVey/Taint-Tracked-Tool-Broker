import { describe, expect, it } from 'vitest';
import {
  ArgsTooDeepError,
  createBroker,
  DisallowedOutboundHostError,
  findOutboundDestinationsOutsideKeys,
  findOutboundHosts,
  isAllowedOutboundHost,
} from '../src/index.js';

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

  // Per-branch isolation of the recursion-depth guard (MAX_ARGS_TREE_DEPTH,
  // GAPS.md HIGH #4's unbounded-recursion DoS). The existing "pathologically
  // deep"/"ordinary nesting" tests above only nest through the generic
  // plain-object branch, which only proves depth is tracked correctly on
  // THAT one branch — array, Map key, Map value, and Set each increment
  // `depth` at their OWN independent `depth + 1` call site. A regression
  // that silently swapped one of those to `depth - 1` would turn the guard
  // into a no-op for exactly that branch. Each case below nests exclusively
  // through ONE branch: under the real guard this throws a clean
  // `ArgsTooDeepError`; under a `depth - 1` regression on that branch the
  // depth counter never grows, so the walk instead runs until a raw,
  // undocumented `RangeError: Maximum call stack size exceeded` — which
  // fails `.toThrow(ArgsTooDeepError)`.
  describe('findOutboundHosts recursion-depth guard — isolated per node-shape branch', () => {
    it('a tree nested exclusively through ARRAYS still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = [deep];
      expect(() => findOutboundHosts(deep)).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exclusively through Map KEYS still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = new Map([[deep, 'v']]);
      expect(() => findOutboundHosts(deep)).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exclusively through Map VALUES still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = new Map([['k', deep]]);
      expect(() => findOutboundHosts(deep)).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exclusively through Sets still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = new Set([deep]);
      expect(() => findOutboundHosts(deep)).toThrow(ArgsTooDeepError);
    });

    // Boundary check on the guard's own threshold, not just its direction —
    // see scan.spec.ts's identical test for the full rationale (same
    // MAX_ARGS_TREE_DEPTH=500 constant, same `depth > ...` guard shape).
    it('a tree nested exactly to MAX_ARGS_TREE_DEPTH (500) does not throw — only one level deeper does', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 500; i++) deep = { nested: deep };
      expect(() => findOutboundHosts(deep)).not.toThrow();
    });
  });

  describe('findOutboundHosts — additional dispatch/edge-case coverage', () => {
    // Array elements inherit `scanning` purely POSITIONALLY (see the array
    // branch's own comment in egress.ts) — they are never individually
    // matched against `destinationKeys` by "key name" the way object
    // properties are, because an array has no key names, only positions. If
    // an array were instead walked via the generic plain-object fallback
    // (Object.entries() also enumerates array indices as string keys "0",
    // "1", ...), a `destinationKeys` entry that happens to collide with an
    // index string would wrongly bring that one element into scope.
    it('array elements are exempt from destinationKeys key-name matching even when an entry looks like an index (e.g. "0")', () => {
      const args = { arr: ['https://evil.example/exfil'] };
      expect(findOutboundHosts(args, { destinationKeys: ['0'] })).toEqual([]);
    });

    // The root call seeds `scanning` from `destinationKeySet === undefined`
    // — i.e. "no destinationKeys option at all" starts the walk already
    // in-scope, reproducing the original whole-tree default. This is only
    // observable at the very root itself: a bare string passed directly as
    // `args` (rather than nested inside an object/array) hits the
    // string-leaf `if (!scanning) return;` check before any nested
    // dispatch logic gets a chance to recompute `scanning` on its own.
    it('a bare string as the WHOLE args value is still scanned by default (no destinationKeys option at all)', () => {
      expect(findOutboundHosts('https://a.example')).toEqual(['a.example']);
    });

    it('a bare string as the WHOLE args value is NOT scanned once destinationKeys narrowing is active, since nothing names it in scope', () => {
      expect(findOutboundHosts('https://a.example', { destinationKeys: ['url'] })).toEqual([]);
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

// GAPS.md #18 / DESIGN.md §7.4: findOutboundHosts() used to be structurally
// blind to a URL/email hidden inside a Map or Set anywhere in the args tree
// — its visit() walk only handled Array.isArray(node), falling back to
// Object.entries(node) for everything else, which returns [] for a Map or
// Set (their entries live in an internal slot, not an own-enumerable
// property). No error, no ArgsTooDeepError trip — just silently zero hosts
// found, letting BrokerOptions.allowedOutboundHosts' documented "hard
// structural boundary... traffic from this deployment never leaves to a host
// I haven't approved, full stop" (DESIGN.md §7.4) be defeated outright by
// nesting the destination one level inside either structure. Exactly the
// same failure mode scanArgsForTaint() already had and already fixed (see
// taint/scan.ts's own "not a theoretical gap" comment on its Map/Set
// branches) — egress.ts simply never got the same fix until now. Confirmed
// by direct exploitation (not just reasoned about) before the fix landed:
// `broker.call('net_post', { headers: new Map([['url',
// 'https://evil.example/exfil']]) })` executed successfully against an
// allowlist of only `['approved.example']`.
describe('Map/Set coverage — a destination nested inside a built-in whose state is not an own-enumerable property (GAPS.md #18)', () => {
  it('finds a URL hidden as a Map VALUE', () => {
    expect(
      findOutboundHosts({ headers: new Map([['url', 'https://evil.example/exfil']]) }),
    ).toEqual(['evil.example']);
  });

  it('finds a URL hidden as a Map KEY', () => {
    // Unlike a plain object's property name (a fixed, schema-defined
    // identifier — see findOutboundHosts' own doc comment for why THOSE are
    // deliberately not scanned), a Map key is ordinary data, just as
    // plausible a place to smuggle a destination as the value slot.
    expect(
      findOutboundHosts({ destinations: new Map([['https://evil.example/exfil', 'primary']]) }),
    ).toEqual(['evil.example']);
  });

  it('finds a URL hidden inside a Set VALUE', () => {
    expect(
      findOutboundHosts({ recipients: new Set(['harmless', 'https://evil.example/exfil']) }),
    ).toEqual(['evil.example']);
  });

  it('finds an email address hidden inside a Map value and a Set value, not just a URL', () => {
    expect(findOutboundHosts({ headers: new Map([['to', 'someone@evil.example']]) })).toEqual([
      'evil.example',
    ]);
    expect(findOutboundHosts({ recipients: new Set(['someone@evil.example']) })).toEqual([
      'evil.example',
    ]);
  });

  it('true negative: an allowlisted-looking host inside a Map/Set is found (extraction itself is allowlist-agnostic) but does not spuriously report an unrelated host', () => {
    // findOutboundHosts() only ever extracts hosts; allowlist comparison is
    // isAllowedOutboundHost()'s job (exercised end-to-end in
    // broker.spec.ts's `allowedOutboundHosts` suite). Here: content that is
    // genuinely benign (no URL/email shape at all) inside a Map/Set value
    // must NOT be misreported as a host.
    expect(
      findOutboundHosts({
        m: new Map([['note', 'nothing to see here']]),
        s: new Set(['also nothing']),
      }),
    ).toEqual([]);
  });

  it('does not stack-overflow or double-scan a Map/Set participating in a cycle', () => {
    const m = new Map<string, unknown>([['note', 'https://a.example']]);
    m.set('self', m);
    expect(findOutboundHosts({ m })).toEqual(['a.example']);
  });

  describe('interaction with destinationKeys scoping (GAPS.md #18, DESIGN.md §7.4)', () => {
    it('a Map/Set nested under a declared destinationKeys path is still scanned', () => {
      const args = {
        url: new Map([['primary', 'https://evil.example/exfil']]),
        text: 'https://internal-wiki.example/kb/42',
      };
      expect(findOutboundHosts(args, { destinationKeys: ['url'] })).toEqual(['evil.example']);
    });

    it('a Map/Set NOT under a declared destinationKeys path is exempt, matching existing plain-object destinationKeys semantics', () => {
      const args = {
        url: 'https://approved.example/post',
        headers: new Map([['x-forward-to', 'https://evil.example/exfil']]),
      };
      expect(findOutboundHosts(args, { destinationKeys: ['url'] })).toEqual(['approved.example']);
    });
  });
});

describe('DisallowedOutboundHostError end-to-end via broker.call() — the exact confirmed exploit (GAPS.md #18)', () => {
  it('a URL hidden inside a Map value is caught by an EXFIL-gated call and rejected for a non-allowlisted host', async () => {
    const broker = createBroker({ allowedOutboundHosts: ['approved.example'] });
    broker.register({
      name: 'net_post',
      capabilities: { capabilities: ['net:outbound'] },
      async execute() {
        return 'posted-ok';
      },
    });
    await expect(
      broker.call('net_post', { headers: new Map([['url', 'https://evil.example/exfil']]) }),
    ).rejects.toBeInstanceOf(DisallowedOutboundHostError);
  });

  it('an allowlisted host hidden inside a Map value is NOT blocked (true negative)', async () => {
    const broker = createBroker({ allowedOutboundHosts: ['approved.example'] });
    broker.register({
      name: 'net_post',
      capabilities: { capabilities: ['net:outbound'] },
      async execute() {
        return 'posted-ok';
      },
    });
    await expect(
      broker.call('net_post', { headers: new Map([['url', 'https://approved.example/post']]) }),
    ).resolves.toBe('posted-ok');
  });
});

// The advisory-only counterpart to destinationKeys narrowing, built for
// BrokerOptions.warnOnLikelyDestinationKeysMismatch (broker.ts, GAPS.md #18's
// "destinationKeys assumes a fixed, singular destination key per tool"
// sub-bullet) — end-to-end broker coverage lives in broker.spec.ts's own
// `warnOnLikelyDestinationKeysMismatch` describe block; this is the direct
// unit-level coverage for the tree walk itself, mirroring how
// `findOutboundHosts` and its `destinationKeys` scoping are each tested
// directly above.
describe('findOutboundDestinationsOutsideKeys (advisory-only, GAPS.md #18)', () => {
  it('finds a destination-shaped value outside the declared keys, naming its dotted path', () => {
    const args = {
      slackUrl: 'https://approved.example/hooks/1',
      emailAddress: 'oncall@not-approved.example',
    };
    expect(findOutboundDestinationsOutsideKeys(args, ['slackUrl'])).toEqual([
      { value: 'oncall@not-approved.example', path: 'emailAddress' },
    ]);
  });

  it('finds nothing when every destination-shaped value is inside a declared key subtree', () => {
    const args = { slackUrl: 'https://approved.example/hooks/1', channel: 'general' };
    expect(findOutboundDestinationsOutsideKeys(args, ['slackUrl'])).toEqual([]);
  });

  it('does not flag a value inside the declared key subtree, even nested', () => {
    const args = {
      destinations: { primary: 'https://a.example', notes: 'ok' },
      unrelated: 'not a url',
    };
    expect(findOutboundDestinationsOutsideKeys(args, ['destinations'])).toEqual([]);
  });

  it('an empty destinationKeys list means nothing is in scope — every destination-shaped value counts as outside', () => {
    const args = { url: 'https://a.example' };
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'https://a.example', path: 'url' },
    ]);
  });

  it('tracks array paths using the same dotted/bracketed convention as TaintMatch.argPath / scanArgsForTaint', () => {
    const args = { recipients: ['a@a.example', 'b@b.example'] };
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'a@a.example', path: 'recipients[0]' },
      { value: 'b@b.example', path: 'recipients[1]' },
    ]);
  });

  it('finds a Map value outside a declared key, mirroring findOutboundHosts() own Map/Set coverage above', () => {
    const args = {
      url: 'https://approved.example/post',
      headers: new Map([['x-forward-to', 'https://evil.example/exfil']]),
    };
    expect(findOutboundDestinationsOutsideKeys(args, ['url'])).toEqual([
      { value: 'https://evil.example/exfil', path: 'headers<Map>[0].value' },
    ]);
  });

  it('does not flag a Map/Set nested under a declared destinationKeys path', () => {
    const args = { url: new Map([['primary', 'https://a.example']]) };
    expect(findOutboundDestinationsOutsideKeys(args, ['url'])).toEqual([]);
  });

  it('tolerates a cyclic args object without infinite-looping', () => {
    const args: Record<string, unknown> = { a: 'https://a.example' };
    args.self = args;
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'https://a.example', path: 'a' },
    ]);
  });

  it('throws a clean, catchable ArgsTooDeepError on a pathologically deep args tree, same bound as findOutboundHosts', () => {
    let deep: unknown = 'bottom';
    for (let i = 0; i < 10_000; i++) deep = { nested: deep };
    expect(() => findOutboundDestinationsOutsideKeys({ payload: deep }, ['other'])).toThrow(
      ArgsTooDeepError,
    );
  });

  // Regression coverage for a complete, previously-untested blind spot: this
  // walk's Set branch (mirroring findOutboundHosts' own Set branch above)
  // had ZERO test coverage before this describe block — no test anywhere in
  // the suite ever passed a Set through findOutboundDestinationsOutsideKeys
  // at all. That is exactly the historical failure shape GAPS.md #18/the
  // CHANGELOG's [1.1.0] Security section describes for findOutboundHosts
  // itself (a destination hidden inside a Map/Set was silently invisible,
  // Object.entries() returning nothing for either) — here it was the same
  // gap, just in the advisory-only sibling function instead of the
  // hard-blocking one.
  it('finds a destination hidden inside a Set VALUE outside the declared keys', () => {
    const args = { headers: new Set(['harmless', 'https://evil.example/exfil']) };
    expect(findOutboundDestinationsOutsideKeys(args, ['url'])).toEqual([
      { value: 'https://evil.example/exfil', path: 'headers<Set>[1]' },
    ]);
  });

  it('does not flag a Set nested under a declared destinationKeys path', () => {
    const args = { url: new Set(['https://a.example']) };
    expect(findOutboundDestinationsOutsideKeys(args, ['url'])).toEqual([]);
  });

  it('multiple Set entries get correctly incrementing indices in their paths, not stuck at the same index', () => {
    const args = { s: new Set(['https://a.example', 'https://b.example']) };
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'https://a.example', path: 's<Set>[0]' },
      { value: 'https://b.example', path: 's<Set>[1]' },
    ]);
  });

  it('a Map at the ARGS ROOT (no outer property) still gets a correctly-formatted path', () => {
    const args = new Map([['https://a.example', 'v']]);
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'https://a.example', path: '<Map>[0].key' },
    ]);
  });

  it('a Map KEY (not just a value) outside declared keys is found, and multiple entries get correctly incrementing indices', () => {
    const args = {
      headers: new Map([
        ['https://a.example', 'primary'],
        ['note', 'https://b.example'],
      ]),
    };
    expect(findOutboundDestinationsOutsideKeys(args, ['url'])).toEqual([
      { value: 'https://a.example', path: 'headers<Map>[0].key' },
      { value: 'https://b.example', path: 'headers<Map>[1].value' },
    ]);
  });

  it('a destination two levels deep under an undeclared key gets a fully dotted path ("outer.inner")', () => {
    const args = { outer: { inner: 'https://a.example' } };
    expect(findOutboundDestinationsOutsideKeys(args, ['url'])).toEqual([
      { value: 'https://a.example', path: 'outer.inner' },
    ]);
  });

  // See scan.spec.ts's identical-in-spirit null test: `typeof null ===
  // 'object'`, so the null/undefined short-circuit at the top of visit() is
  // the ONLY thing standing between a null leaf and the cycle-guard's
  // `visited.add(node)` a few lines later, which throws a TypeError for a
  // non-object value.
  it('skips a null/undefined leaf cleanly (no crash), even alongside a genuine destination elsewhere in the tree', () => {
    const args = { a: null, b: undefined, c: 'https://a.example' };
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'https://a.example', path: 'c' },
    ]);
  });

  // A plain number/boolean leaf (a wholly ordinary tool-call argument shape
  // — e.g. `{ retries: 3, dryRun: true }`) must be skipped the same way: the
  // generic `typeof node !== 'object'` catch-all is what stands between it
  // and the same `visited.add(node)` crash, since none of the earlier
  // null/undefined/string/Array/Map/Set checks match a number or boolean.
  it('skips a plain number/boolean leaf cleanly (no crash), even alongside a genuine destination', () => {
    const args = { retries: 3, dryRun: true, url: 'https://a.example' };
    expect(findOutboundDestinationsOutsideKeys(args, [])).toEqual([
      { value: 'https://a.example', path: 'url' },
    ]);
  });

  // Per-branch isolation of the recursion-depth guard — see
  // findOutboundHosts' identical-in-spirit describe block above and
  // scan.spec.ts's own version for the full rationale (same
  // MAX_ARGS_TREE_DEPTH=500 constant and guard shape, one independent
  // `depth + 1` call site per node-shape branch).
  describe('recursion-depth guard — isolated per node-shape branch', () => {
    it('a tree nested exclusively through ARRAYS still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = [deep];
      expect(() => findOutboundDestinationsOutsideKeys(deep, [])).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exclusively through Map KEYS still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = new Map([[deep, 'v']]);
      expect(() => findOutboundDestinationsOutsideKeys(deep, [])).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exclusively through Map VALUES still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = new Map([['k', deep]]);
      expect(() => findOutboundDestinationsOutsideKeys(deep, [])).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exclusively through Sets still trips the depth guard', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 2000; i++) deep = new Set([deep]);
      expect(() => findOutboundDestinationsOutsideKeys(deep, [])).toThrow(ArgsTooDeepError);
    });

    it('a tree nested exactly to MAX_ARGS_TREE_DEPTH (500) does not throw — only one level deeper does', () => {
      let deep: unknown = 'https://a.example';
      for (let i = 0; i < 500; i++) deep = { nested: deep };
      expect(() => findOutboundDestinationsOutsideKeys(deep, [])).not.toThrow();
    });
  });
});
