/**
 * Outbound-host extraction for the opt-in `BrokerOptions.allowedOutboundHosts`
 * allowlist (broker.ts, DESIGN.md §7.4). Deliberately narrow in scope: finds
 * genuine absolute `http(s)` URLs, and genuine email addresses (GAPS.md #18's
 * own flagship named example of what used to be invisible — a `net:email`
 * sink's recipient carries no `http(s)://` scheme at all), among an
 * EXFIL-class call's string argument values, and extracts a destination
 * hostname from each. It does NOT attempt to cover every egress vector a
 * real deployment might have — a raw IP address or bare hostname embedded in
 * non-URL, non-email text (deliberately NOT pattern-matched: a generic
 * "looks like a hostname" heuristic risks matching an ordinary filename or
 * version string and incorrectly BLOCKING a legitimate call — an
 * unacceptable false-positive cost for a hard gate, unlike the advisory-only
 * `warnOnLikely*` heuristics elsewhere in this library), a hostname
 * assembled across multiple argument fields, or any channel that never
 * passes through a broker-mediated tool call at all. See GAPS.md #18 for
 * exactly what this does and doesn't catch.
 *
 * OVER-DETECTION, not just under-detection: by default this walks EVERY
 * string leaf in the args tree with no notion of which argument key is the
 * call's actual network destination. A field that merely CONTAINS a URL or
 * email address as its entire value — a Slack `text` body that happens to be
 * exactly `"https://internal-wiki.example/kb/42"`, a `notes` field that is
 * exactly someone's email address — is indistinguishable, to this scan, from
 * the argument that is actually dialed. Because DESIGN.md §7.4 makes an
 * outbound-host mismatch an unconditional hard BLOCK (never
 * REQUIRE_APPROVAL), a false positive here is a harder production failure
 * than this library's usual approval-gated false positives: a completely
 * benign call whose destination is really just the tool's fixed API can be
 * rejected outright because an unrelated field's value happened to look like
 * a URL. The optional `destinationKeys` parameter below exists to let an
 * integrator who knows which argument key(s) actually carry a tool's
 * destination narrow the scan and avoid this; without it, the scan stays
 * whole-tree for the reason explained on `findOutboundHosts` itself. See
 * GAPS.md #18 for the fuller discussion of this tradeoff.
 */

import { ArgsTooDeepError } from '../errors.js';

// Same bound and rationale as taint/scan.ts's MAX_ARGS_TREE_DEPTH — see
// ArgsTooDeepError's doc comment in errors.ts. This walk runs on the same
// mandatory gating path (broker.ts's gateDecision(), for EXFIL-class calls
// when allowedOutboundHosts is configured), so it needs the same protection
// against a sufficiently deep argument tree overflowing the JS call stack.
const MAX_ARGS_TREE_DEPTH = 500;

function asHttpUrl(value: string): URL | undefined {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

// Anchored (whole-string) match only — a substring match risks flagging
// ordinary prose that happens to contain an '@' (a display name, a social
// handle mentioned in passing) as an egress destination. Requires a
// dot-separated, alphabetic-TLD domain — the same shape a real email
// address's domain actually has — rather than accepting any string with an
// '@' in it, keeping the false-positive rate low enough to be safe as a
// default (unlike a generic bare-hostname heuristic — see this module's own
// header comment above for why that one is deliberately NOT implemented).
const EMAIL_ADDRESS_RE =
  /^[^\s@]+@((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})$/;

function asEmailDomain(value: string): string | undefined {
  const match = EMAIL_ADDRESS_RE.exec(value);
  return match ? match[1]!.toLowerCase() : undefined;
}

/**
 * Optional narrowing for `findOutboundHosts`. Naming `destinationKeys` lets
 * an integrator who knows which argument key(s) actually carry a call's
 * network destination (e.g. a webhook tool's `url` field, as opposed to its
 * unrelated `text`/`channel`/`notes` fields) scope the scan to just those
 * keys' subtrees instead of the whole-tree default — see the false-positive
 * discussion in this module's header comment. Purely additive: omitting this
 * option (or the whole second argument) reproduces the original, unscoped
 * whole-tree behavior exactly, so every existing call site — including
 * broker.ts's own `findOutboundHosts(argsSnapshot)` — is unaffected unless
 * an integrator opts in.
 */
export interface FindOutboundHostsOptions {
  /**
   * Object keys (matched exactly, case-sensitively — tool-call argument
   * schemas are integrator-defined, not a case-insensitive namespace like
   * DNS names are) that name a call's actual destination argument(s). When
   * supplied, a string value is only inspected for a URL/email if it is
   * reached by descending through one of these keys at some point on the
   * path from the args root — once inside such a key's subtree, everything
   * under it is scanned as normal (an array of destination URLs, or a
   * `{ url, headers }`-shaped destination object, are both still fully
   * covered). A key that never appears in `args` is simply inert, not an
   * error — tool schemas vary per call and this option is meant to be safe
   * to over-specify.
   */
  readonly destinationKeys?: readonly string[];
}

/**
 * Recursively walks `args` (the same shape scanArgsForTaint's own walk in
 * scan.ts covers — arrays, plain objects, cyclic-safe) collecting a
 * destination hostname for every genuine http(s) URL or email address found
 * among its string *values*. Deliberately does not also scan object *keys*
 * the way scanArgsForTaint does for taint text — a target URL/address
 * arriving as an object key rather than a value isn't a realistic shape for
 * how tool-call arguments carry one, so skipping it keeps this simpler
 * without giving up real coverage.
 *
 * By default every string leaf in the tree is a candidate (see this
 * module's header comment for why over-detection is an accepted, documented
 * tradeoff rather than a bug). Passing `options.destinationKeys` narrows
 * that to only the named key(s)' subtrees, trading recall (a destination
 * arriving under an unnamed key is missed) for precision (a benign field
 * that happens to look like a URL can no longer trigger a false BLOCK) —
 * appropriate only when the integrator actually knows which key(s) a given
 * tool uses to carry its destination, which is why it's opt-in rather than
 * the default.
 */
export function findOutboundHosts(args: unknown, options?: FindOutboundHostsOptions): string[] {
  const hosts: string[] = [];
  const visited = new WeakSet<object>();
  const destinationKeys = options?.destinationKeys;
  const destinationKeySet = destinationKeys ? new Set(destinationKeys) : undefined;

  function visit(node: unknown, depth: number, scanning: boolean): void {
    if (depth > MAX_ARGS_TREE_DEPTH) throw new ArgsTooDeepError(MAX_ARGS_TREE_DEPTH);
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
      if (!scanning) return;
      const url = asHttpUrl(node);
      if (url) {
        hosts.push(url.hostname);
        return;
      }
      const emailDomain = asEmailDomain(node);
      if (emailDomain) hosts.push(emailDomain);
      return;
    }
    if (typeof node !== 'object') return;
    if (visited.has(node)) return;
    visited.add(node);
    if (Array.isArray(node)) {
      // Scanning state is inherited, never re-scoped, by array elements —
      // there's no key here to test against destinationKeys, so a member of
      // an already-in-scope array stays in scope and a member of an
      // out-of-scope array stays out of scope.
      for (const child of node) visit(child, depth + 1, scanning);
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      // Once inside a matched destination key's subtree (scanning === true),
      // stay scanning regardless of nested key names — a destination value
      // that is itself structured (e.g. `{ url: { host, path } }`) shouldn't
      // need every nested key re-listed in destinationKeys too. Outside a
      // matched subtree (scanning === false), only a key literally present
      // in destinationKeySet switches scanning on for its own subtree.
      const childScanning = scanning || !destinationKeySet || destinationKeySet.has(key);
      visit(value, depth + 1, childScanning);
    }
  }

  // No destinationKeys supplied: preserve the original, unscoped behavior
  // exactly by starting fully "in scope" at the root, so every string leaf
  // anywhere in the tree is a candidate, same as before this option existed.
  visit(args, 0, destinationKeySet === undefined);
  return hosts;
}

/**
 * Per-array-reference cache of an allowlist's lowercased entries, keyed by
 * the array object identity itself (not its contents). `BrokerOptions.
 * allowedOutboundHosts` is configured once and held for the lifetime of a
 * Broker instance (broker.ts stores it as `private readonly
 * allowedOutboundHosts`), so in the overwhelmingly common case the SAME
 * array reference is passed to `isAllowedOutboundHost` on every EXFIL-class
 * call for that Broker's entire lifetime — re-lowercasing and linearly
 * rescanning the whole array on every single call was pure waste. A WeakMap
 * is the right structure here specifically because it keys on identity: it
 * lets a still-referenced allowlist array's cache entry live indefinitely
 * without this module ever needing to know when a Broker (or its allowlist)
 * is done being used, while still letting the entry be garbage-collected
 * once nothing else holds that array anymore — no manual cache invalidation
 * or size cap required. A caller who mutates an allowlist array in place
 * after first use (rather than passing a new array reference) will see the
 * stale cached membership; that's the same "reconfigure by passing a new
 * value, don't mutate the old one in place" contract BrokerOptions already
 * expects of its other configuration, not a new caveat introduced here.
 */
const allowlistCache = new WeakMap<readonly string[], ReadonlySet<string>>();

function normalizedAllowlistSet(allowlist: readonly string[]): ReadonlySet<string> {
  const cached = allowlistCache.get(allowlist);
  if (cached) return cached;
  const normalized = new Set(allowlist.map((h) => h.toLowerCase()));
  allowlistCache.set(allowlist, normalized);
  return normalized;
}

/**
 * Hostname comparison is case-insensitive (DNS names are). Allowlist array
 * entries are matched exactly, not as a suffix or wildcard — `"example.com"`
 * in the list does NOT also allow `"sub.example.com"` or
 * `"notexample.com"`; a caller wanting subdomain coverage supplies a
 * predicate function instead of an array, and is responsible for that
 * predicate's own correctness (GAPS.md #18 — this library can't verify a
 * custom predicate matches only what the integrator intends).
 *
 * The array-allowlist path is backed by `normalizedAllowlistSet`'s
 * per-array-reference cache (see its own doc comment above): the first
 * lookup against a given allowlist array normalizes and indexes it once,
 * and every subsequent lookup against that same array reference is an O(1)
 * Set membership test rather than an O(n) re-lowercase-and-rescan of the
 * whole array. A predicate allowlist is never cached — it's an arbitrary
 * function the caller owns, and this library has no way to know whether two
 * calls with "the same" function are safe to memoize against.
 */
export function isAllowedOutboundHost(
  hostname: string,
  allowlist: readonly string[] | ((hostname: string) => boolean),
): boolean {
  const normalized = hostname.toLowerCase();
  if (typeof allowlist === 'function') return allowlist(normalized);
  return normalizedAllowlistSet(allowlist).has(normalized);
}
