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
 * scan.ts covers — arrays, plain objects, Map/Set, cyclic-safe) collecting a
 * destination hostname for every genuine http(s) URL or email address found
 * among its string *values*. Deliberately does not also scan plain-object
 * *keys* the way scanArgsForTaint does for taint text — a target URL/address
 * arriving as a plain object's property name rather than its value isn't a
 * realistic shape for how tool-call arguments carry one (property names are
 * fixed, schema-defined identifiers), so skipping those keeps this simpler
 * without giving up real coverage. A Map's keys ARE scanned, though — unlike
 * a plain object's property name, a Map key is ordinary data just as
 * plausible a place for a destination as its value slot is (see the Map
 * branch in `visit()` below for the concrete shape this covers).
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
    // Map/Set hold their entries in an internal slot, not an own-enumerable
    // property, so the generic Object.entries() fallback below returns
    // nothing for either — a destination URL/email hidden inside one was
    // completely invisible to this scan (no error, no ArgsTooDeepError trip,
    // just silently zero hosts found), not merely deprioritized. This is not
    // a theoretical gap: the broker's default cloneArgs is structuredClone,
    // which preserves Map/Set/Date/typed arrays intact specifically because
    // it's meant to (see broker.ts), so a tool's args snapshot can
    // legitimately carry one. Mirrors taint/scan.ts's identical Map/Set
    // branches (see its own, more detailed doc comment there for the same
    // reasoning) — inserted in the same relative position, after the array
    // check and before the generic-object fallback, so both branches below
    // still go through visit() and get MAX_ARGS_TREE_DEPTH/visited-cycle
    // protection uniformly, same as every other node shape.
    if (node instanceof Map) {
      // Unlike a plain object's property name — a fixed, schema-defined
      // identifier, which is why this module's header comment says object
      // KEYS are deliberately not scanned — a Map key is ordinary DATA, just
      // as plausible a place for a tool to put a destination URL/email as
      // the value slot (e.g. `new Map([['https://evil.example', 'primary']])`
      // for a priority-ordered destination list keyed by URL). So both the
      // key AND the value are visited here, mirroring scan.ts's own
      // rationale for why it scans plain-object keys too, not just values.
      // Scanning state is inherited by both, never re-scoped by either —
      // same as an array element above, there's no destinationKeys-matchable
      // key name for either half of a Map entry.
      for (const [key, value] of node.entries()) {
        visit(key, depth + 1, scanning);
        visit(value, depth + 1, scanning);
      }
      return;
    }
    if (node instanceof Set) {
      // Same rationale as the Map branch above, minus the key question — a
      // Set only ever has values.
      for (const value of node.values()) visit(value, depth + 1, scanning);
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
 * One URL/email-shaped string leaf found somewhere in a call's argument tree
 * OUTSIDE every subtree named by a declared `destinationKeys` list — the
 * shape `findOutboundDestinationsOutsideKeys` below produces, and the only
 * shape `BrokerOptions.warnOnLikelyDestinationKeysMismatch` (`broker.ts`)
 * consumes. Never produced by, or consumed on, the load-bearing
 * `allowedOutboundHosts` gating path itself (`findOutboundHosts` above) —
 * this exists purely to feed that separate, opt-in advisory heuristic.
 */
export interface OutOfScopeDestination {
  /** The offending string leaf's own value, verbatim — a genuine http(s) URL or a well-formed email address, exactly what `asHttpUrl`/`asEmailDomain` above already detect. */
  value: string;
  /** Dotted/bracketed path into the argument object — the same convention `TaintMatch.argPath` (`types.ts`) and `scanArgsForTaint()` (`taint/scan.ts`) already use, e.g. `"body.text"`, `"recipients[1]"`, `"payload<Map>[0].value"`. */
  path: string;
}

/**
 * The advisory-only counterpart to `findOutboundHosts`'s own `destinationKeys`
 * narrowing, built specifically for `BrokerOptions.warnOnLikelyDestinationKeysMismatch`
 * (`broker.ts`) — see that option's own doc comment, and GAPS.md #18's
 * "destinationKeys assumes a fixed, singular destination key per tool"
 * sub-bullet, for the full motivation. In short: `ToolExecutor.destinationKeys`
 * is documented (`types.ts`) as "a fixed property of that tool's own schema,
 * not something that varies call to call" — but a real tool can still
 * violate that assumption (a generic `notify` tool whose destination lives
 * under `slackUrl` for one call shape and `emailAddress` for another). When
 * it does, `findOutboundHosts(args, { destinationKeys: ['slackUrl'] })`
 * doesn't get anything wrong for the subtree it looks at — it simply never
 * visits `emailAddress` at all, since that key was never named. Because
 * `allowedOutboundHosts` is often the SOLE check standing between an
 * otherwise-policy-permissive (`CLEAN`) scope and an actual network egress,
 * an under-declared `destinationKeys` here isn't a defense-in-depth loss —
 * it can be a complete, silent removal of the only check, with nothing in
 * the audit log hinting anything is missing.
 *
 * Where `findOutboundHosts(args, { destinationKeys })` scans ONLY the named
 * keys' subtrees (the real, `BLOCK`-capable gate), this walks the identical
 * tree in the opposite sense: it collects every genuine URL/email found
 * OUTSIDE every declared key's subtree instead. Detection logic
 * (`asHttpUrl`/`asEmailDomain`) and traversal shape (arrays, `Map`/`Set`,
 * cyclic-safe via a fresh `WeakSet`, `MAX_ARGS_TREE_DEPTH`) deliberately
 * mirror `findOutboundHosts`'s own `visit()` exactly — just inverted (collect
 * while NOT in an in-scope subtree, instead of scan only while IN one) and
 * path-tracking instead of hostname-collecting, since a bare hostname list
 * (`findOutboundHosts`'s own return shape) can't name WHERE a mismatch
 * actually is, which is the entire point of an advisory meant to help an
 * integrator fix their `destinationKeys` declaration.
 *
 * Deliberately never called from the `allowedOutboundHosts` gating path
 * itself — `broker.ts`'s `gateDecision()` only calls this from its separate,
 * purely-advisory `warnOnLikelyDestinationKeysMismatch` block, strictly
 * after the real gate above has already run and only when it did not
 * `BLOCK`. A purely advisory heuristic must never itself decide, or even be
 * positioned to accidentally influence, an actual block/allow verdict.
 */
export function findOutboundDestinationsOutsideKeys(
  args: unknown,
  destinationKeys: readonly string[],
): OutOfScopeDestination[] {
  const found: OutOfScopeDestination[] = [];
  const visited = new WeakSet<object>();
  const destinationKeySet = new Set(destinationKeys);

  function destinationShaped(value: string): boolean {
    return asHttpUrl(value) !== undefined || asEmailDomain(value) !== undefined;
  }

  // `scanning` means "already inside a declared destinationKeys subtree" —
  // the exact inverse of what gets COLLECTED relative to findOutboundHosts's
  // own `scanning` flag above: findOutboundHosts collects a match only while
  // `scanning` is true (inside scope); this collects a match only while it
  // is false (outside every declared subtree). Both otherwise mean the same
  // thing and propagate identically — see findOutboundHosts's own `visit()`
  // for the shared rationale behind each node-shape branch below.
  function visit(node: unknown, path: string, depth: number, scanning: boolean): void {
    if (depth > MAX_ARGS_TREE_DEPTH) throw new ArgsTooDeepError(MAX_ARGS_TREE_DEPTH);
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
      if (!scanning && destinationShaped(node)) {
        found.push({ value: node, path });
      }
      return;
    }
    if (typeof node !== 'object') return;
    if (visited.has(node)) return;
    visited.add(node);
    if (Array.isArray(node)) {
      node.forEach((child, i) => visit(child, `${path}[${i}]`, depth + 1, scanning));
      return;
    }
    if (node instanceof Map) {
      let i = 0;
      for (const [key, value] of node.entries()) {
        const entryPath = path ? `${path}<Map>[${i}]` : `<Map>[${i}]`;
        visit(key, `${entryPath}.key`, depth + 1, scanning);
        visit(value, `${entryPath}.value`, depth + 1, scanning);
        i++;
      }
      return;
    }
    if (node instanceof Set) {
      let i = 0;
      for (const value of node.values()) {
        visit(value, path ? `${path}<Set>[${i}]` : `<Set>[${i}]`, depth + 1, scanning);
        i++;
      }
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      const childPath = path ? `${path}.${key}` : key;
      const childScanning = scanning || destinationKeySet.has(key);
      visit(value, childPath, depth + 1, childScanning);
    }
  }

  // Root starts OUT of scope (false) — the exact mirror of findOutboundHosts's
  // own scoped-scan starting point (destinationKeySet !== undefined there
  // means it also starts `false`); only descending through a matched key
  // switches a subtree in.
  visit(args, '', 0, false);
  return found;
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
