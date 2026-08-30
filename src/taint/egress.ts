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
 */

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
 * Recursively walks `args` (the same shape scanArgsForTaint's own walk in
 * scan.ts covers — arrays, plain objects, cyclic-safe) collecting a
 * destination hostname for every genuine http(s) URL or email address found
 * among its string *values*. Deliberately does not also scan object *keys*
 * the way scanArgsForTaint does for taint text — a target URL/address
 * arriving as an object key rather than a value isn't a realistic shape for
 * how tool-call arguments carry one, so skipping it keeps this simpler
 * without giving up real coverage.
 */
export function findOutboundHosts(args: unknown): string[] {
  const hosts: string[] = [];
  const visited = new WeakSet<object>();

  function visit(node: unknown): void {
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
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
      for (const child of node) visit(child);
      return;
    }
    for (const value of Object.values(node)) visit(value);
  }

  visit(args);
  return hosts;
}

/**
 * Hostname comparison is case-insensitive (DNS names are). Allowlist array
 * entries are matched exactly, not as a suffix or wildcard — `"example.com"`
 * in the list does NOT also allow `"sub.example.com"` or
 * `"notexample.com"`; a caller wanting subdomain coverage supplies a
 * predicate function instead of an array, and is responsible for that
 * predicate's own correctness (GAPS.md #18 — this library can't verify a
 * custom predicate matches only what the integrator intends).
 */
export function isAllowedOutboundHost(
  hostname: string,
  allowlist: readonly string[] | ((hostname: string) => boolean),
): boolean {
  const normalized = hostname.toLowerCase();
  if (typeof allowlist === 'function') return allowlist(normalized);
  return allowlist.some((h) => h.toLowerCase() === normalized);
}
