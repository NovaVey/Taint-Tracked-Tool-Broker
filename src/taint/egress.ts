/**
 * Outbound-host extraction for the opt-in `BrokerOptions.allowedOutboundHosts`
 * allowlist (broker.ts, DESIGN.md §7.4). Deliberately narrow in scope: finds
 * genuine absolute `http(s)` URLs among an EXFIL-class call's string argument
 * values and extracts their hostnames. It does NOT attempt to cover every
 * egress vector a real deployment might have — an email recipient's domain,
 * a raw IP address embedded in non-URL text, a hostname assembled across
 * multiple argument fields, or any channel that never passes through a
 * broker-mediated tool call at all. See GAPS.md #18 for exactly what this
 * does and doesn't catch.
 */

function asHttpUrl(value: string): URL | undefined {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Recursively walks `args` (the same shape scanArgsForTaint's own walk in
 * scan.ts covers — arrays, plain objects, cyclic-safe) collecting the
 * hostname of every genuine http(s) URL found among its string *values*.
 * Deliberately does not also scan object *keys* the way scanArgsForTaint
 * does for taint text — a target URL arriving as an object key rather than
 * a value isn't a realistic shape for how tool-call arguments carry one, so
 * skipping it keeps this simpler without giving up real coverage.
 */
export function findOutboundHosts(args: unknown): string[] {
  const hosts: string[] = [];
  const visited = new WeakSet<object>();

  function visit(node: unknown): void {
    if (node === null || node === undefined) return;
    if (typeof node === 'string') {
      const url = asHttpUrl(node);
      if (url) hosts.push(url.hostname);
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
