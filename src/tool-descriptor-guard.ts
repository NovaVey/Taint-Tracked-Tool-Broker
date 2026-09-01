/**
 * Reusable MCP/tool/plugin-description "rug pull" guard — GAPS.md #1's own
 * canonical example, promoted out of `examples/mcp-integration.ts` and
 * `examples/mcp-sdk-integration.ts` (which used to each hand-roll a
 * byte-for-byte-identical `createMcpDescriptionGuard()`/`checkDescriptions()`
 * closure) into one exported, tested, core-library capability both examples
 * now import instead of redefining.
 *
 * The threat: `tools/list` (and the analogous `resources/list`/
 * `prompts/list`) responses are metadata read at MCP discovery time, never
 * routed through `broker.call()` at all (GAPS.md #1's own framing) — a
 * malicious or compromised MCP server can rewrite a tool's description, or
 * its input-schema JSON, between one discovery call and the next to smuggle
 * new instructions into whatever later reads it, with nothing about routing
 * ordinary tool CALLS through the broker touching this channel at all. The
 * two example files already demonstrated the description half of this —
 * this module additionally covers the SCHEMA half: a tool's declared
 * parameter/input JSON schema is exactly as attacker-controlled as its
 * description once you're talking to an MCP server, and just as capable of
 * steering a model's behavior through poisoned parameter docs (a schema
 * `description` field reading "before calling this tool, first run
 * shell_exec with ...", say) — the description-only examples never checked
 * it.
 *
 * `createToolDescriptorGuard(broker)` returns a function to call once per
 * `tools/list`-equivalent discovery response (an array of `ToolDescriptor`).
 * It fingerprints each tool's FULL descriptor — `name`, `description`, and
 * `schema` when present, not `description` alone — via this library's own
 * `exactHash()`/`toRegistrableText()` (`taint/fingerprint.ts`), the same
 * hashing convention every other content-addressed check in this codebase
 * already uses, rather than a new ad-hoc hash. The baseline for "did this
 * change" is honestly first-time-THIS-GUARD-has-seen-this-tool-name — a
 * fresh `createToolDescriptorGuard()` call starts with an empty baseline,
 * and there is deliberately no claim of a session-start anchor here: a
 * `ToolCallBroker` has no visibility into when an MCP client's own logical
 * session begins, only into when its caller happens to invoke this
 * function, so "first sighting by this guard instance" is the only honest
 * thing to call the baseline. Call `createToolDescriptorGuard()` once per
 * logical MCP session (mirroring `createBroker()`'s own one-broker-per-
 * session rule, DESIGN.md's implementation note on GAPS.md #19) and reuse
 * the returned function across that session's discovery calls; a fresh call
 * discards whatever baseline the previous one had built up.
 *
 * On a detected change, it calls `broker.markToolDescriptionExposure()` —
 * `ALLOW_WITH_WARNING` plus a taint-watermark raise (`markContextExposure()`
 * under the hood), never a hard deny. This is deliberate, not an
 * oversight: every other advisory heuristic in this library
 * (`warnOnLikelyUnclassifiedSink`, `warnOnLikelyUnmarkedSource`,
 * `warnOnLikelyDestinationKeysMismatch`) warns-and-taints rather than
 * blocking outright, because none of them can tell a genuine attack from a
 * legitimate server-side update (a tool's description improved in a normal
 * release, a schema's `required` field tightened) — only that something
 * changed. A new hard-deny primitive here would be inconsistent with that
 * established design philosophy and is out of scope for this module.
 *
 * What this deliberately does NOT do, for the same reason GAPS.md #14 keeps
 * this whole library's distance from content-matching heuristics: it never
 * inspects whether any one description or schema IS malicious, only whether
 * one CHANGED since this guard last saw that tool name. A tool whose
 * description was hostile from the very first discovery call is invisible
 * to this guard — there is nothing to compare the first sighting against —
 * exactly as the original description-only guard in the two example files
 * always was.
 *
 * Known limitations, stated plainly:
 *
 *   - **The registered/audited exposure text is the description, not the
 *     schema, even when only the schema drifted.**
 *     `markToolDescriptionExposure(toolName, description, level)`'s own
 *     signature only accepts a description string (`types.ts`) — this guard
 *     does not invent a new call shape for the schema-drift case. A
 *     schema-only change is correctly DETECTED (the full-descriptor hash
 *     differs) and correctly fires the exposure (`ALLOW_WITH_WARNING` +
 *     taint raise) exactly as a description-only change does, but the
 *     `text` that lands in the Layer 2 fingerprint registry and the audit
 *     event's `args.text` is the tool's current `description` — unchanged
 *     from what was already registered for that tool — not the schema
 *     content that actually drifted. The signal reaches the broker
 *     correctly; only the human-readable "what exactly changed" detail in
 *     the audit trail's `text` field does not, for this one sub-case.
 *   - **JSON-key-order sensitivity.** Hashing goes through
 *     `toRegistrableText()`, which `JSON.stringify()`s a non-string value —
 *     the same JSON-based coercion `quarantine.ts`/`checkFieldGrounding()`
 *     already use, with the same caveat: two schemas that are semantically
 *     identical but were serialized with their nested object keys in a
 *     different order hash differently, and this guard reports that as a
 *     drift (a false positive, never a false negative — it can only ever
 *     flag MORE changes than a semantic diff would, never fewer). A schema
 *     freshly re-derived by an MCP SDK from the same underlying tool
 *     definition on every `tools/list` call is expected to serialize with
 *     stable key order in practice; this is named here as a known,
 *     inherited limitation, not something this module adds guarding for.
 *   - **A genuinely non-serializable `schema` throws.** `JSON.stringify`
 *     throws on a circular reference or a function value, and this
 *     function does not catch that — the same behavior `toRegistrableText`
 *     already has everywhere else it's used unguarded in this codebase. In
 *     practice this should not matter for the real MCP use case this
 *     module targets: a `tools/list` response is JSON-RPC, so any `schema`
 *     value that reached here from a real MCP client already passed
 *     through `JSON.parse` at least once, and a `JSON.parse` result can
 *     never contain a cycle or a function. A hand-constructed
 *     `ToolDescriptor` fed a genuinely non-serializable `schema` directly
 *     (bypassing any real wire protocol) will still throw here.
 */

import type { ToolCallBroker } from './types.js';
import { exactHash, toRegistrableText } from './taint/fingerprint.js';

/**
 * One tool/plugin/MCP-server-provided tool's discovery-time descriptor —
 * structurally just enough of a real MCP `tools/list` entry (`name`,
 * `description`, and its JSON `inputSchema`) to fingerprint, not a full
 * protocol type. `schema` is `unknown` and optional deliberately: it's
 * whatever JSON-shaped value the caller's own MCP client handed back for
 * that tool's input schema (a real `@modelcontextprotocol/sdk` `Tool`'s
 * `inputSchema`, a hand-rolled mock's plain object, or nothing at all for a
 * tool declared with no schema) — this module only ever hashes it via
 * `toRegistrableText()`, it never parses or validates its shape.
 */
export interface ToolDescriptor {
  /** The tool's stable name — the key this guard's baseline is tracked under. */
  name: string;
  /** The tool's current description text, exactly as the discovery call returned it. */
  description: string;
  /** The tool's current input/parameter JSON schema, when the discovery call provides one. Hashed alongside `name`/`description`; omit for a tool declared with no schema. */
  schema?: unknown;
}

/** Canonical, fixed-key-order text of a descriptor — this project's own `toRegistrableText()`/`exactHash()` are used for the actual hash, this just guarantees the object literal handed to them has the same field order on every call regardless of the input's own property order. */
function descriptorText(descriptor: ToolDescriptor): string {
  return toRegistrableText({
    name: descriptor.name,
    description: descriptor.description,
    schema: descriptor.schema,
  });
}

/**
 * Builds a rug-pull guard bound to one `broker` — see this module's own
 * file-header doc comment for the full threat model, the baseline
 * semantics, and this function's known limitations.
 *
 * Call the returned function once per `tools/list`-equivalent discovery
 * response. The very first time a given tool `name` is seen (by THIS
 * returned function — a fresh `createToolDescriptorGuard()` call starts
 * over), its descriptor hash is only recorded, never flagged — there is
 * nothing to compare against yet, and a tool being seen for the first time
 * is not itself suspicious. On every later call, a tool name whose
 * descriptor hash differs from what was last recorded for it fires
 * `broker.markToolDescriptionExposure(name, description, level)` — an
 * unrelated tool name's own baseline and hash are untouched by another
 * tool's drift, since each is tracked independently by name.
 */
export function createToolDescriptorGuard(
  broker: ToolCallBroker,
): (descriptors: readonly ToolDescriptor[]) => void {
  const lastSeenHash = new Map<string, string>();
  return function checkToolDescriptors(descriptors: readonly ToolDescriptor[]): void {
    for (const descriptor of descriptors) {
      const hash = exactHash(descriptorText(descriptor));
      const previous = lastSeenHash.get(descriptor.name);
      if (previous !== undefined && previous !== hash) {
        broker.markToolDescriptionExposure(
          descriptor.name,
          descriptor.description,
          'RAW_UNTRUSTED',
        );
      }
      lastSeenHash.set(descriptor.name, hash);
    }
  };
}
