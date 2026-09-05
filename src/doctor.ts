/**
 * A `doctor`-style preflight over a tool catalog and a broker configuration
 * — GAPS.md #30's own two asks: a static check of a tool-definition array
 * against `docs/classifying-tools.md`'s checklist, and a config-inertness
 * check (a no-op `auditSink`, an unconfigured `quarantineImpl`,
 * `requireQuarantineSchema` off, `allowedOutboundHosts` unset while
 * EXFIL-class sinks are declared).
 *
 * **What this is not, stated as plainly as GAPS.md #10 already states it
 * for the live-broker heuristics this reuses:** this cannot verify a
 * declaration against a tool's real behavior. A deliberately-deceptive
 * tool, or one whose real side effects don't show up in its name, is
 * exactly as invisible here as it is to `warnOnLikelyUnclassifiedSink`/
 * `likelyUnclassifiedSinkKeyword` — this module reuses that same keyword
 * match rather than reimplementing it, so it inherits the identical
 * blind spot by construction, not by oversight. What this DOES add beyond
 * `docs/classifying-tools.md`'s existing "register the whole catalog
 * against a broker" pattern is two DETERMINISTIC checks — a tool shaped so
 * `register()`/`wrap()` would reject it outright (`DualRoleToolError`,
 * `ReservedToolNameError`) — caught here before a live broker ever sees
 * the catalog, not merely advisory.
 *
 * Every check here is a PURE function of its inputs: no I/O, no broker
 * construction, no `execute()` call. `src/cli/doctor.ts` (the `tttb doctor`
 * bin entry) is the thin, optional CLI wrapper around these same functions
 * for a catalog/config that lives in a plain JS module; calling
 * `checkToolCatalog()`/`checkBrokerConfig()`/`runDoctor()` directly from
 * your own CI test suite works identically and needs no CLI at all.
 */

import { sinkClassOf, type ToolExecutor } from './types.js';
import { isReservedToolName, isUntrustedSource } from './internal-audit.js';
import { likelyUnclassifiedSinkKeyword, type BrokerOptions } from './broker.js';
import { unconfiguredQuarantineImpl } from './quarantine.js';

/**
 * Just the `BrokerOptions` fields this module's checks actually read —
 * `Pick`ed rather than redeclared so a future change to any of these four
 * fields' own types on `BrokerOptions` can't silently drift out of sync
 * with what `checkBrokerConfig()` accepts. An integrator can pass their
 * real `BrokerOptions` object here directly (it's a strict superset).
 */
export type DoctorBrokerConfig = Pick<
  BrokerOptions,
  'auditSink' | 'quarantineImpl' | 'requireQuarantineSchema' | 'allowedOutboundHosts'
>;

export type DoctorSeverity = 'info' | 'warning' | 'error';

/**
 * `'error'` — this exact catalog would fail at `register()`/`wrap()` time
 * (a deterministic certainty, not a heuristic): fix before shipping.
 * `'warning'` — a real, common way GAPS.md #10/#18's misclassification
 * gaps bite in practice; worth a human look, not necessarily a hard
 * blocker for every deployment. `'info'` — worth knowing, often a
 * deliberate, legitimate choice (e.g. `requireQuarantineSchema` off).
 */
export interface DoctorFinding {
  severity: DoctorSeverity;
  /** Stable, kebab-case identifier for this finding's check — e.g. `'dual-role-tool'` — for filtering/grouping without parsing `message`. */
  code: string;
  message: string;
  /** The tool this finding is about, when it's about one specific tool rather than the catalog/config as a whole. */
  toolName?: string;
}

function finding(
  severity: DoctorSeverity,
  code: string,
  message: string,
  toolName?: string,
): DoctorFinding {
  return { severity, code, message, ...(toolName !== undefined ? { toolName } : {}) };
}

export interface DoctorToolCatalogOpts {
  /**
   * Passed straight through to `likelyUnclassifiedSinkKeyword()` — match
   * your own live broker's `warnOnLikelyUnclassifiedSink` tuning here so
   * this preflight and that live advisory agree on what counts as a
   * suspicious name. Defaults to the same built-in list both already
   * share.
   */
  unclassifiedSinkKeywords?: readonly string[];
}

/**
 * Checks a whole tool catalog for two categories of issue, formalizing
 * `docs/classifying-tools.md`'s own "register the whole catalog against a
 * broker, execute nothing, read the audit sink" pattern into one call, plus
 * catching two DETERMINISTIC `register()`/`wrap()` rejections a whole
 * catalog can be checked for without ever constructing a broker at all:
 *
 * - **`'dual-role-tool'` (error)** — `isSource: true` (not `trusted`)
 *   combined with a non-empty `capabilities` array. `register()`/`wrap()`
 *   reject this outright as `DualRoleToolError` (DESIGN.md §4.1) — not a
 *   heuristic, a hard rule this checks statically so the rejection is
 *   caught in CI rather than the first time the real broker registers it.
 * - **`'reserved-tool-name'` (error)** — a name starting with `__tttb_`
 *   (`internal-audit.ts`'s `RESERVED_TOOL_NAME_PREFIX`), which
 *   `register()`/`wrap()` also reject outright (`ReservedToolNameError`).
 * - **`'unclassified-sink-keyword'` (warning)** — `likelyUnclassifiedSinkKeyword()`
 *   (GAPS.md #10) matches a tool declaring `capabilities: []` whose name
 *   contains a keyword that often indicates a mutating/dangerous action.
 *   Purely advisory, exactly as it is live — see this module's own header
 *   for what it cannot catch.
 *
 * Deliberately does NOT attempt `warnOnLikelyUnmarkedSource`'s check
 * (GAPS.md #1's mirror image): that heuristic needs an actual returned-text
 * LENGTH from a real `execute()` call, a runtime property no amount of
 * catalog-only, registration-time tooling can substitute for — see
 * `docs/classifying-tools.md`'s own "Automating what this checklist can
 * automate" section for this exact asymmetry stated in full.
 */
export function checkToolCatalog(
  tools: readonly ToolExecutor[],
  opts: DoctorToolCatalogOpts = {},
): DoctorFinding[] {
  const findings: DoctorFinding[] = [];
  for (const tool of tools) {
    const sinkClass = sinkClassOf(tool.capabilities.capabilities);

    if (isReservedToolName(tool.name)) {
      findings.push(
        finding(
          'error',
          'reserved-tool-name',
          `Tool "${tool.name}" starts with the reserved "__tttb_" prefix — register()/wrap() will reject it outright (ReservedToolNameError). Choose a different name.`,
          tool.name,
        ),
      );
    }

    if (isUntrustedSource(tool) && sinkClass !== 'NONE') {
      findings.push(
        finding(
          'error',
          'dual-role-tool',
          `Tool "${tool.name}" declares isSource:true (untrusted) AND a non-empty capabilities array — register()/wrap() will reject it outright (DualRoleToolError, DESIGN.md §4.1). Split it into a source-only call and a separate sink-only call, mark it trusted if genuinely not attacker-influenceable, or use the fetch-and-quarantine pattern (DESIGN.md §6.2).`,
          tool.name,
        ),
      );
    }

    if (sinkClass === 'NONE') {
      const matchedKeyword = likelyUnclassifiedSinkKeyword(
        tool.name,
        opts.unclassifiedSinkKeywords,
      );
      if (matchedKeyword !== undefined) {
        findings.push(
          finding(
            'warning',
            'unclassified-sink-keyword',
            `Tool "${tool.name}" declares no sink capabilities (capabilities: []) but its name contains "${matchedKeyword}", which often indicates a mutating/dangerous action (GAPS.md #10). If it actually performs exec/write/exfil, it likely needs a non-empty capabilities array.`,
            tool.name,
          ),
        );
      }
    }
  }
  return findings;
}

/**
 * Checks a broker configuration for the four config-inertness shapes
 * GAPS.md #30 names — each one a way a broker can look fully configured
 * while quietly providing much less protection than it appears to:
 *
 * - **`'noop-audit-sink'` (warning)** — no `auditSink` configured.
 *   `createBroker()` still enforces every gate correctly (GAPS.md #25),
 *   but silently produces zero audit trail — the exact "looks configured,
 *   isn't" shape this whole preflight exists to catch before production.
 * - **`'unconfigured-quarantine-impl'` (info, or error if a tool declares
 *   `mayCallSummarize`)** — no `quarantineImpl` configured (or the
 *   library's own `unconfiguredQuarantineImpl`, which throws
 *   unconditionally). `'info'` by default, since not every integration
 *   uses `broker.summarize()` at all and this module cannot see a call to
 *   it from outside a `ToolExecutor.execute()`; escalated to `'error'` the
 *   moment ANY tool in `tools` declares `mayCallSummarize: true` (GAPS.md
 *   #17), which is a direct, provable declaration that it WILL be called
 *   and WILL therefore throw on every invocation.
 * - **`'quarantine-schema-not-required'` (info)** — `requireQuarantineSchema`
 *   is not `true` (GAPS.md #4). Always `'info'`, never higher: an unset
 *   schema requirement is frequently a deliberate, legitimate choice, and
 *   this module has no way to know whether any quarantine call site in
 *   your codebase actually needs the enforcement.
 * - **`'exfil-without-allowlist'` (warning)** — `tools` declares at least
 *   one `EXFIL`-class sink and `allowedOutboundHosts` is unset. Per GAPS.md
 *   #18, this allowlist is often the SOLE structural check standing
 *   between an otherwise-`CLEAN` scope and a real, unapproved network
 *   egress — omitting it isn't a defense-in-depth loss, it can be a
 *   complete absence of that one check for every EXFIL call this catalog
 *   makes.
 */
export function checkBrokerConfig(
  config: DoctorBrokerConfig,
  tools: readonly ToolExecutor[],
): DoctorFinding[] {
  const findings: DoctorFinding[] = [];

  if (config.auditSink === undefined) {
    findings.push(
      finding(
        'warning',
        'noop-audit-sink',
        'No auditSink configured — createBroker() will silently default to a no-op AuditSink (GAPS.md #25). Every gate is still enforced correctly, but you will have zero audit trail.',
      ),
    );
  }

  const quarantineConfigured =
    config.quarantineImpl !== undefined && config.quarantineImpl !== unconfiguredQuarantineImpl;
  if (!quarantineConfigured) {
    const summarizingTools = tools.filter((tool) => tool.mayCallSummarize === true);
    if (summarizingTools.length > 0) {
      findings.push(
        finding(
          'error',
          'unconfigured-quarantine-impl',
          `No quarantineImpl configured, but ${summarizingTools.length} tool(s) declare mayCallSummarize:true (${summarizingTools.map((t) => t.name).join(', ')}) — every broker.summarize() call they make will throw (GAPS.md #17, quarantine.ts's unconfiguredQuarantineImpl).`,
        ),
      );
    } else {
      findings.push(
        finding(
          'info',
          'unconfigured-quarantine-impl',
          'No quarantineImpl configured — broker.summarize() will throw if called. Fine if this integration never uses the quarantine path; otherwise pass a capability-less LLM call to createBroker({ quarantineImpl }).',
        ),
      );
    }
  }

  if (config.requireQuarantineSchema !== true) {
    findings.push(
      finding(
        'info',
        'quarantine-schema-not-required',
        'requireQuarantineSchema is off (the default) — a broker.summarize() call that omits opts.schema gets unconstrained free text back, quietly reintroducing much of the risk DERIVED_UNTRUSTED exists to reduce (GAPS.md #4). Consider createBroker({ requireQuarantineSchema: true }) if every quarantine call site in this codebase should be forced to pass a narrow schema.',
      ),
    );
  }

  const exfilTools = tools.filter(
    (tool) => sinkClassOf(tool.capabilities.capabilities) === 'EXFIL',
  );
  if (exfilTools.length > 0 && config.allowedOutboundHosts === undefined) {
    findings.push(
      finding(
        'warning',
        'exfil-without-allowlist',
        `${exfilTools.length} EXFIL-capable tool(s) registered (${exfilTools.map((t) => t.name).join(', ')}) but allowedOutboundHosts is not configured — per GAPS.md #18, this allowlist is often the SOLE structural check between a CLEAN scope and a real, unapproved network egress. Consider createBroker({ allowedOutboundHosts }).`,
      ),
    );
  }

  return findings;
}

/** Runs both checkToolCatalog() and checkBrokerConfig() and concatenates their findings — the one-call entry point `src/cli/doctor.ts` itself uses. */
export function runDoctor(input: {
  tools: readonly ToolExecutor[];
  brokerConfig?: DoctorBrokerConfig;
  catalogOpts?: DoctorToolCatalogOpts;
}): DoctorFinding[] {
  const catalogFindings = checkToolCatalog(input.tools, input.catalogOpts);
  const configFindings =
    input.brokerConfig !== undefined ? checkBrokerConfig(input.brokerConfig, input.tools) : [];
  return [...catalogFindings, ...configFindings];
}

const SEVERITY_RANK: Record<DoctorSeverity, number> = { error: 0, warning: 1, info: 2 };
const SEVERITY_LABEL: Record<DoctorSeverity, string> = {
  error: 'ERROR',
  warning: 'WARN ',
  info: 'INFO ',
};

/**
 * Renders findings as readable, one-line-per-finding plain-text prose,
 * sorted error/warning/info (stable within a severity, so a caller that
 * ran `checkToolCatalog()` before `checkBrokerConfig()` sees each group's
 * own internal order preserved) — the same "pure renderer, no new
 * tracking" register `src/debug.ts`'s `formatAuditTrail()`/
 * `explainWatermark()` already use for `AuditEvent[]`/`TaintScope`.
 */
export function formatDoctorReport(findings: readonly DoctorFinding[]): string {
  if (findings.length === 0) return 'doctor: no findings.';
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
  );
  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  const summary = `doctor: ${counts.error} error(s), ${counts.warning} warning(s), ${counts.info} info(s)`;
  const lines = sorted.map(
    (f) =>
      `[${SEVERITY_LABEL[f.severity]}] ${f.code}${f.toolName ? ` (${f.toolName})` : ''}: ${f.message}`,
  );
  return [summary, ...lines].join('\n');
}
