/**
 * src/doctor.ts (GAPS.md #30): checkToolCatalog()/checkBrokerConfig()/
 * runDoctor()/formatDoctorReport() — pure functions, no I/O, no broker
 * construction. src/cli/doctor.ts (the `tttb doctor` bin entry) is covered
 * separately in test/cli-doctor.spec.ts and scripts/smoke-test-doctor-cli.mjs.
 */
import { describe, expect, it } from 'vitest';
import {
  checkBrokerConfig,
  checkToolCatalog,
  formatDoctorReport,
  runDoctor,
  unconfiguredQuarantineImpl,
  type DoctorFinding,
  type QuarantineImpl,
  type ToolExecutor,
} from '../src/index.js';

function tool(overrides: Partial<ToolExecutor> = {}): ToolExecutor {
  return {
    name: 'a_tool',
    capabilities: { capabilities: [] },
    async execute() {
      return 'x';
    },
    ...overrides,
  };
}

const findingsOfCode = (findings: readonly DoctorFinding[], code: string) =>
  findings.filter((f) => f.code === code);

describe('checkToolCatalog()', () => {
  it('returns no findings for an ordinary, correctly-classified catalog', () => {
    const findings = checkToolCatalog([
      tool({ name: 'fetch_url', isSource: true }),
      tool({ name: 'shell_exec', capabilities: { capabilities: ['exec:shell'] } }),
    ]);
    expect(findings).toEqual([]);
  });

  it('flags a reserved __tttb_ tool name as an error — register()/wrap() would reject it', () => {
    const findings = checkToolCatalog([tool({ name: '__tttb_evil' })]);
    expect(findingsOfCode(findings, 'reserved-tool-name')).toHaveLength(1);
    expect(findings[0]?.severity).toBe('error');
    expect(findings[0]?.toolName).toBe('__tttb_evil');
  });

  it('flags a dual-role tool (isSource + non-empty capabilities) as an error — register()/wrap() would reject it', () => {
    const findings = checkToolCatalog([
      tool({
        name: 'fetch_and_run',
        isSource: true,
        capabilities: { capabilities: ['exec:shell'] },
      }),
    ]);
    expect(findingsOfCode(findings, 'dual-role-tool')).toHaveLength(1);
    expect(findings[0]?.severity).toBe('error');
  });

  it('does NOT flag isSource + capabilities as dual-role when the tool is also trusted (isUntrustedSource() is false)', () => {
    const findings = checkToolCatalog([
      tool({
        name: 'trusted_fetch_and_run',
        isSource: true,
        trusted: true,
        capabilities: { capabilities: ['exec:shell'] },
      }),
    ]);
    expect(findingsOfCode(findings, 'dual-role-tool')).toHaveLength(0);
  });

  it('flags a NONE-sinkClass tool whose name contains a keyword suggesting a mutating action, as a warning', () => {
    const findings = checkToolCatalog([tool({ name: 'delete_record' })]);
    expect(findingsOfCode(findings, 'unclassified-sink-keyword')).toHaveLength(1);
    expect(findings[0]?.severity).toBe('warning');
    expect(findings[0]?.message).toContain('delete');
  });

  it('does NOT flag a tool once it declares a real sink capability, even with a matching keyword name', () => {
    const findings = checkToolCatalog([
      tool({ name: 'delete_record', capabilities: { capabilities: ['write:fs'] } }),
    ]);
    expect(findingsOfCode(findings, 'unclassified-sink-keyword')).toHaveLength(0);
  });

  it('respects a custom unclassifiedSinkKeywords list, matching live-broker warnOnLikelyUnclassifiedSink tuning', () => {
    const findings = checkToolCatalog([tool({ name: 'launch_the_thing' })], {
      unclassifiedSinkKeywords: ['launch'],
    });
    expect(findingsOfCode(findings, 'unclassified-sink-keyword')).toHaveLength(1);
    // The default keyword list wouldn't have matched "launch_the_thing" at all.
    expect(checkToolCatalog([tool({ name: 'launch_the_thing' })])).toEqual([]);
  });

  it('checks every tool in a catalog independently, accumulating one finding set', () => {
    const findings = checkToolCatalog([
      tool({ name: 'fetch_url', isSource: true }),
      tool({ name: '__tttb_evil' }),
      tool({ name: 'delete_record' }),
    ]);
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.code).sort()).toEqual([
      'reserved-tool-name',
      'unclassified-sink-keyword',
    ]);
  });
});

const stubQuarantineImpl: QuarantineImpl = async function stub<S = string>(): Promise<S> {
  return 'x' as S;
};

describe('checkBrokerConfig()', () => {
  it('returns no findings for a fully-configured, non-EXFIL, schema-required broker', () => {
    const findings = checkBrokerConfig(
      {
        auditSink: { record: () => {} },
        quarantineImpl: stubQuarantineImpl,
        requireQuarantineSchema: true,
      },
      [],
    );
    expect(findings).toEqual([]);
  });

  it('flags a missing auditSink as a warning (GAPS.md #25 — silent NOOP_AUDIT)', () => {
    const findings = checkBrokerConfig({}, []);
    expect(findingsOfCode(findings, 'noop-audit-sink')).toHaveLength(1);
    expect(findingsOfCode(findings, 'noop-audit-sink')[0]?.severity).toBe('warning');
  });

  it('flags a missing quarantineImpl as info when no tool declares mayCallSummarize', () => {
    const findings = checkBrokerConfig({}, [tool()]);
    const f = findingsOfCode(findings, 'unconfigured-quarantine-impl');
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('info');
  });

  it('treats the library\'s own unconfiguredQuarantineImpl as equivalent to "not configured"', () => {
    const findings = checkBrokerConfig({ quarantineImpl: unconfiguredQuarantineImpl }, []);
    expect(findingsOfCode(findings, 'unconfigured-quarantine-impl')).toHaveLength(1);
  });

  it('escalates the missing-quarantineImpl finding to error when a tool declares mayCallSummarize:true', () => {
    const findings = checkBrokerConfig({}, [
      tool({ name: 'fetch_and_quarantine', mayCallSummarize: true }),
    ]);
    const f = findingsOfCode(findings, 'unconfigured-quarantine-impl');
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('error');
    expect(f[0]?.message).toContain('fetch_and_quarantine');
  });

  it('a real quarantineImpl suppresses the finding even when mayCallSummarize tools exist', () => {
    const findings = checkBrokerConfig({ quarantineImpl: stubQuarantineImpl }, [
      tool({ mayCallSummarize: true }),
    ]);
    expect(findingsOfCode(findings, 'unconfigured-quarantine-impl')).toHaveLength(0);
  });

  it('flags requireQuarantineSchema being off as info, always, regardless of catalog', () => {
    const findings = checkBrokerConfig({ requireQuarantineSchema: false }, []);
    expect(findingsOfCode(findings, 'quarantine-schema-not-required')).toHaveLength(1);
    expect(findingsOfCode(findings, 'quarantine-schema-not-required')[0]?.severity).toBe('info');
  });

  it('does not flag quarantine-schema-not-required when requireQuarantineSchema is true', () => {
    const findings = checkBrokerConfig({ requireQuarantineSchema: true }, []);
    expect(findingsOfCode(findings, 'quarantine-schema-not-required')).toHaveLength(0);
  });

  it('flags an EXFIL-capable tool with no allowedOutboundHosts configured, as a warning', () => {
    const findings = checkBrokerConfig({}, [
      tool({ name: 'post_webhook', capabilities: { capabilities: ['net:outbound'] } }),
    ]);
    const f = findingsOfCode(findings, 'exfil-without-allowlist');
    expect(f).toHaveLength(1);
    expect(f[0]?.severity).toBe('warning');
    expect(f[0]?.message).toContain('post_webhook');
  });

  it('does not flag exfil-without-allowlist once allowedOutboundHosts is configured', () => {
    const findings = checkBrokerConfig({ allowedOutboundHosts: ['example.com'] }, [
      tool({ capabilities: { capabilities: ['net:outbound'] } }),
    ]);
    expect(findingsOfCode(findings, 'exfil-without-allowlist')).toHaveLength(0);
  });

  it('does not flag exfil-without-allowlist when no tool is actually EXFIL-classed', () => {
    const findings = checkBrokerConfig({}, [
      tool({ capabilities: { capabilities: ['write:fs'] } }),
    ]);
    expect(findingsOfCode(findings, 'exfil-without-allowlist')).toHaveLength(0);
  });
});

describe('runDoctor()', () => {
  it('runs checkToolCatalog() alone when brokerConfig is omitted', () => {
    const findings = runDoctor({ tools: [tool({ name: '__tttb_evil' })] });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.code).toBe('reserved-tool-name');
  });

  it('concatenates catalog and config findings when brokerConfig is provided', () => {
    const findings = runDoctor({
      tools: [tool({ name: '__tttb_evil' })],
      brokerConfig: {},
    });
    expect(findings.map((f) => f.code)).toContain('reserved-tool-name');
    expect(findings.map((f) => f.code)).toContain('noop-audit-sink');
  });

  it('threads catalogOpts through to checkToolCatalog()', () => {
    const findings = runDoctor({
      tools: [tool({ name: 'launch_the_thing' })],
      catalogOpts: { unclassifiedSinkKeywords: ['launch'] },
    });
    expect(findings.map((f) => f.code)).toContain('unclassified-sink-keyword');
  });
});

describe('formatDoctorReport()', () => {
  it('reports "no findings" for an empty list', () => {
    expect(formatDoctorReport([])).toBe('doctor: no findings.');
  });

  it('summarizes counts by severity and sorts error before warning before info', () => {
    const findings: DoctorFinding[] = [
      { severity: 'info', code: 'z-info', message: 'an info finding' },
      { severity: 'error', code: 'a-error', message: 'an error finding' },
      { severity: 'warning', code: 'm-warning', message: 'a warning finding' },
    ];
    const report = formatDoctorReport(findings);
    expect(report).toContain('1 error(s), 1 warning(s), 1 info(s)');
    const errorPos = report.indexOf('[ERROR]');
    const warnPos = report.indexOf('[WARN ]');
    const infoPos = report.indexOf('[INFO ]');
    expect(errorPos).toBeGreaterThan(-1);
    expect(errorPos).toBeLessThan(warnPos);
    expect(warnPos).toBeLessThan(infoPos);
  });

  it('includes the toolName in parentheses when present, and omits it when absent', () => {
    const withTool = formatDoctorReport([
      { severity: 'error', code: 'c', message: 'm', toolName: 'my_tool' },
    ]);
    expect(withTool).toContain('c (my_tool): m');

    const withoutTool = formatDoctorReport([{ severity: 'error', code: 'c', message: 'm' }]);
    expect(withoutTool).toContain('[ERROR] c: m');
  });
});
