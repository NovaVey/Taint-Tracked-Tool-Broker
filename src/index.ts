/**
 * Taint-Tracked Tool Broker (TTTB) — public API.
 *
 * See DESIGN.md for the architecture and GAPS.md for known limitations.
 * Quick start:
 *
 *   import { createBroker } from 'taint-tracked-tool-broker';
 *
 *   const broker = createBroker({ approvalChannel, auditSink, quarantineImpl });
 *   const fetchUrl = broker.wrap({
 *     name: 'fetch_url',
 *     capabilities: { capabilities: [] },
 *     isSource: true,
 *     async execute({ url }) { ... },
 *   });
 *   const shellExec = broker.wrap({
 *     name: 'shell_exec',
 *     capabilities: { capabilities: ['exec:shell'] },
 *     async execute({ cmd }) { ... },
 *   });
 *
 *   await fetchUrl.execute({ url: 'https://example.com' }); // raises the watermark if untrusted
 *   await shellExec.execute({ cmd: '...' });                // gated by the current watermark
 */

export type {
  TaintLevel,
  ProvenanceTag,
  SensitivityLabel,
  Fingerprint,
  TaintRecord,
  MatchType,
  TaintMatch,
  FuzzyLookupOpts,
  TaintRegistry,
  TaintedValue,
  TaintWatermark,
  ScopeKind,
  TaintScope,
  ResetScope,
  SinkClass,
  SinkCapability,
  SinkCapabilities,
  ToolExecutor,
  ToolCall,
  TaintContext,
  PolicyDecision,
  PolicyFn,
  ApprovalChannel,
  AuditEvent,
  AuditSink,
  QuarantineOpts,
  QuarantineResult,
  QuarantineFn,
  QuarantineImpl,
  ToolCallBroker,
} from './types.js';

export { LEVEL_ORDER, maxLevel, levelAtLeast, sinkClassOf, NOT_SENSITIVE, TAINT_BRAND } from './types.js';

export { createBroker } from './broker.js';
export type { BrokerOptions } from './broker.js';

export { defaultPolicy } from './policy/default-policy.js';

export { InMemoryTaintRegistry } from './taint/registry.js';
export { buildFingerprint, computeSimhash, exactHash, hammingDistance, overlapCoefficient, wordShingles } from './taint/fingerprint.js';
export { scanArgsForTaint } from './taint/scan.js';
export type { ScanResult } from './taint/scan.js';
export { createScope, createWatermark, declassifyScope, markPrivateDataSeen, raiseWatermark } from './taint/scope.js';
export {
  concatTainted,
  isTaintedValue,
  mapTainted,
  spreadTainted,
  taintAwareJSONStringify,
  unwrap,
  wrapTainted,
} from './taint/wrapper.js';

export { unconfiguredQuarantineImpl } from './quarantine.js';

export { TaintBrokerError, ToolCallBlockedError, UnknownToolError, QuarantineInputMismatchError, QuarantineInputUnknownError } from './errors.js';
