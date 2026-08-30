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
  RequireApprovalDecision,
  PolicyFn,
  ApprovalChannel,
  AuditEvent,
  AuditSink,
  QuarantineOpts,
  QuarantineResult,
  QuarantineFn,
  QuarantineImpl,
  PlanStep,
  ToolCallBroker,
  CallResult,
  RawQuarantineSourceTool,
  QuarantineSourceResult,
} from './types.js';

export { LEVEL_ORDER, maxLevel, levelAtLeast, sinkClassOf, NOT_SENSITIVE, TAINT_BRAND } from './types.js';

export { createBroker } from './broker.js';
export type { BrokerOptions } from './broker.js';

export { defaultPolicy } from './policy/default-policy.js';

export { InMemoryTaintRegistry } from './taint/registry.js';
export type { InMemoryTaintRegistryOpts } from './taint/registry.js';

export { serializeRegistry, restoreRegistry, serializeBrokerState, restoreBrokerState } from './persistence.js';
export type { SerializedTaintRecord, SerializedBrokerState } from './persistence.js';
export {
  buildFingerprint,
  computeSimhash,
  exactHash,
  hammingDistance,
  overlapCoefficient,
  shingleIntersectionSize,
  toRegistrableText,
  wordShingles,
} from './taint/fingerprint.js';
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

export { createDeferredApprovalChannel } from './approval.js';
export type { DeferredApprovalChannel, DeferredApprovalChannelOpts } from './approval.js';

export { jsonSafeClone } from './json-safe-clone.js';

export { defineSource, defineSink } from './define.js';
export type { DefineSourceOpts, DefineSinkOpts } from './define.js';

export {
  TaintBrokerError,
  ToolCallBlockedError,
  UnknownToolError,
  QuarantineInputMismatchError,
  QuarantineInputUnknownError,
  DualRoleToolError,
  ReentrantCallError,
  NonCloneableArgsError,
  PlanNotDeclarableError,
  UnplannedPrivilegedActionError,
  ReservedToolNameError,
  QuarantineSourceUnavailableError,
} from './errors.js';
