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
  PlanState,
  ToolCallBroker,
  CallResult,
  RawQuarantineSourceTool,
  QuarantineSourceResult,
} from './types.js';

export {
  LEVEL_ORDER,
  maxLevel,
  levelAtLeast,
  sinkClassOf,
  NOT_SENSITIVE,
  TAINT_BRAND,
} from './types.js';

export { createBroker, likelyUnclassifiedSinkKeyword } from './broker.js';
export type { BrokerOptions } from './broker.js';

export { defaultPolicy } from './policy/default-policy.js';

export { InMemoryTaintRegistry } from './taint/registry.js';
export type { InMemoryTaintRegistryOpts } from './taint/registry.js';

export {
  serializeRegistry,
  restoreRegistry,
  serializeBrokerState,
  restoreBrokerState,
  serializeAuditEvent,
  InvalidBrokerStateError,
  SERIALIZED_BROKER_STATE_SCHEMA_VERSION,
} from './persistence.js';
export type {
  SerializedTaintRecord,
  SerializedBrokerState,
  SerializedTaintMatch,
  SerializedAuditEvent,
} from './persistence.js';
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
export {
  findOutboundDestinationsOutsideKeys,
  findOutboundHosts,
  isAllowedOutboundHost,
} from './taint/egress.js';
export type { OutOfScopeDestination } from './taint/egress.js';
export { diffProposedArgs } from './taint/counterfactual-diff.js';
export type { ArgDiff } from './taint/counterfactual-diff.js';
export { checkFieldGrounding } from './grounding.js';
export type { CheckFieldGroundingOpts, FieldGroundingResult } from './grounding.js';
export { createToolDescriptorGuard } from './tool-descriptor-guard.js';
export type { ToolDescriptor } from './tool-descriptor-guard.js';
export {
  createScope,
  createWatermark,
  declassifyScope,
  markPrivateDataSeen,
  raiseWatermark,
} from './taint/scope.js';
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

export { createDeferredApprovalChannel, DuplicateApprovalTokenError } from './approval.js';
export type { DeferredApprovalChannel, DeferredApprovalChannelOpts } from './approval.js';

export { jsonSafeClone } from './json-safe-clone.js';

export { createTaintEnvelope } from './envelope.js';
export type { TaintEnvelope } from './envelope.js';

export { defineSource, defineSink } from './define.js';
export type { DefineSourceOpts, DefineSinkOpts } from './define.js';

export { formatAuditTrail, explainWatermark, AggregatingAuditSink } from './debug.js';

export {
  TaintBrokerError,
  ToolCallBlockedError,
  UnknownToolError,
  QuarantineInputMismatchError,
  QuarantineInputUnknownError,
  QuarantineSchemaRequiredError,
  DualRoleToolError,
  ReentrantCallError,
  NonCloneableArgsError,
  PlanNotDeclarableError,
  UnplannedPrivilegedActionError,
  ReservedToolNameError,
  QuarantineSourceUnavailableError,
  DisallowedOutboundHostError,
  ArgsTooDeepError,
} from './errors.js';
