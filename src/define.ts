/**
 * Small, pure sugar for building a `ToolExecutor` — no broker involved, no
 * behavior these could get wrong: `broker.register()`/`broker.wrap()` still
 * do all real validation (DualRoleToolError, ReservedToolNameError) on
 * whatever these hand back. They exist only to make the common shapes
 * (a plain source, a plain sink) less verbose to write out by hand.
 */

import type { SinkCapability, ToolExecutor } from './types.js';

export interface DefineSourceOpts {
  /** Deterministic/pure sources may opt out of raising the watermark — same meaning as ToolExecutor.trusted. */
  trusted?: boolean;
  readsPrivateData?: { categories: string[] } | false;
}

/** Builds a source-only ToolExecutor (isSource: true, no sink capabilities) — the common "fetch/read" shape. */
export function defineSource<A = unknown, R = unknown>(name: string, execute: (args: A) => Promise<R>, opts: DefineSourceOpts = {}): ToolExecutor<A, R> {
  const executor: ToolExecutor<A, R> = { name, capabilities: { capabilities: [] }, isSource: true, execute };
  if (opts.trusted !== undefined) executor.trusted = opts.trusted;
  if (opts.readsPrivateData !== undefined) executor.capabilities.readsPrivateData = opts.readsPrivateData;
  return executor;
}

export interface DefineSinkOpts {
  /** Set true only for a tool that is ALSO a source of untrusted content — most sinks aren't; register()/wrap() reject the combination unless `trusted` is also set (DualRoleToolError, GAPS.md). */
  isSource?: boolean;
  trusted?: boolean;
  readsPrivateData?: { categories: string[] } | false;
}

/** Builds a privileged-sink ToolExecutor with the given declared capabilities — the common "act" shape. */
export function defineSink<A = unknown, R = unknown>(
  name: string,
  capabilities: SinkCapability[],
  execute: (args: A) => Promise<R>,
  opts: DefineSinkOpts = {},
): ToolExecutor<A, R> {
  const executor: ToolExecutor<A, R> = { name, capabilities: { capabilities }, execute };
  if (opts.isSource !== undefined) executor.isSource = opts.isSource;
  if (opts.trusted !== undefined) executor.trusted = opts.trusted;
  if (opts.readsPrivateData !== undefined) executor.capabilities.readsPrivateData = opts.readsPrivateData;
  return executor;
}
