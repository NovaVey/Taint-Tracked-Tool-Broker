/**
 * Small, pure sugar for building a `ToolExecutor` — no broker involved, no
 * behavior these could get wrong: `broker.register()`/`broker.wrap()` still
 * do all real validation (DualRoleToolError, ReservedToolNameError) on
 * whatever these hand back. They exist only to make the common shapes
 * (a plain source, a plain sink) less verbose to write out by hand.
 */

import type { SinkCapability, ToolExecutor } from './types.js';

export interface DefineSourceOpts {
  /** Same meaning as ToolExecutor.trusted — see its doc comment (types.ts) before setting this; it is more consequential, and easier to misuse, than "deterministic/pure" alone would suggest. */
  trusted?: boolean;
  readsPrivateData?: { categories: string[] } | false;
}

/** Builds a source-only ToolExecutor (isSource: true, no sink capabilities) — the common "fetch/read" shape. */
export function defineSource<A = unknown, R = unknown>(
  name: string,
  execute: (args: A) => Promise<R>,
  opts: DefineSourceOpts = {},
): ToolExecutor<A, R> {
  const executor: ToolExecutor<A, R> = {
    name,
    capabilities: { capabilities: [] },
    isSource: true,
    execute,
  };
  if (opts.trusted !== undefined) executor.trusted = opts.trusted;
  if (opts.readsPrivateData !== undefined)
    executor.capabilities.readsPrivateData = opts.readsPrivateData;
  return executor;
}

export interface DefineSinkOpts {
  /** Set true only for a tool that is ALSO a source of untrusted content — most sinks aren't; register()/wrap() reject the combination unless `trusted` is also set (DualRoleToolError, GAPS.md). */
  isSource?: boolean;
  /** Only meaningful alongside `isSource: true` above — see ToolExecutor.trusted's doc comment (types.ts) before setting this. */
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
  if (opts.readsPrivateData !== undefined)
    executor.capabilities.readsPrivateData = opts.readsPrivateData;
  return executor;
}
