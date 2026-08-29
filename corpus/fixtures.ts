/**
 * Shared mock tools used by the injection corpus (DESIGN.md §9).
 *
 * Every fixture's execute() just echoes back `args.mockResult` (or `args`
 * itself) — the corpus fully controls what a "source" tool "found" without
 * needing a real fetch/read, so cases are deterministic and offline.
 */

import type { ToolExecutor } from '../src/index.js';

function mockResultOf(args: unknown): unknown {
  if (args !== null && typeof args === 'object' && 'mockResult' in args) {
    return (args as { mockResult?: unknown }).mockResult;
  }
  return args;
}

export const FIXTURES: Record<string, ToolExecutor> = {
  // ---- sources (isSource: true; raise the watermark on a successful call) ----
  fetch_url: {
    name: 'fetch_url',
    capabilities: { capabilities: [] },
    isSource: true,
    async execute(args) {
      return mockResultOf(args);
    },
  },
  read_email: {
    name: 'read_email',
    capabilities: { capabilities: [] },
    isSource: true,
    async execute(args) {
      return mockResultOf(args);
    },
  },
  read_credentials: {
    name: 'read_credentials',
    capabilities: { capabilities: [], readsPrivateData: { categories: ['credentials'] } },
    isSource: true,
    async execute(args) {
      return mockResultOf(args);
    },
  },
  read_local_config: {
    name: 'read_local_config',
    capabilities: { capabilities: [] },
    isSource: true,
    trusted: true, // deterministic/developer-authored — opts out of raising the watermark (§4.1)
    async execute(args) {
      return mockResultOf(args);
    },
  },

  // ---- sinks (declare capabilities; policy-gated) ----
  shell_exec: {
    name: 'shell_exec',
    capabilities: { capabilities: ['exec:shell'] }, // EXEC
    async execute(args) {
      return `ran: ${JSON.stringify(args)}`;
    },
  },
  write_file: {
    name: 'write_file',
    capabilities: { capabilities: ['write:fs'] }, // MUTATE
    async execute(args) {
      return `wrote: ${JSON.stringify(args)}`;
    },
  },
  approve_purchase: {
    name: 'approve_purchase',
    capabilities: { capabilities: ['finance:purchase'] }, // MUTATE
    async execute(args) {
      return `purchase-decision: ${JSON.stringify(args)}`;
    },
  },
  send_email: {
    name: 'send_email',
    capabilities: { capabilities: ['net:email'] }, // EXFIL
    async execute(args) {
      return `sent: ${JSON.stringify(args)}`;
    },
  },
  net_post: {
    name: 'net_post',
    capabilities: { capabilities: ['net:outbound'] }, // EXFIL
    async execute(args) {
      return `posted: ${JSON.stringify(args)}`;
    },
  },

  // ---- non-sink control (capabilities: [] — never gated) ----
  save_draft: {
    name: 'save_draft',
    capabilities: { capabilities: [] },
    async execute(args) {
      return `draft: ${JSON.stringify(args)}`;
    },
  },
};
