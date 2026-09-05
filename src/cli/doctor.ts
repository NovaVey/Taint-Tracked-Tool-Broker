#!/usr/bin/env node
/**
 * `npx tttb doctor <path-to-config.js>` — the CLI wrapper around
 * `checkToolCatalog()`/`checkBrokerConfig()`/`runDoctor()` (`../doctor.js`,
 * also exported from the package root for direct, CLI-free use in your own
 * CI test suite — see that module's own header for why calling those
 * functions directly is usually the more natural fit for a TypeScript-first
 * integration).
 *
 * **Config-module contract.** `<path-to-config.js>` is dynamically
 * `import()`ed as-is — a plain JS/ESM module, your own compiled build
 * output, NOT a `.ts` source file this CLI compiles for you (this package
 * ships no TypeScript-compilation step for consumer code; point this at
 * whatever your own build already produces, or a small hand-written `.js`
 * shim that imports your real catalog/config and re-exports the two names
 * below). It must export, by name (a default export with both keys also
 * works):
 *
 *   export const tools = [ ...your ToolExecutor[] catalog... ];
 *   export const brokerConfig = {
 *     auditSink, quarantineImpl, requireQuarantineSchema, allowedOutboundHosts,
 *   }; // optional — omit entirely to skip checkBrokerConfig()
 *
 * Exit code is non-zero iff at least one `'error'`-severity finding is
 * present, or (with `--strict`) at least one `'warning'` — matching the
 * conventional "CI step fails the build" contract. `'info'` findings never
 * affect the exit code either way.
 */

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  checkBrokerConfig,
  checkToolCatalog,
  formatDoctorReport,
  type DoctorBrokerConfig,
  type DoctorFinding,
} from '../doctor.js';
import type { ToolExecutor } from '../types.js';

interface LoadedDoctorConfig {
  tools: readonly ToolExecutor[];
  brokerConfig?: DoctorBrokerConfig;
}

function usageError(message: string): never {
  console.error(`tttb doctor: ${message}`);
  console.error('Usage: tttb doctor <path-to-config.js> [--strict]');
  process.exit(2);
}

async function loadConfig(modulePath: string): Promise<LoadedDoctorConfig> {
  const absolutePath = resolve(process.cwd(), modulePath);
  let mod: Record<string, unknown>;
  try {
    mod = (await import(pathToFileURL(absolutePath).href)) as Record<string, unknown>;
  } catch (cause) {
    usageError(
      `could not import "${modulePath}" (resolved to "${absolutePath}"): ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }
  const source = (mod.default ?? mod) as Record<string, unknown>;
  const tools = source.tools;
  if (!Array.isArray(tools)) {
    usageError(
      `"${modulePath}" must export a "tools" array (a ToolExecutor[] catalog) — named, or on its default export.`,
    );
  }
  const brokerConfig = source.brokerConfig;
  if (brokerConfig !== undefined && (typeof brokerConfig !== 'object' || brokerConfig === null)) {
    usageError(`"${modulePath}"'s exported "brokerConfig" must be an object if present.`);
  }
  return {
    tools: tools as readonly ToolExecutor[],
    ...(brokerConfig !== undefined ? { brokerConfig } : {}),
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const [subcommand, ...rest] = args;
  if (subcommand !== 'doctor') {
    usageError(
      subcommand === undefined
        ? 'missing subcommand.'
        : `unknown subcommand "${subcommand}" (only "doctor" exists today).`,
    );
  }

  const strict = rest.includes('--strict');
  const positional = rest.filter((arg) => arg !== '--strict');
  const [configPath] = positional;
  if (configPath === undefined) {
    usageError('missing <path-to-config.js> argument.');
  }

  const { tools, brokerConfig } = await loadConfig(configPath);

  const findings: DoctorFinding[] = [...checkToolCatalog(tools)];
  if (brokerConfig !== undefined) {
    findings.push(...checkBrokerConfig(brokerConfig, tools));
  } else {
    console.log(
      'tttb doctor: no "brokerConfig" exported — skipping the config-inertness checks (auditSink/quarantineImpl/requireQuarantineSchema/allowedOutboundHosts).',
    );
  }

  console.log(formatDoctorReport(findings));

  const hasError = findings.some((f) => f.severity === 'error');
  const hasWarning = findings.some((f) => f.severity === 'warning');
  if (hasError || (strict && hasWarning)) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
