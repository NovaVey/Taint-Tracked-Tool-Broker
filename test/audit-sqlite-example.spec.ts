import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

// examples/audit-sqlite.ts (like every file under examples/) is exercised by
// its own `npm run example:*` script, not imported into the library's own
// module graph — its top level calls `main()` unconditionally, so importing
// it here would just run the whole example as an unwanted side effect of
// loading the test file. Running it exactly the way a real
// `npm run example:audit-sqlite` invocation would (`tsx` in a subprocess) is
// the only way to assert on what it actually demonstrates without
// duplicating its wiring by hand — same pattern every other
// `examples/*.ts` file's own regression test uses (e.g.
// test/vercel-ai-sdk-integration-example.spec.ts,
// test/taint-envelope-handoff-example.spec.ts).
//
// What this test is actually pinning down: that writing AuditEvents to a
// real node:sqlite database via serializeAuditEvent(), reading them back out,
// and reviving them into real AuditEvent objects (bigint simhash,
// Uint32Array shingleHashes restored, not left as their JSON-safe stand-ins)
// is genuinely lossless — specifically, that formatAuditTrail() renders the
// SQLite-round-tripped events identically to how the library documents it
// rendering a live AuditEvent stream, and that the QUARANTINE_AND_RETRY
// event's matchedRecords[].record.fingerprint fields come back as real
// bigint/Uint32Array, not strings/plain arrays left over from JSON.parse.
const execFileAsync = promisify(execFile);
const exampleScriptPath = fileURLToPath(new URL('../examples/audit-sqlite.ts', import.meta.url));

// examples/audit-sqlite.ts's own header is explicit that node:sqlite needs
// Node 22+ -- a stricter floor than this library's own package.json
// engines.node (">=20"), which this repository's CI matrix (ci.yml) tests
// directly: Node 20, 22, and 24. Without this guard, this test fails on the
// Node 20 job with ERR_UNKNOWN_BUILTIN_MODULE (node:internal/modules/esm/
// translators) -- not a flake, and not a bug in the example or the library's
// own >=20 floor (nothing in src/ uses node:sqlite), just this one example's
// documented, deliberately-accepted stricter requirement colliding with a CI
// matrix entry below it. assertSqliteAvailable() inside the example itself
// already turns that into a clear thrown message rather than the cryptic
// built-in-module error above; skipping here (rather than asserting on that
// thrown-error text) avoids the test suite reporting a real capability gap
// as a "pass" on Node 20, which would be its own kind of misleading result.
const nodeMajor = Number(process.versions.node.split('.')[0]);

describe('examples/audit-sqlite.ts', () => {
  it.skipIf(Number.isNaN(nodeMajor) || nodeMajor < 22)(
    'writes AuditEvents to a real SQLite table and renders them back losslessly via formatAuditTrail()',
    async () => {
      const { stdout } = await execFileAsync('npx', ['tsx', exampleScriptPath], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
      });

      // The session's four gated calls each landed at the verdict this
      // scenario is built around.
      expect(stdout).toContain('write_file (pre-exposure): ALLOW');
      expect(stdout).toContain('scope watermark after fetch_url: RAW_UNTRUSTED');
      expect(stdout).toContain('shell_exec (post-exposure): QUARANTINE_AND_RETRY');
      expect(stdout).toContain(
        'write_file (post-exposure): REQUIRE_APPROVAL (denied — no approvalChannel configured, fails safe)',
      );

      // A real SQL aggregate query over the table, not just row dumps —
      // proves audit_events is genuinely queryable, not a JSON blob store.
      expect(stdout).toContain(
        'verdict counts via a real SQL GROUP BY query: ALLOW=1, ALLOW_WITH_WARNING=1, QUARANTINE_AND_RETRY=1, REQUIRE_APPROVAL=1',
      );
      expect(stdout).toContain('4 audit events read back from SQLite');

      // formatAuditTrail() rendered over events that came ONLY from a SQLite
      // read-back (sink.all()), not from anything kept in memory from the
      // calls themselves — this is the actual round-trip claim. Assert on the
      // rendered content, not just "some output happened": every one of the
      // four verdict lines, with the real tool name, verdict action, and scope
      // level, must appear in formatAuditTrail()'s output specifically (below
      // the "--- formatAuditTrail()" marker), proving the revived AuditEvent
      // objects actually round-tripped enough real structure to render.
      const trailIndex = stdout.indexOf(
        '--- formatAuditTrail() over events read back from SQLite ---',
      );
      expect(trailIndex).toBeGreaterThan(-1);
      const trail = stdout.slice(trailIndex);
      expect(trail).toContain(
        'write_file({"path":"/tmp/notes.json","contents":"pre-exposure, clean write"}) -> ALLOW',
      );
      expect(trail).toContain('fetch_url({"url":"https://evil.example"}) -> ALLOW_WITH_WARNING');
      expect(trail).toContain('-> QUARANTINE_AND_RETRY [scope: RAW_UNTRUSTED]');
      expect(trail).toContain(
        'write_file({"path":"/tmp/notes.json","contents":"post-exposure write"}) -> REQUIRE_APPROVAL',
      );

      // The specific hazard serializeAuditEvent() exists to close
      // (persistence.ts's own header, AuditSink.record()'s own doc comment):
      // a bigint simhash / Uint32Array shingleHashes surviving a real
      // JSON.stringify -> SQLite TEXT column -> JSON.parse round trip as
      // their genuine runtime types, not merely "some value came back." Verified
      // to have teeth: temporarily replacing reviveTaintRecord()'s
      // BigInt(...)/Uint32Array.from(...) conversion with bare passthrough casts
      // makes this exact assertion fail (the example instead prints
      // "...revived as a real bigint: false | ...revived as a real Uint32Array:
      // false"), and restoring the real conversion makes it pass again.
      expect(stdout).toContain(
        'QUARANTINE_AND_RETRY event found, with fingerprint.simhash revived as a real bigint: true | ' +
          'fingerprint.shingleHashes revived as a real Uint32Array: true',
      );

      // Never mislabels a real block/deny as an allowed call.
      expect(stdout).not.toContain('UNEXPECTED');
    },
    30_000,
  );
});
