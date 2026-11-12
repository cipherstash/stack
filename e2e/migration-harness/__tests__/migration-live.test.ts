import 'dotenv/config'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'vitest'
import { createIsolation } from '../isolation.mjs'
import { createRealDriver } from '../run/real-driver.mjs'
import { run } from '../run/run.mjs'

const keys = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
]
const enabled =
  process.env.HARNESS_LIVE === '1' && keys.every((key) => process.env[key])
const cases = [
  ['reference', 'pass', null],
  ['noop', 'behaviour', 'migration.protect-dependencies-absent'],
  ['downcase', 'behaviour', 'behaviour.downcase-new-write-lookup'],
  ['stale-hmac', 'behaviour', 'migration.active-hmac-absent'],
  ['bigint', 'behaviour', 'behaviour.balance-decimal-string'],
  ['rewrite', 'behaviour', 'no-rewrite.legacy-bytes'],
  ['missing-log', 'invalid-friction-log', null],
  ['legacy-ffi', 'behaviour', 'migration.protect-ffi-version'],
  ['denied-app', 'pass', null],
  ['denied-lifecycle', 'pass', null],
  ['tree', 'pass', null],
] as const
for (const [kind, outcome, checkId] of cases) {
  test.skipIf(!enabled)(
    `real Run self-test: ${kind}`,
    async () => {
      const output = await mkdtemp(resolve(tmpdir(), 'mh-selftest-'))
      const isolation = createIsolation()
      const manifest = {
        stack: kind === 'tree' ? 'tree' : '^1.2.1',
        guideHash: null,
      }
      const driver = createRealDriver({
        id: `selftest-${Date.now()}`,
        root: fileURLToPath(new URL('../../..', import.meta.url)),
        output,
        command: '',
        fakeMigration: kind === 'tree' ? 'reference' : kind,
        isolation,
        credentials: Object.fromEntries(
          keys.map((key) => [key, process.env[key] ?? '']),
        ),
        manifest,
      })
      try {
        const report = await run({
          id: kind,
          manifest,
          driver,
          supervision: isolation,
        })
        const diagnostics = JSON.stringify({
          outcome: report.outcome,
          failures: report.failures,
          checks: report.evidence
            .filter(
              (e) =>
                e.kind === 'oracle-check' && Object(e.payload).passed === false,
            )
            .map((e) => e.payload),
        })
        assert.equal(report.outcome, outcome, diagnostics)
        // Every isolated exec starts with a startup probe that reads the same
        // canary, so only a command-stage denial from the expected actor and
        // Run stage proves the migrated code itself was exercised.
        const deniedBy = (actor: string, stage?: string) =>
          report.evidence.some(
            (e) =>
              e.kind === 'isolation-event' &&
              (stage === undefined || e.stage === stage) &&
              Object(e.payload).actor === actor &&
              Object(e.payload).stage === 'command' &&
              Object(e.payload).result === 'denied' &&
              Object(e.payload).decision === 'forbidden' &&
              Object(e.payload).resource === '/trace/canary',
          )
        if (kind === 'denied-app')
          assert.ok(deniedBy('app-host'), 'createApp probe was not denied')
        // Only the Migrator's bare `npm install` runs the root install hook;
        // the App Host names a package spec, and npm skips root lifecycle
        // scripts for `npm install <spec>`.
        if (kind === 'denied-lifecycle')
          assert.ok(
            deniedBy('migrator', 'migrator'),
            'Migrator install hook was not denied',
          )
        if (checkId)
          assert.equal(
            Object(report.evidence.find((e) => e.checkId === checkId)?.payload)
              .passed,
            false,
            diagnostics,
          )
        if (kind === 'noop')
          assert.ok(
            report.evidence
              .filter(
                (e) =>
                  e.kind === 'oracle-check' &&
                  !e.checkId.startsWith('migration.'),
              )
              .every((e) => Object(e.payload).passed),
          )
        if (kind === 'reference')
          assert.ok(
            report.evidence.some(
              (e) => e.checkId === 'no-rewrite.legacy-bytes',
            ),
          )
      } finally {
        await driver.close()
        await rm(output, { recursive: true, force: true })
      }
    },
    600_000,
  )
}
