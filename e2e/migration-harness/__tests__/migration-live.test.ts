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
  ['noop', 'behaviour', 'migration.legacy-packages-absent'],
  ['downcase', 'behaviour', 'behaviour.downcase-new-write-lookup'],
  ['stale-hmac', 'behaviour', 'migration.active-hmac-absent'],
  ['bigint', 'behaviour', 'behaviour.balance-decimal-string'],
  ['rewrite', 'behaviour', 'no-rewrite.legacy-bytes'],
  ['missing-log', 'invalid-friction-log', null],
  ['legacy-ffi', 'behaviour', 'migration.legacy-packages-absent'],
] as const
for (const [kind, outcome, checkId] of cases) {
  test.skipIf(!enabled)(
    `real Run self-test: ${kind}`,
    async () => {
      const output = await mkdtemp(resolve(tmpdir(), 'mh-selftest-'))
      const isolation = createIsolation()
      const manifest = { stack: '^1.2.1', guideHash: null }
      const driver = createRealDriver({
        id: `selftest-${Date.now()}`,
        root: fileURLToPath(new URL('../../..', import.meta.url)),
        output,
        command: '',
        fakeMigration: kind,
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
        assert.equal(report.outcome, outcome, JSON.stringify(report))
        if (checkId)
          assert.equal(
            Object(report.evidence.find((e) => e.checkId === checkId)?.payload)
              .passed,
            false,
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
