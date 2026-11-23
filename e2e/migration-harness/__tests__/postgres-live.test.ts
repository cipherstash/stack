import { randomUUID } from 'node:crypto'
import 'dotenv/config'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test } from 'vitest'
import { createIsolation } from '../isolation.mjs'
import { createIsolationTrailWriter } from '../run/isolation-trail.mjs'
import { createRealDriver } from '../run/real-driver.mjs'
import { run } from '../run/run.mjs'

const keys = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
]
const enabled = process.env.HARNESS_LIVE === '1'
const cases = [
  ['reference', 'pass', null],
  ['noop', 'behaviour', 'migration.postgres-v3-columns'],
  ['row-loss', 'behaviour', 'behaviour.postgres-row-retention'],
  ['fresh-v2', 'behaviour', 'migration.postgres-fresh-v3-storage'],
  ['wrong-mapping', 'behaviour', 'behaviour.postgres-age-lookup'],
  ['missing-index', 'behaviour', 'migration.postgres-indexes'],
  ['rewrite', 'behaviour', 'no-rewrite.postgres-retained-bytes'],
  ['missing-log', 'invalid-friction-log', null],
] as const
for (const [kind, outcome, checkId] of cases)
  test.skipIf(!enabled)(
    `Postgres v2 real Run: ${kind}`,
    async () => {
      const missing = keys.filter((key) => !process.env[key])
      if (missing.length)
        throw Error(`HARNESS_LIVE=1 requires ${missing.join(', ')}`)
      const id = randomUUID()
      const output = await mkdtemp(resolve(tmpdir(), 'mh-postgres-'))
      const isolation = createIsolation()
      const manifest = {
        stack: '^1.2.1',
        guideHash: null,
        procedure: 'postgres-v2-to-v3' as const,
      }
      const driver = createRealDriver({
        id,
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
          id,
          manifest,
          driver,
          supervision: isolation,
          writeIsolationTrail: createIsolationTrailWriter(output),
        })
        const diagnostics = JSON.stringify({
          failures: report.failures,
          checks: report.evidence
            .filter((e) => e.kind === 'oracle-check')
            .map((e) => e.payload),
        })
        expect(report.outcome, diagnostics).toBe(outcome)
        expect(report.manifest).toMatchObject({
          procedure: 'postgres-v2-to-v3',
          sourceEqlGeneration: 2,
          targetEqlGeneration: 3,
        })
        expect(report.manifest.guideHash).toMatch(/^[a-f0-9]{64}$/)
        expect(report.manifest.stackSource).toMatchObject({
          version: expect.any(String),
        })
        const before = JSON.parse(
          await readFile(resolve(output, 'legacy-snapshot.json'), 'utf8'),
        )
        expect(before.rows).toHaveLength(3)
        expect(before.rows[0].email.v).toBe(2)
        if (kind === 'fresh-v2') {
          for (const id of [
            'behaviour.postgres-fresh-write',
            'behaviour.postgres-fresh-lookups',
          ])
            expect(
              report.evidence.find((e) => e.checkId === id)?.payload,
            ).toMatchObject({ passed: true })
        }
        if (checkId)
          expect(
            report.evidence.find((e) => e.checkId === checkId)?.payload,
          ).toMatchObject({ passed: false })
      } finally {
        await driver.close()
        await rm(output, { recursive: true, force: true })
      }
    },
    600_000,
  )
