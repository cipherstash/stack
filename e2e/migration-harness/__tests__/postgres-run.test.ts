import { expect, test } from 'vitest'
import { run } from '../run/run.mjs'

const checks = [
  'behaviour.postgres-row-retention',
  'no-rewrite.postgres-retained-bytes',
  'migration.postgres-v3-columns',
  'migration.postgres-indexes',
  'migration.protect-dependencies-absent',
  'migration.protect-ffi-version',
  'migration.endpoint-shim-absent',
  'behaviour.postgres-legacy-read',
  'behaviour.postgres-email-lookup',
  'behaviour.postgres-age-lookup',
  'behaviour.postgres-fresh-write',
  'behaviour.postgres-fresh-lookups',
]
test('Postgres Run requires its own Oracle contract rather than DynamoDB HMAC checks', async () => {
  const driver = {
    provision: async () => {},
    installUnmigrated: async () => {},
    initializeLegacyData: async () => {},
    snapshot: async () => {},
    migrate: async () => ({ exitCode: 0 }),
    friction: async () => [],
    installAppHost: async () => {},
    behaviour: async () => checks.map((id) => ({ id, passed: true })),
  }
  const manifest = {
    guideHash: 'guide',
    procedure: 'postgres-v2-to-v3' as const,
  }
  expect((await run({ id: 'pg', manifest, driver })).outcome).toBe('pass')
  driver.behaviour = async () =>
    checks
      .filter((id) => id !== 'migration.postgres-indexes')
      .map((id) => ({ id, passed: true }))
  expect((await run({ id: 'pg-missing', manifest, driver })).outcome).toBe(
    'behaviour',
  )
})
