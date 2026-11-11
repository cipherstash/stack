import assert from 'node:assert/strict'
import { test } from 'vitest'
import { behaviour, legacy, mutation } from '../run/behaviour.mjs'
import { requiredOracleChecks } from '../run/migration-checks.mjs'
import { run } from '../run/run.mjs'

const fields: Record<string, string> = {
  findEmail: 'email',
  findEmailLower: 'emailLower',
  findAge: 'age',
  findBalance: 'balance',
  findActive: 'active',
  findPostgresEmail: 'email',
  findPostgresAge: 'age',
}

async function lookupRun(unfilteredMethod?: string) {
  const rows = new Map<string, Record<string, unknown>>(
    [legacy, mutation].map((row) => [row.pk, { ...row }]),
  )
  const project = (row: Record<string, unknown>) =>
    Object.fromEntries(
      ['pk', 'email', 'age', 'notes'].map((key) => [key, row[key]]),
    )
  const postgres = new Map<string, Record<string, unknown>>(
    [legacy, mutation].map((row) => [row.pk, project(row)]),
  )
  async function call(method: string, [value, active]: unknown[]) {
    if (method === 'get') return rows.get(String(value)) ?? null
    if (method === 'getPostgres') return postgres.get(String(value)) ?? null
    if (method === 'put') {
      if (!value || typeof value !== 'object') throw Error('Expected customer')
      const customer = Object.fromEntries(Object.entries(value))
      rows.set(String(customer.pk), customer)
      return
    }
    if (method === 'setActive') {
      rows.set(String(value), { ...rows.get(String(value)), active })
      return
    }
    if (method === 'copyToPostgres') {
      const row = rows.get(String(value))
      if (!row) throw Error('Missing source')
      postgres.set(String(value), project(row))
      return
    }
    if (method === 'copyToDynamo') {
      rows.set(String(value), {
        ...rows.get(String(value)),
        ...postgres.get(String(value)),
      })
      return
    }
    if (!fields[method]) throw Error(`Unknown method: ${method}`)
    const source = method.startsWith('findPostgres') ? postgres : rows
    return [...source.values()].filter((row) => {
      if (method === unfilteredMethod) return true
      return method === 'findEmailLower'
        ? String(row.emailLower).toLowerCase() === String(value).toLowerCase()
        : row[fields[method]] === value
    })
  }
  return run({
    id: unfilteredMethod ?? 'correct-lookups',
    manifest: { guideHash: 'guide' },
    driver: {
      provision: async () => {},
      installUnmigrated: async () => {},
      initializeLegacyData: async () => {},
      snapshot: async () => {},
      migrate: async () => ({ exitCode: 0 }),
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () => [
        ...(await (await behaviour(call)).mutate()),
        ...requiredOracleChecks.map((id) => ({ id, passed: true })),
      ],
    },
  })
}

test('exact lookups accept all matching rows when fixture values are shared', async () => {
  const report = await lookupRun()
  assert.equal(report.outcome, 'pass', JSON.stringify(report.evidence))
})

test.each(Object.keys(fields))(
  'a Run rejects %s returning every row instead of filtering',
  async (method) => {
    const report = await lookupRun(method)
    assert.equal(report.outcome, 'behaviour')
    assert.ok(
      report.evidence.some(
        (entry) =>
          entry.kind === 'oracle-check' &&
          entry.checkId.startsWith('behaviour.') &&
          typeof entry.payload === 'object' &&
          entry.payload !== null &&
          'passed' in entry.payload &&
          entry.payload.passed === false,
      ),
    )
  },
)
