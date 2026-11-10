import assert from 'node:assert/strict'
import { test } from 'vitest'
import { behaviour, legacy, mutation } from '../run/behaviour.mjs'
import { requiredOracleChecks } from '../run/migration-checks.mjs'
import { run } from '../run/run.mjs'

test('Run observes Legacy Data before new writes and mutation through App Host channel', async () => {
  const rows = new Map<string, Record<string, unknown>>([
    [legacy.pk, legacy],
    [mutation.pk, mutation],
  ])
  const postgres = new Map<string, Record<string, unknown>>([
    [legacy.pk, legacy],
  ])
  const methods: string[] = []
  const project = (row: Record<string, unknown> | undefined) =>
    row &&
    Object.fromEntries(['pk', 'email', 'age', 'notes'].map((k) => [k, row[k]]))
  async function call(method: string, args: unknown[]) {
    methods.push(method)
    const [value] = args
    if (method === 'get') return rows.get(String(value)) ?? null
    if (method === 'getPostgres')
      return project(postgres.get(String(value))) ?? null
    if (method === 'put') {
      if (value === null || typeof value !== 'object')
        throw Error('Expected customer')
      const customer: Record<string, unknown> = Object.fromEntries(
        Object.entries(value),
      )
      rows.set(String(customer.pk), customer)
      return
    }
    if (method === 'setActive') {
      rows.set(String(value), { ...rows.get(String(value)), active: args[1] })
      return
    }
    if (method === 'copyToPostgres') {
      const row = rows.get(String(value))
      if (!row) throw Error('Missing source')
      postgres.set(String(value), row)
      return
    }
    if (method === 'copyToDynamo') {
      rows.set(String(value), {
        ...rows.get(String(value)),
        ...postgres.get(String(value)),
      })
      return
    }
    const fields: Record<string, string> = {
      findEmail: 'email',
      findEmailLower: 'emailLower',
      findAge: 'age',
      findBalance: 'balance',
      findActive: 'active',
      findPostgresEmail: 'email',
      findPostgresAge: 'age',
    }
    const source = method.startsWith('findPostgres') ? postgres : rows
    return [...source.values()]
      .filter((row) =>
        method === 'findEmailLower'
          ? String(row.emailLower).toLowerCase() === String(value).toLowerCase()
          : row[fields[method]] === value,
      )
      .map((row) => (method.startsWith('findPostgres') ? project(row) : row))
  }
  const report = await run({
    id: 'behaviour',
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
  assert.equal(report.outcome, 'pass')
  assert.equal(
    report.evidence.filter((e) => e.kind === 'oracle-check').length,
    19 + requiredOracleChecks.length,
  )
  assert.ok(methods.indexOf('put') > methods.indexOf('findPostgresAge'))
})
test('fresh-write lookup failure is visible as stable Oracle evidence', async () => {
  const result = await behaviour(async (method: string) => {
    if (method.startsWith('find')) return []
    if (method === 'get') return null
    return null
  })
  const checks = await result.mutate()
  assert.deepEqual(
    checks.find((check) => check.id === 'behaviour.fresh-findBalance'),
    {
      id: 'behaviour.fresh-findBalance',
      passed: false,
      cause: 'Fresh write not found',
    },
  )
})
