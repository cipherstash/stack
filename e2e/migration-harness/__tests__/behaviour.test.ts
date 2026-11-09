import assert from 'node:assert/strict'
import { test } from 'vitest'
import { behaviour, legacy, mutation } from '../run/behaviour.mjs'
import { run } from '../run/run.mjs'

test('Run observes Legacy Data before new writes and mutation through App Host channel', async () => {
  const rows = new Map([
    [legacy.pk, legacy],
    [mutation.pk, mutation],
  ])
  const postgres = new Map([[legacy.pk, legacy]])
  const methods = []
  const project = (row) =>
    row &&
    Object.fromEntries(['pk', 'email', 'age', 'notes'].map((k) => [k, row[k]]))
  async function call(method, args) {
    methods.push(method)
    const [value] = args
    if (method === 'get') return rows.get(value) ?? null
    if (method === 'getPostgres') return project(postgres.get(value)) ?? null
    if (method === 'put') {
      rows.set(value.pk, {
        ...value,
        emailLower: value.emailLower.toLowerCase(),
      })
      return
    }
    if (method === 'setActive') {
      rows.set(value, { ...rows.get(value), active: args[1] })
      return
    }
    if (method === 'copyToPostgres') {
      postgres.set(value, rows.get(value))
      return
    }
    if (method === 'copyToDynamo') return
    const fields = {
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
          ? row.emailLower.toLowerCase() === value.toLowerCase()
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
      seed: async () => {},
      snapshot: async () => {},
      migrate: async () => ({ exitCode: 0 }),
      friction: async () => [],
      installAppHost: async () => {},
      behaviour: async () => (await behaviour(call)).mutate(),
    },
  })
  assert.equal(report.outcome, 'pass')
  assert.equal(
    report.evidence.filter((e) => e.kind === 'oracle-check').length,
    19,
  )
  assert.ok(methods.indexOf('put') > methods.indexOf('findPostgresAge'))
})
test('fresh-write lookup failure is visible as stable Oracle evidence', async () => {
  const result = await behaviour(async (method) => {
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
