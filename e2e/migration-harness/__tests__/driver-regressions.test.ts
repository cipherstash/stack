import { expect, test } from 'vitest'
import { behaviour, fresh, legacy, mutation } from '../run/behaviour.mjs'
import { requiredOracleChecks } from '../run/migration-checks.mjs'
import { run } from '../run/run.mjs'

// Model the documented plaintext API. Downcase applies to lookup terms, while
// decrypted source values retain their original casing.
function appChannel({ normalizeSources = false, copiesAreNoops = false } = {}) {
  const rows = new Map<string, Record<string, unknown>>([
    [legacy.pk, { ...legacy }],
    [mutation.pk, { ...mutation }],
  ])
  // This matches the real driver's seed(), including pre-copying Mutation Data.
  const pg = new Map<string, Record<string, unknown>>([
    [legacy.pk, { ...legacy }],
    [mutation.pk, { ...mutation }],
  ])
  const project = (row: Record<string, unknown> | undefined) =>
    row
      ? Object.fromEntries(
          ['pk', 'email', 'age', 'notes'].map((key) => [key, row[key]]),
        )
      : null
  return async (method: string, args: unknown[]) => {
    const [value] = args
    if (method === 'get') return rows.get(String(value)) ?? null
    if (method === 'getPostgres') return project(pg.get(String(value)))
    if (method === 'put') {
      if (value === null || typeof value !== 'object')
        throw Error('Expected customer')
      const customer: Record<string, unknown> = Object.fromEntries(
        Object.entries(value),
      )
      rows.set(String(customer.pk), {
        ...customer,
        emailLower: normalizeSources
          ? String(customer.emailLower).toLowerCase()
          : customer.emailLower,
      })
      return
    }
    if (method === 'setActive') {
      rows.set(String(value), { ...rows.get(String(value)), active: args[1] })
      return
    }
    if (method === 'copyToPostgres') {
      if (!copiesAreNoops) pg.set(String(value), { ...rows.get(String(value)) })
      return
    }
    if (method === 'copyToDynamo') {
      if (!copiesAreNoops)
        rows.set(String(value), {
          ...rows.get(String(value)),
          ...pg.get(String(value)),
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
    const source = method.startsWith('findPostgres') ? pg : rows
    return [...source.values()]
      .filter((row) =>
        method === 'findEmailLower'
          ? String(row.emailLower).toLowerCase() === String(value).toLowerCase()
          : row[fields[method]] === value,
      )
      .map((row) => (method.startsWith('findPostgres') ? project(row) : row))
  }
}

async function runApp(call: import('../run/behaviour.mjs').AppCall) {
  return run({
    id: 'regression',
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

test('D1 Run accepts fresh writes preserving source casing with normalized equality terms', async () => {
  const report = await runApp(appChannel())
  const check = report.evidence.find(
    (record) => record.checkId === 'behaviour.fresh-write',
  )
  expect(check?.payload).toEqual({ id: 'behaviour.fresh-write', passed: true })
  expect(report.outcome).toBe('pass')
})

test('F6 accepts a migrated app that lowercases only new emailLower plaintext', async () => {
  const checks = await (
    await behaviour(appChannel({ normalizeSources: true }))
  ).mutate()
  expect(checks.find((check) => check.id === 'behaviour.fresh-write')).toEqual({
    id: 'behaviour.fresh-write',
    passed: true,
  })
})

test('F6 still rejects changes to other fields on a fresh record', async () => {
  const channel = appChannel({ normalizeSources: true })
  const checks = await (
    await behaviour(async (method, args) => {
      const actual = await channel(method, args)
      return method === 'get' &&
        args[0] === fresh.pk &&
        actual &&
        typeof actual === 'object'
        ? { ...actual, email: 'unexpected@example.com' }
        : actual
    })
  ).mutate()
  expect(
    checks.find((check) => check.id === 'behaviour.fresh-write')?.passed,
  ).toBe(false)
})

test('D5 Run rejects copy methods that do nothing against seeded Mutation Data', async () => {
  const report = await runApp(appChannel({ copiesAreNoops: true }))
  expect(
    report.evidence.find(
      (record) => record.checkId === 'behaviour.copy-postgres',
    )?.payload,
  ).toMatchObject({ passed: false })
  expect(
    report.evidence.find((record) => record.checkId === 'behaviour.copy-dynamo')
      ?.payload,
  ).toMatchObject({ passed: false })
  expect(report.outcome).toBe('behaviour')
})
