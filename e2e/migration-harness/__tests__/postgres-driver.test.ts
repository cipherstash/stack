import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test, vi } from 'vitest'
import { postgresLegacy } from '../run/postgres-behaviour.mjs'
import { createRealDriver } from '../run/real-driver.mjs'

const observed = vi.hoisted(() => ({ provision: vi.fn(), snapshot: vi.fn() }))
vi.mock('../run/stack-source.mjs', () => ({
  resolveStack: async () => ({
    version: '1.2.1',
    install: '@cipherstash/stack@1.2.1',
    ffiRange: '^0.33.0',
  }),
}))
vi.mock('../run/real-stores.mjs', () => ({
  disposeStores: async () => {},
  createStoreSet: async (options: { actor: string }) => {
    observed.provision(options)
    return {
      env: { DATABASE_URL: `postgres://${options.actor}@127.0.0.1/db` },
      forwards: [],
      verify: async () => ({}),
      postgresSnapshot: async () => {
        // A test may return a whole snapshot to replace the Legacy baseline.
        const replacement = observed.snapshot(options.actor)
        if (replacement && typeof replacement === 'object') return replacement
        return {
          columns: {
            email: 'eql_v2_encrypted',
            age: 'eql_v2_encrypted',
            notes: 'eql_v2_encrypted',
          },
          indexes: [],
          rows: postgresLegacy.map((row) => ({
            pk: row.pk,
            ...Object.fromEntries(
              ['email', 'age', 'notes'].map((column) => [
                column,
                {
                  v: 2,
                  k: 'ct',
                  i: { t: 'customers', c: column },
                  c: 'ciphertext',
                  ...(column === 'notes' ? {} : { hm: 'term' }),
                },
              ]),
            ),
          })),
        }
      },
    }
  },
}))
test('Postgres driver seeds both independent v2 Store Sets and snapshots only Oracle data', async () => {
  observed.provision.mockClear()
  observed.snapshot.mockClear()
  const output = await mkdtemp(resolve(tmpdir(), 'mh-postgres-driver-'))
  const writes: Array<{
    actor: string
    pk: unknown
    database: string | undefined
  }> = []
  const driver = createRealDriver({
    id: 'postgres-unit',
    root: fileURLToPath(new URL('../../..', import.meta.url)),
    output,
    command: '',
    credentials: {},
    manifest: {
      stack: '1.2.1',
      guideHash: null,
      procedure: 'postgres-v2-to-v3',
    },
    isolation: {
      prove: async () => ({
        verified: true,
        backend: 'test',
        policies: {
          filesystem: 'test',
          network: 'test',
          migratorEnvironment: { id: 'test', storeSet: 'migrator' },
          appHost: { id: 'test', storeSet: 'oracle' },
        },
      }),
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
      stop: async () => {},
      openAppHost: async ({ actor = 'app-host', env }) => ({
        call: async (method: string, args: unknown[] = []) => {
          if (method === 'put') {
            writes.push({
              actor,
              pk: Object(args[0]).pk,
              database: env?.DATABASE_URL,
            })
            return null
          }
          if (method === 'get')
            return postgresLegacy.find((row) => row.pk === args[0])
          if (method === 'findEmail')
            return postgresLegacy.filter((row) => row.email === args[0])
          if (method === 'findAge')
            return postgresLegacy.filter((row) => row.age === args[0])
          throw Error(`Unexpected method ${method}`)
        },
        close: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
      }),
    },
  })
  try {
    await driver.provision()
    await driver.initializeLegacyData()
    await driver.snapshot()
    expect(
      observed.provision.mock.calls.map(([options]) => [
        options.actor,
        options.postgresV2,
      ]),
    ).toEqual([
      ['migrator', true],
      ['oracle', true],
    ])
    expect(writes).toHaveLength(6)
    expect(new Set(writes.map((write) => write.database)).size).toBe(2)
    expect(observed.snapshot).toHaveBeenCalledExactlyOnceWith('oracle')
    for (const [code, infrastructure] of [
      ['42P01', false],
      ['42703', false],
      ['ECONNRESET', true],
      ['08006', true],
    ] as const) {
      await driver.installAppHost()
      observed.snapshot.mockImplementationOnce(() => {
        throw Object.assign(Error('Snapshot read failed'), { code })
      })
      await expect(driver.behaviour()).rejects.toMatchObject({
        message: 'PostgreSQL Oracle snapshot failed',
        infrastructure,
      })
    }
  } finally {
    await driver.close()
    await rm(output, { recursive: true, force: true })
  }
})

test('Postgres driver inspects fresh stored envelopes after the application write', async () => {
  observed.snapshot.mockClear()
  const events: string[] = []
  observed.snapshot.mockImplementation(() => events.push('snapshot'))
  const output = await mkdtemp(resolve(tmpdir(), 'mh-postgres-fresh-'))
  let fresh: unknown = null
  const driver = createRealDriver({
    id: 'postgres-fresh',
    root: fileURLToPath(new URL('../../..', import.meta.url)),
    output,
    command: '',
    credentials: {},
    manifest: {
      stack: '1.2.1',
      guideHash: null,
      procedure: 'postgres-v2-to-v3',
    },
    isolation: {
      prove: async () => ({
        verified: true,
        backend: 'test',
        policies: {
          filesystem: 'test',
          network: 'test',
          migratorEnvironment: { id: 'test', storeSet: 'migrator' },
          appHost: { id: 'test', storeSet: 'oracle' },
        },
      }),
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
      stop: async () => {},
      openAppHost: async () => ({
        call: async (method, args = []) => {
          events.push(method)
          if (method === 'put') {
            fresh = args[0]
            return null
          }
          if (method === 'get')
            return args[0] === 'new'
              ? fresh
              : postgresLegacy.find((row) => row.pk === args[0])
          return []
        },
        close: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
      }),
    },
  })
  try {
    await driver.provision()
    await driver.snapshot()
    await driver.installAppHost()
    const checks = await driver.behaviour()
    expect(fresh).not.toBeNull()
    expect(
      events.slice(events.indexOf('put'), events.indexOf('put') + 3),
    ).toEqual(['put', 'snapshot', 'get'])
    // Baseline, before and after the migrate(env) rerun, fresh write, final.
    expect(observed.snapshot).toHaveBeenCalledTimes(5)
    expect(checks).toContainEqual(
      expect.objectContaining({
        id: 'migration.postgres-fresh-v3-storage',
        passed: false,
      }),
    )
  } finally {
    observed.snapshot.mockReset()
    await driver.close()
    await rm(output, { recursive: true, force: true })
  }
})

type Row = Record<string, unknown>
function legacySnapshot() {
  return {
    columns: {
      email: 'eql_v2_encrypted',
      age: 'eql_v2_encrypted',
      notes: 'eql_v2_encrypted',
    },
    indexes: [] as Row[],
    rows: postgresLegacy.map((row) => ({
      pk: row.pk,
      ...Object.fromEntries(
        ['email', 'age', 'notes'].map((column) => [
          column,
          {
            v: 2,
            k: 'ct',
            i: { t: 'customers', c: column },
            c: `${row.pk}-${column}`,
            ...(column === 'notes' ? {} : { hm: `${row.pk}-${column}-term` }),
          },
        ]),
      ),
    })) as Row[],
  }
}
function convertedSnapshot() {
  const source = legacySnapshot()
  const target = (value: unknown, column: string) => {
    const { c, hm } = Object(value)
    return {
      v: 3,
      i: { t: 'customers', c: column },
      c,
      ...(column === 'notes' ? {} : { hm }),
    }
  }
  return {
    columns: {
      ...source.columns,
      email_v3: 'eql_v3_text_eq',
      age_v3: 'eql_v3_integer_eq',
      notes_v3: 'eql_v3_text',
    },
    indexes: ['email', 'age'].map((column) => ({
      expression: `eql_v3.eq_term(${column}_v3)`,
      valid: true,
      ready: true,
      partial: false,
      method: 'btree',
    })),
    rows: source.rows.map((row) => ({
      ...row,
      email_v3: target(row.email, 'email'),
      age_v3: target(row.age, 'age'),
      notes_v3: target(row.notes, 'notes'),
    })),
  }
}
function withFresh(snapshot: ReturnType<typeof convertedSnapshot>) {
  const fresh = {
    pk: 'new',
    email: null,
    age: null,
    notes: null,
    email_v3: { v: 3, i: { t: 'customers', c: 'email' }, c: 'n', hm: 'h' },
    age_v3: { v: 3, i: { t: 'customers', c: 'age' }, c: 'n', hm: 'h' },
    notes_v3: { v: 3, i: { t: 'customers', c: 'notes' }, c: 'n' },
  }
  return { ...snapshot, rows: [...snapshot.rows, fresh] }
}
/** Runs one PostgreSQL behaviour phase. `snapshots` is served in order after
 * the Legacy baseline: after the first migrate(env), after the rerun, after the
 * read-only checks, and after the fresh write. */
async function behaviourWith(
  snapshots: unknown[],
  exec: (argv: string[], count: number) => Row = () => ({}),
) {
  observed.snapshot.mockReset()
  const queue = [legacySnapshot(), ...snapshots]
  observed.snapshot.mockImplementation(() => queue.shift())
  const output = await mkdtemp(resolve(tmpdir(), 'mh-postgres-order-'))
  let fresh: unknown = null
  let execs = 0
  const driver = createRealDriver({
    id: 'postgres-order',
    root: fileURLToPath(new URL('../../..', import.meta.url)),
    output,
    command: '',
    credentials: {},
    manifest: {
      stack: '1.2.1',
      guideHash: null,
      procedure: 'postgres-v2-to-v3',
    },
    isolation: {
      prove: async () => ({
        verified: true,
        backend: 'test',
        policies: {
          filesystem: 'test',
          network: 'test',
          migratorEnvironment: { id: 'test', storeSet: 'migrator' },
          appHost: { id: 'test', storeSet: 'oracle' },
        },
      }),
      exec: async ({ command }) => ({
        exitCode: 0,
        stdout: '',
        stderr: '',
        ...exec(command, ++execs),
      }),
      stop: async () => {},
      openAppHost: async () => ({
        call: async (method: string, args: unknown[] = []) => {
          if (method === 'put') {
            fresh = args[0]
            return null
          }
          if (method === 'get')
            return args[0] === 'new'
              ? fresh
              : (postgresLegacy.find((row) => row.pk === args[0]) ?? null)
          if (method === 'findEmail')
            return [...postgresLegacy, ...(fresh ? [fresh] : [])].filter(
              (row) => Object(row).email === args[0],
            )
          if (method === 'findAge')
            return [...postgresLegacy, ...(fresh ? [fresh] : [])].filter(
              (row) => Object(row).age === args[0],
            )
          throw Error(`Unexpected method ${method}`)
        },
        close: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
      }),
    },
  })
  try {
    await driver.provision()
    await driver.snapshot()
    await driver.installAppHost()
    return await driver.behaviour()
  } finally {
    observed.snapshot.mockReset()
    await driver.close()
    await rm(output, { recursive: true, force: true })
  }
}

test('Postgres driver accepts a conversion done by migrate(env) and a clean fresh write', async () => {
  const converted = convertedSnapshot()
  const checks = await behaviourWith([
    converted,
    converted,
    converted,
    withFresh(converted),
  ])
  const failed = checks
    .filter((check) => !check.passed)
    .map((check) => check.id)
  for (const id of [
    'behaviour.postgres-row-retention',
    'no-rewrite.postgres-retained-bytes',
    'migration.postgres-v3-columns',
    'migration.postgres-indexes',
    'migration.postgres-fresh-v3-storage',
    'migration.postgres-migrate',
    'migration.postgres-migrate-rerun',
    'behaviour.postgres-fresh-write',
    'behaviour.postgres-fresh-lookups',
  ])
    expect(failed).not.toContain(id)
})

test('Postgres driver fails a conversion that only happens when the application starts', async () => {
  // An empty migrate(env) leaves v2 data; createApp then converts it before
  // the lookups, so only the pre-application snapshot shows the gap.
  const converted = convertedSnapshot()
  const checks = await behaviourWith([
    legacySnapshot(),
    legacySnapshot(),
    converted,
    withFresh(converted),
  ])
  for (const id of [
    'migration.postgres-v3-columns',
    'migration.postgres-indexes',
  ])
    expect(checks).toContainEqual(
      expect.objectContaining({
        id,
        passed: false,
        cause: expect.stringContaining('before the application started'),
      }),
    )
})

test('Postgres driver fails a migrate(env) rerun that timed out', async () => {
  const converted = convertedSnapshot()
  let migrations = 0
  const checks = await behaviourWith(
    [converted, converted, converted, withFresh(converted)],
    (argv) =>
      argv.includes('migrate') && ++migrations === 2
        ? { exitCode: 124, timedOut: true }
        : {},
  )
  expect(checks).toContainEqual(
    expect.objectContaining({
      id: 'migration.postgres-migrate-rerun',
      passed: false,
      cause: expect.stringContaining('timed out'),
    }),
  )
})

test('Postgres driver fails a fresh write that deletes a pre-existing row', async () => {
  const converted = convertedSnapshot()
  const afterWrite = withFresh(converted)
  afterWrite.rows = afterWrite.rows.filter((row) => Object(row).pk !== 'grace')
  const checks = await behaviourWith([
    converted,
    converted,
    converted,
    afterWrite,
  ])
  expect(checks).toContainEqual(
    expect.objectContaining({
      id: 'migration.postgres-fresh-v3-storage',
      passed: false,
    }),
  )
})
