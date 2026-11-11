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
        observed.snapshot(options.actor)
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
