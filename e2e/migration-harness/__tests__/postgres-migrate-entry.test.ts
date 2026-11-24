import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { beforeEach, expect, test, vi } from 'vitest'
import { postgresLegacy } from '../run/postgres-behaviour.mjs'
import { createRealDriver } from '../run/real-driver.mjs'

// The PostgreSQL guide runs its conversion as a one-off step during a
// write-maintenance window, not at application startup. The Oracle must run the
// fixture's separate conversion entry point (`src/migrate.mjs`, `migrate(env)`)
// against its fresh database once before the App Host starts createApp, then a
// second time to check that a rerun is safe, and report that check.

const oracle = vi.hoisted(() => ({
  /** migrate(env) invocations so far in the Oracle App Host. */
  migrations: 0,
  /** Exit code of each migrate(env) invocation, by 1-based ordinal. */
  exit: (_ordinal: number): number => 0,
  /** When true, the second migrate(env) deletes a Legacy Data row. */
  changeOnRerun: false,
}))
vi.mock('../run/stack-source.mjs', () => ({
  resolveStack: async () => ({
    version: '1.2.1',
    install: '@cipherstash/stack@1.2.1',
    ffiRange: '^0.33.0',
  }),
}))
vi.mock('../run/real-stores.mjs', () => ({
  disposeStores: async () => {},
  createStoreSet: async (options: { actor: string }) => ({
    env: { DATABASE_URL: `postgres://${options.actor}@127.0.0.1/db` },
    forwards: [],
    verify: async () => ({}),
    postgresSnapshot: async () => ({
      columns: {
        email: 'eql_v2_encrypted',
        age: 'eql_v2_encrypted',
        notes: 'eql_v2_encrypted',
      },
      indexes: [],
      rows: postgresLegacy
        .filter(
          (row) =>
            !(oracle.changeOnRerun && oracle.migrations >= 2) ||
            row.pk !== 'alan',
        )
        .map((row) => ({
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
    }),
  }),
}))

beforeEach(() => {
  oracle.migrations = 0
  oracle.exit = () => 0
  oracle.changeOnRerun = false
})

const here = fileURLToPath(new URL('..', import.meta.url))

/** Describes an isolation request without its environment, workspace or
 * forwards, so only the entry point it runs is matched. */
function entry(options: Record<string, unknown>) {
  const { env: _env, workspace: _w, forwards: _f, ...rest } = options
  return JSON.stringify(rest)
}
const runsMigrate = (description: string) =>
  /migrate(\.mjs|\b)/.test(description)

/** Drives the PostgreSQL Oracle against a scripted isolation host. */
async function runOracle() {
  const output = await mkdtemp(resolve(tmpdir(), 'mh-pg-entry-'))
  const events: Array<{
    kind: 'exec' | 'open'
    migrate: boolean
    actor?: string
  }> = []
  const driver = createRealDriver({
    id: 'postgres-entry',
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
      exec: async (options) => {
        if (options.actor === 'app-host' && options.command[0] !== 'npm') {
          const migrate = runsMigrate(entry({ ...options }))
          events.push({ kind: 'exec', migrate, actor: options.actor })
          if (migrate) {
            oracle.migrations += 1
            return {
              exitCode: oracle.exit(oracle.migrations),
              stdout: '',
              stderr: '',
            }
          }
        }
        return { exitCode: 0, stdout: '', stderr: '' }
      },
      stop: async () => {},
      openAppHost: async (options) => {
        events.push({
          kind: 'open',
          migrate: runsMigrate(entry({ ...options })),
          actor: options.actor,
        })
        return {
          call: async (method: string, args: unknown[] = []) => {
            if (method === 'get')
              return postgresLegacy.find((row) => row.pk === args[0]) ?? null
            if (method === 'findEmail')
              return postgresLegacy.filter((row) => row.email === args[0])
            if (method === 'findAge')
              return postgresLegacy.filter((row) => row.age === args[0])
            return null
          },
          close: async () => ({ exitCode: 0, stdout: '', stderr: '' }),
        }
      },
    },
  })
  try {
    await driver.provision()
    await driver.snapshot()
    await driver.installAppHost()
    const checks: Array<{ id: string; passed: boolean; cause?: string }> =
      await driver.behaviour()
    return { checks, events }
  } finally {
    await driver.close()
    await rm(output, { recursive: true, force: true })
  }
}
const find = (checks: Array<{ id: string }>, id: string) =>
  checks.find((check) => check.id === id)

test('Oracle runs migrate(env) once before createApp, then reruns it to check rerun safety', async () => {
  const { checks, events } = await runOracle()
  const migrations = events.filter((event) => event.migrate)
  const appStart = events.findIndex(
    (event) => event.kind === 'open' && !event.migrate,
  )
  expect(
    migrations,
    'Oracle must invoke the fixture migrate(env) entry point twice: conversion, then rerun check',
  ).toHaveLength(2)
  for (const migration of migrations)
    expect(migration.actor, 'migrate(env) runs isolated in App Host').toBe(
      'app-host',
    )
  expect(appStart, 'App Host running createApp must start').toBeGreaterThan(-1)
  for (const migration of migrations)
    expect(
      events.indexOf(migration),
      'both migrate(env) invocations must precede createApp',
    ).toBeLessThan(appStart)
  expect(
    checks.map((check) => check.id),
    'Oracle must report whether rerunning migrate(env) was safe',
  ).toContainEqual(expect.stringMatching(/rerun/))
  expect(find(checks, 'migration.postgres-migrate')).toMatchObject({
    passed: true,
  })
  expect(find(checks, 'migration.postgres-migrate-rerun')).toMatchObject({
    passed: true,
  })
})

test('a rerun that refuses without changing data is safe', async () => {
  oracle.exit = (ordinal) => (ordinal === 2 ? 1 : 0)
  const { checks } = await runOracle()
  expect(find(checks, 'migration.postgres-migrate-rerun')).toMatchObject({
    passed: true,
  })
})

test('a rerun that changes data fails the rerun check, even when it exits zero', async () => {
  oracle.changeOnRerun = true
  const { checks } = await runOracle()
  expect(find(checks, 'migration.postgres-migrate')).toMatchObject({
    passed: true,
  })
  expect(find(checks, 'migration.postgres-migrate-rerun')).toMatchObject({
    passed: false,
    cause: expect.stringContaining('changed stored data'),
  })
})

test('a failed first migrate(env) is a failed Oracle check, not an infrastructure error', async () => {
  oracle.exit = () => 1
  const { checks, events } = await runOracle()
  expect(
    events.filter((event) => event.migrate),
    'no rerun after a failed conversion',
  ).toHaveLength(1)
  expect(find(checks, 'migration.postgres-migrate')).toMatchObject({
    passed: false,
    cause: 'migrate(env) exited 1',
  })
  expect(find(checks, 'migration.postgres-migrate-rerun')).toMatchObject({
    passed: false,
  })
})

/** Runs the real App Host entrypoint in a scratch workspace, outside Docker. */
async function appHost(workspace: string, args: string[]) {
  return new Promise<{ code: number | null; stderr: string }>(
    (resolvePromise, reject) => {
      const child = spawn(
        process.execPath,
        [
          fileURLToPath(new URL('../run/app-host.mjs', import.meta.url)),
          ...args,
        ],
        { cwd: workspace, stdio: ['pipe', 'pipe', 'pipe'] },
      )
      let stderr = ''
      child.stderr.on('data', (data) => {
        stderr += data
      })
      child.on('error', reject)
      child.on('close', (code) => resolvePromise({ code, stderr }))
      child.stdin.end()
    },
  )
}

test('App Host migrate mode runs only migrate(env) and reports failure by exit code', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'harness-migrate-'))
  await mkdir(join(workspace, 'src'))
  await writeFile(
    join(workspace, 'src/app.mjs'),
    `export async function createApp() { throw Error('createApp must not run') }`,
  )
  await writeFile(
    join(workspace, 'src/stores.mjs'),
    `export async function createStores() { throw Error('stores must not initialize') }`,
  )
  try {
    await writeFile(
      join(workspace, 'src/migrate.mjs'),
      `import { writeFileSync } from 'node:fs'
export async function migrate(env) { writeFileSync('ran', typeof env === 'object' ? 'env' : 'none') }`,
    )
    expect((await appHost(workspace, ['migrate'])).code).toBe(0)
    expect(await readFile(join(workspace, 'ran'), 'utf8')).toBe('env')
    await writeFile(
      join(workspace, 'src/migrate.mjs'),
      `export async function migrate() { throw Error('refusing to convert twice') }`,
    )
    const refused = await appHost(workspace, ['migrate'])
    expect(refused.code).not.toBe(0)
    expect(refused.stderr).toContain('refusing to convert twice')
  } finally {
    await rm(workspace, { recursive: true, force: true })
  }
})

test('PostgreSQL fixture and reference put the conversion in src/migrate.mjs, not createApp', async () => {
  const fixtureMigrate = resolve(here, 'postgres-fixture/src/migrate.mjs')
  const referenceMigrate = resolve(here, 'postgres-reference/src/migrate.mjs')
  expect(existsSync(fixtureMigrate), 'unmigrated fixture stub').toBe(true)
  expect(existsSync(referenceMigrate), 'reference conversion').toBe(true)
  expect(await readFile(fixtureMigrate, 'utf8')).toMatch(
    /export async function migrate\(/,
  )
  expect(await readFile(referenceMigrate, 'utf8')).toMatch(
    /export async function migrate\(/,
  )
  const referenceApp = await readFile(
    resolve(here, 'postgres-reference/src/app.mjs'),
    'utf8',
  )
  expect(
    referenceApp,
    'reference createApp must not alter the schema',
  ).not.toMatch(/ALTER TABLE|CREATE INDEX|LOCK TABLE/)
  const readme = await readFile(
    resolve(here, 'postgres-fixture/README.md'),
    'utf8',
  )
  expect(readme).toContain('src/migrate.mjs')
  expect(readme).not.toContain('through application startup')
})
