import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { loadEncryptSchemas } from '@/config/index.js'

/**
 * `loadEncryptSchemas` reads a client out of the USER's `node_modules` through
 * jiti. Nothing about that object is checked by TypeScript at runtime: the
 * project may be on an older `@cipherstash/stack`, on an adapter-built client,
 * or on a hand-rolled stub. So the loader duck-types `getSchemas()` and then
 * verifies the shape of what it hands back.
 *
 * These tests drive that guard through the public seam, with a real temp
 * project and real jiti — the client bodies below are plain object literals so
 * no package resolution is involved.
 */
describe('loadEncryptSchemas against an untrusted client', () => {
  let tmpDir: string
  let originalCwd: () => string

  /** A minimal encrypt config that clears `requireUsableEncryptConfig`. */
  const CONFIG = `{
    v: 1,
    tables: { users: { email: { cast_as: 'string', indexes: {} } } },
  }`

  const writeProject = (clientBody: string) => {
    fs.writeFileSync(
      path.join(tmpDir, 'stash.config.ts'),
      `export default {
         databaseUrl: 'postgresql://u:p@127.0.0.1:5432/db',
         client: './client.ts',
       }`,
    )
    fs.writeFileSync(path.join(tmpDir, 'client.ts'), clientBody)
    process.cwd = () => tmpDir
  }

  /** A client exporting `getEncryptConfig` plus whatever `getSchemas` returns. */
  const clientReturning = (getSchemasBody: string) =>
    `export const encryptionClient = {
       getEncryptConfig: () => (${CONFIG}),
       getSchemas: () => (${getSchemasBody}),
     }`

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-load-schemas-'))
    originalCwd = process.cwd
  })

  afterEach(() => {
    process.cwd = originalCwd
    vi.restoreAllMocks()
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('accepts a well-formed table', async () => {
    writeProject(
      clientReturning(`[{
        tableName: 'users',
        columnBuilders: {
          email: {
            getName: () => 'email',
            getEqlType: () => 'public.eql_v3_text_eq',
            isQueryable: () => true,
            build: () => ({ cast_as: 'string', indexes: { unique: {} } }),
          },
        },
      }]`),
    )

    const { schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toHaveLength(1)
    expect(schemas?.[0].tableName).toBe('users')
  })

  it('degrades to config-only when the client predates getSchemas()', async () => {
    writeProject(
      `export const encryptionClient = { getEncryptConfig: () => (${CONFIG}) }`,
    )

    const { config, schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
    expect(config.tables.users).toBeDefined()
  })

  /**
   * `typeof null === 'object'`, so a `columnBuilders: null` slipped through the
   * shape check and reached `Object.values(null)` in `collectDeclaredColumns`,
   * which throws. The guard exists precisely so a malformed client degrades
   * instead of crashing the command with a stack trace.
   */
  it('rejects a table whose columnBuilders is null rather than crashing later', async () => {
    writeProject(
      clientReturning(`[{ tableName: 'users', columnBuilders: null }]`),
    )

    const { schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
  })

  /**
   * The shape check has to cover the builders too: every one of `getName`,
   * `getEqlType`, `isQueryable` and `build` is called while collecting columns,
   * so a table carrying inert objects is as unusable as a null map.
   */
  it('rejects a table whose builders do not implement the column API', async () => {
    writeProject(
      clientReturning(`[{
        tableName: 'users',
        columnBuilders: { email: { getName: () => 'email' } },
      }]`),
    )

    const { schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
  })

  /**
   * A `tableName` that isn't a string doesn't crash — it propagates as
   * `DeclaredColumn.table === undefined`, which `validateSchemas` then reports
   * as a table missing from the database and exits 1 on. So dropping this arm
   * turns the documented degrade into a hard failure naming a table called
   * "undefined", and nothing else covers it: the well-formed-table case above
   * still passes without it.
   *
   * Two fixtures for that one arm, because they are different inputs: a client
   * can omit `tableName` altogether (an older or hand-rolled stub) or carry a
   * wrong-typed one. Both pass `columnBuilders: {}`, which makes
   * `Object.values({}).every()` vacuously true — so the `tableName` check is
   * the only thing rejecting either one.
   */
  it('rejects a table whose tableName is missing', async () => {
    writeProject(clientReturning(`[{ columnBuilders: {} }]`))

    const { schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
  })

  it('rejects a table whose tableName is not a string', async () => {
    writeProject(clientReturning(`[{ tableName: 42, columnBuilders: {} }]`))

    const { schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
  })

  it('rejects a getSchemas() that does not return an array', async () => {
    writeProject(clientReturning(`{ users: { tableName: 'users' } }`))

    const { schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
  })

  /**
   * The one untrusted behaviour the shape checks structurally cannot cover: a
   * `getSchemas()` that THROWS fails before there is any value to validate. An
   * adapter-built client, a hand-rolled stub, or a getter with a side effect
   * can all do it. Left unguarded the throw escapes `loadEncryptSchemas` and
   * `main.ts` rethrows it as "Fatal error", exiting 1 — the opposite of the
   * degrade contract this function documents.
   */
  it('degrades to config-only when getSchemas() throws', async () => {
    writeProject(
      `export const encryptionClient = {
         getEncryptConfig: () => (${CONFIG}),
         getSchemas: () => {
           throw new Error('adapter client cannot enumerate schemas')
         },
       }`,
    )

    const { config, schemas } = await loadEncryptSchemas('./client.ts')

    expect(schemas).toBeUndefined()
    expect(config.tables.users).toBeDefined()
  })
})
