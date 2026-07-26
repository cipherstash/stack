import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PLACEHOLDER_TABLE_NAME } from '@/config/index.js'

/**
 * `stash encrypt` does not load its client through `loadEncryptConfig`, so the
 * placeholder guard that command group needs lives in `loadEncryptionContext`.
 * Both must refuse the un-replaced scaffold; otherwise `requireTable` reports
 * `Table "users" was not found … Available: __stash_placeholder__`, which names
 * the symptom instead of the cause (#787 review).
 *
 * Runs against the real jiti runtime — the guard reads the tables harvested
 * from an actually-evaluated client module, which is the part worth pinning.
 */
describe('loadEncryptionContext — the un-replaced init scaffold', () => {
  let tmpDir: string
  let originalCwd: () => string

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

  /**
   * The duck-typed shapes `loadEncryptionContext` harvests: any export with a
   * `getEncryptConfig()` method is the client, and any with `tableName` +
   * `build()` is a table. Hand-rolled rather than imported from
   * `@cipherstash/stack` so the test needs no native module.
   */
  const table = (name: string) =>
    `{ tableName: '${name}', build: () => ({ tableName: '${name}', columns: {} }) }`

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-encrypt-ctx-'))
    originalCwd = process.cwd
  })

  afterEach(() => {
    process.cwd = originalCwd
    vi.restoreAllMocks()
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('exits 1 naming the sentinel when it is the only table declared', async () => {
    writeProject(
      `export const encryptionClient = { getEncryptConfig: () => ({}) }
       export const placeholderTable = ${table(PLACEHOLDER_TABLE_NAME)}`,
    )
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })

    const { loadEncryptionContext } = await import('../context.js')
    await expect(loadEncryptionContext()).rejects.toThrow('process.exit')

    const message = error.mock.calls.flat().join('\n')
    expect(message).toContain(PLACEHOLDER_TABLE_NAME)
    // Names the cause, not `requireTable`'s "table not found" symptom.
    expect(message).toContain('still contains the placeholder table')
    expect(message).not.toContain('was not found in the encryption client')
  })

  it('allows the sentinel through once a real table sits alongside it', async () => {
    // Only the SOLE-placeholder case is the un-replaced scaffold. A user who
    // has added real tables must not be blocked by a leftover sentinel export.
    writeProject(
      `export const encryptionClient = { getEncryptConfig: () => ({}) }
       export const placeholderTable = ${table(PLACEHOLDER_TABLE_NAME)}
       export const users = ${table('users')}`,
    )

    const { loadEncryptionContext } = await import('../context.js')
    const ctx = await loadEncryptionContext()

    expect(ctx.tables.has('users')).toBe(true)
  })
})
