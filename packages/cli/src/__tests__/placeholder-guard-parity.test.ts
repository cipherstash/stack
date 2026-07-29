import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { PLACEHOLDER_TABLE_NAME } from '@/config/index.js'

/**
 * `stash db validate` reaches the user's encryption client through
 * `loadEncryptConfig`; `stash encrypt backfill` reaches the same file through
 * `loadEncryptionContext`. Both must refuse the un-replaced `stash init`
 * scaffold, and — because it is one file and one mistake — both must say the
 * same thing about it.
 *
 * The two guards were hand-copied rather than shared, so nothing held them
 * together: the message text could drift on one side, and the nullish-config
 * case HAD already drifted (#787 review follow-up). This pins the agreement at
 * both public seams rather than testing the shared helper directly, which
 * would prove only that a function calls itself.
 *
 * Real jiti, real temp project, real filesystem — the only doubles are
 * `process.exit` and `console.error`.
 */
describe('the un-replaced init scaffold, refused identically by both loaders', () => {
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

  /** The duck-typed table shape `loadEncryptionContext` harvests. */
  const table = (name: string) =>
    `{ tableName: '${name}', build: () => ({ tableName: '${name}', columns: {} }) }`

  /** Run one loader, capturing whatever it wrote to stderr before exiting. */
  const captureRefusal = async (load: () => Promise<unknown>) => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const exit = vi.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit')
    })
    let exited = false
    try {
      await load()
    } catch (err) {
      exited = (err as Error).message === 'process.exit'
      if (!exited) throw err
    }
    const message = error.mock.calls.flat().join('\n')
    error.mockRestore()
    exit.mockRestore()
    return { exited, message }
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-guard-parity-'))
    originalCwd = process.cwd
  })

  afterEach(() => {
    process.cwd = originalCwd
    vi.restoreAllMocks()
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true })
    }
  })

  it('gives db validate and encrypt backfill the same refusal for the same file', async () => {
    writeProject(
      `export const encryptionClient = {
         getEncryptConfig: () => ({ tables: { '${PLACEHOLDER_TABLE_NAME}': {} } }),
       }
       export const placeholderTable = ${table(PLACEHOLDER_TABLE_NAME)}`,
    )

    const { loadEncryptConfig } = await import('@/config/index.js')
    const dbValidate = await captureRefusal(() =>
      loadEncryptConfig('./client.ts'),
    )

    const { loadEncryptionContext } = await import(
      '../commands/encrypt/context.js'
    )
    const backfill = await captureRefusal(() => loadEncryptionContext())

    expect(dbValidate.exited).toBe(true)
    expect(backfill.exited).toBe(true)
    expect(dbValidate.message).toContain('still contains the placeholder table')
    expect(backfill.message).toEqual(dbValidate.message)
  })

  it('names the cause, not the symptom, when the client has no encrypt config', async () => {
    // A client whose `getEncryptConfig()` returns nothing is the same class of
    // unfinished setup. `db validate` already named it; backfill used to
    // fall through to `requireTable`'s `Table "users" was not found …
    // Available: (none)` — the symptom-not-cause message this guard exists to
    // replace (#787 review follow-up).
    writeProject(
      `export const encryptionClient = { getEncryptConfig: () => undefined }
       export const users = ${table('users')}`,
    )

    const { loadEncryptConfig } = await import('@/config/index.js')
    const dbValidate = await captureRefusal(() =>
      loadEncryptConfig('./client.ts'),
    )

    const { loadEncryptionContext } = await import(
      '../commands/encrypt/context.js'
    )
    const backfill = await captureRefusal(() => loadEncryptionContext())

    expect(dbValidate.exited).toBe(true)
    expect(backfill.exited).toBe(true)
    expect(backfill.message).toContain('no initialized encrypt config')
    expect(backfill.message).not.toContain('was not found')
  })
})
