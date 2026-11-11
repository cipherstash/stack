import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const spawnSyncMock = vi.hoisted(() => vi.fn())
vi.mock('node:child_process', () => ({ spawnSync: spawnSyncMock }))
vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: () => 'npm',
  runnerArgv: () => ({ command: 'npx', prefixArgs: [] }),
}))

import { scaffoldDrizzleMigration } from '../drizzle-helper.js'

/**
 * drizzle.config.ts's `out` owns where drizzle-kit writes. The scaffold must
 * follow the path drizzle-kit reports, never the --migrations-dir it scans as
 * a fallback (CIP-5162).
 */
// What drizzle-kit's `generate --custom` actually writes.
const PLACEHOLDER = '-- Custom SQL migration file, put your code below! --\n'

describe('scaffoldDrizzleMigration', () => {
  let root: string
  let cwd: string
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'stash-scaffold-'))
    cwd = process.cwd()
    process.chdir(root)
    spawnSyncMock.mockReset()
  })
  afterEach(() => {
    process.chdir(cwd)
    rmSync(root, { recursive: true, force: true })
  })

  function drizzleKitWrites(relPath: string) {
    spawnSyncMock.mockImplementation(() => {
      mkdirSync(join(relPath, '..'), { recursive: true })
      writeFileSync(relPath, PLACEHOLDER)
      return {
        status: 0,
        stdout: `[✓] Your SQL migration file ➜ ${relPath} 🚀\n`,
        stderr: '',
      }
    })
  }

  it('writes to the directory drizzle-kit reports, not the scanned one', async () => {
    mkdirSync('drizzle')
    writeFileSync(
      'drizzle/0000_drop_users_email.sql',
      'ALTER TABLE t DROP COLUMN c;',
    )
    drizzleKitWrites('src/db/migrations/0003_drop_users_email.sql')

    const result = await scaffoldDrizzleMigration({
      name: 'drop_users_email',
      outDir: 'drizzle',
      sql: 'ALTER TABLE users DROP COLUMN email;',
    })

    expect(result.path).toBe(
      join(root, 'src/db/migrations/0003_drop_users_email.sql'),
    )
    expect(readFileSync(result.path, 'utf-8')).toContain('DROP COLUMN email')
    expect(readFileSync('drizzle/0000_drop_users_email.sql', 'utf-8')).toBe(
      'ALTER TABLE t DROP COLUMN c;',
    )
    expect(result.dir).not.toBe(result.requestedDir)
  })

  it('does not require the fallback directory to exist when the path is reported', async () => {
    drizzleKitWrites('db/0000_drop_a.sql')
    const result = await scaffoldDrizzleMigration({
      name: 'drop_a',
      outDir: 'drizzle',
      sql: 'SELECT 1;',
    })
    expect(existsSync(result.path)).toBe(true)
  })

  it('falls back to the scan when the banner is unrecognised, taking only a new exact-suffix file', async () => {
    mkdirSync('drizzle')
    writeFileSync('drizzle/0000_drop_a.sql', 'ALTER TABLE t DROP COLUMN c;')
    spawnSyncMock.mockImplementation(() => {
      writeFileSync('drizzle/0001_drop_a.sql', PLACEHOLDER)
      writeFileSync('drizzle/0002_drop_a_backup.sql', '')
      return { status: 0, stdout: 'done', stderr: '' }
    })
    const result = await scaffoldDrizzleMigration({
      name: 'drop_a',
      outDir: 'drizzle',
      sql: 'SELECT 1;',
    })
    expect(result.path).toBe(join(root, 'drizzle/0001_drop_a.sql'))
    expect(readFileSync('drizzle/0000_drop_a.sql', 'utf-8')).toBe(
      'ALTER TABLE t DROP COLUMN c;',
    )
  })

  it('refuses to overwrite a pre-existing same-stem file when nothing new appeared', async () => {
    mkdirSync('drizzle')
    writeFileSync('drizzle/0000_drop_a.sql', 'ALTER TABLE t DROP COLUMN c;')
    spawnSyncMock.mockReturnValue({ status: 0, stdout: 'done', stderr: '' })
    await expect(
      scaffoldDrizzleMigration({
        name: 'drop_a',
        outDir: 'drizzle',
        sql: 'SELECT 1;',
      }),
    ).rejects.toThrow(/Refusing to overwrite/)
    expect(readFileSync('drizzle/0000_drop_a.sql', 'utf-8')).toBe(
      'ALTER TABLE t DROP COLUMN c;',
    )
  })

  it('follows a reported path even when the banner is colourised', async () => {
    mkdirSync('db')
    spawnSyncMock.mockImplementation(() => {
      writeFileSync('db/0000_drop_a.sql', PLACEHOLDER)
      return {
        status: 0,
        stdout:
          '[✓] Your SQL migration file \u001b[2m➜\u001b[0m \u001b[1mdb/0000_drop_a.sql\u001b[0m 🚀',
        stderr: '',
      }
    })
    const result = await scaffoldDrizzleMigration({
      name: 'drop_a',
      outDir: 'drizzle',
      sql: 'SELECT 1;',
    })
    expect(result.path).toBe(join(root, 'db/0000_drop_a.sql'))
  })

  it('refuses to overwrite a reported file that already has content', async () => {
    mkdirSync('db')
    writeFileSync('db/0000_old.sql', 'ALTER TABLE t DROP COLUMN c;')
    spawnSyncMock.mockReturnValue({
      status: 0,
      stdout: '➜ db/0000_old.sql',
      stderr: '',
    })
    await expect(
      scaffoldDrizzleMigration({
        name: 'x',
        outDir: 'drizzle',
        sql: 'SELECT 1;',
      }),
    ).rejects.toThrow(/not a drizzle-kit scaffold/)
    expect(readFileSync('db/0000_old.sql', 'utf-8')).toBe(
      'ALTER TABLE t DROP COLUMN c;',
    )
  })

  it('surfaces drizzle-kit stdout and stderr on failure', async () => {
    spawnSyncMock.mockReturnValue({
      status: 1,
      stdout: 'config error',
      stderr: 'boom',
    })
    await expect(
      scaffoldDrizzleMigration({ name: 'x', outDir: 'drizzle', sql: '' }),
    ).rejects.toThrow(/config error\nboom/)
  })
})
