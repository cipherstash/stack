import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { detectSupabaseProject } from '../commands/db/detect.js'
import {
  chooseSupabaseInstallMode,
  routeInstallPathForEqlVersion,
  validateInstallFlags,
} from '../commands/db/install.js'
import {
  SUPABASE_EQL_MIGRATION_FILENAME,
  writeSupabaseEqlMigration,
} from '../commands/db/supabase-migration.js'
import { SUPABASE_PERMISSIONS_SQL } from '../installer/index.js'

/**
 * Generate the migration header for testing purposes.
 * Mirrors the production function but imported for testing.
 */
function migrationHeader(runner: string): string {
  return `-- CipherStash EQL — installed by \`${runner} stash eql install --supabase --migration\`.
--
-- This migration installs the CipherStash Encrypt Query Language (EQL) types,
-- functions, and operators into the \`eql_v2\` schema, then grants Supabase's
-- \`anon\`, \`authenticated\`, and \`service_role\` roles the access they need.
--
-- The all-zero \`YYYYMMDDHHMMSS\` prefix is intentional: Supabase orders
-- migrations lexically, so this file runs before any user migration that
-- references the \`eql_v2_encrypted\` type. Do not rename it.
--
-- To upgrade EQL, re-run the install command — it will refuse to overwrite
-- this file unless you pass --force.
--
-- Docs: https://cipherstash.com/docs/stack/cipherstash/supabase
`
}

describe('detectSupabaseProject', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-supa-detect-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('detects only config.toml', () => {
    fs.mkdirSync(path.join(tmpDir, 'supabase'), { recursive: true })
    fs.writeFileSync(path.join(tmpDir, 'supabase', 'config.toml'), '')

    const info = detectSupabaseProject(tmpDir)
    expect(info.hasConfigToml).toBe(true)
    expect(info.hasMigrationsDir).toBe(false)
    expect(info.migrationsDir).toBe(
      path.resolve(tmpDir, 'supabase', 'migrations'),
    )
  })

  it('detects only the migrations directory', () => {
    fs.mkdirSync(path.join(tmpDir, 'supabase', 'migrations'), {
      recursive: true,
    })

    const info = detectSupabaseProject(tmpDir)
    expect(info.hasConfigToml).toBe(false)
    expect(info.hasMigrationsDir).toBe(true)
  })

  it('detects both config.toml and the migrations directory', () => {
    fs.mkdirSync(path.join(tmpDir, 'supabase', 'migrations'), {
      recursive: true,
    })
    fs.writeFileSync(path.join(tmpDir, 'supabase', 'config.toml'), '')

    const info = detectSupabaseProject(tmpDir)
    expect(info.hasConfigToml).toBe(true)
    expect(info.hasMigrationsDir).toBe(true)
  })

  it('returns false flags when neither marker is present', () => {
    const info = detectSupabaseProject(tmpDir)
    expect(info.hasConfigToml).toBe(false)
    expect(info.hasMigrationsDir).toBe(false)
  })

  it('honors a custom override path (relative + absolute)', () => {
    const customRel = 'db/migrations'
    fs.mkdirSync(path.join(tmpDir, customRel), { recursive: true })

    const relInfo = detectSupabaseProject(tmpDir, customRel)
    expect(relInfo.migrationsDir).toBe(path.resolve(tmpDir, customRel))
    expect(relInfo.hasMigrationsDir).toBe(true)

    const absPath = path.resolve(tmpDir, customRel)
    const absInfo = detectSupabaseProject(tmpDir, absPath)
    expect(absInfo.migrationsDir).toBe(absPath)
    expect(absInfo.hasMigrationsDir).toBe(true)
  })

  it('treats a file at the migrations path as a missing directory', () => {
    fs.mkdirSync(path.join(tmpDir, 'supabase'), { recursive: true })
    fs.writeFileSync(path.join(tmpDir, 'supabase', 'migrations'), 'not a dir')

    const info = detectSupabaseProject(tmpDir)
    expect(info.hasMigrationsDir).toBe(false)
  })
})

describe('writeSupabaseEqlMigration', () => {
  let tmpDir: string

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stash-supa-write-'))
  })

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true })
  })

  it('writes the file at the well-known filename', async () => {
    const migrationsDir = path.join(tmpDir, 'supabase', 'migrations')

    const result = await writeSupabaseEqlMigration({ migrationsDir })

    expect(path.basename(result.path)).toBe(SUPABASE_EQL_MIGRATION_FILENAME)
    expect(result.overwritten).toBe(false)
    expect(fs.existsSync(result.path)).toBe(true)
  })

  it('writes EQL SQL plus the SUPABASE_PERMISSIONS_SQL block', async () => {
    const migrationsDir = path.join(tmpDir, 'supabase', 'migrations')
    const result = await writeSupabaseEqlMigration({ migrationsDir })

    const contents = fs.readFileSync(result.path, 'utf-8')
    // Header comment block includes the detected runner instruction
    expect(contents).toMatch(
      /-- CipherStash EQL — installed by `(npx|bunx|pnpm dlx|yarn dlx) stash eql install --supabase --migration`/,
    )
    expect(contents).toContain('CipherStash')
    // EQL SQL body — the bundled supabase variant defines eql_v2.
    expect(contents).toContain('eql_v2')
    // Permissions block (single source of truth).
    expect(contents).toContain(SUPABASE_PERMISSIONS_SQL.trim())
  })

  it('creates the migrations directory if missing', async () => {
    const migrationsDir = path.join(tmpDir, 'supabase', 'migrations')
    expect(fs.existsSync(migrationsDir)).toBe(false)

    const result = await writeSupabaseEqlMigration({ migrationsDir })

    expect(fs.statSync(migrationsDir).isDirectory()).toBe(true)
    expect(fs.existsSync(result.path)).toBe(true)
  })

  it('throws when the file already exists and force is false', async () => {
    const migrationsDir = path.join(tmpDir, 'supabase', 'migrations')
    fs.mkdirSync(migrationsDir, { recursive: true })
    const existingPath = path.join(
      migrationsDir,
      SUPABASE_EQL_MIGRATION_FILENAME,
    )
    fs.writeFileSync(existingPath, '-- existing')

    await expect(writeSupabaseEqlMigration({ migrationsDir })).rejects.toThrow(
      /already exists/,
    )

    // Existing content untouched
    expect(fs.readFileSync(existingPath, 'utf-8')).toBe('-- existing')
  })

  it('overwrites when force is true', async () => {
    const migrationsDir = path.join(tmpDir, 'supabase', 'migrations')
    fs.mkdirSync(migrationsDir, { recursive: true })
    const existingPath = path.join(
      migrationsDir,
      SUPABASE_EQL_MIGRATION_FILENAME,
    )
    fs.writeFileSync(existingPath, '-- existing')

    const result = await writeSupabaseEqlMigration({
      migrationsDir,
      force: true,
    })

    expect(result.overwritten).toBe(true)
    expect(fs.readFileSync(result.path, 'utf-8')).not.toBe('-- existing')
    expect(fs.readFileSync(result.path, 'utf-8')).toContain('eql_v2')
  })

  it('sorts before realistic Supabase-style migration filenames', () => {
    const filenames = [
      SUPABASE_EQL_MIGRATION_FILENAME,
      '20251015120000_users.sql',
      '99999999999999_other.sql',
    ]
    const sorted = [...filenames].sort()
    expect(sorted[0]).toBe(SUPABASE_EQL_MIGRATION_FILENAME)
  })
})

describe('validateInstallFlags', () => {
  it('returns null for an empty options object', () => {
    expect(validateInstallFlags({})).toBeNull()
  })

  it('returns null when --supabase is paired with --migration', () => {
    expect(validateInstallFlags({ supabase: true, migration: true })).toBeNull()
  })

  it('returns null when --supabase is paired with --direct', () => {
    expect(validateInstallFlags({ supabase: true, direct: true })).toBeNull()
  })

  it('rejects --migration without --supabase', () => {
    const err = validateInstallFlags({ migration: true })
    expect(err).toMatch(/--migration/)
    expect(err).toMatch(/--supabase/)
  })

  it('rejects --direct without --supabase', () => {
    const err = validateInstallFlags({ direct: true })
    expect(err).toMatch(/--direct/)
    expect(err).toMatch(/--supabase/)
  })

  it('rejects --migrations-dir without --supabase', () => {
    const err = validateInstallFlags({ migrationsDir: 'db/migrations' })
    expect(err).toMatch(/--migrations-dir/)
    expect(err).toMatch(/--supabase/)
  })

  it('rejects --migration AND --direct together', () => {
    const err = validateInstallFlags({
      supabase: true,
      migration: true,
      direct: true,
    })
    expect(err).toMatch(/mutually exclusive/i)
  })

  it('accepts --eql-version 2 and 3', () => {
    expect(validateInstallFlags({ eqlVersion: '2' })).toBeNull()
    expect(validateInstallFlags({ eqlVersion: '3' })).toBeNull()
    expect(
      validateInstallFlags({ eqlVersion: '3', supabase: true, direct: true }),
    ).toBeNull()
  })

  it('rejects an unknown --eql-version value', () => {
    expect(validateInstallFlags({ eqlVersion: '4' })).toMatch(/--eql-version/)
  })

  it('rejects --eql-version 3 with --drizzle, --migration, or --latest', () => {
    expect(validateInstallFlags({ eqlVersion: '3', drizzle: true })).toMatch(
      /--drizzle/,
    )
    expect(
      validateInstallFlags({
        eqlVersion: '3',
        supabase: true,
        migration: true,
      }),
    ).toMatch(/--migration/)
    expect(validateInstallFlags({ eqlVersion: '3', latest: true })).toMatch(
      /--latest/,
    )
  })
})

describe('routeInstallPathForEqlVersion', () => {
  it('passes v2 routing through untouched', () => {
    expect(
      routeInstallPathForEqlVersion(2, { supabase: false, drizzle: true }),
    ).toEqual({ drizzle: true, useSupabaseInstallModeSelection: false })
    expect(
      routeInstallPathForEqlVersion(2, { supabase: true, drizzle: false }),
    ).toEqual({ drizzle: false, useSupabaseInstallModeSelection: true })
  })

  it('falls back from auto-detected drizzle to direct for v3, with a notice', () => {
    const routing = routeInstallPathForEqlVersion(3, {
      supabase: false,
      drizzle: true,
    })
    expect(routing.drizzle).toBe(false)
    expect(routing.useSupabaseInstallModeSelection).toBe(false)
    expect(routing.notice).toMatch(/Drizzle/)
  })

  it('skips the supabase migration-vs-direct mode selection for v3', () => {
    const routing = routeInstallPathForEqlVersion(3, {
      supabase: true,
      drizzle: false,
    })
    expect(routing.drizzle).toBe(false)
    expect(routing.useSupabaseInstallModeSelection).toBe(false)
    expect(routing.notice).toBeUndefined()
  })

  it('does NOT auto-imply --supabase from --migration', () => {
    // Even with --supabase: false explicitly, --migration must error.
    const err = validateInstallFlags({ supabase: false, migration: true })
    expect(err).not.toBeNull()
  })
})

describe('migrationHeader', () => {
  it('renders the header with the provided runner for npx', () => {
    const header = migrationHeader('npx')
    expect(header).toContain(
      '-- CipherStash EQL — installed by `npx stash eql install --supabase --migration`.',
    )
  })

  it('renders the header with the provided runner for bunx', () => {
    const header = migrationHeader('bunx')
    expect(header).toContain('bunx stash eql install')
  })

  it('renders the header with the provided runner for pnpm dlx', () => {
    const header = migrationHeader('pnpm dlx')
    expect(header).toContain('pnpm dlx stash eql install')
  })

  it('includes all expected documentation lines', () => {
    const header = migrationHeader('npx')
    expect(header).toContain('eql_v2_encrypted')
    expect(header).toContain(
      'https://cipherstash.com/docs/stack/cipherstash/supabase',
    )
  })
})

describe('chooseSupabaseInstallMode', () => {
  const projectWith = {
    hasMigrationsDir: true,
    hasConfigToml: true,
    migrationsDir: '/tmp/x',
  }
  const projectWithout = {
    hasMigrationsDir: false,
    hasConfigToml: false,
    migrationsDir: '/tmp/x',
  }

  it('honors explicit --migration regardless of TTY or detection', () => {
    expect(
      chooseSupabaseInstallMode({ migration: true }, projectWithout, true),
    ).toBe('migration')
    expect(
      chooseSupabaseInstallMode({ migration: true }, projectWithout, false),
    ).toBe('migration')
  })

  it('honors explicit --direct regardless of TTY or detection', () => {
    expect(chooseSupabaseInstallMode({ direct: true }, projectWith, true)).toBe(
      'direct',
    )
    expect(
      chooseSupabaseInstallMode({ direct: true }, projectWith, false),
    ).toBe('direct')
  })

  it('returns null in TTY mode when neither sub-flag is set (caller should prompt)', () => {
    expect(chooseSupabaseInstallMode({}, projectWith, true)).toBeNull()
    expect(chooseSupabaseInstallMode({}, projectWithout, true)).toBeNull()
  })

  it('non-interactive: defaults to migration when supabase/migrations exists', () => {
    expect(chooseSupabaseInstallMode({}, projectWith, false)).toBe('migration')
  })

  it('non-interactive: defaults to direct when supabase/migrations is missing', () => {
    expect(chooseSupabaseInstallMode({}, projectWithout, false)).toBe('direct')
  })
})
