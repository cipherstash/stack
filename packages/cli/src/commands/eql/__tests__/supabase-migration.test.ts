import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { buildEqlV3MigrationSql } from '../migration.js'
import {
  findExistingEqlMigration,
  SUPABASE_EQL_MIGRATION_SUFFIX,
  writeSupabaseEqlMigration,
} from '../supabase-migration.js'

// Real filesystem throughout: the whole point of this module is what lands on
// disk, and a mocked `node:fs` would assert our own mock's behaviour.
let tmp: string

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'stash-supabase-migration-'))
})

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true })
})

const FIXED_NOW = new Date('2026-08-04T02:19:25.000Z')
const FIXED_FILENAME = `20260804021925${SUPABASE_EQL_MIGRATION_SUFFIX}`

describe('findExistingEqlMigration', () => {
  it('returns null for a directory that does not exist', () => {
    expect(findExistingEqlMigration(join(tmp, 'nope'))).toBeNull()
  })

  it('returns null when no install migration is present', () => {
    mkdirSync(join(tmp, 'migrations'))
    writeFileSync(join(tmp, 'migrations', '20260101000000_users.sql'), '')
    expect(findExistingEqlMigration(join(tmp, 'migrations'))).toBeNull()
  })

  it('matches on the suffix, not an exact filename', () => {
    // The timestamp differs on every run, so an exact-name check would miss a
    // file this command itself wrote — and we would install EQL twice.
    mkdirSync(join(tmp, 'migrations'))
    const path = join(tmp, 'migrations', `20991231235959_cipherstash_eql.sql`)
    writeFileSync(path, '')
    expect(findExistingEqlMigration(join(tmp, 'migrations'))).toBe(path)
  })

  it('returns the lexically last when several exist', () => {
    mkdirSync(join(tmp, 'migrations'))
    writeFileSync(
      join(tmp, 'migrations', '20260101000000_cipherstash_eql.sql'),
      '',
    )
    const newer = join(tmp, 'migrations', '20270101000000_cipherstash_eql.sql')
    writeFileSync(newer, '')
    expect(findExistingEqlMigration(join(tmp, 'migrations'))).toBe(newer)
  })
})

describe('writeSupabaseEqlMigration', () => {
  it('creates the migrations directory when it is absent', async () => {
    const dir = join(tmp, 'supabase', 'migrations')
    expect(existsSync(dir)).toBe(false)

    const result = await writeSupabaseEqlMigration({
      migrationsDir: dir,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })

    expect(result.overwritten).toBe(false)
    expect(result.path).toBe(join(dir, FIXED_FILENAME))
    expect(existsSync(result.path)).toBe(true)
  })

  it('names the file <YYYYMMDDHHMMSS>_cipherstash_eql.sql', async () => {
    const result = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })
    expect(result.path.endsWith(FIXED_FILENAME)).toBe(true)
  })

  it('sorts after an already-applied migration rather than before it', async () => {
    // A version BELOW the highest applied one is "out of order" to the Supabase
    // CLI: `supabase db push` skips it without --include-all. The retired v2
    // writer used an all-zero prefix and had exactly that problem.
    writeFileSync(join(tmp, '20260101000000_users.sql'), '')
    const result = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })
    const [first] = readdirSync(tmp).sort()
    expect(first).toBe('20260101000000_users.sql')
    expect(result.path.endsWith(FIXED_FILENAME)).toBe(true)
  })

  it('writes a header above the SQL body', async () => {
    const result = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })
    const body = readFileSync(result.path, 'utf-8')
    expect(body).toMatch(/^-- CipherStash EQL v3/)
    expect(body).toContain('supabase db reset')
    expect(body.trimEnd().endsWith('SELECT 1;')).toBe(true)
  })

  it('carries the v3 bundle, the Supabase grants, and the tracking schema', async () => {
    // The real SQL, not a stub — this is the contract that one `supabase db
    // reset` provisions everything `stash encrypt` needs.
    const result = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: buildEqlV3MigrationSql({ supabase: true }),
      now: FIXED_NOW,
    })
    const body = readFileSync(result.path, 'utf-8')

    expect(body).toContain('eql_v3')
    expect(body).toContain('eql_v3_internal')
    for (const role of ['anon', 'authenticated', 'service_role']) {
      expect(body).toContain(role)
    }
    expect(body).toContain('cs_migrations')
  })

  it('refuses a second install migration without force', async () => {
    await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })

    await expect(
      writeSupabaseEqlMigration({
        migrationsDir: tmp,
        sql: 'SELECT 2;',
        now: new Date('2026-09-04T02:19:25.000Z'),
      }),
    ).rejects.toThrow(/already exists/)

    expect(readdirSync(tmp)).toHaveLength(1)
  })

  it('overwrites in place under force, keeping the original version', async () => {
    // Not a second, newer-versioned file: the first one may already be applied
    // and cannot be deleted without desyncing schema_migrations, which would
    // leave two EQL installs in the history.
    const first = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })

    const second = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 2;',
      force: true,
      now: new Date('2026-09-04T02:19:25.000Z'),
    })

    expect(second.path).toBe(first.path)
    expect(second.overwritten).toBe(true)
    expect(readdirSync(tmp)).toHaveLength(1)
    expect(readFileSync(second.path, 'utf-8')).toContain('SELECT 2;')
  })
})
