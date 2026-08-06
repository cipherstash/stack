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
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { buildEqlV3MigrationSql } from '../migration.js'
import {
  findEqlDependentMigrationsBefore,
  findExistingEqlMigration,
  SUPABASE_EQL_MIGRATION_SUFFIX,
  writeSupabaseEqlMigration,
} from '../supabase-migration.js'

// Real filesystem throughout: the whole point of this module is what lands on
// disk, and a mocked `node:fs` would assert our own mock's behaviour.
//
// The one exception is `writeFile`, a spy that delegates to the real impl so
// the atomicity test can make just that call fail. `vi.spyOn` cannot do this —
// an ESM namespace is not configurable — so the module is mocked and the
// delegating default restored in `beforeEach` after `clearAllMocks`.
const fsWrite = vi.hoisted(() => ({
  real: (() => {
    throw new Error(
      'fsWrite.real not initialised: node:fs/promises mock factory did not run',
    )
  }) as typeof import('node:fs/promises').writeFile,
  spy: vi.fn(),
}))
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  fsWrite.real = actual.writeFile
  return { ...actual, default: actual, writeFile: fsWrite.spy }
})

let tmp: string

beforeEach(() => {
  fsWrite.spy.mockImplementation(fsWrite.real)
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

  it('ignores a directory that happens to carry the suffix', () => {
    // readdirSync returns directories too. Treating one as the target made it
    // targetPath, and the write then failed with a raw EISDIR through the
    // generic error path.
    mkdirSync(join(tmp, 'migrations', '20260101000000_cipherstash_eql.sql'), {
      recursive: true,
    })
    expect(findExistingEqlMigration(join(tmp, 'migrations'))).toBeNull()
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

  it('reports the version the file carries', async () => {
    const result = await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })
    expect(result.version).toBe('20260804021925')
  })

  it('sorts after an already-applied migration rather than before it', async () => {
    // A version BELOW the highest applied one is "out of order" to the Supabase
    // CLI, and it is not merely skipped: `supabase db push` aborts the whole
    // push with `Found local migration files to be inserted before the last
    // migration on remote database.` and applies nothing, until the user knows
    // to re-run with --include-all. The retired v2 writer used an all-zero
    // prefix and had exactly that problem.
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
    // The version is what the remote ledger keys on, so it is the thing the
    // re-apply guidance has to name — reported, not re-derived by the caller.
    expect(second.version).toBe(first.version)
    expect(readdirSync(tmp)).toHaveLength(1)
    expect(readFileSync(second.path, 'utf-8')).toContain('SELECT 2;')
  })

  it('leaves no partial .sql behind when the write fails', async () => {
    // The migrations directory is executed wholesale by `supabase db reset`, so
    // a truncated file from an interrupted write is not inert — it runs. The
    // write goes to a temp sibling and is renamed, so a failure leaves the
    // directory exactly as it was.
    fsWrite.spy.mockRejectedValueOnce(
      new Error('ENOSPC: no space left on device'),
    )

    await expect(
      writeSupabaseEqlMigration({
        migrationsDir: tmp,
        sql: 'SELECT 1;',
        now: FIXED_NOW,
      }),
    ).rejects.toThrow(/ENOSPC/)

    expect(readdirSync(tmp)).toHaveLength(0)
  })

  it('does not leave a temp file behind on a successful write', async () => {
    await writeSupabaseEqlMigration({
      migrationsDir: tmp,
      sql: 'SELECT 1;',
      now: FIXED_NOW,
    })

    expect(readdirSync(tmp)).toEqual([FIXED_FILENAME])
  })
})

/**
 * Brownfield detection. A current-timestamp install sorts LAST, which is right
 * for a greenfield project and wrong for one that already has encrypted-column
 * migrations on disk: `supabase db reset` replays in version order with no
 * dependency awareness, so those run before EQL exists and the reset dies on
 * `type "eql_v3_text_search" does not exist`.
 */
describe('findEqlDependentMigrationsBefore', () => {
  // What the stash-supabase skill tells people to write by hand for an
  // encrypted twin: a `public.eql_v3_*` domain the bundle creates.
  const ENCRYPTED_COLUMN_SQL =
    'ALTER TABLE users ADD COLUMN email_encrypted public.eql_v3_text_search;\n'

  it('returns nothing for a directory that does not exist', () => {
    expect(findEqlDependentMigrationsBefore(join(tmp, 'nope'))).toEqual([])
  })

  it('returns nothing for an empty directory', () => {
    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('finds an earlier migration that names an EQL domain', () => {
    writeFileSync(
      join(tmp, '20260101000000_encrypt_email.sql'),
      ENCRYPTED_COLUMN_SQL,
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual([
      '20260101000000_encrypt_email.sql',
    ])
  })

  it('finds an earlier migration that calls into the eql_v3 schema', () => {
    // The other reference form: a function/operator call rather than a column
    // domain (`eql_v3.query_text(...)`, `eql_v3.ste_vec(...)`).
    writeFileSync(
      join(tmp, '20260101000000_index_email.sql'),
      'CREATE INDEX ON users (eql_v3.hmac_256(email_encrypted));\n',
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual([
      '20260101000000_index_email.sql',
    ])
  })

  it('ignores a migration that sorts after the install', () => {
    writeFileSync(
      join(tmp, '20990101000000_encrypt_email.sql'),
      ENCRYPTED_COLUMN_SQL,
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('ignores an earlier migration that never mentions EQL', () => {
    writeFileSync(
      join(tmp, '20260101000000_users.sql'),
      'CREATE TABLE users (id uuid PRIMARY KEY, email text);\n',
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('does not trip on a longer identifier that merely contains the token', () => {
    writeFileSync(
      join(tmp, '20260101000000_notes.sql'),
      'CREATE TABLE not_eql_v3_notes (id integer);\n',
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('ignores our own install migrations', () => {
    // An older `_cipherstash_eql.sql` is another copy of the install, not
    // something depending on it — reporting it would tell the user to reorder
    // the install below itself.
    writeFileSync(
      join(tmp, '20260101000000_cipherstash_eql.sql'),
      'CREATE SCHEMA eql_v3;\n',
    )
    writeFileSync(join(tmp, '20260301000000_cipherstash_eql.sql'), '')

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('ignores files the Supabase CLI itself skips', () => {
    // `^([0-9]+)_(.*)\.sql$` in pkg/migration/file.go. A name that fails it is
    // never applied (the CLI prints `Skipping migration ...` and moves on), so
    // it cannot break a reset however it sorts.
    writeFileSync(join(tmp, 'encrypt_email.sql'), ENCRYPTED_COLUMN_SQL)
    writeFileSync(
      join(tmp, '20260101000000_encrypt_email.sql.bak'),
      ENCRYPTED_COLUMN_SQL,
    )
    writeFileSync(
      join(tmp, '.20260101000000_encrypt_email.sql'),
      ENCRYPTED_COLUMN_SQL,
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('ignores a directory that carries a migration-shaped name', () => {
    mkdirSync(join(tmp, '20260101000000_encrypt_email.sql'))

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })

  it('sorts the hits so the earliest is first', () => {
    writeFileSync(
      join(tmp, '20260201000000_encrypt_name.sql'),
      ENCRYPTED_COLUMN_SQL,
    )
    writeFileSync(
      join(tmp, '20260101000000_encrypt_email.sql'),
      ENCRYPTED_COLUMN_SQL,
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual([
      '20260101000000_encrypt_email.sql',
      '20260201000000_encrypt_name.sql',
    ])
  })

  it('compares against the version --force keeps, not the clock', () => {
    // With an install migration already on disk, that file is overwritten in
    // place and keeps ITS version — so the ordering question is about that
    // version, not today's. Comparing against the clock would report a
    // dependant that in fact replays after the install.
    writeFileSync(join(tmp, '20260101000000_cipherstash_eql.sql'), '')
    writeFileSync(
      join(tmp, '20260102000000_encrypt_email.sql'),
      ENCRYPTED_COLUMN_SQL,
    )

    expect(findEqlDependentMigrationsBefore(tmp, { now: FIXED_NOW })).toEqual(
      [],
    )
  })
})
