import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { findGeneratedMigration } from '../../eql/migration.js'

/**
 * `findGeneratedMigration` locates the custom migration scaffolded by
 * `eql migration --drizzle`; pin its failure and ordering branches directly.
 */
describe('findGeneratedMigration', () => {
  let dir: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'stash-find-migration-'))
  })
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true })
  })

  it('throws when the out directory does not exist', async () => {
    await expect(
      findGeneratedMigration(join(dir, 'nope'), 'install-eql'),
    ).rejects.toThrow(/output directory not found/)
  })

  it('throws when no .sql file matches the migration name', async () => {
    writeFileSync(join(dir, '0000_other.sql'), '')
    await expect(findGeneratedMigration(dir, 'install-eql')).rejects.toThrow(
      /Could not find a migration matching "install-eql"/,
    )
  })

  it('returns the highest-numbered match, ignoring non-.sql and non-matching entries', async () => {
    for (const f of [
      '0000_install-eql.sql',
      '0010_install-eql.sql',
      '0011_install-eql.txt', // not .sql
      '0001_users.sql', // doesn't match the name
      '9999_install-eql-backup.sql', // contains the name, but is not an exact match
    ]) {
      writeFileSync(join(dir, f), '')
    }
    // Relies on drizzle-kit's zero-padded 4-digit prefix for lexical == numeric.
    expect(await findGeneratedMigration(dir, 'install-eql')).toBe(
      join(dir, '0010_install-eql.sql'),
    )
  })
})
