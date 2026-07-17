import { describe, expect, it } from 'vitest'
import { buildEqlV3MigrationSql } from '../migration.js'

/**
 * `buildEqlV3MigrationSql` is the pure core of `stash eql migration --drizzle`:
 * it assembles the migration contents from the CLI's bundled v3 install SQL,
 * the optional Supabase grants, and the `cs_migrations` tracking schema. The
 * file-writing orchestration around it (drizzle-kit scaffold + inject) is thin
 * and I/O-bound, so the assembly is where the contract lives.
 */
describe('buildEqlV3MigrationSql', () => {
  it('emits the EQL v3 install bundle and the cs_migrations tracking schema', () => {
    const sql = buildEqlV3MigrationSql({ supabase: false })
    // v3 bundle, not v2 — the whole point of the command.
    expect(sql).toContain('EQL v3 schema creation')
    expect(sql).toContain('eql_v3')
    // Bundled tracking schema so one migration run is enough for `stash encrypt`.
    expect(sql).toContain('cs_migrations')
  })

  it('omits the Supabase role grants without --supabase', () => {
    const sql = buildEqlV3MigrationSql({ supabase: false })
    expect(sql).not.toContain('TO anon, authenticated, service_role')
    expect(sql).not.toContain('-- Supabase role grants')
  })

  it('appends the eql_v3 + eql_v3_internal grants with --supabase', () => {
    const sql = buildEqlV3MigrationSql({ supabase: true })
    expect(sql).toContain('-- Supabase role grants')
    expect(sql).toContain(
      'GRANT USAGE ON SCHEMA eql_v3 TO anon, authenticated, service_role',
    )
    expect(sql).toContain(
      'GRANT USAGE ON SCHEMA eql_v3_internal TO anon, authenticated, service_role',
    )
  })

  it('is a superset of the non-supabase content when --supabase is set', () => {
    const base = buildEqlV3MigrationSql({ supabase: false })
    const supa = buildEqlV3MigrationSql({ supabase: true })
    // The grants are additive: everything in the base still appears.
    expect(supa.length).toBeGreaterThan(base.length)
    expect(supa).toContain('EQL v3 schema creation')
    expect(supa).toContain('cs_migrations')
  })
})
