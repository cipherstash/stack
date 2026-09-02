/**
 * Live-Postgres coverage for `stash eql verify` (#890).
 *
 * The unit suite proves the parser and the differ against synthetic installed
 * states — what it cannot prove is the seam between the two spellings of a
 * type: the bundle writes `text[]` and `public.eql_v3_double_ord`, the
 * catalog stores `_text` and typname rows, and the OPERATORS_SQL/format_type
 * normalisation is what makes them meet. A wrong spelling on either side
 * reports thousands of phantom missing operators (or none at all, ever) and
 * no fake can catch it. So: install the real pinned bundle, verify it reads
 * as complete, then break it surgically and check the damage is named.
 *
 * Gated on STASH_TEST_DATABASE_URL so the default `pnpm test` stays green
 * without a database. Locally:
 *
 *   docker compose -f local/docker-compose.postgres.yml up -d --wait
 *   export STASH_TEST_DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EQLInstaller } from '../index.js'
import {
  assessEqlSurface,
  bundledExpectedSurface,
  readInstalledSurface,
  verifyEqlSurface,
} from '../verify.js'

const DATABASE_URL = process.env.STASH_TEST_DATABASE_URL
const describeLive = DATABASE_URL ? describe : describe.skip

async function query(sql: string): Promise<void> {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: DATABASE_URL })
  await client.connect()
  try {
    await client.query(sql)
  } finally {
    await client.end().catch(() => undefined)
  }
}

describeLive('verifyEqlSurface — live Postgres', () => {
  beforeAll(async () => {
    // A real install of the pinned bundle. The docker role is a superuser, so
    // the ORE operator class is created and the expected state is
    // `indexable`. Re-running over a previous (possibly broken-by-this-suite)
    // install is exactly what the bundle supports.
    const url = DATABASE_URL ?? ''
    await new EQLInstaller({ databaseUrl: url }).install()
  }, 180_000)

  afterAll(async () => {
    // The tests below drop an operator and eql_v3.version() — reinstall so
    // the damage does not outlive this file into whatever runs against the
    // database next (the live suites run serially in the `live` project, so
    // "next" is a real thing, not a race).
    const url = DATABASE_URL ?? ''
    await new EQLInstaller({ databaseUrl: url }).install()
  }, 180_000)

  it('reads a fresh superuser install as complete', async () => {
    const url = DATABASE_URL ?? ''
    const report = await verifyEqlSurface(url)
    expect(report.findings.filter((f) => f.severity === 'damage')).toEqual([])
    expect(report.status).toBe('complete')
    expect(report.ore?.state).toBe('indexable')
    // Full-count sanity: the catalog spelling met the bundle spelling for
    // every single object, not just most of them.
    expect(report.counts?.operators.present).toBe(
      report.counts?.operators.expected,
    )
    expect(report.counts?.functions.present).toBe(
      report.counts?.functions.expected,
    )
    expect(report.counts?.domains.present).toBe(report.counts?.domains.expected)
    expect(report.counts?.casts.present).toBe(report.counts?.casts.expected)
  }, 60_000)

  /**
   * `eql status` reads the ORE half through the summary assessment rather than
   * the full surface diff (#891). Both must answer the same question the same
   * way against the same database — a cheap read that disagreed with `verify`
   * would be worse than no read at all.
   */
  it('reads the same ORE state through the standalone probe as through verify', async () => {
    const url = DATABASE_URL ?? ''
    const report = await verifyEqlSurface(url)
    const { default: pg } = await import('pg')
    const client = new pg.Client({ connectionString: url })
    await client.connect()
    try {
      await client.query('BEGIN READ ONLY')
      const { ore } = await assessEqlSurface(client, 'summary')
      // The database runs the pinned bundle, so the probe is comparable —
      // it declines to answer only on a version skew.
      expect(ore.comparable).toBe(true)
      if (!ore.comparable) return
      expect(ore.state).toBe(report.ore?.state)
      expect(ore.opclassPresent).toBe(report.ore?.opclassPresent)
      expect(ore.poisonedDomains).toBe(report.ore?.poisonedDomains)
      expect(ore.expectedPoisoned).toBe(report.ore?.expectedPoisoned)
    } finally {
      await client.query('ROLLBACK').catch(() => undefined)
      await client.end().catch(() => undefined)
    }
  }, 60_000)

  /**
   * `CASTS_SQL` used to require BOTH endpoints in the EQL/public schemas,
   * while the parser takes every `CREATE CAST` in the bundle — so the day a
   * bundle casts an EQL type to or from a `pg_catalog` type (`jsonb`, `text`)
   * that cast would enter the expected surface and be unreadable as installed,
   * reporting "Cast missing" damage on every healthy database. Only a live
   * catalogue read can prove the widened query sees one.
   */
  it('reads a cast with a pg_catalog endpoint as installed', async () => {
    const url = DATABASE_URL ?? ''
    await query(
      'CREATE CAST (eql_v3_internal.ore_block_256 AS text) WITH INOUT',
    )
    const { default: pg } = await import('pg')
    const client = new pg.Client({ connectionString: url })
    await client.connect()
    try {
      const installed = await readInstalledSurface(
        client,
        bundledExpectedSurface(),
      )
      expect(
        installed.presentCasts.has('eql_v3_internal.ore_block_256 AS text'),
      ).toBe(true)
    } finally {
      await client.end().catch(() => undefined)
      await query('DROP CAST (eql_v3_internal.ore_block_256 AS text)')
    }
  }, 60_000)

  it('names a dropped comparison operator, attributed to its domain', async () => {
    // The failure class from #890: the domain exists, its comparison surface
    // does not, and `weight >= x` errors at query time.
    await query(
      'DROP OPERATOR >= (public.eql_v3_double_ord, public.eql_v3_double_ord)',
    )
    const url = DATABASE_URL ?? ''
    const report = await verifyEqlSurface(url)
    expect(report.status).toBe('incomplete')
    expect(report.ok).toBe(false)
    const finding = report.findings.find(
      (f) => f.kind === 'operator' && f.severity === 'damage',
    )
    expect(finding?.message).toContain(
      '>= (public.eql_v3_double_ord, public.eql_v3_double_ord)',
    )
    expect(finding?.domain).toBe('eql_v3_double_ord')
  }, 60_000)

  it('treats a dropped version() as damage rather than "unknown version"', async () => {
    await query('DROP FUNCTION eql_v3.version()')
    const url = DATABASE_URL ?? ''
    const report = await verifyEqlSurface(url)
    expect(report.status).toBe('incomplete')
    expect(
      report.findings.some(
        (f) => f.kind === 'version' && f.severity === 'damage',
      ),
    ).toBe(true)
  }, 60_000)
})
