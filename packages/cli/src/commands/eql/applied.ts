/**
 * drizzle's own migration ledger: schema `drizzle`, table
 * `__drizzle_migrations`, one row per applied migration carrying `hash` and
 * `created_at`. These are drizzle-kit's defaults (`migrationsSchema` /
 * `migrationsTable`); a project that overrides them is out of scope for the
 * check, which then reports "nothing applied" and is handled like the offline
 * case.
 */
const LATEST_APPLIED_SQL =
  'select max(created_at) as max_created_at from drizzle.__drizzle_migrations'

/** Postgres SQLSTATEs meaning "the ledger isn't there", i.e. nothing applied. */
const NO_LEDGER = new Set([
  '42P01', // undefined_table
  '3F000', // invalid_schema_name
])

/** The ledger is absent — `drizzle-kit migrate` has never run against this DB. */
export const NOTHING_APPLIED = Symbol('nothing-applied')

/**
 * The `created_at` of the most recently applied migration, in epoch
 * milliseconds, or {@link NOTHING_APPLIED} when the ledger does not exist or is
 * empty.
 *
 * **Why a single watermark rather than a per-migration lookup.** drizzle's
 * applied-check is timestamp-based, not hash-based: `drizzle-orm@0.45.2`
 * `pg-core/dialect.js:62` is `if (!lastDbMigration || Number(
 * lastDbMigration.created_at) < migration.folderMillis)`, with the hash written
 * on insert at `:67` and never read for the decision, and `folderMillis` coming
 * from the journal's `when` (`migrator.js:22`). `drizzle-kit migrate` delegates
 * to that same code for every Postgres driver. So a migration is applied iff
 * its `when` is at or below this watermark, and comparing hashes would be
 * modelling a mechanism drizzle does not have.
 *
 * `pg` is imported lazily: repair is an offline command in every run that does
 * not pass a database URL, and it should not pay for the driver to find that
 * out.
 */
export async function latestAppliedMillis(
  databaseUrl: string,
): Promise<number | typeof NOTHING_APPLIED> {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: databaseUrl })
  try {
    await client.connect()
    const result = await client.query<{ max_created_at: string | null }>(
      LATEST_APPLIED_SQL,
    )
    // `created_at` is a bigint, which node-postgres returns as a string to
    // avoid a lossy Number conversion. The values are epoch milliseconds, far
    // inside Number.MAX_SAFE_INTEGER, so converting here is safe.
    const raw = result.rows[0]?.max_created_at
    if (raw === null || raw === undefined) return NOTHING_APPLIED
    return Number(raw)
  } catch (error) {
    // A missing ledger is an answer, not a failure: `drizzle-kit migrate` has
    // never run here, so nothing is applied. Every other error (auth, network,
    // permissions) is a check that did NOT happen, and must not be quietly
    // downgraded to "all clear" — it propagates to the caller.
    if (
      typeof error === 'object' &&
      error !== null &&
      NO_LEDGER.has(String((error as { code?: unknown }).code))
    ) {
      return NOTHING_APPLIED
    }
    throw error
  } finally {
    await client.end()
  }
}
