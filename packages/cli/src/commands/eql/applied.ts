/**
 * drizzle's own migration ledger: schema `drizzle`, table
 * `__drizzle_migrations`, one row per applied migration carrying `hash` and
 * `created_at`. These are drizzle-kit's defaults (`migrations.schema` /
 * `migrations.table` in drizzle.config.ts); a project that overrides them must
 * say so, because the probe cannot discover it — see {@link LEDGER_ABSENT}.
 */
export const DEFAULT_MIGRATIONS_RELATION = 'drizzle.__drizzle_migrations'

/**
 * Postgres SQLSTATEs meaning "the relation isn't there".
 *
 * In practice this query only ever raises `42P01`: a SELECT against a
 * schema-qualified relation reports `relation "s.t" does not exist` whether the
 * TABLE or the SCHEMA is the missing part. `3F000` (invalid_schema_name) comes
 * from statements that name a schema directly — `SET search_path`, `CREATE
 * TABLE s.t` — and is kept here only as defensive breadth, not because this
 * query produces it. Confirmed against live Postgres 17 in
 * `__tests__/applied.live.test.ts`, and by mutation: removing `3F000` leaves
 * both live absent-ledger cases green.
 */
const NO_LEDGER = new Set([
  '42P01', // undefined_table
  '3F000', // invalid_schema_name — see above; unreachable via this query
])

/** The ledger exists and is empty — nothing has been applied. A real answer. */
export const NOTHING_APPLIED = Symbol('nothing-applied')

/**
 * The ledger is not where we looked. NOT the same answer as {@link
 * NOTHING_APPLIED}: it means either `drizzle-kit migrate` never ran here, or
 * the project overrode `migrations.table` / `migrations.schema` and the probe
 * queried the wrong relation. Those are indistinguishable from the SQLSTATE, so
 * the caller must report the state as unverified rather than claim nothing has
 * been applied — the second case would otherwise rewrite applied migrations
 * while telling the user they were safe.
 */
export const LEDGER_ABSENT = Symbol('ledger-absent')

/**
 * Is `relation` a plain `table` or `schema.table` of unquoted identifiers?
 *
 * The relation is quoted before it reaches SQL, so this is not what stops
 * injection — {@link quoteRelation} does. It stops something quieter: a value
 * that is not a plain identifier pair becomes a quoted relation no database
 * has, whose `undefined_table` would be read as {@link LEDGER_ABSENT}. A typo
 * would then silently downgrade the very check the caller asked for.
 */
export function isValidRelation(relation: string): boolean {
  const parts = relation.split('.')
  if (parts.length < 1 || parts.length > 2) return false
  return parts.every((part) => /^[A-Za-z_][A-Za-z0-9_$]*$/.test(part))
}

/**
 * Render `[schema.]table` as quoted SQL identifiers.
 *
 * The relation reaches the query as text, so it is quoted rather than
 * interpolated bare: each dot-separated part is wrapped in double quotes with
 * any embedded quote doubled, which is injection-safe by construction. The
 * caller validates the shape separately, so a malformed value is rejected with
 * a useful message instead of becoming a quoted identifier that cannot exist.
 */
function quoteRelation(relation: string): string {
  return relation
    .split('.')
    .map((part) => `"${part.replace(/"/g, '""')}"`)
    .join('.')
}

/**
 * The `created_at` of the most recently applied migration, in epoch
 * milliseconds; {@link NOTHING_APPLIED} when the ledger exists and is empty; or
 * {@link LEDGER_ABSENT} when it is not where we looked.
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
  relation: string = DEFAULT_MIGRATIONS_RELATION,
): Promise<number | typeof NOTHING_APPLIED | typeof LEDGER_ABSENT> {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString: databaseUrl })
  try {
    await client.connect()
    const result = await client.query<{ max_created_at: string | null }>(
      `select max(created_at) as max_created_at from ${quoteRelation(relation)}`,
    )
    // `created_at` is a bigint, which node-postgres returns as a string to
    // avoid a lossy Number conversion. The values are epoch milliseconds, far
    // inside Number.MAX_SAFE_INTEGER, so converting here is safe.
    const raw = result.rows[0]?.max_created_at
    if (raw === null || raw === undefined) return NOTHING_APPLIED
    return Number(raw)
  } catch (error) {
    // A missing relation is a partial answer — see LEDGER_ABSENT for why it is
    // not "nothing applied". Every other error (auth, network, permissions) is
    // a check that did NOT happen, and must not be quietly downgraded to "all
    // clear" — it propagates to the caller.
    if (
      typeof error === 'object' &&
      error !== null &&
      NO_LEDGER.has(String((error as { code?: unknown }).code))
    ) {
      return LEDGER_ABSENT
    }
    throw error
  } finally {
    await client.end().catch(() => undefined)
  }
}
