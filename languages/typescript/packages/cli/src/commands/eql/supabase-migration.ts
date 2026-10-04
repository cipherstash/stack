import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { mkdir, rename, rm, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'

/**
 * Suffix every generated Supabase EQL install migration carries.
 *
 * The filename is `<YYYYMMDDHHMMSS>_cipherstash_eql.sql`, so the stem varies
 * per run and only the suffix is stable. {@link findExistingEqlMigration}
 * matches on it — an exact-filename check would miss a file this command
 * itself wrote at a different second, and re-running would silently install
 * EQL a second time in the migration ledger.
 */
export const SUPABASE_EQL_MIGRATION_SUFFIX = '_cipherstash_eql.sql'

/**
 * A Supabase migration version is the leading `YYYYMMDDHHMMSS`. Generating it
 * from the current time (rather than the all-zero prefix the retired EQL v2
 * writer used) keeps the file sorting *after* everything already applied.
 *
 * A lower-sorting version is "out of order" to the Supabase CLI, and it is not
 * merely skipped: `FindPendingMigrations` (`pkg/migration/apply.go`) collects
 * every local version below the last remote one into `unapplied` and returns
 * `ErrMissingRemote` — "Found local migration files to be inserted before the
 * last migration on remote database." — which `push.Run` propagates *before*
 * applying anything. The whole push aborts until the user re-runs with
 * `--include-all` (the only escape, in `internal/migration/up/up.go`). A
 * current timestamp lands in the pending tail and pushes with no flag at all.
 *
 * That is the right default, not a universal one: an install stamped today also
 * sorts after any encrypted-column migration a project already has, and those
 * replay first on `supabase db reset`. See
 * {@link findEqlDependentMigrationsBefore}, which detects that case so the
 * command can say so rather than write a file that breaks the next reset.
 */
function migrationVersion(now: Date): string {
  return now
    .toISOString()
    .replace(/[-:.TZ]/g, '')
    .slice(0, 14)
}

/**
 * The Supabase CLI's own migration filename filter, `^([0-9]+)_(.*)\.sql$`
 * (`migrateFilePattern`, `pkg/migration/file.go`). A file that fails it is
 * never applied: `ListLocalMigrations` prints `Skipping migration <name>...
 * (file name must match pattern "<timestamp>_name.sql")` to stderr and moves
 * on. Mirrored here so this module's ordering analysis considers exactly the
 * files the CLI will run.
 */
const SUPABASE_MIGRATION_FILENAME = /^(\d+)_.*\.sql$/

function migrationVersionOf(filename: string): string | null {
  return SUPABASE_MIGRATION_FILENAME.exec(filename)?.[1] ?? null
}

/**
 * Anything that needs the EQL install to have run first: a `public.eql_v3_*`
 * column domain, an `eql_v3.*` function or operator, an `eql_v3_internal.*`
 * index-term type. One token covers all three, and the leading `\b` keeps it
 * off lookalikes (`not_eql_v3_notes` does not match — the `_` before it is a
 * word character, so there is no boundary).
 *
 * Deliberately unaware of SQL comments. A migration whose only mention of EQL
 * is in a comment gets a warning it does not need; a migration whose dependency
 * we miss gets a `supabase db reset` that fails with no explanation. The first
 * costs a line of terminal output, the second costs a debugging session.
 */
const EQL_REFERENCE = /\beql_v3/

function referencesEql(path: string): boolean {
  try {
    return EQL_REFERENCE.test(readFileSync(path, 'utf-8'))
  } catch {
    // Unreadable, or a directory (EISDIR) — either way not a migration the
    // Supabase CLI will run against EQL.
    return false
  }
}

/**
 * Migration filenames in `migrationsDir` that reference EQL and sort BEFORE the
 * version this command's install file will carry.
 *
 * The failure this exists to catch: a project that ran `stash eql install`
 * directly, added encrypted-column migrations against the EQL it put on the
 * live database, and only then discovered #613 and ran `stash eql migration
 * --supabase`. The install is stamped with today's date, so it sorts after
 * those migrations. `supabase db reset` replays the directory in version order
 * (`fs.ReadDir` order, filtered by `LoadPartialMigrations`) with no dependency
 * awareness at all, so they run first, reference a domain nothing has created,
 * and the reset fails.
 *
 * Version comparison is a plain string compare on the numeric prefix, matching
 * both consumers in the Go CLI: `db reset` replays in `fs.ReadDir`'s
 * filename order, and `FindPendingMigrations` compares version strings with
 * `<`. Supabase versions are fixed-width timestamps, so the two agree.
 *
 * Returns names rather than paths: every hit is in `migrationsDir`, and the
 * name is both what the user sees and what the ordering is computed from.
 * Sorted, so `[0]` is the one to sort the install below.
 */
export function findEqlDependentMigrationsBefore(
  migrationsDir: string,
  options: { now?: Date } = {},
): string[] {
  const { now = new Date() } = options

  // The version the install will actually carry. A `--force` run overwrites the
  // existing file IN PLACE and keeps its version, so comparing against the
  // clock there would report dependants that in fact replay after it.
  const existing = findExistingEqlMigration(migrationsDir)
  const installVersion =
    (existing && migrationVersionOf(basename(existing))) ??
    migrationVersion(now)

  let entries: string[]
  try {
    entries = readdirSync(migrationsDir)
  } catch {
    return []
  }

  return entries
    .filter((entry) => {
      // Our own install migrations are the thing being ordered, not something
      // ordered against it — an older duplicate would otherwise be reported as
      // a dependant of the file replacing it.
      if (entry.endsWith(SUPABASE_EQL_MIGRATION_SUFFIX)) return false
      const version = migrationVersionOf(entry)
      return version !== null && version < installVersion
    })
    .filter((entry) => referencesEql(join(migrationsDir, entry)))
    .sort()
}

/**
 * Header prepended to the generated migration, for whoever opens
 * `supabase/migrations/` in six months and finds 4,000 lines of EQL.
 */
function migrationHeader(): string {
  return `-- CipherStash EQL v3 — generated by \`stash eql migration --supabase\`.
--
-- Installs the CipherStash Encrypt Query Language (EQL) types, functions, and
-- operators into the \`eql_v3\` and \`eql_v3_internal\` schemas, grants Supabase's
-- \`anon\`, \`authenticated\`, and \`service_role\` roles access to them, and adds
-- the \`cipherstash.cs_migrations\` tracking schema that \`stash encrypt\` writes
-- its per-column progress into.
--
-- Keeping the install here rather than applying it directly is what makes it
-- survive \`supabase db reset\` — a reset replays this directory, so EQL comes
-- back with everything else.
--
-- Generated file: edit the bundle version by re-running the command with
-- --force rather than hand-editing this SQL.
--
-- Docs: https://cipherstash.com/docs/stack/cipherstash/supabase
`
}

/**
 * Return the path of an EQL install migration already present in
 * `migrationsDir`, or `null`. Lexically last wins, so the reported path is the
 * newest when several exist.
 */
export function findExistingEqlMigration(migrationsDir: string): string | null {
  if (!existsSync(migrationsDir)) return null
  let entries: string[]
  try {
    entries = readdirSync(migrationsDir)
  } catch {
    return null
  }
  const matches = entries
    .filter(
      (entry) =>
        entry.endsWith(SUPABASE_EQL_MIGRATION_SUFFIX) &&
        // readdirSync returns directories too, and one named `…_cipherstash_eql.sql`
        // would otherwise become the write target and fail with a raw EISDIR.
        isFile(join(migrationsDir, entry)),
    )
    .sort()
  return matches.length > 0
    ? join(migrationsDir, matches[matches.length - 1])
    : null
}

function isFile(path: string): boolean {
  try {
    return statSync(path).isFile()
  } catch {
    return false
  }
}

export interface WriteSupabaseEqlMigrationOptions {
  /**
   * Absolute path to the directory the migration should be written into.
   * Created recursively when absent — `supabase init` makes it, but a project
   * that has never run a migration may not have it yet.
   */
  migrationsDir: string
  /** The install SQL body (from `buildEqlV3MigrationSql({ supabase: true })`). */
  sql: string
  /**
   * Write even though an EQL install migration is already present. Without
   * this the function throws rather than adding a second one.
   */
  force?: boolean
  /** Injectable clock, so tests can pin the generated filename. */
  now?: Date
}

export interface WriteSupabaseEqlMigrationResult {
  /** Absolute path to the migration written. */
  path: string
  /** Whether this replaced an install migration that was already there. */
  overwritten: boolean
  /**
   * The `YYYYMMDDHHMMSS` the file carries — a `force` run keeps the original,
   * so this is not derivable from the clock. It is the key the remote ledger
   * (`supabase_migrations.schema_migrations`) records, hence what the re-apply
   * guidance has to name.
   *
   * `null` only for an existing install file whose name has no numeric prefix,
   * which the Supabase CLI skips entirely rather than applying.
   */
  version: string | null
}

/**
 * Write `<migrationsDir>/<version>_cipherstash_eql.sql`.
 *
 * A `force` run overwrites the existing install migration **in place**, keeping
 * its original version. Writing a second, newer-versioned file instead would
 * leave the first one applied and unremovable (deleting an applied migration
 * desyncs `supabase_migrations.schema_migrations`), so the user would end up
 * with two EQL installs in their history. Overwriting keeps it to one.
 *
 * @throws when an EQL install migration already exists and `force` is unset.
 */
export async function writeSupabaseEqlMigration(
  options: WriteSupabaseEqlMigrationOptions,
): Promise<WriteSupabaseEqlMigrationResult> {
  const { migrationsDir, sql, force = false, now = new Date() } = options

  const existing = findExistingEqlMigration(migrationsDir)
  if (existing && !force) {
    throw new Error(
      `An EQL install migration already exists at ${existing}. Re-run with --force to replace it, or delete that file first.`,
    )
  }

  const targetPath =
    existing ??
    join(
      migrationsDir,
      `${migrationVersion(now)}${SUPABASE_EQL_MIGRATION_SUFFIX}`,
    )
  const body = `${migrationHeader()}\n${sql.trimEnd()}\n`

  await mkdir(migrationsDir, { recursive: true })

  // Write to a sibling and rename, rather than straight to targetPath. The
  // migrations directory is executed wholesale by `supabase db reset`, so a
  // truncated file from an interrupted or failed write is not inert — it runs.
  // The rename is atomic within the filesystem, and the temp name fails the
  // Supabase CLI's `^([0-9]+)_(.*)\.sql$` filter twice over (leading dot,
  // trailing `.tmp`), so a crash between the two leaves nothing that will ever
  // be applied. Not nothing that will be SEEN, though: the CLI reads the whole
  // directory and reports each rejected name — `Skipping migration
  // .<version>_cipherstash_eql.sql.tmp... (file name must match pattern
  // "<timestamp>_name.sql")` on stderr, on every `db reset` and `db push` until
  // someone deletes it. Inert and noisy, which is the trade we want.
  const tempPath = join(migrationsDir, `.${basename(targetPath)}.tmp`)
  try {
    await writeFile(tempPath, body, 'utf-8')
    await rename(tempPath, targetPath)
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => {})
    throw error
  }

  return {
    path: targetPath,
    overwritten: existing !== null,
    version: migrationVersionOf(basename(targetPath)),
  }
}
