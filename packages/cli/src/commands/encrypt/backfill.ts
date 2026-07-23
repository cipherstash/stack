import {
  appendEvent,
  detectColumnEqlVersion,
  type EqlVersion,
  type ManifestColumn,
  progress,
  runBackfill,
  upsertManifestColumn,
} from '@cipherstash/migrate'
import {
  type ColumnSchema,
  castAsEnum,
  toEqlCastAs,
} from '@cipherstash/stack/schema'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { loadEncryptionContext, requireTable } from './context.js'

/**
 * Options accepted by `stash encrypt backfill`. Each field maps 1:1 to a
 * CLI flag of the same name (kebab-case at the CLI boundary).
 */
export interface BackfillCommandOptions {
  /**
   * Confirms the application is already deployed with dual-write code in
   * place — i.e. every insert/update writes both the plaintext column and
   * `<col>_encrypted`. Required when this is the column's first backfill
   * (no `dual_writing` event in `cs_migrations` yet).
   *
   * Interactive runs prompt for confirmation; non-interactive runs (CI
   * etc.) require the flag explicitly. The CLI prints a loud warning when
   * the flag is used so a misuse is at least visible in the logs.
   *
   * Subsequent runs (resume, re-run) don't need the flag — the
   * `dual_writing` event from the first run satisfies the precondition.
   */
  confirmDualWritesDeployed?: boolean
  /**
   * When true, encrypt every row whose plaintext is non-null — including
   * rows that already have a ciphertext. Recovery path for drift caused
   * by the application updating the plaintext column without dual-writing
   * the encrypted twin (e.g. dual-writes weren't actually deployed when
   * an earlier backfill ran). Not destructive: re-encrypting a value
   * already-correctly-encrypted just rewrites the same payload.
   */
  force?: boolean
  /**
   * Physical table name, e.g. `users`. Supports schema-qualified form
   * (`public.users`); identifiers are quoted before being put into SQL.
   * Must also exist as an exported `EncryptedTable` in the user's
   * encryption client file (`src/encryption/index.ts`) — the command
   * errors early if the schema is missing.
   */
  table: string
  /**
   * Physical plaintext column to encrypt, e.g. `email`. The command reads
   * from this column, encrypts client-side, and writes the ciphertext
   * into {@link encryptedColumn}. Rows where this is `NULL` are skipped.
   */
  column: string
  /**
   * Override auto-detection of the primary-key column. The command
   * otherwise queries `information_schema` for the table's single-column
   * PK. Required when the table has a composite PK (composite support is
   * deferred; pick one column that is unique and comparable).
   */
  pkColumn?: string
  /**
   * Rows per chunk/transaction. Default `1000`. Lower for lock-sensitive
   * tables or very wide rows; higher for tables with tiny encrypted
   * payloads. Also bounds the most work lost to a `Ctrl-C` mid-chunk.
   */
  chunkSize?: number
  /**
   * Physical destination column for the ciphertext, e.g. `email_encrypted`.
   * Defaults to `<column>_encrypted` to match the convention produced by
   * `drizzle-kit` + CipherStash's migration rewriter. Override only if
   * your schema uses a non-standard column name.
   */
  encryptedColumn?: string
  /**
   * Key in the `EncryptedTable` schema object that corresponds to this
   * column. Defaults to `column`. Override when your schema uses a
   * different key than the physical column — for example:
   *
   * ```ts
   * // src/encryption/index.ts
   * export const usersTable = encryptedTable('users', {
   *   emailAddress: encryptedColumn('email').equality(),
   *   //  ^^^^^^^^^^^^ schema key              ^^^^^ physical column
   * })
   * ```
   *
   * would need `--schema-column-key emailAddress --column email`.
   */
  schemaColumnKey?: string
}

/**
 * CLI handler for `stash encrypt backfill`. Loads the user's encryption
 * client via jiti, opens a pg pool, wires `SIGINT`/`SIGTERM` to a clean
 * shutdown, and delegates to {@link runBackfill}. Exits with code `1` on
 * any unrecoverable error.
 *
 * Safe to re-run: backfill is idempotent (guards with `encrypted IS NULL`)
 * and resumes from the last committed checkpoint.
 */
export async function backfillCommand(options: BackfillCommandOptions) {
  p.intro(runnerCommand(detectPackageManager(), 'stash encrypt backfill'))

  const stashConfig = await loadStashConfig()
  const ctx = await loadEncryptionContext()
  const tableSchema = requireTable(ctx, options.table)

  const pool = new pg.Pool({
    connectionString: stashConfig.databaseUrl,
    max: 2,
  })

  const controller = new AbortController()
  const onSignal = () => {
    p.log.warn('Interrupt received; finishing current chunk and exiting.')
    controller.abort()
  }

  let db: pg.PoolClient | undefined
  let exitCode = 0
  try {
    process.on('SIGINT', onSignal)
    process.on('SIGTERM', onSignal)
    db = await pool.connect()
    const pkColumn =
      options.pkColumn ?? (await detectPkColumn(db, options.table))

    const plaintextColumn = options.column
    const encryptedColumn =
      options.encryptedColumn ?? `${options.column}_encrypted`

    // v2 or v3 changes the rest of the LIFECYCLE (v3 has no cut-over — the
    // ladder is backfill → switch-by-name → drop), so detect it up front,
    // record it in the manifest, and tell the user which path they're on.
    // `null` means the target column doesn't exist, isn't an EQL domain, or is
    // a legacy `eql_v2_encrypted` column (no longer classified — v3 is the sole
    // authored generation). Every one of those falls through to the v2 ladder,
    // which is the correct default for the v2 case and lets the existing checks
    // below produce their specific errors for the other two.
    const eqlVersion = await detectColumnEqlVersion(
      db,
      options.table,
      encryptedColumn,
    )
    if (eqlVersion) {
      p.log.info(
        `${options.table}.${encryptedColumn} is EQL v${eqlVersion}${eqlVersion === 3 ? ' — lifecycle is backfill → switch the app to the encrypted column by name → drop (no cut-over rename).' : ''}`,
      )
    }

    // Phase guard: backfill requires the application to already be writing
    // to both columns, otherwise rows inserted *during* the backfill land
    // in plaintext only and create silent migration drift. Records the
    // `dual_writing` event on first acceptance so re-runs / `--resume` are
    // a no-op for this guard.
    const okToProceed = await ensureDualWritesDeployed(db, {
      table: options.table,
      column: plaintextColumn,
      confirmFlag: options.confirmDualWritesDeployed === true,
    })
    if (!okToProceed) {
      p.outro('Aborted.')
      return
    }

    if (options.force) {
      p.log.warn(
        `--force will re-encrypt every row in ${options.table}.${plaintextColumn}, including ${encryptedColumn} values that already exist. This is the recovery path for drift; expensive but not destructive.`,
      )
      const proceed = await p.confirm({
        message: 'Continue with --force?',
        initialValue: false,
      })
      if (p.isCancel(proceed) || !proceed) {
        p.outro('Aborted.')
        return
      }
    }
    const columns = (tableSchema.build().columns ?? {}) as Record<
      string,
      ColumnSchema
    >
    const schemaColumnKey = resolveSchemaColumnKey({
      columns,
      tableName: options.table,
      plaintextColumn,
      encryptedColumn,
      override: options.schemaColumnKey,
    })
    const column = columns[schemaColumnKey]

    const { transform: transformPlaintext, castAs: detectedCastAs } =
      buildPlaintextCoercer(column?.cast_as)

    // Idempotent: re-runs (resume / --force) replace the same entry.
    const manifestEntry = buildManifestEntry(
      column,
      schemaColumnKey,
      plaintextColumn,
      encryptedColumn,
      options.pkColumn,
      eqlVersion,
    )
    await upsertManifestColumn(options.table, manifestEntry)
    p.log.success(
      `Recorded intent for ${options.table}.${plaintextColumn} in .cipherstash/migrations.json.`,
    )

    // protect-ffi's JsPlaintext wire enum currently has 4 variants:
    // String / Number / Boolean / JsonB. Date and Timestamp columns are
    // typed on the Rust side (NaiveDate / DateTime<Utc>) but there is no
    // JS-visible wire format for them, so any JS Date is serialised to
    // an ISO string by napi-rs and the Rust side then refuses it because
    // string values only bind to Utf8Str columns. Warn before wasting
    // time running a backfill that will fail on the first chunk.
    if (detectedCastAs === 'date' || detectedCastAs === 'timestamp') {
      p.log.warn(
        `Column ${options.table}.${encryptedColumn} declares cast_as: '${detectedCastAs}', which protect-ffi does not currently support for encryption. The backfill will fail with "Cannot convert String to Date". Consider changing the schema to dataType: 'string' (or omitting dataType) and storing ISO date strings instead, then re-running the backfill.`,
      )
      const proceed = await p.confirm({
        message: 'Continue anyway?',
        initialValue: false,
      })
      if (p.isCancel(proceed) || !proceed) {
        p.outro('Aborted.')
        return
      }
    }

    p.log.info(
      `Backfilling ${options.table}.${plaintextColumn} → ${encryptedColumn} (pk: ${pkColumn}, chunk: ${options.chunkSize ?? 1000}, schema cast_as: ${detectedCastAs ?? '(unknown, passing through)'}).`,
    )

    let lastLogged = 0
    const result = await runBackfill({
      db,
      encryptionClient: ctx.client as unknown as Parameters<
        typeof runBackfill
      >[0]['encryptionClient'],
      tableSchema,
      tableName: options.table,
      schemaColumnKey,
      plaintextColumn,
      encryptedColumn,
      pkColumn,
      chunkSize: options.chunkSize,
      signal: controller.signal,
      transformPlaintext,
      force: options.force,
      onProgress: (progress) => {
        if (
          progress.rowsProcessed - lastLogged >= 5000 ||
          progress.rowsProcessed === progress.rowsTotal
        ) {
          p.log.step(
            `${progress.rowsProcessed.toLocaleString()}/${progress.rowsTotal.toLocaleString()} rows`,
          )
          lastLogged = progress.rowsProcessed
        }
      },
    })

    if (!result.completed) {
      p.log.warn(
        `Stopped before completion. ${result.rowsProcessed.toLocaleString()} rows processed. Re-run to resume.`,
      )
      p.outro('Paused.')
      return
    }

    if (eqlVersion === 3) {
      p.note(
        `EQL v3 has no cut-over. Next:\n  1. Point your application at ${encryptedColumn} (schema + queries), deploy, verify reads.\n  2. Generate the plaintext drop: stash encrypt drop --table ${options.table} --column ${plaintextColumn}`,
        'Next steps (EQL v3)',
      )
    }
    p.outro(
      `Backfill complete. ${result.rowsProcessed.toLocaleString()} rows encrypted.`,
    )
  } catch (error) {
    if (error instanceof BackfillConfigError) {
      // Author-controlled diagnostic — safe to print verbatim and tells
      // the user exactly what to fix. Does not include any row data.
      p.log.error(error.message)
    } else {
      // Generic message only — `error.message` may include plaintext sample
      // values bubbled up from the encryption pipeline (e.g. the leak guard
      // in @cipherstash/migrate now emits type-only diagnostics, but
      // upstream libraries can still embed offending input in their
      // exception text). Preserve exit behaviour but stop the message path
      // from leaking sensitive data.
      p.log.error(
        `Backfill failed${error instanceof Error && /^[\w. -]+$/.test(error.name) ? ` (${error.name})` : ''}. Re-run with diagnostic logging if you need details.`,
      )
    }
    exitCode = 1
  } finally {
    process.off('SIGINT', onSignal)
    process.off('SIGTERM', onSignal)
    db?.release()
    await pool.end()
  }
  if (exitCode) process.exit(exitCode)
}

/**
 * Tagged error class for misconfigurations we detect ourselves (e.g. a
 * `--schema-column-key` that does not exist in the schema). Messages on
 * these errors are author-controlled and safe to print in full — unlike
 * upstream encryption errors, which can embed plaintext samples and are
 * suppressed by the catch block in {@link backfillCommand}.
 */
class BackfillConfigError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BackfillConfigError'
  }
}

/**
 * Pick the schema-column key for this physical column. The drizzle
 * helper (`extractEncryptionSchema`) keys by the physical encrypted name;
 * handwritten `encryptedTable(...)` schemas key by whatever the author
 * wrote (typically plaintext). Honour `--schema-column-key`; otherwise
 * prefer encrypted, fall back to plaintext, and throw a
 * {@link BackfillConfigError} listing the schema's available keys when
 * neither candidate is present.
 */
function resolveSchemaColumnKey(opts: {
  columns: Record<string, ColumnSchema>
  tableName: string
  plaintextColumn: string
  encryptedColumn: string
  override: string | undefined
}): string {
  const { columns, override, encryptedColumn, plaintextColumn, tableName } =
    opts
  const available = Object.keys(columns).join(', ') || '(none)'

  if (override !== undefined) {
    if (!(override in columns)) {
      throw new BackfillConfigError(
        `--schema-column-key "${override}" is not declared in the encryption schema for table "${tableName}". Available keys: ${available}.`,
      )
    }
    return override
  }

  if (encryptedColumn in columns) return encryptedColumn
  if (plaintextColumn in columns) return plaintextColumn

  throw new BackfillConfigError(
    `Could not resolve a schema column key for ${tableName}.${plaintextColumn} (encrypted twin: ${encryptedColumn}). The encryption schema for this table declares: ${available}. Pass --schema-column-key <name> with one of those keys.`,
  )
}

/**
 * Build a coercer that turns whatever the `pg` driver returns for a given
 * column into the JS shape `bulkEncryptModels` expects, based on the
 * schema's declared `cast_as`. Fixes the common "pg returns numeric as
 * string, Protect wants a JS number" mismatch without forcing the user
 * to set a global pg type parser.
 *
 * - `'number'` / `'double'` / `'real'` / `'int'` etc. → `Number(string)`
 * - `'bigint'` / `'big_int'` → `BigInt(string)`
 * - `'date'` → `new Date(string)` if pg returned a string
 * - `'boolean'` → `"true"`/`"false"` strings coerced to bool
 * - `'string'` / `'text'` / `'json'` / `'jsonb'` → identity (pg already fits)
 *
 * Null / undefined are always passed through unchanged.
 */
function buildPlaintextCoercer(castAs: string | undefined): {
  transform: (value: unknown) => unknown
  castAs: string | undefined
} {
  const transform = (() => {
    switch (castAs) {
      case 'number':
      case 'double':
      case 'real':
      case 'float':
      case 'decimal':
      case 'int':
      case 'small_int':
        return (v) => {
          if (v === null || v === undefined) return v
          return typeof v === 'string' ? Number(v) : v
        }
      case 'bigint':
      case 'big_int':
        return (v) => {
          if (v === null || v === undefined) return v
          if (typeof v === 'bigint') return v
          if (typeof v === 'number' || typeof v === 'string') return BigInt(v)
          return v
        }
      case 'date':
      case 'timestamp':
        return (v) => {
          if (v === null || v === undefined) return v
          if (v instanceof Date) return v
          if (typeof v === 'string' || typeof v === 'number') return new Date(v)
          return v
        }
      case 'boolean':
        return (v) => {
          if (v === null || v === undefined) return v
          if (typeof v === 'boolean') return v
          if (typeof v === 'string') return v === 'true' || v === 't'
          return v
        }
      default:
        // 'string', 'text', 'json', 'jsonb', or unknown — pg already returns
        // the right JS type for these.
        return (v: unknown) => v
    }
  })()

  return { transform, castAs }
}

async function detectPkColumn(
  db: pg.PoolClient,
  tableName: string,
): Promise<string> {
  const [schema, table] = tableName.includes('.')
    ? tableName.split('.')
    : [null, tableName]

  const result = await db.query<{ column_name: string }>(
    `SELECT a.attname AS column_name
     FROM pg_index i
     JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
     JOIN pg_class c ON c.oid = i.indrelid
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE i.indisprimary
       AND c.relname = $1
       AND ($2::text IS NULL OR n.nspname = $2)
     ORDER BY a.attnum ASC`,
    [table, schema],
  )

  if (result.rows.length === 0) {
    throw new Error(
      `Could not detect a primary key on ${tableName}. Pass --pk-column <name>.`,
    )
  }
  if (result.rows.length > 1) {
    throw new Error(
      `${tableName} has a composite primary key; composite keys are not yet supported. Pass --pk-column <name> to override.`,
    )
  }
  return result.rows[0]?.column_name
}

/**
 * Confirm the application is dual-writing before running backfill, and
 * record the `dual_writing` event in `cs_migrations` so subsequent runs
 * (resume / re-run) skip the prompt.
 *
 * Three paths:
 * - Already in `dual-writing` (or beyond) per `cs_migrations` — no-op,
 *   return true. The user has confirmed before, the event log is the
 *   bookmark.
 * - Interactive TTY with no prior `dual_writing` event — prompt the user;
 *   on yes, append the event and return true.
 * - Non-interactive or `--confirm-dual-writes-deployed` with no prior
 *   event — print a loud reminder of the precondition, append the event,
 *   return true.
 *
 * Returns false when the user declines. Caller exits cleanly.
 */
async function ensureDualWritesDeployed(
  db: pg.PoolClient,
  opts: { table: string; column: string; confirmFlag: boolean },
): Promise<boolean> {
  const last = await progress(db, opts.table, opts.column)

  // Already advanced past `schema-added` — the bookmark is recorded.
  if (last && last.phase !== 'schema-added') return true

  const isInteractive =
    Boolean(process.stdin.isTTY) && process.env.CI !== 'true'

  if (opts.confirmFlag) {
    p.log.warn(
      `Proceeding under --confirm-dual-writes-deployed. You are asserting that every code path that writes to ${opts.table}.${opts.column} now also writes the encrypted twin. If that is not true, rows inserted during the backfill will land in plaintext only and you will need to re-run with --force later to recover.`,
    )
  } else if (isInteractive) {
    p.log.info(
      `${opts.table}.${opts.column} has no \`dual_writing\` event yet — backfill requires your application to already write to both \`${opts.column}\` (plaintext) and \`${opts.column}_encrypted\` (ciphertext) on every insert/update.`,
    )
    const ok = await p.confirm({
      message: `Has the dual-write code been deployed for ${opts.table}.${opts.column}?`,
      initialValue: false,
    })
    if (p.isCancel(ok) || !ok) return false
  } else {
    p.log.error(
      `${opts.table}.${opts.column} has no recorded \`dual-writing\` transition. Re-run with --confirm-dual-writes-deployed once your application is writing to both columns.`,
    )
    return false
  }

  await appendEvent(db, {
    tableName: opts.table,
    columnName: opts.column,
    event: 'dual_writing',
    phase: 'dual-writing',
  })
  p.log.success(
    `${opts.table}.${opts.column} marked as 'dual-writing' in cs_migrations.`,
  )
  return true
}

function buildManifestEntry(
  column: ColumnSchema | undefined,
  schemaColumnKey: string,
  plaintextColumn: string,
  encryptedColumn: string,
  pkColumn: string | undefined,
  eqlVersion: EqlVersion | null,
): ManifestColumn {
  // SDK `cast_as` ('string', 'number', …) and EQL `castAs` ('text',
  // 'double', …) are different vocabularies; translate via the same
  // helper `stash db push` uses so the two stay aligned.
  const castAs: ManifestColumn['castAs'] =
    column?.cast_as !== undefined
      ? translateCastAs(
          column.cast_as,
          `"${schemaColumnKey}" (plaintext: "${plaintextColumn}")`,
        )
      : 'text'

  const indexConfig = column?.indexes ?? {}
  const indexes = (['unique', 'match', 'ore', 'ste_vec'] as const).filter(
    (kind) => indexConfig[kind] !== undefined,
  )

  const entry: ManifestColumn = {
    column: plaintextColumn,
    castAs,
    indexes,
    // Recorded so later commands (cutover/drop/status) don't have to guess
    // the name from the `<column>_encrypted` convention — the name is a
    // convention only, never relied upon.
    encryptedColumn,
    // v2's ladder ends with the rename cut-over; v3 has none — its end
    // state is the plaintext column dropped. An unclassified column (null,
    // which now includes a legacy v2 domain) takes the v2 ladder.
    targetPhase: eqlVersion === 3 ? 'dropped' : 'cut-over',
  }
  if (pkColumn) entry.pkColumn = pkColumn
  // Absent means the classifier returned null: the column isn't there, isn't
  // an EQL domain, or carries the legacy `eql_v2_encrypted` domain (which
  // `classifyEqlDomain` no longer recognises — v3 is the sole authored
  // generation). Readers fall back to the live domain type, which yields null
  // for those same three cases, so `encrypt status` reports no version rather
  // than guessing one. Manifests written before v2 classification was dropped
  // still carry `eqlVersion: 2`, so existing v2 columns keep their version;
  // only a v2 column backfilled from here on records none.
  if (eqlVersion) entry.eqlVersion = eqlVersion
  return entry
}

// Drop the wrapping default so unknown values fail validation instead of
// being silently coerced to `'text'`. Reuses `castAsEnum` so this list
// stays in lockstep with the SDK as new types are added.
const sdkCastAsEnum = castAsEnum.removeDefault()

function translateCastAs(
  raw: unknown,
  where: string,
): ManifestColumn['castAs'] {
  const parsed = sdkCastAsEnum.safeParse(raw)
  if (!parsed.success) {
    throw new BackfillConfigError(
      `Encryption schema for column ${where} declares cast_as: ${JSON.stringify(raw)}, which is not one of the supported SDK data types (${sdkCastAsEnum.options.join(', ')}). Fix the .dataType(...) call in your encryption client.`,
    )
  }
  return toEqlCastAs(parsed.data)
}
