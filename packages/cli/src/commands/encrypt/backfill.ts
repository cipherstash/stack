import { loadStashConfig } from '@/config/index.js'
import { runBackfill } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { loadEncryptionContext, requireTable } from './context.js'

/**
 * Options accepted by `stash encrypt backfill`. Each field maps 1:1 to a
 * CLI flag of the same name (kebab-case at the CLI boundary).
 */
export interface BackfillCommandOptions {
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
  p.intro('npx @cipherstash/cli encrypt backfill')

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
  process.on('SIGINT', onSignal)
  process.on('SIGTERM', onSignal)

  const db = await pool.connect()
  try {
    const pkColumn =
      options.pkColumn ?? (await detectPkColumn(db, options.table))

    const plaintextColumn = options.column
    const encryptedColumn =
      options.encryptedColumn ?? `${options.column}_encrypted`
    // The EncryptedTable schema is keyed by the *encrypted* column name
    // (because the user's ORM schema declares the encrypted column, not
    // the plaintext one). Default accordingly — override with
    // --schema-column-key only if your schema uses a different object key.
    const schemaColumnKey = options.schemaColumnKey ?? encryptedColumn

    const { transform: transformPlaintext, castAs: detectedCastAs } =
      buildPlaintextCoercer(tableSchema, schemaColumnKey)

    // protect-ffi's JsPlaintext wire enum currently has 4 variants:
    // String / Number / Boolean / JsonB. Date and Timestamp columns are
    // typed on the Rust side (NaiveDate / DateTime<Utc>) but there is no
    // JS-visible wire format for them, so any JS Date is serialised to
    // an ISO string by napi-rs and the Rust side then refuses it because
    // string values only bind to Utf8Str columns. Warn before wasting
    // time running a backfill that will fail on the first chunk.
    if (detectedCastAs === 'date' || detectedCastAs === 'timestamp') {
      p.log.warn(
        `Column ${options.table}.${encryptedColumn} declares cast_as: '${detectedCastAs}', which protect-ffi does not currently support for encryption. The backfill will fail with "Cannot convert String to Date". Consider changing the schema to dataType: 'string' (or omitting dataType) and storing ISO date strings instead, then re-running \`stash db push\`.`,
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

    p.outro(
      `Backfill complete. ${result.rowsProcessed.toLocaleString()} rows encrypted.`,
    )
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : 'Backfill failed.')
    process.exit(1)
  } finally {
    process.off('SIGINT', onSignal)
    process.off('SIGTERM', onSignal)
    db.release()
    await pool.end()
  }
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
function buildPlaintextCoercer(
  // biome-ignore lint/suspicious/noExplicitAny: EncryptedTableLike.build is generic
  tableSchema: { build(): { columns: Record<string, any> } },
  schemaColumnKey: string,
): { transform: (value: unknown) => unknown; castAs: string | undefined } {
  let castAs: string | undefined
  try {
    castAs = tableSchema.build().columns?.[schemaColumnKey]?.cast_as
  } catch {
    castAs = undefined
  }

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
