import { Encryption } from '@cipherstash/stack'
import type {
  EncryptedTable,
  EncryptedTableColumn,
} from '@cipherstash/stack/schema'
import type { UnmodelledColumn } from './introspect'
import { eqlRequiresQueryDomains, introspect } from './introspect'
import { EncryptedQueryBuilderImpl } from './query-builder'
import { EncryptedQueryBuilderV3Impl } from './query-builder-v3'
import { mergeDeclaredTables, synthesizeTables } from './schema-builder'
import type {
  EncryptedQueryBuilder,
  EncryptedSupabaseConfig,
  EncryptedSupabaseInstance,
  EncryptedSupabaseV3Instance,
  EncryptedSupabaseV3Options,
  SupabaseClientLike,
  TypedEncryptedSupabaseV3Instance,
  V3Schemas,
} from './types'
import { verifyDeclaredSchemas } from './verify'

/**
 * Create an encrypted Supabase wrapper that transparently handles encryption
 * and decryption for queries on encrypted columns.
 *
 * @param config - Configuration containing the encryption client and Supabase client.
 * @returns An object with a `from()` method that mirrors `supabase.from()` but
 *   auto-encrypts mutations, adds `::jsonb` casts, encrypts filter values, and
 *   decrypts results.
 *
 * @example
 * ```typescript
 * import { Encryption } from '@cipherstash/stack'
 * import { encryptedSupabase } from '@cipherstash/stack-supabase'
 * import { encryptedTable, encryptedColumn } from '@cipherstash/stack/schema'
 *
 * const users = encryptedTable('users', {
 *   name: encryptedColumn('name').freeTextSearch().equality(),
 *   email: encryptedColumn('email').freeTextSearch().equality(),
 * })
 *
 * const client = await Encryption({ schemas: [users] })
 * const eSupabase = encryptedSupabase({ encryptionClient: client, supabaseClient: supabase })
 *
 * // INSERT - auto-encrypts, auto-converts to PG composite
 * await eSupabase.from('users', users)
 *   .insert({ name: 'John', email: 'john@example.com', age: 30 })
 *
 * // SELECT with filter - auto-casts ::jsonb, auto-encrypts search term, auto-decrypts
 * const { data } = await eSupabase.from('users', users)
 *   .select('id, email, name')
 *   .eq('email', 'john@example.com')
 * ```
 */
export function encryptedSupabase(
  config: EncryptedSupabaseConfig,
): EncryptedSupabaseInstance {
  const { encryptionClient, supabaseClient } = config

  return {
    from<T extends Record<string, unknown> = Record<string, unknown>>(
      tableName: string,
      schema: EncryptedTable<EncryptedTableColumn>,
    ) {
      return new EncryptedQueryBuilderImpl<T>(
        tableName,
        schema,
        encryptionClient,
        supabaseClient,
      )
    },
  }
}

/**
 * Throw if `tableName` carries an EQL v3 column this SDK version cannot model.
 *
 * Such a column is a silent data leak: it never enters the encrypt config, but
 * it IS in `allColumns`, so `select('*')` selects it and `decryptModel` skips
 * it — the caller gets raw ciphertext typed as data. (Writes fail loudly on the
 * domain CHECK; only reads are silent.)
 *
 * Keyed by table, not applied to the whole schema, because the hazard exists
 * only for a table the caller actually queries. An `audit_log.payload
 * public.eql_v3_json_search` column on a table you never name cannot leak, and must not stop
 * you constructing a client for `users`.
 */
function assertTableIsModelled(
  tableName: string,
  unmodelled: Map<string, UnmodelledColumn[]>,
): void {
  const columns = unmodelled.get(tableName)
  if (!columns?.length) return
  const detail = columns
    .map((c) => `"${tableName}.${c.columnName}" (public.${c.domainName})`)
    .join(', ')
  throw new Error(
    `[supabase v3]: table "${tableName}" has EQL v3 columns this @cipherstash/stack version does not model: ${detail}. Upgrade the package, or stop using this table — the columns cannot be plaintext passthroughs (reads would return ciphertext undecrypted).`,
  )
}

/**
 * Create an encrypted Supabase wrapper for **EQL v3** schemas by introspecting
 * the database at connect time. Detects EQL v3 columns by their Postgres domain
 * and derives each column's encryption config from it — callers no longer pass a
 * schema to `from()`. Supplying `schemas` is optional: it adds compile-time
 * types and verifies the declared tables against the database at construction.
 *
 * Requires a Postgres connection (`options.databaseUrl` or `DATABASE_URL`) for
 * introspection, so it cannot run in a Worker or the browser.
 *
 * A column is an EQL v3 column when its type is one of the `public` domains the
 * EQL v3 bundle installs. The domain names the capabilities, and introspection
 * turns it into the column's encryption config:
 *
 * ```sql
 * CREATE TABLE users (
 *   id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 *   email public.eql_v3_text_search,  -- equality, ordering, free-text match
 *   age   public.eql_v3_integer_ord,  -- equality, ordering
 *   name  text                 -- plaintext passthrough, untouched
 * );
 * ```
 *
 * @example
 * ```typescript
 * const supabase = await encryptedSupabaseV3(supabaseUrl, supabaseKey)
 * await supabase.from('users').insert({ email: 'alice@example.com' })
 * const { data } = await supabase.from('users').select().eq('email', 'alice@example.com')
 * ```
 */
export async function encryptedSupabaseV3<S extends V3Schemas>(
  supabaseUrl: string,
  supabaseKey: string,
  options: EncryptedSupabaseV3Options<S> & { schemas: S },
): Promise<TypedEncryptedSupabaseV3Instance<S>>
export async function encryptedSupabaseV3(
  supabaseUrl: string,
  supabaseKey: string,
  options?: EncryptedSupabaseV3Options,
): Promise<EncryptedSupabaseV3Instance>
export async function encryptedSupabaseV3<S extends V3Schemas>(
  supabaseClient: SupabaseClientLike,
  options: EncryptedSupabaseV3Options<S> & { schemas: S },
): Promise<TypedEncryptedSupabaseV3Instance<S>>
export async function encryptedSupabaseV3(
  supabaseClient: SupabaseClientLike,
  options?: EncryptedSupabaseV3Options,
): Promise<EncryptedSupabaseV3Instance>
// The implementation's option params are `EncryptedSupabaseV3Options<V3Schemas |
// undefined>`, NOT `<V3Schemas>`. The no-schemas overloads take
// `EncryptedSupabaseV3Options` — i.e. `<undefined>`, whose `schemas` is typed
// `undefined` — and TS2394s against an implementation param whose `schemas` is
// typed `V3Schemas`. Widening the type argument to the full constraint makes
// every overload relatable to the implementation signature.
export async function encryptedSupabaseV3(
  clientOrUrl: SupabaseClientLike | string,
  keyOrOptions?: string | EncryptedSupabaseV3Options<V3Schemas | undefined>,
  maybeOptions?: EncryptedSupabaseV3Options<V3Schemas | undefined>,
): Promise<
  EncryptedSupabaseV3Instance | TypedEncryptedSupabaseV3Instance<V3Schemas>
> {
  // 1. Resolve the Supabase client + options from the overload shape.
  let supabaseClient: SupabaseClientLike
  let options: EncryptedSupabaseV3Options<V3Schemas | undefined>
  if (typeof clientOrUrl === 'string') {
    const url = clientOrUrl
    const key = keyOrOptions as string
    options = maybeOptions ?? {}
    // `@supabase/supabase-js` is an optional peer: the url+key overload needs it
    // to construct a client, but the (client) overload does not. Remap a missing
    // install to an actionable message, matching `loadPg`. Guard on `err.code`
    // (CJS `MODULE_NOT_FOUND`, ESM `ERR_MODULE_NOT_FOUND`), not message text.
    let createClient: (url: string, key: string) => unknown
    try {
      ;({ createClient } = await import('@supabase/supabase-js'))
    } catch (err) {
      const code = (err as { code?: string }).code
      if (code !== 'MODULE_NOT_FOUND' && code !== 'ERR_MODULE_NOT_FOUND')
        throw err
      throw new Error(
        "[supabase v3]: encryptedSupabaseV3(url, key) needs '@supabase/supabase-js' " +
          'to build the client, but that optional peer dependency is not installed. ' +
          'Install it (`npm install @supabase/supabase-js`), or pass an existing ' +
          'client: encryptedSupabaseV3(supabaseClient, options).',
        { cause: err },
      )
    }
    supabaseClient = createClient(url, key) as unknown as SupabaseClientLike
  } else {
    supabaseClient = clientOrUrl
    options =
      (keyOrOptions as EncryptedSupabaseV3Options<V3Schemas | undefined>) ?? {}
  }

  // 2. Resolve the database URL for introspection.
  const databaseUrl = options.databaseUrl ?? process.env.DATABASE_URL
  if (!databaseUrl) {
    throw new Error(
      '[supabase v3]: no database URL — pass options.databaseUrl or set the DATABASE_URL environment variable',
    )
  }

  // 3. Introspect. Unmodelled EQL columns are NOT a construction-time veto —
  //    they are checked per table, at the point the caller names one.
  const { tables, unmodelled, eqlVersion } = await introspect(databaseUrl)
  const queryDomainsRequired = eqlRequiresQueryDomains(eqlVersion)

  // 4. Synthesize; if declared, guard record keys, verify, then merge.
  //    A DECLARED table is one the caller named, so it is validated eagerly,
  //    before the encryption client is built.
  let synth = synthesizeTables(tables)
  if (options.schemas) {
    for (const [key, table] of Object.entries(options.schemas)) {
      if (key !== table.tableName) {
        throw new Error(
          `[supabase v3]: schemas key "${key}" does not match its table name "${table.tableName}" — the record key must equal the table's name`,
        )
      }
      assertTableIsModelled(key, unmodelled)
    }
    verifyDeclaredSchemas(options.schemas, tables)
    synth = mergeDeclaredTables(synth, options.schemas)
  }

  // 5. Build the raw (eqlVersion 3) encryption client from the merged tables.
  //    NB: `Encryption`, not `EncryptionV3` — the query builder consumes the raw
  //    chainable `EncryptionClient`, whereas `EncryptionV3` returns the typed
  //    wrapper whose `decryptModel` returns a plain Promise<Result>. Pass only
  //    tables that carry at least one encrypted column (`Encryption` requires a
  //    non-empty schema list).
  const encryptionSchemas = [...synth.tables.values()].filter(
    (t) => Object.keys(t.columnBuilders).length > 0,
  )

  // A database with no modelled EQL v3 columns anywhere would hand `Encryption`
  // an empty array, which throws "[encryption]: At least one encryptedTable must
  // be provided to initialize the encryption client" (encryption/index.ts:693).
  // That message is about a caller-supplied schema list the caller never
  // supplied — actively misleading here. Fail with a diagnosis instead. The
  // realistic causes are: EQL v3 is not installed, the tables live outside the
  // `public` schema, or the columns were never migrated to `eql_v3` domains.
  if (encryptionSchemas.length === 0) {
    throw new Error(
      '[supabase v3]: no EQL v3 encrypted columns found in schema "public". ' +
        'Check that EQL v3 is installed (`stash eql install --eql-version 3`) ' +
        'and that at least one column uses an eql_v3 domain type.',
    )
  }

  const encryptionClient = await Encryption({
    schemas: encryptionSchemas as unknown as Parameters<
      typeof Encryption
    >[0]['schemas'],
    config: { ...options.config, eqlVersion: 3 },
  })

  // 6. Return the instance. `from` resolves the introspected/merged table and
  //    threads the full column list for select('*'). Casts are localized to the
  //    builder/instance boundary (this-chaining does not match structurally),
  //    NOT `as any` — the four overloads above remain the caller-facing contract.
  const instance = {
    from(tableName: string) {
      const table = synth.tables.get(tableName)
      if (!table) {
        throw new Error(
          `[supabase v3]: unknown table "${tableName}" — it was not found during introspection`,
        )
      }
      // Unconditional: `synthesizeTables` silently drops unmodelled columns, so
      // this is the only thing preventing `select('*')` from returning raw
      // ciphertext for one. Never make it optional.
      assertTableIsModelled(tableName, unmodelled)
      const allColumns = synth.allColumns.get(tableName) ?? null
      return new EncryptedQueryBuilderV3Impl(
        tableName,
        table,
        encryptionClient,
        supabaseClient,
        allColumns,
        queryDomainsRequired,
      ) as unknown as EncryptedQueryBuilder<Record<string, unknown>>
    },
  }
  return instance as unknown as
    | EncryptedSupabaseV3Instance
    | TypedEncryptedSupabaseV3Instance<V3Schemas>
}

export type {
  EncryptedQueryBuilder,
  EncryptedQueryBuilderCore,
  EncryptedQueryBuilderV3,
  EncryptedQueryBuilderV3Untyped,
  EncryptedSupabaseConfig,
  EncryptedSupabaseError,
  EncryptedSupabaseInstance,
  EncryptedSupabaseResponse,
  EncryptedSupabaseV3Instance,
  EncryptedSupabaseV3Options,
  PendingOrCondition,
  SupabaseClientLike,
  TypedEncryptedSupabaseV3Instance,
  V3FilterableKeys,
  V3FreeTextSearchableKeys,
  V3Schemas,
} from './types'
