import { Encryption } from '@cipherstash/stack'
import type { UnmodelledColumn } from './introspect'
import { eqlRequiresQueryDomains, introspect } from './introspect'
import { EncryptedQueryBuilderImpl } from './query-builder'
import { mergeDeclaredTables, synthesizeTables } from './schema-builder'
import type {
  EncryptedQueryBuilderUntyped,
  EncryptedSupabaseInstance,
  EncryptedSupabaseOptions,
  SupabaseClientLike,
  TypedEncryptedSupabaseInstance,
  V3Schemas,
} from './types'
import { verifyDeclaredSchemas } from './verify'

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
 * Create an encrypted Supabase wrapper over **native EQL v3 column domains** by
 * introspecting the database at connect time. Detects EQL v3 columns by their
 * Postgres domain and derives each column's encryption config from it — callers
 * do not pass a schema to `from()`. Supplying `schemas` is optional: it adds
 * compile-time types and verifies the declared tables against the database at
 * construction.
 *
 * Encrypted data is stored as EQL v3 payloads. The generation-agnostic decrypt
 * path in `@cipherstash/stack` still reads existing EQL v2 payloads, but this
 * wrapper only AUTHORS EQL v3 — the legacy v2 authoring surface (a hand-written
 * client-side schema and `from(tableName, schema)`) has been removed.
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
 * const supabase = await encryptedSupabase(supabaseUrl, supabaseKey)
 * await supabase.from('users').insert({ email: 'alice@example.com' })
 * const { data } = await supabase.from('users').select().eq('email', 'alice@example.com')
 * ```
 */
export async function encryptedSupabase<S extends V3Schemas>(
  supabaseUrl: string,
  supabaseKey: string,
  options: EncryptedSupabaseOptions<S> & { schemas: S },
): Promise<TypedEncryptedSupabaseInstance<S>>
export async function encryptedSupabase(
  supabaseUrl: string,
  supabaseKey: string,
  options?: EncryptedSupabaseOptions,
): Promise<EncryptedSupabaseInstance>
export async function encryptedSupabase<S extends V3Schemas>(
  supabaseClient: SupabaseClientLike,
  options: EncryptedSupabaseOptions<S> & { schemas: S },
): Promise<TypedEncryptedSupabaseInstance<S>>
export async function encryptedSupabase(
  supabaseClient: SupabaseClientLike,
  options?: EncryptedSupabaseOptions,
): Promise<EncryptedSupabaseInstance>
// The implementation's option params are `EncryptedSupabaseOptions<V3Schemas |
// undefined>`, NOT `<V3Schemas>`. The no-schemas overloads take
// `EncryptedSupabaseOptions` — i.e. `<undefined>`, whose `schemas` is typed
// `undefined` — and TS2394s against an implementation param whose `schemas` is
// typed `V3Schemas`. Widening the type argument to the full constraint makes
// every overload relatable to the implementation signature.
export async function encryptedSupabase(
  clientOrUrl: SupabaseClientLike | string,
  keyOrOptions?: string | EncryptedSupabaseOptions<V3Schemas | undefined>,
  maybeOptions?: EncryptedSupabaseOptions<V3Schemas | undefined>,
): Promise<
  EncryptedSupabaseInstance | TypedEncryptedSupabaseInstance<V3Schemas>
> {
  // 1. Resolve the Supabase client + options from the overload shape.
  let supabaseClient: SupabaseClientLike
  let options: EncryptedSupabaseOptions<V3Schemas | undefined>
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
        "[supabase v3]: encryptedSupabase(url, key) needs '@supabase/supabase-js' " +
          'to build the client, but that optional peer dependency is not installed. ' +
          'Install it (`npm install @supabase/supabase-js`), or pass an existing ' +
          'client: encryptedSupabase(supabaseClient, options).',
        { cause: err },
      )
    }
    supabaseClient = createClient(url, key) as unknown as SupabaseClientLike
  } else {
    supabaseClient = clientOrUrl
    options =
      (keyOrOptions as EncryptedSupabaseOptions<V3Schemas | undefined>) ?? {}
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
      return new EncryptedQueryBuilderImpl(
        tableName,
        table,
        encryptionClient,
        supabaseClient,
        allColumns,
        queryDomainsRequired,
      ) as unknown as EncryptedQueryBuilderUntyped<Record<string, unknown>>
    },
  }
  return instance as unknown as
    | EncryptedSupabaseInstance
    | TypedEncryptedSupabaseInstance<V3Schemas>
}

/**
 * @deprecated Use {@link encryptedSupabase}. `encryptedSupabaseV3` is a
 * type-identical alias kept for existing imports; the `V3` suffix is redundant
 * now that EQL v3 is the only generation this wrapper authors.
 */
export const encryptedSupabaseV3 = encryptedSupabase

export type {
  EncryptedQueryBuilder,
  EncryptedQueryBuilderCore,
  EncryptedQueryBuilderUntyped,
  // Deprecated `*V3` aliases (Decision 5 — supabase keeps type-identical aliases).
  EncryptedQueryBuilderV3,
  EncryptedQueryBuilderV3Untyped,
  EncryptedSupabaseError,
  EncryptedSupabaseInstance,
  EncryptedSupabaseOptions,
  EncryptedSupabaseResponse,
  EncryptedSupabaseV3Instance,
  EncryptedSupabaseV3Options,
  FilterableKeys,
  FreeTextSearchableKeys,
  PendingOrCondition,
  SupabaseClientLike,
  TypedEncryptedSupabaseInstance,
  TypedEncryptedSupabaseV3Instance,
  V3FilterableKeys,
  V3FreeTextSearchableKeys,
  V3Schemas,
} from './types'
