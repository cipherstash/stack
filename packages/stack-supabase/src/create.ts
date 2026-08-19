import { hasBuildColumnKeyMap, logger } from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { IntrospectionData, UnmodelledColumn } from './introspect'
import { EncryptedQueryBuilderImpl } from './query-builder'
import type { SynthesizedSchema } from './schema-builder'
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
 * The core of `encryptedSupabase`, with the encryption client factory left
 * open (#708).
 *
 * Two entry points bind it: `./index` supplies `Encryption` from the native
 * `@cipherstash/stack` entry, and `./wasm-inline` supplies it from
 * `@cipherstash/stack/wasm-inline`. Everything else about the wrapper is
 * identical, so it lives here once. The split exists because the native entry
 * statically imports `@cipherstash/protect-ffi` — a Node-API binary that
 * cannot load on an edge runtime — and a static import loads whether or not
 * the code path is taken.
 *
 * Every `@cipherstash/stack` import in this module is either type-only or on a
 * native-free subpath (`adapter-kit`, `eql/v3`, `encryption` types). A value
 * import of the package root here would defeat the entire split by pulling the
 * native binary back into the wasm bundle.
 *
 * The type is written structurally rather than as `typeof Encryption` because
 * the two factories genuinely differ: the wasm one requires its `config`
 * (a `WasmClientConfig` carrying explicit `CS_*` credentials, since there is no
 * `~/.cipherstash` to discover on an edge runtime), while the native one
 * defaults it. Only the shape used here is shared, so only that shape is
 * named, and each entry casts its own factory to it.
 */
export type EncryptionFactory = (config: {
  schemas: readonly AnyV3Table[]
  config?: unknown
}) => Promise<EncryptionClient>

/**
 * Database introspection, injected for the same reason the encryption factory
 * is — and with the same consequence if it were not.
 *
 * `introspect` reaches `pg` through a dynamic `import('pg')`. A dynamic import
 * is still a *specifier in the bundle*: statically importing this module would
 * put `import("pg")` into the edge build, where a bundler resolves it at build
 * time and fails on a dependency that runtime will never have. Injecting it
 * keeps the specifier out of the wasm entry's graph entirely, which is a
 * property that can be asserted on the emitted file rather than hoped for.
 */
export interface Introspector {
  introspect(databaseUrl: string): Promise<IntrospectionData>
  eqlRequiresQueryDomains(version: string | null | undefined): boolean
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
 * Bind {@link construct} to one encryption-client factory, producing the
 * `encryptedSupabase` a given entry point exports.
 */
export function makeEncryptedSupabase(
  createEncryptionClient: EncryptionFactory,
  introspector: Introspector | null,
): EncryptedSupabaseFactory {
  return ((
    clientOrUrl: SupabaseClientLike | string,
    keyOrOptions?: string | EncryptedSupabaseOptions<V3Schemas | undefined>,
    maybeOptions?: EncryptedSupabaseOptions<V3Schemas | undefined>,
  ) =>
    construct(
      createEncryptionClient,
      introspector,
      clientOrUrl,
      keyOrOptions,
      maybeOptions,
    )) as EncryptedSupabaseFactory
}

/**
 * Create an encrypted Supabase wrapper over **native EQL v3 column domains** by
 * introspecting the database at connect time. Detects EQL v3 columns by their
 * Postgres domain and derives each column's encryption config from it — callers
 * do not pass a schema to `from()`. Supplying `schemas` is optional: it adds
 * compile-time types and verifies the declared tables against the database at
 * construction.
 *
 * Encrypted data is stored as EQL v3 payloads. This wrapper is EQL v3 only — it
 * both authors and reads v3, and the legacy v2 authoring surface (a hand-written
 * client-side schema and `from(tableName, schema)`) has been removed. It does
 * not auto-read an `eql_v2_encrypted` column: introspection recognises the
 * `public.eql_v3_*` domains exclusively, so a v2 column never enters the
 * encrypt config and is returned as an untouched passthrough. No v2 ciphertext
 * is stranded — decryption in `@cipherstash/stack` is generation-agnostic, so
 * legacy payloads still decrypt through the core client (`decrypt` /
 * `decryptModel`). Handle mixed-generation data explicitly on the caller side.
 *
 * **Declare your schemas and it runs anywhere; omit them and we discover them
 * for you, which needs a database connection and is therefore Node-only.**
 * Passing `schemas` skips introspection entirely — no Postgres connection, no
 * `pg`, no `databaseUrl` — at the cost of the drift check and of `select('*')`,
 * which is refused because nothing enumerated the table's plaintext columns.
 * Pass `databaseUrl` alongside `schemas` to keep both.
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
export interface EncryptedSupabaseFactory {
  <S extends V3Schemas>(
    supabaseUrl: string,
    supabaseKey: string,
    options: EncryptedSupabaseOptions<S> & { schemas: S },
  ): Promise<TypedEncryptedSupabaseInstance<S>>
  (
    supabaseUrl: string,
    supabaseKey: string,
    options?: EncryptedSupabaseOptions,
  ): Promise<EncryptedSupabaseInstance>
  <S extends V3Schemas>(
    supabaseClient: SupabaseClientLike,
    options: EncryptedSupabaseOptions<S> & { schemas: S },
  ): Promise<TypedEncryptedSupabaseInstance<S>>
  (
    supabaseClient: SupabaseClientLike,
    options?: EncryptedSupabaseOptions,
  ): Promise<EncryptedSupabaseInstance>
}

/**
 * Read `DATABASE_URL` without assuming a `process` global exists.
 *
 * On Workers, Deno isolates and Edge Functions there is no `process`, and a
 * bare `process.env.DATABASE_URL` is a `ReferenceError` rather than
 * `undefined` — so an unguarded read throws during construction, before
 * declared mode gets the chance to make the connection unnecessary. Same
 * defect class the adapter-kit logger carried (#799).
 */
function readDatabaseUrlFromEnv(): string | undefined {
  return typeof process === 'undefined' ? undefined : process.env?.DATABASE_URL
}

/**
 * The starting point for declared mode: no tables, and — deliberately — no
 * `allColumns`.
 *
 * `allColumns` is the full column list per table, and only introspection can
 * produce it. Leaving it empty is what makes `select('*')` fail closed instead
 * of silently selecting a subset: the query builder throws when a table has no
 * entry, so the caller is told to list columns rather than handed a query that
 * quietly omits the plaintext ones.
 */
function emptySchema(): SynthesizedSchema {
  return { tables: new Map(), allColumns: new Map() }
}

// The implementation's option params are `EncryptedSupabaseOptions<V3Schemas |
// undefined>`, NOT `<V3Schemas>`. The no-schemas call signatures take
// `EncryptedSupabaseOptions` — i.e. `<undefined>`, whose `schemas` is typed
// `undefined` — so widening the type argument to the full constraint is what
// makes every signature relatable to this implementation.
async function construct(
  createEncryptionClient: EncryptionFactory,
  introspector: Introspector | null,
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
    if (clientOrUrl === null || typeof clientOrUrl !== 'object') {
      throw new Error(
        '[supabase v3]: encryptedSupabase expected a Supabase client with a from() method. Pass encryptedSupabase(supabaseClient, options), or use encryptedSupabase(url, key, options).',
      )
    }
    if ('encryptionClient' in clientOrUrl && 'supabaseClient' in clientOrUrl) {
      throw new Error(
        '[supabase v3]: encryptedSupabase({ encryptionClient, supabaseClient }) was the removed EQL v2 API. Pass the Supabase client directly instead: encryptedSupabase(supabaseClient, { databaseUrl, schemas? }).',
      )
    }
    if (typeof clientOrUrl.from !== 'function') {
      throw new Error(
        '[supabase v3]: encryptedSupabase expected a Supabase client with a from() method. Pass encryptedSupabase(supabaseClient, options), or use encryptedSupabase(url, key, options).',
      )
    }
    supabaseClient = clientOrUrl
    options =
      (keyOrOptions as EncryptedSupabaseOptions<V3Schemas | undefined>) ?? {}
  }

  // 2. Resolve the database URL — but only if we are going to introspect.
  //
  //    DECLARED MODE (#708). When the caller passes `schemas` they have already
  //    told us every encrypted column, so introspection has nothing left to
  //    discover and the connection it needs is pure cost: a second, more
  //    privileged credential on Node, and a hard blocker anywhere a TCP socket
  //    to Postgres is unavailable. Skipping it is what makes this wrapper
  //    constructible outside Node.
  //
  //    `process` is read through a guard, not directly: on a runtime with no
  //    `process` global a bare `process.env.X` is a ReferenceError, not
  //    `undefined`, so the unguarded read would throw during construction
  //    before any of the logic below ran (same defect class as the adapter-kit
  //    logger, #799).
  //    The ambient `DATABASE_URL` fallback applies ONLY when nothing was
  //    declared. Two failures come from letting it apply in declared mode
  //    (#708 review): on the edge entry, a project secret named DATABASE_URL —
  //    which Deno exposes through `process.env` — makes construction throw
  //    "drop databaseUrl" about an option the caller never passed; and on Node
  //    it would introspect and drift-verify a database the caller never named.
  //    Declaring your tables is an explicit statement that this client does not
  //    need a connection, so an environment variable must not overrule it.
  const declared = options.schemas
  const ambientDatabaseUrl = readDatabaseUrlFromEnv()
  const databaseUrl =
    options.databaseUrl ?? (declared ? undefined : ambientDatabaseUrl)
  if (!databaseUrl && !declared) {
    throw new Error(
      '[supabase v3]: no database URL — pass options.databaseUrl or set the DATABASE_URL environment variable. Alternatively pass `schemas` to declare your tables, which skips introspection entirely and needs no Postgres connection.',
    )
  }
  //    ...but say so, rather than changing mode in silence.
  //
  //    Two different callers land here and neither should land silently. One
  //    passed `schemas` deliberately and wants no connection. The other was
  //    already passing `schemas` while `DATABASE_URL` supplied the connection,
  //    and has just deployed somewhere that variable is missing — before this
  //    change that was a construction-time throw, and now it is a working
  //    client with no drift check. Nothing distinguishes them at this point,
  //    so both get told.
  //
  //    Gated on `introspector`, not on the ambient value: on the edge entry
  //    declared mode is the ONLY mode, so the warning would be noise on every
  //    cold start. On the native entry it is a choice between two modes, which
  //    is exactly when saying which one you got is worth a line.
  if (declared && !options.databaseUrl && introspector) {
    logger.warn(
      `[supabase v3]: no database URL, so \`schemas\` were taken as a complete declaration and no introspection ran — the declared tables are NOT verified against the database, and any encrypted column missing from the declaration is treated as plaintext.${
        ambientDatabaseUrl
          ? ' A DATABASE_URL is set but was deliberately ignored, because declaring your tables says this client needs no connection.'
          : ''
      } Pass \`databaseUrl\` explicitly to introspect and verify.`,
    )
  }

  // 3. Introspect, unless declared mode made it unnecessary. Unmodelled EQL
  //    columns are NOT a construction-time veto — they are checked per table,
  //    at the point the caller names one.
  //
  //    The gate is the database URL, NOT the absence of `schemas`: a caller
  //    who passes both still gets introspection, and therefore still gets the
  //    drift check that verifies their declaration against the database. That
  //    keeps every existing `schemas`-passing caller exactly as it was, and
  //    makes "pass `databaseUrl` as well" the way to keep verification while
  //    declaring types. Declared mode is the case where no URL resolves at all.
  //
  //    With no introspection there is no observed `eqlVersion` to derive from,
  //    so query domains are FORCED rather than detected. Forcing is the
  //    fail-loud direction: on EQL >= 3.0.2 it is simply correct, and on an
  //    older install the operand cast fails visibly instead of silently
  //    emitting an operator the database will not engage.
  //
  //    An entry with no introspector cannot honour a database URL at all, so
  //    say that rather than ignoring the option the caller passed.
  if (databaseUrl && !introspector) {
    throw new Error(
      '[supabase v3]: this build of encryptedSupabase cannot introspect — it is the edge entry (`@cipherstash/stack-supabase/wasm-inline`), which carries no Postgres driver. Declare your tables with `schemas` and drop `databaseUrl`, or import the default entry on Node.',
    )
  }
  const introspection =
    databaseUrl && introspector
      ? await introspector.introspect(databaseUrl)
      : null
  const unmodelled =
    introspection?.unmodelled ?? new Map<string, UnmodelledColumn[]>()
  const queryDomainsRequired =
    introspection && introspector
      ? introspector.eqlRequiresQueryDomains(introspection.eqlVersion)
      : true

  // 4. Synthesize; if declared, guard record keys, verify, then merge.
  //    A DECLARED table is one the caller named, so it is validated eagerly,
  //    before the encryption client is built.
  let synth = introspection
    ? synthesizeTables(introspection.tables)
    : emptySchema()
  if (options.schemas) {
    for (const [key, table] of Object.entries(options.schemas)) {
      if (key !== table.tableName) {
        throw new Error(
          `[supabase v3]: schemas key "${key}" does not match its table name "${table.tableName}" — the record key must equal the table's name`,
        )
      }
      // A v2 `EncryptedTable` carries `tableName` and `columnBuilders` exactly
      // as a v3 one does, so nothing above this distinguishes them and the
      // types only catch it for callers who are actually type-checking. Left
      // unguarded it reached `verifyDeclaredSchemas`, which calls
      // `builder.getEqlType()` — absent on a v2 column — and died as
      // `builder.getEqlType is not a function`: an internal method name, from
      // a caller's perspective unrelated to the mistake they made.
      if (!hasBuildColumnKeyMap(table)) {
        throw new Error(
          `[supabase v3]: schemas entry "${key}" is an EQL v2 table — it has no buildColumnKeyMap(), the marker every v3 table carries. This adapter is EQL v3 only. Author the table with \`encryptedTable\`/\`types\` from \`@cipherstash/stack/eql/v3\`.`,
        )
      }
      assertTableIsModelled(key, unmodelled)
    }
    // Verification compares the declaration against the database, so it is
    // only possible when we read the database. In declared mode the drift it
    // would have caught — a column whose real domain differs from the declared
    // one — surfaces instead as a 23514 CHECK violation on the first write.
    // Callers who want it back pass `databaseUrl` ALONGSIDE `schemas`, which
    // keeps introspection and therefore keeps this check.
    if (introspection) {
      verifyDeclaredSchemas(options.schemas, introspection.tables)
    }
    synth = mergeDeclaredTables(synth, options.schemas)
  }

  // 5. Build the raw (eqlVersion 3) encryption client from the merged tables.
  //    NB: the query builder consumes the raw chainable `EncryptionClient`, and
  //    calls `decryptModel(row)` with no table — the typed client degrades to
  //    nominal (passthrough) behaviour for that arity, so either shape works.
  //    Pass only tables that carry at least one encrypted column (`Encryption`
  //    requires a non-empty schema list).
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
      introspection
        ? '[supabase v3]: no EQL v3 encrypted columns found in schema "public". ' +
            'Check that EQL v3 is installed (`stash eql install --supabase`) ' +
            'and that at least one column uses an eql_v3 domain type.'
        : '[supabase v3]: the `schemas` you declared contain no encrypted columns. ' +
            'Declare at least one column with a `types.*` factory from ' +
            '`@cipherstash/stack/eql/v3`, or omit `schemas` and pass `databaseUrl` ' +
            'to discover them by introspection.',
    )
  }

  const encryptionClient = await createEncryptionClient({
    schemas:
      encryptionSchemas as unknown as Parameters<EncryptionFactory>[0]['schemas'],
    config: options.config,
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
          introspection
            ? `[supabase v3]: unknown table "${tableName}" — it was not found during introspection`
            : `[supabase v3]: unknown table "${tableName}" — it is not in the \`schemas\` you declared. In declared mode there is no introspection to discover it, so every table you query must be declared.`,
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
