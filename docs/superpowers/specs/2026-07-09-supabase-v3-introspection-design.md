# Supabase v3 adapter: schema introspection at connect time

**Status:** design
**Date:** 2026-07-09
**Package:** `@cipherstash/stack/supabase`

## Summary

`encryptedSupabaseV3` becomes a connect-time-async factory that reads the
database schema, detects EQL v3 columns by their Postgres domain, and derives
each column's encryption config from its domain. Callers stop passing a schema
to `from()`.

```ts
const supabase = await encryptedSupabaseV3(supabaseUrl, supabaseKey)

await supabase.from('users').insert({ email: 'alice@example.com' })

const { data } = await supabase
  .from('users')
  .select()
  .eq('email', 'alice@example.com')
```

Declaring schemas remains available, and adds compile-time types plus
startup verification of the database against the declaration.

## Motivation

Today both `encryptedSupabase` and `encryptedSupabaseV3` require the caller to
build an `EncryptionClient`, build a Supabase client, and pass a schema object
to every `from()` call. For v3 the schema object is largely redundant: a v3
column's Postgres domain (`public.text_search`, `public.integer_ord`, …) *is*
its encryption config. The database already holds every fact the adapter needs.

## Background: how the v2 adapter works

`encryptedSupabase({ encryptionClient, supabaseClient })` returns an object with
one member, `from(tableName, schema)`, constructing an
`EncryptedQueryBuilderImpl`. That builder mirrors supabase-js's chainable
surface, but every method is a *recorder* — it pushes onto `this.filters` /
`this.transforms` / `this.mutation` and returns `this`. Nothing executes.

The builder is `PromiseLike`. Awaiting it calls `execute()`
(`query-builder.ts:343`), which:

1. Encrypts mutation data (`encryptModel` / `bulkEncryptModels`), then wraps
   each value as `{ data: … }` for the `eql_v2_encrypted` composite.
2. Builds the select string, appending `::jsonb` to encrypted columns.
   `select('*')` throws — there is no column list to cast.
3. Walks the filter buckets, collects encryptable terms into a flat `terms[]`
   with a parallel `termMap[]` recording provenance, and batch-encrypts them in
   one `encryptQuery()` call.
4. Replays the recorded chain onto the real Supabase builder, substituting
   encrypted values where a term existed.
5. Decrypts result rows.

The schema is consulted for exactly three things: the set of encrypted column
**names**, the column **builder** for each name (which carries the index
config), and the **table** object as encryption context.

`EncryptedQueryBuilderV3Impl` overrides protected seams on this machinery —
full-envelope filter operands, raw jsonb mutation payloads, `like` → `cs`,
property↔DB name resolution, `Date` reconstruction from `cast_as`. The
recording and replay machinery is shared.

Only the three schema lookups change under this design. The query mechanism
does not.

## Design

### 1. Load the type

Every v3 domain is `CREATE DOMAIN public.<name> AS jsonb`. For a domain column,
`information_schema.columns` populates `domain_schema` and `domain_name`; both
`data_type` and `udt_name` report the *base* type.

Measured against Postgres 17 (spike, 2026-07-09):

| column | `data_type` | `udt_name` | `domain_schema` | `domain_name` |
|---|---|---|---|---|
| `id serial` | integer | int4 | — | — |
| `email spike.text_search` | jsonb | jsonb | spike | text_search |
| `note text` | text | text | — | — |
| `meta jsonb` | jsonb | jsonb | — | — |

Three consequences:

- **`domain_name` is unqualified**, with `domain_schema` returned separately.
- **`udt_name` is `jsonb`**, so the v2 detection
  (`udt_name === 'eql_v2_encrypted'`,
  `packages/cli/src/commands/init/lib/introspect.ts:88`) cannot be adapted by
  swapping the compared string — it would compare against `jsonb` forever.
  `eql_v2_encrypted` has `typtype = 'c'` (composite), which is why it surfaces
  in `udt_name`; domains surface in `domain_name`.
- **A plain `jsonb` column has `domain_name` NULL**, so encrypted and
  unencrypted jsonb columns are cleanly distinguishable. A domain carrying a
  `CHECK` constraint — as every EQL domain does — reports identically to one
  without.

```sql
SELECT c.table_name, c.column_name, c.domain_name
FROM information_schema.columns c
JOIN information_schema.tables t
  ON t.table_name = c.table_name AND t.table_schema = c.table_schema
WHERE c.table_schema = 'public'
  AND t.table_type = 'BASE TABLE'
ORDER BY c.table_name, c.ordinal_position
```

Plaintext columns are retained, not filtered out. This buys three things:

- `from('unknown_table')` throws rather than silently passing through.
- A table with zero encrypted columns is a *known* passthrough.
- `select('*')` becomes expandable — emit the full column list with `::jsonb` on
  the encrypted ones — so the current `select('*')` throw is removed.

A `domain_name` absent from the registry (a user's own domain, or a newer EQL
release) is treated as plaintext. Not an error.

### 2. Use the type

`packages/stack/src/eql/v3/columns.ts` defines 47 domain constants, each
`{ eqlType, castAs, capabilities }`. `public.integer_ord` is
`castAs: 'number'`, order-and-range. That *is* the encryption config.

Add a `DOMAIN_REGISTRY: Record<string, (name: string) => AnyEncryptedV3Column>`
keyed by unqualified domain name, whose values are the **existing `types`
factories** (`eql/v3/types.ts`) rather than direct `new EncryptedXColumn(...)`
calls. The factories pass the literal domain constants
(`Integer: (name) => new EncryptedIntegerColumn(name, INTEGER)`), and that
literal is what keeps the domains nominally distinct. Constructing the classes
directly would create a second source of truth for exactly the thing the class
comments warn about drifting. `types.TextSearch` has a different arity —
`(name) => new EncryptedTextSearchColumn(name)`, no constant — so the registry
maps values, not a mechanical transform.

**Key normalization.** `eqlType` is qualified (`'public.text_search'`), while
`information_schema` returns `domain_schema = 'public'` and
`domain_name = 'text_search'` as separate columns. The registry is keyed on the
unqualified name; the exhaustiveness test must strip the `public.` prefix from
each `eqlType` before comparing, or it will pass while matching nothing.

A test asserts every `eqlType` in `columns.ts` has a registry entry, and that
each entry round-trips: `registry[strip(eqlType)]('c').getEqlType() === eqlType`.

Introspected rows group by table into synthesized `EncryptedTable` instances,
which feed `EncryptionV3({ schemas })`.

Because introspection yields DB column names directly, the JS property name
equals the DB column name. `propToDb` is the identity, and the `prop:db::jsonb`
aliasing branch in `addJsonbCastsV3` becomes a no-op for synthesized tables. It
stays in place for declared tables, which may still map `createdAt → created_on`.

### 3. Construction

```ts
type V3Schemas = Record<string, AnyV3Table>

type EncryptedSupabaseV3Options<S extends V3Schemas | undefined = undefined> = {
  /** Defaults to `process.env.DATABASE_URL`. */
  databaseUrl?: string
  /** Passed through to `EncryptionV3`. */
  config?: ClientConfig
  /** Optional. See "Optional schemas". */
  schemas?: S
}

// url + key
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

// existing client
export async function encryptedSupabaseV3<S extends V3Schemas>(
  supabaseClient: SupabaseClientLike,
  options: EncryptedSupabaseV3Options<S> & { schemas: S },
): Promise<TypedEncryptedSupabaseV3Instance<S>>
export async function encryptedSupabaseV3(
  supabaseClient: SupabaseClientLike,
  options?: EncryptedSupabaseV3Options,
): Promise<EncryptedSupabaseV3Instance>
```

The `schemas`-bearing overload precedes the bare one in declaration order, so
TypeScript selects it whenever `schemas` is present and infers `S` from the
value.

The factory creates (or accepts) a Supabase client, introspects over
`databaseUrl ?? process.env.DATABASE_URL`, synthesizes tables, builds the
encryption client via `EncryptionV3`, and returns `{ from(tableName) }`.

Accepting an existing client is required: SSR apps hand the adapter a client
that already carries an auth session, and `withLockContext` depends on that
identity.

If neither `databaseUrl` nor `DATABASE_URL` is present, throw at construction
with a message naming both.

`from()` resolves the table from the introspected map and passes the synthesized
`EncryptedTable` to `EncryptedQueryBuilderV3Impl`, unchanged.

### 4. Optional schemas

Types cannot be derived from an `await`. Introspection runs at runtime, so
`from('users')` sees only a string literal at compile time. Deriving the schema
from the database therefore *necessarily* costs compile-time type safety.

The resolution is to invert introspection's role when a schema is supplied: it
verifies rather than derives.

```ts
const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  amount: types.IntegerOrd('amount'),
  active: types.Boolean('active'),
})

const supabase = await encryptedSupabaseV3(url, key, { schemas: { users } })
```

`from('users')` still takes no schema argument. The instance is generic over
`typeof schemas`, so the table name is constrained to the declared keys and the
builder resolves to `EncryptedQueryBuilderV3<S[K], InferPlaintext<S[K]>>`.

This mirrors `createClient<Database>(url, key)` — schema on the client, naked
`from()` — except the generic is inferred from a value rather than supplied by
hand. It matches Drizzle's `drizzle(client, { schema })`.

Two overloads:

- **Without `schemas`** — `from(tableName: string)` accepts an optional row
  generic, returning the untyped builder. Rows are `Record<string, unknown>`.
- **With `schemas: S`** — `from<K extends keyof S & string>(table: K)` returns
  `EncryptedQueryBuilderV3<S[K], InferPlaintext<S[K]>>`.

Adoption is a **gradient**, not a switch: declare one table, leave the rest
introspected. Declared tables get types; undeclared tables behave exactly as
they would with no `schemas` at all.

#### Verification

For every declared column, assert the column exists and its introspected
`domain_name` matches the declared `eqlType`. Mismatch throws at construction,
naming table, column, declared domain, and actual domain.

`types.TextSearch('email')` against a column that is actually `public.text_eq`
fails at startup, instead of a `23514` CHECK violation on the first query.
Neither the current code nor codegen offers this: codegen'd types are correct
only until the next migration.

Declaring a table that does not exist, or a column that does not exist, is an
error. Declaring a *subset* of a table's encrypted columns is not — undeclared
columns are synthesized from their domains.

#### Runtime effect of declaring

For 46 of the 47 domains, a synthesized column and a declared column emit a
**byte-identical** encrypt config. `columns.ts` defines 42 subclasses and
exactly one `override build()`; every other class inherits

```ts
build(): ColumnSchema {
  return {
    cast_as: this.definition.castAs,
    indexes: indexesForCapabilities(this.definition.capabilities, this.definition.castAs),
  }
}
```

— a pure function of `{ castAs, capabilities }`, which is a pure function of the
domain name. Declaring such a column adds types and verification, nothing else.

`EncryptedTextSearchColumn` (`columns.ts:470`) is the sole exception: it carries
`matchOpts` and overrides `build()` to replace the `match` index block. Its
constructor initialises `defaultMatchOpts()`, and `indexesForCapabilities`
(`columns.ts:355`) emits the same defaults for the freeTextSearch capability —
so even a `text_search` column is byte-identical when synthesized, **unless the
caller invoked `.freeTextSearch(opts)`**.

Therefore the rule is:

- **Column declared** — verify the domain matches, then use the *declared*
  builder, which carries any tuned match options.
- **Column not declared** — synthesize from the introspected domain.

The single observable consequence: the `include_original: false` caveat
documented on `EncryptedQueryBuilderV3Impl` can only be honoured on a declared
`text_search` column. Substring `like` against an undeclared `text_search`
column will not match, because the default `include_original: true` puts the
whole pattern into the bloom filter as an extra token.

This asymmetry must be documented on the `schemas` option, not only here.

### 5. Dependencies

`pg` becomes a dependency of the Supabase entrypoint. It is already a CLI
dependency. Declare it as an optional peer and load it with a dynamic import so
bundlers do not pull it in unless introspection runs.

This means `encryptedSupabaseV3` cannot run in a Worker or the browser: it needs
a Postgres socket. That is a real narrowing of where the adapter runs, and it is
inherent to introspecting at connect time. Supplying `schemas` does not avoid
it — verification still connects.

## Components

| Unit | Responsibility | Depends on |
|---|---|---|
| `eql/v3/domain-registry.ts` | `domain_name` → column factory | `eql/v3/types` (the `types` factories) |
| `supabase/introspect.ts` | Read `information_schema`, return tables + columns + domains | `pg` |
| `supabase/schema-builder.ts` | Rows → `EncryptedTable[]`; merge declared over synthesized | registry, `eql/v3/table` |
| `supabase/verify.ts` | Declared schema vs introspected reality | introspect output |
| `supabase/index.ts` | Factory: client, introspect, verify, `EncryptionV3`, `from()` | all of the above |

`query-builder.ts` and `query-builder-v3.ts` are unchanged apart from removing
the `select('*')` throw and threading the full column list for expansion.

## Data flow

```
encryptedSupabaseV3(url, key, { schemas? })
  ├─ createClient(url, key)            (or accept a client)
  ├─ introspect(databaseUrl)           → [{ table, column, domain_name }]
  ├─ registry lookup                   → synthesized EncryptedTable[]
  ├─ if schemas: verify + override     → declared builders win
  ├─ EncryptionV3({ schemas: tables }) → EncryptionClient
  └─ { from(tableName) }               → EncryptedQueryBuilderV3Impl
```

## Error handling

| Condition | Behaviour |
|---|---|
| No `databaseUrl` and no `DATABASE_URL` | Throw at construction, naming both |
| Introspection connection failure | Throw at construction, with the pg error |
| Declared table absent from database | Throw, naming the table |
| Declared column absent from table | Throw, naming table + column |
| Declared domain ≠ actual domain | Throw, naming both domains |
| Unknown `domain_name` in database | Treated as plaintext, no error |
| `from()` on an unknown table | Throw, naming the table |
| Filter on storage-only column | Compile error if declared; runtime throw otherwise (existing behaviour, `query-builder-v3.ts:180`) |

## Testing

- **Unit** — `DOMAIN_REGISTRY` exhaustiveness against every `eqlType` in
  `columns.ts`. Rows → `EncryptedTable[]` grouping. Verification: match,
  wrong-domain, missing column, missing table. Declared-over-synthesized
  override, including that a declared `TextSearch` retains its tuner options.
- **Live Postgres** — introspection against a table with mixed encrypted and
  plaintext columns, asserting the domain→builder round-trip.

  **Setup dependency.** The compose image (`postgres-eql:17-2.3.1`,
  `local/docker-compose.yml`) reports `eql_v3.version()` as `DEV` but contains
  **zero domains** in `public` — the concrete-domain surface is absent. The 47
  domains exist only after applying this branch's
  `packages/cli/src/sql/cipherstash-encrypt-v3.sql`. Live introspection tests
  must apply that SQL first, as the existing v3 pg tests do; they cannot run
  against the stock image.
- **Wire encoding** — existing `supabase-v3-builder.test.ts` mock-client tests
  continue to pass unchanged, with the builder constructed from a synthesized
  table rather than a declared one.
- **Types** — `supabase-v3.test-d.ts` splits: the existing four guarantees are
  re-pinned under `{ schemas }`, and a new block asserts the untyped surface
  without `schemas` (rows are `Record<string, unknown>`; `from` accepts any
  string).

## Out of scope

- **Codegen.** `stash gen types` emitting the v3 table objects from the same
  `information_schema` query. The API does not change when it lands — callers
  stop hand-writing `users` and import it instead. Deferred deliberately: make
  it work before generating it.
- **v2.** `encryptedSupabase` keeps its current signature and behaviour.
- **PostgREST-only introspection.** Neither `@supabase/supabase-js` nor
  `@supabase/postgrest-js` exposes any introspection API (verified: no
  `openapi`/`swagger`/`introspect` surface in either package; `schema()` only
  swaps the `Accept-Profile` header). PostgREST's OpenAPI root document is the
  only non-Postgres runtime source, and whether it names a column's domain or
  flattens it to `jsonb` is unverified. If it names the domain, a future
  increment can drop the `pg` dependency and restore Worker/browser support.
