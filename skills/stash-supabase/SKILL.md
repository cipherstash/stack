---
name: stash-supabase
description: Integrate CipherStash encryption with Supabase using @cipherstash/stack-supabase. Covers the encryptedSupabaseV3 wrapper over native EQL v3 column domains, transparent encryption/decryption on insert/update/select, encrypted query filters (eq, matches, gt/gte/lt/lte, in, or, match), encrypted JSON querying (contains, selectorEq/selectorNe), ordering on encrypted columns, identity-aware encryption, and the complete query builder API. Use when adding encryption to a Supabase project, querying encrypted columns, or building secure Supabase applications.
---

# CipherStash Stack - Supabase Integration

Guide for integrating CipherStash field-level encryption with Supabase using
the `encryptedSupabaseV3` wrapper over native EQL v3 column domains. The
wrapper provides transparent encryption on mutations and decryption on
selects, with full support for querying encrypted columns — equality, range,
fuzzy free-text search, encrypted JSON containment and selectors, and
ordering.

A legacy EQL v2 wrapper (`encryptedSupabase`) still ships for existing
deployments — see "Legacy: EQL v2" at the end. New projects should use
`encryptedSupabaseV3`.

## When to Use This Skill

- Adding field-level encryption to a Supabase project
- Querying encrypted data with Supabase's query builder (eq, matches, gt, in, or, etc.)
- Querying encrypted JSON documents (containment, path selectors)
- Inserting, updating, or upserting encrypted data
- Using identity-aware encryption (lock contexts) with Supabase
- Building applications where sensitive columns need encryption at rest and in transit

## Installation

```bash
npm install @cipherstash/stack @cipherstash/stack-supabase @supabase/supabase-js
```

> **Version note:** `npx stash init` is the preferred install path — it pins
> every `@cipherstash/*` package to the versions matching your CLI release.
> If you install manually as above, verify what actually resolved
> (`node -p "require('@cipherstash/stack/package.json').version"`): bare
> dist-tag installs can lag behind a release, and `stash init` will warn on
> the version skew.

The Supabase integration ships as its own first-party package,
`@cipherstash/stack-supabase`, which depends on `@cipherstash/stack`. Install both.

## Setup

**Credentials first:** for local development run `npx stash init` (the
agent-assisted flow — auth, schema, and database end to end) or
`npx stash auth login` (device code flow; no environment variables needed).
CI and production use the `CS_*` machine-credential environment variables —
see the `stash-encryption` skill's Configuration section. Mint them from your
device session with `npx stash env --name <name>` (no dashboard copy-paste);
this is also how **Supabase Edge Functions** get credentials in local dev —
`supabase functions serve` runs in a container that cannot see
`~/.cipherstash`, so write the vars to a file with
`stash env --name edge-dev --write` and pass `--env-file`, or
`supabase secrets set` them for deploys.

### 1. Install EQL v3 on the database

```bash
stash eql install --eql-version 3 --supabase
```

Since eql-3.0.0 there is **one** v3 SQL artifact for every target — there is
no separate Supabase variant. The bundle's only superuser-requiring
statements (the ORE operator class/family) skip themselves when the install
role lacks the privilege, and the bundle then disables the ORE-opclass-backed
domains it cannot support. `--supabase` changes one thing: it additionally
applies the role grants for `anon` / `authenticated` / `service_role` to the
two schemas the bundle creates — `eql_v3` (the operator-backing functions)
and `eql_v3_internal` (SEM internals). Without the grants, encrypted queries
fail loudly with a permission error (e.g. `permission denied for schema
eql_v3_internal`).

No **Exposed schemas** change is needed: the column domains and their
operators live in `public`, so bare `col = term` filters resolve under
Supabase's default PostgREST configuration. Do not expose `eql_v3_internal`.

### 2. Database schema (per-domain columns)

Each encrypted column is declared with a concrete `public.eql_v3_*` domain —
the domain encodes both the plaintext type and the column's query
capabilities. There is no extension to enable and no generic `jsonb` column:

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email public.eql_v3_text_search,        -- eq + range + free-text search
  amount public.eql_v3_integer_ord,       -- eq + range
  joined_at public.eql_v3_timestamp_ord,  -- eq + range, decrypts to Date
  payload public.eql_v3_json,             -- encrypted JSON document
  role VARCHAR(50),                       -- regular plaintext column
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

The `types.*` member name (see declared schemas below) maps to the flat
`public.eql_v3_<name>` domain — strip the `eql_v3_` prefix and PascalCase
each `_`-separated segment: `types.TextEq` → `public.eql_v3_text_eq`,
`types.IntegerOrd` → `public.eql_v3_integer_ord`. The domains use
SQL-standard type names (`integer`, `smallint`, `real`, `double`, `boolean`,
`timestamp`).

### 3. Initialize the wrapper

```typescript
import { encryptedSupabaseV3 } from "@cipherstash/stack-supabase"

// Introspects the database via options.databaseUrl or DATABASE_URL
const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey)
// or wrap an existing client: await encryptedSupabaseV3(supabaseClient, options)

await es.from("users").insert({ email: "a@b.com", amount: 30 })
await es.from("users").select("id, email, amount").eq("email", "a@b.com")
```

`encryptedSupabaseV3` **introspects the database at connect time**: it
detects EQL v3 columns by their Postgres domain, derives each column's
encryption config from the domain, and builds the encryption client
internally — there is no client-side schema to hand-maintain. Introspection
needs a direct Postgres connection (`options.databaseUrl`, defaulting to
`DATABASE_URL`), so the factory cannot run in a Worker or the browser.

Options: `{ schemas?, databaseUrl?, config? }` — `config` is the encryption
client config (e.g. `config.authStrategy`, see Authentication below).

`from(tableName)` takes only the table name — no schema argument. Column
capabilities come from the introspected domains.

### 4. Optional declared schemas (compile-time types)

Declaring tables is optional. Passing `schemas` — a record whose keys must
equal each table's name — adds compile-time types and verifies the declared
tables against the database at construction:

```typescript
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"
import { encryptedSupabaseV3 } from "@cipherstash/stack-supabase"

const users = encryptedTable("users", {
  email:  types.TextSearch("email"),      // public.eql_v3_text_search — eq + range + free-text
  amount: types.IntegerOrd("amount"),     // public.eql_v3_integer_ord — eq + range
  joined: types.TimestampOrd("joined_at") // public.eql_v3_timestamp_ord — eq + range, decrypts to Date
})

const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey, {
  schemas: { users },
})

const { data } = await es.from("users").select("id, email, joined").eq("email", "a@b.com")
```

A declared table gets a typed builder: rows infer each column's plaintext
type (`types.IntegerOrd` → `number`, `types.TimestampOrd` → `Date`),
storage-only columns are excluded from every filter method, `matches()` is
narrowed to match-indexed columns, and `order()` to orderable columns.
Undeclared tables behave exactly as with no `schemas` at all. Every v3 column
is fully described by its `types.*` factory — there are no capability or
tuning chains on v3 columns.

A JS property may map to a different DB column name
(`joined: types.TimestampOrd("joined_at")`) — filters, selects, and results
are translated automatically, and `date`/`timestamp` columns decrypt to real
`Date` objects.

## Insert (Encrypted Automatically)

```typescript
// Single insert
const { data, error } = await es
  .from("users")
  .insert({
    email: "alice@example.com",  // encrypted automatically
    amount: 30,                  // encrypted automatically
    role: "admin",               // plaintext column, passed through
  })
  .select("id")

// Bulk insert
const { data, error } = await es
  .from("users")
  .insert([
    { email: "alice@example.com", amount: 30, role: "admin" },
    { email: "bob@example.com", amount: 25, role: "user" },
  ])
  .select("id")
```

## Update (Encrypted Automatically)

```typescript
const { data, error } = await es
  .from("users")
  .update({ email: "alice@new.example.com" })  // encrypted automatically
  .eq("id", 1)
  .select("id, email")
```

## Upsert

```typescript
const { data, error } = await es
  .from("users")
  .upsert(
    { id: 1, email: "alice@example.com", role: "admin" },
    { onConflict: "id" },
  )
  .select("id, email")
```

## Select (Decrypted Automatically)

```typescript
// All columns — select('*') (and bare select()) expands to the
// introspected column list
const { data, error } = await es.from("users").select("*")

// Explicit columns
const { data, error } = await es
  .from("users")
  .select("id, email, amount, role")
// data: [{ id: 1, email: "alice@example.com", amount: 30, role: "admin" }]

// Single result
const { data, error } = await es
  .from("users")
  .select("id, email")
  .eq("id", 1)
  .single()

// Maybe single (returns null if no match)
const { data, error } = await es
  .from("users")
  .select("id, email")
  .eq("email", "nobody@example.com")
  .maybeSingle()
// data: null
```

`select()` also accepts an optional second parameter: `select(columns, { head?: boolean, count?: 'exact' | 'planned' | 'estimated' })`.

## Query Filters

All filter values for encrypted columns are automatically encrypted before
the query executes. Filter operands are grouped by column and each column
group takes one `bulkEncrypt` crossing — a query filtering N distinct
encrypted columns makes N ZeroKMS calls, run in parallel.

### Equality Filters

```typescript
// Exact match (requires an equality-capable domain)
.eq("email", "alice@example.com")

// Not equal
.neq("email", "alice@example.com")

// IN array
.in("email", ["alice@example.com", "bob@example.com"])

// NULL check (no encryption needed). Use this for genuine null checks — a
// null operand passed to eq/neq is not rejected; it is forwarded unencrypted.
.is("email", null)
```

### Free-Text Search (`matches`)

```typescript
// Fuzzy bloom token search (requires a match-indexed domain,
// e.g. text_search / text_match). Matches substrings of >= 3 characters.
.matches("email", "alice")
```

`like`/`ilike` on an encrypted column are a **deprecated approximate shim**
that delegates to `matches()` — see "Query behaviour on encrypted columns"
below. On plaintext columns they stay real SQL LIKE. The shim is
**runtime-only**: neither the typed nor the untyped v3 builder interface
declares `like`/`ilike`, so in TypeScript the call is a compile error (use
`matches()`) — the shim is reachable only from plain JavaScript or via a cast.

### Range/Comparison Filters

```typescript
// Requires a range-capable domain (e.g. *_ord, text_search)
.gt("amount", 21)
.gte("amount", 18)
.lt("amount", 65)
.lte("amount", 100)
```

### Match (Multi-Column Equality)

```typescript
.match({ email: "alice@example.com", amount: 30 })
```

### OR Conditions

```typescript
// String format
.or("email.eq.alice@example.com,email.eq.bob@example.com")

// Structured format (more type-safe)
.or([
  { column: "email", op: "eq", value: "alice@example.com" },
  { column: "email", op: "eq", value: "bob@example.com" },
])
```

Both forms encrypt values for encrypted columns automatically.

### NOT Filter

```typescript
.not("email", "eq", "alice@example.com")
```

### Raw Filter

```typescript
.filter("email", "eq", "alice@example.com")
```

## Delete

```typescript
const { data, error } = await es
  .from("users")
  .delete()
  .eq("id", 1)
```

## Transforms

These are passed through to Supabase directly:

```typescript
.order("email", { ascending: true })  // encrypted columns: see behaviour below
.limit(10)
.range(0, 9)
.csv()
.abortSignal(signal)
.throwOnError()
.returns<U>()
```

`order()` works on plaintext columns and on OPE-backed encrypted ordering
columns — see the `order()` bullet in the next section for exactly which
domains qualify.

## Query behaviour on encrypted columns

All envelopes (stored payloads and filter operands) are versioned `v: 3`.

- **`select('*')` (and bare `select()`) works** — it expands to the
  introspected column list.
- **Encrypted free-text search is `matches()`, not `contains()`/`like`/`ilike`.**
  The v3 domains define no LIKE operator — encrypted free-text search is fuzzy
  bloom-filter token matching (PostgREST `cs` / SQL `@>`): one-sided (a match
  may be a false positive, a non-match never is) and order-/multiplicity-
  insensitive, where `%` is tokenized like any other character. `matches(col,
  needle)` is the operator; `contains()` on an encrypted TEXT column throws an
  error pointing at `matches()`. `contains()` is native (exact) jsonb/array
  containment on plaintext columns — and ENCRYPTED (exact) containment on a
  `types.Json` column (see "Encrypted JSON querying" below).
- **`like`/`ilike` on an encrypted column are an approximate compatibility
  shim** delegating to `matches()`: leading/trailing `%` are stripped and the
  residual term is fuzzy-matched (same `cs` wire, plus a one-time warning).
  Results are APPROXIMATE — case-insensitive, one-sided, and anchoring is not
  honored. A pattern with an internal `%` or any `_` cannot be approximated and
  throws; call `matches()` directly to make the fuzzy intent explicit. On
  plaintext columns `like`/`ilike` stay real SQL LIKE. Note the shim is
  reachable only at runtime: `like`/`ilike` are absent from the v3 builder
  interfaces (typed and untyped alike), so on the TypeScript surface the call
  is a compile error — only untyped JavaScript or a cast reaches the shim.
- **`matches()` matches substrings.** The search term blooms to its own
  trigrams, and a row matches when the stored value's bloom contains all of
  them — so any substring of at least 3 characters (the tokenizer's
  `token_length`) matches. Shorter terms bloom to nothing and would match every
  row, so they are rejected with an error rather than answered.
- **INTERIM — filter operands are full storage envelopes.** EQL ships
  term-only query domains (`eql_v3.query_<name>`, which accept envelopes with
  no ciphertext) and the encryption client can mint those narrowed terms, but
  PostgREST has no syntax to cast a filter value — an uncast operand can only
  reach the `jsonb` operator overload, which coerces it into the storage
  domain, whose CHECK requires ciphertext. So the adapter still encrypts each
  filter value with the full storage path. The call shape is unchanged.

  **Security caveat:** query terms are meant to be index-terms-only by
  design, but a full-envelope operand carries a real decryptable ciphertext
  `c` plus **all** of the column's index terms, and PostgREST filters travel
  in GET query strings — so these envelopes can land in URL logs,
  intermediate proxies, and Supabase request logs. The remaining gap is
  PostgREST operand casting; an adapter-side fix is tracked.
- **`order()` works on OPE-backed encrypted ordering columns** (every plain
  `*_ord` domain, plus `text_ord` and `text_search`). PostgREST cannot emit
  `ORDER BY eql_v3.ord_term(col)`, and a bare `ORDER BY` would silently sort
  the raw ciphertext envelope — so the builder instead emits `order=col->op`,
  sorting by the OPE term inside the envelope, which reproduces plaintext
  order (the term is fixed-width lowercase hex, so string comparison agrees
  with the bytea btree; pinned by `ope-term.integration.test.ts`). ORE-flavour
  columns (`*_ord_ore`) are rejected at compile time and runtime — their `ob`
  term needs the superuser-only operator class no jsonb path can reach — and
  columns with no ordering term (storage-only, equality-only, match-only)
  reject `order()` with a clear error. For those, order by a plaintext column
  or sort application-side after decrypting.
- **Storage-only domains are not filterable** (e.g. `types.Boolean`,
  `types.Text`): a filter (including `.match()`) on one is a type error on a
  declared table, and always a clear runtime error. `.is(column, null)`
  remains available.
- **Null filter operands are forwarded unencrypted, not rejected.** A null
  cannot be encrypted into an operand, so the builder skips encryption and
  passes the null through to PostgREST as-is (e.g. a `col=eq.null` filter),
  which is rarely what you want. Use `.is(column, null)` for genuine null
  checks — the builder does not throw.

## Encrypted JSON querying (`types.Json`)

A `types.Json("payload")` column (`public.eql_v3_json`) stores an encrypted
JSONB document and supports two query forms:

```typescript
// Exact encrypted containment: every leaf of the sub-document must match at
// its path (ste_vec `@>` — PostgREST `cs`).
es.from("events").select("id").contains("payload", { user: { role: "admin" } })

// JSONPath selector equality / inequality at a dot-notation path:
es.from("events").select("id").selectorEq("payload", "$.user.role", "admin")
es.from("events").select("id").selectorNe("payload", "$.user.role", "admin")
```

- `selectorEq(col, path, value)` matches rows carrying exactly `value` at
  `path` — it compiles to containment of the path-shaped needle
  (`{user: {role: "admin"}}`), which is the same operation. Paths are
  dot-notation object keys (`"$.a.b"` or `"a.b"`); array/wildcard steps are
  rejected, and values must be JSON scalars — string, number, or boolean (an
  object operand belongs to `contains()`). On Supabase a `Date` or `bigint`
  leaf is rejected with a serialization steer: pass a Date as
  `date.toISOString()` and a bigint as its string/number form. (The Drizzle
  selector accepts Date/bigint directly.)
- `selectorNe` matches rows that do NOT carry the value — **including rows
  where the path is absent entirely, and rows whose document column is SQL
  NULL** (it compiles to `payload.is.null OR payload.not.cs.<needle>`, matching
  the Drizzle selector's `ne` semantics for both absence cases).
- **Array-valued paths:** a scalar needle does NOT match an array at the path —
  ste_vec encodes array elements under their own selectors — so
  `selectorEq("payload", "$.roles", "admin")` does not match
  `{roles: ["admin", "analyst"]}` (and `selectorNe` includes that row). To
  match an array-valued path, pass the full array through `contains()`.
- **Selector ordering (`gt`/`gte`/`lt`/`lte`) is not available on Supabase.**
  PostgREST cannot reach the entry-comparison operators (it wraps JSON arrow
  paths in `to_jsonb`, and bare-column comparison is blocked by design); it
  needs an EQL-bundle overload, tracked in
  cipherstash/encrypt-query-language#407. The Drizzle integration's
  `ops.selector()` supports ordering today — use it where ordering at a path
  is required.
- `matches()` does not apply to JSON columns (it is text free-text search) and
  throws with a steer; scalar filters (`eq`, `gt`, `in`, …) on the column are
  rejected by capability.
- The containment/selector operand is a **full storage envelope** of the
  needle document. The GET-query-string security caveat above applies with an
  important difference in degree: a JSON needle carries the root decryptable
  ciphertext PLUS one ciphertext-bearing entry **per node of the sub-document**
  — the exposure scales with needle size (the equivalent Drizzle containment
  ships no ciphertext at all). Keep needles minimal; removing the ciphertext on
  this surface is tracked in cipherstash/stack#654.
- Empty needles (`{}` / `[]`) are rejected — jsonb containment holds for every
  document, so an accidentally-empty filter would silently return the whole
  table (the Drizzle adapter rejects the same needle).

## Authentication

The encryption client authenticates to ZeroKMS through `config.authStrategy`.
Unset, it uses the default **auto** strategy — the `npx stash auth login`
profile in local development (preferred), `CS_*` environment variables in
CI/production — which is fine for service-level encryption. To authenticate **as the end user**, federate their
third-party OIDC JWT (Clerk, Supabase, Auth0, ...) with
`OidcFederationStrategy`:

```typescript
import { OidcFederationStrategy } from "@cipherstash/stack"
import { encryptedSupabaseV3 } from "@cipherstash/stack-supabase"

const strategy = OidcFederationStrategy.create(
  process.env.CS_WORKSPACE_CRN!,
  () => getUserJwt(), // re-invoked on every (re-)federation
)
if (strategy.failure) throw new Error(strategy.failure.error.message)

const es = await encryptedSupabaseV3(supabaseUrl, supabaseKey, {
  config: { authStrategy: strategy.data },
})
```

Authentication stands on its own — an OIDC-authenticated client runs every
query normally. Binding *data* to the authenticated user is the optional next
step: the lock context.

## Identity-Aware Encryption (Lock Contexts)

Bind the data key to a claim from the end user's JWT by chaining
`.withLockContext({ identityClaim })` on a query. This **requires** an
`OidcFederationStrategy`-authenticated client (above) — the claim's value
resolves from the federated JWT; auto/access-key auth has no user JWT to
resolve claims from. Plain authentication never requires a lock context.

```typescript
const { data, error } = await es
  .from("users")
  .insert({ email: "alice@example.com" })
  .withLockContext({ identityClaim: ["sub"] })
  .select("id")
```

`identityClaim` is an array of JWT claim *names* (`["sub"]`), not values; the same
claim must be used to encrypt and decrypt. `.withLockContext()` also accepts a
`LockContext` instance.

> **Deprecated: `LockContext.identify()`.** Older code did
> `new LockContext().identify(userJwt)` to fetch a per-operation CTS token. Those
> tokens were removed in `protect-ffi` 0.25 and the fetched token is no longer
> used by encryption. Authenticate with `OidcFederationStrategy` and pass the
> claim directly, as above.

## Audit Logging

Chain `.audit()` to attach metadata for ZeroKMS audit logging:

```typescript
const { data, error } = await es
  .from("users")
  .select("id, email")
  .eq("email", "alice@example.com")
  .audit({ metadata: { action: "user-lookup", requestId: "abc-123" } })
```

## Complete Example

```typescript
import { encryptedTable, types } from "@cipherstash/stack/eql/v3"
import { encryptedSupabaseV3 } from "@cipherstash/stack-supabase"

// Optional declared schema — compile-time types. Introspection alone
// (no `schemas`) also works.
const users = encryptedTable("users", {
  email:  types.TextSearch("email"),
  amount: types.IntegerOrd("amount"),
})

const es = await encryptedSupabaseV3(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
  { schemas: { users } }, // databaseUrl defaults to DATABASE_URL
)

// Insert — values encrypted automatically
await es.from("users").insert([
  { email: "alice@example.com", amount: 30 },
  { email: "bob@example.com", amount: 25 },
])

// Query with multiple filters — operands encrypted automatically
const { data } = await es
  .from("users")
  .select("id, email, amount")
  .gte("amount", 18)
  .lte("amount", 35)
  .matches("email", "alice")

// data is fully decrypted:
// [{ id: 1, email: "alice@example.com", amount: 30 }]
```

## Response Type

```typescript
type EncryptedSupabaseResponse<T> = {
  data: T | null                     // Decrypted rows
  error: EncryptedSupabaseError | null
  count: number | null
  status: number
  statusText: string
}
```

Errors can come from Supabase (API errors) or from encryption operations. Check `error.encryptionError` for encryption-specific failures.

The full `EncryptedSupabaseError` type:

```typescript
type EncryptedSupabaseError = {
  message: string
  details?: string       // Supabase error details
  hint?: string          // Supabase error hint
  code?: string          // Supabase/PostgreSQL error code
  encryptionError?: EncryptionError  // CipherStash encryption-specific error
}
```

## Filter to Domain Capability Mapping

The column's `public.eql_v3_*` domain determines which filters it accepts:

| Filter Method | Works On |
|---|---|
| `eq`, `neq`, `in`, `match()` | Equality-capable domains (`*_eq`, `*_ord`, `text_search`) |
| `matches()` (and the runtime-only `like`/`ilike` shim — absent from the TS interfaces) | Match-indexed domains (`text_match`, `text_search`) |
| `gt`, `gte`, `lt`, `lte` | Range-capable domains (`*_ord`, `text_search`) |
| `contains()`, `selectorEq()`, `selectorNe()` | `eql_v3_json` (encrypted); `contains()` is also native containment on plaintext jsonb/array columns |
| `order()` | OPE-backed ordering domains (plain `*_ord`, `text_ord`, `text_search`) — never `*_ord_ore` |
| `is` | Any column (no encryption; NULL check) |

Storage-only domains (e.g. `eql_v3_text`, `eql_v3_boolean`) accept no filters
at all — only `.is(column, null)`.

## Exported Types

`@cipherstash/stack-supabase` also exports the following types:

- `EncryptedSupabaseV3Options`, `EncryptedSupabaseV3Instance`, `TypedEncryptedSupabaseV3Instance`, `EncryptedQueryBuilderV3`, `EncryptedQueryBuilderV3Untyped`, `V3Schemas`
- `SupabaseClientLike`
- `EncryptedSupabaseConfig`, `EncryptedSupabaseInstance`, `EncryptedQueryBuilder`, `PendingOrCondition` (legacy EQL v2)

## Migrating an Existing Column to Encrypted

The hard case: a Supabase table that already exists with live data in a plaintext column you want to encrypt. You can't just change the column type — that would drop the data.

CipherStash splits this into two named steps with a hard production-deploy gate between them: an **encryption rollout** (schema-add + dual-write code) and an **encryption cutover** (backfill + rename + drop). The `stash-encryption` skill is the canonical reference for the lifecycle; this section walks the Supabase-specific shape.

> **EQL version note.** The `stash encrypt *` tooling works with **both EQL versions** and auto-detects a column's version from its Postgres domain type — there is no flag. The lifecycles differ at the end: **v3** (the default, and what this section's schema uses) is `rollout → deploy gate → backfill → switch the app to the encrypted column by name → drop`, with **no cut-over rename**; **v2** finishes with `stash encrypt cutover` (a rename swap plus an `eql_v2_configuration` promotion) before the drop. Running `stash encrypt cutover` on a v3 column reports "not applicable" and exits 0.

> **Using CipherStash Proxy?** If you query encrypted data through [CipherStash Proxy](https://github.com/cipherstash/proxy) instead of the SDK, also run `stash db push` after schema-add and again before cutover to register the encrypted column shape with EQL.

> **Runner note.** `stash init` adds `stash` to the project as a dev dependency, so `stash <command>` runs through whichever package manager the project uses (Bun, pnpm, Yarn, or npm) — examples below show this bare form. Before init has run, prefix with your package manager's one-shot runner: `bunx`, `pnpm dlx`, `yarn dlx`, or `npx`. The CLI's behaviour is identical across all of them.

> **Where am I?** Run `stash status` first (substitute the runner per the note above). It shows you which tables/columns are mid-rollout, which are post-deploy, and what the next move is. Re-run after every transition.

### Starting state

You have:

```sql
-- supabase/migrations/<timestamp>_initial.sql (already applied)
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,             -- plaintext, populated, NOT NULL
  created_at timestamptz DEFAULT now()
);
```

…and an `await supabase.from('users').insert({ email })` somewhere in your app code.

### Step 1 — Encryption rollout (one PR, one deploy)

Everything below lands in one PR. The deploy of that PR is the gate.

#### Schema-add: declare the encrypted twin

Generate a Supabase migration:

```bash
supabase migration new add_users_email_encrypted
```

Edit the generated file to add an `email_encrypted` column **alongside** `email`. The encrypted column must be **nullable** at creation — never `NOT NULL`, because rows that already exist will have NULL in this column until backfill catches them.

```sql
-- supabase/migrations/<timestamp>_add_users_email_encrypted.sql
ALTER TABLE users
  ADD COLUMN email_encrypted public.eql_v3_text_search;  -- nullable
```

Apply with `supabase db reset` locally or `supabase migration up` against the remote project.

No client-side schema change is required — `encryptedSupabaseV3` introspects
the new column's domain at the next client startup. If you use declared
`schemas`, add the column so it is typed:

```typescript
// src/encryption/schema.ts (optional — compile-time types)
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'

export const users = encryptedTable('users', {
  email_encrypted: types.TextSearch('email_encrypted'),
})
```

> **Using CipherStash Proxy?** Register the new encryption config with EQL:
>
> ```bash
> stash db push
> ```
>
> If this is the project's first encrypted column, `db push` writes directly to the active EQL config. If an active config already exists, it writes the new config as `pending` — that's expected. Cutover (later) will promote it.
>
> **SDK users:** Skip this step. Your encryption config lives in app code.

#### Dual-writing: write to both columns from app code

Find **every** code path that writes to `users.email` and update it to also write the encrypted twin. With the v3 wrapper this is a single insert: `email` is a plaintext column and passes through unchanged, while `email_encrypted` is a v3 domain column the wrapper encrypts automatically. Wrap it in one function so callers can't forget one half:

```typescript
// src/db/users.ts
import { es } from './clients' // encryptedSupabaseV3 instance

export async function insertUser(email: string) {
  return es.from('users').insert({
    email,                   // plaintext — keep writing
    email_encrypted: email,  // encrypted twin — new, encrypted automatically
  })
}
```

Same shape for UPDATE: every site that updates `email` must also update `email_encrypted` in the same statement.

**The dual-write rule.** Every persistence path that mutates this row writes both columns, in the same transaction, on every code branch. Insert sites, update sites, upserts, ON CONFLICT clauses, seeders, fixtures, edge functions, RPC functions, admin actions, background jobs, third-party webhooks — all of them. A single missed branch means rows inserted in production after deploy land in plaintext only, and backfill won't catch them. Grep for every site that touches `users.email` before declaring this step done.

After this phase, existing rows still have `email_encrypted = NULL`. Reads still come from `email`. Nothing has broken.

### ⛔ Deploy gate

Stop. Ship this PR to production. The deployed environment must be running the dual-write code before any cutover-step work is safe.

When the deploy is live:

```bash
stash status        # verify the rollout is recorded
stash plan          # detects dual-writes are live; drafts the cutover plan
```

`stash impl` will refuse to run a cutover-step plan if `cs_migrations` has no `dual_writing` event for `users.email`. That refusal is the safety net for cases where someone runs cutover work locally before the code is actually live.

### Step 2 — Encryption cutover

Once dual-writes are live in production and `cs_migrations` records `dual_writing`:

#### Backfill: encrypt the historical rows

```bash
stash encrypt backfill --table users --column email
# (Interactive: answer 'yes' to the dual-write confirmation prompt.)
# (CI: pass --confirm-dual-writes-deployed instead.)
```

Resumable, idempotent, chunked. The CLI walks the table in keyset-pagination order, encrypts each chunk via the encryption client, and writes the ciphertext into `email_encrypted` inside transactions that also checkpoint to `cs_migrations`. SIGINT-safe. It auto-detects whether the column is EQL v2 or v3 and records that in `cs_migrations`.

If something goes wrong (e.g. you discover the dual-write code wasn't actually live when backfill ran), re-run with `--force` to re-encrypt every row regardless of current state.

#### Switch reads to the encrypted column

**EQL v3 (the schema above): there is no cut-over.** The encrypted column keeps
its own name — point your application at `email_encrypted` through the
`encryptedSupabaseV3` wrapper, deploy, verify reads decrypt correctly, then skip
ahead to the drop step. Running `stash encrypt cutover` on a v3 column reports
"not applicable" and exits 0.

The rest of this subsection is the **EQL v2** path (an `eql_v2_encrypted` twin
queried through the legacy `encryptedSupabase` wrapper), kept for existing v2
deployments.

First, if you use declared `schemas`, update them to the post-cutover shape — the encrypted column will live under the original column name:

```typescript
// src/encryption/schema.ts (post-cutover)
export const users = encryptedTable('users', {
  email: types.TextSearch('email'),
})
```

(Without declared schemas, introspection picks up the renamed column at the next client startup.)

> **Known gap (EQL v2, SDK-only users):** `stash encrypt cutover` requires a pending EQL configuration, which is set by `stash db push`. If you're using the SDK without Proxy, you'll hit a "No pending EQL configuration" error from cutover. **Workaround:** run `stash db push` once before `stash encrypt cutover`. EQL v3 columns never hit this — cut-over doesn't apply to them.
>
> **Using CipherStash Proxy?** Re-push the encryption config so EQL has a pending row that points at `email` (no `_encrypted` suffix):
>
> ```bash
> stash db push
> # → writes the new config as `pending`. Active config (still pointing at
> #   `email_encrypted`) keeps serving while we complete the cutover.
> ```

Now run the cutover:

```bash
stash encrypt cutover --table users --column email
```

Inside one transaction it: (1) renames `email` → `email_plaintext` and `email_encrypted` → `email`, (2) promotes the pending EQL config to `active` (and the prior active to `inactive`), (3) records a `cut_over` event in `cs_migrations`.

App code that does `select('email')` now returns ciphertext that must be decrypted via the `encryptedSupabaseV3` wrapper. **This is the moment that breaks read paths if they aren't going through the wrapper.**

Update read paths to use the wrapper:

```typescript
// Before
const { data } = await supabase.from('users').select('email').eq('id', id).single()

// After — the wrapper decrypts transparently
const { data } = await es.from('users').select('email').eq('id', id).single()
```

For queries that filter on `email`, the wrapper handles the encrypted operators internally — the call site is the same shape as before (`.eq()`, `.matches()`, `.gte()`, etc.), but the values are encrypted before reaching the database. See `## Query Filters` above.

#### Drop: remove the plaintext column

Once read paths are routing through the wrapper and you're confident reads are decrypting correctly:

```bash
stash encrypt drop --table users --column email
```

The CLI emits a Supabase migration file with the drop. **Which column it drops depends on the EQL version**, which the CLI auto-detects:

- **v3** — drops the original plaintext column, `ALTER TABLE users DROP COLUMN email;`. There was no rename, so no `email_plaintext` exists. Requires the `backfilled` phase plus a live coverage check.
- **v2** — drops the post-rename leftover, `ALTER TABLE users DROP COLUMN email_plaintext;`. Requires the `cut-over` phase.

Review and apply with `supabase migration up` (or `supabase db reset` locally). Then remove the dual-write code from app paths — the plaintext column is gone; only the encrypted column is written now, through the wrapper.

### Inspecting progress at any time

```bash
stash status         # quest log: where each rollout is, what to do next
stash encrypt status # raw per-column phase, EQL state, backfill progress
stash encrypt plan   # diffs your migrations.json intent vs observed state
```

All three are read-only.

## Legacy: EQL v2

Earlier versions of this integration stored ciphertext in `jsonb` /
composite `eql_v2_encrypted` columns (enabled via `CREATE EXTENSION eql_v2`
or the v2 EQL bundle) and queried them through the `encryptedSupabase({
supabaseClient, encryptionClient })` factory, which takes a hand-written
client-side schema and a two-argument `from(tableName, schema)`. That surface
still ships in `@cipherstash/stack-supabase` and is unchanged — keep using it
for existing v2 deployments — but it is not the recommended path for new
projects: use `encryptedSupabaseV3`. The CLI rollout tooling (`stash encrypt
backfill` / `cutover` / `drop`) supports both generations and auto-detects which
one a column uses, so a v2 twin is no longer needed to get CLI-managed
backfill — see the EQL version note in the migration section above. For the v2
wrapper's full API and semantics, see the docs at https://cipherstash.com/docs.
