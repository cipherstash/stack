# @cipherstash/stack-supabase

## 1.1.0

### Minor Changes

- a2b0b45: **Reading this release.** These packages share one version line with
  `@cipherstash/stack-prisma`, so all six move together:

  - `stash`
  - `@cipherstash/stack`
  - `@cipherstash/stack-drizzle`
  - `@cipherstash/stack-supabase`
  - `@cipherstash/stack-prisma`
  - `@cipherstash/wizard`

  They are versioned together on purpose. `stash init` pins the versions of the
  packages it installs and the CLI embeds that map at build time, so a package
  shipping alone would leave the CLI recommending versions that no longer match
  what is published, and warning about a skew it had itself created.

  Two changes in this release can need action from some users. They are named
  here so you do not have to read six changelogs to find them:

  - **`@cipherstash/stack` — `clientKey` is hex-only.** A decoder fallback that
    also accepted standard padded base64 is gone, and such a key is now rejected
    at client construction with `invalid clientKey: expected a hex-encoded key`.
    Hex is the only encoding ever documented, and the only one `stash env` or any
    part of the JavaScript stack has ever produced — the base64 tolerance was an
    accident of the underlying Rust decoder, which accepts base64 solely to read
    its own profile store. A key pasted out of `~/.cipherstash/secretkey.json`
    (which stores base64) stops working; re-encode it, or drop the explicit key
    and let the client read the profile store directly, which is unaffected. The
    full entry is "Adopt protect-ffi 0.31.0" in the **`@cipherstash/stack`**
    changelog; it also narrows which `error.code` values DynamoDB operations
    report.
  - **`stash` — `stash eql validate` lost `--exclude-operator-family`,** and two
    checks that used to exit 1 no longer do. A script passing that flag, or a CI
    gate relying on those exit codes, needs updating. The full entry is under
    `eql validate` in the **`stash`** changelog.

  `@cipherstash/stack-prisma` also moves to Prisma Next 0.17 in this release,
  which requires migration steps from its consumers — see its own changelog
  entry.

- a2b0b45: `encryptedSupabase` can now be constructed without a Postgres connection, and there is a new edge entry that runs it off Node.

  **The rule: declare your schemas and it runs anywhere; omit them and we discover them for you, which needs a database connection and is therefore Node-only.**

  Previously the wrapper always introspected the database to derive each column's encryption config from its Postgres domain. That made it unconstructible anywhere a TCP socket to Postgres is unavailable, and cost a second, more privileged credential even on Node — the caller already had an authenticated Supabase client and had to supply a `databaseUrl` as well.

  - **Passing `schemas` with no database URL skips introspection entirely.** No connection, no `pg`, no `databaseUrl`.
  - **New `@cipherstash/stack-supabase/wasm-inline` entry.** Identical wrapper, WASM engine. The package root statically imports the native engine (`@cipherstash/protect-ffi` and `@cipherstash/auth`, both Node-API), and a static import loads whether or not you encrypt anything — so an edge runtime needs a different entry, not a different code path. ESM-only, matching `@cipherstash/stack/wasm-inline`. Server-side only; not browser-safe (#804).
  - **`DATABASE_URL` is now read through a guard.** On a runtime with no `process` global a bare `process.env.X` is a `ReferenceError`, not `undefined`, so the unguarded read threw during construction before declared mode could help.

  **Existing callers are unaffected.** The gate is the database URL, not the presence of `schemas`: if a URL resolves — from `options.databaseUrl` or `DATABASE_URL` — introspection still runs, and a `schemas`-passing caller still gets the drift check that verifies their declaration against the real column domains. "Pass `databaseUrl` as well" is how you keep verification while declaring types.

  What declared mode gives up, it gives up loudly rather than silently:

  - **`select('*')` and bare `select()` are refused.** `allColumns` comes only from introspection, and an unexpanded `*` reaches PostgREST without the `::jsonb` casts encrypted columns need.
  - **`from()` on an undeclared table throws**, naming the declaration rather than an introspection pass that never ran.
  - **The drift check is absent**, so a wrong declared domain surfaces as a `23514` CHECK violation on the first write instead of at construction.
  - **`queryDomainsRequired` is forced rather than detected**, since the installed EQL version is read by introspection. This is the fail-loud direction: correct on EQL >= 3.0.2, and on an older install the operand cast fails visibly instead of emitting an operator the database will not engage.
  - **Passing `databaseUrl` to the `wasm-inline` entry is refused** — it carries no Postgres driver, and saying so beats ignoring the option.

  One tradeoff is **not** loud, and is the declared-mode contract you have to hold yourself: **your declaration must cover every encrypted column of a table you query.** Nothing introspects, so a column carrying an `eql_v3` domain in the database but absent from `schemas` is treated as an ordinary plaintext column — a `select` naming it returns the raw EQL payload as data, and a filter on it sends the plaintext operand to PostgREST. The always-introspect path could not do this (undeclared columns were synthesized from their domains). Declare every encrypted column, or pass `databaseUrl` so introspection fills the gaps.

  An ambient `DATABASE_URL` no longer overrules a declaration, and is consulted only by a build that could act on it: on the edge entry — which cannot introspect at all — it is never read, so a `DATABASE_URL` that happens to be set in the environment cannot break a declared-mode client. On the native entry, passing `schemas` without an explicit `databaseUrl` ignores the variable and warns that the declaration is unverified. The refusal of a `databaseUrl` on the edge entry now keys on the option you actually passed, so it can never fire for a value you did not write. Previously a stray variable silently exited declared mode — introspecting a database the caller never named on Node, and on the edge entry throwing "drop databaseUrl" about an option never passed.

  **The edge entry adapts the WASM client rather than casting to it.** The two engines are not drop-in for each other, and every difference is silent at construction — the entry would have built a client happily while each query through it failed. `decryptModel` / `bulkDecryptModels` require the table on WASM and derive it from the payloads on native (both call sites now pass it, which native ignores); WASM operations are plain Results with no `.withLockContext()` or `.audit()`, so both are attached and throw a sentence naming the gap rather than a bare `TypeError`; and `bulkEncrypt` is deliberately not forwarded, selecting the supported per-term fallback instead of a mismatched signature. Lock context is a real capability gap on the WASM engine (cipherstash/stack#797) — failing loudly is the only honest option, since silently dropping the claim would write values any keyset holder could decrypt.

  The edge entry's options are also typed for what it actually requires: `schemas` and a `WasmClientConfig` `config` are both mandatory (there is no `~/.cipherstash` to discover credentials from), and `databaseUrl` is absent from the type as well as refused at runtime. Previously the shared factory's erased config type let an edge caller omit credentials entirely and reach a `TypeError` from inside the engine.

### Patch Changes

- Updated dependencies [a2b0b45]
- Updated dependencies [a2b0b45]
- Updated dependencies [a2b0b45]
- Updated dependencies [a2b0b45]
  - @cipherstash/stack@1.1.0

## 1.0.0

### Major Changes

- e0dea47: Remove the EQL v2 authoring surface and de-suffix the v3 API to the canonical
  unsuffixed names (part of the EQL v2 removal, #707).

  - **`encryptedSupabase` is now the connect-time-introspecting EQL v3 factory**
    (formerly `encryptedSupabaseV3`). `encryptedSupabaseV3` remains a
    type-identical `@deprecated` alias, so existing imports keep working.
  - **The legacy v2 `encryptedSupabase({ encryptionClient, supabaseClient })`
    wrapper is removed** — with it the two-argument `from(tableName, schema)` form
    and the hand-written client-side v2 schema. Its `EncryptedSupabaseConfig` and
    the v2 `EncryptedSupabaseInstance`/`EncryptedQueryBuilder` type shapes are gone;
    the unsuffixed type names now denote the v3 surface.
  - **The public types use canonical unsuffixed names:**
    `EncryptedSupabaseOptions`, `EncryptedSupabaseInstance`,
    `TypedEncryptedSupabaseInstance`, `EncryptedQueryBuilder`,
    `EncryptedQueryBuilderUntyped`, `FilterableKeys`, and `OrderableKeys`. Each
    keeps a type-identical `@deprecated` `*V3` alias.

  **Reading existing v2 data.** Only the v2 _authoring/emission_ surface is removed
  — no v2 ciphertext is stranded. Decryption in `@cipherstash/stack` is
  generation-agnostic, so EQL v2 payloads still decrypt through the core client
  (`decrypt` / `decryptModel`). This adapter, however, is now EQL v3 only and will
  not auto-read an `eql_v2_encrypted` column: to read legacy v2 data during
  migration, decrypt fetched rows with `@cipherstash/stack` directly, or use a
  dedicated migration reader that calls the native client's generation-agnostic
  decrypt operations. The public Stack client cannot be configured to author v2;
  mixed-generation handling is explicit rather than adapter auto-detection.

  Internally the v3 query builder (`query-builder-v3.ts`) was folded into the base
  `EncryptedQueryBuilderImpl`, which is now natively EQL v3; no runtime behaviour or
  wire encoding changed.

  **Migration:** use `await encryptedSupabase(supabaseUrl, supabaseKey)` with
  `eql_v3_*` column domains. See the `stash-supabase` skill and
  https://cipherstash.com/docs.

- 7c7dbca: CipherStash Stack 1.0.

  This is the first 1.0-line release of `@cipherstash/stack`, the first published
  release of the split-out EQL v3 adapters `@cipherstash/stack-drizzle` and
  `@cipherstash/stack-supabase`, and moves the `stash` CLI to 1.0 alongside them.
  These four packages now version together as the Stack 1.0 family.

- 8ac4f64: `single()` and `maybeSingle()` now type `data` as the ROW, not an array.

  Both have always returned one object at runtime, but the builder kept
  advertising the array shape it was created with, so `data` was typed `T[] | null`
  while holding a single row. Every caller had to launder it:

  ```typescript
  const { data } = await supabase.from("users").select("id, email").single();
  // before: data is `User[] | null` — wrong; a cast was the only way through
  const user = data as unknown as User;
  // after: data is `User | null`
  data?.email;
  ```

  `single()`/`maybeSingle()` now return `EncryptedSingleQueryBuilder<T>`, which
  awaits to `EncryptedSupabaseResponse<T>` (`data: T | null`). That covers the
  zero-row case for `maybeSingle()` and the error case for both, so no separate
  null modelling was needed.

  Filters and transforms are no longer chainable after `single()`/`maybeSingle()`,
  matching supabase-js — applying one afterwards would change the query the
  single-row promise was made about. `.single().eq(...)`, `.single().limit(...)`
  and friends were previously accepted and are now compile errors. What only
  re-types or re-configures the pending request is carried over: `returns<U>()`
  (preserving the awaited shape, so `.single().returns<U>()` awaits one row),
  `abortSignal()`, `throwOnError()`, `withLockContext()` and `audit()`.
  `EncryptedSingleQueryBuilder<T>` is exported so a stored builder can be
  annotated.

  **Migration:** delete the cast. Code that worked around the old typing with
  `data as unknown as Row` (or read `data![0]`) should now use `data` directly;
  the cast still compiles but is no longer needed, and `data![0]` becomes a type
  error. Move any filter or transform chained after `single()`/`maybeSingle()` to
  before it.

- 3aff6cb: Make `Encryption` and schema authoring EQL v3-only. The client now always writes
  EQL v3, exposes the single generic `EncryptionClient<S>` type, and removes the
  legacy v2 builders, client aliases, `config.eqlVersion`, and `./client` subpath.

  Native decrypt operations continue to read stored EQL v2 payloads. DynamoDB
  legacy reads now use a v3 table descriptor with `{ storedEqlVersion: 2 }`.
  Update the Supabase and Prisma Next integrations and the bundled agent skills
  for the consolidated API.

### Minor Changes

- 31ca318: Split the Drizzle and Supabase integrations into their own packages.

  The adapters now ship as first-party packages that depend on `@cipherstash/stack`,
  following the `@cipherstash/stack-prisma` precedent:

  - **`@cipherstash/stack-drizzle`** — EQL v3 Drizzle integration on the package
    root (`types` factories, `createEncryptionOperators`,
    `extractEncryptionSchema`, …).
  - **`@cipherstash/stack-supabase`** — EQL v3 Supabase integration through the
    connect-time-introspecting `encryptedSupabase` factory.

  **Breaking (`@cipherstash/stack`):** the `./drizzle`, `./supabase`, and
  `./eql/v3/drizzle` subpath exports are removed. Migrate imports:

  - `@cipherstash/stack/drizzle` → `@cipherstash/stack-drizzle`
  - `@cipherstash/stack/eql/v3/drizzle` → `@cipherstash/stack-drizzle`
  - `@cipherstash/stack/supabase` → `@cipherstash/stack-supabase`

  Add the relevant package to your dependencies alongside `@cipherstash/stack`. A new
  `@cipherstash/stack/adapter-kit` subpath exposes the narrow core internals the
  first-party adapters consume; it is the core↔adapter seam, not general-purpose API.

- e155956: Finish the EQL v2-removal release gates and adapter correctness pass.

  - **Supabase encrypts leaves nested inside a PostgREST boolean group.** This
    is a disclosure fix, not a formatting one. The `.or()` string parser had
    no group recursion, so `.or('and(createdAt.gte.2026-01-01,note.eq.x)')`
    came back from the top-level split as one part and the leaf parser cut it
    at the first dot into the pseudo-column `and(createdAt`. That name matched
    no encrypted column, so the whole expression took the verbatim branch: the
    operand `2026-01-01` reached PostgREST **as plaintext, against an
    encrypted column**, under the JS property name `createdAt` rather than the
    DB column name `created_at`. Every encrypted leaf nested inside `and(...)`
    / `or(...)` / `not.and(...)` leaked its operand to the database and
    returned wrong results. Nested groups and `referencedTable` are now
    preserved while each encrypted leaf is substituted in place.
  - Supabase never sends nullish encrypted search operands as plaintext, honours
    escaped LIKE metacharacters, rejects CSV result mode before decryption, and
    diagnoses the removed object-form factory call. The bundled `stash-supabase`
    skill no longer lists `csv()` among the transforms passed through to
    Supabase — it throws, and the skill now says so and shows serializing the
    decrypted rows instead.
  - Native, WASM, and Supabase model decryption reconstruct valid date and
    timestamp values consistently, including nested paths, aliases, and bulk
    results, while leaving invalid values unchanged. That last clause is a
    behavioural change on the native typed client and the Supabase adapter,
    which previously pushed every date-like column through `new Date(...)`
    unconditionally: a stored value that does not parse used to come back as an
    Invalid `Date` and now comes back as the raw string, matching what the WASM
    entry already did. The declared column type is still `Date`, so code that
    assumed `instanceof Date` held for every date column — or called a `Date`
    method on it unguarded, so that `.getTime()` used to yield `NaN` and now
    throws a `TypeError` — has to handle the raw value.
  - `stash init` names the concrete `public.eql_v3_*` domain family and gives
    `public.eql_v3_text_search` as a valid Supabase example.
  - CLI and wizard skill selection stay in parity for every integration,
    including the Prisma Next skill, and verify that each selected skill has a
    `SKILL.md`.

  The final 1.0 integration surface is `Encryption` from
  `@cipherstash/stack/v3`, the `@cipherstash/stack-drizzle` package root, and
  `encryptedSupabase` from `@cipherstash/stack-supabase`. DynamoDB decrypt
  operations retain `.audit()` on the typed `Encryption` client. Existing EQL v2
  ciphertext remains readable through the core client; authoring and adapter
  writes use EQL v3.

- c4787c0: Restore the EQL v3 envelope and `Result` types the adapters were erasing.

  Both adapters typed their operand-encryption paths as `unknown` and dropped the
  `Result` wrapper, so the query-type encoding and the failure channel were
  invisible to the type system:

  - The Drizzle operator module typed the client's `encrypt`/`bulkEncrypt` as
    returning `unknown`, collapsed the operation's `Result` to
    `{ data?: unknown; failure?: { message } }`, and cast the bulk response to
    `Array<{ data: unknown }>`.
  - The Supabase query builder returned `Promise<unknown[]>` from
    `encryptCollectedTerms`, `bulkEncryptGroup` and `encryptGroupPerTerm`.

  These now carry the SDK's real types — `Encrypted` (the storage envelope union,
  which includes every v3 per-domain payload), `BulkEncryptedData`, and
  `EncryptedQueryResult` — threaded through a properly-typed operation surface that
  resolves `Result<T, EncryptionError>`.

  Tightening `createEncryptionOperators`' client contract from `unknown` to a typed
  operation surface is a compile-time breaking change for a downstream consumer
  passing a loosely-typed (`unknown`-returning) client double: it will now fail
  `tsc`. That tightening has teeth — `operators.test-d.ts` pins it with a negative
  type-test asserting an `unknown`-returning `{ encrypt }` double is rejected (a
  positive "correctly-typed double is accepted" assertion cannot catch a
  re-erasure, since a correct value is assignable to `unknown`).

  Behaviour is otherwise unchanged, with one addition: the Supabase bulk path now
  rejects a `null` envelope returned by `bulkEncrypt` (the restored
  `Encrypted | null` type makes that arm reachable, and a `null` would otherwise
  be `JSON.stringify`'d to the literal `"null"` and sent as a filter operand).

- e40c3da: Rename the EQL v3 encrypted free-text operator `contains()` → `matches()` (#617).

  Encrypted free-text search is fuzzy bloom-filter token matching — order- and
  multiplicity-insensitive and one-sided (a `true` may be a false positive) — not
  containment. The name `contains()` promised substring/containment semantics it
  never had. It is renamed to `matches()` on the encrypted surface; `contains()` is
  kept for genuine, exact containment:

  - **Drizzle** (`@cipherstash/stack-drizzle`): `matches()` = bloom free-text on
    `text_match`/`text_search` columns; `contains()` = exact encrypted-JSON `@>` on
    `types.Json` (ste_vec) columns.
  - **Supabase** (`@cipherstash/stack-supabase`): `.matches()` = encrypted free-text;
    `.contains()` = native jsonb/array `@>` on plaintext columns (and throws on an
    encrypted column, pointing to `matches()`).

  Also on the Supabase v3 surface, `like()`/`ilike()` on an encrypted column are no
  longer rejected — they are delegated to `matches()` as a best-effort compatibility
  shim. This is APPROXIMATE (fuzzy, case-insensitive, one-sided; anchoring and
  wildcards are not honored): surrounding `%` are stripped, an internal `%` or any
  `_` is rejected, and a one-time warning is emitted. A plaintext column keeps real
  SQL LIKE.

  Breaking: encrypted `contains()` callers must migrate to `matches()`. The
  encrypted operator has not shipped in a stable release (it lands via the EQL v3
  work), so there is no deprecation alias.

- 5d23e80: `encryptedSupabase` is a connect-time-async, introspecting EQL v3 factory:
  `await encryptedSupabase(url, key)` (or `(client)`) introspects the database over
  `DATABASE_URL`, detects EQL v3 columns by their Postgres domain
  (`information_schema.columns.domain_name`), and derives each column's encryption
  config from its domain — callers no longer pass a schema to `from()`.
  `select('*')` is supported (expanded from the introspected column list, and
  aliased back to each declared column's JS property name so a property→DB rename
  round-trips). A column using a `public.eql_v3_*` domain this SDK version does not
  model throws when its table is named via `from()` rather than silently passing
  through. Supplying `schemas` remains optional and adds compile-time types plus
  eager construction-time verification of the declared tables against the
  database — including that same unmodelled-column check. Requires a Postgres connection for
  introspection (`pg` is an optional peer), so it cannot run in a Worker or the
  browser.

  Every column name a query carries — filters, `match`, `not`, raw `filter`,
  `or()`, `order()`, and the `onConflict` option — is resolved from its JS property
  name to its DB column name in a single pass before the query is built, so a
  declared rename round-trips everywhere rather than only on the paths that
  remembered to translate.

  `.or()` understands PostgREST's `column.not.<op>.<value>` negation. It was
  previously parsed as `{ op: 'not', value: '<op>.<value>' }`, so on an encrypted
  column `or('nickname.not.in.(ada,grace)')` encrypted the literal string
  `in.(ada,grace)` as a single plaintext and produced a filter that silently
  matched nothing.

  Encrypted free-text search is `matches(column, value)`, narrowed at compile time
  to columns whose domain carries the `freeTextSearch` capability
  (`public.eql_v3_text_match`, `public.eql_v3_text_search`) and guarded at runtime
  for the untyped surface. It matches any needle whose trigrams are all present in
  the stored value; needles shorter than the tokenizer's window (3 characters)
  bloom to nothing and are rejected rather than silently matching every row. A raw
  `filter(column, operator, …)` on an encrypted column derives its query type from
  the operator instead of always encrypting an equality term, so
  `filter('bio', 'cs', …)` on a `public.eql_v3_text_match` column works rather than
  being rejected, and an unsupported operator throws instead of silently encrypting
  the wrong term.

  The v3 match index emits `include_original: false` — the flag is inert in
  protect-ffi (the bloom is trigram-only either way), so this moves no ciphertext
  and only pins the value a substring-search domain wants.

- 99f8b0a: Fix encrypted `in`-list operands in the Supabase adapter, and widen the `is` /
  `contains` type surfaces.

  **`in()` on an encrypted column produced a request PostgREST rejects.** Every
  encrypted operand is a serialized envelope, dense with `"` and `,`. postgrest-js
  wraps a comma-bearing element as `"…"` but never escapes the quotes already
  inside it, so `.in('email', […])` emitted

  ```
  in.("{"v":1,"c":"…"}",…)
         ^ PostgREST ends the value here → PGRST100
  ```

  Encrypted lists are now emitted through `filter(col, 'in', …)` with each element
  quoted and escaped, matching what the `.or()` path already did.

  **`not(col, 'in', […])` encrypted the whole list as a single ciphertext**, so
  the filter silently matched nothing, and emitted an unparenthesized
  `not.in.a,b`. Each element is now encrypted separately and the operand is
  rendered as `not.in.(…)`. Passing a PostgREST list literal (`'(a,b)'`) for an
  encrypted column now throws instead of silently matching nothing — pass an
  array.

  **`filter(col, 'in', […])` encrypted the whole list as a single ciphertext.**
  The raw `.filter()` path reached `in` with none of the element-splitting the
  `in()`, `not(…, 'in', …)` and `.or()` paths perform, so the entire list operand
  was encrypted as one equality term. A bare `{…}` envelope is not parenthesized,
  so PostgREST rejected the request outright with
  `PGRST100 (failed to parse filter)`.

  Each element is now encrypted separately and the operand rendered as a quoted
  PostgREST list literal. As on the `not` path, passing a list literal
  (`'(a,b)'`) for an encrypted column now throws instead — pass an array.

  Plaintext columns are unaffected, including the pre-existing quirk that
  postgrest-js renders `.filter(col, 'in', [array])` as an unparenthesized
  `in.a,b` that PostgREST rejects; pass a list literal there, or use `.in()`.

  **`is(col, null)` is now allowed on every column**, including storage-only
  encrypted ones (`types.Boolean`, `types.Integer`, …). `is` is never encrypted
  and a NULL plaintext is stored as a SQL NULL, so `IS NULL` is not merely legal
  there but the only predicate those columns support. `is(col, true)` remains a
  compile error on encrypted columns.

  **`contains()` accepts native operands on plaintext array and jsonb columns.** A
  plaintext jsonb/array column falls through to PostgREST's native containment, so
  `contains('tags', ['vip'])` and `contains('meta', { plan: 'pro' })` now
  typecheck. A plaintext SCALAR column does not: `@>` is undefined on `text`, so
  the operand type follows the column's own shape and a scalar rejects every
  containment operand. Encrypted free-text search is `matches()`, which takes a
  `string` token; `contains()` on an encrypted non-JSON column throws and names it.
  Relatedly, `.or([{ op: 'contains' }])` now emits PostgREST's `cs` operator for
  plaintext columns too — previously only encrypted conditions were translated, so
  a plaintext containment reached the wire as `.contains.` and failed to parse.

  **Direct `contains()` / `not(col, 'contains', …)` now serialize their operand.**
  postgrest-js builds an array operand as `cs.{a,b}` with no element quoting, so
  `contains('tags', ['with,comma'])` reached Postgres as two elements; and its
  `not()` stringifies the operand outright, emitting `not.contains.with,comma`
  (no braces, and the wrong operator token) or `[object Object]` for a jsonb
  operand. Both paths now build the containment literal the `.or()` path already
  built, and emit the `cs` token.

  **`.or()` no longer drops a condition after an unbalanced brace or paren.** A
  scalar operand containing `{` left the parser's depth counter stranded above
  zero, so no later comma separated a condition and everything behind it was
  swallowed into that operand. With a plaintext column first, the group was then
  forwarded verbatim — running the swallowed condition against a ciphertext column
  with a plaintext operand. Braces are now quoted on emit (they are structural to
  PostgREST inside `or=(…)`), and the parser falls back to quote-only splitting
  when its depth tracking does not balance.

  **`is(col, true)` is now rejected on every encrypted column, not just the
  storage-only ones.** The boolean form was gated on the filterable keys, which
  exclude storage-only columns but keep queryable encrypted ones — so
  `is(emailTextSearchColumn, true)` compiled and emitted `IS TRUE` against a jsonb
  ciphertext.

  **In-list operands encrypt in one crossing per column.** The element-wise `in` /
  `not.in` encoding above spent one ZeroKMS round-trip per element; terms are now
  grouped by column and each group takes a single `bulkEncrypt` call, matching the
  Drizzle path. Falls back to per-term encryption for clients without
  `bulkEncrypt`, and rejects a bulk response whose length does not match the list
  rather than silently truncating the predicate.

- ffe4974: Row-type generics now accept an `interface`, not just a `type` alias.

  `from<Row>()`, `returns<U>()` and `single().returns<U>()` constrained their row
  parameter to `Record<string, unknown>`. An `interface` has no implicit index
  signature, so the most ordinary way to declare a row type failed to compile:

  ```typescript
  interface User {
    id: string;
    email: string;
  }

  // before: TS2344 — Index signature for type 'string' is missing in type 'User'
  // after: fine
  const { data } = await supabase.from<User>("users").select("id, email");
  ```

  A `type User = { … }` alias worked, which is why the existing type tests never
  caught it. The constraint is now `object`, which still rejects `string`/`number`
  row types. upstream `postgrest-js` constrains `returns` to nothing at all, so
  this brings the adapter in line with the API it mirrors rather than being
  stricter than it.

  Also corrects the `EncryptedSingleQueryBuilder` documentation, which claimed
  that "everything that only re-types or re-configures the pending request is
  carried over" after `single()`/`maybeSingle()`. `overrideTypes` and `setHeader`
  are not carried over — they have no adapter equivalent, and since
  `single()`/`maybeSingle()` return the same builder instance rather than a
  passthrough, calling them would fail at runtime, not just fail to typecheck.

- 5fe9a2f: Encrypted-JSON querying on the v3 Supabase surface (#650). A `types.Json`
  column now supports exact encrypted containment — `contains(col, subDocument)`
  (ste_vec `@>` via PostgREST `cs`, with the sub-document storage-encrypted
  against the column) — and JSONPath selector predicates: `selectorEq(col, path,
value)` and `selectorNe(col, path, value)` (dot-notation paths; `ne` includes
  rows where the path is absent, mirroring the Drizzle selector's semantics).
  Raw `.filter(col, 'cs', subDocument)` and `not(col, 'contains', …)` route
  through the same encrypted path. Selector ordering is not expressible over
  PostgREST yet (needs an EQL-bundle overload — see
  cipherstash/encrypt-query-language#407); the Drizzle integration's
  `ops.selector()` covers ordering today.

  In core, `QueryTypesForColumn` gains the `searchableJson` arm (a `types.Json`
  column no longer resolves to `never`, so typed adapter key sets can include
  it), and the JSONPath selector-path helpers the Drizzle adapter introduced in
  #651 moved to `@cipherstash/stack/adapter-kit` so both adapters share one
  validation surface (`@cipherstash/stack-drizzle` re-exports them unchanged).

  The bundled `stash-supabase` and `stash-encryption` skills are updated to
  document the new querying surface (including the array-leaf and SQL-NULL
  semantics, and the operand-exposure caveat) — skills ship inside the `stash`
  tarball, hence the patch.

- 9b65ae8: **`order()` works on EQL v3 encrypted ordering columns.**

  A bare `ORDER BY col` on an EQL v3 domain is wrong — the bundle declares no btree
  operator class on any domain, so the sort falls through to jsonb's default
  `jsonb_cmp` and compares the envelope's keys in storage order, starting at the
  random ciphertext `c`. Measured over ten rows it returns `r00,r04,r08,r01,…`
  where the plaintext order is `r00..r09`. No error, a stable and
  plausible-looking meaningless order.

  But the correct sort key is reachable without a function call. `eql_v3.ord_term`
  returns the domain's `op` term, and OPE is order-preserving, so ordering by the
  term reproduces the plaintext order. PostgREST cannot emit
  `ORDER BY eql_v3.ord_term(col)`, but it can emit a jsonb path. The builder emits
  `order=col->op` for an encrypted ordering column, verified against a live
  PostgREST for `eql_v3_integer_ord` and `eql_v3_text_search` in both directions.

  The guard is on the ordering FLAVOUR, not on encryption:

  - **`ope` present → supported.** Every plain `eql_v3_*_ord` domain, plus
    `eql_v3_text_ord` and `eql_v3_text_search`.
  - **`ore` present → rejected.** The `ob` term is an array of ORE blocks whose
    comparison needs the superuser-only operator class, which no jsonb path can
    reach. (Such a column cannot hold data on managed Postgres anyway: its domain
    CHECK raises `ore_domain_unavailable`.) ORE columns are excluded from `order()`
    at COMPILE time as well as at runtime — `.order(oreColumn)` is a type error,
    matching the rejection.
  - **neither → rejected.** Storage-only, equality-only and match-only columns
    carry no ordering term.

  The path is `col->op` (jsonb), not `col->>op` (text). Neither avoids the
  database collation — Postgres compares jsonb strings with `varstr_cmp` under the
  default collation, exactly as it does text. What makes the ordering
  collation-independent is the term's encoding: lowercase hex, fixed-width for
  numeric and date domains, and per-character (16 hex chars each) for text, so
  lexicographic order reproduces plaintext order including the prefix case
  (`ada` < `adam`). `ope-term.integration.test.ts` pins that shape.

  `OrderableKeys` admits OPE-backed ordering columns (`eql_v3_*_ord`,
  `eql_v3_text_ord`, `eql_v3_text_search`) while excluding ORE
  (`eql_v3_*_ord_ore`) columns, so `order()` typechecks exactly where it works.
  `is(col, true)` is unaffected — it stays plaintext-only, with its own
  `PlaintextKeys` rather than borrowing the orderable set.

### Patch Changes

- 57441cc: Refresh the adapter READMEs (they ship on each package's npm page):

  - **stack-supabase**: full rewrite — the old README was a stub. Now covers the
    introspecting `encryptedSupabase(url, key)` factory, the encrypted filter
    surface (`eq`/`neq`/`in`/`match`, range, `order()` on OPE-backed columns),
    the EQL 3.0.2 PostgREST limitations, and the quick start.
  - **stack-drizzle**: fix the hero example — `ops.contains` is encrypted-JSONB
    containment (a `types.Json` column) and would throw on a text column; the
    free-text operator is `ops.matches`. The operator table no longer lists
    `contains` under free-text match.
  - **stack-prisma**: correct the encrypted-column-type catalog (domain-named
    factories across text/integer/float/numeric/date/timestamp/boolean/JSON, not
    "six types"), fix the authentication docs URL, and replace relative links
    (which 404 on npm) with absolute ones.
  - All three: add the badge header and the architecture diagram from the root
    README.

- cf2c57c: Upgrade Stack to `@cipherstash/protect-ffi` 0.30 and EQL 3.0.2.

  Prisma Next includes a versioned EQL 3.0.2 upgrade migration, so databases
  that have already recorded the original EQL v3 baseline still install the new
  domains and functions.

  Encrypted JSON now uses the `public.eql_v3_json_search` storage domain and
  `eql_v3.query_json` query domain. Drizzle selector equality uses exact,
  GIN-indexable value-selector containment, while selector range comparisons use
  a ciphertext-free path selector plus string/number query term. Prisma Next gains
  the equivalent `eqlJsonPathEq`, `eqlJsonPathNeq`, `eqlJsonPathGt`,
  `eqlJsonPathGte`, `eqlJsonPathLt`, and `eqlJsonPathLte` operators. Selector
  Selector-based `ORDER BY` is available as
  `ops.selector(column, path).asc()/desc()` in Drizzle
  and `eqlJsonPathAsc(column, path)` / `eqlJsonPathDesc(column, path)` in Prisma
  Next; both lower to `ORDER BY eql_v3.ord_term` over the selected entry.

  If you call `encryptQuery` with an explicit `queryType`, note that `steVecTerm`
  now produces a scalar JSON ordering term. It no longer means structural
  containment; use the JSON containment query type with an object or array, or
  `steVecValueSelector` with
  `{ path, value }` for exact equality at a path.

  The FFI now rejects free-text needles shorter than the configured n-gram size
  at the core query-encryption boundary, including callers that bypass adapter
  guards.

  This EQL release changes the SteVec storage format. Existing EQL v3 encrypted
  JSON rows must be re-encrypted before they can be queried with the new domain.
  The former EQL v2 JSON schema shape is not accepted by the public client because
  the old selector envelope can no longer be emitted; migrate to the v3
  `types.Json` domain. Native decrypt compatibility for stored v2 payloads is
  unchanged.

  EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
  operators. PostgREST cannot express those casts, so Supabase v3 fails fast for
  `matches()`, encrypted `contains()`, and `selectorEq()`/`selectorNe()` instead
  of placing a decryptable storage envelope in a GET query string that the new
  SQL surface will reject. Use the Drizzle or Prisma Next adapter, or a carefully
  scoped direct SQL/RPC path.

- 2fd4985: Populate `EncryptedSupabaseError.encryptionError` on encryption failures (#626).
  The query builder's catch block previously hardcoded `encryptionError: undefined`,
  so the typed field was always empty and callers had to detect encryption failures
  indirectly (via `status`/`statusText` or `.throwOnError()`). It now threads the
  underlying `EncryptionError` through — for both the v2 and v3 dialects — when the
  failure originates in an encrypt/decrypt step, and leaves it unset for plain
  PostgREST/API errors.
- fd33aad: Fix the Supabase adapter encrypting `is` and `null` filter operands.

  `is` is a SQL predicate — PostgREST accepts only `null`/`true`/`false` after it
  — and a `null` operand is SQL NULL, never a value to search for. Only the direct
  `.is()` filter skipped encryption; `not()`, `or()`, `match()`, raw `filter()`,
  and the `in()` element list all encrypted whatever they were handed. So
  `or('age.is.null')` emitted `age.is."("null")"` and `eq('email', null)` emitted
  `email=("null")` — operands PostgREST rejects. A null plaintext is stored as a
  NULL column rather than ciphertext, so it is found with an unencrypted
  `IS NULL`; encrypting the operand could never match.

  A single `isEncryptableTerm(operator, value)` predicate now guards every term
  collector. This additionally removes a spurious `does not support equality
queries` error, which `is` raised because it maps to the `equality` query type
  and so hit the column-capability guard — `or('active.is.null')` on a storage-only column
  threw rather than querying.

  Relatedly, an `or()` string is now rebuilt whenever a condition _references_ an
  encrypted column, not only when one of its values was encrypted. An `is` on an
  encrypted column encrypts nothing, and the old condition sent it down the
  verbatim path, forwarding the caller's JS property name to a database that only
  knows the column's DB name.

- 8cd485d: Fix the Supabase adapter's `.or()` string parser mis-splitting conditions.

  An `.or()` string is only rebuilt from its parse when it references an encrypted column — otherwise the caller's string is forwarded verbatim — so each of these corrupts precisely the mixed encrypted/plaintext case.

  **Quotes were tracked only at brace depth 0.** A `}` inside a quoted array element or jsonb string value closed the literal early, and the next `"` re-opened quoting, so the following top-level comma never split: `.or('tags.cs.{"a}b"},email.eq.secret')` parsed as a single condition and silently absorbed `email.eq.secret` into the operand. Quotes are now opaque at every depth.

  **A stray `}` or `)` drove the depth counter negative**, after which no comma split again. `}` and `)` are not PostgREST reserved characters, so `a}b` is a valid unquoted operand and `.or('nickname.eq.a}b,id.eq.1')` dropped `id.eq.1`. Depth now floors at zero.

  **`in`-list elements were split on every comma, ignoring quotes.** `.or('email.in.("a,b",c)')` parsed as three elements with the quotes still embedded; on an encrypted column each fragment was encrypted as its own term, so the intended element never matched. Elements are now split on top-level commas and unquoted, the inverse of what the rebuild emits.

  **A parenthesized operand was read as a list for every operator.** Only `in` and the range operators (`ov`, `sl`, `sr`, `nxr`, `nxl`, `adj`) take a paren-delimited operand; elsewhere `(` is an ordinary character. `email.eq.(foo)` parsed as `['foo']` and encrypted a JS array rather than the string, matching nothing.

  **A string operand spelling `null`, `true` or `false` is now quoted.** PostgREST reads a bare `null` as SQL NULL, so `.or([{ column: 'name', op: 'eq', value: 'null' }])` emitted `name.eq.null` and compared against NULL instead of the three-character string.

- 41a04a6: Fix: a table authored with `encryptedTable`/`types` imported from `@cipherstash/stack/wasm-inline` was treated as having **no encrypted columns**, so filter operands were sent to PostgREST as plaintext.

  `ColumnMap` gated on `builder instanceof EncryptedV3Column`, and the published bundles contain two separately-emitted copies of that class (`dist/adapter-kit.js` and `dist/wasm-inline.js` are separate esbuild runs). The check is now structural, so both copies are recognised. Tables authored from `@cipherstash/stack/eql/v3` were never affected — they resolve to the same copy the adapter imports.

  The failure was silent: `::jsonb` casts and result decryption go through a different path and kept working.

  The recognition now also fails closed: a column builder that does not present the v3 surface makes `encryptedSupabase` throw at construction rather than silently omitting the column — an omitted column would send its filter operands to PostgREST as plaintext.

- 8d31708: Diagnose a legacy EQL v2 table shape by name instead of crashing with a raw
  `TypeError`.

  A table created by the former v2 API is structurally similar to a v3 one. Old
  compiled code or untyped JavaScript could therefore pass that shape to
  `encryptedSupabase({ schemas })` and fail deep inside verification, naming an
  internal method rather than the version mismatch that caused it.

  Both paths now fail closed with the table named and the fix stated. The check
  routes through `hasBuildColumnKeyMap`, the canonical v2/v3 discriminator, rather
  than a second hand-written spelling of it.

  First-party adapters share an internal discriminator through
  `@cipherstash/stack/adapter-kit`; it is adapter plumbing rather than an
  end-user schema-authoring API.

- 7b53141: Three correctness fixes surfaced while documenting the v3 surface:

  - **Supabase `matches()` now rejects a short free-text needle.** A needle
    below the tokenizer's `token_length` blooms to zero tokens, so `bloom @> {}`
    matched (and the caller decrypted) every row — a fail-open exposure. The
    guard (`matchNeedleError`) was wired into the Drizzle adapter only; the
    Supabase adapter now applies it at the same term-resolution choke point, so
    both first-party surfaces reject identically. (Authoritative FFI-level backstop
    for the `encryptQuery` paths tracked in cipherstash/protectjs-ffi#138.)
  - **Supabase `.withLockContext()` accepts the plain `{ identityClaim }` form**,
    not only a `LockContext` instance — matching the stack-level operations and
    the documented identity-aware example (widened to `LockContextInput`).
  - **`EncryptionErrorTypes` is now `as const`**, so the `StackError` union
    actually discriminates: `switch (error.type)` narrows and `error.code` is
    reachable on the relevant branches. Without it every `type` was `string` and
    the documented exhaustive error handler did not compile.

- Updated dependencies [31ca318]
- Updated dependencies [e155956]
- Updated dependencies [8b2551a]
- Updated dependencies [8817cfb]
- Updated dependencies [ace2a4f]
- Updated dependencies [3a0a0dc]
- Updated dependencies [5d304ec]
- Updated dependencies [d26950d]
- Updated dependencies [90c3873]
- Updated dependencies [de804c2]
- Updated dependencies [a9d430b]
- Updated dependencies [310bb19]
- Updated dependencies [c54f19c]
- Updated dependencies [66a0e02]
- Updated dependencies [cfd46ee]
- Updated dependencies [7eba32d]
- Updated dependencies [89b903f]
- Updated dependencies [229ce59]
- Updated dependencies [50c0a9c]
- Updated dependencies [63ca540]
- Updated dependencies [e297f64]
- Updated dependencies [1aa9a11]
- Updated dependencies [af2d04e]
- Updated dependencies [b8a3d20]
- Updated dependencies [a0f3b2c]
- Updated dependencies [8817cfb]
- Updated dependencies [a5fab3c]
- Updated dependencies [cf2c57c]
- Updated dependencies [04f7ac7]
- Updated dependencies [36f9988]
- Updated dependencies [c516b34]
- Updated dependencies [4d92090]
- Updated dependencies [b2f9d7a]
- Updated dependencies [f23f952]
- Updated dependencies [40ab142]
- Updated dependencies [7c7dbca]
- Updated dependencies [5411a13]
- Updated dependencies [8832d35]
- Updated dependencies [8832d35]
- Updated dependencies [ea74846]
- Updated dependencies [20cb8c3]
- Updated dependencies [57441cc]
- Updated dependencies [17393b9]
- Updated dependencies [8d31708]
- Updated dependencies [5fe9a2f]
- Updated dependencies [5d304ec]
- Updated dependencies [310bb19]
- Updated dependencies [856dcc8]
- Updated dependencies [ade9707]
- Updated dependencies [3aff6cb]
- Updated dependencies [c745db7]
- Updated dependencies [7b53141]
- Updated dependencies [b085f66]
- Updated dependencies [3a0a0dc]
- Updated dependencies [508f1d5]
- Updated dependencies [d25d100]
  - @cipherstash/stack@1.0.0

## 1.0.0-rc.4

### Patch Changes

- cf2c57c: Upgrade Stack to `@cipherstash/protect-ffi` 0.30 and EQL 3.0.2.

  Prisma Next includes a versioned EQL 3.0.2 upgrade migration, so databases
  that have already recorded the original EQL v3 baseline still install the new
  domains and functions.

  Encrypted JSON now uses the `public.eql_v3_json_search` storage domain and
  `eql_v3.query_json` query domain. Drizzle selector equality uses exact,
  GIN-indexable value-selector containment, while selector range comparisons use
  a ciphertext-free path selector plus string/number query term. Prisma Next gains
  the equivalent `eqlJsonPathEq`, `eqlJsonPathNeq`, `eqlJsonPathGt`,
  `eqlJsonPathGte`, `eqlJsonPathLt`, and `eqlJsonPathLte` operators. Selector
  Selector-based `ORDER BY` is available as
  `ops.selector(column, path).asc()/desc()` in Drizzle
  and `eqlJsonPathAsc(column, path)` / `eqlJsonPathDesc(column, path)` in Prisma
  Next; both lower to `ORDER BY eql_v3.ord_term` over the selected entry.

  If you call `encryptQuery` with an explicit `queryType`, note that
  `steVecTerm` now produces a scalar JSON ordering term. It no longer means
  structural containment; use the recommended `searchableJson` query type with
  an object or array for containment, or `steVecValueSelector` with
  `{ path, value }` for exact equality at a path.

  The FFI now rejects free-text needles shorter than the configured n-gram size
  at the core query-encryption boundary, including callers that bypass adapter
  guards.

  This EQL release changes the SteVec storage format. Existing EQL v3 encrypted
  JSON rows must be re-encrypted before they can be queried with the new domain.
  Legacy EQL v2 `searchableJson()` schemas are rejected during client setup
  because the old selector envelope can no longer be emitted; migrate them to the
  v3 `types.Json` domain.

  EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
  operators. PostgREST cannot express those casts, so Supabase v3 fails fast for
  `matches()`, encrypted `contains()`, and `selectorEq()`/`selectorNe()` instead
  of placing a decryptable storage envelope in a GET query string that the new
  SQL surface will reject. Use the Drizzle or Prisma Next adapter, or a carefully
  scoped direct SQL/RPC path.

- Updated dependencies [cf2c57c]
- Updated dependencies [508f1d5]
  - @cipherstash/stack@1.0.0-rc.4

## 1.0.0-rc.3

### Patch Changes

- Updated dependencies [8b2551a]
  - @cipherstash/stack@1.0.0-rc.3

## 1.0.0-rc.2

### Patch Changes

- Updated dependencies [b085f66]
  - @cipherstash/stack@1.0.0-rc.2

## 1.0.0-rc.1

### Minor Changes

- 5fe9a2f: Encrypted-JSON querying on the v3 Supabase surface (#650). A `types.Json`
  column now supports exact encrypted containment — `contains(col, subDocument)`
  (ste_vec `@>` via PostgREST `cs`, with the sub-document storage-encrypted
  against the column) — and JSONPath selector predicates: `selectorEq(col, path,
value)` and `selectorNe(col, path, value)` (dot-notation paths; `ne` includes
  rows where the path is absent, mirroring the Drizzle selector's semantics).
  Raw `.filter(col, 'cs', subDocument)` and `not(col, 'contains', …)` route
  through the same encrypted path. Selector ordering is not expressible over
  PostgREST yet (needs an EQL-bundle overload — see
  cipherstash/encrypt-query-language#407); the Drizzle integration's
  `ops.selector()` covers ordering today.

  In core, `QueryTypesForColumn` gains the `searchableJson` arm (a `types.Json`
  column no longer resolves to `never`, so typed adapter key sets can include
  it), and the JSONPath selector-path helpers the Drizzle adapter introduced in
  #651 moved to `@cipherstash/stack/adapter-kit` so both adapters share one
  validation surface (`@cipherstash/stack-drizzle` re-exports them unchanged).

  The bundled `stash-supabase` and `stash-encryption` skills are updated to
  document the new querying surface (including the array-leaf and SQL-NULL
  semantics, and the operand-exposure caveat) — skills ship inside the `stash`
  tarball, hence the patch.

### Patch Changes

- 7b53141: Three correctness fixes surfaced while documenting the v3 surface:

  - **Supabase `matches()` now rejects a short free-text needle.** A needle
    below the tokenizer's `token_length` blooms to zero tokens, so `bloom @> {}`
    matched (and the caller decrypted) every row — a fail-open exposure. The
    guard (`matchNeedleError`) was wired into the Drizzle adapter only; the
    Supabase adapter now applies it at the same term-resolution choke point, so
    both first-party surfaces reject identically. (Authoritative FFI-level backstop
    for the `encryptQuery` paths tracked in cipherstash/protectjs-ffi#138.)
  - **Supabase `.withLockContext()` accepts the plain `{ identityClaim }` form**,
    not only a `LockContext` instance — matching the stack-level operations and
    the documented identity-aware example (widened to `LockContextInput`).
  - **`EncryptionErrorTypes` is now `as const`**, so the `StackError` union
    actually discriminates: `switch (error.type)` narrows and `error.code` is
    reachable on the relevant branches. Without it every `type` was `string` and
    the documented exhaustive error handler did not compile.

- Updated dependencies [e297f64]
- Updated dependencies [40ab142]
- Updated dependencies [5fe9a2f]
- Updated dependencies [7b53141]
  - @cipherstash/stack@1.0.0-rc.1

## 1.0.0-rc.0

### Major Changes

- 7c7dbca: CipherStash Stack 1.0 (release candidate).

  This is the first 1.0-line release of `@cipherstash/stack`, the first published
  release of the split-out EQL v3 adapters `@cipherstash/stack-drizzle` and
  `@cipherstash/stack-supabase`, and moves the `stash` CLI to 1.0 alongside them.
  These four packages now version together as the Stack 1.0 family.

### Minor Changes

- 31ca318: Split the Drizzle and Supabase integrations into their own packages.

  The adapters now ship as first-party packages that depend on `@cipherstash/stack`,
  following the `@cipherstash/prisma-next` precedent:

  - **`@cipherstash/stack-drizzle`** — Drizzle ORM integration. EQL v2 on the package
    root (`@cipherstash/stack-drizzle`: `encryptedType`, `extractEncryptionSchema`,
    `createEncryptionOperators`) and EQL v3 on `@cipherstash/stack-drizzle/v3`
    (`types` factories, `createEncryptionOperatorsV3`, `extractEncryptionSchemaV3`, …).
  - **`@cipherstash/stack-supabase`** — Supabase integration: `encryptedSupabase` (v2)
    and `encryptedSupabaseV3` (v3, connect-time introspection).

  **Breaking (`@cipherstash/stack`):** the `./drizzle`, `./supabase`, and
  `./eql/v3/drizzle` subpath exports are removed. Migrate imports:

  - `@cipherstash/stack/drizzle` → `@cipherstash/stack-drizzle`
  - `@cipherstash/stack/eql/v3/drizzle` → `@cipherstash/stack-drizzle/v3`
  - `@cipherstash/stack/supabase` → `@cipherstash/stack-supabase`

  Add the relevant package to your dependencies alongside `@cipherstash/stack`. A new
  `@cipherstash/stack/adapter-kit` subpath exposes the narrow core internals the
  first-party adapters consume; it is the core↔adapter seam, not general-purpose API.

- e40c3da: Rename the EQL v3 encrypted free-text operator `contains()` → `matches()` (#617).

  Encrypted free-text search is fuzzy bloom-filter token matching — order- and
  multiplicity-insensitive and one-sided (a `true` may be a false positive) — not
  containment. The name `contains()` promised substring/containment semantics it
  never had. It is renamed to `matches()` on the encrypted surface; `contains()` is
  kept for genuine, exact containment:

  - **Drizzle** (`@cipherstash/stack-drizzle/v3`): `matches()` = bloom free-text on
    `text_match`/`text_search` columns; `contains()` = exact encrypted-JSON `@>` on
    `types.Json` (ste_vec) columns.
  - **Supabase** (`@cipherstash/stack-supabase`): `.matches()` = encrypted free-text;
    `.contains()` = native jsonb/array `@>` on plaintext columns (and throws on an
    encrypted column, pointing to `matches()`).

  Also on the Supabase v3 surface, `like()`/`ilike()` on an encrypted column are no
  longer rejected — they are delegated to `matches()` as a best-effort compatibility
  shim. This is APPROXIMATE (fuzzy, case-insensitive, one-sided; anchoring and
  wildcards are not honored): surrounding `%` are stripped, an internal `%` or any
  `_` is rejected, and a one-time warning is emitted. A plaintext column keeps real
  SQL LIKE.

  Breaking: encrypted `contains()` callers must migrate to `matches()`. The
  encrypted operator has not shipped in a stable release (it lands via the EQL v3
  work), so there is no deprecation alias.

### Patch Changes

- 2fd4985: Populate `EncryptedSupabaseError.encryptionError` on encryption failures (#626).
  The query builder's catch block previously hardcoded `encryptionError: undefined`,
  so the typed field was always empty and callers had to detect encryption failures
  indirectly (via `status`/`statusText` or `.throwOnError()`). It now threads the
  underlying `EncryptionError` through — for both the v2 and v3 dialects — when the
  failure originates in an encrypt/decrypt step, and leaves it unset for plain
  PostgREST/API errors.
- Updated dependencies [31ca318]
- Updated dependencies [c4787c0]
- Updated dependencies [66a0e02]
- Updated dependencies [cfd46ee]
- Updated dependencies [7eba32d]
- Updated dependencies [0ebf57e]
- Updated dependencies [d73a03c]
- Updated dependencies [89b903f]
- Updated dependencies [229ce59]
- Updated dependencies [50c0a9c]
- Updated dependencies [63ca540]
- Updated dependencies [5d23e80]
- Updated dependencies [1aa9a11]
- Updated dependencies [af2d04e]
- Updated dependencies [b8a3d20]
- Updated dependencies [a0f3b2c]
- Updated dependencies [f23f952]
- Updated dependencies [7c7dbca]
- Updated dependencies [5411a13]
- Updated dependencies [99f8b0a]
- Updated dependencies [fd33aad]
- Updated dependencies [8cd485d]
- Updated dependencies [9b65ae8]
  - @cipherstash/stack@1.0.0-rc.0
