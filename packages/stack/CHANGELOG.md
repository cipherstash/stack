# @cipherstash/stack

## 1.0.0

### Major Changes

- 7c7dbca: CipherStash Stack 1.0.

  This is the first 1.0-line release of `@cipherstash/stack`, the first published
  release of the split-out EQL v3 adapters `@cipherstash/stack-drizzle` and
  `@cipherstash/stack-supabase`, and moves the `stash` CLI to 1.0 alongside them.
  These four packages now version together as the Stack 1.0 family.

- 8832d35: The typed EQL v3 client's `decryptModel` / `bulkDecryptModels` are now
  audit-chainable. They return a chainable operation (a `MappedDecryptOperation`)
  instead of a bare `Promise<Result<…>>`, so you can attach audit metadata and a
  lock context before awaiting:

  ```typescript
  await client
    .decryptModel(item, table)
    .audit({ metadata: { requestId } })
    .withLockContext({ identityClaim: ["sub"] });
  ```

  Both chaining orders forward the metadata to ZeroKMS, and the `Date`
  reconstruction still applies to the successful result. Await-only call sites are
  unchanged — the operation is still thenable to the same `Result`. This restores
  audited decrypt through the DynamoDB adapter (`encryptedDynamoDB(...).decryptModel`)
  for a v3 client, which previously had nowhere to carry the metadata.

  Chaining `.withLockContext()` onto a decrypt operation that already took a lock
  context positionally (`decryptModel(item, table, lc).withLockContext(other)`) now
  throws instead of silently keeping the first. Pass the lock context one way or
  the other, not both.

  **Breaking:** `Encryption` now accepts concrete EQL v3 tables and returns the
  single strongly typed `EncryptionClient<S>` surface. The former v3 factory and
  client aliases have been removed. If you were already passing EQL v3 tables to
  `Encryption`, model decrypt now reconstructs `Date` columns from `cast_as`
  instead of leaving them as ISO strings. Code that read those columns as strings
  needs updating.

  `Encryption({ schemas: [] })` no longer type-checks (it used to compile and then
  throw). The public config no longer selects an EQL wire version: new clients
  always author EQL v3. Name a client for a schema set as `EncryptionClient<S>`.

  `decryptModel` / `bulkDecryptModels` on the typed client also accept a call with
  no table, matching the runtime, which has always allowed it — that is the path
  for reading models written before the upgrade, above all legacy EQL v2 ones,
  whose table cannot be a member of a v3 schema tuple. Prefer the two-argument
  form whenever the table is registered.

  The public EQL v2 schema builders and version-selection config have been removed.
  Native decrypt operations remain able to read legacy EQL v2 payloads.

- 8832d35: **Breaking (DynamoDB adapter):** `encryptedDynamoDB(...).encryptModel` and
  `bulkEncryptModels` no longer accept an EQL v2 table. The v2 write type overloads
  have been removed, narrowing encrypt to `AnyV3Table`. The narrowing is
  type-level — treat the type as the contract, not a runtime guard.

  **Decrypt still reads existing v2 items.** Pass the corresponding EQL v3 table
  and `{ storedEqlVersion: 2 }` to `decryptModel` / `bulkDecryptModels`; the adapter
  uses that explicit storage-version hint for legacy envelope reconstruction.

  Migrate v2 write call sites to an EQL v3 table (`encryptedTable` + `types.*` from
  `@cipherstash/stack/eql/v3`) and reuse that table for reads, adding the explicit
  legacy-read option only while reading stored v2 data.

- ade9707: Close the gaps found reviewing the v3-only change against #815's acceptance
  criteria.

  `config.eqlVersion` is now rejected by the type system as well as at runtime, on
  both entries. `ClientConfig.eqlVersion` and `WasmClientConfig.eqlVersion` are
  declared `?: never` rather than omitted: every other property on those types is
  optional, so excess-property checking was the only thing catching a leftover
  `eqlVersion` — and that fires on fresh object literals alone. A shared config
  const, which is the shape a v2 → v3 migration actually holds, type-checked clean
  and then threw at `Encryption()`. It is now a compile error. Both entries keep
  their runtime guard, since JS and JSON callers bypass types entirely.

  `@cipherstash/stack/wasm-inline` now rejects `config.eqlVersion` at runtime too,
  with the same message as the native entry. Previously the native factory threw
  and the WASM one accepted the field silently — the entry disagreement #815 exists
  to remove.

  The WASM entry's non-v3-table error no longer refers the reader to the native
  entry for EQL v2 authoring. Authoring v2 has been removed everywhere, so that
  referral only bought a second rejection; the message now says so and points at
  what v2 payloads are still good for — decryption, which is unchanged.

  The `Encryption` signature sketch in the `@cipherstash/stack` README carried
  `schemas: AnyV3Table[]`, understating what is accepted; it now shows both real
  overloads, including the `readonly` and non-literal array forms. The bundled
  `stash-encryption` skill regained the `./encryption` and `./adapter-kit` subpath
  rows, both of which still ship. `cipherstashFromStack`'s `encryptionConfig`
  JSDoc described `config.eqlVersion` as an escape hatch that throws over an
  all-v3 schema set; it is rejected unconditionally, and the doc now says that.

  The `stash-dynamodb` skill documented the v3 descriptor a legacy read takes but
  not that it must also be one of the tables passed to `Encryption({ schemas })`.
  The adapter forwards that descriptor to the client, which rejects a table it was
  not initialized with, so reading v2 rows for a table your current schema no
  longer declares fails. That requirement is now stated where the legacy-read
  signature is.

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

- d26950d: `encryptedDynamoDB` now accepts EQL v3 tables.

  Pass a table built with `encryptedTable` + the `types.*` domains from
  `@cipherstash/stack/v3` to any of `encryptModel`, `bulkEncryptModels`,
  `decryptModel`, or `bulkDecryptModels`. Build the typed client with
  `Encryption({ schemas: [table] })`.

  Existing EQL v2 items continue to be **readable**: pass the corresponding EQL v3
  table plus `{ storedEqlVersion: 2 }` to `decryptModel` /
  `bulkDecryptModels`. Writes accept EQL v3 tables only.

  This fixes a latent bug that made v3 unusable: the write path detected an
  encrypted value by its `k: 'ct'` tag, but EQL v3 scalars carry no `k`
  discriminator at all. Every v3 scalar fell through to the nested-object branch
  and was written as a raw map instead of being split into `<attr>__source` and
  `<attr>__hmac`.

  Notes on capability:

  - Only equality is usable on DynamoDB. `<attr>__hmac` is written for domains
    that mint an `hm` term — the `*Eq` family, plus `TextOrd`/`TextOrdOre`/
    `TextSearch`. Ordering and bloom-filter terms have no DynamoDB query surface
    and are not stored, so those columns remain decryptable but not queryable.
  - Nested attributes are supported in v3. There is no nested-group authoring
    form (that is a compile error), so declare the column flat with a dotted
    path — `{ 'profile.ssn': types.TextEq('profile.ssn') }`. The model is
    matched by dotted path, so `{ profile: { ssn } }` resolves, and the nested
    attribute keeps its `__hmac` for key conditions.
  - The typed `Encryption` client supports `.audit()` on `decryptModel` and
    `bulkDecryptModels`, including when used through the DynamoDB adapter.

  The DynamoDB adapter also gains its first test coverage — across the v2 and v3
  paths, where it previously had none.

  Robustness, from review:

  - Passing a v3 table to a client that never registered it (one built for a
    different schema set, so it is not in v3 mode for that table) now throws a
    clear, actionable error naming the table, instead of failing opaquely deep in
    the FFI.
  - A malformed decrypt result from a non-conforming client is surfaced as a
    failure rather than resolving as a silent `undefined` success.
  - Reading back a `<attr>__source` attribute that matches no declared column now
    logs a debug diagnostic instead of silently returning the raw ciphertext.
  - Caller input that cannot be structurally cloned no longer reaches the FFI by
    reference — the "encryption never mutates a caller's object" guarantee holds
    on that path too.
  - The write path now splits only declared columns, matched on the same property
    path the read path rebuilds from. A pre-encrypted payload placed under an
    undeclared nested name is stored whole (and round-trips) instead of being
    split into a `<attr>__source` the read path could never reassemble.
  - A degenerate payload with an empty-string ciphertext is split like any other
    ciphertext rather than falling through and being written as a raw map, which
    had leaked its `v`/`i` envelope metadata into storage.
  - Arrays are documented as a deliberate carve-out: the mapping does not descend
    into them, so a payload inside a list is stored whole (still decryptable, but
    not queryable and not part of the `__source`/`__hmac` layout).

  The v3 overloads are strongly typed. `encryptModel` / `bulkEncryptModels` check
  the input model against the table's column domains, and return the DynamoDB
  attribute map that is actually written — the new exported `EncryptedAttributes`
  type, where a declared column `email` becomes `email__source` (plus
  `email__hmac` for the equality domains that mint one) rather than surviving as
  `email`. `decryptModel` / `bulkDecryptModels` invert it via `DecryptedAttributes`.
  `AnyEncryptedTable`, `DynamoDBEncryptionClient` and `AuditConfig` are now
  exported from `@cipherstash/stack/dynamodb` so these signatures can be named.
  Legacy reads use the explicit storage-version option rather than an EQL v2 table
  overload; the v2 encrypt overloads are removed in this release.

- 310bb19: `Encryption({ schemas })` now accepts any non-empty array of EQL v3 tables, not
  only an array literal.

  Previously the v3 signature required a non-empty _tuple_, so every indirect form
  was rejected at compile time even though it worked at runtime:

  ```ts
  // all of these used to fail with TS2769
  export const schemas: AnyV3Table[] = [users, orders];
  await Encryption({ schemas });

  const readonlySchemas: ReadonlyArray<AnyV3Table> = [users, orders];
  await Encryption({ schemas: readonlySchemas });

  const built: AnyV3Table[] = [];
  built.push(users);
  await Encryption({ schemas: built });
  ```

  They all compile now. `Encryption({ schemas: [] })` is still a compile error, and
  an array literal still gets full per-column typing — passing the wrong plaintext
  for a column's domain, or a table the client was not built with, is still
  rejected.

  `EncryptionClient<S>` accepts the same schema parameter, so it names the client
  for a loose `readonly AnyV3Table[]` as well as for a tuple. Code that is generic
  over its schemas — an adapter that builds a table per request, say — can write
  `EncryptionClient<readonly AnyV3Table[]>`.

  That keeps the `table` and `column` arguments checked, but not the model input:
  with the schema parameter loose there is no per-column plaintext to resolve, so
  `encryptModel` / `bulkEncryptModels` still reject an untyped
  `Record<string, unknown>` model and an adapter holding untyped rows needs a cast
  at that one boundary. Full model typing requires a concrete schema tuple.

  If you narrowed a schema array to `readonly [AnyV3Table, ...AnyV3Table[]]` to
  satisfy the old signature, that narrowing is no longer needed.

  A wrapper that is itself generic over its schemas keeps working too:

  ```ts
  async function makeClient<S extends readonly [AnyV3Table, ...AnyV3Table[]]>(
    schemas: S
  ) {
    return await Encryption({ schemas });
  }
  ```

  Note the non-empty tuple constraint. A wrapper generic over a loose
  `readonly AnyV3Table[]` is still rejected — that type admits `readonly []`, so
  the wrapper cannot promise what `Encryption` requires. Constrain it as above, or
  take `EncryptionClient<readonly AnyV3Table[]>` as a parameter instead of
  building the client inside the generic function.

- 66a0e02: Add the EQL v3 bigint domain family to the public DSL: `types.Bigint`,
  `types.BigintEq`, `types.BigintOrdOre`, and `types.BigintOrd`, backed by the
  `public.bigint*` concrete domains. Plaintext is a JS `bigint`, round-tripped
  losslessly across the protect-ffi 0.28 boundary (i64 bounds enforced at the
  FFI — out-of-range values surface as encryption errors). Index emission follows
  the numeric rule: `bigint_eq` → unique (hm); `bigint_ord`/`bigint_ord_ore` →
  ore (equality answered via ob).
- 7eba32d: EQL v3 Drizzle: encrypt every query operand with `encryptQuery`, not `encrypt` (#622).

  The Drizzle operators (`eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`notBetween`/
  `inArray`/`notInArray`/`matches`/`contains`) previously encrypted their operands with
  `client.encrypt`, producing a full storage envelope (including the ciphertext `c`)
  cast to `::jsonb`. A WHERE-clause operand should be a query _term_, not a value to
  store. Every operator now uses `client.encryptQuery`, which yields a
  ciphertext-free query term cast to the column's `eql_v3.query_<domain>` type — so
  predicates carry no ciphertext and reach the bundle's `(domain, query_<domain>)`
  operator overloads. This unifies the scalar/text operators with the JSON
  containment path (already on `encryptQuery`) and removes the previously-optional
  `encryptQuery` guard: it is now a required capability of the operand client.

  `@cipherstash/stack` gains a batch `encryptQuery(terms)` overload on the generic
  `EncryptionClient<S>` returned by `Encryption`. This is additive — it lets
  `inArray`/`notInArray` encrypt a whole list of query terms in one crossing.

- 89b903f: Upgrade `@cipherstash/protect-ffi` to 0.28.0 and update EQL v3 concrete Postgres domain names to match the SQL fixture (`integer*`, `smallint*`, `bool`, `real*`, and `double*`). The public factories remain semantic (`Integer`, `Smallint`, `Boolean`, `Real`, `Double`) while their concrete domains change, so this is a minor release.
- 229ce59: Re-baseline EQL v3 on the eql-3.0.0 GA release and protect-ffi 0.29.

  - **Breaking (v3 preview surface):** the EQL v3 column domains follow the
    eql-3.0.0 naming convention — flat, prefixed names in `public`
    (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, …) instead of the
    alpha-era bare names. Databases installed from an alpha bundle must be
    re-installed (`stash eql install` replaces the schema).
  - `encryptQuery` on the EQL v3 client now returns EQL v3 query operands
    (protect-ffi 0.29): term-only scalar operands for the `eql_v3.query_<name>`
    domains, the `eql_v3.query_jsonb` containment needle, and bare selector
    hashes for JSON path queries — v3 scalar and selector queries no longer
    throw `EQL_V3_QUERY_UNSUPPORTED` (the code is gone).
  - Legacy EQL v2 JSON compatibility fixtures pin the SteVec encoding to
    `standard` explicitly. protect-ffi 0.29 flipped the library default to
    `compat` (EQL v3's encoding); without the pin, v2 JSON containment fixtures
    would silently mismatch existing data.
  - The EQL v3 test/install SQL is sourced from the pinned `@cipherstash/eql`
    package (3.0.0) instead of a hand-vendored fixture.

- 50c0a9c: Add EQL v3 JSON columns. `types.Json('col')` declares a `public.eql_v3_json`
  column that encrypts a JSON document to an ste_vec `SteVecDocument` and
  round-trips it losslessly through `encrypt`/`decrypt` and the model path. A new
  `searchableJson` query capability emits the ste_vec index; the index uses
  `mode: 'compat'`, which eql-3.0.0's `eql_v3_json` requires (it orders ste_vec
  entries by the CLLW-OPE `op` term, so v2's `'standard'`/CLLW-`oc` terms are
  rejected).

  The Drizzle integration's `contains(col, subObject)` now answers encrypted-JSONB
  containment on a `types.Json` column, emitting the `@>` operator with a
  `query_jsonb` needle (from `encryptQuery`). The ste_vec index indexes array
  elements by identity but not position, so containment is a true subset test
  (`{ roles: ['x'] }` matches any document whose `roles` array contains `x`,
  regardless of index).

- 1aa9a11: Add the EQL v3 `text_search` authoring DSL on a new `@cipherstash/stack/eql/v3`
  subpath (`types.TextSearch`, v3 `encryptedTable` / `buildEncryptConfig`). The v3
  builders emit the existing `EncryptConfig` shape, so encryption, payloads, and
  query paths are unchanged at runtime.

  Also widens the public client types (`EncryptionClientConfig.schemas`,
  `EncryptOptions`, `SearchTerm`/`EncryptQueryOptions`) to a structural contract so
  both v2 and v3 builders are accepted by `Encryption` / `encrypt` / `decrypt` /
  `encryptQuery`. This is a backward-compatible widening — existing v2 usage is
  unaffected. The structural contracts themselves (`BuildableColumn`,
  `BuildableQueryColumn`, `BuildableV3QueryableColumn`, `BuildableTable`,
  `BuildableTableColumns`) and the `encryptModel` return-type mapper
  (`EncryptedFromBuildableTable`) are exported from `@cipherstash/stack/types` so
  consumers can name them.

- af2d04e: Add a strongly typed EQL v3 client surface on `@cipherstash/stack/v3`.
  `Encryption` returns the generic `EncryptionClient<S>` type and the subpath
  re-exports the v3 `types` namespace and table API (from
  `@cipherstash/stack/eql/v3`), so one import provides everything needed to author
  and use a v3 schema.

  Every method derives its types from the concrete `table` / `column` builder
  arguments:

  - `encrypt` / `encryptQuery` pin the plaintext to the column's domain type
    (`text → string`, `timestamp → Date`, …).
  - `encryptQuery` constrains `queryType` to the column's capabilities and rejects
    storage-only columns at compile time.
  - `encryptModel` / `bulkEncryptModels` validate schema-column fields against their
    inferred plaintext type (passthrough fields are untouched) and return a precise
    encrypted model.
  - `decryptModel` / `bulkDecryptModels` return the precise plaintext model,
    reconstructing `Date` values from the encrypt-config `cast_as`.

  Because the typed methods bind to the concrete branded v3 classes, a hand-rolled
  structural table/column is rejected — closing the soundness gap where a non-branded
  table could be encrypted at runtime while typed as plaintext.

  The model-decrypt paths add per-column `Date` reconstruction. New clients author
  EQL v3 only; native decrypt operations remain compatible with stored EQL v2
  payloads.

- b8a3d20: Add EQL v3 schema builders for supported generated SQL domains under `@cipherstash/stack/eql/v3`, exposed as the `types` namespace (one member per supported EQL v3 domain, e.g. `types.TextEq` / `types.IntegerOrd` / `types.Timestamp`), including explicit query capability metadata (`getQueryCapabilities()` / `isQueryable()`) and v3 table support in model encryption helpers (`encryptModel` / `bulkEncryptModels`).

  Also widen the accepted plaintext input type for `encrypt` / `encryptQuery` to include `Date` (via the new `Plaintext` type), so v3 `date` / `timestamp` domains can be encrypted and queried with their natural JavaScript values.

- a0f3b2c: `@cipherstash/stack/wasm-inline` is now EQL v3 (#614).

  The WASM entry (Deno / Bun / Cloudflare Workers / Supabase Edge) previously
  created a client pinned to the FFI's EQL v2 wire format, so a v3 schema
  (concrete `eql_v3_*` domains) failed every encrypt on the edge. It now targets
  EQL v3 exclusively:

  - The factory builds an EQL v3 WASM client, so v3 schemas
    encrypt/decrypt correctly on the edge.
  - The entry re-exports the **v3** authoring surface (`types`, `encryptedTable`,
    the column classes, `buildEncryptConfig`, and the inference helpers) — the
    same API as `@cipherstash/stack/eql/v3` — so an Edge Function authors and runs
    v3 from one import:

    ```ts
    import {
      Encryption,
      encryptedTable,
      types,
    } from "@cipherstash/stack/wasm-inline";

    const patients = encryptedTable("patients", {
      email: types.TextSearch("email"),
    });
    const client = await Encryption({ schemas: [patients], config });
    ```

  Only the EQL v3 schema authoring surface is public, and passing a legacy table
  shape throws a clear error. The WASM path was never announced or documented for
  v2 and had no known users. The native `@cipherstash/stack` entry continues to
  decrypt stored EQL v2 payloads, but new clients author EQL v3 only.

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

- 36f9988: `Encryption` no longer accepts a public wire-version override or legacy schema
  set. It requires EQL v3 tables and always builds a client that writes EQL v3,
  eliminating the configuration that could write EQL v2 payloads into
  `eql_v3_*` columns.

  Reading stored EQL v2 payloads is unaffected: native `decrypt` and
  `decryptModel` continue to read both generations. Compatibility fixtures mint
  v2 payloads directly through the FFI rather than through the public Stack
  authoring API.

- 5411a13: Add the `@cipherstash/stack/adapter-kit` subpath — a narrow support surface for
  the first-party adapter packages (`@cipherstash/stack-supabase`,
  `@cipherstash/stack-drizzle`) being split out of this package (#627). It
  re-exports exactly the core internals the adapters consume (the logger,
  `AuditConfig`, the v3 column model + `DATE_LIKE_CASTS`, the domain registry, the
  match-index guard, and the model→composite helpers) so those imports resolve
  across the package boundary without leaking six internal module paths. This is the
  core↔adapter seam, not general-purpose public API.
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

- b085f66: `@cipherstash/stack/wasm-inline` now exposes `encryptQuery` and
  `encryptQueryBulk` on `WasmEncryptionClient` (#662) — searchable encryption
  is reachable on Deno/edge runtimes. Previously the WASM entry exposed only
  `encrypt`/`decrypt`/`isEncrypted`, so encrypted WHERE-clause search was
  architecturally impossible on the edge even though the underlying protect-ffi
  WASM build carries the capability.

  The new methods mint ciphertext-free EQL v3 query terms — equality,
  free-text match, ORE range, and JSON containment/selector — with the same
  index-type resolution as the native client (explicit `queryType`, or
  inference from the column's configured indexes). Cast the term to the
  column's `eql_v3.query_<domain>` type in SQL to reach the indexed operators.
  Both return `{ data } | { failure }`, consistent with the WASM surface's
  `encrypt`/`decrypt`; the bulk form is position-stable (`null` values pass
  through as `null`).

- 508f1d5: **Breaking (`@cipherstash/stack/wasm-inline`):** every fallible method now returns a `Result` — `{ data } | { failure }` — instead of throwing. And `bulkEncrypt` / `bulkDecrypt` are added, so a list of encrypted rows costs **one** ZeroKMS round trip instead of one per row.

  ### Result alignment

  `encrypt`, `decrypt`, `encryptQuery` and `encryptQueryBulk` previously threw on failure, and returned bare values on success. They now return `{ data } | { failure }`, with `failure.type` drawn from `EncryptionErrorTypes` (`EncryptionError` for encrypt-side operations, `DecryptionError` for decrypt-side) and `failure.code` carrying the FFI error code where there is one.

  ```typescript
  // before
  const encrypted = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });

  // after
  const result = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });
  if (result.failure) throw new Error(result.failure.message);
  const encrypted = result.data;
  ```

  This is the contract the native entry has always honoured, and the one `AGENTS.md` states outright: _"Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`."_ The WASM entry never followed it. That was drift rather than a design decision — nothing about WASM prevents it (`@byteslice/result` is already bundled into `dist/wasm-inline.js`), and it meant edge code had to be written in a different shape from every other surface, with failures that were easy to miss.

  Fixed now because it is a breaking change and 1.0.0 has not shipped: `@cipherstash/stack@latest` is still `0.19.0`, so this surface has only ever been published under the `rc` tag. After GA it would have had to wait for a major.

  `isEncrypted` is unchanged — a pure predicate with nothing to fail at, exactly as on the native entry.

  ### Bulk operations

  ```typescript
  // Write: several columns across many rows, one round trip
  const encrypted = await client.bulkEncrypt([
    { plaintext: "alice@example.com", table: users, column: users.email },
    { plaintext: "hello", table: users, column: users.bio },
  ]);

  // Read: a whole page in one call
  const emails = await client.bulkDecrypt(rows.map((r) => r.email));
  ```

  The WASM entry previously exposed no bulk operations at all, so rendering an N-row list on Deno, Cloudflare Workers, or Supabase Edge Functions meant N sequential ZeroKMS calls. Combined with the WASM cold start, that made list endpoints impractical on the edge.

  Both are index-aligned with their input, and `null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS (an all-null batch makes no call at all). Because each entry names its own table and column, a single `bulkEncrypt` can cover several columns across many rows — which is what makes the saving real, since a single-column batch would still cost one round trip per column.

  `bulkDecrypt` builds on the fallible FFI primitive, so when items fail the `failure.message` names **every** failing index with its reason, rather than surfacing the first and discarding the rest.

  The model helpers (`encryptModel` / `decryptModel` and their bulk forms) remain Node-only: the WASM entry has no single-model operation to build them on, so those need their own port.

- d25d100: `@cipherstash/stack/wasm-inline` now has the model helpers: `encryptModel` / `decryptModel` and `bulkEncryptModels` / `bulkDecryptModels` (#742). They run the same schema traversal as the native entry (shared code, so the two entries cannot drift on which fields get encrypted): declared columns are encrypted — matched by JS property name, nested fields via the column's dotted path — everything else passes through, and `null`/`undefined` fields are preserved without reaching ZeroKMS. A call that encrypts (or decrypts) at least one field is one ZeroKMS round trip regardless of how many fields or models it covers; a `null`/empty batch, or one whose models carry no schema fields, returns without contacting ZeroKMS at all. `types.Date`/`types.Timestamp` columns round-trip `Date` → `Date` (ISO strings on the wire), and failures follow this entry's `{ data } | { failure }` Result contract, with decrypt failures naming every failing field by its model path. Edge code no longer needs the hand-written `bulkEncrypt` field mapping whose failure mode was a schema column silently persisted in plaintext.

  The shared model traversal is also hardened: it no longer mutates the caller's model (previously a nested-column decrypt wrote decrypted plaintext back into the caller's input, and encrypt overwrote it with ciphertext); a literal flat dotted key, a `__proto__`-shaped key, or a non-object model element is handled safely instead of crashing, leaking plaintext, or reaching `Object.prototype`; an already-encrypted field is passed through rather than re-encrypted; and an invalid `Date` is rejected per field. On the WASM entry, model ops now validate the table against the client's schemas, `Date` values are normalized at every encrypt/query crossing (not just the model path), and a `null`/empty model batch returns `{ data: [] }`. The skills update ships in the `stash` tarball, hence the `stash` patch.

### Patch Changes

- 8b2551a: Fix "Failed to load native binding" on project-local installs of the CLI/SDK
  (npm). `@cipherstash/auth` was pinned at 0.41.0 while the six
  `@cipherstash/auth-*` platform bindings declared in stack/stash/wizard's
  optionalDependencies were pinned at 0.42.0. Because auth pins its bindings as
  exact-version optional peer dependencies, the skew made npm nest per-consumer
  binding copies that the hoisted `auth` package could not resolve — any command
  or import touching auth then died at startup. All seven packages now move in
  lockstep at 0.42.0, Dependabot is barred from bumping any of them
  independently, and a supply-chain CI test fails on any future skew.
- 8817cfb: Fix the `Encryption()` auth-strategy doc examples to unwrap `create()`'s Result.

  Since `@cipherstash/auth` 0.41, `AccessKeyStrategy.create()` and
  `OidcFederationStrategy.create()` return a `Result<Strategy, AuthFailure>`,
  but the JSDoc examples on the native entry still passed the return value
  straight into `config.authStrategy` — demonstrating exactly the mistake that
  fails opaquely at the first `getToken()` call. The examples now check
  `.failure` and pass `.data`, matching the WASM entry's docs and the
  integration tests.

  Also corrects the lock-context wording in the `WasmEncryptionClient` doc
  comment: a lock context decides who can _retrieve a value's data key_ (the
  claim from the encrypting caller's service token is bound to the key), not
  "which key the value is encrypted under" — key material is identical either
  way; the binding gates retrieval.

- ace2a4f: Correct the shipped documentation for `decryptModel` / `bulkDecryptModels`.

  Three places in `skills/stash-encryption` and four in `packages/stack/README.md`
  said these return "a plain `Promise<Result<...>>` (not a chainable operation)"
  and that there is therefore "no `.withLockContext()` to chain". They return an
  `AuditableDecryptModelOperation`, which is thenable and carries both
  `.withLockContext()` and `.audit()` — the same `.audit()` chain the
  audit-on-decrypt work advertises. The skill contradicted itself: its own
  reference table already listed the correct return type.

  The skill ships inside the `stash` tarball and `installSkills()` copies it into
  customer repos, so this was steering agents away from an API that exists. The
  README ships in the `@cipherstash/stack` tarball.

  The equivalent statement about the **WASM entry** is correct and unchanged —
  `@cipherstash/stack/wasm-inline` really does return a plain promise from decrypt,
  with no lock-context argument.

  Also fixes the setup prompt `stash init` writes for coding agents, which
  referenced `protectOps.eq` — an API that does not exist anywhere in the repo.
  Every step naming an integration-specific API now branches on the project's
  actual integration, instead of naming Drizzle's and Supabase's and leaving the
  other two to guess:

  - **Query paths.** `createEncryptionOperators(client)` (conventionally `ops`)
    for Drizzle, the `encryptedSupabase` wrapper's own filters for Supabase, the
    `eql*` column operators for Prisma Next, and `client.encryptQuery(...)` for a
    plain Postgres project.
  - **Schema authoring.** The `types.*` column factories for Drizzle, a concrete
    `public.eql_v3_*` domain such as `public.eql_v3_text_search` in migration SQL
    for Supabase, the `cipherstash.*`
    field constructors in `schema.prisma` for Prisma Next, and `encryptedTable`
    for plain Postgres. Prisma Next was previously sent at `types.*` /
    `encryptedTable` — the client `stash schema build` explicitly refuses to
    scaffold for that integration.
  - **Read paths.** `decryptModel(row, usersSchema)` where that applies, and the
    wrapper's transparent decryption where it does not.
  - **Skill pointers.** A plain Postgres project installs no integration-specific
    skill, so each "see the integration skill" was a pointer at a file that was
    never written. Those now point at `stash-encryption`, which it does get.

  `client.encryptQuery` is also shown taking the schema objects themselves
  (`{ table: usersSchema, column: usersSchema.email }`) rather than an
  object-shorthand that read as three required strings — `queryType` is inferred
  from the column's configured indexes.

  The cutover and complete-rollout **plan templates** now describe the EQL v3
  rollout. Both described a rename swap (`<col>` → `<col>_plaintext`, twin →
  `<col>`) as the only cutover path, which EQL v3 does not have — the application
  switches to the encrypted column by name. The implement prompt already carried
  the v3 story; the plan templates did not.

  The "already encrypted" stop-and-ask now recognises `eql_v3_*` domains
  alongside the legacy `eql_v2_encrypted` udt, so it can fire on the default
  path at all.

  **`stash init` now detects already-encrypted columns on EQL v3.** Database
  introspection marked a column as CipherStash-managed only when its udt was
  exactly `eql_v2_encrypted`. v3 columns carry per-domain types
  (`eql_v3_text_search`, `eql_v3_integer_ord`, …), so on the default path every
  encrypted column was reported as plaintext — shown with its `dataType` and left
  unticked in the column picker, inviting a re-run to encrypt it a second time.
  The picker also labelled any encrypted column with the literal string
  `eql_v2_encrypted`; it now shows the column's real domain.

- 3a0a0dc: `decryptModel` / `bulkDecryptModels` now drop `.withLockContext()` from the
  returned operation once a lock context is bound, so binding twice is a compile
  error instead of a runtime throw.

  Passing a lock context positionally and then chaining it —
  `client.decryptModel(row, users, lockContext).withLockContext(lockContext)` —
  type-checked, then threw `this decrypt operation is already bound to a lock
context`. The type promised a method the runtime rejected.

  The operation interface is split to match what the encrypt path already does,
  where `EncryptModelOperationWithLockContext` simply lacks the method: the
  new `LockBoundDecryptModelOperation` carries `.audit()` only, and
  `AuditableDecryptModelOperation.withLockContext()` returns it. The runtime throw
  stays as the backstop for plain-JavaScript callers.

  An OPTIONAL lock context still type-checks. `decryptModel(row, users,
session?.lockContext)` — where the value is `LockContextInput | undefined` — is
  the ordinary shape for code that decrypts identity-bound rows only for
  signed-in users, and it compiled against the single optional parameter this
  replaces. The positional overloads accept `LockContextInput | undefined` so it
  keeps compiling; `undefined` binds nothing.

- 5d304ec: The phantom domain carrier on encrypted v3 columns is no longer part of the
  public surface.

  Recovering a column's domain after declaration emit requires the type parameter
  to appear bare somewhere in the instance type, which is what makes typed
  `encryptQuery` callable against the published package. That carrier was a
  plainly named `__domain` property, and this build has no `stripInternal`, so
  `@internal` was documentation rather than enforcement: it appeared in
  autocomplete on every column and could be read from consumer code, typed
  `D | undefined` while being `undefined` at runtime in every case.

  It is now keyed by a `unique symbol` that is not exported, so it is unnameable
  outside the package while remaining exactly as inferrable. Nothing is emitted at
  runtime and no call site changes.

- 90c3873: Fix reading a nested EQL v2 DynamoDB attribute that was stored under a grouped
  field.

  A v2 grouped column registered its build key on the BARE LEAF, so a field inside
  a group was written as `<group>.<leaf>__source` while the schema knew it only as
  `<leaf>`. The v3 rewrite made attribute matching exact-dotted-path only, for both
  generations, which orphaned every such attribute: it read back as raw base64
  inside a `{ data }` success, with only a debug-level log — invisible at the
  default log level. Silent wrong data on the one path that exists for backward
  compatibility.

  The bare-leaf fallback is restored for `{ storedEqlVersion: 2 }` reads only.
  It stays off for v3, where full dotted paths are registered precisely so a
  nested leaf cannot collide with a same-named top-level column — matching by
  bare leaf there rewrote a plaintext sibling as an envelope and handed it to the
  FFI as a decrypt target. Writes are EQL v3-only and stay strict.

  If you carried a v2 grouped column forward as a top-level v3 column, you can
  also declare it by its dotted path with the original DB name —
  `'details.amount': types.TextEq('amount')` — which reproduces the v2 identifier
  exactly.

- de804c2: Fix `encryptedDynamoDB`'s EQL v2 read path, which failed against a v3-configured
  client — the case the v2 read support exists for.

  `decryptModel` and `bulkDecryptModels` forwarded the table to the encryption
  client unconditionally. The second argument is only meaningful to the typed EQL
  v3 client, which resolves it against its own reconstructor map; a legacy v2
  table is not in that map, so the call failed with:

  ```
  [eql/v3]: decryptModel received a table this client was not initialized with
  ```

  That contradicted the adapter's documented contract — writes are EQL v3 only,
  but decrypt keeps accepting a v2 table so previously stored items stay readable.
  In practice the failure hit exactly the customers the compatibility promise was
  written for: upgraded to a v3 schema, with v2 items still in the table.

  The current v3 table is now forwarded on every read, legacy storage included:
  the legacy path reconstructs the v2 envelope around it, and the reconstructor
  map is keyed by the current schema either way. (Schema authoring is EQL v3-only,
  so there is no longer any such thing as a v2 table object to pass.)

  Both paths are covered by a credential-free test asserting what the adapter
  forwards, so a regression no longer depends on a live-credential integration run
  to surface.

- a9d430b: `encryptedDynamoDB` now serves legacy `{ storedEqlVersion: 2 }` reads on the
  `@cipherstash/stack/wasm-inline` entry, not just the native one.

  The legacy read reconstructs the EQL v2 envelope around the **current v3 table**
  and forwards that table exactly as a v3 read does, so both entries can serve it:
  protect-ffi's `decrypt` accepts either wire generation regardless of the
  client's `eqlVersion`, and the reconstructor map is keyed by the current schema
  either way. Deno, Cloudflare Workers and Supabase Edge Functions can therefore
  read rows written before the v3 migration; previously the pairing was refused
  outright and those runtimes had no way to read that data at all.

  Writes remain EQL v3-only on both entries.

  `encryptModel` / `bulkEncryptModels` now also tolerate a client whose encrypt
  returns a plain promise. They chained `.audit()` onto the result
  unconditionally, which the wasm-inline client does not carry — so **every EQL v3
  write through this adapter on that entry** failed with
  `client.encryptModel(...).audit is not a function`, surfaced as a
  `DYNAMODB_ENCRYPTION_ERROR` and so indistinguishable from a real encryption
  fault. The read path already handled this; the write path now matches, via the
  same fail-closed check that rejects a malformed result rather than passing an
  unencrypted item through as a success. Audit metadata still has nowhere to go on
  that client, so it is dropped and logged at debug — the write itself succeeds.

  Three comments in this package claimed audit metadata was forwarded "regardless
  of client shape" and that "every client this package ships carries `.audit()` on
  decrypt". Neither was true of the wasm-inline client, whose decrypt returns a
  plain promise — the metadata is dropped, observably (it is logged at debug), and
  the comments and the debug message now say so.

- c54f19c: Fix `prisma-next db init` failing with PN-RUN-3020 on fresh databases, and bump the pinned EQL bundle to 3.0.4.

  The cipherstash space's EQL install migration is re-emitted with `additive` operation class (it only CREATEs its own schemas/domains/functions, and the genesis edge is not a self-edge, so the integrity checker accepts it) and now bakes the eql-3.0.4 bundle while carrying the upgrade invariants, so fresh-database `db init` — including Prisma Compute preview deploys — satisfies the head ref from a single all-additive edge. A new `data`-classed 3.0.4 upgrade self-edge covers databases installed at an older bundle via `migrate`. Consumers with a vendored `migrations/cipherstash/` should delete the space directory and re-run `prisma-next migration plan` to pick up the re-emitted artefacts.

- cfd46ee: Source the EQL v3 install bundle from `@cipherstash/eql@3.0.0-alpha.3` instead of a hand-vendored 43k-line SQL fixture committed to the test tree. The package publishes its SQL and its TypeScript wire types from the same `eql-bindings` commit, so the bundle is now pinned to a released EQL version rather than tracked by convention.

  Test-and-tooling only — `@cipherstash/eql` is a `devDependency` and no public API changes.

  The staleness check in the v3 install helper now compares `eql_v3.version()` against the pinned release instead of probing for a hand-picked sentinel domain. The previous sentinel (`public.timestamp`) exists in both the old and new bundles, so it would have reported a stale install as current and left the suite silently running the wrong SQL.

- 63ca540: Re-vendor the EQL v3 SQL bundle and align the v3 DSL to it: encrypted type domains now live in the `public` schema (`public.text`, `public.integer`, …) rather than `eql_v3`, and the boolean domain is `public.boolean` (was `eql_v3.bool`). The `eql_v3` schema now holds only the operator-backing functions, and the index-term constructors (`hmac_256`, `ore_block_256`, `bloom_filter`) moved to `eql_v3_internal`. This keeps the SDK's emitted domain names byte-matched to the installed bundle so `CREATE TABLE`/cast resolution succeeds.
- e297f64: Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
  `stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
  README teach only the v3 typed surface (`Encryption`, the `types.*` concrete
  domains, the `@cipherstash/stack-drizzle` package root, `encryptedSupabase`);
  EQL v2 shrinks to read-compatibility notes. Two places keep more detail because
  stored EQL v2 data is still reachable there:

  - **DynamoDB reads.** `encryptedDynamoDB` writes EQL v3 only, but `decryptModel`
    / `bulkDecryptModels` can read previously stored v2 items when passed the
    corresponding v3 table and `{ storedEqlVersion: 2 }`, so the
    `stash-dynamodb` skill documents that explicit compatibility path (#657).
  - **The encrypt rollout lifecycle.** `stash encrypt *` and `@cipherstash/migrate`
    classify a column from its Postgres domain type: a `public.eql_v3_*` domain is
    recognised as v3, and anything else — including a legacy `eql_v2_encrypted`
    column — does not classify. The documented lifecycle is the v3 one
    (backfill → switch the application to the encrypted column → drop the
    plaintext); legacy v2 columns are read-only, covered under a version callout
    (#648).

  Also corrects the legacy `@cipherstash/drizzle` README's pointer to the removed
  `@cipherstash/stack/drizzle` subpath (now the separate `@cipherstash/stack-drizzle`
  package).

- 8817cfb: Correct the `config.keyset` docs on what omitting the option resolves to.

  The `Encryption()` and `ClientConfig.keyset` doc comments said omitting
  `config.keyset` uses "the workspace's default keyset". The actual resolution
  is the **client's** default keyset — the keyset the ZeroKMS client behind
  your credentials was created against. The two coincide when the client was
  created without naming a keyset — as with the profile credentials in a dev
  environment — but a client created against a named keyset defaults to that
  keyset, so two processes that both omit `config.keyset` share a keyspace
  only if their clients default to the same keyset. The docs now say exactly
  that.

- a5fab3c: Correct shipped documentation that claimed the tooling detects a column's EQL
  **v2** generation. It does not, and has not since `classifyEqlDomain` dropped v2:
  detection is one-sided — a `public.eql_v3_*` Postgres domain classifies as **v3**,
  and anything else (a plaintext column, or a legacy `eql_v2_encrypted` one)
  classifies as _unknown_ and falls through to the **v2** lifecycle. The v2 path is
  reached by fallback, not by detection, and a v2 column records no `eqlVersion` in
  `.cipherstash/migrations.json`, so `stash encrypt status` reports no version for
  it.

  - `skills/stash-supabase/SKILL.md` said the CLI "still auto-detects a v2 column"
    (twice, once inside the "Stay on v2 for now" bullet — exactly the case it got
    wrong) and that `stash encrypt drop` picks its target from a version the CLI
    "auto-detects". All three now describe the one-sided rule, matching the correct
    wording already in the same file's EQL version note. This skill is copied into
    customer repos by `stash init`, so the wrong version of it was being installed
    as guidance.
  - `packages/migrate/README.md` documented `detectColumnEqlVersion(client, table,
column)` as returning `2`, `3`, or `null`. It cannot return `2` — the return
    type is now stated as `3` or `null`, with what a `null` means for the caller.
    The lifecycle intro no longer presents the v2 ladder as a detection result.
  - `packages/stack/README.md`'s Supabase example imported and called
    `encryptedSupabaseV3`, the `@deprecated` alias, contradicting the same file's
    package table and v3-only note. It now uses `encryptedSupabase`.

  Documentation only — no behaviour change.

- 04f7ac7: Document the `Date` reconstruction boundary on `decrypt` / `bulkDecrypt`, and correct the reason given for it.

  A `types.Date` / `types.Timestamp` column comes back as a `Date` from `decryptModel(row, table)` and as the string it was stored as from `decrypt(payload)` / `bulkDecrypt(payloads)`. Reconstruction is driven by the table's `cast_as`, and only the model path is handed a table. That split is intentional — the raw methods resolve to the FFI plaintext union, which excludes `Date`, so reconstructing without widening the return type would make the declared type wrong — but it was undocumented, and the JSDoc explained it with a reason that does not hold: that a lone ciphertext "carries no column identity". Every stored payload carries `i: { t, c }`, so the identity is present and simply unused. The real constraint is static typing (TypeScript cannot know which column a runtime payload came from), not a missing capability at runtime.

  No behaviour change. What changed:

  - `decrypt` and the new `bulkDecrypt` JSDoc state the boundary, its consequence, and the actual reason, on both the native and `wasm-inline` entries.
  - The one-arg `decryptModel(row)` / `bulkDecryptModels(rows)` overloads had the same wrong justification ("there is no `cast_as` to reconstruct from"); corrected to name the real one — the `table` argument is what selects reconstruction, and `Decrypted<T>` types those fields `string` to match.
  - `skills/stash-encryption` and the `@cipherstash/stack` README now call out the `Date`-vs-string consequence and point at the model helpers. Both also stop calling `bulkEncrypt` untyped: its plaintexts are pinned to the column's domain via `{ table, column }`, exactly like `encrypt` — it is `bulkDecrypt`, which takes the payloads alone, that resolves to the untyped plaintext union.
  - `bulkDecrypt` was the one path with no test either way; it is now pinned, using a payload whose `i: { t, c }` names a registered date-like column, so a future change of heart is a deliberate decision rather than a silent drift.
  - The boundary is pinned at the type layer too, which is the layer it is argued from: the raw paths resolve to the FFI plaintext union with no `Date` arm, the table-taking model path resolves to `Date`, and the table-less one to `string`. If `JsPlaintext` ever gains a `Date` arm upstream, the justification for the split expires — and the type tests fail rather than the docs quietly going stale.

  Resolves #779.

- c516b34: Follow the `@cipherstash/stack-drizzle` package-root collapse in the packages that
  document it.

  - **`stash`:** `stash init --drizzle` emits the package-root
    `extractEncryptionSchema` import, and the bundled `stash-drizzle` and
    `stash-encryption` skills match.
  - **`@cipherstash/stack`:** README only — its Drizzle section documents the
    package-root exports.

- 4d92090: Remove the EQL v2-only published packages `@cipherstash/protect`,
  `@cipherstash/schema`, and `@cipherstash/protect-dynamodb` from the repository
  and the release train. They formed a closed dependency chain
  (`@cipherstash/protect-dynamodb` → `@cipherstash/protect` → `@cipherstash/schema`)
  and are superseded by `@cipherstash/stack`:

  - `@cipherstash/protect` (core encryption) → `@cipherstash/stack`, which now
    carries the encryption client directly.
  - `@cipherstash/schema` (schema builders) → the EQL v3 `encryptedTable` and
    `types.*` factories from `@cipherstash/stack/eql/v3`.
  - `@cipherstash/protect-dynamodb` (standalone DynamoDB adapter) →
    `@cipherstash/stack/dynamodb` (`encryptedDynamoDB`), the maintained
    implementation.

  Already-published versions remain installable from npm; the git history
  preserves the source for any emergency maintenance. Existing EQL v2 ciphertext
  stays decryptable through `@cipherstash/stack` — this removes the v2 authoring
  and emission surface, not the read path.

- b2f9d7a: Use the consolidated v3 client name in generated code and shipped guidance.

  `stash init` now scaffolds `Encryption` from `@cipherstash/stack/v3`, so a v3
  schema and its client come from one import specifier. The former suffixed client
  alias has been removed from the public API.

  Corrects the bundled agent skills and package docs, which described
  `encryptedSupabase` as the legacy EQL v2 wrapper. It is the EQL v3 factory;
  the v2 wrapper was removed. Also drops the stale "DynamoDB still requires v2"
  note from the `@cipherstash/stack` README — DynamoDB writes EQL v3 and reads
  existing v2 items.

- f23f952: Remove the leftovers from the secrets removal (`1929c8fe`), which deleted
  `packages/stack/src/secrets/` but left its export, build entry, skill, and docs
  behind. Secrets tooling is not ready; nothing here was functional.

  - **Drop the dead `@cipherstash/stack/secrets` subpath export.** It pointed at
    `./dist/secrets/index.js`, which has no source and is not in the tarball, so
    `import '@cipherstash/stack/secrets'` has been throwing `ERR_MODULE_NOT_FOUND`
    for every consumer since the source was removed. Also drops the dangling
    `src/secrets/index.ts` entry from `tsup.config.ts`. Removing an export that
    cannot resolve breaks nothing.
  - **Remove the `stash-secrets` agent skill** and its references in `AGENTS.md`
    and the init setup-prompt skill index. It was never installed by `stash init`
    (it is absent from `SKILL_MAP`), so no user project ever received it.
  - **Remove the secrets documentation** from both published READMEs: the
    `Secrets` class API and the `npx stash secrets` command reference in
    `@cipherstash/stack`, and the `npx stash secrets` section in `stash`. The CLI
    command does not exist — `stash secrets` returns `Unknown command`.

- 40ab142: Docs: stop teaching the deprecated `LockContext.identify()` as the primary
  identity-aware-encryption path (#591). The `stash-encryption` and `stash-supabase`
  skills and the `@cipherstash/stack` README now lead with the current pattern —
  authenticate the client with `OidcFederationStrategy`, then bind the claim per
  operation with `.withLockContext({ identityClaim })` — and demote
  `LockContext.identify()` to a clearly-marked deprecated note (per-operation CTS
  tokens were removed in protect-ffi 0.25). Skills ship in the `stash` tarball, so
  this keeps the bundled guidance correct for the 1.0 surface.
- ea74846: `@cipherstash/stack/adapter-kit` is now importable in a runtime with no `process` global.

  The shared logger read `process.env.STASH_STACK_LOG` unguarded while initialising at module scope, so importing adapter-kit — which re-exports that logger — threw `ReferenceError: process is not defined` before any user code ran. The environment read is now guarded.

  This is not a single-adapter fix. `@cipherstash/stack-supabase`, `@cipherstash/stack-drizzle` and `@cipherstash/stack-prisma` all value-import `@cipherstash/stack/adapter-kit`, so edge users of all three hit the same import-time throw, and all three are fixed by this release.

  **No behaviour change on Node.** `STASH_STACK_LOG`, its accepted values (`debug` / `info` / `error`), its `error` default, and the point at which the logger is configured are all unchanged.

- 20cb8c3: README only — drop the removed `--proxy` / `--no-proxy` flags from the `stash init`
  flag table.

  The flags went away with the EQL v2 CipherStash Proxy lifecycle: they are absent
  from the CLI command registry, and `stash init` now rejects them with an
  actionable message. `packages/cli/README.md` and the bundled `stash-cli` skill
  were already updated, but this table row in the `@cipherstash/stack` README —
  which ships in the tarball — still documented them as supported.

- 57441cc: The npm README for `@cipherstash/stack` is now the root Stack README — the
  package copy had drifted badly out of date. The root `README.md` is the single
  source of truth: the package's `prebuild` script copies it in before every
  build (npm cannot publish a symlink, so a real file has to ship in the
  tarball), and a unit test fails CI if the two files ever drift apart.
- 17393b9: Two new bundled agent skills for the integrations that don't use an ORM —
  `stash-postgres` and `stash-edge` (#754).

  Everything a raw-SQL or edge integration needed was reachable only from
  `dist/*.d.ts` JSDoc, the Postgres catalog, or experiment: grepping the skills
  `stash init` installs for `postgres-js|::jsonb::eql|sql.json|query_text_search`
  returned a single hit, in an unrelated code comment.

  **`stash-postgres`** — hand-written SQL over `pg` / `postgres-js`, no ORM. The
  column-domain-to-query-domain operator matrix (which of `=`, `<>`, `<`, `>=`,
  `@@`, `@>` each encrypted domain accepts, and against which `eql_v3.query_*`
  operand), the storage-vs-query payload distinction, per-driver parameter
  binding, recipes for equality / free-text / range / `ORDER BY` / JSON
  containment / JSON field selectors, and the `information_schema` drift check.
  Two failure modes get their mechanism spelled out: pre-stringifying a payload
  on postgres-js double-encodes it into a jsonb _string_ scalar, tripping the
  domain CHECK with a message naming neither JSON nor encoding; and leaving an
  operand as bare `jsonb` silently selects a different operator overload — one
  that coerces to the _storage_ domain and so rejects the ciphertext-free query
  term. It also scopes itself against the two things a hand-written-SQL reader
  is otherwise left to infer: **CipherStash Proxy** (where you write plaintext
  SQL and none of the skill applies — the `usesProxy` fork `stash init` already
  asked about), and the provenance of the operator surface itself (the EQL
  bundle from `cipherstash/encrypt-query-language`, version-checkable with
  `SELECT eql_v3.version()`, and where operator gaps should be filed). Its
  domain and operator tables are explicitly marked as a snapshot of a versioned
  surface, with a ranked list of authorities to confirm current types against —
  the EQL skill first, then the generated `@cipherstash/eql` types and install
  SQL, both of which need only `node_modules` and no database.

  **`stash-edge`** — the `@cipherstash/stack/wasm-inline` entry for Deno,
  Supabase Edge Functions, Cloudflare Workers, and Bun. Import specifier per
  runtime, the four mandatory `CS_*` variables and minting them with
  `stash env`, how the WASM client surface differs from the native typed client
  (no `.audit()`, no `.withLockContext()`, per-item bulk shape, a required
  `table` argument on `decryptModel` / `bulkDecryptModels`, ESM-only), and the
  auth-strategy `Result` that must be unwrapped before it reaches
  `config.authStrategy`.

  It also separates the two mechanisms behind identity-bound encryption, which
  are routinely conflated — and which the source comment on the entry itself got
  wrong. An auth strategy decides _who the client is_; a lock context decides
  _which key the value is encrypted under_. Only the first exists on this entry,
  so an `authStrategy` alone still writes values encrypted under the workspace
  key, and the entry cannot read what the native one wrote under a lock context.
  That is a silent read split between the two entries, and the skill says so
  rather than leaving it to be discovered as a failed decrypt.

  Both carry **the credential-identity rule**, a silent data-loss footgun now
  also stated in `stash-cli` (under `env` and `encrypt backfill`) and
  `stash-supabase`: EQL index terms derive from the ZeroKMS client key, so rows
  written under one credential and queried under another decrypt correctly and
  never match a query, with no error.

  `stash-encryption` now states that the two entries' schema types **do not
  interchange** — their column classes carry private fields, so TypeScript
  compares them nominally and rejects a shared schema module in both directions.
  It works at runtime, which makes a type assertion the tempting fix; the
  guidance is to author the schema against exactly one entry instead.

  `stash init` / `stash impl` handoffs and the `@cipherstash/wizard` skills
  prompt install both skills for the `postgresql` and `supabase` integrations.
  Drizzle and Prisma Next get cross-links from their own skills instead, since
  those integrations emit correctly-typed operands themselves.

  Also fixes the `@cipherstash/stack/wasm-inline` module JSDoc, which showed
  `OidcFederationStrategy.create(...)`'s `Result` being passed straight to
  `config.authStrategy` without unwrapping — the same JSDoc the raw-SQL surface
  was being reverse-engineered from.

- 5d304ec: The declaration gate now covers all three emitted type artifacts, not just one.

  `packages/stack/dist-types` typechecks what `tsc` emits rather than what the
  source says — the gap that let typed `encryptQuery` ship uncallable for every
  column through the whole rc series. It resolved `../dist/*.js` by relative path
  under bundler resolution, which never consults the `exports` map, so it only ever
  exercised the ESM `.d.ts` set. `tsup` emits the CJS `.d.cts` set in a separate
  pass and `wasm-inline.d.ts` in a third, each with its own inlined copy of the
  column class whose domain parameter the bug was about.

  A second suite now resolves `@cipherstash/stack/*` **by package name** under
  `moduleResolution: node16`, with the file extension selecting the condition
  (`.cts` → `require` → `.d.cts`, `.mts` → `import` → `.d.ts`), plus a probe for
  the `wasm-inline` entry — the documented target for Workers, Deno, Bun and
  Supabase Edge, and previously the one artifact nothing typechecked. Removing the
  phantom domain carrier makes all three fail, so none of them passes vacuously.

- 310bb19: `Encryption` now exposes one EQL v3-only construction path and returns
  `EncryptionClient<S>` consistently for the supplied schemas:

  ```ts
  const config: ClientConfig = { keyset };
  const client = await Encryption({ schemas: [users], config });
  // type and runtime share the same generic EncryptionClient<S> surface
  ```

  The public client no longer exposes a separate `init` method or a config option
  that can select EQL v2. Initialization happens through `Encryption`, which
  always configures EQL v3 and prevents the former type/runtime split.

- 856dcc8: Fixed: `encryptQuery` on the typed EQL v3 client did not typecheck against the
  published package — for any column.

  ```ts
  const users = encryptedTable("users", { email: types.TextSearch("email") });
  const client = await Encryption({ schemas: [users] });

  client.encrypt("a@b.com", { table: users, column: users.email }); // fine
  client.encryptQuery("a@b.com", { table: users, column: users.email });
  // TS2345: Argument of type '"a@b.com"' is not assignable to parameter of type 'never'
  ```

  `PlaintextForColumn` and `QueryTypesForColumn` recover a column's domain with
  `C extends EncryptedV3Column<infer D>`, which needs `D` to appear bare somewhere
  in the instance type. Its only bare occurrence was a **private** field, and
  `tsc` strips the types of private members on declaration emit — so in the
  shipped `.d.ts` the inference fell back to the `V3DomainDefinition` constraint.
  `QueryTypesForColumn` collapsed to `never`, which made `QueryableColumnsOf`
  `never`, which typed every query plaintext `never`. `encrypt` was unaffected
  because it resolves through `ColumnsOf`.

  `EncryptedV3Column` now carries a type-only `declare readonly __domain?: D`.
  Nothing is emitted at runtime and no call site changes; the declaration survives
  emit and restores the inference site.

  This affected every published release with the v3 typed client, including
  `1.0.0-rc.4` — the searchable-query recipes in the `stash-encryption` skill did
  not compile in a customer's repo. It was invisible in CI because the type tests
  import source rather than `dist/`; a new `test:types:dist` suite now typechecks
  the emitted declarations and is wired into CI.

- c745db7: Three fixes to the EQL v3-only surface.

  **DynamoDB: grouped v2 `date` / `timestamp` columns now reconstruct to `Date`.**
  A legacy grouped field is stored as `<group>.<leaf>__source` while the v2 schema
  knew it only as `<leaf>`, so a `{ storedEqlVersion: 2 }` read matches it by its
  bare leaf and writes the plaintext back at the nested path (`details.placedAt`).
  Both clients resolve their date columns from the _declared_ paths, so neither
  reconstructed that value and it came back as an ISO string. The read path now
  reports the path it actually wrote to and the adapter reconstructs there —
  covering the native and `wasm-inline` entries, on `decryptModel` and
  `bulkDecryptModels` alike. Carrying a grouped date forward as a plain top-level
  column no longer requires re-declaring it as a dotted path.

  **`EncryptionClientConfig` no longer accepts an empty schema set.** Its default
  type argument widened to `readonly AnyV3Table[]`, where `S['length']` resolves to
  `number` and the non-empty conditional stopped firing, so
  `const cfg: EncryptionClientConfig = { schemas: [] }` typechecked and then threw
  at `Encryption(cfg)`. The default is a non-empty tuple again, matching
  `WasmEncryptionConfig`. The factory still accepts widened arrays passed inline.

  **`config.eqlVersion: undefined` is tolerated at runtime.** `eqlVersion?: never`
  admits an explicit `undefined` (this repo does not enable
  `exactOptionalPropertyTypes`, and no declaration can reject it), but both
  factories threw on the mere presence of the key — failing a config the published
  types accept. An explicit `undefined` names no version and is now allowed; every
  real value, `eqlVersion: 3` included, is still rejected.

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

- 3a0a0dc: The `@cipherstash/stack/wasm-inline` `Encryption` factory now accepts the same
  schema-array shapes the native entry does.

  `WasmEncryptionConfig.schemas` was a mutable non-empty tuple
  (`[AnyV3Table, ...AnyV3Table[]]`), which rejects every form that is not an array
  literal: a shared `export const all: AnyV3Table[]`, a `ReadonlyArray`, a
  `.map()` result, anything spread or push-built. The native factory was widened
  to `readonly AnyV3Table[]` for exactly that reason; the WASM twin kept the
  tuple, so the two entries disagreed about identical calls while their runtimes
  agreed exactly (both check only `schemas.length`).

  Non-emptiness moves to the `Encryption` overloads, so `Encryption({ schemas: [] })`
  remains a compile error on this entry too. The built `wasm-inline.d.ts` is now
  covered by the declaration gate, which is where this drift went unnoticed — the
  entry gets its own tsup DTS pass that no source-level type test can see.

## 1.0.0-rc.4

### Minor Changes

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

- 508f1d5: **Breaking (`@cipherstash/stack/wasm-inline`):** every fallible method now returns a `Result` — `{ data } | { failure }` — instead of throwing. And `bulkEncrypt` / `bulkDecrypt` are added, so a list of encrypted rows costs **one** ZeroKMS round trip instead of one per row.

  ### Result alignment

  `encrypt`, `decrypt`, `encryptQuery` and `encryptQueryBulk` previously threw on failure, and returned bare values on success. They now return `{ data } | { failure }`, with `failure.type` drawn from `EncryptionErrorTypes` (`EncryptionError` for encrypt-side operations, `DecryptionError` for decrypt-side) and `failure.code` carrying the FFI error code where there is one.

  ```typescript
  // before
  const encrypted = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });

  // after
  const result = await client.encrypt(plaintext, {
    table: users,
    column: users.email,
  });
  if (result.failure) throw new Error(result.failure.message);
  const encrypted = result.data;
  ```

  This is the contract the native entry has always honoured, and the one `AGENTS.md` states outright: _"Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`."_ The WASM entry never followed it. That was drift rather than a design decision — nothing about WASM prevents it (`@byteslice/result` is already bundled into `dist/wasm-inline.js`), and it meant edge code had to be written in a different shape from every other surface, with failures that were easy to miss.

  Fixed now because it is a breaking change and 1.0.0 has not shipped: `@cipherstash/stack@latest` is still `0.19.0`, so this surface has only ever been published under the `rc` tag. After GA it would have had to wait for a major.

  `isEncrypted` is unchanged — a pure predicate with nothing to fail at, exactly as on the native entry.

  ### Bulk operations

  ```typescript
  // Write: several columns across many rows, one round trip
  const encrypted = await client.bulkEncrypt([
    { plaintext: "alice@example.com", table: users, column: users.email },
    { plaintext: "hello", table: users, column: users.bio },
  ]);

  // Read: a whole page in one call
  const emails = await client.bulkDecrypt(rows.map((r) => r.email));
  ```

  The WASM entry previously exposed no bulk operations at all, so rendering an N-row list on Deno, Cloudflare Workers, or Supabase Edge Functions meant N sequential ZeroKMS calls. Combined with the WASM cold start, that made list endpoints impractical on the edge.

  Both are index-aligned with their input, and `null` / `undefined` entries yield `null` at the same index without reaching ZeroKMS (an all-null batch makes no call at all). Because each entry names its own table and column, a single `bulkEncrypt` can cover several columns across many rows — which is what makes the saving real, since a single-column batch would still cost one round trip per column.

  `bulkDecrypt` builds on the fallible FFI primitive, so when items fail the `failure.message` names **every** failing index with its reason, rather than surfacing the first and discarding the rest.

  The model helpers (`encryptModel` / `decryptModel` and their bulk forms) remain Node-only: the WASM entry has no single-model operation to build them on, so those need their own port.

## 1.0.0-rc.3

### Patch Changes

- 8b2551a: Fix "Failed to load native binding" on project-local installs of the CLI/SDK
  (npm). `@cipherstash/auth` was pinned at 0.41.0 while the six
  `@cipherstash/auth-*` platform bindings declared in stack/stash/wizard's
  optionalDependencies were pinned at 0.42.0. Because auth pins its bindings as
  exact-version optional peer dependencies, the skew made npm nest per-consumer
  binding copies that the hoisted `auth` package could not resolve — any command
  or import touching auth then died at startup. All seven packages now move in
  lockstep at 0.42.0, Dependabot is barred from bumping any of them
  independently, and a supply-chain CI test fails on any future skew.

## 1.0.0-rc.2

### Minor Changes

- b085f66: `@cipherstash/stack/wasm-inline` now exposes `encryptQuery` and
  `encryptQueryBulk` on `WasmEncryptionClient` (#662) — searchable encryption
  is reachable on Deno/edge runtimes. Previously the WASM entry exposed only
  `encrypt`/`decrypt`/`isEncrypted`, so encrypted WHERE-clause search was
  architecturally impossible on the edge even though the underlying protect-ffi
  WASM build carries the capability.

  The new methods mint ciphertext-free EQL v3 query terms — equality,
  free-text match, ORE range, and JSON containment/selector — with the same
  index-type resolution as the native client (explicit `queryType`, or
  inference from the column's configured indexes). Cast the term to the
  column's `eql_v3.query_<domain>` type in SQL to reach the indexed operators.
  Errors throw, consistent with the WASM surface's `encrypt`/`decrypt`; the
  bulk form is position-stable (`null` values pass through as `null`).

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

- e297f64: Docs: EQL v3 is now the sole documented approach. The `stash-encryption`,
  `stash-drizzle`, and `stash-supabase` skills and the `@cipherstash/stack`
  README teach only the v3 typed surface (`EncryptionV3`, `types.*` concrete
  domains, `@cipherstash/stack-drizzle/v3`, `encryptedSupabaseV3`); EQL v2
  shrinks to one short Legacy section per document. Two explicit exceptions are
  called out: DynamoDB still requires the v2 schema surface (#657), and the
  encrypt rollout tooling (`stash encrypt backfill`/`cutover`,
  `@cipherstash/migrate`) currently targets v2 columns (#648) — its guidance is
  kept under a version callout. Also corrects the legacy `@cipherstash/drizzle`
  README's pointer to the removed `@cipherstash/stack/drizzle` subpath (now the
  separate `@cipherstash/stack-drizzle` package).
- 40ab142: Docs: stop teaching the deprecated `LockContext.identify()` as the primary
  identity-aware-encryption path (#591). The `stash-encryption` and `stash-supabase`
  skills and the `@cipherstash/stack` README now lead with the current pattern —
  authenticate the client with `OidcFederationStrategy`, then bind the claim per
  operation with `.withLockContext({ identityClaim })` — and demote
  `LockContext.identify()` to a clearly-marked deprecated note (per-operation CTS
  tokens were removed in protect-ffi 0.25). Skills ship in the `stash` tarball, so
  this keeps the bundled guidance correct for the 1.0 surface.
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

- c4787c0: Restore the EQL v3 envelope and `Result` types the adapters were erasing.

  Both v3 adapters typed their operand-encryption paths as `unknown` and dropped
  the `Result` wrapper, so the query-type encoding and the failure channel were
  invisible to the type system:

  - `eql/v3/drizzle/operators.ts` typed the client's `encrypt`/`bulkEncrypt` as
    returning `unknown`, collapsed the operation's `Result` to
    `{ data?: unknown; failure?: { message } }`, and cast the bulk response to
    `Array<{ data: unknown }>`.
  - `supabase/query-builder-v3.ts` returned `Promise<unknown[]>` from
    `encryptCollectedTerms`, `bulkEncryptGroup` and `encryptGroupPerTerm`, and the
    base `query-builder.ts` did the same.

  These now carry the SDK's real types — `Encrypted` (the storage envelope union,
  which includes every v3 per-domain payload), `BulkEncryptedData`, and
  `EncryptedQueryResult` — threaded through a properly-typed operation surface that
  resolves `Result<T, EncryptionError>`. The Supabase divergence the erasure hid is
  now explicit: the v2 path yields `encryptQuery` composite literals and the v3
  path yields `JSON.stringify`'d envelope strings, and both are `EncryptedQueryResult`.

  Bumped `minor`, not `patch`: `createEncryptionOperatorsV3` is a public export
  (`@cipherstash/stack/eql/v3/drizzle`), and tightening its client contract from
  `unknown` to a typed operation surface is a compile-time breaking change — a
  downstream consumer passing a loosely-typed (`unknown`-returning) client double
  will now fail `tsc`. That tightening has teeth: `operators.test-d.ts` pins it
  with a negative type-test asserting an `unknown`-returning `{ encrypt }` double
  is rejected (a positive "correctly-typed double is accepted" assertion cannot
  catch a re-erasure, since a correct value is assignable to `unknown`).

  Behaviour is otherwise unchanged, with one addition: the Supabase v3 bulk path
  now rejects a `null` envelope returned by `bulkEncrypt` (the restored
  `Encrypted | null` type makes that arm reachable, and a `null` would otherwise
  be `JSON.stringify`'d to the literal `"null"` and sent as a filter operand).

- 66a0e02: Add the EQL v3 bigint domain family to the public DSL: `types.Bigint`,
  `types.BigintEq`, `types.BigintOrdOre`, and `types.BigintOrd`, backed by the
  `public.bigint*` concrete domains. Plaintext is a JS `bigint`, round-tripped
  losslessly across the protect-ffi 0.28 boundary (i64 bounds enforced at the
  FFI — out-of-range values surface as encryption errors). Index emission follows
  the numeric rule: `bigint_eq` → unique (hm); `bigint_ord`/`bigint_ord_ore` →
  ore (equality answered via ob).
- 7eba32d: EQL v3 Drizzle: encrypt every query operand with `encryptQuery`, not `encrypt` (#622).

  The v3 Drizzle operators (`eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`notBetween`/
  `inArray`/`notInArray`/`contains`) previously encrypted their operands with
  `client.encrypt`, producing a full storage envelope (including the ciphertext `c`)
  cast to `::jsonb`. A WHERE-clause operand should be a query _term_, not a value to
  store. Every operator now uses `client.encryptQuery`, which yields a
  ciphertext-free query term cast to the column's `eql_v3.query_<domain>` type — so
  predicates carry no ciphertext and reach the bundle's `(domain, query_<domain>)`
  operator overloads. This unifies the scalar/text operators with the JSON
  containment path (already on `encryptQuery`) and removes the previously-optional
  `encryptQuery` guard: it is now a required capability of the operand client.

  `@cipherstash/stack` gains a batch `encryptQuery(terms)` overload on
  `TypedEncryptionClient` (the type `EncryptionV3` returns), mirroring the nominal
  `EncryptionClient`. This is additive — it lets `inArray`/`notInArray` encrypt a
  whole list of query terms in one crossing.

- 0ebf57e: Close two fail-open paths in the EQL v3 Drizzle adapter.

  `ops.contains()` now throws `EncryptionOperatorError` for a search term that
  tokenizes to nothing: the empty string, or a term shorter than the match index
  tokenizer's `token_length` (3 by default). Such a term produces an empty bloom
  filter, and `stored_bf @> '{}'` is true for every row — so a user searching
  `"ad"` silently received the entire table. Measured live, the terms `"ad"`,
  `"a"` and `"x"` each returned every seeded row, including one in which `"x"`
  did not appear.

  The floor counts Unicode codepoints, matching the tokenizer. A UTF-16 length
  check would wave through an astral-plane term — `"👍👍"` is 4 code units but
  only 2 codepoints, yields no trigram, and matched every row.

  **Breaking for callers passing short terms:** `contains()` calls that previously
  returned every row now throw. Terms of 3+ codepoints are unaffected.

  `v3FromDriver()` now throws the new `EqlV3CodecError` on a payload that is not
  an EQL envelope, instead of surfacing a raw `SyntaxError` for malformed JSON and
  passing a bare scalar through unchecked — `v3FromDriver('5')` previously returned
  `5` typed as `Encrypted`, which then reached `decrypt` as garbage. The guard
  accepts both scalar envelopes (ciphertext at `c`) and SteVec documents
  (ciphertext at `sv[0].c`). A SteVec's `sv` must be a non-empty array: `sv[0]` is
  the decryption root, so `sv: []` carries a ciphertext key but no ciphertext, and
  is now rejected rather than passed to `decrypt`. `EqlV3CodecError` is exported
  from `@cipherstash/stack/eql/v3/drizzle` so callers can catch it.

  Also removes an unreachable branch in `inArray`/`notInArray`, whose empty-list
  guard already throws before it.

  Note: the v2 Drizzle adapter's `like`/`ilike` path builds the same bloom filters
  and has the same short-term fail-open. It is **not** fixed here — v2 terms carry
  SQL wildcards, so the floor must be measured against what its tokenizer actually
  receives before the shared guard can be reused. Tracked separately.

- d73a03c: Add EQL v3 Drizzle support at `@cipherstash/stack/eql/v3/drizzle`. A Drizzle-native
  `types` namespace (same PascalCase names as `@cipherstash/stack/eql/v3`) declares
  encrypted columns whose Postgres type is the semantic `public.<domain>`; the concrete
  type drives the legal query operators. `createEncryptionOperatorsV3` provides
  capability-checked `eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`contains`/`inArray`/
  `asc`/`desc`/`and`/`or` that emit the latest two-argument `eql_v3` SQL functions with
  full-envelope operands, and
  `extractEncryptionSchemaV3` rebuilds the schema for `EncryptionV3`. The existing v2
  `@cipherstash/stack/drizzle` integration is unchanged.

  The v3 text-search helper is `contains`; obsolete `like`/`ilike` helpers are not
  exposed because v3 free-text search is token containment rather than SQL wildcard
  matching.

- 89b903f: Upgrade `@cipherstash/protect-ffi` to 0.28.0 and update EQL v3 concrete Postgres domain names to match the SQL fixture (`integer*`, `smallint*`, `bool`, `real*`, and `double*`). The public factories remain semantic (`Integer`, `Smallint`, `Boolean`, `Real`, `Double`) while their concrete domains change, so this is a minor release.
- 229ce59: Re-baseline EQL v3 on the eql-3.0.0 GA release and protect-ffi 0.29.

  - **Breaking (v3 preview surface):** the EQL v3 column domains follow the
    eql-3.0.0 naming convention — flat, prefixed names in `public`
    (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, …) instead of the
    alpha-era bare names. Databases installed from an alpha bundle must be
    re-installed (`stash eql install --eql-version 3` replaces the schema).
  - `encryptQuery` under `eqlVersion: 3` now returns EQL v3 query operands
    (protect-ffi 0.29): term-only scalar operands for the `eql_v3.query_<name>`
    domains, the `eql_v3.query_jsonb` containment needle, and bare selector
    hashes for JSON path queries — v3 scalar and selector queries no longer
    throw `EQL_V3_QUERY_UNSUPPORTED` (the code is gone).
  - v2 `searchableJson()` columns now pin the SteVec encoding to `standard`
    explicitly. protect-ffi 0.29 flipped the library default to `compat`
    (EQL v3's encoding); without the pin, v2 JSON containment queries would
    silently match nothing and newly written rows would not be comparable with
    existing ones.
  - The EQL v3 test/install SQL is sourced from the pinned `@cipherstash/eql`
    package (3.0.0) instead of a hand-vendored fixture.

- 50c0a9c: Add EQL v3 JSON columns. `types.Json('col')` declares a `public.eql_v3_json`
  column that encrypts a JSON document to an ste_vec `SteVecDocument` and
  round-trips it losslessly through `encrypt`/`decrypt` and the model path. A new
  `searchableJson` query capability emits the ste_vec index; the index uses
  `mode: 'compat'`, which eql-3.0.0's `eql_v3_json` requires (it orders ste_vec
  entries by the CLLW-OPE `op` term, so v2's `'standard'`/CLLW-`oc` terms are
  rejected).

  The Drizzle integration's `contains(col, subObject)` now answers encrypted-JSONB
  containment on a `types.Json` column, emitting the `@>` operator with a
  `query_jsonb` needle (from `encryptQuery`). The ste_vec index indexes array
  elements by identity but not position, so containment is a true subset test
  (`{ roles: ['x'] }` matches any document whose `roles` array contains `x`,
  regardless of index).

- 5d23e80: Add `encryptedSupabaseV3` — the EQL v3 dialect of the Supabase adapter. It is
  now a connect-time-async factory: `await encryptedSupabaseV3(url, key)` (or
  `(client)`) introspects the database over `DATABASE_URL`, detects EQL v3 columns
  by their Postgres domain (`information_schema.columns.domain_name`), and derives
  each column's encryption config from its domain — callers no longer pass a
  schema to `from()`. `select('*')` is supported (expanded from the introspected
  column list, and aliased back to each declared column's JS property name so a
  property→DB rename round-trips). A column using an EQL v3 domain this SDK version does not model
  (e.g. `public.json`, `*_ord_ope`) throws at construction rather than silently
  passing through. Supplying `schemas` remains optional and adds compile-time
  types plus startup verification of the declared tables against the database.
  Requires a Postgres connection for introspection (`pg` is a new optional peer),
  so it cannot run in a Worker or the browser.

  Every column name a query carries — filters, `match`, `not`, raw `filter`,
  `or()`, `order()`, and the `onConflict` option — is now resolved from its JS
  property name to its DB column name in a single pass before the query is built,
  so a declared rename round-trips everywhere rather than only on the paths that
  remembered to translate.

  `order()` on ANY encrypted v3 column is now rejected — at compile time when
  `schemas` is supplied, and at runtime otherwise. The EQL v3 domains are
  `DOMAIN … AS jsonb` and the bundle declares no btree operator class on them, so
  `ORDER BY col` resolves through jsonb's default `jsonb_cmp` and sorts by the
  envelope's byte structure: a stable, plausible-looking, meaningless row order,
  with no error. Correct ordering is `ORDER BY eql_v3.ord_term(col)`, which
  PostgREST's `order=` cannot express. Order by a plaintext column, expose
  `eql_v3.ord_term()` as a generated column or view, or use the EQL v3 Drizzle
  integration, which emits `ord_term` directly. Note `gte`/`lte` filters remain
  correct: the comparison operators _are_ declared on the ord domains, and only
  sorting resolves through the missing operator class.

  `.or()` now understands PostgREST's `column.not.<op>.<value>` negation. It was
  previously parsed as `{ op: 'not', value: '<op>.<value>' }`, so on an encrypted
  column `or('nickname.not.in.(ada,grace)')` encrypted the literal string
  `in.(ada,grace)` as a single plaintext and produced a filter that silently
  matched nothing.

  Free-text search on the v3 builder is `contains(column, value)`. `like`/`ilike`
  are not exposed, because EQL v3 free-text search is token containment over a
  bloom filter (`@>`, backed by `eql_v3.contains`) rather than SQL wildcard
  matching — `%` is tokenized like any other character, so a `like` pattern is a
  category error. This matches the v3 Drizzle integration, which omits them for
  the same reason. On an encrypted column `like`/`ilike` now throw and name
  `contains`; on a plaintext column they remain ordinary PostgREST filters.

  `contains` is narrowed at compile time to columns whose domain carries the
  `freeTextSearch` capability (`public.text_match`, `public.text_search`), and
  guarded at runtime for the untyped surface. A raw `filter(column, operator, …)`
  on an encrypted v3 column now derives its query type from the operator instead
  of always encrypting an equality term, so `filter('bio', 'cs', …)` on a
  `public.text_match` column works rather than being rejected, and an unsupported
  operator throws instead of silently encrypting the wrong term.

  Substring `contains` matches any needle whose trigrams are all present in the
  stored value; needles shorter than the tokenizer's window (3 characters) bloom to
  nothing and are rejected rather than silently matching every row. The v3 match
  index now emits `include_original: false` — the flag is inert in protect-ffi (the
  bloom is trigram-only either way), so this moves no ciphertext and only pins the
  value a substring-search domain wants.

  v2 (`encryptedSupabase`) is unchanged: it keeps `like`/`ilike` (`eql_v2.like`,
  `~~`) and its raw-`filter` query-type mapping, so no v2 ciphertext moves.

- 1aa9a11: Add the EQL v3 `text_search` authoring DSL on a new `@cipherstash/stack/eql/v3`
  subpath (`types.TextSearch`, v3 `encryptedTable` / `buildEncryptConfig`). The v3
  builders emit the existing `EncryptConfig` shape, so encryption, payloads, and
  query paths are unchanged at runtime.

  Also widens the public client types (`EncryptionClientConfig.schemas`,
  `EncryptOptions`, `SearchTerm`/`EncryptQueryOptions`) to a structural contract so
  both v2 and v3 builders are accepted by `Encryption` / `encrypt` / `decrypt` /
  `encryptQuery`. This is a backward-compatible widening — existing v2 usage is
  unaffected. The structural contracts themselves (`BuildableColumn`,
  `BuildableQueryColumn`, `BuildableV3QueryableColumn`, `BuildableTable`,
  `BuildableTableColumns`) and the `encryptModel` return-type mapper
  (`EncryptedFromBuildableTable`) are exported from `@cipherstash/stack/types` so
  consumers can name them.

- af2d04e: Add a strongly-typed EQL v3 client surface on a new `@cipherstash/stack/v3`
  subpath (`EncryptionV3`, `typedClient`, `TypedEncryptionClient`). It re-exports
  the v3 `types` namespace and table API (from `@cipherstash/stack/eql/v3`), so a
  single import provides everything needed to author and use a v3 schema.

  Every method derives its types from the concrete `table` / `column` builder
  arguments:

  - `encrypt` / `encryptQuery` pin the plaintext to the column's domain type
    (`text → string`, `timestamp → Date`, …).
  - `encryptQuery` constrains `queryType` to the column's capabilities and rejects
    storage-only columns at compile time.
  - `encryptModel` / `bulkEncryptModels` validate schema-column fields against their
    inferred plaintext type (passthrough fields are untouched) and return a precise
    encrypted model.
  - `decryptModel` / `bulkDecryptModels` return the precise plaintext model,
    reconstructing `Date` values from the encrypt-config `cast_as`.

  Because the typed methods bind to the concrete branded v3 classes, a hand-rolled
  structural table/column is rejected — closing the soundness gap where a non-branded
  table could be encrypted at runtime while typed as plaintext.

  Runtime behaviour is unchanged: the encrypt/query paths return the same operations
  as the base client; only the model-decrypt paths add a per-column `Date`
  reconstruction step. The v2 client surface (`Encryption`) is untouched.

- b8a3d20: Add EQL v3 schema builders for supported generated SQL domains under `@cipherstash/stack/eql/v3`, exposed as the `types` namespace (one member per supported EQL v3 domain, e.g. `types.TextEq` / `types.IntegerOrd` / `types.Timestamp`), including explicit query capability metadata (`getQueryCapabilities()` / `isQueryable()`) and v3 table support in model encryption helpers (`encryptModel` / `bulkEncryptModels`).

  Also widen the accepted plaintext input type for `encrypt` / `encryptQuery` to include `Date` (via the new `Plaintext` type), so v3 `date` / `timestamp` domains can be encrypted and queried with their natural JavaScript values.

- a0f3b2c: `@cipherstash/stack/wasm-inline` is now EQL v3 (#614).

  The WASM entry (Deno / Bun / Cloudflare Workers / Supabase Edge) previously
  created a client pinned to the FFI's EQL v2 wire format, so a v3 schema
  (concrete `eql_v3_*` domains) failed every encrypt on the edge. It now targets
  EQL v3 exclusively:

  - The factory constructs the WASM client with `eqlVersion: 3`, so v3 schemas
    encrypt/decrypt correctly on the edge.
  - The entry re-exports the **v3** authoring surface (`types`, `encryptedTable`,
    the column classes, `buildEncryptConfig`, and the inference helpers) — the
    same API as `@cipherstash/stack/eql/v3` — so an Edge Function authors and runs
    v3 from one import:

    ```ts
    import {
      Encryption,
      encryptedTable,
      types,
    } from "@cipherstash/stack/wasm-inline";

    const patients = encryptedTable("patients", {
      email: types.TextSearch("email"),
    });
    const client = await Encryption({ schemas: [patients], config });
    ```

  The v2 schema builders (`encryptedColumn` / `encryptedField` / the v2
  `encryptedTable`) are no longer exported from this entry, and passing a v2 table
  throws a clear error. The WASM path was never announced or documented for v2 and
  had no known users; EQL v2 remains fully supported on the native
  `@cipherstash/stack` entry.

- 5411a13: Add the `@cipherstash/stack/adapter-kit` subpath — a narrow support surface for
  the first-party adapter packages (`@cipherstash/stack-supabase`,
  `@cipherstash/stack-drizzle`) being split out of this package (#627). It
  re-exports exactly the core internals the adapters consume (the logger,
  `AuditConfig`, the v3 column model + `DATE_LIKE_CASTS`, the domain registry, the
  match-index guard, and the model→composite helpers) so those imports resolve
  across the package boundary without leaking six internal module paths. This is the
  core↔adapter seam, not general-purpose public API.
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
  quoted and escaped, matching what the `.or()` path already did. This affects
  **v2 as well as v3** — v2's `("a@b.com")` composite literal is itself
  quote-bearing and was equally broken.

  **`not(col, 'in', […])` encrypted the whole list as a single ciphertext**, so
  the filter silently matched nothing, and emitted an unparenthesized
  `not.in.a,b`. Each element is now encrypted separately and the operand is
  rendered as `not.in.(…)`. Passing a PostgREST list literal (`'(a,b)'`) for an
  encrypted column now throws instead of silently matching nothing — pass an
  array.

  **`filter(col, 'in', […])` encrypted the whole list as a single ciphertext.**
  The raw `.filter()` path reached `in` with none of the element-splitting the
  `in()`, `not(…, 'in', …)` and `.or()` paths perform, so the entire list operand
  was encrypted as one equality term. The two wire formats then failed
  differently, which is why this went unnoticed: **v2**'s `("json")` composite
  literal is already parenthesized, so PostgREST parsed it as a one-element list
  and answered `200 []` — a filter that silently matched nothing. **v3**'s bare
  `{…}` envelope is not, so PostgREST rejected the request outright with
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
  containment operand. Encrypted match columns still take a `string` token.
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
  Drizzle v3 path. Falls back to per-term encryption for clients without
  `bulkEncrypt`, and rejects a bulk response whose length does not match the list
  rather than silently truncating the predicate.

- 9b65ae8: **`order()` now works on EQL v3 encrypted ordering columns in the Supabase
  adapter.** It was rejected outright on every encrypted column.

  A bare `ORDER BY col` on an EQL v3 domain really is wrong — the bundle declares
  no btree operator class on any domain, so the sort falls through to jsonb's
  default `jsonb_cmp` and compares the envelope's keys in storage order, starting
  at the random ciphertext `c`. Measured over ten rows it returns
  `r00,r04,r08,r01,…` where the plaintext order is `r00..r09`. No error, a stable
  and plausible-looking meaningless order.

  But the correct sort key is reachable without a function call. `eql_v3.ord_term`
  returns the domain's `op` term, and OPE is order-preserving, so ordering by the
  term reproduces the plaintext order. PostgREST cannot emit
  `ORDER BY eql_v3.ord_term(col)`, but it can emit a jsonb path. The builder now
  emits `order=col->op` for an encrypted ordering column, verified against a live
  PostgREST for `integer_ord` and `text_search` in both directions.

  The guard is now on the ordering FLAVOUR, not on encryption:

  - **`ope` present → supported.** Every plain `*_ord` domain, plus `text_ord` and
    `text_search`.
  - **`ore` present → rejected.** The `ob` term is an array of ORE blocks whose
    comparison needs the superuser-only operator class, which no jsonb path can
    reach. (Such a column cannot hold data on managed Postgres anyway: its domain
    CHECK raises `ore_domain_unavailable`.) ORE columns are now excluded from
    `order()` at COMPILE time too, not only at runtime — `.order(oreColumn)` is a
    type error, matching the rejection.
  - **neither → rejected.** Storage-only, equality-only and match-only columns
    carry no ordering term.

  The path is `col->op` (jsonb), not `col->>op` (text). Neither avoids the
  database collation — Postgres compares jsonb strings with `varstr_cmp` under the
  default collation, exactly as it does text. What makes the ordering
  collation-independent is the term's encoding: lowercase hex, fixed-width for
  numeric and date domains, and per-character (16 hex chars each) for text, so
  lexicographic order reproduces plaintext order including the prefix case
  (`ada` < `adam`). `ope-term.integration.test.ts` pins that shape.

  `V3OrderableKeys` widens to admit OPE-backed ordering columns (`*_ord`,
  `text_ord`, `text_search`) while still excluding ORE (`*_ord_ore`) columns, so
  `order()` typechecks exactly where it works. `is(col, true)` is unaffected — it
  stays plaintext-only, and now has its own `V3PlaintextKeys` rather than
  borrowing the orderable set.

### Patch Changes

- cfd46ee: Source the EQL v3 install bundle from `@cipherstash/eql@3.0.0-alpha.3` instead of a hand-vendored 43k-line SQL fixture committed to the test tree. The package publishes its SQL and its TypeScript wire types from the same `eql-bindings` commit, so the bundle is now pinned to a released EQL version rather than tracked by convention.

  Test-and-tooling only — `@cipherstash/eql` is a `devDependency` and no public API changes.

  The staleness check in the v3 install helper now compares `eql_v3.version()` against the pinned release instead of probing for a hand-picked sentinel domain. The previous sentinel (`public.timestamp`) exists in both the old and new bundles, so it would have reported a stale install as current and left the suite silently running the wrong SQL.

- 63ca540: Re-vendor the EQL v3 SQL bundle and align the v3 DSL to it: encrypted type domains now live in the `public` schema (`public.text`, `public.integer`, …) rather than `eql_v3`, and the boolean domain is `public.boolean` (was `eql_v3.bool`). The `eql_v3` schema now holds only the operator-backing functions, and the index-term constructors (`hmac_256`, `ore_block_256`, `bloom_filter`) moved to `eql_v3_internal`. This keeps the SDK's emitted domain names byte-matched to the installed bundle so `CREATE TABLE`/cast resolution succeeds.
- f23f952: Remove the leftovers from the secrets removal (`1929c8fe`), which deleted
  `packages/stack/src/secrets/` but left its export, build entry, skill, and docs
  behind. Secrets tooling is not ready; nothing here was functional.

  - **Drop the dead `@cipherstash/stack/secrets` subpath export.** It pointed at
    `./dist/secrets/index.js`, which has no source and is not in the tarball, so
    `import '@cipherstash/stack/secrets'` has been throwing `ERR_MODULE_NOT_FOUND`
    for every consumer since the source was removed. Also drops the dangling
    `src/secrets/index.ts` entry from `tsup.config.ts`. Removing an export that
    cannot resolve breaks nothing.
  - **Remove the `stash-secrets` agent skill** and its references in `AGENTS.md`
    and the init setup-prompt skill index. It was never installed by `stash init`
    (it is absent from `SKILL_MAP`), so no user project ever received it.
  - **Remove the secrets documentation** from both published READMEs: the
    `Secrets` class API and the `npx stash secrets` command reference in
    `@cipherstash/stack`, and the `npx stash secrets` section in `stash`. The CLI
    command does not exist — `stash secrets` returns `Unknown command`.

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
  collector. Affects both `encryptedSupabase` (v2) and `encryptedSupabaseV3`. On
  v3 this additionally removes a spurious `does not support equality queries`
  error, which `is` raised because it maps to the `equality` query type and so hit
  the column-capability guard — `or('active.is.null')` on a storage-only column
  threw rather than querying.

  Relatedly, an `or()` string is now rebuilt whenever a condition _references_ an
  encrypted column, not only when one of its values was encrypted. An `is` on an
  encrypted column encrypts nothing, and the old condition sent it down the
  verbatim path, forwarding the caller's JS property name to a database that only
  knows the column's DB name.

- 8cd485d: Fix the Supabase adapter's `.or()` string parser mis-splitting conditions, and pin `contains()` on a mixed union column key to the encrypted operand.

  An `.or()` string is only rebuilt from its parse when it references an encrypted column — otherwise the caller's string is forwarded verbatim — so each of these corrupts precisely the mixed encrypted/plaintext case.

  **Quotes were tracked only at brace depth 0.** A `}` inside a quoted array element or jsonb string value closed the literal early, and the next `"` re-opened quoting, so the following top-level comma never split: `.or('tags.cs.{"a}b"},email.eq.secret')` parsed as a single condition and silently absorbed `email.eq.secret` into the operand. Quotes are now opaque at every depth.

  **A stray `}` or `)` drove the depth counter negative**, after which no comma split again. `}` and `)` are not PostgREST reserved characters, so `a}b` is a valid unquoted operand and `.or('nickname.eq.a}b,id.eq.1')` dropped `id.eq.1`. Depth now floors at zero.

  **`in`-list elements were split on every comma, ignoring quotes.** `.or('email.in.("a,b",c)')` parsed as three elements with the quotes still embedded; on an encrypted column each fragment was encrypted as its own term, so the intended element never matched. Elements are now split on top-level commas and unquoted, the inverse of what the rebuild emits.

  **A parenthesized operand was read as a list for every operator.** Only `in` and the range operators (`ov`, `sl`, `sr`, `nxr`, `nxl`, `adj`) take a paren-delimited operand; elsewhere `(` is an ordinary character. `email.eq.(foo)` parsed as `['foo']` and encrypted a JS array rather than the string, matching nothing.

  **A string operand spelling `null`, `true` or `false` is now quoted.** PostgREST reads a bare `null` as SQL NULL, so `.or([{ column: 'name', op: 'eq', value: 'null' }])` emitted `name.eq.null` and compared against NULL instead of the three-character string.

  **`contains(col, …)` where `col` is a union spanning an encrypted and a plaintext column** accepted an array or object operand. The union is now only as permissive as its strictest member: any declared encrypted column in the union pins the operand to `string`. A literal column argument was never affected.

## 0.19.0

### Minor Changes

- cc62407: Add EQL v3 Supabase support, baselined on the `eql-3.0.0-alpha.2` release.

  `@cipherstash/stack/supabase` gains `encryptedSupabaseV3` — the EQL v3
  counterpart of `encryptedSupabase` for schemas authored with
  `@cipherstash/stack/eql/v3`. The public surface and call shape are identical
  to v2 (same filter methods, `withLockContext`, `audit`); only the schema type
  and wire encoding differ.

  **The v3 surface** is the `eql-3.0.0-alpha.2` release artifact: domains use
  SQL-standard type names (`eql_v3.integer_ord`, `eql_v3.timestamp_ord`,
  `eql_v3.boolean`, … mirrored by `types.IntegerOrd`, `types.TimestampOrd`,
  `types.Boolean`, …), SEM internals live in a separate `eql_v3_internal`
  schema (grant it roles, never expose it — only `eql_v3` goes in Supabase's
  Exposed schemas), and envelopes are versioned `v: 3`. Envelope production
  rides on `@cipherstash/protect-ffi` 0.27, which takes an `eqlVersion` so the
  same client emits v2 or v3 payloads per schema.

  **Adapter behaviour:**

  - columns are stored in their native `eql_v3.*` domains (raw jsonb payloads,
    no composite wrap), with JS property → DB column name resolution and `Date`
    reconstruction from `cast_as` on decrypted rows;
  - **INTERIM:** filter operands are full storage envelopes — every `eql_v3.*`
    domain CHECK requires the storage keys, and the SQL operators coerce their
    operand into the domain, so a term-only operand is rejected today. This is
    a tracked workaround (Linear CIP-3402), not the design: a full-envelope
    operand carries a real decryptable ciphertext plus all of the column's
    index terms, and PostgREST filters travel in GET query strings, so operands
    can land in URL logs, proxies, and Supabase request logs (query terms are
    index-terms-only by design). The fix is an EQL-side term-only scalar query
    envelope (the scalar analog of `eql_v3.jsonb_query`);
  - `like`/`ilike` on encrypted columns are emitted as PostgREST `cs`
    (bloom-filter `@>`) — the v3 domains define no LIKE operator. Substring
    search currently also requires `include_original: false` on the match
    index; that requirement is a symptom of the same interim full-envelope
    operand and goes away with CIP-3402;
  - filters on storage-only columns (e.g. `types.Boolean`) and null filter
    values are rejected at the type level and at runtime.

  The v3 builder's default row type is exactly the table's inferred plaintext
  shape (no index-signature widening — widening would disable the storage-only
  filter guard). Filtering or inserting plaintext passthrough columns requires
  an explicit row type: `es.from<typeof users, UserRow>('users', users)`.

  The CLI gains an EQL v3 path: `stash eql install --eql-version 3` installs the
  vendored `eql-3.0.0-alpha.2` bundle (`--supabase` selects the opclass-stripped
  variant and applies the role grants for both `eql_v3` and `eql_v3_internal`);
  `stash db upgrade` also accepts `--eql-version`, and `stash db status` reports
  v2 and v3 installs independently. The v2 `SUPABASE_PERMISSIONS_SQL` block is
  now generated from a shared `supabasePermissionsSql(schemaName)` helper, with
  `SUPABASE_PERMISSIONS_SQL_V3` covering the v3 schemas.

- 5e4f354: Add the EQL v3 `text_search` authoring DSL on a new `@cipherstash/stack/eql/v3`
  subpath (`types.TextSearch`, v3 `encryptedTable` / `buildEncryptConfig`). The v3
  builders emit the existing `EncryptConfig` shape, so encryption, payloads, and
  query paths are unchanged at runtime.

  Also widens the public client types (`EncryptionClientConfig.schemas`,
  `EncryptOptions`, `SearchTerm`/`EncryptQueryOptions`) to a structural contract so
  both v2 and v3 builders are accepted by `Encryption` / `encrypt` / `decrypt` /
  `encryptQuery`. This is a backward-compatible widening — existing v2 usage is
  unaffected. The structural contracts themselves (`BuildableColumn`,
  `BuildableQueryColumn`, `BuildableV3QueryableColumn`, `BuildableTable`,
  `BuildableTableColumns`) and the `encryptModel` return-type mapper
  (`EncryptedFromBuildableTable`) are exported from `@cipherstash/stack/types` so
  consumers can name them.

- 4ceefed: Add a strongly-typed EQL v3 client surface on a new `@cipherstash/stack/v3`
  subpath (`EncryptionV3`, `typedClient`, `TypedEncryptionClient`). It re-exports
  the v3 `types` namespace and table API (from `@cipherstash/stack/eql/v3`), so a
  single import provides everything needed to author and use a v3 schema.

  Every method derives its types from the concrete `table` / `column` builder
  arguments:

  - `encrypt` / `encryptQuery` pin the plaintext to the column's domain type
    (`text → string`, `int8 → bigint`, `timestamptz → Date`, …).
  - `encryptQuery` constrains `queryType` to the column's capabilities and rejects
    storage-only columns at compile time.
  - `encryptModel` / `bulkEncryptModels` validate schema-column fields against their
    inferred plaintext type (passthrough fields are untouched) and return a precise
    encrypted model.
  - `decryptModel` / `bulkDecryptModels` return the precise plaintext model,
    reconstructing `Date` / `bigint` values from the encrypt-config `cast_as`.

  Because the typed methods bind to the concrete branded v3 classes, a hand-rolled
  structural table/column is rejected — closing the soundness gap where a non-branded
  table could be encrypted at runtime while typed as plaintext.

  Runtime behaviour is unchanged: the encrypt/query paths return the same operations
  as the base client; only the model-decrypt paths add a per-column `Date` / `bigint`
  reconstruction step. The v2 client surface (`Encryption`) is untouched.

- cb34d71: Add EQL v3 schema builders for all generated SQL domains under `@cipherstash/stack/eql/v3`, exposed as the `types` namespace (one member per EQL v3 domain, e.g. `types.TextEq` / `types.Int4Ord` / `types.Timestamptz`), including explicit query capability metadata (`getQueryCapabilities()` / `isQueryable()`) and v3 table support in model encryption helpers (`encryptModel` / `bulkEncryptModels`).

  Also widen the accepted plaintext input type for `encrypt` / `encryptQuery` to include `Date` and `bigint` (via the new `Plaintext` type), so v3 `date` / `timestamptz` / `int8` domains can be encrypted and queried with their natural JavaScript values.

- 90d19fb: Rename the encryption client's auth strategy config field from `config.strategy` to **`config.authStrategy`** to make its purpose clear, and expand the `Encryption()` TypeDoc with a full authentication and keysets walkthrough.

  **`config.authStrategy`** is the new, documented field for supplying an auth strategy (`OidcFederationStrategy`, `AccessKeyStrategy`, or any `{ getToken() }` object). **`config.strategy` is retained as a deprecated alias** — passing it still works and forwards to the client, but logs a one-time runtime deprecation warning. When both are set, `authStrategy` wins (and the deprecation warning still fires so the leftover field gets cleaned up).

  ```ts
  import { Encryption, OidcFederationStrategy } from "@cipherstash/stack";

  const client = await Encryption({
    schemas: [users],
    config: {
      authStrategy: OidcFederationStrategy.create(workspaceCrn, () =>
        getUserJwt()
      ),
    },
  });
  ```

  **Migration:** rename `config.strategy` → `config.authStrategy`. No behavioural change beyond the deprecation warning; the field is forwarded to protect-ffi's `strategy` option exactly as before.

  The `Encryption()` TypeDoc now documents the default `auto` strategy (env vars → local dev profile via `npx stash auth login`), the four `CS_*` production/CI variables, custom strategies (`AccessKeyStrategy`, `OidcFederationStrategy`), lock context, and keysets for multi-tenant isolation.

  The `@cipherstash/stack/wasm-inline` entry (Deno / Edge / Workers / Bun) gets the same rename so the Node and WASM interfaces stay in sync: `WasmClientConfig.authStrategy` is the documented field, `strategy` is a deprecated alias that still works and warns at runtime.

- a5f5422: Bump `@cipherstash/auth` (and its per-platform native bindings) from `0.40.0` to `0.41.0`, and migrate to its new `Result`-returning API.

  **What changed in `@cipherstash/auth` `0.41`.** Every fallible auth operation now returns a `@byteslice/result` `Result<T, AuthFailure>` (`{ data }` on success, `{ failure }` on error) instead of throwing. This covers strategy construction (`AccessKeyStrategy.create`, `OidcFederationStrategy.create`, `AutoStrategy.detect`, `DeviceSessionStrategy.fromProfile`), `getToken()`, and the device-code flow (`beginDeviceCodeFlow`, `pollForToken`, `openInBrowser`, `bindClientDevice`). Consumers now write `if (result.failure) …` and read `result.data` rather than `try/catch`. The `AuthError` type was renamed to **`AuthFailure`** — a discriminated union keyed by `type` (`"NOT_AUTHENTICATED"`, `"WORKSPACE_MISMATCH"`, …), replacing the old `error.code` string.

  **`@cipherstash/stack` (breaking type surface).**

  - **`AuthError` is renamed to `AuthFailure`** in the public re-exports from `@cipherstash/stack`. `AuthErrorCode` and `TokenResult` are unchanged. Anyone importing `AuthError` from `@cipherstash/stack` must switch to `AuthFailure`.
  - The WASM-inline access-key path (`resolveStrategy`, used by `@cipherstash/stack/wasm-inline`'s `Encryption()`) now unwraps the `Result` from `AccessKeyStrategy.create`. A construction failure (e.g. an invalid CRN or access key) throws a descriptive `[encryption]` error naming the `AuthFailure.type` instead of surfacing the raw auth error.
  - Bump `@cipherstash/protect-ffi` from `0.27.0` to `0.28.0`. auth `0.41`'s `getToken()` returns the token inside a `Result` envelope; protect-ffi `0.28` unwraps it (`.data.token`) inside its WASM `newClient`, whereas `0.27` read `.token` off the envelope and got `undefined` — which failed the WASM encrypt/decrypt round-trip with `token field is not a string`. `0.28` is the floor for the WASM path under auth `0.41`.

  **`stash` (CLI) and `@cipherstash/wizard`.** Internal auth call sites (`stash auth login`, device binding, `init` auth check, and the wizard's token acquisition / prerequisite check) were updated to unwrap `Result` and branch on `failure.type`. Behaviour is preserved — auth failures still surface the same way to end users; no CLI/wizard API changed.

- 35b9ed6: Bump `@cipherstash/protect-ffi` to `0.26.0` and `@cipherstash/auth` to `0.40.0`, and replace the lock-context token ceremony with a strategy-based approach for identity-bound encryption.

  **protect-ffi `0.26.0`** supersedes `0.25.0`. The public API is unchanged from `0.25` (internal fixes only). As in `0.25`, `serviceToken` is gone from the encrypt / decrypt / query option types; auth flows through the client's strategy / credentials, and lock contexts travel as `lockContext.identityClaim`. The WASM-inline path takes a single options object with the auth strategy nested under `strategy`, and `Encryption()` config uses **`workspaceCrn`** (`CS_WORKSPACE_CRN`) as the single source of truth — `CS_REGION` is no longer consulted. On that path `workspaceCrn` is required only alongside an `accessKey` (it derives the region); with a pre-built `strategy` it is **optional**, since the strategy already carries the CRN.

  **Strategy-based, identity-bound encryption.** `OidcFederationStrategy` federates an end user's third-party OIDC JWT (Clerk, Supabase, Auth0, …) into a CTS service token. As of `@cipherstash/auth` `0.40` it takes a `workspaceCrn` (region derived from the CRN), matching `AccessKeyStrategy`. Pass it as `config.strategy` so every ZeroKMS request authenticates _as that user_, then bind the data key to a claim with `.withLockContext({ identityClaim })`:

  ```ts
  import { Encryption, OidcFederationStrategy } from "@cipherstash/stack";

  const client = await Encryption({
    schemas: [users],
    config: {
      strategy: OidcFederationStrategy.create(workspaceCrn, () => getUserJwt()),
    },
  });

  await client
    .encrypt("alice@example.com", { column: users.email, table: users })
    .withLockContext({ identityClaim: ["sub"] });
  ```

  This replaces the old ceremony (`new LockContext()` → `await lc.identify(jwt)` → `.withLockContext(lc)`), which relied on a per-operation CTS token that protect-ffi removed in `0.25`.

  - **`.withLockContext()`** now accepts a plain `{ identityClaim }` object (as well as a `LockContext`) and no longer requires a CTS token or an `identify()` call — it carries the identity claim only.
  - **`LockContext.identify()` / `getLockContext()`** are **deprecated** (kept for backwards compatibility); the strategy handles token acquisition.
  - **Strategies are re-exported** from `@cipherstash/stack` (`OidcFederationStrategy`, `AccessKeyStrategy`, `AutoStrategy`, `DeviceSessionStrategy`) and from `@cipherstash/stack/wasm-inline` (`OidcFederationStrategy`, `AccessKeyStrategy`) so integrators don't need a separate `@cipherstash/auth` install. `AuthStrategy` remains re-exported for the structural type.

  **Migrating `region` → `workspaceCrn` (WASM-inline).** If you previously passed `region` (or relied on `CS_REGION`) to the WASM-inline `Encryption()` path, replace it with your workspace CRN: set `workspaceCrn` in config (or `CS_WORKSPACE_CRN` in the environment) to the value shown in the CipherStash dashboard (`crn:<region>.aws:<workspace-id>` — it embeds the region, which is now derived from it). `region` is ignored if passed.

  **Lock-context enforcement is now server-side only.** Because the client no longer resolves a per-user CTS token at `withLockContext` time, it also cannot fail fast there: a wrong or missing identity claim surfaces as a ZeroKMS **decryption failure** (the data key simply doesn't unlock), not as a client-side error before the request. The cryptographic guarantee is unchanged — enforcement happens in ZeroKMS — but anyone relying on the old client-side throw for early feedback should assert on the operation's `failure` result instead.

  Existing credential / env behaviour is preserved when `config.strategy` is omitted.

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.

## 0.18.0

### Minor Changes

- 6e7ae4e: Export the operation classes returned by the encryption and DynamoDB clients as public API.

  The classes returned from public methods are now exported and documented in the API reference, so their types can be named and their TSDoc links resolve.

  - From `@cipherstash/stack/encryption`: `EncryptOperation`, `EncryptQueryOperation`, `BatchEncryptQueryOperation`, `DecryptOperation`, `EncryptModelOperation`, `DecryptModelOperation`, `BulkEncryptOperation`, `BulkDecryptOperation`, `BulkEncryptModelsOperation`, `BulkDecryptModelsOperation`. `EncryptQueryOperation` and `BatchEncryptQueryOperation` were previously marked `@internal`; since they are returned from `EncryptionClient.encryptQuery`, they are now public for consistency with the other operations.
  - From `@cipherstash/stack/dynamodb`: `EncryptModelOperation`, `DecryptModelOperation`, `BulkEncryptModelsOperation`, `BulkDecryptModelsOperation`.
  - From `@cipherstash/stack/types`: `EncryptedQuery` and `EncryptedFromSchema`.

  The `*WithLockContext` variants returned by `.withLockContext()` remain internal — they share the same awaitable shape and are not intended to be named directly.

  No runtime behaviour changes; this only widens the exported surface and corrects TSDoc cross-references that previously failed to resolve.

- 712d7fa: Fix: restore runtime null short-circuits in the encryption operation classes.

  A prior refactor (`feat(stack): remove null from Encrypted type`) tightened the type signatures to disallow `null` and, alongside that, deleted the `if (value === null) return null` guards from every operation in `packages/stack/src/encryption/operations/`. The type guard does not survive runtime: callers reaching the operation through a cast (e.g. `null as any`), dynamic model walking, or JS interop would then have their null silently encrypted by protect-ffi into a real SteVec ciphertext (`{ k: 'sv', v: 2, ... }`) — which is observable, surprising, and breaks symmetry with the model-helpers layer that does still treat null as "absent" at the field level.

  Restored, mirroring the pattern in `@cipherstash/protect`:

  - `encrypt` / `encryptWithLockContext`: `if (plaintext === null) return null`.
  - `bulkEncrypt` / `bulkEncryptWithLockContext`: per-element null filter; nulls are preserved in position in the output.
  - `decrypt` / `decryptWithLockContext`: `if (encryptedData === null) return null`.
  - `bulkDecrypt` / `bulkDecryptWithLockContext`: per-element null filter, position-preserving merge.
  - `encryptQuery` / `encryptQueryWithLockContext`: `if (plaintext === null || plaintext === undefined) return { data: null }`.
  - `batchEncryptQuery` / `batchEncryptQueryWithLockContext`: per-element null/undefined filter; null slots in the input array stay null in the result array.

  Type adjustments to support the runtime behavior honestly:

  - `BulkEncryptPayload['plaintext']`, `BulkEncryptedData['data']`, `BulkDecryptPayload['data']`, and the `T` of `BulkDecryptedData` all widen to `... | null`. Bulk APIs now accept and return mixed nullable arrays without filtering ahead of time.
  - `EncryptedQueryResult` widens to include `null` so the batch query path can return position-stable arrays with null slots.
  - `Encryption.encrypt()` and `Encryption.decrypt()` public signatures are unchanged — still narrow (`JsPlaintext` / `Encrypted` input, `Encrypted` / `JsPlaintext` non-nullable output). The runtime null short-circuit in `EncryptOperation` / `DecryptOperation` is defense in depth for callers reaching the operation classes through casts, dynamic field walking, or JS interop. The narrow-return contract holds for any caller that respects the input contract.

## 0.17.0

### Minor Changes

- f743fcc: Upgrade `@cipherstash/protect-ffi` to `0.23.0` and the bundled CipherStash EQL extension to `eql-2.3.1`.

  Breaking upstream changes adopted in this release:

  - **Encrypt-config schema version**: `buildEncryptConfig` now emits `{ v: 1, ... }` (was `{ v: 2, ... }`). protect-ffi `0.22.0` started validating this field and rejects any value other than `1` with the new `UNSUPPORTED_CONFIG_VERSION` error code.
  - **Storage and query payloads are now distinct types** (protect-ffi `0.23.0`): the previously-conflated `Encrypted` type splits into `Encrypted` (storage-only, `c` required) and a new `EncryptedQuery` (search terms — scalar `unique`/`match`/`ore` lookups and `ste_vec_selector` JSON path queries; no `c`). JSON containment queries (`ste_vec_term`) still return a storage-shaped `Encrypted` payload. `encryptQuery` / `encryptQueryBulk` now return `Encrypted | EncryptedQuery`, and the stack's `EncryptedSearchTerm` / `EncryptedQueryResult` unions widen to match. `decrypt` rejects query payloads at the type level. The DynamoDB `SearchTermsOperation` narrows via `'hm' in term` rather than `term.hm`.
  - **SteVec encoding default flipped**: protect-ffi's default `mode` for `ste_vec` indexes changed from `compat` to `standard`. The two encodings are not cross-compatible. Existing JSON-searchable data that was indexed under `compat` will need to be re-encrypted to be queryable. The stack adopts the new `standard` default — there is no longer a way to pin `compat` from the SDK.
  - **EQL extension bumped to `eql-2.3.1`**: the new SteVec `standard` encoding requires matching support in the database EQL extension. The CLI's bundled SQL (`packages/cli/src/sql/*.sql`) and the `@cipherstash/prisma-next` install bundle (`migrations/20260601T0000_install_eql_bundle/ops.json` + `eql-install.generated.ts`) are updated to `eql-2.3.1`. Databases installed with an older EQL extension must be reinstalled (`stash db install`) before containment / contained-by queries against SteVec columns will work. `eql-2.3.1` ships the `_encrypted_check_c` fix for SteVec storage payloads ([cipherstash/encrypt-query-language#232](https://github.com/cipherstash/encrypt-query-language/issues/232)).
  - **New error codes**: `ProtectErrorCode` (re-exported from `@cipherstash/protect-ffi`) gains `MATCH_REQUIRES_TEXT` and `UNSUPPORTED_CONFIG_VERSION`. Exhaustive switches over `ProtectErrorCode` will need additional cases.
  - **`match` index validation**: protect-ffi now rejects `match` indexes on columns whose `cast_as` is not text-family (`'text'` / `'string'`) with `MATCH_REQUIRES_TEXT`. The stack's `freeTextSearch()` builder is unaffected because it only targets string-typed columns.
  - **`Encrypted` ciphertext shape**: protect-ffi's `Encrypted` type is now a discriminated union keyed on `k` (`'ct'` for scalars, `'sv'` for SteVec). SteVec storage payloads now place the root document ciphertext at `sv[0].c`. The stack's `isEncryptedPayload` runtime check continues to work because storage payloads still carry `c` (scalar) or `sv` (SteVec). The DynamoDB helpers (`toEncryptedDynamoItem`, `SearchTermsOperation`) now narrow on `k` before reading variant-only fields.
  - **Config-validation error message wording**: error messages for config-validation failures now come from upstream `ConfigError`. `ProtectError.code` values are preserved; consumers that string-match on `err.message` for config-validation errors must update.

## 0.16.0

### Minor Changes

- 1c2fdbf: Fix CJS consumers crashing with `Must use import to load ES Module: .../uuid/dist-node/index.js`. The `uuid` package is pure ESM and has no CJS entry point, so the CJS build of `@cipherstash/stack` could not `require()` it at runtime. `uuid` is now bundled into the CJS output (the ESM build is unchanged).

  Expose `EncryptedTable.columnBuilders` as a public, read-only field so consumers can iterate the typed column-builder map of an encrypted table without reaching into the built `TableDefinition` (`schema.build().columns`) or the private internal.

## 0.15.3

### Patch Changes

- afe6810: Bump protect-ffi version

## 0.15.2

### Patch Changes

- 510c485: Bundle `evlog` into the CJS output. `evlog` is pure ESM (no `require` condition in its `exports` map), so CJS consumers of `@cipherstash/stack` (e.g. webpack bundles) were failing with `ERR_PACKAGE_PATH_NOT_EXPORTED` when the stack's `index.cjs` tried to `require("evlog")`. `evlog` is now inlined at build time and no longer resolved at runtime.

## 0.15.1

### Patch Changes

- 8513705: Fix mangled `eql_v2_encrypted` type in drizzle-kit migrations.

  - `@cipherstash/stack/drizzle`'s `encryptedType` now returns the bare `eql_v2_encrypted` identifier from its Drizzle `customType.dataType()` callback. Returning the schema-qualified `"public"."eql_v2_encrypted"` (0.15.0) triggered a drizzle-kit quirk that wraps the return value in double-quotes and prepends `"{typeSchema}".` in ALTER COLUMN output — producing `"undefined".""public"."eql_v2_encrypted""`, which Postgres cannot parse.
  - `stash db install` / `stash wizard`'s migration rewriter now matches all four forms drizzle-kit may emit (`eql_v2_encrypted`, `"public"."eql_v2_encrypted"`, `"undefined"."eql_v2_encrypted"`, `"undefined".""public"."eql_v2_encrypted""`) and rewrites each into the safe `ADD COLUMN … DROP COLUMN … RENAME COLUMN` sequence.

  Users on 0.15.0 who hit this in generated migrations should upgrade and re-run `npx drizzle-kit generate` + `stash db install` (or re-run the wizard).

## 0.15.0

### Minor Changes

- 1929c8f: Mark secrets as a coming soon feature and remove existing SDK integration.

## 0.14.0

### Minor Changes

- 1e0d4c1: Support CipherStash rebrand with new docs links.

## 0.13.0

### Minor Changes

- 068f820: Release the consolidated CipherStash CLI npm package.

## 0.12.0

### Minor Changes

- 15764a8: Implement stack auth into stash cli flow.

## 0.11.0

### Minor Changes

- b0e56b8: Upgrade protect-ffi to 0.21.0 and enable array_index_mode for searchable JSON

  - Upgrade `@cipherstash/protect-ffi` to 0.21.0 across all packages
  - Enable `array_index_mode: 'all'` on STE vec indexes so JSON array operations
    (jsonb_array_elements, jsonb_array_length, array containment) work correctly
  - Delegate credential resolution entirely to protect-ffi's `withEnvCredentials`
  - Download latest EQL at build/runtime instead of bundling hardcoded SQL files

## 0.10.0

### Minor Changes

- 5245cd7: Improved CLI setup and initialization commands.

## 0.9.0

### Minor Changes

- 2b907a1: Improve CLI user experience for developer onboarding.

## 0.8.0

### Minor Changes

- 3414761: Fixed Supabase or wrapper to escape EQL payloads correctly.

## 0.7.0

### Minor Changes

- 1be8f81: Exposed a public method on the Encryption client to expose the build Encryption schema.

## 0.6.0

### Minor Changes

- 0b9fd7a: Add notes to CLI about init in prototype phase.

## 0.5.0

### Minor Changes

- a645115: ### Documentation

  - **TypeDoc**: Improved JSDoc for `Encryption()`, `EncryptOptions`, schema builders (`encryptedTable`, `encryptedColumn`, `encryptedField`, `EncryptedField`, `EncryptedTableColumn`), and `encrypt` / `bulkEncrypt` with clearer `@param`, `@returns`, `@throws`, `@example`, and `@see` links.
  - **README**: Refreshed main repo README and Stack package readme; basic example README now uses `npm install @cipherstash/stack`, CipherStash account and dashboard credentials, and drops Stash CLI references. Added docs badge linking to cipherstash.com/docs.

  ### Features

  - **Logging**: Logger is now used consistently across Stack client interfaces for initialization and operations.

## 0.4.0

### Minor Changes

- 5c3f4e7: Remove null support from encrypt and bulk encrypt operations to improve typescript support and reduce operation complexity.

## 0.3.0

### Minor Changes

- afe0a55: Improved encrypt model return types to account for Encrypted values.

## 0.2.0

### Minor Changes

- 68c8199: Improved typing for model interfaces and full bun support.

## 0.1.0

### Minor Changes

- 7ed89a5: Initial release of the CipherStash Stack.
