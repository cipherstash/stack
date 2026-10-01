# @cipherstash/stack-drizzle

## 1.1.1

### Patch Changes

- @cipherstash/stack@1.1.1

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

### Patch Changes

- Updated dependencies [a2b0b45]
- Updated dependencies [a2b0b45]
- Updated dependencies [a2b0b45]
- Updated dependencies [a2b0b45]
  - @cipherstash/stack@1.1.0

## 1.0.0

### Major Changes

- 3d34862: Remove the EQL v2 authoring surface from `@cipherstash/stack-drizzle` and collapse the EQL v3 `./v3` subpath into the package root.

  **Breaking (`@cipherstash/stack-drizzle`):**

  - The EQL v2 root exports are gone: `encryptedType`, the v2 `extractEncryptionSchema`, the v2 `createEncryptionOperators` (including the `like` / `ilike` operators), and `EncryptionConfigError`. Authoring or querying `eql_v2_encrypted` columns through Drizzle is no longer supported.
  - The `./v3` subpath is **removed** from the package `exports` map and `typesVersions`. The EQL v3 implementation is now the package root, and the `*V3` names are de-suffixed (`createEncryptionOperatorsV3` → `createEncryptionOperators`, `extractEncryptionSchemaV3` → `extractEncryptionSchema`). This is a **hard break with no alias**: post-collapse the root names would collide with the removed v2 names, and keeping an alias would silently type-check v2 call sites against v3 semantics.

  **Migration** — import `types`, `extractEncryptionSchema`, and
  `createEncryptionOperators` from the `@cipherstash/stack-drizzle` package root.

  The `types.*` column factories, `makeEqlV3Column` / `getEqlV3Column` / `isEqlV3Column`, the codec helpers (`v3ToDriver` / `v3FromDriver` / `EqlV3CodecError`), and `EncryptionOperatorError` are unchanged apart from moving to the root.

  Existing EQL v2 ciphertext remains decryptable via `@cipherstash/stack` — only the Drizzle-side v2 authoring and query-building is removed.

- 7c7dbca: CipherStash Stack 1.0.

  This is the first 1.0-line release of `@cipherstash/stack`, the first published
  release of the split-out EQL v3 adapters `@cipherstash/stack-drizzle` and
  `@cipherstash/stack-supabase`, and moves the `stash` CLI to 1.0 alongside them.
  These four packages now version together as the Stack 1.0 family.

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

- 239f79b: New `encryptedIndexes` helper on the package root: spread
  `...encryptedIndexes(t)` in `pgTable`'s third-argument callback and it derives
  the recommended functional indexes for every encrypted column in the table —
  named `<table>_<column>_<capability>`, tracked by `drizzle-kit generate` like
  any other index. The mapping comes from the same per-domain capability record
  the operator layer gates on, so the emitted indexes and the operators that
  engage them cannot drift: equality → btree on `eql_v3.eq_term`, ordering →
  btree on `eql_v3.ord_term` (on the numeric/date/timestamp `_ord` domains one
  index serves `=` and range — their injective ordering term answers equality
  and no `eq_term` overload exists; the non-injective `text_ord` / `text_ord_ore`
  also carry `hm` and get an `eq_term` index alongside), ORE ordering →
  `eql_v3.ord_term_ore`, free-text →
  GIN on `eql_v3.match_term`, encrypted JSON → GIN on
  `(eql_v3.to_ste_vec_query(col)::jsonb) jsonb_path_ops`. Storage-only and
  non-encrypted columns emit nothing. Closes the #753 gap where integrations
  emitted query operators but no index DDL, so encrypted predicates
  sequential-scanned by default.

  Also fixed: `isEqlV3Column` / `getEqlV3Column` no longer blow the stack when
  handed a column from `pgTable`'s extras callback — drizzle-orm ≤0.45's
  `ExtraConfigColumn.getSQLType()` recurses into itself, so the domain is now
  recovered from the column's custom-type params instead of calling it.

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

- 0ebf57e: Close two fail-open paths in the Drizzle adapter.

  `ops.matches()` now throws `EncryptionOperatorError` for a search term that
  tokenizes to nothing: the empty string, or a term shorter than the match index
  tokenizer's `token_length` (3 by default). Such a term produces an empty bloom
  filter, and `stored_bf @> '{}'` is true for every row — so a user searching
  `"ad"` silently received the entire table. Measured live, the terms `"ad"`,
  `"a"` and `"x"` each returned every seeded row, including one in which `"x"`
  did not appear.

  The floor counts Unicode codepoints, matching the tokenizer. A UTF-16 length
  check would wave through an astral-plane term — `"👍👍"` is 4 code units but
  only 2 codepoints, yields no trigram, and matched every row.

  **Breaking for callers passing short terms:** free-text calls that previously
  returned every row now throw. Terms at or above the configured `token_length`
  are unaffected.

  `v3FromDriver()` now throws the new `EqlV3CodecError` on a payload that is not
  an EQL envelope, instead of surfacing a raw `SyntaxError` for malformed JSON and
  passing a bare scalar through unchecked — `v3FromDriver('5')` previously returned
  `5` typed as `Encrypted`, which then reached `decrypt` as garbage. The guard
  accepts both scalar envelopes (ciphertext at `c`) and SteVec documents
  (ciphertext at `sv[0].c`). A SteVec's `sv` must be a non-empty array: `sv[0]` is
  the decryption root, so `sv: []` carries a ciphertext key but no ciphertext, and
  is now rejected rather than passed to `decrypt`. `EqlV3CodecError` is exported
  from the `@cipherstash/stack-drizzle` package root so callers can catch it.

  Also removes an unreachable branch in `inArray`/`notInArray`, whose empty-list
  guard already throws before it.

- d73a03c: EQL v3 Drizzle support on the `@cipherstash/stack-drizzle` package root. A
  Drizzle-native `types` namespace (same PascalCase names as
  `@cipherstash/stack/eql/v3`) declares encrypted columns whose Postgres type is
  the semantic `public.eql_v3_<domain>`; the concrete type drives the legal query
  operators. `createEncryptionOperators` provides capability-checked
  `eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`matches`/`contains`/`inArray`/
  `asc`/`desc`/`and`/`or` that emit the two-argument `eql_v3` SQL functions with
  full-envelope operands, and `extractEncryptionSchema` rebuilds the schema for
  `Encryption`.

  The encrypted free-text helper is `matches`; obsolete `like`/`ilike` helpers are
  not exposed, because encrypted free-text search is bloom-filter token matching
  rather than SQL wildcard matching. `contains` is genuine encrypted-JSON
  containment (`@>` against a `types.Json` column), not free-text.

- 59b994e: Add EQL v3 JSON **selector-with-constraint** querying to the Drizzle integration
  (#623). `ops.selector(col, '$.path')` returns comparison methods bound to a
  JSONPath into a `types.Json` column — `eq`/`ne`/`gt`/`gte`/`lt`/`lte` — emitting
  `col->'<selector>' <op> <value>` over the encrypted document. Its unique power
  over `contains` is **ordering at a path** (`col->'$.age' > 21`), which
  containment cannot express.

  Complements the existing `contains` (JSONB `@>`) containment operator. Core
  `@cipherstash/stack` needs no change — the selector hash and comparison entry are
  produced by `encryptQuery`/`encrypt` on the existing `types.Json` surface. v1
  supports dot-notation object paths; array-index/wildcard paths are rejected with
  a clear error. The Supabase adapter is tracked separately.

  The right-hand comparison operand is currently a storage-encrypted needle (its
  ste_vec entry carries the ordering term), pending a ciphertext-free ordering
  query needle from protect-ffi (cipherstash/protectjs-ffi#137); until then the
  value's ciphertext appears in the WHERE clause.

  The bundled `stash-encryption` and `stash-drizzle` skills document the new
  `ops.selector(...)` surface (they previously said JSONPath selector queries were
  not yet implemented).

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

- 62df494: Type `extractEncryptionSchema` precisely: a Drizzle-extracted schema now preserves each column's concrete EQL v3 domain instead of widening to `AnyV3Table` (#589).

  `extractEncryptionSchema` is generic over the Drizzle table (`<T extends PgTable>(table: T)`) and returns `EncryptedTable<Cols> & Cols`, the same shape a hand-written `encryptedTable({...})` returns, when concrete column brands are available. Each column's builder is carried through `pgTable()` on a phantom brand and recovered by a mapped type, which also filters out the table's non-encrypted columns. Tables widened to `PgTable`, and tables containing ordinary `customType` columns recovered from their EQL SQL domain, retain the safe `AnyV3Table` fallback instead of incorrectly becoming an empty or partial schema type.

  What this fixes, along the documented flow `extractEncryptionSchema(table)` → `Encryption({ schemas })` → `bulkEncryptModels`:

  - `InferPlaintext<typeof schema>` is a precise per-column plaintext map (`{ email: string; age: number }`) rather than an index signature.
  - `encryptModel` / `bulkEncryptModels` check each schema field against its own domain's plaintext — a `string` written to an `IntegerOrd` column is now a compile error instead of an encrypt-time failure — and pass plain helper columns (`id`, a plain `text()`) through with their own types rather than typing them as encrypted.
  - `schema.email` addresses the column at its concrete type, so `encrypt` / `encryptQuery` pin the value to that column's plaintext.

  **Runtime behaviour is unchanged** — the runtime already recovered each column's builder correctly, so this is a type-level fix only. It is `minor` rather than `patch` because code that previously compiled against the widened types can now fail to compile: a model field typed against the wrong domain, or a schema-derived type that relied on the old index signature. Rows whose shape is only known at runtime (a dynamically built table) should name their model type explicitly — `client.bulkEncryptModels<typeof schema, MyRow>(rows, schema)` — rather than being cast back to `AnyV3Table`.

  `skills/stash-drizzle` documents the preserved typing and warns against casting an extracted schema to `AnyV3Table` to make an insert compile. A matching update to the separately maintained CipherStash documentation site is required so its Drizzle schema-extraction guidance explains the precise branded typing and the widened fallback for incomplete runtime-recovered column maps.

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

- b8cb599: Fix invalid DDL from `drizzle-kit generate`/`push` for EQL v3 encrypted columns.
  A v3 column declared its SQL type as the schema-qualified domain
  (`public.eql_v3_text_search`), but drizzle-kit wraps a custom type's whole name
  in a single pair of double quotes — emitting `"public.eql_v3_text_search"`, which
  Postgres reads as one dotted identifier and rejects with `type
"public.eql_v3_text_search" does not exist`. Generated migrations had to be
  hand-repaired.

  The v3 column now emits the **unqualified** domain (`eql_v3_text_search`), which
  drizzle-kit renders as the valid `"eql_v3_text_search"` and which resolves via the
  search path (the domains live in `public`). This also matches how drizzle-kit
  reads the type back during a `push` introspection diff, so the two sides no
  longer disagree.
  Builder recovery still yields the canonical `public.eql_v3_*` identity, so
  operators and schema extraction are unchanged.

  The bundled `stash-drizzle` skill is updated to describe the unqualified generated
  type and the search-path requirement (hence the `stash` bump — the skill ships in
  its tarball).

- 413ca39: The legacy `@cipherstash/drizzle` package (the `@cipherstash/protect`-based
  Drizzle integration) is removed from the repository and the release train —
  `@cipherstash/protect` is sunsetting at Stack 1.0, and the package's successor
  is `@cipherstash/stack-drizzle`. Already-published versions remain installable
  from npm (deprecated, pointing here); the git history preserves the source for
  any emergency maintenance. The `stash-drizzle` skill and the
  `@cipherstash/stack-drizzle` README now state the deprecation explicitly so
  nobody (human or agent) installs the legacy package by mistake.
- ba706cb: README overhaul: lead with what the package does and why — application-side
  encryption with per-value keys, queryable ciphertext (equality, range,
  ORDER BY, fuzzy text, encrypted JSON), drizzle-kit-native types and index
  derivation — plus a How-it-works section on EQL payloads and searchable
  terms. No code changes.
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

### Patch Changes

- Updated dependencies [cf2c57c]
- Updated dependencies [508f1d5]
  - @cipherstash/stack@1.0.0-rc.4

## 1.0.0-rc.3

### Patch Changes

- b8cb599: Fix invalid DDL from `drizzle-kit generate`/`push` for EQL v3 encrypted columns.
  A v3 column declared its SQL type as the schema-qualified domain
  (`public.eql_v3_text_search`), but drizzle-kit wraps a custom type's whole name
  in a single pair of double quotes — emitting `"public.eql_v3_text_search"`, which
  Postgres reads as one dotted identifier and rejects with `type
"public.eql_v3_text_search" does not exist`. Generated migrations had to be
  hand-repaired.

  The v3 column now emits the **unqualified** domain (`eql_v3_text_search`), which
  drizzle-kit renders as the valid `"eql_v3_text_search"` and which resolves via the
  search path (the domains live in `public`). This matches how the v2
  `encryptedType` surface already declares its type, and how drizzle-kit reads the
  type back during a `push` introspection diff, so the two sides no longer disagree.
  Builder recovery still yields the canonical `public.eql_v3_*` identity, so
  operators and schema extraction are unchanged.

  The bundled `stash-drizzle` skill is updated to describe the unqualified generated
  type and the search-path requirement (hence the `stash` bump — the skill ships in
  its tarball).

- Updated dependencies [8b2551a]
  - @cipherstash/stack@1.0.0-rc.3

## 1.0.0-rc.2

### Patch Changes

- 413ca39: The legacy `@cipherstash/drizzle` package (the `@cipherstash/protect`-based
  Drizzle integration) is removed from the repository and the release train —
  `@cipherstash/protect` is sunsetting at Stack 1.0, and the package's successor
  is `@cipherstash/stack-drizzle`. Already-published versions remain installable
  from npm (deprecated, pointing here); the git history preserves the source for
  any emergency maintenance. The `stash-drizzle` skill and the
  `@cipherstash/stack-drizzle` README now state the deprecation explicitly so
  nobody (human or agent) installs the legacy package by mistake.
- Updated dependencies [b085f66]
  - @cipherstash/stack@1.0.0-rc.2

## 1.0.0-rc.1

### Minor Changes

- 59b994e: Add EQL v3 JSON **selector-with-constraint** querying to the Drizzle integration
  (#623). `ops.selector(col, '$.path')` returns comparison methods bound to a
  JSONPath into a `types.Json` column — `eq`/`ne`/`gt`/`gte`/`lt`/`lte` — emitting
  `col->'<selector>' <op> <value>` over the encrypted document. Its unique power
  over `contains` is **ordering at a path** (`col->'$.age' > 21`), which
  containment cannot express.

  Complements the existing `contains` (JSONB `@>`) containment operator. Core
  `@cipherstash/stack` needs no change — the selector hash and comparison entry are
  produced by `encryptQuery`/`encrypt` on the existing `types.Json` surface. v1
  supports dot-notation object paths; array-index/wildcard paths are rejected with
  a clear error. The Supabase adapter is tracked separately.

  The right-hand comparison operand is currently a storage-encrypted needle (its
  ste_vec entry carries the ordering term), pending a ciphertext-free ordering
  query needle from protect-ffi (cipherstash/protectjs-ffi#137); until then the
  value's ciphertext appears in the WHERE clause.

  The bundled `stash-encryption` and `stash-drizzle` skills document the new
  `ops.selector(...)` surface (they previously said JSONPath selector queries were
  not yet implemented).

### Patch Changes

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
