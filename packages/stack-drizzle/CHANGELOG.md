# @cipherstash/stack-drizzle

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
