# @cipherstash/stack-supabase

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
