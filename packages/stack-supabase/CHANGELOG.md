# @cipherstash/stack-supabase

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
