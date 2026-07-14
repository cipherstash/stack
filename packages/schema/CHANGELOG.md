# @cipherstash/schema

## 3.0.2-rc.0

### Patch Changes

- 229ce59: `searchableJson()` now pins the SteVec encoding mode to `standard` explicitly.
  protect-ffi 0.29 flipped the library default to `compat` (the EQL v3
  encoding); pinning keeps the v2 wire format byte-stable so existing encrypted
  JSON columns stay queryable and comparable.

## 3.0.1

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.

## 3.0.0

### Major Changes

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

## 2.2.0

### Minor Changes

- b0e56b8: Upgrade protect-ffi to 0.21.0 and enable array_index_mode for searchable JSON

  - Upgrade `@cipherstash/protect-ffi` to 0.21.0 across all packages
  - Enable `array_index_mode: 'all'` on STE vec indexes so JSON array operations
    (jsonb_array_elements, jsonb_array_length, array containment) work correctly
  - Delegate credential resolution entirely to protect-ffi's `withEnvCredentials`
  - Download latest EQL at build/runtime instead of bundling hardcoded SQL files

## 2.1.0

### Minor Changes

- e769740: Add encrypted JSONB query support with `searchableJson()` (recommended).

  - New `searchableJson()` schema method enables encrypted JSONB path and containment queries
  - Automatic query operation inference: string values become JSONPath selector queries, objects/arrays become containment queries
  - Also supports explicit `queryType: 'steVecSelector'` and `queryType: 'steVecTerm'` for advanced use cases
  - JSONB path utilities (`toJsonPath`, `buildNestedObject`, `parseJsonbPath`) for building encrypted JSON column queries

## 2.0.2

### Patch Changes

- 532ac3a: Corrected types documentation in README to match Typedoc.
  `int` -> `number`
  `text` -> `string`

## 2.0.1

### Patch Changes

- ff4421f: Expanded typedoc documentation

## 2.0.0

### Major Changes

- 9005484: Include EQL 2.1.8 in package distribution

## 1.1.0

### Minor Changes

- d8ed4d4: Exported all types for packages looking for deeper integrations with Protect.js.

## 1.0.0

### Major Changes

- 788dbfc: Added JSON and INT data type support and update FFI to v0.17.1 with x86_64 musl environment platform support.

  - Update @cipherstash/protect-ffi from 0.16.0 to 0.17.1 with support for x86_64 musl platforms.
  - Add searchableJson() method to schema for JSON field indexing (the search operations still don't work but this interface exists)
  - Refactor type system: EncryptedPayload → Encrypted, add JsPlaintext
  - Add comprehensive test suites for JSON, integer, and basic encryption
  - Update encryption format to use 'k' property for searchable JSON
  - Remove deprecated search terms tests for JSON fields
  - Simplify schema data types to text, int, json only
  - Update model helpers to handle new encryption format
  - Fix type safety issues in bulk operations and model encryption

## 0.1.0

### Minor Changes

- d0b02ea: Released initial package for CipherStash Encrypt schemas.
