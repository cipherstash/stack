# @cipherstash/protect-dynamodb

## 12.0.2-rc.0

### Patch Changes

- @cipherstash/protect@12.0.2-rc.0

## 12.0.1

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.
- Updated dependencies [aa9c4b1]
  - @cipherstash/protect@12.0.1

## 12.0.0

### Patch Changes

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

- Updated dependencies [f743fcc]
  - @cipherstash/protect@12.0.0

## 11.0.2

### Patch Changes

- Updated dependencies [a8dbb65]
  - @cipherstash/protect@11.1.2

## 11.0.1

### Patch Changes

- Updated dependencies [afe6810]
  - @cipherstash/protect@11.1.1

## 11.0.0

### Patch Changes

- Updated dependencies [068f820]
  - @cipherstash/protect@11.1.0

## 10.0.0

### Patch Changes

- Updated dependencies [b0e56b8]
  - @cipherstash/protect@10.6.0

## 9.0.0

### Patch Changes

- Updated dependencies [db72e2c]
- Updated dependencies [e769740]
  - @cipherstash/protect@10.5.0

## 8.0.0

### Patch Changes

- Updated dependencies [9ccaf68]
  - @cipherstash/protect@10.4.0

## 7.0.0

### Patch Changes

- Updated dependencies [a1fce2b]
- Updated dependencies [622b684]
  - @cipherstash/protect@10.3.0

## 6.0.1

### Patch Changes

- @cipherstash/protect@10.2.1

## 6.0.0

### Patch Changes

- Updated dependencies [de029de]
  - @cipherstash/protect@10.2.0

## 5.1.1

### Patch Changes

- Updated dependencies [ff4421f]
  - @cipherstash/protect@10.1.1

## 5.1.0

### Patch Changes

- Updated dependencies [6b87c17]
  - @cipherstash/protect@10.1.0

## 5.0.2

### Patch Changes

- @cipherstash/protect@10.0.2

## 5.0.1

### Patch Changes

- @cipherstash/protect@10.0.1

## 5.0.0

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

### Patch Changes

- Updated dependencies [788dbfc]
  - @cipherstash/protect@10.0.0

## 4.0.0

### Patch Changes

- Updated dependencies [c7ed7ab]
- Updated dependencies [211e979]
  - @cipherstash/protect@9.6.0

## 3.0.0

### Minor Changes

- 6f45b02: Fully implemented audit metadata functionality.

### Patch Changes

- Updated dependencies [6f45b02]
  - @cipherstash/protect@9.5.0

## 2.0.1

### Patch Changes

- @cipherstash/protect@9.4.1

## 2.0.0

### Patch Changes

- Updated dependencies [1cc4772]
  - @cipherstash/protect@9.4.0

## 1.0.0

### Minor Changes

- 01fed9e: Added audit support for all protect and protect-dynamodb interfaces.

### Patch Changes

- Updated dependencies [01fed9e]
  - @cipherstash/protect@9.3.0

## 0.3.0

### Minor Changes

- 2b63ee1: Support nested protect schema in dynamodb helper functions.
- e33fbaf: Fixed bug when handling schema definitions without an equality flag.

## 0.2.0

### Minor Changes

- 5fc0150: Fix build and publish.

## 1.0.0

### Minor Changes

- c8468ee: Released initial version of the DynamoDB helper interface.

### Patch Changes

- Updated dependencies [c8468ee]
  - @cipherstash/protect@9.1.0
