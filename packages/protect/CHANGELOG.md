# @cipherstash/protect

## 12.0.1

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.
- Updated dependencies [aa9c4b1]
  - @cipherstash/schema@3.0.1

## 12.0.0

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

### Patch Changes

- Updated dependencies [f743fcc]
  - @cipherstash/schema@3.0.0

## 11.1.2

### Patch Changes

- a8dbb65: Render every user-facing CLI string and execute every shell-out under the detected package manager (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`), completing the work started in #379. Affected surfaces: `@cipherstash/cli` top-level + `auth` + `env` help, `db install` Drizzle migration steps, `db migrate` not-implemented warning, the Supabase migration SQL header, the Supabase status fallback exec, the `@cipherstash/protect` `stash` Stricli help (set/get/list/delete), the `@cipherstash/wizard` usage line and agent command allowlist, and the `@cipherstash/drizzle` `generate-eql-migration` help + drizzle-kit invocation. A new `pnpm run lint:runners` lint runs in CI and fails on any reintroduction of a hardcoded runner literal.

## 11.1.1

### Patch Changes

- afe6810: Bump protect-ffi version

## 11.1.0

### Minor Changes

- 068f820: Release the consolidated CipherStash CLI npm package.

## 11.0.0

### Major Changes

- b0e56b8: Upgrade protect-ffi to 0.21.0 and enable array_index_mode for searchable JSON

  - Upgrade `@cipherstash/protect-ffi` to 0.21.0 across all packages
  - Enable `array_index_mode: 'all'` on STE vec indexes so JSON array operations
    (jsonb_array_elements, jsonb_array_length, array containment) work correctly
  - Delegate credential resolution entirely to protect-ffi's `withEnvCredentials`
  - Download latest EQL at build/runtime instead of bundling hardcoded SQL files

### Patch Changes

- Updated dependencies [b0e56b8]
  - @cipherstash/schema@2.2.0

## 10.5.0

### Minor Changes

- db72e2c: Add `encryptQuery` API for encrypting query terms with explicit query type selection.

  - New `encryptQuery()` method replaces `createSearchTerms()` with improved query type handling
  - Supports `equality`, `freeTextSearch`, and `orderAndRange` query types
  - Deprecates `createSearchTerms()` - use `encryptQuery()` instead
  - Updates drizzle operators to use correct index selection via `queryType` parameter

- e769740: Add encrypted JSONB query support with `searchableJson()` (recommended).

  - New `searchableJson()` schema method enables encrypted JSONB path and containment queries
  - Automatic query operation inference: string values become JSONPath selector queries, objects/arrays become containment queries
  - Also supports explicit `queryType: 'steVecSelector'` and `queryType: 'steVecTerm'` for advanced use cases
  - JSONB path utilities (`toJsonPath`, `buildNestedObject`, `parseJsonbPath`) for building encrypted JSON column queries

### Patch Changes

- Updated dependencies [e769740]
  - @cipherstash/schema@2.1.0

## 10.4.0

### Minor Changes

- 9ccaf68: Allow stash cli tool to read env files from .env.\*.

## 10.3.0

### Minor Changes

- a1fce2b: Add Stash interface and CLI tool.

### Patch Changes

- 622b684: Update @cipherstash/protect-ffi to 0.19.0

## 10.2.1

### Patch Changes

- Updated dependencies [532ac3a]
  - @cipherstash/schema@2.0.2

## 10.2.0

### Minor Changes

- de029de: Add client safe exports.

## 10.1.1

### Patch Changes

- ff4421f: Expanded typedoc documentation
- Updated dependencies [ff4421f]
  - @cipherstash/schema@2.0.1

## 10.1.0

### Minor Changes

- 6b87c17: Added support for multi-tenant encryption with configurable keysets.

## 10.0.2

### Patch Changes

- Updated dependencies [9005484]
  - @cipherstash/schema@2.0.0

## 10.0.1

### Patch Changes

- Updated dependencies [d8ed4d4]
  - @cipherstash/schema@1.1.0

## 10.0.0

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
  - @cipherstash/schema@1.0.0

## 9.6.0

### Minor Changes

- c7ed7ab: Support TypeORM example with ES2022.
- 211e979: Added support for ES2022 and later.

## 9.5.0

### Minor Changes

- 6f45b02: Fully implemented audit metadata functionality.

## 9.4.1

### Patch Changes

- Updated dependencies [d0b02ea]
  - @cipherstash/schema@0.1.0

## 9.4.0

### Minor Changes

- 1cc4772: Released support for bulk encryption and decryption.

## 9.3.0

### Minor Changes

- 01fed9e: Added audit support for all protect and protect-dynamodb interfaces.

## 9.2.0

### Minor Changes

- 587f222: Added support for deeply nested protect schemas to support more complex model objects.

## 9.1.0

### Minor Changes

- c8468ee: Released initial version of the DynamoDB helper interface.

## 9.0.0

### Major Changes

- 1bc55a0: Implemented a more configurable pattern for the Protect client.

  This release introduces a new `ProtectClientConfig` type that can be used to configure the Protect client.
  This is useful if you want to configure the Protect client specific to your application, and will future proof any additional configuration options that are added in the future.

  ```ts
  import { protect, type ProtectClientConfig } from "@cipherstash/protect";

  const config: ProtectClientConfig = {
    schemas: [users, orders],
    workspaceCrn: "your-workspace-crn",
    accessKey: "your-access-key",
    clientId: "your-client-id",
    clientKey: "your-client-key",
  };

  const protectClient = await protect(config);
  ```

  The now deprecated method of passing your tables to the `protect` client is no longer supported.

  ```ts
  import { protect, type ProtectClientConfig } from "@cipherstash/protect";

  // old method (no longer supported)
  const protectClient = await protect(users, orders);

  // required method
  const config: ProtectClientConfig = {
    schemas: [users, orders],
  };

  const protectClient = await protect(config);
  ```

## 8.4.0

### Minor Changes

- a471821: Fixed a bug in the model interface to correctly handle undefined and null values.

## 8.3.0

### Minor Changes

- 628acdc: Implemented createSearchTerms for a streamlined way of working with encrypted search terms.

## 8.2.0

### Minor Changes

- 0883e16: Fix cipherstash.toml and cipherstash.secret.toml file loading by bumping to @cipherstash/protect-ffi v0.14.2

## 8.1.0

### Minor Changes

- 95c891d: Implemented CipherStash CRN in favor of workspace ID.

  - Replaces the environment variable `CS_WORKSPACE_ID` with `CS_WORKSPACE_CRN`
  - Replaces `workspace_id` with `workspace_crn` in the `cipherstash.toml` file

- 18d3653: Fixed handling composite types for EQL v2.

## 8.0.0

### Major Changes

- 8a4ea80: Implement EQL v2 data structure.

  - Support for Protect.js searchable encryption when using Supabase.
  - Encrypted payloads are now composite types which support searchable encryption with EQL v2 functions.
  - The `data` property is an object that matches the EQL v2 data structure.

## 7.0.0

### Major Changes

- 2cb2d84: Replaced bulk operations with model operations.

## 6.3.0

### Minor Changes

- a564f21: Bumped versions of dependencies to address CWE-346.

## 6.2.0

### Minor Changes

- fe4b443: Added symbolic link for protect readme.

## 6.1.0

### Minor Changes

- 43e1acb: \* Added support for searching encrypted data
  - Added a schema strategy for defining your schema
  - Required schema to initialize the protect client

## 6.0.0

### Major Changes

- f4d8334: Released protectjs-ffi with toml file configuration support.
  Added a `withResult` pattern to all public facing functions for better error handling.
  Updated all documentation to reflect the new configuration pattern.

## 5.2.0

### Minor Changes

- 499c246: Implemented protectjs-ffi.

## 5.1.0

### Minor Changes

- 5a34e76: Rebranded logging context and fixed tests.

## 5.0.0

### Major Changes

- 76599e5: Rebrand jseql to protect.

## 4.0.0

### Major Changes

- 5c08fe5: Enforced lock context to be called as a proto function rather than an optional argument for crypto functions.
  There was a bug that caused the lock context to be interpreted as undefined when the users intention was to use it causing the encryption/decryption to fail.
  This is a breaking change for users who were using the lock context as an optional argument.
  To use the lock context, call the `withLockContext` method on the encrypt, decrypt, and bulk encrypt/decrypt functions, passing the lock context as a parameter rather than as an optional argument.

## 3.9.0

### Minor Changes

- e885975: Fixed improper use of throwing errors, and log with jseql logger.

## 3.8.0

### Minor Changes

- eeaec18: Implemented typing and import synatx for es6.

## 3.7.0

### Minor Changes

- 7b8ec52: Implement packageless logging framework.

## 3.6.0

### Minor Changes

- 7480cfd: Fixed node:util package bundling.

## 3.5.0

### Minor Changes

- c0123be: Replaced logtape with native node debuglog.

## 3.4.0

### Minor Changes

- 9a3132c: Implemented bulk encryption and decryptions.
- 9a3132c: Fixed the logtape peer dependency version.

## 3.3.0

### Minor Changes

- 80ee5af: Fixed bugs when implmenting the lock context with CTS v2 tokens.

## 3.2.0

### Minor Changes

- 0526f60: Use the latest jseql-ffi (0.4.0)
- fbb2bcb: Implemented CTS v2 for identity lock.

## 3.1.0

### Minor Changes

- 71ce612: Released support for LockContext initializer.
- e484718: Refactored init function to not require envrionment variables as arguments.
- e484718: Replaces jset with vitest for better typescript support.

## 3.0.0

### Major Changes

- 2eefb5f: Implemented jseql-ffi for inline crypto.

## 2.1.0

### Minor Changes

- 0536f03: Implemented new CsPlaintextV1Schema type and schema.

## 2.0.0

### Major Changes

- bea60c4: Added release management.

## 1.0.0

### Major Changes

- Released the initial version of jseql.
