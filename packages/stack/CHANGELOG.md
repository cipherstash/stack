# @cipherstash/stack

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
