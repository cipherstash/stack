# @cipherstash/prisma-next

## 0.4.0-rc.0

### Minor Changes

- d6d23be: Upgrade to Prisma Next 0.14.0 (from 0.8.0). Every `@prisma-next/*` dependency is now pinned at 0.14.0; consuming apps must run Prisma Next 0.14 to use this release.

  Highlights of the upgrade:

  - The extension contract space is re-emitted in the 0.14 canonical shape: storage is namespace-enveloped (`storage.namespaces.public.entries.table`), the domain plane replaces flat `models`, and the baseline EQL-install migration is re-pinned to the new storage hash. The vendored EQL bundle SQL is unchanged byte-for-byte.
  - `deriveStackSchemas` reads the namespace-enveloped contract shape emitted by Prisma Next 0.10+.
  - The bulk-encrypt middleware accepts the widened insert/update AST value unions introduced through 0.9–0.11.
  - README examples use the namespace-qualified ORM accessors (`db.orm.public.User`) required since Prisma Next 0.14.

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

## 0.3.2

### Patch Changes

- Updated dependencies [cc62407]
- Updated dependencies [5e4f354]
- Updated dependencies [4ceefed]
- Updated dependencies [cb34d71]
- Updated dependencies [aa9c4b1]
- Updated dependencies [90d19fb]
- Updated dependencies [a5f5422]
- Updated dependencies [35b9ed6]
  - @cipherstash/stack@0.19.0

## 0.3.1

### Patch Changes

- Updated dependencies [6e7ae4e]
- Updated dependencies [712d7fa]
  - @cipherstash/stack@0.18.0

## 0.3.0

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

### Patch Changes

- Updated dependencies [f743fcc]
  - @cipherstash/stack@0.17.0

## 0.2.0

### Minor Changes

- f2aca22: Upgrade `@prisma-next/*` peer/runtime stack from `0.6.0-dev.8` to `0.8.0`.

  `@prisma-next/sql-runtime@0.8` reordered the SQL execution pipeline so the `beforeExecute` middleware chain fires _before_ `encodeParams`. `bulkEncryptMiddleware` now mutates params via `replaceValues(...)` ahead of encode, which means `CipherstashCellCodec.encode` is invoked with the wire-format string rather than the original `EncryptedEnvelopeBase`. The cell codec now short-circuits string values through unchanged; the envelope path is preserved for direct (non-runtime) callers such as the codec unit tests.

  `SqlMiddlewareContext.scope` (`"runtime" | "connection" | "transaction"`) also became required in 0.8 (was optional in 0.7); test mocks now set `scope: 'runtime'` explicitly.

### Patch Changes

- Updated dependencies [1c2fdbf]
  - @cipherstash/stack@0.16.0

## 0.1.0

### Minor Changes

- dc02d0b: Add `@cipherstash/prisma-next` — searchable application-layer encryption for Postgres with Prisma Next. The framework's migration system installs the EQL bundle in the same `prisma-next migration apply` sweep that creates the application schema; no separate `stash db install` step.

  **`@cipherstash/prisma-next` (new package, initial release)**

  - **Six encrypted column types** — `EncryptedString`, `EncryptedDouble`, `EncryptedBigInt`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedJson` — declared via PSL constructors (`cipherstash.Encrypted*()`) or TS factories (`encryptedString()`, etc.).
  - **17 query operators** — 13 predicate operators surfaced as column methods (`cipherstashEq`, `cipherstashIlike`, `cipherstashGt`, `cipherstashBetween`, `cipherstashInArray`, `cipherstashJsonbPathExists`, …) and 4 free-standing helpers (`cipherstashAsc`, `cipherstashDesc`, `cipherstashJsonbPathQueryFirst`, `cipherstashJsonbGet`).
  - **Per-codec search-mode flags** (`equality`, `freeTextSearch`, `orderAndRange`, `searchableJson`) drive the EQL search-config indices the codec lifecycle hook emits at migration time. Defaults to `true` across the board.
  - **One-call setup** via `cipherstashFromStack({ contractJson })` from `@cipherstash/prisma-next/stack` — derives the stack `encryptedTable` / `encryptedColumn` schemas from `contract.json` (single source of truth, no duplicate hand-written declarations), constructs the `@cipherstash/stack` `EncryptionClient`, builds the framework-native `CipherstashSdk` adapter, and returns ready-to-spread `{ extensions, middleware, encryptionClient }` for `postgres<Contract>({...})`.
  - **Layered API** — `deriveStackSchemas(contractJson)` and `createCipherstashSdk(client, schemas)` exposed as primitives for advanced users (custom keysets, multi-tenant routing, non-stack KMS).
  - **Bulk-encrypt middleware** (`bulkEncryptMiddleware(sdk)`) coalesces every plaintext placeholder across a query into one `bulkEncrypt` SDK round-trip per `(table, column)` group. `decryptAll(rows)` does the symmetric coalescing on the read side.
  - **Misconfig diagnostic** — if the user constructs the runtime descriptor but forgets to register `bulkEncryptMiddleware(sdk)` against the same SDK, the codec's encode throws a `RUNTIME.ENCODE_FAILED` envelope with a copy-pasteable wiring snippet at the first encrypted write.
  - **Subpath exports** — `./stack`, `./control`, `./runtime`, `./middleware`, `./pack`, `./column-types`; tree-shakable along the control / runtime / middleware seams.
  - **Contributes an EQL contract space** — installs the `eql_v2` schema, `eql_v2_encrypted` composite type, `ore_*` types, EQL functions / operators / casts via the cipherstash extension's baseline migration. Runs in the same control-plane sweep as the application schema.
  - **Full docs**: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next.

  **`stash` (new feature)**

  - **`stash init --prisma-next`** — new init provider for Prisma Next projects. Reuses `authenticate` + `resolve-database` + `install-deps` (additionally installs `@cipherstash/prisma-next`), skips `install-eql` (the framework handles it via `prisma-next migration apply`) and `build-schema` (`cipherstashFromStack` derives schemas from the contract — no hand-written encryption client file). Detected automatically when a `prisma-next.config.*` or `@cipherstash/prisma-next` dependency is present in the project.
  - **`detectPrismaNext(cwd)`** — new export from `commands/db/detect.ts` mirroring the existing `detectDrizzle` / `detectSupabase` helpers.
