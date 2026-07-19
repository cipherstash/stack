# @cipherstash/prisma-next

## 1.0.0-rc.3

### Minor Changes

- a75513b: **Breaking:** EQL v3 columns are now authored through **concrete per-domain constructors** — the constructor you choose _is_ the capability set. The legacy boolean-option surface (`EncryptedString({ equality, freeTextSearch, orderAndRange })`) is not carried into v3.

  - New per-domain constructors, one per exposed `public.eql_v3_*` domain:
    - Text: `EncryptedText` (storage), `EncryptedTextEq`, `EncryptedTextOrd` (eq + order/range), `EncryptedTextMatch` (free-text), `EncryptedTextSearch` (eq + free-text + order/range).
    - Scalars (Integer, Smallint, BigInt, Numeric, Real, Double, Date, Timestamp): `Encrypted<Fam>` (storage), `Encrypted<Fam>Eq`, `Encrypted<Fam>Ord`.
    - `EncryptedBoolean` — storage-only (`public.eql_v3_boolean`); there is no boolean equality constructor.
    - `EncryptedJson` — searchable encrypted JSONB (`public.eql_v3_json`, `ste_vec`), queried with `eqlJsonContains` (`@>` containment). Selector querying (comparing the value at a JSONPath) is tracked in #677.
  - **Impossible capability combinations have no constructor** (e.g. text equality + free-text without order/range) — they are unrepresentable, not runtime errors.
  - **BigInt is a first-class v3 family** (`EncryptedBigInt` / `EncryptedBigIntEq` / `EncryptedBigIntOrd`, JS `bigint` plaintext, backed by `public.eql_v3_bigint*`).
  - Use the `*V2` constructors (`EncryptedStringV2`, `EncryptedDoubleV2`, `EncryptedBigIntV2`, `EncryptedDateV2`, `EncryptedBooleanV2`, `EncryptedJsonV2`) to keep EQL v2 columns. A client is v2 or v3 — the two runtime descriptors are never co-registered.
  - New `@cipherstash/prisma-next/v3` entry point: `cipherstashFromStackV3({ contractJson })` builds the v3 runtime descriptor, bulk-encrypt middleware, and a stack `EncryptionV3` client from the emitted contract.
  - Query operators use an **EQL-derived vocabulary** (`eqlEq`, `eqlNeq`, `eqlIn`, `eqlNotIn`, `eqlGt`, `eqlGte`, `eqlLt`, `eqlLte`, `eqlBetween`, `eqlNotBetween`, `eqlJsonContains`; ordering via `eqlAsc` / `eqlDesc`), lowering to the same-named `eql_v3.*` functions with operands cast to the domain's query type (`$n::eql_v3.query_<domain>`); ordering uses `eql_v3.ord_term` / `eql_v3.ord_term_ore` by the column's ordering flavour. The domains are `public.eql_v3_*`; the operator functions live in the `eql_v3` schema. (The v2 surface keeps its `cipherstash*` names.)
  - Free-text search is **`eqlMatch`** — fuzzy bloom token matching (`eql_v3.contains`), deliberately NOT named after SQL `ILIKE`: matching is case-insensitive, order/multiplicity-insensitive, and one-sided (may false-positive). Two guards run before encryption: SQL wildcards are normalised (leading/trailing `%` stripped; interior `%` or any `_` rejected), and needles the column's match index cannot answer (empty / below the tokenizer length) are rejected via the shared `matchNeedleError` guard. There is **no negated match operator** — negating a may-false-positive bloom test would silently drop matching rows.
  - A new baseline migration `20260601T0100_install_eql_v3_bundle` (invariant `cipherstash:install-eql-v3-bundle-v1`) installs the `public.eql_v3_*` domains and `eql_v3.*` functions from the pinned `@cipherstash/eql` release. Regenerate contracts and run migrations after changing constructors.
  - **The v3 ORM surface is fully wired end-to-end** (proven by converting `examples/prisma`):
    - The generated `contract.d.ts` type surface covers every v3 codec id: `CodecTypes` gains all 40 `cipherstash/eql-v3/*@1` entries (envelope outputs — `number`-castAs domains decode to the new `EncryptedNumber` — plus trait-accurate operator visibility), and `QueryOperationTypes` gains the `eql*` operator set, surfaced on v3 columns via type-level `cipherstash:v3-*` marker traits (the v2 `cipherstash*` methods never appear on v3 columns, and vice-versa). Storage-only domains (including `EncryptedBoolean`) surface no operator methods at the type level, matching the runtime gate.
    - The v3 runtime descriptor now presents the **pack id** (`cipherstash`) with v3's own version, so `postgres<Contract>({ extensions })` accepts contracts emitted by the cipherstash extension pack instead of failing with `RUNTIME.MISSING_EXTENSION_PACK`.
    - Every v3 codec id registers a control-plane `expandNativeType` hook that strips the `public.` qualifier — `prisma-next migration plan` now renders `CREATE TABLE` columns as bare domain names (`eql_v3_bigint_ord`), matching what introspection reports, with **no `add_search_config` ops** (v3 domains carry their own index metadata). No `onFieldEvent` is registered for v3.
    - The v3 bundle baseline migration op is reclassified `data` (it is a contract-shape-neutral self-edge; the aggregate integrity checker rejects self-edges without a data-class op), unblocking `prisma-next migration plan` / `migrate` in consuming apps.

- 4923c0a: **Breaking (v3 authoring surface):** the EQL v3 PSL column constructors drop
  the `Encrypted` prefix to line up with the stack / Drizzle `types.*` catalog —
  the `cipherstash.` namespace already disambiguates. So
  `cipherstash.EncryptedTextSearch()` → `cipherstash.TextSearch()`,
  `cipherstash.EncryptedDoubleOrd()` → `cipherstash.DoubleOrd()`,
  `cipherstash.EncryptedBoolean()` → `cipherstash.Boolean()`, etc.

  The v3 one-call setup function is renamed `cipherstashFromStackV3` →
  `cipherstashFromStack` (v3 is the default), and the existing v2 setup function
  becomes `cipherstashFromStackV2`.

  The camelCase TS-authoring factory exports move in lockstep:
  `encryptedTextSearch` → `textSearch`, `encryptedDoubleOrd` → `doubleOrd`, etc.
  (a property test enforces the PSL and TS names agree modulo first-letter case).

  Unchanged: the runtime value envelopes (`EncryptedString`, `EncryptedNumber`,
  `EncryptedBoolean`, …), the `cipherstash.*V2` legacy column constructors, the
  generated `contract.json` / codec ids, and the `eql*` query operators.

  The `stash-prisma-next` skill is updated to the new names (skills ship in the
  `stash` tarball).

- a2f80ea: Source the EQL v3 install SQL from `@cipherstash/eql` at runtime instead of
  baking it into the baseline migration.

  `@cipherstash/eql` is now a runtime dependency, pinned exact (`3.0.0`) to match
  the release `@cipherstash/stack` encodes its v3 domain **types** against — the
  two must move together, so an EQL upgrade is a coordinated version bump, not a
  float. The v3 baseline migration no longer embeds the ~1.7 MB install bundle in
  its `ops.json`: the committed op carries a placeholder, and the extension
  descriptor injects `readInstallSql()` from the installed `@cipherstash/eql` when
  it is built, and recomputes the content-addressed migration hash from the
  injected operations before Prisma Next materialises the package.

  The win over baking: bumping the pinned `@cipherstash/eql` no longer requires
  re-running the maintainer emit loop to regenerate a 1.7 MB `ops.json` — it is a
  one-line version bump plus a rebuild. This mirrors how the `stash` CLI already
  sources the v3 SQL.

  No change to user-facing behaviour: EQL still installs as part of
  `prisma-next migration apply`. Safe because the v3 baseline is an
  invariant-only self-edge — the install SQL never contributes to the
  contract-space hash. Injection matches the placeholder by value and fails loudly
  if it is absent, so a drift between the emit source and the injector can never
  silently ship an empty install.

### Patch Changes

- Updated dependencies [8b2551a]
  - @cipherstash/stack@1.0.0-rc.3

## 1.0.0-rc.2

### Patch Changes

- daa25b8: `@cipherstash/prisma-next` now versions in lockstep with the Stack release
  train (`stash`, `@cipherstash/stack`, and the other adapters) via a Changesets
  `fixed` group — `stash init` installs it pinned by exact version, so the two
  must always release together. This moves the package from its previous `0.4.x`
  line onto the shared train version; no API changes.
- Updated dependencies [b085f66]
  - @cipherstash/stack@1.0.0-rc.2

## 0.4.0-rc.1

### Patch Changes

- Updated dependencies [e297f64]
- Updated dependencies [40ab142]
- Updated dependencies [5fe9a2f]
- Updated dependencies [7b53141]
  - @cipherstash/stack@1.0.0-rc.1

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
