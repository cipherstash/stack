# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the project is pre-1.0, breaking changes are released as minor version
bumps and called out under a `Breaking` heading — an addition to the standard
Keep a Changelog categories (Added/Changed/Deprecated/Removed/Fixed/Security).

Add notes for unreleased work under the `[Unreleased]` heading below. On
release, the `version` npm lifecycle hook promotes that section to a dated
release entry (see `scripts/changelog-release.mjs`), and the release workflow
uses the promoted section as the GitHub release notes.

## [Unreleased]

## [0.31.0] - 2026-07-27

### Breaking

- **The wasm `newClient` takes credentials and `keyset` under `clientOpts`.**
  It used to read `clientId`, `clientKey`, and `keyset` from the top level of
  the options object; they now live where the Neon entry has always had them,
  because both entries deserialize the same `NewClientOptions`. ([#142])

  ```js
  // before
  await newClient({ encryptConfig, strategy, clientId, clientKey, keyset })
  // after
  await newClient({
    encryptConfig,
    authStrategy,
    clientOpts: { clientId, clientKey, keyset },
  })
  ```

  **Move `keyset` with the rest.** Unknown option keys are still dropped
  rather than rejected (tracked in [#147]), so a `keyset` left at the top
  level is silently ignored and the client binds to the **default keyset** —
  it will encrypt, under the wrong keys. The credential fields fail loudly if
  you miss them; this one does not.

  `clientOpts` also carries `workspaceCrn` and `accessKey`, which the wasm
  `newClient` did not accept before. Top-level `eqlVersion` is unchanged — it
  worked on this entry already.

  Otherwise: `strategy` still works under its old name, and `encryptConfig`
  accepts strictly more than it did (see normalisation, below).

- **`clientOpts.clientKey` must be hex.** It was decoded by
  `SecretKey::from_hex`, which falls back to standard padded base64 — the
  encoding `~/.cipherstash/secretkey.json` uses on disk — so a base64 value
  passed as `clientKey`, or set in `CS_CLIENT_KEY` (which the Neon entry
  forwards as `clientKey`), used to work. It is now rejected with `invalid
  clientKey: expected a hex-encoded key`. Re-encode as hex, or read the key
  from the profile store instead of pasting it.

  The decode error deliberately says nothing more: `hex`'s own message names
  the offending character and its offset, which would put part of a live key
  into logs.

- **A malformed `clientOpts.clientId` now fails even without a `clientKey`.**
  It used to be parsed only as half of the `clientId` + `clientKey` pair, so
  `newClient({ encryptConfig, clientOpts: { clientId: '<malformed>' } })` fell
  through to the profile store and succeeded on the Neon entry. It now throws
  `invalid clientId: ...` at the options boundary. Fail-closed, and the error
  names the field, but it is a call that used to work.

- **The wasm entry's declarations are types now, not `any`.** Every export was
  `(client: WasmClient, opts: any) => Promise<any>`, which type-checked
  anything. A TypeScript consumer whose calls were wrong all along will now
  see those errors at build time. That is the feature, but it lands as a build
  failure on upgrade, so budget for it.

- **A key an options object doesn't declare is now an error, not a silent
  drop.** Every options struct rejects unrecognised fields, naming the
  offender — ``unknown field `clientId` `` — instead of discarding them on the
  way in. A misspelling, a stale key, or a value in the wrong place fails
  loudly. ([#144])

  This is how the wasm credential move was found: four integration tests
  failed with "clientOpts.clientId and clientOpts.clientKey are required"
  while passing exactly those, because the old top-level spelling was being
  dropped in silence. The message described the symptom, not the cause.

  `lockContext` is the case that mattered most. On a bulk call it belongs on
  each payload item; at the top level it was dropped, and every value
  encrypted **unbound** while the caller believed it was identity-bound.
  Nothing in the output distinguished the two.

  Two notes on how far this reaches:

  - The wasm boundary needed more than the serde attribute.
    `serde-wasm-bindgen` reads a struct by looking up the fields it expects
    (`obj[key]`), never enumerating the object — an undeclared key was
    invisible to serde, so `deny_unknown_fields` alone would have rejected
    nothing there. A marker type puts every options struct on serde's flatten
    path, which does enumerate. That boundary needed it most: it is the one
    that dropped the credentials.
  - The Neon entry's `newClient` rebuilt the native options object field by
    field, dropping unrecognised top-level keys before the Rust could see
    them. It now forwards them.
  - **On wasm, a declared field is now read only if it is an own enumerable
    property.** The lookup it replaces walked the prototype chain and saw
    non-enumerable properties too. An options bag — an object literal, or a
    spread of one — is unaffected; a class instance passed as options loses
    its inherited fields, and a field defined through
    `Object.defineProperty({enumerable: false})` is dropped. Neon has always
    been `JSON.stringify`, which is own-enumerable too.
  - **A misspelled *required* field now reports it as missing, not unknown.**
    `encrypt(client, {plaintext, column, tabel: 'users'})` says ``missing
    field `table` `` and never names `tabel`; it used to say both. Serde's
    flatten path buffers the map and reports at its closing brace, which also
    drops the `expected one of ...` list from every rejection. Neon-only —
    the wasm path had no error to lose.

  Three differences between the boundaries remain, all of them about how
  strictly a *mistake* is reported. Correct input behaves identically on both.

  - A key whose value is `undefined` (`{...opts, typo: undefined}`) is
    rejected on wasm and accepted on Neon, where `JSON.stringify` drops it
    before serde runs.
  - A key whose value is a **function or a symbol** is reported on wasm — as a
    *type* error, naming the wrong problem — and dropped in silence on Neon,
    where `JSON.stringify` omits it.
  - A key holding a **circular value or a `bigint`** throws in
    `JSON.stringify` on Neon before serde can see it. `newClient` names the
    key itself rather than let a bare `TypeError: Converting circular
    structure to JSON` out; the other entries do not.

- **`ProtectError` and `normalizeError` are gone. Both entries throw an
  ordinary `Error` with a `code` property.** ([#146])

  ```ts
  // before — Node entry only, and only for errors the message table matched
  if (err instanceof ProtectError && err.code === 'INVALID_JSON_PATH') { }

  // after — both entries, nothing to import
  if (err instanceof Error && 'code' in err && err.code === 'INVALID_JSON_PATH') { }

  // after, when you want the code as a typed value
  import { isProtectErrorCode } from '@cipherstash/protect-ffi'
  const { code } = err as { code?: unknown }
  if (isProtectErrorCode(code)) { /* code narrows to ProtectErrorCode */ }
  ```

  Every export used to run through a try/catch that re-threw the failure as a
  `ProtectError`. Once Rust set `code` on the error it builds, that layer had
  nothing left to add and three costs left to pay: the two bindings threw
  different things, the stack trace was re-based onto the wrapper with the real
  one demoted to `cause`, and `instanceof` is false across duplicate copies of
  a package — so the check it existed to provide was the unreliable one.

  Nothing is lost with it. `message` and `code` are what callers read, and both
  come straight from Rust. A `RangeError` for an out-of-range bigint is still a
  `RangeError` — before, it survived because the inference table happened not
  to match it.

- **A failed `decryptBulkFallible` item with no code omits the field instead of
  setting `'UNKNOWN'`.** The declared type has always been
  `code?: ProtectErrorCode`, but on the Neon entry the field was in practice
  always present, because the JS wrapper ran every failed item's message
  through the inference table and stored whatever came back — `'UNKNOWN'`
  included. Rust sets the field now, and only when there is a code to set, so
  `item.code === 'UNKNOWN'` no longer matches. Test for absence instead.
  ([#146])

### Added

- **The wasm build declares the real option types**, emitted by wasm-bindgen
  from `typescript_type` / `typescript_custom_section` attributes on the Rust.
  Previously it typed every export as `(client: WasmClient, opts: any):
  Promise<any>`, so the
  `./wasm` and `./wasm-inline` entries checked nothing and exported no option
  or payload types at all — while the Neon entry declared fourteen. Both
  entries now name the same types.

  This was not cosmetic. A consumer writing one interface over both bindings
  had to import the option types from the Neon entry, since that was the only
  place they existed — which put a `@cipherstash/protect-ffi` specifier into
  the published types of a bundle whose entire purpose is to avoid loading a
  native binary. ([#142])

  Mistakes the wasm entry now catches at compile time, all of which previously
  reached the Rust:

  - `lockContext` at the top level of a bulk call. It belongs on each payload
    item; at the top level serde drops it, and the values are encrypted
    **unbound** while the caller believes they are identity-bound.
  - A misspelled or unknown option key.
  - A closed-set value typo such as `indexType: 'matsh'`.
  - A plaintext that is not a `JsPlaintext`.

  The shared types moved to `src/types.ts` and are re-exported by the Neon
  entry, so **its public surface is unchanged**.

  There is now no wasm-only type: both entries name exactly the same set.
  Two exceptions existed while this work was in progress and both are resolved
  below — `newClient` took a different options shape and a pre-canonicalised
  config, and `WasmDecryptResult` omitted `code` because Rust did not emit one.
  The bindings share one `NewClientOptions` and one `DecryptResult` ([#146]).

- **`PROTECT_ERROR_CODES` and `isProtectErrorCode`.** The codes are now a
  runtime list with the `ProtectErrorCode` union derived from it, plus a
  predicate over that list. Together they are the whole of the error API.
  ([#146])

  Branching on a code needs neither — `err instanceof Error && 'code' in err &&
  err.code === 'MISSING_INDEX'` compiles under `strict` on its own.
  `isProtectErrorCode` earns its place when you want the code as a *typed*
  value, since it narrows `unknown` to `ProtectErrorCode`:

  ```ts
  import {
    isProtectErrorCode,
    type ProtectErrorCode,
  } from '@cipherstash/protect-ffi'

  function errorCode(err: unknown): ProtectErrorCode | undefined {
    const { code } = err as { code?: unknown }
    return isProtectErrorCode(code) ? code : undefined
  }
  ```

  It checks the value rather than the field's presence because `code` is not
  ours alone: Node sets one on its own errors, so an `ECONNRESET` would
  otherwise pass for one of these.

- `CanonicalCastAs`, `CanonicalColumn`, and `CanonicalEncryptConfig` are now
  public, in `types.ts`. They were `NativeCastAs` / `NativeColumn` /
  `NativeEncryptConfig`, internal to `normalizeEncryptConfig.ts` — never
  exported from any entry point, so nothing depended on the old names.
  Renamed because the vocabulary is the Rust core's, not the Node addon's —
  the wasm build requires it too, and now says so in its types.

### Changed

- **`encryptConfig` normalisation moved into Rust.** `cast_as: 'string' |
  'number' | 'bigint'` → `'text' | 'float' | 'big_int'`, and the `ste_vec`
  `array_index_mode` default of `'none'`, now happen at the deserialization
  boundary rather than in the Neon entry's JS wrapper.

  Both bindings therefore accept the same config. Previously only the Neon
  entry normalised, so a wasm caller had to pre-canonicalise by hand or be
  rejected with an opaque variant error — and `@cipherstash/stack` had
  reimplemented the `cast_as` half for its own wasm path. One implementation
  now, in `crates/protect-ffi/src/encrypt_config.rs`, with the JS
  `normalizeEncryptConfig` module removed and its cases ported to Rust tests.

  Normalisation stays tolerant: an unrecognised shape passes through untouched
  so `CanonicalEncryptionConfig` still produces the error, which is more
  specific than anything the normaliser could invent.

  It also drops `undefined`-valued keys, which is new behaviour on the wasm
  entry. `{ cast_as: cfg.castAs }` with an undefined `castAs` is ordinary
  JavaScript and has always worked on the Neon entry, whose extractor is
  `JSON.stringify`-based; on wasm those keys survive as `null` and every
  non-optional field rejected them (`invalid type: null, expected string or
  map`). One config now works on both.

- **`newClient`'s `strategy` option is now `authStrategy`**, matching
  `@cipherstash/stack`'s `config.authStrategy` so one concept has one name
  across the stack. Both entries accept it.

  `strategy` still works and is marked `@deprecated`; `authStrategy` wins if
  both are set. No caller breaks today, but move over — the old name will be
  removed.

- **Error codes come from Rust now, rather than from parsing the error message
  in JavaScript.** `err.code` is set at the FFI boundary from the error's
  variant. The values are unchanged. ([#146])

  What it replaces: the same process serialised structure to prose and then
  parsed the prose back. Rust threw away the variant, and `src/errors.ts`
  recovered a code by matching the message against fourteen prefixes and
  substrings. Three of them matched wording owned by **cipherstash-config**,
  not this repo —

  ```ts
  if (message.includes('requires plaintext_type: json'))
    return 'STE_VEC_REQUIRES_JSON_CAST_AS'
  ```

  — so an upstream reword would have silently downgraded a caller's error to
  `UNKNOWN`: the call still fails, just less usefully, and nothing here would
  have failed to say so. Nor could you tell which three by reading the table:
  `' index configured'` looks like an upstream phrase and is this repo's own.

  Those three (`STE_VEC_REQUIRES_JSON_CAST_AS`, `MATCH_REQUIRES_TEXT`,
  `UNSUPPORTED_CONFIG_VERSION`) still have to be told apart from one upstream
  type. They are decided by matching the `ConfigError` variant now, so a
  rename upstream is a compile error rather than a silent downgrade.

  One code is still recovered from a message: `UNKNOWN_QUERY_OP`. `queryOp` is
  rejected inside `Deserialize` — which is what makes the failure name the
  field, rather than surfacing later from query preparation — and serde's
  `de::Error::custom` takes a `Display`, so nothing typed survives for the
  boundary to read. The match moved into Rust beside the constant that defines
  the message, where the prefix is pinned by tests on both sides; it is a
  smaller and louder version of the same coupling, not its removal.

  Two consequences worth knowing:

  - **The wasm entry carries codes too**, for the first time. The reconstruction
    lived in the Neon entry's JS wrapper, and the wasm build has no such
    wrapper — every error it threw was uncoded.
  - **An error with no code no longer gets a guessed one.** The
    `#[error(transparent)]` variants wrap a cipherstash-client failure whose
    text this repo does not own; claiming a code for those is exactly the guess
    being removed. They arrive without the field.

### Fixed

- **`match.include_original` no longer reaches query-term generation**
  (#134). The flag is a storage-only option — it asks the indexer to add the
  whole (filtered, untokenized) value as an extra bloom term so the stored
  filter can also answer whole-value equality. Query blooms must stay
  token-only (EQL matches by bit-subset, so a whole-needle term would make
  substring queries match nothing), so `newClient` now builds a query-side
  copy of the config with `include_original` forced off and every
  `encryptQuery` / `encryptQueryBulk` path (native and wasm, v2 and v3) uses
  it. The config remains accepted as-is for storage encryption.

### Removed

- **`ProtectErrorCode` values are no longer restated in
  `docs/jsonb-api-reference.md`.** The copy there had already drifted — it was
  missing `SHORT_MATCH_NEEDLE`. The values live in `src/errors.ts` as
  `PROTECT_ERROR_CODES`, checked against the Rust attributes by
  `src/errorCodes.test.ts`. ([#146])

[#142]: https://github.com/cipherstash/protectjs-ffi/issues/142
[#144]: https://github.com/cipherstash/protectjs-ffi/issues/144
[#146]: https://github.com/cipherstash/protectjs-ffi/issues/146
[#147]: https://github.com/cipherstash/protectjs-ffi/issues/147

## [0.30.0] - 2026-07-20

### Breaking

- **EQL v3 encrypted JSON uses the client 0.42 key-header envelope.** A stored
  SteVec document is now `{v, k: "sv", i, h, sv}`: key-retrieval material is
  stored once in `h`, each entry carries raw AEAD output in `c`, and the entry
  selector supplies the authenticated nonce. Per-entry `hm` terms are removed;
  exact equality uses value-inclusive selectors. Existing v3 SteVec rows must
  be decrypted and re-encrypted because the old wire format cannot be converted
  mechanically.
- **`ste_vec_term` now means an ordering operand**, matching
  cipherstash-client: it accepts a string or number for comparisons against an
  extracted JSON entry. Use `default` with an object or array for containment.
- Configurations containing a `ste_vec` index now default to EQL v3, and an
  explicit `eqlVersion: 2` is rejected during client creation. Scalar-only
  configurations retain the v2 default.
- **EQL v3 JSON domains renamed** (eql-bindings 3.0.1 / eql 3.0.1). SteVec
  columns now target `public.eql_v3_json_search` (was `public.eql_v3_json`)
  and containment needles bind as `eql_v3.query_json` (was
  `eql_v3.query_jsonb`); `public.eql_v3_json` is now a distinct storage-only
  scalar JSON domain, which protect-ffi does not yet emit (an index-less JSON
  column still errors under `eqlVersion: 3`). Databases must run the eql 3.0.1
  installer, and SQL referencing the old names must be updated.
- **Fuzzy bloom matching is the `@@` operator** in eql 3.0.1: bind match
  queries as `col @@ $1::jsonb::eql_v3.query_<name>`. `@>`/`<@` no longer
  perform bloom matching on scalar search domains — they remain jsonb/SteVec
  containment (`doc @> $1::jsonb::eql_v3.query_json` is unchanged).

### Changed

- Bumped cipherstash-client, cts-common, stack-auth, and stack-profile to
  0.42.0 and eql-bindings to 3.0.2. The generated TypeScript types are
  refreshed from the locked Rust crate; integration tests install SQL from the
  exact matching @cipherstash/eql 3.0.2 npm package.
- Added `ste_vec_value_selector` for exact equality at a JSON path. It accepts
  exactly `{path: "$.field", value: <scalar>}` and emits a one-entry,
  selector-only containment needle. Objects and arrays continue to use the
  regular containment path.
- **EQL v3 payloads (storage and query) are now emitted natively** via
  cipherstash-client's `encrypt_eql_v3` instead of converting v2 payloads
  through `from_v2` at runtime. Scalar wire output remains pinned against the
  `from_v2` oracle; SteVec v3 is intentionally no longer convertible from v2.
  A native
  payload that fails its target domain's strict parse surfaces as
  `EQL_V3_CONVERSION_FAILED`, the same code conversion failures produced.

## [0.29.0] - 2026-07-09

### Added

- **EQL v3 scalar query-term encryption.** On an `eqlVersion: 3`
  client, `encryptQuery` / `encryptQueryBulk` on a scalar index now return the
  term-only operand for the column domain's query twin — `{v: 3, i, <terms>}`
  with **no `c` ciphertext** — bindable as
  `col = $1::jsonb::eql_v3.query_<name>` (and the ordering / `@>` match
  operators). The operand always carries ALL the column domain's terms
  (`text_search_ore` → `hm` + `ob` + `bf`), whichever `indexType` was queried:
  the EQL v3 operators pair each column domain only with its same-name query
  twin, whose domain CHECK requires the full term set. Terms derive from the
  same conversion as storage encryption, so bounds behaviour (e.g. bigint i64
  boundary rejection) is identical. This replaces the interim
  full-storage-envelope workaround — query operands no longer carry a
  decryptable ciphertext through query strings and SQL logs.
- **EQL v3 selector queries.** `queryOp: 'ste_vec_selector'` on a v3 client
  returns the bare selector hash as a **string** (there is no
  encrypted-selector envelope in v3) — bind it as the `text` argument of the
  `->` / `->>` operators. It is the same `Selector` encoding SteVec entries
  carry in `s`.
- The vendored EQL v3 TypeScript types now include the 38 scalar query-twin
  payload types (`TextEqQuery`, `IntegerOrdOreQuery`, …), exported alongside a
  new `EncryptedV3ScalarQuery` union.

### Changed

- Bumped `eql-bindings` to `3.0.0` (from `3.0.0-alpha.3`) and
  `cipherstash-client` (with `cts-common`, `stack-auth`, `stack-profile`) to
  `0.40.0` (from `0.39.1`). The EQL v3 SQL snapshot and the vendored
  `src/eql-v3-types/**` TypeScript types were regenerated from the newly
  locked release (`mise run eql:v3:build`, `scripts/sync-eql-v3-types.sh`).
- Bumped `eql-bindings` to `3.0.0-alpha.3` (from `0.4.2`): catalog-generated
  scalar `QueryPayload` variants, scalar term hoisting in `from_v2_query`, and
  the domain rename — query operands are `eql_v3.query_<name>` /
  `eql_v3.query_jsonb` (the pre-release `jsonb_query` name is gone), column
  domains live in `public.*`.
- The integration-test EQL v3 SQL snapshot
  (`integration-tests/sql/cipherstash-encrypt-v3.sql`) is now extracted from
  the locked `eql-bindings` release (`eql_bindings::sql::INSTALL_SQL`, via the
  `print_eql_v3_sql` example) instead of a sibling checkout, and was refreshed
  to EQL `3.0.0-alpha.3` — column domains are now `public.<name>` and the
  `eql_v3.query_*` operand domains exist. Rebuild with `mise run eql:v3:build`
  after bumping `eql-bindings`.
- v3 scalar queries perform a full storage-mode encryption internally (the
  ciphertext is computed, then dropped when the terms are hoisted) — the same
  trade the JSON containment path already makes.

### Breaking

- **EQL v3 public column domain is versioned.** Every
  public-schema column domain gained an `eql_v3_` prefix: a column declared
  `email public.text_eq` is now `email public.eql_v3_text_eq`, and
  `public.json` is `public.eql_v3_json`. The term-only query twins are
  unchanged (`eql_v3.query_text_eq`) — the `eql_v3` schema already versions
  them. Existing v3 tables must be migrated to the new column types.
- **`text_search` now means OPE, not ORE.** The bare search domain carries
  `hm` + `op` + `bf`; the ORE search domain is the new
  `eql_v3_text_search_ore` (`hm` + `ob` + `bf`). A `unique` + `ore` + `match`
  text column therefore targets `eql_v3_text_search_ore` and binds against
  `eql_v3.query_text_search_ore`. The same flip applies to the bare
  `<family>_ord` domains upstream; protect-ffi only ever selects the explicit
  `_ord_ore` / `_ord_ope` variants, which are unaffected. As a result,
  `unique` + `ope` + `match` on text now resolves (to `eql_v3_text_search`)
  where it previously errored.
- **The `ste_vec` index mode default flipped to `compat`** in
  `cipherstash-client` 0.40.0 (it was `standard`). An unconfigured JSON
  column now emits CLLW-OPE `op` SteVec terms instead of CLLW-ORE `oc` — in
  **v2 output as well as v3**. Indexes built under the two modes are not
  cross-comparable, so JSON columns with existing rows must either pin
  `mode: 'standard'` or be re-encrypted.
- **EQL v3 requires `compat`-mode `ste_vec`.** v3 orders SteVec entries by
  the `op` term under native byte comparison; ORE ciphertext bytes do not
  order that way, so `oc` has no mechanical conversion. A `standard`-mode
  JSON column on an `eqlVersion: 3` client now fails at configuration time
  with `EQL_V3_UNSUPPORTED_COLUMN` rather than converting incorrectly.
- The `OreCllw` TypeScript type is removed — v3 SteVec entries carry `hm` XOR
  `op`, so `oc` no longer appears in any v3 payload. `TextSearchOre` and
  `TextSearchOreQuery` are added.
- The `EQL_V3_QUERY_UNSUPPORTED` error code is removed from
  `ProtectErrorCode` — the scalar and selector queries that threw it now
  succeed and return operands.
- `EncryptedV3Query` widened from `SteVecQuery` to
  `EncryptedV3ScalarQuery | SteVecQuery | Selector`. Code that assumed every
  v3 query payload has an `sv` key must narrow first; selector results are
  plain strings.

### Fixed

- **`AuthStrategy` now types the contract the runtime already implements.** Both
  the Node (Neon) and WASM clients have accepted either a bare `{ token }` or a
  `@byteslice/result` envelope (`{ data: { token } }` / `{ failure }`) since
  `0.28.0`, but the exported `AuthStrategy` type still declared only
  `getToken: () => Promise<{ token: string }>`. That made every
  `@cipherstash/auth` `>= 0.41` strategy — whose `getToken()` resolves the
  envelope — unassignable to `newClient`'s `opts.strategy`, so downstream
  consumers hit `TS2322` on code that runs correctly. `getToken` may now resolve
  `TokenResult | TokenResultEnvelope`; both are exported. The bare shape is
  unchanged, so this is backward compatible.

  The WASM `newClient` doc comment said the same thing and has been corrected.

  Nothing here exercised the mismatch: `integration-tests` pins
  `@cipherstash/auth ^0.39.0` (pre-`Result`), so `oidc-federation.test.ts`
  compiled against the old shape. Added type-level coverage in
  `src/index.types.test.ts` asserting both shapes assign.

## [0.28.0] - 2026-07-08

### Added

- Support for `@cipherstash/auth` `0.41`'s `@byteslice/result` `Result`-shaped
  `getToken()` — `{ data: { token, … } }` on success, `{ failure: { type,
  error, … } }` on error — on both the Node (Neon) and WASM auth paths. The
  bare `{ token }` shape (the documented `getToken(): Promise<{ token }>`
  contract, used by `@cipherstash/auth` `<= 0.40` and custom strategies) is
  still accepted, so this is backward compatible. A `failure` result is
  reconstructed into the real `stack_auth::AuthError` via
  `AuthError::from_error_code`, preserving its code (e.g. `NOT_AUTHENTICATED`,
  `EXPIRED_TOKEN`) rather than flattening every failure to `Server`; unknown or
  foreign codes become `AuthError::Custom`. On the WASM path the structured
  payload rides along too, so `WORKSPACE_MISMATCH` round-trips; the Node path
  reconstructs by code + message (there `WORKSPACE_MISMATCH` surfaces as
  `Custom`, with the workspace detail preserved in the message).
- `CHANGELOG.md` plus automated release notes. On `npm version`, the `version`
  lifecycle hook promotes the `[Unreleased]` section to a dated entry
  (`scripts/changelog-release.mjs`); the release workflow then publishes that
  section as the GitHub release body (`scripts/changelog-extract.mjs`).

### Changed

- Bumped `cipherstash-client`, `cts-common`, `stack-auth`, and `stack-profile`
  to `0.39.1`. `stack-auth`'s `AuthError::Server` now wraps a `ServerError`
  newtype rather than a bare `String`, and `0.39.1` adds
  `AuthError::from_error_code` (the reconstruction the auth bridge now uses).
- License is now MIT across `LICENSE.md`, `package.json`, and `Cargo.toml`
  (the manifests previously declared ISC).

### Fixed

- Access-key auth now refreshes tokens correctly (via the `cipherstash-client`
  bump). Previously the refresher treated the absolute-epoch `expiry`
  as a relative duration, so auto-refresh never fired and every encrypt/decrypt
  began failing roughly 15 minutes after process start.

### Security

- Hardened the release and build workflows: the version input is allowlist-gated
  to npm bump keywords or strict semver before it reaches any `run:` step,
  guarding against `${{ }}` template injection.

## [0.26.0] - 2026-06-08

### Changed

- Bumped `cipherstash-client` and `stack-auth` to `0.37.0`.
- npm publishing now uses OIDC trusted publishing, and the release publish job
  was hardened (the publisher app token is scoped to `contents:write`).

### Added

- Integration coverage for the `OidcFederation` auth strategy, wired against
  `@cipherstash/auth` 0.39.0.

### Fixed

- Point the `dryrun` npm script at `release.yml`.

## [0.25.0] - 2026-05-29

### Breaking

- Removed `serviceToken` from `EncryptOptions`, `DecryptOptions`, and the query
  option types.
- Removed the `CtsToken` public type export.
- Auth environment updated for stack-auth 0.36: `CS_REGION` is dropped in favour
  of `CS_WORKSPACE_CRN`.

### Added

- `newClient` now accepts an optional `opts.strategy` (an `AuthStrategy`,
  `@cipherstash/auth`-shaped object) on **both Node and WASM**. When supplied,
  `getToken()` is invoked on every ZeroKMS request. On WASM the strategy is
  **required** (there is no env/filesystem fallback); on Node it is optional and
  falls back to the `AutoStrategy` built from credentials / profile.

### Fixed

- Node: capture a per-isolate Neon `Channel` for the JS-backed strategy, and
  `unref` it so scripts can exit cleanly after a round trip.
- Node: wrap the `getToken` JS call in `Context::try_catch` so a strategy that
  throws (or otherwise misbehaves) surfaces as a clean error instead of an
  unhandled rejection.

### Changed

- Bumped `cipherstash-client`, `cts-common`, `stack-auth`, and `stack-profile`
  to `0.36.0`.
- Expanded integration coverage: JS-backed auth contract, event-loop-exit, and
  `newClient` guard tests.

## [0.24.0] - 2026-05-26

### Added

- WASM build target: a `wasm-bindgen` surface (`src/wasm.rs`), a build pipeline
  with CI integration, and an end-to-end round-trip integration test.

### Fixed

- WASM: match Neon's flat API shape and drop the `@ts-self-types` directive from
  the inline shim.
- WASM: wrap the `client_key` hex in a `ZeroizeOnDrop` newtype from
  deserialization, with tighter typing and zeroize for client credentials.
- WASM: use `CanonicalEncryptionConfig` after the config refactor.

### Changed

- `cfg`-gate Neon-only code so `wasm32` compiles.
- Bumped dependencies for a wasm-ready `cipherstash-client` and `vitaminc`.

## [0.23.0] - 2026-05-21

### Fixed

- Types: split the storage `Encrypted` payload from the query payload types.
- Types: forbid ciphertext on `EncryptedScalarQuery`.

## [0.22.0] - 2026-05-20

### Added

- Expose the STE-vector encoding mode option.
- Normalize encrypt config vocabulary at the FFI boundary, including a
  `normalizeEncryptConfig` `cast_as` translation helper.

### Changed

- Replace the hand-rolled encrypt config with `CanonicalEncryptionConfig`
  (see the migration notes documented in this release for breaking config
  changes).
- Upgrade `cipherstash-client` to `0.35.0`.

[Unreleased]: https://github.com/cipherstash/protectjs-ffi/compare/v0.31.0...HEAD
[0.31.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.30.0...v0.31.0
[0.30.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.26.0...v0.28.0
[0.26.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/cipherstash/protectjs-ffi/compare/v0.21.4...v0.22.0
