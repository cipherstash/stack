# CipherStash Client FFI (`@cipherstash/protect-ffi`)

> [!IMPORTANT]
> If you are looking to implement this package into your application please use the official [`@cipherstash/stack` package](https://github.com/cipherstash/stack).

This project provides the JS bindings for the CipherStash Client Rust SDK and is bootstrapped by [create-neon](https://www.npmjs.com/package/create-neon).

## Building

Building requires a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support).

To run the build, run:

```sh
$ npm run build
```

This command uses the [@neon-rs/cli](https://www.npmjs.com/package/@neon-rs/cli) utility to assemble the binary Node addon from the output of `cargo`.

## Local setup

Authenticate the `stash` CLI to set up your local environment. It runs via `npx` — no separate install needed:

```sh
npx stash auth login
```

You will be prompted to sign in or create an account.

## Exploring

After building `protect-ffi`, you can explore its exports at the Node console.
Credentials must be available for the call to `newClient()` to succeed — resolved from the CipherStash profile store, from environment variables, or from an explicit `authStrategy` passed to `newClient()`. For local development the simplest option is `npx stash auth login`, which populates the profile store. Alternatively, set `CS_WORKSPACE_CRN`, `CS_ACCESS_KEY`, and the `CS_CLIENT_ID`/`CS_CLIENT_KEY` keypair in your environment.

```sh
$ npm i
$ npm run build
$ node
> const addon = require(".");
> const client = await addon.newClient({ encryptConfig: {v: 1, tables: {users: {email: {indexes: {ore: {}, match: {}, unique: {}}}}}} });
> const ciphertext = await addon.encrypt(client, { plaintext: "plaintext", column: "email", table: "users" });
> const plaintext = await addon.decrypt(client, { ciphertext });
> console.log({ciphertext, plaintext});
```

## EQL version selection

`newClient` accepts an `eqlVersion` option selecting the wire format that
`encrypt` / `encryptBulk` / `encryptQuery` emit:

```js
// EQL v2 (default) — the `eql_v2_encrypted` payload format
const v2 = await addon.newClient({ encryptConfig })

// EQL v3 — payloads for the per-capability `eql_v3` domains
const v3 = await addon.newClient({ encryptConfig, eqlVersion: 3 })
```

With `eqlVersion: 3`, each column's payload targets the `eql_v3` domain
derived from its `cast_as` and indexes:

Every public-schema column domain carries an `eql_v3_` prefix (so the SQL
column type is `public.eql_v3_text_eq`); the term-only query twins do not
(`eql_v3.query_text_eq`), because the `eql_v3` schema already versions them.

| `cast_as` | family | indexes | domain |
|-----------|--------|---------|--------|
| `text` | `text` | `unique` + `ore` + `match` | `eql_v3_text_search_ore` |
| `text` | `text` | `unique` + `ope` + `match` | `eql_v3_text_search` |
| `text` | `text` | `unique` + `ore` | `eql_v3_text_ord_ore` |
| `text` | `text` | `match` | `eql_v3_text_match` |
| `text` | `text` | `unique` | `eql_v3_text_eq` |
| `int` / `small_int` / `bigint` | `integer` / `smallint` / `bigint` | `ore` (with or without `unique`) | `eql_v3_<family>_ord_ore` |
| `int` / `small_int` / `bigint` | `integer` / `smallint` / `bigint` | `unique` | `eql_v3_<family>_eq` |
| `number` / `decimal` / `date` / `timestamp` | `double` / `numeric` / `date` / `timestamp` | as above | as above |
| any scalar | — | none | storage-only domain (`eql_v3_text`, `eql_v3_integer`, …) |
| `boolean` | `boolean` | none only | `eql_v3_boolean` (storage-only — any index errors) |
| `json` | `json` | `ste_vec` (required, `compat` mode) | `eql_v3_json_search` |

Notes:

- The richest matching domain wins, and it must cover every configured
  capability — a combination that would silently drop a term errors instead
  (e.g. `unique` + `match` or `ore` + `match` on text: no single domain
  carries those term sets, so add the missing index to reach a search
  domain or split the capabilities across columns. Scalar-only configurations
  may use `eqlVersion: 2`; configurations containing `ste_vec` require v3.
- The two text search domains differ only in the ordering term they carry:
  `eql_v3_text_search_ore` carries `ob` (ORE), `eql_v3_text_search` carries
  `op` (OPE). Configuring both `ore` and `ope` selects the ORE one.
- Exception: dropping a *term* is fine when the *capability* survives.
  Non-text ordering domains carry only `ob`, so `unique` + `ore` on a
  numeric column drops `hm` — equality still works via the ORE operators.
- Ordered text requires a `unique` index (`eql_v3_text_ord_ore` /
  `eql_v3_text_ord_ope` carry `hm` + `ob`/`op`); `ore`-only text errors.
- A `json` column's `ste_vec` index must use the `compat` mode (the
  `cipherstash-client` default since 0.40.0). v3 orders SteVec entries by
  the CLLW-OPE `op` term; a `standard`-mode index emits CLLW-ORE `oc`, which
  has no mechanical conversion, so such a column errors at config time.
- Configurations containing `ste_vec` default to EQL v3. Explicit
  `eqlVersion: 2` is rejected because client 0.42 cannot represent the new
  selector-bound SteVec envelope in the v2 wire format.
- `decrypt` accepts **both** formats regardless of `eqlVersion`, so v2 and
  v3 data can coexist during a migration.
- v3 query encryption returns index-terms-only operands: scalar queries
  produce the column domain's query twin (`{v, i, <terms>}`, no `c`
  ciphertext) — bind with `col = $1::jsonb::eql_v3.query_<name>` (or the
  ordering operators, or `@@` for match). The operand always carries ALL the
  column domain's terms, whichever `indexType` was queried. JSON
  containment queries produce the `eql_v3.query_json` needle, and
  `ste_vec_selector` queries return the bare selector hash (a string) for
  the `->` / `->>` operators. Exact JSON equality at a path uses
  `ste_vec_value_selector` with `{path, value}` and returns a one-entry
  selector-only containment needle suitable for the GIN-backed `@>` operator.
- `ope`-indexed columns map to `<family>_ord_ope` and carry the `op`
  (CLLW-OPE) term (emitted since cipherstash-client 0.38.1).

> [!NOTE]
> **Breaking TypeScript change:** `encrypt`/`encryptBulk` now return
> `EncryptedPayload` (`Encrypted | EncryptedV3`) instead of `Encrypted`.
> Runtime output is unchanged for v2 clients, but code that accessed `.k`
> or assigned the result to `Encrypted` must narrow first. v3 scalars carry
> no `k`, so guard its presence before reading it:
> `'k' in payload && payload.k === 'ct'` (a v2 scalar), or check
> `payload.v === 3` to detect the v3 members. (A bare `payload.k === 'ct'`
> does not compile against the union.)

## BigInt plaintexts

Encrypted `cast_as: 'bigint'` columns store signed 64-bit integers
(PostgreSQL `bigint`). `encrypt` / `encryptBulk` / `encryptQuery` /
`encryptQueryBulk` accept the plaintext as either a JS `number` or a JS
`bigint`:

- `bigint` inputs are exact and bounds-checked against the full i64 range:
  **-9223372036854775808 to 9223372036854775807** (-2^63 to 2^63 - 1).
  Values outside that range throw a `RangeError` naming the bounds and the
  offending direction. It carries no `code` — this is a boundary check in JS,
  not one of the Rust errors described under [Errors](#errors). Search index
  terms (`hm`, `ob`, `op`) are derived from the same value, so the boundary
  check covers index-term generation too.
- `number` inputs keep the existing exact-integer guard: fractional,
  non-finite, or out-of-range values error instead of being silently
  truncated.
- A `bigint` is only accepted as the top-level plaintext of a scalar
  column. JSON has no bigint, so bigints nested inside `cast_as: 'json'`
  documents (or JSON containment query terms) are rejected with a
  `TypeError` on both Neon and wasm. More generally, plaintexts follow
  `JSON.stringify` semantics on both platforms: `toJSON` is honored (a
  `Date` becomes its ISO string), `undefined` properties are dropped, and
  non-finite numbers become `null`.
- The internal wire form `{"__protect_ffi_bigint__": "<digits>"}` is
  reserved: a `cast_as: 'json'` plaintext consisting of exactly that
  single-key shape (with an in-range i64 decimal string) is read as a
  bigint at the boundary and rejected for json columns. Nested
  occurrences of the key inside a larger document are unaffected.

```js
const ciphertext = await addon.encrypt(client, {
  plaintext: 9007199254740993n, // beyond Number.MAX_SAFE_INTEGER — stays exact
  column: 'score',
  table: 'users',
})
const decrypted = await addon.decrypt(client, { ciphertext })
// decrypted === 9007199254740993n (a JS bigint)
```

> [!WARNING]
> **Breaking change:** `decrypt` / `decryptBulk` / `decryptBulkFallible`
> now ALWAYS return a JS `bigint` for `cast_as: 'bigint'` columns — even
> for values that fit in a JS number. Previous releases returned a
> `number`, silently losing precision beyond `Number.MAX_SAFE_INTEGER`
> (2^53 - 1). Code comparing or doing arithmetic on decrypted bigint
> columns must be updated (e.g. `decrypted === 123n` instead of
> `decrypted === 123`, or `Number(decrypted)` when the value is known to
> be small).

## Errors

Both entries throw an ordinary JS `Error` with a stable `code`, set in Rust
from the error variant. There is no wrapper class and nothing to unwrap.

Not every failure has a code — the ones wrapping a cipherstash-client error
arrive without the field. `'UNKNOWN'` is the name for that case, not a value
Rust emits.

TypeScript types a `catch` variable as `unknown`, so you narrow once. That
needs nothing from this package:

```typescript
try {
  await addon.encryptQuery(client, opts)
} catch (err) {
  if (err instanceof Error && 'code' in err && err.code === 'INVALID_JSON_PATH') {
    // handle JSON path mistakes
  }
  throw err
}
```

To carry the code around as a typed value, use `isProtectErrorCode`. Checking
the value rather than the field's presence matters: Node sets `code` on its own
errors, so a bare `err?.code` read would let an `ECONNRESET` pass for one of
these.

```typescript
import {
  isProtectErrorCode,
  type ProtectErrorCode,
} from '@cipherstash/protect-ffi'

function errorCode(err: unknown): ProtectErrorCode | undefined {
  const { code } = err as { code?: unknown }
  return isProtectErrorCode(code) ? code : undefined
}
```

The codes themselves are `PROTECT_ERROR_CODES` in `src/errors.ts`, which
`src/errorCodes.test.ts` checks against the `#[diagnostic(code(..))]`
attributes on `Error` in `crates/protect-ffi/src/lib.rs` — the one place a code
is decided.

## Available Scripts

In the project directory, you can run:

#### `npm run build`

Builds the Node addon (`index.node`) from source, generating a release build with `cargo --release`.

Additional [`cargo build`](https://doc.rust-lang.org/cargo/commands/cargo-build.html) arguments may be passed to `npm run build` and similar commands. For example, to enable a [cargo feature](https://doc.rust-lang.org/cargo/reference/features.html):

```
npm run build -- --feature=beetle
```

#### `npm run debug`

Similar to `npm run build` but generates a debug build with `cargo`.

#### `npm run cross`

Similar to `npm run build` but uses [cross-rs](https://github.com/cross-rs/cross) to cross-compile for another platform. Use the [`CARGO_BUILD_TARGET`](https://doc.rust-lang.org/cargo/reference/config.html#buildtarget) environment variable to select the build target.

#### `npm run release`

Initiate a full build and publication of a new patch release of this library via GitHub Actions.

#### `npm run dryrun`

Initiate a dry run of a patch release of this library via GitHub Actions. This performs a full build but does not publish the final result.

#### `npm test`

Typechecks the TypeScript and runs the unit tests (tsc + vitest), checks formatting for both languages, lints the TypeScript, and runs the Rust tests.

Note: `npm test` at project root does not run integration tests.
For integration tests, see [below](#integration-tests).

#### `mise run lint:rust`

Every Rust check CI gates on: clippy against the host target, clippy against `wasm32-unknown-unknown`, and `cargo fmt --check`. `npm test` deliberately leaves clippy out to keep the inner loop fast, so run this before pushing.

The wasm arm needs the target installed once:

```sh
rustup target add wasm32-unknown-unknown
```

`mise run fmt` fixes what the formatting check reports.

## Project Layout

The directory structure of this project is:

```
protect-ffi/
├── Cargo.toml
├── README.md
├── integration-tests/
├── lib/
├── src/
|   ├── index.mts
|   └── index.cts
├── crates/
|   └── protect-ffi/
|       └── src/
|           └── lib.rs
├── platforms/
├── docs/
├── scripts/
├── package.json
└── target/
```

| Entry                | Purpose                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `Cargo.toml`         | The Cargo [manifest file](https://doc.rust-lang.org/cargo/reference/manifest.html), which informs the `cargo` command.             |
| `README.md`          | This file.                                                                                                                         |
| `integration-tests/` | The directory containing integration tests.                                              |
| `lib/`               | The directory containing the generated output from [tsc](https://typescriptlang.org).                                              |
| `src/`               | The directory containing the TypeScript source files.                                                                              |
| `index.mts`          | Entry point for when this library is loaded via [ESM `import`](https://nodejs.org/api/esm.html#modules-ecmascript-modules) syntax. |
| `index.cts`          | Entry point for when this library is loaded via [CJS `require`](https://nodejs.org/api/modules.html#requireid).                    |
| `crates/`            | The directory tree containing the Rust source code for the project.                                                                |
| `lib.rs`             | Entry point for the Rust source code.                                                                                              |
| `platforms/`         | The directory containing distributions of the binary addon backend for each platform supported by this library.                    |
| `docs/`              | JSONB integration docs and migration notes.                                                                        |
| `scripts/`           | Build helper scripts (e.g. WASM inlining).                                                                         |
| `package.json`       | The npm [manifest file](https://docs.npmjs.com/cli/v7/configuring-npm/package-json), which informs the `npm` command.              |
| `target/`            | Binary artifacts generated by the Rust build.                                                                                      |

## Integration tests

Integration tests live in the `./integration-tests` directory.
These tests use the local build of Rust and JavaScript artifacts to test `@cipherstash/protect-ffi` as API consumers would.

These tests rely on:

- CipherStash to be configured (via `.toml` config or environment variables), and
- Environment variables for Postgres to be set

Example environment variables:
```
CS_CLIENT_ID=
CS_CLIENT_KEY=
# The integration tests read CS_CLIENT_ACCESS_KEY; the library itself reads CS_ACCESS_KEY
CS_CLIENT_ACCESS_KEY=
CS_WORKSPACE_CRN=
# Must match the port used by the integration-test setup (mise.toml)
PGPORT=5436
PGDATABASE=cipherstash
PGUSER=cipherstash
PGPASSWORD=password
PGHOST=localhost
```

To run integration tests:
```sh
mise setup
mise test:integration
```

You can also run the integration tests in "watch" mode:

```sh
mise test:integration --watch
```

By default lock context tests are not included because invalid lock contexts fire security warnings in ZeroKMS.
To include these, run:

```sh
mise test:integration:all
```

## Releasing

Releases are handled by GitHub Actions using a `workflow_dispatch` event trigger.
The [release workflow](./.github/workflows/release.yml) was generated by [Neon](https://neon-rs.dev/).

The release workflow is responsible for:

- Building and publishing the main `@cipherstash/protect-ffi` package as well as the native packages for each platform (e.g. `@cipherstash/protect-ffi-darwin-arm64`).
- Creating the GitHub release.
- Creating a Git tag for the version.

To perform a release:

1. Navigate to the ["Release" workflow page](https://github.com/cipherstash/protectjs-ffi/actions/workflows/release.yml) in GitHub.
1. Click on "Run workflow".
1. Select the branch to release from.
   Use the default of `main` unless you want to do a pre-release version or dry run from a branch.
1. Select whether or not to do a dry run.
   Dry runs are useful for verifying that the build will succeed for all platforms before doing a full run with a publish.
1. Choose a version to publish.
   The options are similar to [`npm version`](https://docs.npmjs.com/cli/v11/commands/npm-version).
   Select "custom" in the dropdown and fill in the "Custom version" text box if you want to use a semver string instead of the shorthand (patch, minor, major, etc.).
1. Click "Run workflow".

Release notes and the changelog are automated. Add notes for your changes under the
`[Unreleased]` heading in [`CHANGELOG.md`](./CHANGELOG.md). On release, the `version`
npm lifecycle hook promotes that section to a dated release entry
(`scripts/changelog-release.mjs`), and the workflow publishes the promoted section as
the GitHub release notes (`scripts/changelog-extract.mjs`).

## Learn More

Learn more about:

- [Neon](https://neon-bindings.com).
- [Rust](https://www.rust-lang.org).
- [Node](https://nodejs.org).
