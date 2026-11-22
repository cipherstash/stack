# `@cipherstash/recipher`: the TypeScript SDK on Stack Encrypt

Date: 2026-11-22. Status: proposed. Nothing in this plan is built.

This plan says how to build `@cipherstash/recipher`, the TypeScript SDK on
the Stack Encrypt engine (`packages/stack-encrypt`), and how the Drizzle,
Supabase and Prisma Next adapters move onto it. It follows the
[SDK design principles](../sdk-design-principles.md) and the
[language integration guide](../../packages/stack-encrypt/docs/language-integration.md).
The Go SDK (`languages/golang/encrypt`) is the reference for what an SDK does.
The Python SDK (PR #1284) is the nearest example of a native binding.

The engine crate, `stack-encrypt`, is to be renamed `recipher`. This plan
uses the current name. The Rust crates of the TypeScript SDK are named
`recipher-js`, so they never share the engine's name; the npm package is
`@cipherstash/recipher`.

## Contents

- [What it is](#what-it-is)
- [Scope](#scope)
- [Before starting](#before-starting)
- [Packages and build targets](#packages-and-build-targets)
- [The declaration](#the-declaration)
- [Operations](#operations)
- [Values](#values)
- [Credentials, keysets and audit metadata](#credentials-keysets-and-audit-metadata)
- [Errors](#errors)
- [Plaintext hygiene](#plaintext-hygiene)
- [Promises and cancellation](#promises-and-cancellation)
- [The adapters](#the-adapters)
- [Room for EQL v3 and v2](#room-for-eql-v3-and-v2)
- [Tests](#tests)
- [Packaging and release](#packaging-and-release)
- [Documentation and skills](#documentation-and-skills)
- [Order of work](#order-of-work)
- [Decisions needed](#decisions-needed)
- [What was checked](#what-was-checked)

## What it is

A TypeScript program declares its encrypted tables in TypeScript. It
encrypts rows into EQL v4 values, builds query terms for them, and decrypts
them again. The compiler refuses a query that a column cannot answer and a
value of the wrong type.

The engine does all the work. The SDK sends a declaration and values across
a native binding, and the engine returns stored rows, terms and values. The
bytes are the same as Go's and Rust's for the same declaration, because they
run the same code.

It runs in two places:

- **Node.js**, through a native extension built with napi-rs.
- **Edge runtimes and browsers**, through the same Rust code built for
  `wasm32-unknown-unknown` with `wasm-bindgen`.

It does not use the WASI guest that the Go SDK uses.

## Scope

In scope:

- EQL v4 only. The SDK writes and reads EQL v4 values. It does not read EQL
  v3 values or anything `cipherstash-client` wrote.
- Every EQL v4 type the engine produces, including `JsonSearch` documents.
- Encrypt, query and decrypt, with scopes, bindings, nulls, credentials,
  keysets and audit metadata.
- Every profile of `conformance/stack-encrypt`.
- The Drizzle, Supabase and Prisma Next adapters, moved onto
  `@cipherstash/recipher` in a new major version each.

Not in scope:

- A change to a declaration over time. The principles leave it undecided.
- EQL v3 and v2. A separate crate, `recipher-compat`, is planned to read
  and write them. This plan does not design it, but leaves room for it:
  see [Room for EQL v3 and v2](#room-for-eql-v3-and-v2).

## Before starting

These issues in the milestone *Stable Stack Encrypt Rust release* change
what a binding calls or sends. A binding written before them is rewritten
after them.

Before step 1:

- **#1669**: `dynamic::record::encrypt_with` and `decrypt_with` become
  `Planned` or private, so `Planned` is the one way in.
- **#1663**: remove `Label` and `IntoLabel`. A decrypt's expected context
  takes a `Label` today.
- **#1489**: apply the naming review (`StackCipher` becomes `Cipher`,
  `stack-kms` becomes `stack-zerokms`, and the rest). Every name the
  extension uses is on that list.
- **#1594**: what a binding sends is a serialised `Planned`, and the
  conformance corpus is written as one. The extension calls `Planned`
  directly, but its conformance runners read the corpus.

Before step 2 (the declaration):

- **#1672**: a field's indexes become the closed `FieldIndexes` shape.
- **#1673**: match options become one analyzer pipeline. Both change what
  the declaration builder writes.
- **#1678**: JSON Schemas and a protocol version for the plan and the
  messages. The TypeScript types for a plan can then be generated from the
  schemas, not written by hand.

Before the first release, because they change stored bytes or the
compatibility promise:

- **#1566** (scopes and bindings as key request items) and **#1567**
  (labels in EQL payloads).
- **#1398** and **#1399** (match index text filters), which change match
  terms.
- **#1490** (stable gates and conformance versions) and **#1314**
  (the compatibility policy).

The rest of the milestone does not block this plan. The Go-only issues,
the internal ones (#1458, #1676, #1670, #1671, #1063, #1684) and the typed
Rust ones (#1668, #1569, #1570) do not change a binding. #1572 and #1683
add features the SDK picks up later. #1479 (the TypeScript conformance
runner) is part of this plan. #561 and #1565 are answered by this design.

## Packages and build targets

The Python SDK splits its Rust code in two: a core crate with the logic and
a thin crate that converts at the boundary. This SDK does the same, with one
thin crate for each build target.

| Path | Name | What it is |
|---|---|---|
| `languages/typescript/packages/recipher-js/crates/core` | crate `recipher-js` | Rust, no JavaScript types. Builds plans, runs operations through `dynamic::Planned`, maps errors. Depends on `stack-encrypt` (`dynamic`) and `eql-bindings` (`targets`) by path. |
| `languages/typescript/packages/recipher-js/crates/node` | crate `recipher-js-node` | Rust, napi-rs. Converts between JavaScript values and frames, and exposes the core as a Node addon. |
| `languages/typescript/packages/recipher-js/crates/wasm` | crate `recipher-js-wasm` | Rust, `wasm-bindgen`, for `wasm32-unknown-unknown`. The same conversions over `JsValue`. |
| `languages/typescript/packages/recipher-js` | npm `@cipherstash/recipher` | The TypeScript SDK, its types and the loaders. |
| `languages/typescript/packages/recipher-js/platforms/*` | npm `@cipherstash/recipher-<platform>` | One package per Node platform, holding its `.node` file. |

The npm package picks its binding by export condition, as
`@cipherstash/auth` does:

- `node` loads the napi addon for the platform.
- `default` loads the wasm build, as a separate `.wasm` file.
- `./wasm-inline` loads the wasm build inlined into the JavaScript, for
  bundlers and edge runtimes that cannot load a second file.

The six platforms are the ones `@cipherstash/auth` ships: `darwin-arm64`,
`darwin-x64`, `linux-arm64-gnu`, `linux-x64-gnu`, `linux-x64-musl` and
`win32-x64-msvc`.

The cargo workspace is detached, with its own `Cargo.lock`, as Python's is.
The package's `build` and `test` scripts never run cargo, so root
`pnpm test` needs no Rust toolchain; `build:native`, `build:wasm` and
`test:cargo` do. This is the rule protect-ffi and `@cipherstash/auth` follow.

## The declaration

A table is declared with a builder and the EQL v4 type of each column. The
type names are the EQL catalog's.

```ts
import { encryptedTable, types } from "@cipherstash/recipher";

export const users = encryptedTable("users", {
  id: types.passthrough<bigint>(),
  email: types.TextEq(),
  name: types.TextMatch(),
  age: types.IntegerEq({ null: "sealed" }),
  profile: types.JsonSearch({ ordered: ["$.score"] }),
});
```

- **The types come from the EQL catalog.** `eql-codegen` writes the Go
  types today (`go_eql.rs` writes `languages/golang/encrypt/eql/eql_gen.go`).
  It gains a TypeScript writer, which writes each type's plaintext type, its
  operators and its options. A drift check fails CI when the file is stale,
  as `types:check` does for Go.
- **The compiler checks the model.** `Plaintext<typeof users>` is
  `{ id: bigint; email: string; name: string; age: number | null; profile: Json }`.
  A row of another shape does not compile.
- **The compiler checks queries.** A query on `age` with `matches` does not
  compile, because `IntegerEq` has no match operator. The operators come
  from the generated catalog. A test asks the engine
  (`dynamic::field_operators`) for each type's operators and compares them
  with the generated file.
- **The engine checks the declaration when the client starts.** The SDK
  turns each table into a plan once, in Rust (`record::plan_with` with the
  EQL resolver), when the client is built. A refusal names the table, the
  column and the reason. A `checkDeclarations()` function runs the same
  check with no credentials, for a test or a CI step.
- **The user never sees the plan.** The plan's frame is written in Rust from
  the declaration. TypeScript writes no frame.
- **Context.** The table name and the column name are the column's label, as
  in Go. A table whose tenant is in each row declares its context field with
  `contextField: "tenant"`.
- **A declaration is plain data.** An adapter reads a table's name, its
  columns and each column's type from the declaration object, so it can
  build its own column objects from it, or check its own against it.

## Operations

Every operation runs through `dynamic::Planned` in the core crate. A column
is named by its table declaration and its name. Drizzle, Supabase.js and
Prisma Next each have their own column objects, and each already maps them
to the encryption client by table and column name. So this is the one way
to name a column, and the compiler checks the name, the operator and the
value against the declaration.

```ts
const client = await Recipher.create({ tables: [users] });

// Rows: always a batch, one ZeroKMS request.
const stored = await client.encrypt(users, rows);
const decrypted = await client.decrypt(users, stored);

// One column, for an update of that column or an adapter that encrypts
// column by column: still a batch of values.
const emails = await client.encryptColumn(users, "email", ["ada@example.com"]);

// Query terms: a batch, which may span columns.
const [byEmail, byAge] = await client.query(users, [
  { column: "email", op: "eq", value: "ada@example.com" },
  { column: "age", op: "eq", value: 36 },
]);
```

- **Batch by default.** Every call takes a batch and makes at most one key
  request. A one-column call is the exception the principles allow, and is
  still a batch of values.
- **The stored row is EQL v4 JSON per column**, ready for a SQL parameter.
  A query term carries the SQL domain it binds as (`term.domain`), as the
  engine's `QueryTerm` does, so an adapter writes the cast without a table
  of its own.
- **Scopes and bindings** are part of a call:
  `client.encrypt(users, rows).scope(tenantId).bind(rowIds)` and
  `client.query(users, terms).scope(tenantId)`. A query has no `bind`
  method, so a query with a binding does not compile.
- **Probabilistic queries.** A match term comes with `targetLimit` and
  `verify`, which call `dynamic::target_limit` and `dynamic::verify`.
- **JSON documents.** A `JsonSearch` column has its document operators:
  `contains`, `contained_by`, the comparisons at a path, `element_match`,
  `match`, and the reads `selector`, `subtree`, `children` and
  `child_count`. A read's rows open through `client.openJson(..)`, over
  `dynamic::json_open`.

Each call returns a builder. Awaiting it runs it. `.scope`, `.bind`,
`.audit`, `.withCredential` and `.signal` come before the `await`.

## Values

The native crate converts each JavaScript value straight into a frame, by
the column's declared kind, with `ValueFrame::of` over a type that
describes itself to vitaminc. Python's `Typed` does the same. No JSON text
of a row crosses the boundary.

| EQL kind | TypeScript type | Rule |
|---|---|---|
| text | `string` | |
| boolean | `boolean` | |
| int16, int32 | `number` | A safe integer in range, else refused |
| int64, uint64, int128 | `bigint` | A `number` is refused, so no 64-bit value passes through a double |
| real, double | `number` | |
| decimal | `string` | Decimal text, parsed in Rust |
| date | see [Decisions needed](#decisions-needed) | |
| timestamp | see [Decisions needed](#decisions-needed) | |
| bytes | `Uint8Array` | |
| json | any JSON value | Written to JSON text in Rust, then parsed by the engine's one parser |
| null | `null` | Only where the column declares `null` |

The value profile of the conformance suite (`record-values-v1`) is the
contract for this table. Its cases include every kind at its edges and the
conversions the host refuses.

## Credentials, keysets and audit metadata

- **Credentials.** The client finds credentials as every SDK does: the
  `CS_*` variables, then the profile that `stash auth login` writes. On
  Node, `stack-kms`'s profile store reads the file. The wasm build has no
  file system, so its credentials come from the variables or the client's
  options.
- **A credential with each call.** A client built over a strategy that
  takes a credential with each call, such as OIDC federation, has a
  different type. Its calls return a builder that cannot be awaited until
  `.withCredential(jwt)` is called. Forgetting it is a type error, as it is
  a compile error in Rust. The JWT is read in the caller's request, which is
  what #1565 asks of `@cipherstash/stack`.
- **Keysets.** `client.keyset(name)` returns a client bound to that keyset.
  Decrypting through the client opens a value from any of its keysets;
  decrypting through a keyset refuses a value from another.
- **Audit metadata.** `.audit({ ... })` on `encrypt`, `encryptColumn`,
  `decrypt` and `openJson`. A date and time in it is sent as RFC 3339 text
  in UTC, the form every SDK sends. A query has no data-key request, so it
  has no `.audit`.

## Errors

Every failure is a `RecipherError` with `code`, `reason` and `field` from
the engine's error. Subclasses name the failures a caller acts on
differently: a refused declaration, a value of the wrong type, a refused
credential, a ZeroKMS refusal, a foreign keyset, a context mismatch and a
value that did not open. No message, property or `toString()` holds a
plaintext, a key, a token, a ciphertext or a context value. A decrypted
row's `inspect` output names its columns and hides their values, as Go's
`Redacted` does.

## Plaintext hygiene

A JavaScript string cannot be wiped. The SDK keeps the number of copies
down instead:

- The native crate reads a JavaScript value into a frame, which lives in a
  buffer wiped when it drops. No intermediate Rust `String` or JSON text
  holds the row.
- A decrypted frame is converted straight into JavaScript values.
- The wasm build follows the same rules, and its linear memory holds no
  plaintext after a call returns.

A heap-hygiene test in the native crate runs each operation under the
watching allocator of `packages/stack-encrypt/tests/heap_hygiene.rs`, as
the Python engine crate does. The plaintext the JavaScript engine holds is
outside what any test can check, and the README says so.

## Promises and cancellation

- Every operation returns a `Promise`. napi-rs runs the engine's future on
  its tokio runtime. The wasm build runs it through `wasm-bindgen-futures`,
  and ZeroKMS requests go out through the runtime's `fetch`.
- A call takes an `AbortSignal`. Aborting drops the future, which wipes what
  it held, and rejects with the signal's reason. Only that call fails; the
  client goes on serving others. The Go SDK's cancellation tests
  (`languages/golang/encrypt/cancel_test.go`) are the list of cases.

## The adapters

`@cipherstash/stack-drizzle`, `@cipherstash/stack-supabase` and
`@cipherstash/stack-prisma` move onto `@cipherstash/recipher`. Each takes a
new major version that depends on it and drops `@cipherstash/stack`.

- **Columns.** Each adapter maps its own column objects to a recipher table
  and column name, as each does today: Drizzle by its column builder's
  table and name, Supabase.js by the table and the column string it
  filters on, and Prisma Next by its routing key.
- **Batches.** Drizzle's batched query terms map to `client.query`.
  Supabase's model encryption maps to `client.encrypt` and
  `client.decrypt`. Prisma Next's middleware encrypts column by column,
  which maps to `client.encryptColumn`.
- **SQL.** Each adapter writes EQL v3 SQL today: `eql_v3` operators and
  casts, and Prisma Next's baseline migration installs the v3 bundle. Each
  moves to the EQL v4 functions and query domains, taking the cast from the
  query term's `domain`.
- **Installing EQL v4.** `@cipherstash/eql` ships the v3 bundle, and
  `stash eql install` installs it. Both need the v4 bundle before an
  adapter can move. That is its own piece of work, in the CLI and in
  `packages/eql`, and step 11 depends on it.
- **Supabase.js.** The v3 adapter refuses some operators because PostgREST
  cannot write the `eql_v3.query_*` cast they need. Whether PostgREST can
  write the v4 query domains is checked before the Supabase step; the
  answer decides which operators the new major offers.
- **DynamoDB.** `@cipherstash/stack/dynamodb` is a subpath of
  `@cipherstash/stack`, not an adapter package. It moves to
  `@cipherstash/recipher/dynamodb`, or stays; see
  [Decisions needed](#decisions-needed).
- **Skills.** `skills/stash-drizzle`, `stash-supabase`, `stash-prisma`,
  `stash-dynamodb`, `stash-encryption` and `stash-indexing` change with
  their adapters, in the same pull requests.

## Room for EQL v3 and v2

`recipher-compat` is planned to read and write EQL v3 and v2 on the same
engine. When it exists, `@cipherstash/recipher` should take it on without
a new call shape. So this plan holds to three rules:

- **The EQL version is in the column's type, never in a call.** A
  declaration names an EQL v4 type from the catalog. A v3 type would be
  another type in the same declaration, through the same `encrypt`,
  `query` and `decrypt`.
- **The core crate passes the EQL resolver in one place.** The resolver
  that runs a named type is built once, in `recipher-js`, so a resolver
  that also knows the v3 and v2 types replaces it there.
- **Nothing outside the generated catalog knows a type's version.** Query
  terms carry their SQL domain, and adapters write casts from it, so an
  adapter does not branch on the version.

These rules are checked when `recipher-compat` is designed, not before.

## Tests

- **Conformance.** A Vitest runner for every profile in
  `conformance/stack-encrypt/v1`, against both the napi build and the wasm
  build (#1479). The exchange profile enrols TypeScript in
  `scripts/stack-exchange-conformance.mjs`, so TypeScript opens what Rust
  and Go wrote in the same run, and they open what TypeScript wrote.
- **A frozen stored-rows file.** Rows the first release wrote, opened on
  every build and never regenerated.
- **Value conversion.** The value profile, plus a fuzz target that converts
  a host value to a frame and compares it with `ValueFrame::of` for the same
  value.
- **Type tests.** A wrong row, a wrong value, an unknown column and an
  operator a column cannot answer do not compile.
- **Edge runtime.** The wasm build runs one encrypt, query and decrypt
  under an edge runtime in CI (Miniflare or `workerd`).
- **Live.** One credentialed round trip against ZeroKMS and PostgreSQL with
  EQL v4 installed, in a path-filtered workflow like the other
  `integration-*.yml` jobs. Each adapter's live suite moves to EQL v4 with
  its major.

## Packaging and release

The package follows `@cipherstash/auth`:

- `release.yml` builds the six platform addons and the wasm build, and
  publishes the platform packages before the wrapper, as `publish-auth`
  does. npm trusted publishing is set up for each package, bound to
  `release.yml`.
- Each package gets a changeset like any other workspace package.
- The crates depend on `stack-encrypt` and `eql-bindings` by path, so one
  release carries the engine of its own commit. The package names that
  commit in an `engineCommit` export.

## Documentation and skills

- A README that starts with the steps to a working round trip, tested in
  CI, as Python's is.
- A skill under `skills/` for `@cipherstash/recipher` once it is
  published, since skills ship to customers.
- `AGENTS.md` (repository layout) and `SECURITY.md` (package list) gain the
  package in the pull request that adds it.

## Order of work

Each step is one pull request, and each ends with its tests passing in CI.

1. **Walking skeleton.** The three crates and the npm package. One
   hand-written table, `encrypt` and `decrypt` of one `TextEq` column on
   Node, through `Planned`. CI builds it on Linux. Proves that the engine's
   futures run on napi-rs's runtime.
2. **The catalog in TypeScript.** The `eql-codegen` writer, its drift
   check, `encryptedTable` and `types`, and the type tests.
3. **Values.** The conversion table above, the value profile and the fuzz
   target.
4. **Queries.** Every scalar operator, `encryptColumn`, match `verify` and
   `targetLimit`, and the query-refusal profile.
5. **Context.** Scopes, bindings, context fields and nulls, with the
   context, bindings and runtime profiles.
6. **Credentials, keysets, audit metadata and cancellation.** The
   per-call credential type and the lifecycle profile.
7. **JSON documents.** `JsonSearch` and the EQL/JSON profile.
8. **The wasm build.** The `wasm-bindgen` crate, the export conditions, the
   inlined build and the edge-runtime test.
9. **Exchange and stored rows.** The exchange enrolment and the frozen
   stored-rows file.
10. **Release.** The platform packages, the release jobs, the README and
    the skill.
11. **The adapters.** Drizzle, then Prisma Next, then Supabase, each a
    major version in its own pull request, after EQL v4 installs through
    `stash eql install`.

## Decisions needed

1. **Data the current adapters wrote.** The new majors read EQL v4 only
   until `recipher-compat` exists. Until then, a customer with rows the
   current majors wrote stays on those majors. Whether the new majors wait
   for `recipher-compat`, or ship first and gain v3 support later, is a
   product decision.
2. **Dates and times.** A JavaScript `Date` has millisecond precision; the
   engine's timestamp has nanosecond precision. `Temporal` is the newer
   standard date and time API with nanosecond instants and plain dates. It
   is not in Safari yet. The choices are `Date`, `Temporal` with a
   fallback, or strings.
3. **DynamoDB.** Whether `@cipherstash/stack/dynamodb` moves to
   `@cipherstash/recipher/dynamodb`.

## What was checked

Run on 2026-11-22, on `next` at `38db57856`:

- `cargo check --target wasm32-unknown-unknown -p stack-encrypt --features dynamic`:
  passes.
- `cargo check --manifest-path packages/eql/Cargo.toml -p eql-bindings --features targets --target wasm32-unknown-unknown`:
  passes.
- `stack-kms`'s HTTP connection on `wasm32` uses reqwest's `fetch` backend
  (read in `packages/stack-kms/src/connection/http.rs`).
- `@cipherstash/auth` uses napi-rs 2 with napi's tokio runtime, and a
  `wasm-bindgen` sibling crate (`stack-auth-wasm`), chosen by the `node` and
  `default` export conditions (read in their `Cargo.toml` and
  `package.json`).
- The adapters name columns by table and column name: Drizzle passes
  `{ table, column }` to `encryptQuery` (`stack-drizzle/src/operators.ts`),
  Supabase passes the table and column strings
  (`stack-supabase/src/query-encrypt.ts`), and Prisma Next passes a
  routing key per column (`stack-prisma/src/execution/sdk.ts`).
- The CLI's installer and `@cipherstash/eql` carry no EQL v4 bundle
  (searched `languages/typescript/packages/cli/src` and
  `packages/eql/packages/eql/src`).
- `dynamic::Planned`, `Plan::query`, `Plan::field`, `QueryTerm::domain` and
  the per-call credential exist on `next` and are covered by their
  doctests.

Not checked:

- That a `Pending` from a `Planned` call is `Send`, as napi-rs's async
  functions need. Step 1 proves it or finds the change the engine needs.
- The size of the wasm build with the EQL types in it.
- napi-rs addons under Bun and Deno.
- Whether PostgREST can write the EQL v4 query domains.
