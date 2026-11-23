# `@cipherstash/recipher`: the TypeScript SDK on Stack Encrypt

Date: 2026-11-22. Revised 2026-11-23: the SDK is a general-purpose core
with EQL as an extension, and the work is in three phases. Status:
proposed. Nothing in this plan is built.

This plan says how to build the TypeScript SDK on the Stack Encrypt engine
(`packages/stack-encrypt`). It is two npm packages:

- `@cipherstash/recipher`, the core. It encrypts values, files, whole
  objects and records, and derives search terms. It knows nothing about a
  database.
- `@cipherstash/recipher-eql`, an extension. It adds the EQL v4 types, so
  a record's fields can be stored in PostgreSQL columns and queried there.

The split is the one Rust has: `stack-encrypt` is the engine, and
`eql-bindings` adds the EQL types to it. The plan also says how the
Drizzle, Supabase and Prisma Next adapters move onto the two packages.

It follows the [SDK design principles](../sdk-design-principles.md). The
engine's own documentation (`packages/stack-encrypt/src/lib.rs`) sets the
order: a value first, then a whole object, then a record, then search
terms. A database comes last, through EQL. The Go SDK
(`languages/golang/encrypt`, with `encrypt/eql`) is the reference for what
an SDK does. The Python SDK (PR #1284) is the nearest example of a native
binding.

The engine crate, `stack-encrypt`, is to be renamed `recipher`. This plan
uses the current name. The Rust crates of the TypeScript SDK are named
`recipher-js`, so they never share the engine's name.

## Contents

- [What it is](#what-it-is)
- [Scope](#scope)
- [Phases](#phases)
- [Packages and build targets](#packages-and-build-targets)
- [The core](#the-core)
- [Values](#values)
- [The EQL extension](#the-eql-extension)
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

A TypeScript program declares what it encrypts, in TypeScript. It encrypts
values, builds search terms for them, and decrypts them again. The
compiler refuses a value of the wrong type and a query that a field cannot
answer.

The core is enough for a program that keeps its ciphertext anywhere: a
file, an object store, a key-value store, or a database column of bytes.
A program that wants PostgreSQL to compare encrypted values adds the EQL
extension.

The engine does all the work. The SDK sends a declaration and values across
a native binding, and the engine returns ciphertexts, terms and values. The
bytes are the same as Go's and Rust's for the same declaration, because they
run the same code.

It runs in two places:

- **Node.js**, through a native extension built with napi-rs.
- **Edge runtimes and browsers**, through the same Rust code built for
  `wasm32-unknown-unknown` with `wasm-bindgen`.

It does not use the WASI guest that the Go SDK uses.

## Scope

In scope, for the core:

- A value, a file and a whole object, each as one ciphertext.
- A record: fields that are encrypted, indexed or passed through.
- The engine's indexes (`equality`, `match`, `ore`, `ope`) and the query
  terms for them.
- Scopes, bindings, nulls, credentials, keysets and audit metadata.
- Every profile of `conformance/stack-encrypt` that needs no EQL type.

In scope, for the EQL extension:

- EQL v4 only. The extension writes and reads EQL v4 values. It does not
  read EQL v3 values or anything `cipherstash-client` wrote.
- Every EQL v4 type the engine produces, including `JsonSearch` documents.
- The EQL/JSON profile, and the EQL rows of the exchange profile.

In scope, after both:

- The Drizzle, Supabase and Prisma Next adapters, moved onto the two
  packages in a new major version each.

Not in scope:

- A change to a declaration over time. The principles leave it undecided.
- Streaming. A file is encrypted in memory, as one value.
- EQL v3 and v2. A separate crate, `recipher-compat`, is planned to read
  and write them. This plan does not design it, but leaves room for it:
  see [Room for EQL v3 and v2](#room-for-eql-v3-and-v2).

## Phases

The engine issues this plan first waited for are still open, and the design
of contexts and labels is taking time. So the work is in three phases, and
the first starts now.

| Phase | Starts | What it builds |
|---|---|---|
| 1 | Now | Everything that needs no context from the caller. The core first: values, records, query terms, credentials and the wasm build. Then the EQL extension. |
| 2 | When #1663 is closed and the context design is settled | Scopes, bindings, context fields and the expected context of a decrypt. |
| 3 | When the issues that change stored bytes are closed | The first stable release, then the adapters. |

[Order of work](#order-of-work) lists the steps of each phase.

### What phase 1 leaves out

A phase 1 value is encrypted under the context its declaration names, and
nothing else. For a record field, that is the record's name and the field's
name. The caller adds no part to it. So phase 1 has no `.scope`, no
`.bind`, no context field and no expected context on a decrypt.

Three rules keep phase 1 clear of the open design:

- **The core crate does not name `Label` or `IntoLabel`.** A test fails if
  its source does. #1663 then removes them without a change here. Its
  acceptance says a context made of the same names gives the same bytes.
- **Only the core crate names an engine type.** The node crate, the wasm
  crate and the TypeScript code see the core crate's own types. A rename in
  the engine changes one crate.
- **No phase 1 build promises that a later build opens its stored values.**
  The README says so. The promise starts with the first stable release.

### Issues that are still open

Phase 1 does not wait for these. Each one changes a small, known part of
phase 1 when it lands.

| Issue | State on 2026-11-23 | What it changes here |
|---|---|---|
| #1669 (`encrypt_with` and `decrypt_with` become `Planned`) | Closed | Nothing. The core crate calls `Planned` from the first record step. |
| #1489 (the naming review) | Open | The engine names in the core crate (`StackCipher` becomes `Cipher`, `stack-kms` becomes `stack-zerokms`, and the rest). The TypeScript names already follow the review: `Cipher` and `Keyset`. |
| #1594 (a binding sends a serialised `Planned`) | Open | The conformance runners' reader of the corpus. The core crate calls `Planned` directly. |
| #1672 (the closed `FieldIndexes` shape) | Open | The one function in the core crate that writes a plan from a declaration. |
| #1673 (match options as one analyzer pipeline) | Open | The options of a `match` index. Phase 1 offers the default options only. |
| #1678 (JSON Schemas and a protocol version) | Open | Nothing in phase 1, because TypeScript writes no frame. Phase 3 checks the plan the core crate writes against the schema. |

Phase 2 waits for:

- **#1663**: remove `Label` and `IntoLabel`. A decrypt's expected context
  takes a `Label` today.
- **The context design.** How a caller's context parts are named (scope,
  binding, label) is being decided for every SDK at once. The TypeScript
  names follow that decision, so they are not written before it.

Phase 3 waits for these, because they change stored bytes or the
compatibility promise:

- **#1566** (scopes and bindings as key request items) and **#1567**
  (labels in EQL payloads).
- **#1399** (a character filter in the match index), which changes match
  terms. #1398, its pair, is closed.
- **#1490** (stable gates and conformance versions) and **#1314**
  (the compatibility policy).
- EQL v4 installable through `stash eql install`, for the adapters.

The rest of the milestone *Stable Stack Encrypt Rust release* does not
block this plan. The Go-only issues, the internal ones (#1458, #1676,
#1670, #1671, #1063, #1684) and the typed Rust ones (#1668, #1569, #1570)
do not change a binding. #1572 and #1683 add features the SDK picks up
later. #1479 (the TypeScript conformance runner) is part of this plan.
#561 and #1565 are answered by this design.

## Packages and build targets

The Python SDK splits its Rust code in two: a core crate with the logic and
a thin crate that converts at the boundary. This SDK does the same, with one
thin crate for each build target.

| Path | Name | What it is |
|---|---|---|
| `languages/typescript/packages/recipher-js/crates/core` | crate `recipher-js` | Rust, no JavaScript types. Builds plans, runs operations through the engine, maps errors. Depends on `stack-encrypt` (`dynamic`) by path. It takes the engine's `TargetResolver` as a parameter and names no EQL type. |
| `languages/typescript/packages/recipher-js/crates/node` | crate `recipher-js-node` | Rust, napi-rs. Converts between JavaScript values and frames, and exposes the core as a Node addon. |
| `languages/typescript/packages/recipher-js/crates/wasm` | crate `recipher-js-wasm` | Rust, `wasm-bindgen`, for `wasm32-unknown-unknown`. The same conversions over `JsValue`. |
| `languages/typescript/packages/recipher-js` | npm `@cipherstash/recipher` | The core SDK, its types and the loaders. Its builds hold no EQL type (`NoTargets`). |
| `languages/typescript/packages/recipher-js/platforms/*` | npm `@cipherstash/recipher-<platform>` | One package per Node platform, holding its `.node` file. |
| `languages/typescript/packages/recipher-eql` | npm `@cipherstash/recipher-eql` | The EQL extension: the EQL v4 types in TypeScript, and the builds that hold them. |
| `languages/typescript/packages/recipher-eql/platforms/*` | npm `@cipherstash/recipher-eql-<platform>` | One package per Node platform, holding the EQL build's `.node` file. |

**How the extension reaches the engine.** The engine runs a named type
through a `TargetResolver` that the host links in. `NoTargets` is the
build without one. So the node crate and the wasm crate each have a cargo
feature, `eql`, which links `eql-bindings` (`targets`) by path and passes
its resolver to the core crate. The core package ships the builds without
the feature. The EQL package ships the builds with it. This is what Go
does: `encrypt/eql` holds a second build of the guest, with the EQL types.

A cipher runs in one build. A program names its extensions when it builds
the cipher, and the cipher loads the build that holds them:

```ts
import { Cipher } from "@cipherstash/recipher";
import { eql } from "@cipherstash/recipher-eql";

const cipher = await Cipher.create({ extensions: [eql] });
```

The extension is passed as a value, not registered by an import, because a
bundler can drop an import that is used only for its side effect.
`Cipher.create` refuses an extension built from another engine commit than
the core package.

Each package picks its build by export condition, as `@cipherstash/auth`
does:

- `node` loads the napi addon for the platform.
- `default` loads the wasm build, as a separate `.wasm` file.
- `./wasm-inline` loads the wasm build inlined into the JavaScript, for
  bundlers and edge runtimes that cannot load a second file.

The six platforms are the ones `@cipherstash/auth` ships: `darwin-arm64`,
`darwin-x64`, `linux-arm64-gnu`, `linux-x64-gnu`, `linux-x64-musl` and
`win32-x64-msvc`.

The cargo workspace is detached, with its own `Cargo.lock`, as Python's is.
Each package's `build` and `test` scripts never run cargo, so root
`pnpm test` needs no Rust toolchain; `build:native`, `build:wasm` and
`test:cargo` do. This is the rule protect-ffi and `@cipherstash/auth` follow.

## The core

The core follows the engine's own order: a value, a whole object, a record,
then search terms. Nothing in this section needs a database.

### A value

```ts
import { Cipher, kinds, value } from "@cipherstash/recipher";

const cipher = await Cipher.create();
const keyset = cipher.defaultKeyset();

const note = value("notes", kinds.string);

const [sealed] = await keyset.encrypt(note, ["a secret message"]);
const [opened] = await cipher.decrypt(note, [sealed]);
```

- **A declaration, even for one value.** `value(context, kind)` says the
  context the value is encrypted under and its type. The write and the read
  take the same declaration, so they cannot name different contexts.
- **Encrypting needs a keyset; decrypting does not.** Every data key is
  made under one keyset, and a ciphertext names the keyset it was made
  under. `cipher.decrypt` opens a value from any of the cipher's keysets.
  `keyset.decrypt` refuses a value from another keyset. This is the
  engine's rule.
- **A `Ciphertext` is opaque bytes.** `ciphertext.toBytes()` gives a
  `Uint8Array` to store, and `Ciphertext.fromBytes(..)` reads one back.
  Each ciphertext has its own data key.
- **A kind is one of the engine's value kinds:** `kinds.string`,
  `kinds.int32`, `kinds.int64`, `kinds.bytes`, `kinds.json` and the rest.
  [Values](#values) lists them and the TypeScript type of each.

### A file, and a whole object

A file or a stored object is a value of kind `bytes`:

```ts
const invoice = value("invoices", kinds.bytes);
const [sealed] = await keyset.encrypt(invoice, [await readFile("invoice.pdf")]);
await writeFile("invoice.pdf.enc", sealed.toBytes());
```

A whole object is one ciphertext with `opaque`:

```ts
import { opaque } from "@cipherstash/recipher";

type Card = { number: string; expiry: { month: number; year: number } };
const card = opaque<Card>("cards");

const [sealed] = await keyset.encrypt(card, [
  { number: "4111 1111 1111 1111", expiry: { month: 4, year: 2031 } },
]);
```

`opaque` stores what the engine's `OpaqueBlob` stores, in the same format
as a Go opaque struct. Nothing inside it can be searched.

### A record

A record declares each field once. A field is encrypted, encrypted and
indexed, or passed through. The words are the engine's.

```ts
import { encrypt, kinds, passthrough, record } from "@cipherstash/recipher";

export const user = record("users", {
  id: passthrough<bigint>(),
  email: encrypt(kinds.string, { index: ["equality"] }),
  name: encrypt(kinds.string, { index: ["match"] }),
  age: encrypt(kinds.int32, { index: ["equality", "ore"] }),
  notes: encrypt(kinds.string),
});

// Rows: always a batch, one ZeroKMS request.
const stored = await keyset.encrypt(user, rows);
const opened = await cipher.decrypt(user, stored);
```

- **The stored row has one object for each sealed field**, with one
  property for each output: `ciphertext`, and `equality`, `match`, `ore`
  or `ope` for each index the field declares. Each is opaque bytes. A
  passthrough field keeps its value. This is the shape Go stores.
- **The compiler checks the row.** `Plaintext<typeof user>` is
  `{ id: bigint; email: string; name: string; age: number; notes: string }`.
  A row of another shape does not compile. `Stored<typeof user>` is the
  stored type, and `stored[0].notes.equality` does not compile.
- **The engine checks the declaration when the cipher is built.**
  `Cipher.create({ records: [user] })` turns each record into a plan once,
  in Rust. A refusal names the record, the field and the reason. A
  `checkDeclarations()` function runs the same check with no credentials,
  for a test or a CI step.
- **The user never sees the plan.** The plan's frame is written in Rust
  from the declaration. TypeScript writes no frame.
- **Context.** A field's context is the record's name and the field's
  name. Phase 2 adds scopes, bindings and a context field.
- **Nulls.** A field that can be `null` declares it, with the null modes
  the engine's `NullMode` has.
- **A declaration is plain data.** A library reads a record's name, its
  fields and each field's declaration from the object.

One field of a record, for an update of that field, is still a batch:

```ts
const emails = await keyset.encryptField(user, "email", ["ada@example.com"]);
const opened = await cipher.decryptField(user, "email", emails);
```

### Search terms

A query names a field, an operator and a value. The result is the term to
compare with the stored term.

```ts
// Query terms: a batch, which may span fields.
const [byEmail, byAge] = await keyset.query(user, [
  { field: "email", op: "eq", value: "ada@example.com" },
  { field: "age", op: "gte", value: 36 },
]);
```

- **The compiler checks queries.** A query on `name` with `eq` does not
  compile, because a `match` index answers no equality. The operators of
  each index are generated from the engine. A test asks the engine
  (`dynamic::field_operators`) and compares the answer with the generated
  file.
- **A term is opaque bytes**, byte-equal to the term Rust and Go derive.
  An equality term compares with `=`. `OreTerm.compare` orders two terms
  in TypeScript.
- **Probabilistic queries.** A match term comes with `targetLimit` and
  `verify`, which call `dynamic::target_limit` and `dynamic::verify`.
- **Match options.** A `match` index takes no options until #1673 decides
  them.

### The shape of a call

- **Batch by default.** Every call takes a batch and makes at most one key
  request. A one-field call is the exception the principles allow, and is
  still a batch of values.
- **Each call returns a builder.** Awaiting it runs it. `.audit`,
  `.withCredential` and `.signal` come before the `await`. Phase 2 adds
  `.scope` and `.bind` to the same builder, so it changes no phase 1 call.
- **Scopes and bindings** (phase 2) are part of a call:
  `keyset.encrypt(user, rows).scope(tenantId).bind(rowIds)` and
  `keyset.query(user, terms).scope(tenantId)`. A query has no `bind`
  method, so a query with a binding does not compile.

## Values

The native crate converts each JavaScript value straight into a frame, by
the declared kind, with `ValueFrame::of` over a type that describes itself
to vitaminc. Python's `Typed` does the same. No JSON text of a row crosses
the boundary.

| Kind | TypeScript type | Rule |
|---|---|---|
| string | `string` | |
| boolean | `boolean` | |
| int16, int32 | `number` | A safe integer in range, else refused |
| int64, uint64, int128 | `bigint` | A `number` is refused, so no 64-bit value passes through a double |
| real, double | `number` | |
| decimal | `string` | Decimal text, parsed in Rust |
| date | see [Decisions needed](#decisions-needed) | |
| timestamp | see [Decisions needed](#decisions-needed) | |
| bytes | `Uint8Array` | |
| json | a JSON value, with `bigint` for a large integer | See below |
| null | `null` | Only where the field declares `null` |

**JSON numbers.** A JavaScript `number` cannot hold every integer a JSON
document can. So a JSON value is a tree in which an integer outside the
safe range is a `bigint`. On encrypt, a `number` that is an unsafe integer
is refused, and a `bigint` is written as its digits. On decrypt, an integer
outside the safe range comes back as a `bigint`. The conversion is in Rust,
and the engine's one parser reads the result. The `eql-json-v1` case that
holds `18446744073709551615` round-trips on both builds.

The value profile of the conformance suite (`record-values-v1`) is the
contract for this table. Its cases include every kind at its edges and the
conversions the host refuses.

## The EQL extension

`@cipherstash/recipher-eql` adds one thing to the core: a field that is
stored as an EQL v4 type. In the engine's words, the field names a target.
In Go it is the `encrypt_into=` tag.

```ts
import { Cipher, passthrough, record } from "@cipherstash/recipher";
import { eql, types } from "@cipherstash/recipher-eql";

export const users = record("users", {
  id: passthrough<bigint>(),
  email: types.TextEq(),
  name: types.TextMatch(),
  age: types.IntegerEq({ null: "sealed" }),
  profile: types.JsonSearch({ ordered: ["$.score"] }),
});

const cipher = await Cipher.create({ extensions: [eql], records: [users] });
const keyset = cipher.defaultKeyset();

const stored = await keyset.encrypt(users, rows);
const [byEmail] = await keyset.query(users, [
  { field: "email", op: "eq", value: "ada@example.com" },
]);
```

- **The same declaration and the same calls.** An EQL type goes where
  `encrypt(..)` goes in a record. `encrypt`, `query`, `decrypt`,
  `encryptField` and `decryptField` are the core's. The extension adds no
  call of its own for a scalar type.
- **A record is a table, and a field is a column.** The record's name is
  the table's name and the field's name is the column's name. EQL stores
  both in the value.
- **A field is plain verbs or one EQL type, never both.** A record can mix
  the two kinds of field, as an engine plan can.
- **The stored field is EQL v4 JSON**, ready for a SQL parameter. A query
  term carries the SQL domain it binds as (`term.domain`), as the engine's
  `QueryTerm` does, so an adapter writes the cast without a table of its
  own.
- **The types come from the EQL catalog.** `eql-codegen` writes the Go
  types today (`go_eql.rs` writes `languages/golang/encrypt/eql/eql_gen.go`).
  It gains a TypeScript writer, which writes each type's plaintext type, its
  operators and its options. A drift check fails CI when the file is stale,
  as `types:check` does for Go.
- **The compiler checks that the extension is there.** A record that names
  an EQL type does not compile against a cipher built without `eql`.
- **JSON documents.** A `JsonSearch` field has its document operators:
  `contains`, `contained_by`, the comparisons at a path, `element_match`,
  `match`, and the reads `selector`, `subtree`, `children` and
  `child_count`. A read's rows open through `cipher.openJson(..)`, over
  `dynamic::json_open`. These are the extension's only calls of its own.
- **A context field** (phase 2). The engine refuses a context field on a
  record with an EQL type (`TargetError::ContextField`), because an EQL
  value is stored under the table its declaration names. So an EQL record
  takes a tenant as a scope from the caller, and has no context field.

## Credentials, keysets and audit metadata

- **Credentials.** `Cipher.create()` finds credentials as every SDK does:
  the `CS_*` variables, then the profile that `stash auth login` writes. On
  Node, `stack-kms`'s profile store reads the file. The wasm build has no
  file system, so its credentials come from the variables or the cipher's
  options.
- **A credential with each call.** A cipher built over a strategy that
  takes a credential with each call, such as OIDC federation, has a
  different type. Its calls return a builder that cannot be awaited until
  `.withCredential(jwt)` is called. Forgetting it is a type error, as it is
  a compile error in Rust. The JWT is read in the caller's request, which is
  what #1565 asks of `@cipherstash/stack`.
- **Keysets.** `cipher.defaultKeyset()` is the keyset a ZeroKMS
  administrator set for the client. `cipher.keyset(name)` is any other,
  loaded on first use.
- **Audit metadata.** `.audit({ ... })` on `encrypt`, `encryptField`,
  `decrypt`, `decryptField` and `openJson`. A date and time in it is sent
  as RFC 3339 text in UTC, the form every SDK sends. A query has no
  data-key request, so it has no `.audit`.
- **Testing without ZeroKMS.** `@cipherstash/recipher/testing` builds a
  cipher over the engine's deterministic test keys, with no credentials and
  no network, as Go's `encrypttest.NewClient` does.

## Errors

Every failure is a `RecipherError` with `code`, `reason` and `field` from
the engine's error. Subclasses name the failures a caller acts on
differently: a refused declaration, a value of the wrong type, a refused
credential, a ZeroKMS refusal, a foreign keyset, a context mismatch and a
value that did not open. No message, property or `toString()` holds a
plaintext, a key, a token, a ciphertext or a context value. A decrypted
row's `inspect` output names its fields and hides their values, as Go's
`Redacted` does.

## Plaintext hygiene

A JavaScript string cannot be wiped. The SDK keeps the number of copies
down instead:

- The native crate reads a JavaScript value into a frame, which lives in a
  buffer wiped when it drops. No intermediate Rust `String` or JSON text
  holds the row.
- A decrypted frame is converted straight into JavaScript values.
- The wasm build follows the same rules. When a call ends, the buffers
  that call owned are wiped: on success, on failure and on cancellation.
  Other calls in flight share the same linear memory and still hold theirs.

A heap-hygiene test in the native crate runs each operation under the
watching allocator of `packages/stack-encrypt/tests/heap_hygiene.rs`, as
the Python engine crate does. A wasm test checks the three endings of a
call. The plaintext the JavaScript engine holds is outside what any test
can check, and the README says so.

## Promises and cancellation

- Every operation returns a `Promise`. napi-rs runs the engine's future on
  its tokio runtime. The wasm build runs it through `wasm-bindgen-futures`,
  and ZeroKMS requests go out through the runtime's `fetch`.
- A call takes an `AbortSignal`. Aborting drops the future, which wipes what
  it held, and rejects with the signal's reason. Only that call fails; the
  cipher goes on serving others. The Go SDK's cancellation tests
  (`languages/golang/encrypt/cancel_test.go`) are the list of cases.

## The adapters

`@cipherstash/stack-drizzle`, `@cipherstash/stack-supabase` and
`@cipherstash/stack-prisma` move onto `@cipherstash/recipher` and
`@cipherstash/recipher-eql`. Each takes a new major version that depends on
them and drops `@cipherstash/stack`.

- **Columns.** Each adapter maps its own column objects to a record and a
  field name, as each maps them to a table and a column name today:
  Drizzle by its column builder's table and name, Supabase.js by the table
  and the column string it filters on, and Prisma Next by its routing key.
- **Batches.** Drizzle's batched query terms map to `keyset.query`.
  Supabase's model encryption maps to `keyset.encrypt` and
  `cipher.decrypt`. Prisma Next's middleware encrypts and decrypts column
  by column, which maps to `encryptField` and `decryptField`.
- **SQL.** Each adapter writes EQL v3 SQL today: `eql_v3` operators and
  casts, and Prisma Next's baseline migration installs the v3 bundle. Each
  moves to the EQL v4 functions and query domains, taking the cast from the
  query term's `domain`.
- **Installing EQL v4.** `@cipherstash/eql` ships the v3 bundle, and
  `stash eql install` installs it. Both need the v4 bundle before an
  adapter can move. That is its own piece of work, in the CLI and in
  `packages/eql`, and step 15 depends on it.
- **Supabase.js.** The v3 adapter refuses some operators because PostgREST
  cannot write the `eql_v3.query_*` cast they need. Whether PostgREST can
  write the v4 query domains is checked before the Supabase step; the
  answer decides which operators the new major offers.
- **DynamoDB.** `@cipherstash/stack/dynamodb` is a subpath of
  `@cipherstash/stack`, not an adapter package. DynamoDB has no EQL, so it
  needs the core only; see [Decisions needed](#decisions-needed).
- **Skills.** `skills/stash-drizzle`, `stash-supabase`, `stash-prisma`,
  `stash-dynamodb`, `stash-encryption` and `stash-indexing` change with
  their adapters, in the same pull requests.

## Room for EQL v3 and v2

`recipher-compat` is planned to read and write EQL v3 and v2 on the same
engine. In TypeScript it arrives as another extension, beside
`@cipherstash/recipher-eql`, with no new call shape. So this plan holds to
three rules:

- **The EQL version is in the field's type, never in a call.** A
  declaration names an EQL v4 type from the catalog. A v3 type would be
  another type in the same record, through the same `encrypt`, `query` and
  `decrypt`.
- **The core never names a resolver.** The core crate takes the engine's
  `TargetResolver` as a parameter, and an extension's build passes its own.
  A resolver that knows the v3 and v2 types is another extension's.
- **Nothing outside an extension's generated catalog knows a type's
  version.** Query terms carry their SQL domain, and adapters write casts
  from it, so an adapter does not branch on the version.

A cipher runs in one build, so two extensions in one cipher need one build
that holds both. That is decided when `recipher-compat` is designed, and
these rules are checked then.

## Tests

- **Conformance.** A Vitest runner for every profile in
  `conformance/stack-encrypt/v1`, against both the napi build and the wasm
  build (#1479). The core package runs the profiles that name no EQL type.
  The EQL package runs `eql-json-v1`. Phase 1 runs the cases that take no
  context from the caller. Phase 2 adds the context, context-boundary and
  binding profiles (`record-contexts-v1`, `record-context-boundaries-v1`,
  `record-bindings-v1`) and the cases of the other profiles that name a
  context field. A case a phase skips is listed as not run, never as
  passed. The exchange profile enrols TypeScript in
  `scripts/stack-exchange-conformance.mjs`, so TypeScript opens what Rust
  and Go wrote in the same run, and they open what TypeScript wrote.
- **The core has no EQL in it.** A test fails if the core package's
  builds link `eql-bindings`, or if its TypeScript names an EQL type.
- **A frozen stored-rows file** (phase 3). Rows the first stable release
  wrote, opened on every build and never regenerated.
- **Value conversion.** The value profile, plus a fuzz target that converts
  a host value to a frame and compares it with `ValueFrame::of` for the same
  value.
- **Type tests.** A wrong row, a wrong value, an unknown field, an
  operator a field cannot answer, and an EQL type against a cipher without
  the extension do not compile.
- **Edge runtime.** Each package's wasm build runs one encrypt, query and
  decrypt under an edge runtime in CI (Miniflare or `workerd`).
- **Live.** One credentialed round trip of the core against ZeroKMS, and
  one of the EQL extension against ZeroKMS and PostgreSQL with EQL v4
  installed, in a path-filtered workflow like the other `integration-*.yml`
  jobs. Each adapter's live suite moves to EQL v4 with its major.

## Packaging and release

The packages follow `@cipherstash/auth`:

- `release.yml` builds the six platform addons and the wasm build of each
  package, and publishes the platform packages before the wrapper, as
  `publish-auth` does. npm trusted publishing is set up for each package,
  bound to `release.yml`.
- The core package and the EQL package are released together, at one
  version. Each package gets a changeset like any other workspace package.
- The crates depend on `stack-encrypt` and `eql-bindings` by path, so one
  release carries the engine of its own commit. Each package names that
  commit in an `engineCommit` export, and `Cipher.create` compares them.

## Documentation and skills

- The core's README starts with the steps to encrypt and decrypt one
  value, then a record, then a query term. It needs no database. The EQL
  package's README starts with the steps to a working round trip through
  PostgreSQL. Both are tested in CI, as Python's is.
- A skill under `skills/` for each package once it is published, since
  skills ship to customers.
- `AGENTS.md` (repository layout) and `SECURITY.md` (package list) gain
  each package in the pull request that adds it.

## Order of work

Each step is one pull request, and each ends with its tests passing in CI.

### Phase 1: now

The core, with no EQL:

1. **Walking skeleton.** The three crates and the core npm package.
   `Cipher.create`, and `encrypt` and `decrypt` of one `string` value on
   Node. CI builds it on Linux. Proves that the engine's futures run on
   napi-rs's runtime. Adds the tests that the core crate names no `Label`
   and links no `eql-bindings`.
2. **Values.** Every kind in the table above, `bytes` for a file, `opaque`
   for a whole object, the value profile and the fuzz target.
3. **Records.** `record`, `encrypt`, `passthrough`, nulls, the stored row
   type, `encryptField` and `decryptField`, the type tests, and the
   declaration, runtime and read profiles. This step is the first to call
   `Planned`.
4. **Search terms.** The indexes, `query`, every operator, match `verify`
   and `targetLimit` with the default match options, and the scalar and
   query-refusal profiles.
5. **Credentials, keysets, audit metadata and cancellation.** The
   per-call credential type, the testing cipher and the lifecycle profile.
6. **The wasm build.** The `wasm-bindgen` crate, the export conditions, the
   inlined build and the edge-runtime test.

Then the EQL extension:

7. **EQL types.** The EQL package, the `eql` cargo feature, the extension
   passed to `Cipher.create`, the `eql-codegen` writer and its drift check,
   and the scalar EQL types on Node and on wasm.
8. **JSON documents.** `JsonSearch` and the EQL/JSON profile.
9. **Exchange.** The exchange enrolment, so TypeScript, Rust and Go open
   each other's values in one run.

Phase 1 ends with a core and an extension that pass every conformance case
with no caller context, on Node and on wasm. Neither is published as
stable.

### Phase 2: after #1663

10. **Context.** Scopes, bindings and context fields, under the names the
    context design settles on, with the context, context-boundary and
    binding profiles.
11. **Expected context.** A decrypt that names the context it expects, and
    the context-mismatch error.

### Phase 3: after the issues that change stored bytes

12. **Catch up with the engine.** Match options (#1673), the plan checked
    against the JSON Schemas (#1678), and any rename from #1489 not yet
    taken.
13. **Stored rows.** The frozen stored-rows file.
14. **Release.** The platform packages, the release jobs, the READMEs and
    the skills.
15. **The adapters.** Drizzle, then Prisma Next, then Supabase, each a
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
3. **DynamoDB.** Whether `@cipherstash/stack/dynamodb` moves onto the core
   package, as `@cipherstash/recipher/dynamodb` or as a package of its own.
4. **A pre-release after phase 1.** Phase 1 could publish to npm under a
   pre-release tag, so the adapters and early users can try it. Its stored
   values would carry no promise that a later version opens them. The
   other choice is to publish nothing until phase 3. Publishing early
   moves the release jobs of step 14 into phase 1.
5. **How the EQL extension ships its build.** This plan gives the EQL
   package its own builds, as Go does. The core's builds then hold no EQL
   code, which keeps the core's wasm small. The cost is six more platform
   packages to publish. The other choice is one build that always holds
   the EQL types, with the split in the TypeScript API only.
6. **The EQL package's name.** This plan uses `@cipherstash/recipher-eql`.
   `@cipherstash/eql` exists already and holds the SQL bundle.
7. **A value with no context.** Rust's `keyset.encrypt(value)` takes no
   context. This plan gives every value a declared context, as Go does, so
   no ciphertext opens in a place it was not written for. The other choice
   is to allow `value(kind)` with no context.

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

Read on 2026-11-23, on `next` at `e62420d8e`:

- The state of each issue in [Phases](#phases): #1669 and #1398 are
  closed; the others named there are open.
- A plan field declares its context as a list of names
  (`"context": ["users", "email"]`, in the module example of
  `packages/stack-encrypt/src/dynamic/planned.rs`), and a `Planned`
  encrypts and decrypts with no context from the caller (`encrypt_into`
  and `decrypt_from` in the tests of `dynamic/record.rs`). An expected
  context is an `Option<Label>` in `planned.rs`, which phase 1 never
  passes.
- Of the conformance case files, only `record-bindings-v1` names a scope
  or a binding; `record-declarations-v1` and `record-reads-v1` have cases
  that name a context field.
- The engine separates the EQL types from itself. A plan field is plain
  outputs (`"outputs": ["c", "eq"]`) or one named target. A
  `TargetResolver` that the host links in runs a named target, and
  `NoTargets` is the build without one
  (`packages/stack-encrypt/src/dynamic/mod.rs`). `eql-bindings`' `targets`
  feature is the resolver for the EQL types. Go's `encrypt/eql` embeds a
  second guest build with them.
- The engine's documentation order: a scalar, a context, credentials, a
  whole value as one ciphertext (`OpaqueBlob`, `src/blob.rs`), then
  records (`packages/stack-encrypt/src/lib.rs` and `examples/`).
- A whole value is sealed outside `dynamic`: a `ValueFrame` implements
  `Encrypt`, and `keyset.encrypt_tree(value, aad)` seals it
  (`dynamic/mod.rs`, "What is not here").
- `Plan::with_context_field` refuses a field that names an EQL type, with
  `TargetError::ContextField` (`dynamic/record.rs`).

Not checked:

- That the engine's pending calls are `Send`, as napi-rs's async
  functions need. Step 1 proves it for a value and step 3 for a `Planned`
  call, or finds the change the engine needs.
- That a binding can reach `OpaqueBlob`'s format for a value whose type is
  known only at run time. Step 2 proves it or finds the change the engine
  needs.
- That the engine opens one field of a stored row without the row's other
  fields, which `decryptField` needs. Step 3 proves it or finds the change
  the engine needs.
- The largest value one call can seal, which bounds the size of a file.
- The size of each wasm build, with and without the EQL types.
- napi-rs addons under Bun and Deno.
- Whether PostgREST can write the EQL v4 query domains.
