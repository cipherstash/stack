# Building a language integration

How to reach Stack Encrypt from a language other than Rust: what crosses
between your code and the engine, what the engine expects of you, and how
to prove you got it right.

Stack Encrypt is CipherStash's encryption engine. It encrypts each value of a
record under its own data key from ZeroKMS, the key service, and derives the
*search terms* a database can compare without decrypting: an equality term
(a keyed hash), order terms (for `<`, `>` and `BETWEEN`), match terms (for
text search) and the terms of a JSON document. Rust programs call it
directly. Every other language calls it through the `dynamic` module, which
this guide is about.

The Go SDK in `languages/golang` is the reference for what a language SDK
does, and every rule below names where in it the rule is kept. Its binding
is a WebAssembly guest, which is right for Go and wrong for a language that
can link Rust natively. Section 2 says which kind of binding to build.

## 1. A binding and a language SDK are two things

- The **engine** is this crate: the Rust code that encrypts, decrypts and
  derives terms.
- A **binding** is the interface between the engine and a language: a native
  extension that links this crate, or a WebAssembly module. What crosses it
  is data: a declaration, a value, a result.
- A **language SDK** is what users of the language work with: the types,
  decorators, struct tags or generators they write against. It sits on the
  binding.

Keep the two apart in code and in words. The user-facing library is never
"the binding". The Go SDK is `languages/golang/encrypt`; its binding is the
WebAssembly guest in `languages/golang/encrypt/guest` and the Go code in
`languages/golang/internal/guest` that runs it.

`docs/sdk-design-principles.md` fixes what a language SDK may and may not
do, and this guide does not repeat it. Two of the engine's rules matter
most here:

- A binding enters the engine through a plan, never through an executor of
  its own. It has no loop over fields, no batching and no sealing.
- An operator selects the index that answers it, and a query term is
  derived for that operator. It is not the stored term.

The one sentence to carry: the engine does all the work, an SDK declares
what to do and sends it across as data, and the bytes are the same in
every language because every language runs the same code.

## 2. Link the engine natively

Build a native extension that links this crate with the `dynamic` feature,
through the language's own Rust binding tool:

- Python: PyO3.
- Elixir and Erlang: Rustler.
- Node.js: napi-rs.

The engine then runs in the host's process, on the host's threads. It makes
its own requests to ZeroKMS, its errors are Rust values the extension turns
into the language's own, and the extension calls the Rust API in section 3
directly. There is no buffer registry to manage, no step loop and no status
table.

An edge runtime or a browser is not a reason for a guest. JavaScript there
cannot load a native library, so build the same extension crate for the
`wasm32-unknown-unknown` target with `wasm-bindgen`, as the
`@cipherstash/stack/wasm-inline` entry is built (the `build:wasm` script of
`languages/typescript/packages/protect-ffi`). The extension then exports a
JavaScript API, and the engine's requests to ZeroKMS go out through the
runtime's `fetch` (stack-kms's HTTP connection on that target). It is the
native extension's code and the native extension's API, compiled to
another target; nothing in the guest sections of this guide applies to it.

Build a WebAssembly (WASI) guest only for a language that cannot link a
native library cleanly. Go is the one today: the Go SDK is free of cgo, so
its binding is a guest that the wazero runtime runs. C and C++ may be
another case. A language with a good native binding story never uses the
guest.

The engine is the same either way. A guest wraps the same `dynamic` API in
exports, as `languages/golang/encrypt/guest/src/abi.rs` does, over the
conventions in the `stack-guest-abi` crate (`packages/stack-guest-abi`).
Where this guide describes the guest, it says so; skip those parts for a
native extension.

## 3. The operations

A binding does three things: encrypt a record, derive a query term, and
decrypt a record. It does each through [`crate::dynamic::Planned`]: a plan
paired with one value. A `Planned` is a target in the sense of the Rust
API, so it runs through the same `encrypt_into` and `decrypt_from` entry
points as a typed Rust record, and its scopes and bindings are the same
context argument.

### What an operation needs

- A **plan**: the declaration of what each field is, as data. Section 4 has
  the grammar. Read it once, when the language SDK loads a declaration, and
  keep it. [`crate::dynamic::record::plan`] reads one from its frame;
  [`crate::dynamic::record::plan_with`] reads one that may name EQL types
  (see "EQL types" below). Both take the frame as a
  [`vitaminc_protected::ProtectedRef`]; call
  [`crate::AsProtectedRef::as_protected_ref`] on the bytes.
- A **value**: the record, as one frame in a
  [`crate::dynamic::ValueFrame`]. A binding never builds a tree of values; it
  writes the host value straight into a frame, which holds the bytes in a
  buffer wiped when it drops, and the engine walks them in place.
- A **keyset cipher**: which ZeroKMS keyset mints and opens the keys.
  [`crate::StackCipher::default_keyset`] gives the default one;
  [`crate::StackCipher::keyset`] names another.

Every operation returns a [`crate::Pending`]: the work, with its key
requests batched into one ZeroKMS call, not yet sent. Two things attach to a
pending call before it is awaited. `.audit(metadata)` adds facts about the
call to the ZeroKMS audit log. `.with_credential(credential)` makes the
call as one caller, and section 7 says when a binding needs it.

### Encrypt a record

`Planned::new(&plan, row).encrypt_into(&keyset)` settles to the stored
record, a [`crate::StackCipherText`]. A batch is a sequence of records in
one frame, and is still one ZeroKMS call. With a scope or a binding, the
call is `encrypt_into_with_context(&keyset, Scope::new(7u64).bind(9u64))`
(see "Scopes and bindings" below). The row is moved in, and wiped when the
call is done with it.

### Derive a query term

A query is planned before any value exists:
[`crate::dynamic::record::Plan::query`]`(field, operator)` returns a
[`crate::dynamic::QueryPlan`], or refuses an operator no index of the field
answers. Keep it beside the plan. A query value then runs under it:
`Planned::new(&query_plan, value).encrypt_into(&keyset)` settles to a
[`crate::dynamic::QueryTerm`], the operand the database compares against.
A query takes a scope and no binding.

[`crate::dynamic::record::Plan::field`] gives the same query as a chain, for
an SDK that builds queries one at a time:
`plan.field("email")?.eq(value)?.scope(Scope::new(7u64)).encrypt(&keyset)`.

An operator ([`crate::dynamic::Op`]) is named by its wire name: `eq`, `lt`,
`lte`, `gt`, `gte`, `between` and `matches` for a single value, and the JSON
operators below for a document. The engine reads the value as the field's
declared type, finds the index that answers the operator
([`crate::dynamic::Op::answered_by`]), and derives the term the same way
the stored term was derived.

### Decrypt a record

`ValueFrame::decrypt_from(Planned::new(&plan, stored), cipher)` settles to
the record's frame, in a buffer wiped when it drops. The `cipher` argument
says which cipher opens ([`crate::CipherRef`]):

- pass `&cipher`, the client, to open a value sealed under any of its
  keysets;
- pass `&keyset` to open only values sealed under that keyset. A value
  sealed under another is refused before any key is fetched.

A record encrypted with a scope or a binding is decrypted with the same
ones, through `decrypt_from_with_context`.

### Scopes and bindings

A field is sealed under its label, `["profiles", "age"]`. A caller adds to
that context in two ways:

- A **scope** is added to the context of encryption, decryption and search
  alike: a tenant, say. A query under a scope finds only the rows sealed
  under it.
- A **binding** is added to the stored context only, after every scope:
  a row ID, say. It decides the data key and the authenticated data, so a
  value moved to another row does not open. A query takes no binding: its
  terms derive under the label and the scopes, and a query with a binding
  is refused before any key is requested.

The stored value holds neither; whoever reads it supplies them again. A
`Planned` call takes them as its context argument, built from
[`crate::target::Scope`] and [`crate::target::Bind`]. A plan can also carry
them itself: a scope written into each field's context and a binding in
the plan-level `"bind"` key (section 4). The full rules, with the cases
every binding runs, are in `conformance/stack-encrypt/context-contract.md`.

### Questions asked of the plan

Some questions take a plan and no record, so they are functions of the
plan rather than `Planned` calls:

- [`crate::dynamic::field_operators`] lists the operators a plan field
  answers, so a generator can ask the engine instead of keeping a copy of
  the table.
- [`crate::dynamic::verify`] answers, for a page of decrypted values,
  which ones a probabilistic query matches (a match index gives a
  probabilistic term), and [`crate::dynamic::target_limit`] says how many
  rows to fetch. Neither needs a key.
- [`crate::dynamic::json_open`] opens the rows a read of a JSON document
  returned (see "JSON documents" below).
- `Planned::contexts` and [`crate::dynamic::QueryPlan::contexts`] say which
  contexts each field is sealed and queried under, with placeholders for
  the caller's scope and binding, so a test can pin them.

One case still needs the record function underneath `Planned`: a plan that
takes its context from a field of each record (section 4), decrypted with a
check that each record names the context the caller expects. That check is
the `expected` argument of [`crate::dynamic::record::decrypt`].

### JSON documents

A field of type `"json"` stores a JSON document, which the language SDK
hands over as UTF-8 JSON text. It names a target that stores a document
(`JsonSearch`), and its options say which paths are ordered. The engine
parses the text by one set of rules ([`crate::dynamic::read_json`]) and
gives it back as text ([`crate::dynamic::json_frame`]). The whole document
is sealed as one leaf, its JSON text.

A document answers its own operators: `contains` and `contained_by`; `eq_at`,
`lt_at` and the other comparisons at a path; `element_match`; `match`, a
jsonpath predicate; and the reads `selector`, `subtree`, `children` and
`child_count`. [`crate::dynamic::Op::input`] names each one's input. A
query plan derives the operand for every one of them, and
[`crate::dynamic::json_open`] opens the rows a read returned.

### EQL types

A plan field may name an EQL type as its **target** instead of listing
outputs: `{"context": ["profiles", "age"], "target": "IntegerEq"}`. EQL is
the SQL library installed into a customer's PostgreSQL, and an EQL type is
the JSON value one of its column types stores. The engine does not know the
EQL types; the crate that does, `eql-bindings`, depends on this one. So the
binding that links the EQL types passes a
[`crate::dynamic::TargetResolver`], which the engine calls once per target
field to run the named type's own plan: to
[`crate::dynamic::record::plan_with`], to `Planned::with_resolver`, and to
[`crate::dynamic::record::Plan::query_with`] and
[`crate::dynamic::record::Plan::field_with`].
[`crate::dynamic::NoTargets`] is the resolver of a build without them; it
refuses every name when the plan is read. The by-name dispatch, generated
from the EQL catalog, is `eql_bindings::encryption::targets` under its
`targets` feature.

### The Go guest's exports

This part is for a guest. The Go guest exports the same operations as
functions of a plan and a value, which `Planned` runs underneath
([`crate::dynamic::record::encrypt_with`],
[`crate::dynamic::record::decrypt_with`] and
[`crate::dynamic::query_term`]), because a host across a WebAssembly
boundary hands over the plan's bytes on every call:

- `se_encrypt_record(value, plan, options)`, `se_decrypt_record(stored, plan, options)`
  and `se_query_term`. The options object names the keyset and may carry
  audit metadata (`languages/golang/encrypt/guest/src/options.rs`); the
  selector `{"any": {}}` opens under whichever keyset each value names, the
  data form of passing `&cipher`.
- `se_verify`, `se_target_limit`, `se_operators` and `se_json_open`, the
  questions of the plan.
- `se_cipher_init` builds the cipher from a configuration object (section 7)
  and runs once per instance; `se_keyset` loads a keyset by name or id.
- `se_term` derives one index term under an explicit context, kept for one
  host need the file explains.
- `se_plan_check` reads a plan and reports its refusal with no cipher, so a
  generator can check a declaration before the program runs; `se_contexts`
  prints the context each field of a plan is sealed under; `se_targets`
  lists the EQL types a build holds. The Go module ships two guest builds,
  one with the EQL types and one without.
- `se_shutdown` drops every key and wipes every buffer.
- `se_io`, `se_resume` and `se_abort` are the step loop of section 7.
- `se_alloc`, `se_dealloc` and `se_last_error` come from `stack-guest-abi`
  (sections 6 and 8).

## 4. The plan grammar

A plan is a map from field name to field spec. The grammar is defined by
what [`crate::dynamic::record::plan_with`] accepts, in `src/dynamic/record.rs`;
its docs and the module docs there are the full statement, and
`conformance/stack-encrypt/declaration-grammar.md` states it as a contract
with the cases every binding runs. The shape:

```text
{
  "<field>": {
    "context": ["<table>", "<column>"],     // required: the field's label
    "outputs": ["c", "eq", "ore", "ope", "match", "passthrough"],
    "target":  "IntegerEq",                   // instead of "outputs"
    "type":    "int32",                       // required with any index
    "null":    "sealed" | "sql"               // optional
  },
  "context_field": "<field>",                 // optional, plan-level
  "bind": [<part>, ...]                       // optional, plan-level
}
```

- **`context`** is the label the field is sealed under, as a list of parts.
  Every field of one plan shares the same prefix (the table) and its last
  part is the field's identity (the column). A scope nests to the left:
  `[["profiles", "age"], 7]`, and every field carries the same scopes.
- **`outputs`** are what the engine produces for the field: `c` is the
  ciphertext; `eq`, `ore`, `ope` and `match` are index terms; `passthrough`
  carries the value as it is, unsealed and unauthenticated. These keys are
  wire format: they are the map keys of the stored record, fixed in
  [`crate::dynamic::Output`] and [`crate::target::IndexSpec`], so a binding
  never spells its own. A match index with options other than the defaults
  is written as an object,
  `{"match": {"tokenizer": ..., "downcase": ..., "short_words": ..., "k": ..., "m": ...}}`;
  a bare `"match"` is the default options. A field declares at most one
  index per operator.
- **`target`** names an EQL type and is exclusive with `outputs`. A target
  field's label must be exactly a table and a column. A type that stores a
  document takes its options in an object form:
  `{"name": "JsonSearch", "options": {"sealed_root": <bool>, "ordered": [<path>, ...]}}`.
- **`type`** is a [`crate::dynamic::ValueKind`] name: `bool`, `int8` to
  `int128`, `uint8` to `uint128`, `float32`, `float64`, `decimal`, `date`,
  `timestamp`, `string`, `bytes`, `array`, `object` or `json`. A field with
  any index term must declare one: its terms derive from that kind, never
  from whatever tag each value arrives with. The type decides which indexes
  a field may have ([`crate::dynamic::admits`]) and which values it accepts,
  and nothing about the bytes.
- **`null`** says how the field stores a value that is not there. Without
  it, every row must have the field and a typed field refuses a null.
  `"sql"` stores nothing for the field, so the host's column holds SQL
  `NULL`. `"sealed"` seals a null as a value of the field's width, so the
  stored record does not show which rows are absent; it is for a type of
  fixed width whose only index is equality, and an `eq` query of a null
  finds those rows. [`crate::dynamic::NullMode`] has the rules.
- **`context_field`**, at the top level, names the field whose value is the
  context every other field is sealed under, for a record that names its
  own tenant. The named field is stored as a passthrough, and each other
  field's `context` is its identity alone (`["email"]`).
- **`bind`**, at the top level, is the plan's bindings (section 3): a
  non-empty list of scalar parts.

The plan is read from a frame, not from JSON. The Go SDK's generator writes
the plan from struct tags (`languages/golang/encrypt/gensupport/declaration.go`
turns a declaration into one), and the guest's `se_plan_check` checks the
plan's frame at `go generate`, so a mistake is found before the program
runs. A native SDK gets the same check by reading the plan when it loads a
declaration. A refusal names the field and a reason (section 8).

## 5. Control messages and plaintext

Two kinds of data cross a binding, and the engine treats them differently.

**Plaintext** is a value or a record. It crosses as a *frame*: vitaminc's
self-describing transport encoding, the same bytes a native Rust value
describes itself as. The engine never decodes a frame into a tree. It reads
it in place, walks it into the encrypting sink and the term derivers, and
drops it. [`crate::dynamic::ValueFrame::from_bytes`] accepts a frame that
holds one value of the value model, and [`crate::dynamic::ValueFrame::check`]
checks a record source in place. A decrypted record comes back as a frame
too, in a buffer wiped on drop.

**Control messages** are everything else: the plan, a context, query
statistics, an error, and for a guest the options object, a configuration
and a step's requests and responses. They cross as frames as well, and the
engine reads each straight into a typed message with serde
(`vitaminc_aead_frame::serde`), with no intermediate tree. There is no type
a binding can use to hold plaintext as a tree, by design. If you find
yourself building one, you are building a second value model.

The frame format itself is documented in the crate that owns it,
[`vitaminc-aead-frame`](https://docs.rs/vitaminc-aead-frame/0.10.0): the
byte layout, the tag table, and the depth and length limits. This guide
does not restate it. This crate re-exports it as
[`crate::dynamic::frame`], so a binding builds against the same version the
engine does.

- **A native extension links the crate** and has no codec of its own: the
  crate writes and reads every frame, on both sides. The version it pins in
  its `Cargo.toml` is the statement of which frame format it speaks. What
  the extension adds is the conversion from a value of its language to a
  frame and back, and that conversion is what its tests must cover
  (section 11).
- **A guest's host has a codec of its own**, because the host cannot link
  Rust. The Go SDK's is in `languages/golang/internal/guest`. It targets one
  version of the frame format and says which.

## 6. Plaintext hygiene

The engine's rule is that plaintext lives in one place, for as long as the
operation needs it, and is wiped on every path out, including failure. A
binding inherits the rule for every copy it makes.

What the engine does for every binding:

- The engine holds a value as a [`crate::dynamic::ValueFrame`] in a
  `Protected` buffer, and an opened value as the same, so the one copy is
  wiped by the type, not by a line someone has to remember. A `Planned`
  value is moved in and wiped when the call is done with it.
- **Keys never leave the engine.** Key material derived from a ZeroKMS
  response stays in it.
- **Errors carry no values** (section 8).

What a native extension does:

- **Write a host value straight into a frame**, and read a decrypted frame
  straight into the host value. Do not stage plaintext in a second buffer
  on the way. A frame is wiped when it drops; the host language's own
  objects (a Python `str`, a JavaScript string) usually cannot be, so the
  fewer of them the extension makes, the better.
- **Drop runs destructors.** The cipher wipes its keys when it drops; make
  sure the host releases it, and does not keep it alive in a global after
  the program is done with it.

What a guest adds, from `languages/golang/encrypt/guest/src/abi.rs` and
`packages/stack-guest-abi/src/abi.rs`:

- **Every buffer the host hands the guest is wiped before the export
  returns** when it carries plaintext: the configuration (it holds the
  client key), a record to seal, a query input, a page of values to verify,
  and the responses to a step (they hold wrapped keys). The host must not
  read such a buffer back afterwards, or pass one buffer to two calls.
- **Every buffer the guest hands the host is released by the guest**, never
  freed on the host's say-so, through a registry that knows each buffer's
  true length (`stack_guest_abi::buffers`). `se_dealloc` wipes before it
  frees. A decrypted record, and a step's requests (they hold the bearer
  token), are the host's to copy out and release at once.
- **A paused operation owns its inputs** (section 7) and wipes them when it
  finishes or is aborted.
- **Shutdown runs destructors.** Closing a WebAssembly instance frees its
  memory without running Rust's drop code, so a guest needs an explicit
  shutdown export that drops the cipher and wipes every buffer.

The proof is a test, not a review. `packages/stack-encrypt/tests/heap_hygiene.rs`
runs each operation under an allocator that watches every freed block for a
marked plaintext and fails if one is freed unwiped. Its tests cover a
record encrypted from a frame and decrypted with a nested field, a failure
part of the way through a batch, a query term, an order term, `verify`, a
JSON operator's input and a JSON document; for example
`a_record_encrypted_from_a_value_frame_leaves_no_plaintext_on_the_heap` and
`a_query_term_leaves_no_plaintext_on_the_heap`. The EQL side has the same
test for a target field (`packages/eql/tests/encryption/tests/heap_hygiene.rs`),
and the Go module has leak tests for the guest's memory
(`languages/golang/internal/guest`). The lifecycle profile of the
conformance suite (`conformance/stack-encrypt/lifecycle-contract.md`)
collects that evidence, with the gaps it knows of. Write the same test for
your binding's own copies: it is item 4 of the checklist.

## 7. Keys and authentication

The engine fetches data keys from ZeroKMS with a bearer token, from an
auth strategy in `stack-auth`.

### A native extension

The extension builds a [`crate::StackCipher`] over a ZeroKMS client and an
auth strategy, as a Rust program would, and the engine makes its own
requests. Choose the strategy by who the calls are for:

- A strategy that holds its own credential, such as an access key, serves
  every call.
- A strategy that takes a credential with each call, such as
  `OidcFederationStrategy`, serves the caller who signed in. Every call then
  needs `.with_credential(credential)` before it is awaited, usually with
  the end user's JWT. A call through such a cipher does not compile without
  it, so pass the caller's credential through your binding on every
  operation that reaches ZeroKMS.

One cipher serves every caller of a service. A cipher and a keyset hold no
credential; the call does.

`.audit(metadata)` adds facts about a call to the ZeroKMS audit log. A time
in it crosses as RFC 3339 text in UTC, so every language SDK logs one form;
`languages/golang/encrypt/guest/src/options.rs` gives the rules. A term
derives from the index key and requests no data key, so a query has no
request to send audit metadata with.

A `Pending` is a Rust future. Run it on the async runtime your binding
tool provides, or on a runtime the extension owns. Dropping it before it
settles cancels it, and wipes what it held.

### A guest

This part is for a guest. **The guest never waits on the network: it
steps.** An export that may reach ZeroKMS runs its work as a future and
polls it once. If the work needs a request, the export returns
`STATUS_NEEDS_IO` with a handle instead of a result. The host takes the
handle's requests with `se_io`, performs them, and hands the responses to
`se_resume`, which polls again and returns the same three ways: done,
needs more I/O, or failed. A host that gives up calls `se_abort`. The loop
is `stack_guest_abi::step`; the wire form of a step is in
`languages/golang/encrypt/guest/src/io.rs`:

```text
se_io  ->  { "handle": <u64>, "requests": [ { "method", "url", "headers", "body" }, ... ] }
se_resume(handle, [ { "status": <i32>, "headers", "body" }, ... ])
```

A negative `status` is a request the host could not perform, with the error
text as the body. The guest is never running while a request is in flight,
so a host's cancellation never interrupts it: an aborted operation is a
future dropped between two polls, and everything it held is wiped. At most
64 operations may be paused at once; the Go client bounds itself to that
and queues callers rather than failing them (`maxPaused` in
`languages/golang/encrypt/client.go`).

**The token comes through one import.** The guest imports exactly one host
function, `token_get` in module `cipherstash_transport`
(`languages/golang/encrypt/guest/src/host.rs`). The host holds a fresh
bearer token before each step, so the import never waits. Minting and
refreshing tokens stay on the host side; in Go that is the `auth` package
and its credential guest, a separate module that reads the profile and
signs in, so the encryption guest holds none of that code. During an export,
a host import may re-enter the guest only through `se_alloc`, to place the
token. Calling any other export from inside an import is undefined
behaviour of the embedding.

**Configuration.** `se_cipher_init` takes one object: `client_id`,
`client_key` and optionally `zerokms_url` and `keyset_cache_size`
(`languages/golang/encrypt/guest/src/config.rs`). There is no key for a
keyset: the default keyset is the one ZeroKMS set for the client, and every
other keyset is chosen per call in the options object. Unknown keys are
refused, so a typo cannot silently fall back to a default.

**Audit metadata** is the options object's `audit` key, on
`se_encrypt_record`, `se_decrypt_record` and `se_json_open`. The term
exports refuse it.

### Cancellation

**Cancellation is the language SDK's contract to keep.** The Go SDK's rule,
from `languages/golang/encrypt/doc.go`: a call whose context ends fails
with the context's error, and only that call fails. One client is shared by
every request in a service, and one request giving up must not close it for
the rest. A call that succeeds after its context ended returns the
context's error and its output is wiped. Write the same contract for your
language, and the tests in `languages/golang/encrypt/cancel_test.go` are the
list of cases to cover.

For the guest, a step runs under a context the caller cannot end (`Detach`
in `languages/golang/internal/guest/lock.go`), and the client closes itself
only when the guest's state is unknown: the guest trapped, or a call ran on
for 30 seconds after its context ended, which is a bug rather than an
impatient caller.

## 8. Errors

**A native extension** gets the engine's error as a Rust value:
[`crate::Error`], or the [`crate::dynamic::Error`] that a plan or a value
was refused with. Turn it into the language's own exception, keeping what
the error carries. Every engine error implements [`crate::ErrorPayload`]:
a code, a message, help, structured fields and causes. Every input error
from the `dynamic` module names the field it is about and a
[`crate::dynamic::Reason`] (`no_such_field`, `operator_not_answered`,
`field_type`, `bind_in_query`, and so on) as fields, so a caller tells a
bad plan from a bad value without parsing text. The conformance cases
assert the code, the reason and the field, never the message.

**A guest** reports a failure in two parts, and its host passes both on.
The full error, as above, is behind `se_last_error`, encoded as a frame
(`packages/stack-guest-abi/src/last_error.rs`). A host asks for it after a
non-zero status; a call that succeeds pays nothing. The status number is
the fast path a host acts on. The table is `stack_guest_abi::status`
(`packages/stack-guest-abi/src/status.rs`), one numbering for every guest,
and a code keeps its value for good. The ones a host meets first:

| code | name | what a host does |
|---|---|---|
| 1 | `AUTH` | the ciphertext did not open: it was tampered with, or opened under a context ZeroKMS did not check |
| 2 | `ENCODING` | malformed input at the boundary; fix the caller |
| 3 | `STATE` | a call out of order: before init, after shutdown, an unknown handle |
| 4 | `INTERNAL` | a bug in the guest; report it |
| 5 | `KMS_UNAUTHORIZED` | the credential was refused; refresh the token and retry. The only status a token refresh can fix |
| 6, 7, 8, 10 | `KMS_FORBIDDEN`, `KMS_NOT_FOUND`, `KMS_CONFLICT`, `KMS_OTHER` | ZeroKMS's verdict; surface it. A wrong context against ZeroKMS is `KMS_FORBIDDEN` |
| 9 | `KMS_TRANSPORT` | no verdict reached: the host's transport or configuration. A refresh does not fix it; a transient network failure may be retried under your transport's own policy |
| 11 | `TERM` | a term could not derive from the value (match text with no token) |
| 12 | `FOREIGN_KEYSET` | the value was sealed under a keyset the call did not allow |
| 28 | `CONTEXT_MISMATCH` | the record's stored context is not the one expected |
| 29 | `NEEDS_IO` | not a failure: the step loop of section 7 |

Codes 13 to 27 belong to the credential guest (profile files and sign-in).
How the Go guest maps the engine's errors onto those numbers, and what
`FOREIGN_KEYSET` and `CONTEXT_MISMATCH` do not prove, is
`languages/golang/encrypt/guest/src/status.rs`. The same distinctions hold
for a native extension's exceptions: a refused credential, a wrong keyset
and a tampered value are different failures, and a caller acts on each
differently.

**Never a value.** No error, warning or log line holds a plaintext value, a
key, a token, a ciphertext or a context value. The guest's configuration
parser names the key at fault and never its value, because the value may be
the client key. Keep that rule in your own messages, and in what your SDK
prints when a user prints a struct.

## 9. Versioning

Three things have versions, and a binding ties them together.

- **The engine.** This crate is on crates.io. A native extension pins its
  version in its `Cargo.toml`. The Go guest depends on `stack-encrypt` by
  path (`languages/golang/encrypt/guest/Cargo.toml`), and the Go package
  embeds the guest built from the same commit, so host and engine cannot
  drift: a tagged Go release carries the guest built at that tag
  (`languages/golang/encrypt/README.md`, "Building").
- **The wire.** The frame format is `vitaminc-aead-frame`'s. A native
  extension gets the version this crate depends on; a guest's host codec
  targets one version of it (section 5).
- **The stored record.** A record's map keys (`c`, `eq`, `match`, `ore`,
  `ope`, `passthrough`, `eql`), a plan's `type` names and the operator
  names are wire format, fixed in [`crate::dynamic`]. A row written under
  one spelling is read under the same spelling or not at all. What keeps
  them fixed is a fixture that is never regenerated:
  `packages/stack-encrypt/tests/fixtures/stored_rows_v1.json` holds rows
  sealed by one release, and `tests/stored_rows.rs` opens every one on
  every build. A change that cannot open them is a broken release, not a
  reason to regenerate. The EQL side has
  `packages/eql/tests/encryption/fixtures/stored_v4_rows_v1.json`, rows the
  Go SDK stored, opened by Rust and sealed again by Go on every build. Your
  binding should keep the same kind of file: rows it wrote with one version,
  opened by every later one.

## 10. One integer, end to end

A Go field `Age int32`, stored as the EQL v4 type `IntegerEq`, traced
through all three operations. Every byte below comes from a committed
fixture or from the code that runs in this crate's tests, and each is named
so you can check it.

### The declaration

The Go struct in `languages/golang/encrypt/internal/testusers/profiles.go`:

```text
type Profile struct {
    _   struct{} `stash:"context=profiles"`
    // ...
    Age int32    `stash:"age,encrypt_into=IntegerEq"`
    // ...
}
```

`stashgen` turns it into the declaration in `profile_stash.go`,
`EncryptInto("age", gensupport.Int32, "IntegerEq")`, and the declaration
becomes a plan. The one-field plan, as JSON for reading and as the frame the
engine actually receives:

```text
{ "age": { "context": ["profiles", "age"], "target": "IntegerEq" } }

f1 01000000  03000000 616765
   f1 02000000  07000000 636f6e74657874  f0 02000000  0a 08000000 70726f66696c6573  0a 03000000 616765
                06000000 746172676574   0a 09000000 496e74656765724571
```

The same field written with outputs instead of a target, which is the form
this crate can run without the EQL types, is
`{"age": {"context": ["profiles", "age"], "outputs": ["c", "eq"], "type": "int32"}}`.

### The value

The row `{"age": 42}` with `age` an `int32`, as a frame:

```text
f1 01000000  03000000 616765  04 2a000000
```

`04 2a000000` on its own is the value `42` as an `int32`: the frame's tag
for a 32-bit integer and the integer in little-endian order. What the other
bytes mean is in `vitaminc-aead-frame`'s documentation; the point here is
that this is the whole of what crosses, and nothing is decoded into a tree.

The bytes above are what this crate produces today, and this example runs
as a test of that:

```
use std::collections::BTreeMap;
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::Controlled as _;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

let value = ValueFrame::of(42i32)?;
assert_eq!(hex(value.risky_ref()), "042a000000");

let row = ValueFrame::of(BTreeMap::from([("age", 42i32)]))?;
assert_eq!(hex(row.risky_ref()), "f10100000003000000616765042a000000");

// A control message is written by serde into a buffer wiped on drop.
let plan = vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
    "age": { "context": ["profiles", "age"], "target": "IntegerEq" }
}))?;
assert_eq!(
    hex(plan.risky_ref()),
    "f10100000003000000616765\
     f10200000007000000636f6e74657874f0020000000a0800000070726f66696c65730a03000000616765\
     060000007461726765740a09000000496e74656765724571"
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Encrypt

The Go SDK's generated code sent that plan and that row to the deterministic
test guest, a build whose keys derive from a seed rather than from ZeroKMS,
and stored what came back in
`packages/eql/tests/encryption/fixtures/v4_rows.json` (seed
`encrypt round-trip tests seed v1`, row `id` 1, field `age`):

```text
{
  "v": 4,
  "i": { "t": "profiles", "c": "age" },
  "c": "stack-encrypt:1:AQAAAAAAAAAAAAAAAAAAAACaqBouRs68ubIb5N1OQbmcIABm7QQMIr1TNGIweTMmGzZsXGuC+7f6J8hofUigXNGM5QIXIEdBIW5IurSiSx5HzqZvnrotMr1+3KjlzthAMHIvvIE=",
  "hm": "ed60c97cff62963a142f9b7762de2e2b98e3d486a178b07f6e930318770fbecb"
}
```

That is the `IntegerEq` value: the envelope (`v`, the version; `i`, the
table and column), `c`, the ciphertext under the `stack-encrypt:1:` prefix
(`packages/eql/crates/eql-bindings/src/encryption.rs`), and `hm`, the
equality term. The `c` bytes depend on a random nonce and differ on every
run; the `hm` does not. The Rust test `rows_the_go_sdk_sealed_open_in_rust`
in `packages/eql/tests/encryption/tests/v4_types.rs` opens this row with a
cipher over the same seed, which is the proof that Go and Rust ran the same
code.

### Query

A query `age = 42` from Rust derives the term in
`packages/eql/tests/encryption/fixtures/v4_queries.json`, key `age`:

```text
{ "v": 4, "i": { "t": "profiles", "c": "age" },
  "hm": "ed60c97cff62963a142f9b7762de2e2b98e3d486a178b07f6e930318770fbecb" }
```

Its `hm` is the stored row's `hm`, byte for byte, which is what makes
`WHERE age = $1` find the row: the stored term and the query term are the
same derivation under the same index key. (The two fixtures were written by
different key sources, the deterministic guest and the test
`FakeDataKeySource`, whose index keys are the same; the test
`the_v4_query_fixture_is_what_the_dispatch_derives` holds the file to what
the dispatch derives.) The Go SDK derives the same bytes through
`se_query_term` and asserts them in its own tests.

The outputs form of the same field runs in this crate alone, through
`Planned`, as a native extension would run it. The opened record is the
frame that went in:

```
use std::collections::BTreeMap;
use stack_encrypt::dynamic::{record, Op, Operand, Planned, QueryTerm, ValueFrame};
use stack_encrypt::{AsProtectedRef, DecryptFrom, EncryptInto, StackCipher, StackCipherText};

# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
// With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
// the environment, or from the profile that `npx stash auth login` writes.
let cipher = StackCipher::builder()
#     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    .init()
    .await?;
let keyset = cipher.default_keyset();

// Read once, when the SDK loads the declaration.
let declaration = vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
    "age": { "context": ["profiles", "age"], "outputs": ["c", "eq"], "type": "int32" },
}))?;
let plan = record::plan(declaration.as_protected_ref())?;
let by_age = plan.query("age", Op::Eq)?;

// A frame is moved into each call and wiped by it, so the row is written
// once for each call that takes it.
let row = || ValueFrame::of(BTreeMap::from([("age", 42i32)]));

// Encrypt: one ZeroKMS request, the stored record.
let stored: StackCipherText = Planned::new(&plan, row()?).encrypt_into(&keyset).await?;

// Query: the equality term for 42, the bytes the stored `eq` term holds.
let term: QueryTerm = Planned::new(&by_age, ValueFrame::of(42i32)?)
    .encrypt_into(&keyset)
    .await?;
assert!(matches!(term.operand(), Operand::One(bytes) if bytes.len() == 32));

// Decrypt through the keyset: the record's frame, equal to what went in,
// in a buffer wiped when it drops.
let opened = ValueFrame::decrypt_from(Planned::new(&plan, stored), &keyset).await?;
assert_eq!(opened, row()?);
# Ok::<(), Box<dyn std::error::Error>>(())
# }).unwrap();
```

### Decrypt

Decrypting the stored `IntegerEq` value runs the type's own `DecryptInto`
through the resolver, which reads the ciphertext inside the JSON,
authenticates it under `profiles/age`, and refuses a different stored `i`.
What comes back to the binding is the frame `04 2a000000`, in a buffer the
engine wipes when it drops. In the Go SDK it lands in `Age int32` and
nowhere else.

## 11. Checklist for a new binding

`conformance/stack-encrypt` holds the shared test contract for bindings:
language-neutral cases, the outputs the native engine froze for them, and
the requirement IDs each profile maps onto existing tests. Its `README.md`
lists every profile and its Rust and Go runners. Before a binding is called
done:

1. **The conformance profiles pass in your language.** Write a runner for
   each profile in `conformance/stack-encrypt/v1`, as
   `languages/golang/encrypt/*conformance_test.go` does for Go: scalar
   records, declarations, reads, runtime and nulls, contexts and bindings,
   value boundaries, query refusals, raw frames and, if your binding links
   the EQL types, EQL and JSON. Read the frozen expectations; never
   regenerate them to pass. A profile you have not run is not a pass.
2. **Fresh artifacts cross both ways.** The exchange profile
   (`conformance/stack-encrypt/exchange-contract.md`) has your binding open
   what Rust wrote in the same run, and Rust open what your binding wrote,
   for every value kind at its edges. Enrol your runner in
   `scripts/stack-exchange-conformance.mjs`.
3. **Your value conversion is tested and fuzzed.** For a native extension,
   the frame is the crate's, and what you test is the conversion from a
   value of your language to a frame and back: run the value profile
   against it, and fuzz the conversion of a host value to a frame and back
   against [`crate::dynamic::ValueFrame::of`] for the same value. For a
   guest, the host's codec writes and reads every frame of the raw-frame
   profile and refuses every frame it says to refuse; add a fuzz target
   that feeds the codec's output to the engine's reader and the engine's
   output to the codec's reader. The engine's own fuzz targets are in
   `packages/stack-encrypt/fuzz/fuzz_targets` (`check_record`, `json_text`,
   `json_wire_decode`, `label_parse`, `sealed_value_decode`, `term_decode`),
   run as `docs/fuzzing.md` describes.
4. **The plaintext hygiene tests pass**, for the engine's copies and for
   yours (section 6), and the lifecycle profile's cases hold for your
   language: cancellation, cleanup of a partial output, validation before
   any key is requested.
5. **A stored-rows fixture exists and is frozen** (section 9): rows your
   binding wrote with its first release, opened on every build and never
   regenerated.
6. **The versions are tied.** The engine version, the frame-format version
   and your binding's version move together, and a reader of your release
   notes can tell which engine a release carries.

## 12. Where the rest is

- The frame format: [`vitaminc-aead-frame` on docs.rs](https://docs.rs/vitaminc-aead-frame/0.10.0).
- The `dynamic` API: [`crate::dynamic`], [`crate::dynamic::Planned`] for
  the operations, and `src/dynamic/record.rs` for the plan grammar in full.
- The binding contract and its cases: `conformance/stack-encrypt`, starting
  at `README.md` and `declaration-grammar.md`.
- The reference SDK: `languages/golang/encrypt`. Its binding, for a guest
  only: `languages/golang/encrypt/guest` and
  `languages/golang/internal/guest` (the host side), over the conventions
  in `packages/stack-guest-abi`.
- The design rules for a language SDK: `docs/sdk-design-principles.md`.
