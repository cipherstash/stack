# Building a language integration

How to reach Stack Encrypt from a language other than Rust: what crosses
between your code and the engine, what the engine expects of you, and how
to prove you got it right. The Go SDK in `languages/golang` is the reference
integration, and every rule below names where in it the rule is kept.

Stack Encrypt is CipherStash's encryption engine. It encrypts each value of a
record under its own data key from ZeroKMS, the key service, and derives the
*search terms* a database can compare without decrypting: an equality term
(a keyed hash), order terms (for `<`, `>` and `BETWEEN`) and match terms (for
text search). Rust programs call it directly. Every other language calls it
through the `dynamic` module, which this guide is about.

## 1. A binding and a language SDK are two things

- The **engine** is this crate: the Rust code that encrypts, decrypts and
  derives terms.
- A **binding** is the interface between the engine and a language: a native
  library loaded through FFI, or a WebAssembly module. What crosses it is
  data: a declaration, a value, a result.
- A **language SDK** is what users of the language work with: the types,
  decorators, struct tags or generators they write against. It sits on the
  binding.

Keep the two apart in code and in words. The user-facing library is never
"the binding". The Go SDK is `languages/golang/encrypt`; its binding is the
WebAssembly guest in `languages/golang/encrypt/guest` and the Go code in
`languages/golang/internal/guest` that runs it.

Two documents fix what a language SDK may and may not do, and this guide
does not repeat them: `docs/sdk-design-principles.md` (adopted by ADR-0008
in `docs/adr/`) and ADR-0007, *bindings enter the engine through a plan,
never through a second executor*. The one sentence to carry from them: the
engine does all the work, an SDK declares what to do and sends it across as
data, and the bytes are the same in every language because every language
runs the same code.

## 2. Native or WebAssembly

Build a native library by default. Build a WebAssembly (WASI) guest only
where WebAssembly is the reason you are there:

- the host language cannot load a native library cleanly (Go, whose cgo-free
  story is why its binding is a wazero guest);
- the code runs where native libraries are not allowed (an edge runtime, a
  browser);
- you want the sandbox: a guest's memory is a single buffer the host owns,
  can lock in RAM and can wipe as a whole.

The engine is the same either way. What differs is how bytes cross and who
owns memory, which sections 6 and 7 cover. A native shell links this crate
with the `dynamic` feature and calls the functions in section 3 directly. A
guest wraps the same functions in exports, as `languages/golang/encrypt/guest/src/abi.rs`
does, over the conventions in the `stack-guest-abi` crate
(`packages/stack-guest-abi`), which every guest shares so a host reads two
guests the same way.

## 3. The three operations

A binding does three things: encrypt a record, derive a query term, and
decrypt a record. Each is one function in [`crate::dynamic`], and each is
one export in the Go guest. Everything else a guest exports exists to serve
those three.

### What a record operation needs

- A **plan**: the declaration of what each field is, as data. Section 4 has
  the grammar. [`crate::dynamic::record::plan`] reads one from its frame;
  [`crate::dynamic::record::plan_with`] reads one that may name EQL types
  (section 3, "EQL types").
- A **value**: the record, as one frame. A binding never builds a tree of
  values; it hands the engine the bytes and the engine walks them in place.
  [`crate::dynamic::ValueFrame`] is the engine's hold on such a value.
- A **keyset cipher**: which ZeroKMS keyset mints and opens the keys.
  [`crate::StackCipher::default_keyset`] gives the default one;
  [`crate::StackCipher::keyset`] names another.

### Encrypt a record

[`crate::dynamic::record::encrypt`]`(&keyset, &frame, &plan)` returns a
[`crate::Pending`]: the key requests the record needs, batched into one
ZeroKMS call. Await it and the result is the stored record, as a frame.
With a plan that names EQL types, call
[`crate::dynamic::record::encrypt_with`] and pass the resolver (section 3,
"EQL types").

The Go guest's export is `se_encrypt_record(value, plan, options)` in
`languages/golang/encrypt/guest/src/abi.rs`. The options object names the
keyset (`languages/golang/encrypt/guest/src/options.rs`).

### Derive a query term

[`crate::dynamic::query_term`]`(&keyset, &plan, field, operator, input, &resolver)`
takes the plan, the field's name, an operator ([`crate::dynamic::OpSpec`]:
`eq`, `lt`, `lte`, `gt`, `gte`, `between` or `matches`) and the operator's
input, and returns the term the database compares against. The engine reads
the input as the field's declared type, finds the index that answers the
operator, and derives the term the same way the stored term was derived. An
operator the field does not answer is refused before any key is touched.

Two more functions serve a probabilistic term, which is what a match index
gives: [`crate::dynamic::verify`] answers, for a page of decrypted values,
which ones the query matches; [`crate::dynamic::target_limit`] says how many
rows to fetch. Neither needs a key. [`crate::dynamic::field_operators`]
lists the operators a plan field answers, so a generator can ask the engine
instead of keeping a copy of the table.

The Go guest's exports are `se_query_term`, `se_verify`, `se_target_limit`
and `se_operators`.

### Decrypt a record

[`crate::dynamic::record::decrypt`]`(scope, stored, &plan, expected_context)`
returns a `Pending` that opens to the record's frame. The
[`crate::dynamic::Scope`] says which cipher opens: the client, which opens a
value sealed under any of its keysets, or one keyset, which refuses a value
sealed under another before any key is fetched. With EQL types, use
[`crate::dynamic::record::decrypt_with`].

The Go guest's export is `se_decrypt_record(stored, plan, options)`.

### EQL types

A plan field may name an EQL type as its **target** instead of listing
outputs: `{"context": ["profiles", "age"], "target": "IntegerEq"}`. EQL is
the SQL library installed into a customer's PostgreSQL, and an EQL type is
the JSON value one of its column types stores. The engine does not know the
EQL types; the crate that does, `eql-bindings`, depends on this one. So the
binding that links the EQL types installs a [`crate::dynamic::TargetResolver`],
which the engine calls once per target field to run the named type's own
plan. [`crate::dynamic::NoTargets`] is the resolver of a build without them;
it refuses every name when the plan is read. The by-name dispatch, generated
from the EQL catalog, is `eql_bindings::encryption::targets` under its
`targets` feature. The Go module ships two guest builds, one with the EQL
types and one without, and `se_targets` lists the types a build holds.

### The other guest exports

The Go guest's remaining exports, for a reader of `abi.rs`: `se_cipher_init`
builds the cipher from a configuration object (section 7) and runs once per
instance; `se_keyset` loads a keyset by name or id; `se_term` derives one
index term under an explicit context, kept for one host need the file
explains; `se_plan_check` reads a plan and reports its refusal with no
cipher, so a generator can check a declaration before the program runs;
`se_shutdown` drops every key and wipes every buffer. `se_io`, `se_resume`
and `se_abort` are the step loop of section 7, and `se_alloc`, `se_dealloc`
and `se_last_error` come from `stack-guest-abi` (sections 6 and 8).

## 4. The plan grammar

A plan is a map from field name to field spec. The grammar is defined by
what [`crate::dynamic::record::plan`] accepts, in `src/dynamic/record.rs`;
the module docs there are the full statement. The shape:

```text
{
  "<field>": {
    "context": ["<table>", "<column>"],     // required: the field's label
    "outputs": ["c", "eq", "ore", "ope", "match", "passthrough"],
    "type":    "int32",                       // required with any index
    "target":  "IntegerEq"                    // instead of "outputs"
  },
  "context_field": "<field>"                  // optional, plan-level
}
```

- **`context`** is the label the field is sealed under, as a list of parts.
  Every field of one plan shares the same prefix (the table) and its last
  part is the field's identity (the column). A caller's extension, such as
  a tenant, nests to the left: `[["profiles", "age"], 7]`.
- **`outputs`** are what the engine produces for the field: `c` is the
  ciphertext; `eq`, `ore`, `ope` and `match` are index terms; `passthrough`
  carries the value as it is. These keys are wire format: they are the map
  keys of the stored record, fixed in [`crate::dynamic::Output`] and
  [`crate::target::IndexSpec`], so a binding never spells its own. A match
  index with options other than the defaults is written as an object,
  `{"match": {"tokenizer": ..., "downcase": ..., "k": ..., "m": ...}}`;
  `IndexSpec`'s docs in `src/dynamic/term.rs` give the form, and a bare
  `"match"` is the default options.
- **`type`** is a [`crate::dynamic::ValueKind`] name: `string`, `bytes`,
  `bool`, `int8` to `int128`, `uint8` to `uint128`, `float32`, `float64`,
  `decimal`, `date`, `timestamp`. A field with any index term must declare
  one: its terms derive from that kind, never from whatever tag each value
  arrives with. The type decides which indexes a field may have
  ([`crate::dynamic::admits`]) and which values it accepts, and nothing
  about the bytes.
- **`target`** names an EQL type and is exclusive with `outputs`. A target
  field's label must be exactly a table and a column.
- **`context_field`**, at the top level, names the field whose value is the
  context every other field is sealed under, for a record that names its
  own tenant. The named field is stored as a passthrough.

The plan is read from a frame, not from JSON. The Go SDK's generator writes
the plan from struct tags (`languages/golang/encrypt/gensupport/declaration.go`
turns a declaration into one), and the plan's frame is checked by
`se_plan_check` at `go generate`, so a mistake is found before the program
runs. Refusals name the field and a reason (section 8).

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

**Control messages** are everything else: the plan, a context, the options
object, a configuration, query statistics, a step's requests and responses,
an error. They cross as frames as well, and the engine reads each straight
into a typed message with serde (`vitaminc_aead_frame::serde`), with no
intermediate tree. The general-purpose value tree that earlier versions of
this crate decoded everything into is gone: there is no type a binding can
use to hold plaintext as a tree, by design. If you find yourself building
one, you are building a second value model.

The frame format itself is documented in the crate that owns it,
[`vitaminc-aead-frame`](https://docs.rs/vitaminc-aead-frame/0.6.1): the
byte layout, the tag table, the depth and length limits, and the
conformance corpus. This guide does not restate it. A binding's codec
targets one version of that crate and says which.

## 6. Plaintext hygiene

The engine's rule is that plaintext lives in one place, for as long as the
operation needs it, and is wiped on every path out, including failure. A
binding inherits the rule for every copy it makes. What the Go guest does,
from `languages/golang/encrypt/guest/src/abi.rs` and
`packages/stack-guest-abi/src/abi.rs`:

- **Every buffer the host hands the guest is wiped before the export
  returns** when it carries plaintext: the configuration (it holds the
  client key), a record to seal, a query input, a page of values to verify.
  The host must not read such a buffer back afterwards, or pass one buffer
  to two calls.
- **Every buffer the guest hands the host is released by the guest**, never
  freed on the host's say-so, through a registry that knows each buffer's
  true length (`stack_guest_abi::buffers`). `se_dealloc` wipes before it
  frees. A decrypted record is the host's to copy out and release at once.
- **A paused operation owns its inputs** (section 7) and wipes them when it
  finishes or is aborted. The engine holds a value as a
  [`crate::dynamic::ValueFrame`] in a `Protected` buffer, and an opened
  value as the same, so the one copy is wiped by the type, not by a line
  someone has to remember.
- **Shutdown runs destructors.** Closing a WebAssembly instance frees its
  memory without running Rust's drop code, so a guest needs an explicit
  shutdown export that drops the cipher and wipes every buffer. A native
  library gets this from drop; make sure your host calls it.
- **Keys never cross.** Key material derived from a ZeroKMS response stays
  in the engine; what crosses to the host is the request and the response
  bytes that would cross the network anyway.
- **Errors carry no values** (section 8).

The proof is a test, not a review. `packages/stack-encrypt/tests/heap_hygiene.rs`
runs each operation under an allocator that watches every freed block for a
marked plaintext and fails if one is freed unwiped:
`a_record_encrypted_from_a_value_frame_leaves_no_plaintext_on_the_heap`,
`a_record_decrypted_with_a_nested_field_leaves_no_plaintext_on_the_heap`,
`a_query_term_leaves_no_plaintext_on_the_heap`,
`an_order_term_of_owned_text_or_bytes_leaves_no_plaintext_on_the_heap` and
`verify_leaves_no_plaintext_on_the_heap`. The EQL side has the same test
for a target field (`packages/eql/tests/encryption/tests/heap_hygiene.rs`),
and the Go module has leak tests for the guest's memory
(`languages/golang/internal/guest`). Write the same test for your binding's
own copies: it is item 3 of the checklist.

## 7. Keys and authentication

The engine fetches data keys from ZeroKMS with a bearer token. Neither the
HTTP request nor the token is the engine's business: both come from the
host.

**The guest never waits on the network: it steps.** An export that may
reach ZeroKMS runs its work as a future and polls it once. If the work needs
a request, the export returns `STATUS_NEEDS_IO` with a handle instead of a
result. The host takes the handle's requests with `se_io`, performs them
however it likes (a goroutine, `fetch`), and hands the responses to
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

This shape is what lets the same guest run under wazero, where a host
function may block, and on an edge runtime, where it may not. A native
binding can do the same, or run the `Pending` to completion on a thread it
owns; either way, the host performs the HTTP.

**The token comes through one import.** The guest imports exactly one host
function, `token_get` in module `cipherstash_transport`
(`languages/golang/encrypt/guest/src/host.rs`). The host holds a fresh
bearer token before each step, so the import never waits. Minting and
refreshing tokens stay on the host side; in Go that is the `auth` package
and its credential guest, a separate module by ADR-0005. During an export,
a host import may re-enter the guest only through `se_alloc`, to place the
token. Calling any other export from inside an import is undefined
behaviour of the embedding.

**Cancellation is the host's contract to keep.** The Go SDK's rule, from
`languages/golang/encrypt/doc.go`: a call whose context ends fails with the
context's error, and only that call fails. One client is shared by every
request in a service, and one request giving up must not close it for the
rest. A step runs under a context the caller cannot end
(`guest.Detach` in `languages/golang/internal/guest/lock.go`), and the
client closes itself only when the guest's state is unknown: the guest
trapped, or a call ran on for 30 seconds after its context ended, which is
a bug rather than an impatient caller. A call that succeeds after its
context ended returns the context's error and its output is wiped. Write
the same contract for your language, and the tests in
`languages/golang/encrypt/cancel_test.go` are the list of cases to cover.

**Configuration.** `se_cipher_init` takes one object: `client_id`,
`client_key` and optionally `zerokms_url` and `keyset_cache_size`
(`languages/golang/encrypt/guest/src/config.rs`). There is no key for a
keyset: the default keyset is the one ZeroKMS set for the client, and every
other keyset is chosen per call in the options object. Unknown keys are
refused, so a typo cannot silently fall back to a default.

## 8. Errors

A failure crosses a binding in two parts, and a binding passes both on.

**A status number** is the fast path a host acts on. The table is
`stack_guest_abi::status` (`packages/stack-guest-abi/src/status.rs`), one
numbering for every guest, and a code keeps its value for good. The ones a
binding author meets first:

| code | name | what a host does |
|---|---|---|
| 1 | `AUTH` | the ciphertext did not open: tampered, or the wrong context |
| 2 | `ENCODING` | malformed input at the boundary; fix the caller |
| 3 | `STATE` | a call out of order: before init, after shutdown, an unknown handle |
| 4 | `INTERNAL` | a bug in the guest; report it |
| 5 | `KMS_UNAUTHORIZED` | refresh the token and retry; the only retryable one |
| 6, 7, 8, 10 | `KMS_FORBIDDEN`, `KMS_NOT_FOUND`, `KMS_CONFLICT`, `KMS_OTHER` | ZeroKMS's verdict; surface it |
| 9 | `KMS_TRANSPORT` | no verdict reached: the host's transport or configuration |
| 11 | `TERM` | a term could not derive from the value (match text with no token) |
| 12 | `FOREIGN_KEYSET` | the value was sealed under a keyset the call did not allow |
| 28 | `CONTEXT_MISMATCH` | the record's stored context is not the one expected |
| 29 | `NEEDS_IO` | not a failure: the step loop of section 7 |

How this guest maps the engine's errors onto those numbers is
`languages/golang/encrypt/guest/src/status.rs`.

**The full error** is behind `se_last_error`: the engine's error as a frame,
with its code, message, help, structured fields and causes
(`packages/stack-guest-abi/src/last_error.rs`). A host asks for it after a
non-zero status; a call that succeeds pays nothing. The engine's errors
implement [`crate::ErrorPayload`], which is what makes them encodable, and
every input error from the `dynamic` module names the field it is about and
a [`crate::dynamic::Reason`] (`not_an_object`, `no_such_field`,
`operator_not_answered`, `field_type`, and so on) as fields, so a caller
tells a bad plan from a bad value without parsing text.

**Never a value.** No error, warning or log line holds a plaintext value, a
key, a token, a ciphertext or a context value. The guest's configuration
parser names the key at fault and never its value, because the value may be
the client key. Keep that rule in your own messages, and in what your SDK
prints when a user prints a struct.

## 9. Versioning

Three things have versions, and a binding ties them together.

- **The engine.** This crate is on crates.io. A native binding pins its
  version in its build; a guest builds against a path in this repository.
  The Go module's guest depends on `stack-encrypt` by path
  (`languages/golang/encrypt/guest/Cargo.toml`), and the Go package embeds
  the guest built from the same commit, so host and engine cannot drift: a
  tagged Go release carries the guest built at that tag
  (`languages/golang/encrypt/README.md`, "Building").
- **The wire.** The frame format is `vitaminc-aead-frame`'s and is frozen;
  a codec in another language targets one version and runs that version's
  conformance corpus (section 11).
- **The stored record.** A record's map keys (`c`, `eq`, `match`, `ore`,
  `ope`, `passthrough`, `eql`) and a plan's `type` names are wire format,
  fixed in [`crate::dynamic`]. A row written under one spelling is read
  under the same spelling or not at all. What keeps them fixed is a fixture
  that is never regenerated: `packages/stack-encrypt/tests/fixtures/stored_rows_v1.json`
  holds rows sealed by one release, and `tests/stored_rows.rs` opens every
  one on every build. A change that cannot open them is a broken release,
  not a reason to regenerate. The EQL side has
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

let value = ValueFrame::of(42i32)?;
assert_eq!(hex(value.risky_ref()), "042a000000");

let row = ValueFrame::of(BTreeMap::from([("age", 42i32)]))?;
assert_eq!(hex(row.risky_ref()), "f10100000003000000616765042a000000");

let plan = vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
    "age": { "context": ["profiles", "age"], "target": "IntegerEq" }
}))?;
assert_eq!(
    hex(&plan),
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

The outputs form of the same query runs in this crate alone, and the opened
record is the frame that went in:

```
use std::collections::BTreeMap;
use stack_encrypt::dynamic::{query_term, record, NoTargets, OpSpec, Operand, Scope, ValueFrame};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::StackCipher;

# tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
let keyset = cipher.default_keyset();

let plan = record::plan(&vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
    "age": { "context": ["profiles", "age"], "outputs": ["c", "eq"], "type": "int32" },
}))?)?;
let row = ValueFrame::of(BTreeMap::from([("age", 42i32)]))?;

// Encrypt: one pending, one ZeroKMS request, the stored record as a frame.
let stored = record::encrypt(&keyset, &row, &plan)?.await?;

// Query: the equality term for 42, the bytes the stored `eq` term holds.
let term = query_term(&keyset, &plan, "age", OpSpec::Eq, 42i32, &NoTargets)?.await?;
assert!(matches!(term.operand(), Operand::One(bytes) if bytes.len() == 32));

// Decrypt: the record's frame, equal to what went in, in a wiped buffer.
let opened = record::decrypt(Scope::Client(&cipher), stored, &plan, None)?.await?;
assert_eq!(opened.risky_ref(), row.risky_ref());
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

Before a binding is called done:

1. **The conformance corpus passes.** Your codec writes and reads every
   frame in `vitaminc-aead-frame`'s corpus byte for byte, and refuses every
   frame the corpus says to refuse (depth, length, a repeated key). The
   corpus and how to run it from the crate are tracked at
   <https://github.com/cipherstash/vitaminc/issues/473>.
2. **The differential fuzzers run against the engine.** The engine's own
   targets are in `packages/stack-encrypt/fuzz/fuzz_targets`
   (`plan_build`, `check_record`, `term_decode`, `sealed_value_decode`),
   run as `docs/fuzzing.md` describes. Add a target that feeds your codec's
   output to the engine's reader and the engine's output to your codec's
   reader; a disagreement is a bug on one side.
3. **The plaintext hygiene tests pass**, for the engine's copies and for
   yours (section 6).
4. **A stored-rows fixture exists and is frozen** (section 9): rows your
   binding wrote with its first release, opened on every build and never
   regenerated.
5. **The versions are tied.** The engine version, the frame-format version
   and your binding's version move together, and a reader of your release
   notes can tell which engine a release carries.
6. **The cross-language fixtures agree.** `packages/stack-encrypt/tests/fixtures/record_lowering.json`,
   `query_operators.json` and `value_kinds.json` are the records, query
   terms and value kinds the engine derives under a deterministic key
   source; the Go SDK reads them and derives the same bytes. Read them from
   your binding's tests too.

## 12. Where the rest is

- The frame format: [`vitaminc-aead-frame` on docs.rs](https://docs.rs/vitaminc-aead-frame/0.6.1).
- The `dynamic` API: [`crate::dynamic`], and `src/dynamic/record.rs` for
  the plan grammar in full.
- The guest conventions every WebAssembly binding shares:
  `packages/stack-guest-abi`.
- The reference integration: `languages/golang/encrypt` (SDK),
  `languages/golang/encrypt/guest` (binding) and
  `languages/golang/internal/guest` (the host side of the binding).
- The design rules: `docs/sdk-design-principles.md`, ADR-0007 and ADR-0008
  in `packages/stack-encrypt/docs/adr`, and ADR-0002 in `docs/adr` for the
  value model and the EQL v4 envelope.
