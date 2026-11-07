# Stack Encrypt API review

Started on 24 October 2026. This review covers the current Rust
`stack-encrypt` API. It started with one task: encrypt one `i32` into
opaque ciphertext and store the result.

This document is a running log of the issues found. Each numbered section
records one issue: what the code does now, what changes were proposed, and
which decisions are made or still open. The proposed APIs are illustrations,
not implemented code, unless a status line says otherwise. Add a numbered
section for each new issue, and keep observations, proposed changes, and
open decisions apart.

On 7 November 2026, this log was checked against `next` at commit
`e4990e49b`. Some issues are now partly done. The owned API for one value and for collections is merged. A conformance corpus for Rust and Go is merged too. No issue is completely done.

The [summary of
status](#summary-of-status) gives the status of each issue and the pull
requests behind it. "Current behaviour" sections describe the code when
each issue was written. Where a code block in one of them is now wrong, a
note follows the block.

Three companion documents go with this log:

- [Complete public workflow examples](2026-10-24-stack-encrypt-public-examples.md)
  is a draft API design that covers encryption, storage, decryption, and
  queries.
- [Directional context examples](2026-10-24-stack-encrypt-context-examples.md)
  explores where context comes from and where it is stored, using attribute
  syntax modelled on Serde.
- [The implementation plan](2026-10-24-stack-encrypt-api-plan.md) records the
  requirements, the recommended decisions, the order of work, and when the
  work is complete.

## The stored format must stay compatible from 7 November 2026

On 7 November 2026, the user decided: "The stored data must not break as of
now. The Go customer has already started implementation with rc.3. We can
make breaking changes to the code/API but not the stored format."

The stored format is what is written to the database. It includes
ciphertexts with their envelopes and headers. It includes index and search
terms. It includes JSON tree entries.

The baseline is what the Go module at
tag `languages/golang/v0.1.0-rc.3` writes, with the EQL v4 SQL bundle
attached to that release. The tag is commit `114e08448`, built on 2
November 2026 from `next` at `929451b49`.

From now on, a change that would alter the stored format must keep data
written by rc.3 readable and searchable. Otherwise it must add a new,
versioned format beside the rc.3 format. The Rust and Go code and APIs can
still change in breaking ways. The [API
plan](2026-10-24-stack-encrypt-api-plan.md#changes-that-would-alter-the-stored-format)
lists the planned work that this decision constrains.

### History: no backward compatibility with the prototype

On 25 October 2026 the user clarified that this API has never shipped beyond
an early prototype. Backward compatibility, and migration of prototype data,
were not requirements. That replaced any earlier suggestion in this log to
keep old encodings or public imports. The new Rust, Go, guest, and EQL
(Encrypt Query Language) implementations must agree with each other.

The decision of 7 November 2026 replaces this one for stored data. The
earlier decision still applies to the code and the APIs. Issue 22 had said
the exemption would end when the customer release shipped. It now ends for
stored data before that release.

## Terms used in this log

These terms appear in many issues. Terms used in only one issue are defined
where they first appear.

| Term | Meaning |
| --- | --- |
| Vitamin C | CipherStash's Rust cryptography library, published as the `vitaminc-*` crates. Stack Encrypt used version 0.8.0 when this log started. #1501 moved it to 0.9 |
| ZeroKMS | CipherStash's key management service, which issues and retrieves data keys |
| KMS | Key management service |
| EQL | Encrypt Query Language, the SQL and storage format for searchable encrypted data in PostgreSQL |
| AEAD | Authenticated encryption with associated data |
| AAD | Additional authenticated data: data that encryption checks for one ciphertext, but does not encrypt. Stack Encrypt builds it from the context. See [Context and AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad) |
| Context | Data that a ciphertext is tied to, such as a column name or a row ID. Decryption needs the same context. See [Context and AAD](2026-10-24-stack-encrypt-api-plan.md#context-and-aad) |
| Leaf | One sealed value, `SealedValue`, in Vitamin C's ciphertext tree |
| Node | One element of Vitamin C's ciphertext tree, `Node<SealedValue>`: a single leaf, a sequence, a map, an empty container, or a passthrough value |
| Passthrough | A field that is copied into the output in plaintext, without encryption |
| Target | An output type that declares how a plaintext is encrypted into it, through `EncryptFrom`, or `EncryptTarget` in the owned API |
| Owned API | The Rust API added by #1404 that consumes its plaintext input: `keyset.encrypt`, `EncryptInto`, and `DecryptFrom`, over `EncryptTarget` and `DecryptSource` |
| Stored format | What is written to the database, as Go `v0.1.0-rc.3` writes it. See [the stored-format decision](#the-stored-format-must-stay-compatible-from-7-november-2026) |
| Plan | The lower-level builder, `Plan`, that composes encryption operations. The derives generate plans, and the dynamic interface uses them |
| Dynamic interface | The interface driven by data instead of Rust types, used through FFI (foreign function interface) and by the Go SDK |
| Guest | The WebAssembly build of the Rust engine that the Go SDK runs |
| ORE | Order-revealing encryption, the index used for range queries and sorting |

## Summary of status

| Issue | Status on 7 November 2026 |
| --- | --- |
| 1. Cipher trait mismatch | Partly done. #1404 adds `encrypt`, `encrypt_with_context`, `decrypt`, and `decrypt_with_context` on the keyset. How Stack's ciphers relate to Vitamin C's traits is still open |
| 2. Opaque ciphertext storage | Partly done. #1404 adds `Ciphertext`; text encodings and `OpaqueBlob` (#1503, in progress) are still open |
| 3. Plaintext-side encryption | Partly done. #1404 implements the keyset receiver, and an empty context for `Ciphertext` through both APIs. The structural API keeps its different rules |
| 4. Fixed context on the scalar derive | Still open. #1491 makes the composition rules in this issue true for repeated extensions |
| 5. `EncryptFrom` has no `encrypt_from` | Partly done. #1404 adds `EncryptTarget` and `DecryptSource`; the structural traits remain |
| 6. Plan builder `encrypt_into` | Still open |
| 7. Mixed encrypted and plaintext fields | Still open. In progress in #1504 |
| 8. Whole-value encryption and layouts | Still open. In progress in #1503 and #1504 |
| 9. Ownership across Stack and Vitamin C | Still open. #1501 moves the Rust crates to Vitamin C 0.9 |
| 10. Public `encrypt_as` | Still open. `encrypt_as` is still public |
| 11. Context from an input struct | Still open |
| 12. `Default` compared with optional context | Partly done. #1404 adds explicit context inputs for the owned API. The structural API still uses `Default` |
| 13. JSON layouts and output adaptation | Still open |
| 14. Decrypt context variants | Partly done. #1404 implements both pairs for one value, and #1501 for collections. Records are in progress in #1504 |
| 15. Go JSON work in pull request #1353 | Coordination item. Unchanged |
| 16. Prior query design | Adopted as the baseline. Unchanged |
| 17. One name for definition selection | Still open |
| 18. Consuming inputs with cleanup | Partly done (#1404, #1493, #1501). Blob cleanup, partial Serde decoding, and drop-guarded results are still open |
| 19. First-release completeness | Partly done (#1445, #1446, #1451, #1452, #1492). Opening a child bound to its parent is still open |
| 20. Keysets chosen from plaintext | Still open |
| 21. Packaging and `AsyncCipher` | Still open |
| 22. Customer-driven order of work | Partly done. The conformance corpus is merged. Merged work was reconciled on 7 November 2026 |

## 1. Cipher trait mismatch and the required context argument

**Status:** Partly done. #1404 adds `encrypt` and `encrypt_with_context`, and
the matching `decrypt` pair, on the keyset. The open questions about
Vitamin C's cipher traits remain.

The user asked for two separate methods, so that the common case needs no
empty context argument. Questions remain about how Stack's ciphers relate
to Vitamin C's cipher traits.

### Decision of 7 November 2026: name context parameters `context`

A parameter that takes the caller's context is named `context`. The name `aad` is kept only for a value that is an AAD.

Several public methods, such as `encrypt_tree`, still name the context `aad`. The [API
plan](2026-10-24-stack-encrypt-api-plan.md#name-context-parameters-context)
lists them as work to do. The rename breaks the Rust API only. It does not
change the stored format.

### Requested API direction

Passing an empty tuple, `()`, for the common case of no application context is
needless ceremony. Use separate methods, following the convention used
elsewhere:

```rust
keyset.encrypt(42_i32).await?;
keyset.encrypt_with_context(42_i32, "users/age").await?;
```

The method without context selects the same empty context that `()`
represents today. Make this split even if `KeysetCipher` keeps inherent
methods instead of implementing a Vitamin C trait.

### Current behaviour

`KeysetCipher::encrypt` is an inherent method, not a trait method:

```rust
let ciphertext = keyset.encrypt(42_i32, ()).await?;
let ciphertext = keyset.encrypt(42_i32, "users/age").await?;
```

Note added on 7 November 2026: this block is no longer current. #1404
renamed the two-argument method to `encrypt_tree`. `keyset.encrypt(value)`
now takes one argument and returns a `Ciphertext`. The second argument of
`encrypt_tree` is named `aad` in the code, but it takes a context.

Vitamin C (`vitaminc-aead` 0.8.0) provides the `Cipher` trait and the
`AsyncCipher` trait. Stack implements the synchronous `Cipher` trait on
internal adapters after it fetches keys. `MintedKeys` seals leaves, and
`BoundKeys` opens them. Neither public cipher implements `AsyncCipher`.
Callers therefore cannot pass `KeysetCipher` to generic Vitamin C code that
needs that trait.

Each internal adapter implements only half of `Cipher`. `MintedKeys::open`
and `BoundKeys::seal` always return errors.

### Why the mismatch exists

Batching alone does not explain the separate API, because `AsyncCipher`
already batches through `seal_many` and `open_many`. The real reasons are
these:

- `AsyncCipher`'s methods receive each leaf's derived AAD. ZeroKMS needs a
  descriptor of the original structured context, and the derived leaf AAD
  does not contain that context.
- Stack's layer for pending operations combines key requests across
  documents, fields, and rows. The trait's batch interface works on one
  document at a time.

Any trait integration has to keep meeting these constraints. The current
separation is deliberate. It still leaves a gap for code that is generic
over Vitamin C's traits, and internal implementations with operations that
always fail.

### Open questions

- Can an adapter bound to a context implement `AsyncCipher`, or does
  Vitamin C's interface need to carry the original context explicitly?
- How does that integration keep batching across several documents?
- Should sealing and opening be separate trait capabilities, so that no
  method is present but always fails?
- Should decryption have the matching `decrypt` and `decrypt_with_context`
  split?

**Source:**
[cipher implementation and rationale](../../packages/stack-encrypt/src/cipher.rs)
(`KeysetCipher::encrypt`, `MintedKeys`, `BoundKeys`, and the module's
discussion of batching). Vitamin C's trait definitions are in
`vitaminc-aead` 0.8.0, `src/seal.rs`.

## 2. The Node and SealedValue types make opaque ciphertext storage harder

**Status:** Partly done. Several decisions are recorded below. Pull request #1404 adds `Ciphertext`. The type has `to_bytes`, `from_bytes`, `key_tag`, and Serde support as Base64 or bytes. The text encodings and `OpaqueBlob` are still open.

### Decisions so far

- **Ordinary encryption produces one opaque ciphertext.** To encrypt a
  value structurally, the caller chooses an explicit target. To encrypt a
  composite plaintext as one ciphertext, the caller encodes it first with
  `OpaqueBlob<T>`. The
  [implementation plan](2026-10-24-stack-encrypt-api-plan.md) recommends
  adapting a native single sealed leaf through the existing transcoder. The
  transcoder is the `target::transcode` protocol described in issue 13. This
  avoids serialising a whole encrypted tree or encrypting again.
- **Collections, decided on 25 October 2026.** Direct `encrypt` takes a
  single value. It does not lift itself over collections automatically.
  Collections are still composed through `EncryptInto`, for example
  `let encrypted: Vec<Ciphertext> = vec![1_i32, 3_i32].encrypt_into(&keyset).await?`.
  To encode and seal a whole collection as one ciphertext, use
  `OpaqueBlob<Vec<T>>`. The collection question had been reopened earlier.
  This decision settles it.
- **Text encodings, decided on 25 October 2026.** Text conversions must use
  the existing `Base64Text` and `Base85Text` wrappers from the EQL bindings.
  The
  [text encodings item](2026-10-24-stack-encrypt-api-plan.md#typed-text-encodings-and-key-tag-extraction)
  in the API plan records the remaining work and the limit on decoding
  Base85 in SQL.

The follow-up of 25 October 2026 also set these directions:

- Explore moving these general encoding types to a layer below Stack and
  EQL, and supporting encoded field targets specific to ciphertext.
- Rust and PL/pgSQL must both be able to extract the stored ZeroKMS key tag
  with simple code.
- A protocol for refined tags is being designed separately. The proposed
  refinement replaces the ZeroKMS tag with a tag derived from it. The user
  clarified that ZeroKMS checks policy and writes logs against the refined
  tag, and returns the original tag. The decrypt path uses the original tag
  to rebuild the leaf AAD. Record these two separate roles in the
  implementation.

### Open questions

- Should byte buffers be spelled `Vec<u8>`, or use an explicit bytes
  wrapper?
- What form should a simple round trip take that stores and loads opaque
  ciphertext for scalar values, with direct conversion to bytes and back?
  It could be a dedicated scalar result type, a wrapper, or conversion
  helpers on the existing API.
- Should Base64 and Serde be supported conveniences?
- Does serialising a whole tree belong in Stack, or does it stay with the
  caller? If it stays with the caller, say so explicitly, and keep it out
  of the simple scalar path.

The prototype's canonical leaf encoding is a useful starting point. On 25
October 2026 it was not a backward-compatibility obligation. Since 7
November 2026 it is, because Go rc.3 writes that envelope. #1404's
`Ciphertext` uses the same envelope unchanged.

### Current behaviour

`KeysetCipher::encrypt` returns `StackCipherText`, an alias for Vitamin C's
`Node<SealedValue>`. Encrypting an `i32` produces `Single(SealedValue)`.
The return type also allows sequences, maps, empty containers, and
passthrough nodes. It does not keep the plaintext type as a type parameter.

| Capability | `StackCipherText` tree | `SealedValue` leaf |
| --- | --- | --- |
| Debug printing (`{:?}`) | Yes | Yes |
| Serde serialisation and deserialisation | No | Yes |
| Canonical byte encoding | None | `to_bytes()` and `from_bytes()` |
| Direct Base64 conversion | None | None. Encode the canonical bytes separately |

A leaf's canonical bytes contain its keyset ID, the metadata needed to
retrieve its key, and the local ciphertext. That versioned byte format is
the storage commitment. The leaf's Serde representation is not the same
compatibility commitment. Since 7 November 2026, data written by Go rc.3
must stay readable.

### Effect on callers

Even storing a scalar makes the caller handle the container
representation:

```rust
let ciphertext = keyset.encrypt(42_i32, ()).await?;
let StackCipherText::Single(leaf) = ciphertext else {
    unreachable!("encrypting an i32 produces a single leaf");
};
let bytes = leaf.to_bytes();

// After loading the bytes:
let leaf = SealedValue::from_bytes(&bytes)?;
let ciphertext = StackCipherText::Single(leaf);
let value: i32 = cipher.decrypt(ciphertext, ()).await?;
```

Note added on 7 November 2026: this block is no longer current. With #1404,
`keyset.encrypt(42_i32, ())` does not compile. The tree form is `keyset.encrypt_tree(42_i32, ())`.

For one value, `keyset.encrypt(42_i32)` returns a `Ciphertext`. A `Ciphertext` has `to_bytes` and `from_bytes`. `keyset.decrypt` opens it. `StackCipher::decrypt` still takes a tree and a
context, as in the last line.

The caller has to:

1. handle a shape mismatch that cannot happen for this input;
2. extract the leaf;
3. rebuild the node before decrypting.

There is no direct `ciphertext.to_bytes()` or
`serde_json::to_string(&ciphertext)` path. Base64 adds a separate encoding
step. For collections, the caller also has to choose a representation that
keeps the tree structure and the node variants.

Stored bytes alone are not enough to decrypt. The caller also needs
authorised access to ZeroKMS and the same application context. The storage
API should make that clear without exposing tree internals in the simple
scalar case.

**Sources:**
[ciphertext alias and leaf encoding](../../packages/stack-encrypt/src/cipher.rs)
(`StackCipherText`, `SealedValue`) and
[storage documentation and public re-exports](../../packages/stack-encrypt/src/lib.rs).
Vitamin C's container definition is in `vitaminc-aead` 0.8.0,
`src/container.rs`.

## 3. Plaintext-side encryption has different syntax and context requirements

**Status:** Partly done. The receiver for ordinary `encrypt` was decided on 24 October 2026. Pull request #1404 implements it. Pull request #1404 also gives `Ciphertext`
the same empty context through the keyset and through `EncryptInto`. The
structural API keeps its different requirements.

### Decision: the keyset is the receiver for ordinary encryption

**Decided on 24 October 2026.** Use only the keyset as the receiver of the
ordinary `encrypt` method:

```rust
tenant_keyset.encrypt(value).await?;
```

Do not add a plaintext-side counterpart, `value.encrypt(&keyset)`.

**`EncryptInto` stays.** This decision covers only the `encrypt` method. It
does not remove the API that encrypts into a chosen target. Implementation
is pending. The current inherent method still requires its context argument
(issue 1).

Both receiver forms take the same inputs and perform the same operation.
Neither gives better type safety, ownership behaviour, performance, or
batching by itself. Those depend on the signatures and the implementation,
not on which argument is `self`.

| Consideration | Plaintext receiver | Keyset receiver |
| --- | --- | --- |
| Mental model | Transform this value using a capability | Ask this encryption capability to process a value |
| Discoverability | The caller imports an extension trait. Methods appear on plaintext types | Encryption methods are found on the encryption handle |
| Fluent composition | Reads naturally after an expression that produces plaintext | Reads naturally when a keyset is chosen before an operation |
| Operational scope | The keyset and its authority appear as an argument | The keyset and its authority come first in the call |
| API surface | Adds methods to primitives and application types | Keeps execution methods on handles the library owns |
| Generic integration | Can work through a cipher trait | Can work through a cipher trait |

The reasons for the decision:

- Stack performs an asynchronous operation through a configured KMS
  capability. Putting that capability first makes its scope visible. It
  also gives callers one place to find operations.
- Plaintext traits can describe how values are represented without also
  owning the execution API.
- Two equivalent spellings add documentation, completion entries, and
  naming choices, but no capability. Familiarity with an earlier API matters
  for migration, but does not by itself justify two permanent entry points.

The `EncryptInto` API can choose outputs other than ordinary ciphertext. The
decision keeps it explicitly. Its context inconsistency is open, separately
from this decision. This decision does not cover the receivers for
decryption or batch methods.

### Current behaviour

Vitamin C's current `Encrypt` trait describes a plaintext through `visit`.
It has no `encrypt` method. Importing Stack's re-export of that trait does
not make `10_i32.encrypt(&keyset)` work. Vitamin C 0.8.0 documents this
trait as the replacement for an older trait. The older trait used a visitor
to drive a cipher directly.

Vitamin C's `ContextTag` wrapper has encryption methods, but those require
Vitamin C's cipher traits. The methods do not make the syntax available on
bare integers. They also do not accept Stack's public ciphers directly.

Stack supplies its own blanket extension trait, `EncryptInto`:

```rust
use stack_encrypt::{nonempty, EncryptInto, StackCipherText};

let ciphertext: StackCipherText = 10_i32
    .encrypt_into_with_context(&keyset, nonempty!("users/age"))
    .await?;
```

Note added on 7 November 2026: this block no longer compiles as written. This was checked by reading the source, not by compiling.

Since #1404, the crate-root `EncryptInto` is the owned trait. `StackCipherText` is not an owned target on `next`. The structural form needs
`stack_encrypt::target::legacy::EncryptInto`. The owned equivalent is
`let ciphertext: Ciphertext = 10_i32.encrypt_into_with_context(&keyset, "users/age").await?;`.

The output type selects the `EncryptFrom` implementation. For
`StackCipherText`, that implementation requires a source that implements
`Encrypt + Clone`, and an `AeadContext`. An `AeadContext` must not be
empty.

`EncryptInto` also has `encrypt_into(&keyset)`. That method requires the
target's context to implement `Default`. `AeadContext` does not, so this
form without context cannot produce `StackCipherText`. The form works for
other targets whose contexts have defaults, such as declarations that
include their own contexts.

The scalar derive also chooses a context without saying so. That choice is
hard to discover. `#[stash(plaintext = i32)]` generates
`type Context = CallerContext`, even for a record whose only field is a
`StackCipherText`, whose own context is `AeadContext`. The generated
operation converts between the two types.

The reviewer found that hidden choice surprising. It is undecided whether
this needs an API change, or clearer diagnostics and documentation. The
`Default` bound belongs to `EncryptInto::encrypt_into`, not to the
`EncryptFrom` trait itself.

### Effect on callers

Plaintext-side encryption exists, but it is not a mirror image of
`keyset.encrypt(value, context)`. Compared with the keyset method, it:

- uses different method names;
- selects an output through a target trait;
- adds a `Clone` bound for this output;
- refuses the empty context that the inherent method accepts.

Resolve the differing requirements for an empty context together with
issue 1. Renaming alone would not make the two paths equivalent. This
inconsistency is separate from the receiver decision above.

**Sources:**
[plaintext-side methods and ciphertext target implementation](../../packages/stack-encrypt/src/target/operations.rs)
(`EncryptInto`, `EncryptFrom<S> for StackCipherText`) and
[context types](../../packages/stack-encrypt/src/target/context.rs)
(`AeadContext`). Vitamin C's source trait is in `vitaminc-aead` 0.8.0,
`src/plaintext/mod.rs`.

## 4. The scalar derive cannot declare a fixed literal context

**Status:** Direction agreed. Still open. #1491 makes repeated Rust
extensions append, so the composition table below now matches the code.

### Agreed direction

Allow a scalar `plaintext = T` derive to declare a fixed literal context:

```rust
#[derive(EncryptFrom)]
#[stash(plaintext = i32, context = "example/integer")]
struct EncryptedInteger {
    ciphertext: StackCipherText,
}

let encrypted: EncryptedInteger = 10_i32.encrypt_into(&keyset).await?;
```

With a fixed context, the generated operation supplies that context. It
exposes a caller-context type that has a default, so `encrypt_into` works.
Without a fixed context, the ordinary scalar derive keeps using
`CallerContext` and requires `encrypt_into_with_context`.

Keep the explicit `context_type` and `context_field` configurations. Their
interaction with a fixed context needs validation rules, not a silent
override.

This closes the scalar gap in the derive. It does not need `CallerContext`
itself to implement `Default`. It also leaves the `EncryptFrom` trait
unchanged. A bare scalar has no input field for the derive to take context
from. The caller can still supply context at run time.

### Combining caller context with the fixed context

Extra context from the caller is accepted. Reuse the existing mechanism,
`DeclaredContext::under(own)`. Operation descriptions expose it through
`Encryption::under(own)`.

`DeclaredContext` implements `Default`, and its
empty default leaves the declared context unchanged. A caller extension is
combined as `(own, caller)`. It never replaces the declared context.

The recommended rules follow this existing mechanism:

| Caller input | Effective structured context, with static context `C` |
| --- | --- |
| No extension | `C` |
| One extension `P` | `(C, P)` |
| Extensions `P`, then `Q`, through `DeclaredContext::with` | `((C, P), Q)` |
| One extension that contains the pair `(P, Q)` | `(C, (P, Q))` |

This is structured composition, not string concatenation. Order and
grouping matter, and decryption must rebuild the same structure.
`NonEmpty::with` builds the matching pairs directly. The existing test
`under_gives_a_subtree_its_own_context_which_the_callers_extends` in
[target.rs](../../packages/stack-encrypt/tests/target.rs) checks one case.
An operation's declared context plus a caller extension must agree with a
context composed directly.

The derive implementation still has to specify how a static literal is
represented: for example, as text or as a parsed path label. Encryption and
decryption then produce the same descriptor and AAD. This choice is
separate from keeping the `EncryptInto` trait.

### Current behaviour and workaround

The goal is a derived output for a bare `i32`, a fixed context declared on
that output, and `10_i32.encrypt_into(&keyset)`. The current macro rejects
`#[stash(plaintext = i32, context = "example")]`. The literal `context`
attribute works only with `struct = ..`.

A workaround that uses only the derive wraps the integer in a plaintext
struct:

```rust
struct IntegerInput {
    value: i32,
}

#[derive(stack_encrypt::EncryptFrom)]
#[stash(struct = IntegerInput, context = "example")]
struct EncryptedInteger {
    value: stack_encrypt::StackCipherText,
}

// With EncryptInto imported:
let encrypted: EncryptedInteger = IntegerInput { value: 10 }
    .encrypt_into(&keyset)
    .await?;
```

Note added on 7 November 2026: since #1404, "EncryptInto" here must be
`stack_encrypt::target::legacy::EncryptInto`. The crate-root `EncryptInto` is the owned trait. The `EncryptFrom` derive does not implement it.
This was checked by reading the source, not by compiling.

This form declares the field's context as the pair `("example", "value")`.
ZeroKMS receives it as the descriptor `example/value`. For optional caller
extensions, the form uses `DeclaredContext`, a type with a default. It is
not a direct conversion from a bare integer.

A manual `EncryptFrom<i32>` implementation can supply its own context. The
ordinary literal attribute cannot do that on a scalar derive today.

**Sources:**
[macro validation](../../packages/stack-encrypt-derive/src/shape.rs)
(`a_container_context_requires_a_struct`) and
[generated implementations](../../packages/stack-encrypt-derive/src/encrypt.rs)
(`struct_derive`, `value_derive`).

## 5. EncryptFrom does not define encrypt_from

**Status:** Partly done. #1404 adds the declaration traits `EncryptTarget`
and `DecryptSource`, executed by the owned `EncryptInto` and `DecryptFrom`.
The structural `EncryptFrom` and `DecryptInto` remain. #1504 is in
progress.

Review the trait names and method names, or where the convenience function
lives. Keep the distinction between declaring an operation and executing
it.

`EncryptFrom<S>` defines the associated type `Context`, the constructor
for an operation description, `encryption()`, and `indexes()`. It does not
define a function named `encrypt_from`.

A function with that name exists on the blanket extension trait
`EncryptInto`. `Target::encrypt_from(&value, &keyset, context)` delegates to
`keyset.encrypt_as`. To call it, the caller needs `EncryptInto` in scope and
a target that implements `EncryptFrom<S>`.

This breaks the standard Rust naming pattern. `From<T>` defines `from`, and
`Into<T>` defines `into`. The names here suggest the same pattern, but two
things differ:

- `EncryptFrom` declares an operation. It does not execute a conversion.
- The execution function on the target side belongs to the extension trait
  on the source side.

As a result, finding the method, and knowing which trait to import, is
surprising.

**Source:**
[target operation traits](../../packages/stack-encrypt/src/target/operations.rs)
(`EncryptFrom`, `EncryptInto`, including `EncryptInto::encrypt_from`).

## 6. The plan builder's encrypt_into reads like the execution method

**Status:** Still open. Revisit during the plan API discussion.

`Plan::value::<S>().encrypt_into::<T>()` is an inherent builder method. It
selects an output target and requires `T: EncryptFrom<S>`. It does not
implement `EncryptInto`. It does not execute encryption either.

Its name is the same as `value.encrypt_into(&keyset).await?`. The shared
name caused confusion during this review.

A proposal for later discussion is to rename the builder method to
`target`:

```rust
Plan::value::<S>()
    .target::<StackCipherText>()
    .build()
```

The name `target` describes the choice being made, and separates it from
executing a conversion. The rename is not a decision. The API has not
changed. The proposal leaves `EncryptInto::encrypt_into` unchanged.

**Source:**
[value plan builder](../../packages/stack-encrypt/src/plan/value.rs)
(`ValueStart::encrypt_into`).

## 7. The output derive cannot mix encrypted and plaintext fields directly

**Status:** The passthrough attribute is accepted in principle. Still open. Pull request #1504 adds it to the owned derives. That pull request is in progress.

### Accepted proposal: a passthrough attribute

The proposed `#[stash(passthrough)]` attribute on output fields was accepted
as sensible. It copies the matching source field unchanged, next to fields
whose types select encryption.

Passthrough fields stay unencrypted and unauthenticated. Making a field
part of the encryption context is a separate choice. Copying a field does
not imply it.

### Current behaviour

Take a `User` with encrypted `name` and `email`, and plaintext `id` and
`created_at`. The fields-plan API supports this directly with
`.encrypt(pick(..))` and `.passthrough(pick(..))`. It batches the encrypted
fields and returns `FieldValues`. Callers can extract those values into a
typed storage struct.

The current `EncryptFrom` derive has no attribute to copy a source field
through. `#[stash(default)]` initialises an output from a default or an
expression. It does not copy a field from the input. Keeping the original
field type does not select passthrough either, because derived fields need
target traits.

### How Vitamin C's derive differs

This gap applies only to Stack's output-side `EncryptFrom` derive. Vitamin
C already has a plaintext-side `#[derive(Encrypt, Decrypt)]`, with
`#[aead(passthrough)]` on source fields. Stack's
`keyset.encrypt(&user, aad)` can take that derived source. Since #1404,
that method is `keyset.encrypt_tree(&user, aad)`, and its `aad` parameter
takes a context. The result is a
generic `StackCipherText` map with sealed and passthrough nodes.

That route has three limits:

- It does not generate a named `EncryptedUser` type. The output is not
  exposed as typed Rust fields.
- It derives AAD for map entries differently from the per-field contexts of
  a Stack fields plan. Do not present the two routes as interchangeable
  storage formats.
- No source-side derive exists that generates the typed encrypted
  counterpart shown in this review.

**Sources:**
[plan passthrough](../../packages/stack-encrypt/src/plan/build.rs)
(`FieldsBuilder::passthrough`) and
[derive field attributes](../../packages/stack-encrypt-derive/src/attrs.rs)
(`FieldAttrs`).

## 8. Clarify whole-value encryption, layouts, and searchable outputs

**Status:** Open architectural discussion. The recommendations below are
not decisions. #1503 is in progress for workflow 1, and #1504 for workflows
2 and 3.

Three user workflows need clear support:

1. Serialise a complete value into bytes, and encrypt those bytes as one
   opaque ciphertext.
2. Produce a chosen layout, such as `EncryptedUser`, with fields encrypted
   independently and explicit plaintext fields.
3. Produce a layout with extra encrypted forms or search terms, such as
   EQL targets.

### Recommended model

Separate the encryption granularity from the output representation and the
operations it requests. The granularity is either one encoded value or
selected fields. Workflow 3 should extend workflow 2 through field targets
that request ciphertext, search terms, or both. It should not add a separate
execution system. The generic tree can stay as one layout option without
being the required storage representation for scalars.

- **Whole-value path.** The follow-up review favours an explicit named
  wrapper, provisionally `OpaqueBlob<T>`. The wrapper owns serialisation
  and deserialisation through one codec that the library chooses. It
  produces one opaque ciphertext that can be stored. Decrypting into
  `OpaqueBlob<T>` selects the matching decoding path. Today callers can
  serialise into `Vec<u8>`. Vitamin C treats a `Vec<u8>` as a single byte
  leaf. Callers still meet the storage gap between node and leaf (issue 2).
- **Layout path.** Select a target with `EncryptFrom` and `EncryptInto`, or
  a plan, with an explicit passthrough choice. A source-side derive that
  generates a target would make authoring easier on the same system. It
  would not add another set of encryption semantics.
- **Searchable layout path.** Compose the core encryption and index
  operations through targets. EQL adapters own their storage
  representation, and Stack owns execution. Write operations and query
  operations must share the relevant context and normalisation rules.

Inside the library, keep these four things separate: source
representation, requested operations, output encoding, and execution. Give
each workflow a short public path. An application should not need to learn
visitor machinery or plans to encrypt and store a scalar. Arbitrary
serialisation must not silently replace the typed normalisation that
indexes use.

Before choosing more trait names, write examples for all three workflows
from start to end: encrypt, store, load, and decrypt, plus query for
searchable targets. Use those examples to judge the public API and its
error messages.

### Why Vitamin C's derive is not whole-value encryption

The existing Vitamin C plaintext derive produces a structural ciphertext
tree, not one encrypted serialisation. It is a generic output layout for
workflow 2, not workflow 1. The difference affects four properties: the
number of keys, independent access to fields, the visible structure, and
the authenticated boundaries. Encoding the completed ciphertext tree
into one byte string would not give it those properties of whole-value
encryption.

### Follow-up: a whole-value wrapper chosen by the library

The first public example now uses
`keyset.encrypt_with_context(OpaqueBlob::new(user), context)` instead of
encoding JSON by hand. The wrapper name is provisional. The direction is to
make blob serialisation an explicit behaviour that the library owns.

The stored result stays opaque ciphertext. Decryption returns an
`OpaqueBlob<User>` that the caller can unwrap. The codec and its
authenticated versioning still need a specification. The wrapper does not
silently change how unwrapped structs are encrypted.

### Constant-time serialisation is not yet established

Constant-time serialisation and deserialisation is a property to
investigate. Choosing a binary codec, or using constant-time AEAD, does not
establish it. The first revised example uses Serde traits provisionally.
Arbitrary user implementations of those traits cannot give that guarantee.

Before promising execution that does not depend on secrets, define which
lengths and shapes may be public. Also decide whether a stricter set of
supported types is needed. The examples document this open question
separately from how easy the wrapper is to use.

Investigate `serdect` as part of that work. Stack Encrypt already depends
on it. Check what its encoding and decoding guarantees are and what they
cover. Then judge whether it applies to serialising ciphertext and to the
proposed blob codec. Its current use does not imply a constant-time
guarantee for whole objects, or a codec choice.

## 9. Ownership of the value-encryption API across Stack and Vitamin C

**Status:** Open architectural discussion. Moving the traits is proposed.
It is not authorised implementation work. #1501 moves the Rust crates to
Vitamin C 0.9. `OpaqueEncode` now follows Vitamin C's `Scalar` marker for
which types are single values.

### Recommendation

Stack should own the public model for encrypting values. That includes:

- the plaintext traits and derives;
- target declarations;
- contexts;
- storing ciphertext;
- execution semantics.

Vitamin C can keep reusable primitives for cryptography and for protecting
memory. Moving files alone does not fix three problems:

- ambiguous names: for example, `Encrypt` currently describes a source;
- duplicate entry points;
- the missing path for whole values and storage.

One core layer owned by Stack could serve both Rust and language guests,
without pulling in KMS transport or HTTP. Applications should still have one
consistent entry point, `stack_encrypt`. An internal split of dependencies
should not become another public API that users have to understand.

### Where the proposal came from

The review kept crossing from Stack's target declarations into Vitamin C's
plaintext visitor traits, cipher traits, contexts, derives, and ciphertext
tree. The user proposes moving the encryption traits into Stack Encrypt,
and keeping general primitives, such as protected values and randomness, in
Vitamin C.

### Migration constraints

- Today `stack-encrypt` depends on both `vitaminc-aead` and
  `vitaminc-encrypt`, and `vitaminc-encrypt` also depends on
  `vitaminc-aead`. Moving the traits of `vitaminc-aead` into the top-level
  Stack crate, and making the existing backend depend on Stack, would create
  a dependency cycle. Either move the backend adapters for values too, or
  draw a separate boundary for a lower-level core of primitives.
- These must agree across the new consumers: context composition, type
  tags, ciphertext framing, index normalisation, and the transport frames of
  the bindings. On 25 October 2026 they could change without keeping
  prototype data and without a migration. Since 7 November 2026, stored
  data written by Go rc.3 must stay readable and searchable.
- Keep one canonical identity for each trait and type. Update consumers
  directly. Re-exports for compatibility are not needed. Independent copies
  of trait definitions would need duplicate implementations and adapters.
- Account for guest and FFI consumers and EQL target implementations, not
  only Rust application imports. The path without HTTP, for WebAssembly, must
  stay usable.

**Sources:** [Stack dependencies](../../packages/stack-encrypt/Cargo.toml),
[guest application binary interface (ABI) dependencies](../../packages/stack-guest-abi/Cargo.toml),
and
[EQL encryption adapters](../../packages/eql/crates/eql-bindings/src/encryption.rs).
The installed `vitaminc-encrypt` 0.8.0 manifest confirms that it depends on
`vitaminc-aead`.

## 10. The public encrypt_as duplicates encrypt_into

**Status:** Decision agreed. Still open: `encrypt_as` is still public on
`next`.

### Decision

Remove `encrypt_as` from the public API. Keep `encrypt_into` and
`encrypt_into_with_context` as the public entry points for encrypting into
a target:

```rust
let encrypted: EncryptedInteger = value.encrypt_into(&keyset).await?;
let encrypted: EncryptedInteger = value
    .encrypt_into_with_context(&keyset, context)
    .await?;
```

The machinery that executes operations can stay internal. Removing the
public method does not remove target declarations, batching, or execution.
Public examples of the proposed API should use the entry points that stay.
Earlier mentions of `encrypt_as` in this log describe the current code.

This is separate from issue 3's decision about ordinary encryption.
`keyset.encrypt(value)` stays the only spelling of ordinary `encrypt`.
`value.encrypt_into(&keyset)` selects a particular output type. The
question in issue 5 about the name and location of `encrypt_from` is still
open.

### Current behaviour

`KeysetCipher::encrypt_as` is currently an inherent method. It requires the
output to implement `EncryptFrom<S>`, and executes that target's operation
declaration. `EncryptInto::encrypt_into` and
`EncryptInto::encrypt_into_with_context` delegate to it. They supply either
the default context or the caller's context.

**Source:**
[target operations](../../packages/stack-encrypt/src/target/operations.rs)
(`KeysetCipher::encrypt_as`, `EncryptInto`).

## 11. Context fields do not yet take context from an input struct

**Status:** Still open. The syntax is still open. The shorthand
`context(field = "id")` is recommended. No merged pull request adds it.

### Current behaviour

`#[stash(context_field)]` exists on derived output types:

- On encryption, it stores the supplied context in that output field.
- On decryption, it uses the stored context. It can also check the stored
  context against an expected value that the caller supplies separately.

It does not automatically select a field from a plaintext input struct.

The macro treats this field as the complete context, and rejects it next to
a literal `context`. Because `struct = User` requires a literal context,
that form cannot mark its `id` with `context_field`. The public examples
first described passing the ID explicitly, without explaining this
difference.

### Clarified model: where context comes from and where it is stored

Two similar scenarios need to be told apart:

1. The caller supplies context as a function argument, and the encrypted
   output stores it for later use. This is what scalar-output
   `context_field` does today.
2. The encryption declaration takes context from one or more fields of the
   plaintext. Whether those values are also stored is a separate choice.

The second scenario can include storage too. It reads `User.id`, uses it to
bind the encrypted fields, and copies it into `EncryptedUser.id`. The caller
does not pass the same value twice. Several fields, such as a tenant ID and
a user ID, can supply a structured composite context.

| Context source | Stored in the encrypted output | What decryption needs |
| --- | --- | --- |
| Caller argument | Yes | Read the stored context. Optionally check it against an expected value supplied separately |
| Caller argument | No | Supply the same context again |
| One or more plaintext fields | Yes | Rebuild the context from the stored fields. Optionally check expected values |
| One or more plaintext fields | No | Supply equivalent context separately before decrypting |

Store a context taken from the source separately from the ciphertext that
needs it. Decryption then does not have to open that ciphertext first to
find its own context. Binding a ciphertext to a stored context
authenticates that relationship. It does not by itself prove that the whole
record is where the application expected it to be.

### Recommended syntax

The derive should express two separate concepts: selecting the source, and
storing in the output. A shorthand can cover the common case of reading and
storing. Do not assume that one `context_field` attribute should silently
do both.

The syntax is still open. Define each of these:

- the ordering and grouping of fields for a composite context;
- literal prefixes;
- optional caller extensions;
- `from` mappings;
- checks of expected context.

These capabilities are proposed, not implemented.

The recommended shorthand for the common case is `context(field = "id")`.
It expands exactly to `encrypt(field = "id"), decrypt(field = "id")`. It
selects the same Rust field name on the two different inputs. It does not
copy or store that field implicitly.

- Keep the directional form for different names or different sources.
- At first, reject mixing the shorthand with directional selectors, so
  that precedence is never ambiguous.

The context examples now use this shorthand for the case where a plaintext
ID becomes a stored ID.

**Sources:**
[macro validation](../../packages/stack-encrypt-derive/src/shape.rs)
(`Record::parse`, `context_type`) and
[context-field output assembly](../../packages/stack-encrypt-derive/src/encrypt.rs)
(`assignments`, `value_derive`).

## 12. Default is not the same as optional caller context

**Status:** Partly done. The directional-context examples showed this
problem. Pull request #1404 implements the first option below for the owned API. It adds `RequiredContext`, with the capabilities `AllowsNoContext` and `AcceptsContext`. #1501 adds compile-fail tests for a `u64` context. The
structural API still uses `Default`.

`EncryptInto::encrypt_into` and `DecryptFrom::decrypt_from` offer the form
without context whenever the associated `Context` type implements
`Default`. That works for types that are meant to have defaults, such as
`DeclaredContext` and `ExpectedContext`. It currently excludes
`CallerContext` and `AeadContext`.

A required caller value can still have a Rust default. If a declaration
exposes `Context = u64`, the form without context supplies zero. The
directional proposal `encrypt(caller = u64)` must not accidentally mean
"optional, with zero as the default".

Separate the application's type for the context value from the trait's
type or capability for caller input. Two options:

- a `RequiredContext<T>` wrapper with no default, accepting convenient
  conversions from `T`;
- a dedicated marker that controls the entry points without context.

Required context matters on decryption too. Context taken from the source
may need no argument for encryption. Decryption may need an external value,
or accept an optional expectation of the stored context. Do not assume that
the two associated input types must match. Do not assume that either one
always equals the complete logical context that encryption uses.

See the
[context scenario examples](2026-10-24-stack-encrypt-context-examples.md)
for the proposed selectors and what each one requires as input.

**Source:**
[convenience methods](../../packages/stack-encrypt/src/target/operations.rs)
(`EncryptInto::encrypt_into`, `DecryptFrom::decrypt_from`).

## 13. JSON layouts and adapting encrypted output

**Status:** Open. This is a first assessment of the JSON tree
implementation on the `next` branch at `b1049824b`. No replacement API is
chosen.

**Agreed follow-up:** investigate replacing the serialisation round trips in
the EQL JSON adapter with direct typed conversions. This does not yet choose
an extended visitor protocol, or authorise a particular replacement API.

### How JSON configuration and targets work today

`Layout<S>` describes a target that is selected by a value carrying run-time
options. It links a `Target: EncryptFrom<S>` with an `Index`. It supplies an
`encryption(&self)` description, and the configured index for queries.
`EncryptFrom<S>::encryption()`, by contrast, selects a description by
output type.

For JSON, both routes can produce `JsonDocument`:

- Selecting that type uses the default options.
- `Json::new(options)` can set ordered paths, and whether the root is
  sealed. Under a sealed root, the root entry's ciphertext contains the
  whole document, so it can be opened as a complete document.

A plan keeps those options for its queries.

This goes beyond choosing the field layout of a Rust record. JSON options
affect the cryptographic structure, what queries can do, and what
information is exposed to the server. The same output type can represent
different configurations, so the type alone does not identify the
configuration. The JSON tree belongs to the searchable-layout workflow
(issue 8). It is not an opaque serialised blob.

### The existing transcode protocol does a different job

The existing `target::transcode` protocol works at a later stage. A
`Reader` hands completed ciphertext, structural markers, metadata, and
search terms to a destination `Visitor`. `Encryption::transcode()` uses it
to adapt encrypted output without an intermediate serialisation tree. The
protocol does not choose JSON indexing options. It does not generate
missing search terms either.

The new EQL adapter takes another route:

- `JsonTree` implements `Layout<Value, Target = JsonTreeDocument>`. It
  delegates encryption to the engine's `Json` layout, and wraps the
  completed `JsonDocument` with EQL version and column metadata.
- Its envelope conversion goes through a `serde_json::Value` intermediate.
- A private helper that is also named `transcode` converts query types and
  extraction types. It calls `to_value`, then `from_value`.

Neither conversion is the existing `target::transcode` protocol. That
protocol has no reader or visitor event for a JSON document today. The
conversion processes encrypted output and query metadata. It is not a way
to skip plaintext serialisation.

On decryption, the EQL target checks its stored column against any expected
value supplied. It rebuilds the engine document through the wire form, and
delegates opening to the engine. Its layout object is not needed for that
conversion.

The sources for this section are:

- 
  [layout and operation descriptions](../../packages/stack-encrypt/src/target/operations.rs)
  (`Layout`, `json_document`, `EncryptFrom<Value> for JsonDocument`);
- 
  [encrypted-output protocol](../../packages/stack-encrypt/src/target/transcode.rs);
- [JSON options and document](../../packages/stack-encrypt/src/json/mod.rs);
- 
  [EQL JSON adapter](../../packages/eql/crates/eql-bindings/src/v4/json_tree.rs)
  (`JsonTree`, `JsonTreeDocument::envelope`, `transcode`, `DecryptInto`).

### Open questions about JSON configuration

- How should the API keep encryption configuration separate from adapting
  encrypted output?
- Is `Layout` the clearest public name for a configured target, given that
  this log earlier used "layout" for output records?
- How do run-time target options fit the `EncryptInto` API that stays?
  Today type-directed conversion selects the target's defaults, and plans
  accept a configured layout through `encrypt_with_layout`.
- Should JSON use a direct typed adapter for JSON documents, or an extended
  visitor for encrypted output? Do not force the JSON protocol into generic
  map and sequence events. Those events lose its header, shared document
  key, projection, and extraction semantics. A shared architectural boundary
  does not have to mean one universal visitor.
- Should a general abstraction for configured targets require an index?
  Today's `Layout` requires one, but targets that only encrypt can also need
  options.
- How does the design keep the link between write configuration and query
  configuration? A plan's reuse of the configured index is useful whatever
  the names are.

### Static Rust API compared with run-time configuration

The intended public Rust experience is traits and derives. Plans are the
lower-level composition interface. They support those APIs and the dynamic
FFI interface. Rust callers should not have to write a plan for JSON.

The derive already emits plans. Its implementation can keep that shared
execution path without making the plan builder the main user example.

JSON already has a type-directed path. Given an initialised `cipher` and its
`keyset`, this code uses existing methods and the default JSON options:

```rust
use eql_bindings::v4::json_tree::JsonTreeDocument;
use eql_bindings::Identifier;
use serde_json::{json, Value};
use stack_encrypt::{DecryptFrom, EncryptInto};

let profile = json!({"name": "Alice", "age": 34});
let column = Identifier::for_column("users", "profile")?;

let encrypted: JsonTreeDocument = profile
    .encrypt_into_with_context(&keyset, column.clone())
    .await?;

let restored: Value = encrypted.decrypt_into(&keyset, column).await?;
assert_eq!(restored, profile);
```

This produces searchable JSON with a sealed root and no ordered paths. The
explicit decryption context checks the expected column against the stored
identifier. The snippet was checked against the source, not compiled.

The earlier `SearchableEmail` example fixes its recipe in the target type:
ciphertext plus an equality term. `EncryptFrom::encryption()` takes no
configuration value. JSON's default target also fixes a recipe in its type.

What `Layout::encryption(&self)` adds is access to configuration on an
instance. One `JsonTreeDocument` output type can be produced with `$.age`
ordered, with `$.salary` ordered, or with different root settings, chosen
at run time. Its configured index also supplies the matching query
behaviour.

Search metadata itself does not require `Layout`:

- A custom target could fix ordered JSON paths in a manual `EncryptFrom`
  implementation, using the existing JSON operation.
- A derive could later generate such a fixed policy.
- Targets configured at run time need an extra configuration input. Today
  `encrypt_into_with_context` accepts context, but no layout or options.
  Custom JSON configurations use the lower-level plan, or the `keyset.run`
  path.

Keep those options separate from cryptographic context.

The cryptographic difference is separate from the API difference. JSON uses
a specialised document operation, with a shared document data key and its
own node and extraction semantics. Adding a generic equality-term field to
the ordinary ciphertext tree cannot implement it. That explains why the
JSON operation exists. It does not by itself require a public `Layout`
trait.

### Names hide the roles of the JSON types

| Current type | Role |
| --- | --- |
| `serde_json::Value` | Plaintext input, and recovered plaintext |
| `stack_encrypt::json::JsonOptions` | Run-time configuration |
| `stack_encrypt::target::Json` | Configured index. Also implements `Layout` |
| `stack_encrypt::json::JsonDocument` | Encrypted engine document, including search metadata |
| `eql_bindings::v4::json_tree::JsonTree` | Configured EQL target or layout |
| `eql_bindings::v4::json_tree::JsonTreeDocument` | Encrypted EQL storage envelope |

Review names that state these roles:

- `Encrypted` for documents that contain ciphertext;
- `Index` for index descriptions;
- `Target` or `Config` for configuration;
- module paths that separate EQL types from engine types.

No replacement names are chosen. Consider `Json`'s double role as index and
layout before renaming it.

### Candidate: a fixed-policy wrapper around the EQL output

This is a proposal. It is not implemented. Its syntax is not agreed.

The fixed policy is attached to an output newtype. The inner library type
defines the database format. The alias below only makes the existing
type's role clearer. It does not rename anything in the library.

The later [implementation plan](2026-10-24-stack-encrypt-api-plan.md)
recommends a general factory for typed options, `target(options = factory)`,
instead of the JSON-specific attribute below. Dynamic callers deserialise
options into the same concrete type. Rust and Go support ship together. This
log keeps the sketch to explain the earlier alternative.

```rust
use eql_bindings::v4::json_tree::JsonTreeDocument as EqlEncryptedJsonTree;
use eql_bindings::Identifier;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use stack_encrypt::{DecryptFrom, DecryptInto, EncryptFrom, EncryptInto};

#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[serde(transparent)]
#[stash(
    plaintext = Value,
    transparent,
    json_tree(ordering_paths = ["$.salary"])
)]
struct EncryptedPayroll(EqlEncryptedJsonTree);

// Given a keyset:
let payroll = json!({"name": "Alice", "salary": 120_000});
let column = Identifier::for_column("employees", "payroll")?;

let encrypted: EncryptedPayroll = payroll
    .encrypt_into_with_context(&keyset, column.clone())
    .await?;

// The wire representation is the inner EQL envelope, with no extra field.
let wire = serde_json::to_vec(&encrypted)?;
let loaded: EncryptedPayroll = serde_json::from_slice(&wire)?;
let restored: Value = loaded.decrypt_into(&keyset, column).await?;
assert_eq!(restored, payroll);
```

The proposed `stash(transparent, json_tree(...))` selects the configured
JSON operation for the inner target, and wraps its completed output. It
must not:

- run the ordinary scalar or record derivation on the wrapper;
- run the inner target's default encryption and then try to add ordering
  terms.

The wrapper inherits the EQL target's caller context and decryption
behaviour. Serde's existing `transparent` attribute keeps the EQL envelope.
It does not provide trait implementations for database drivers. Those stay
a separate integration concern. Under this candidate's defaults, the root
stays sealed.

The generated declaration must also expose the configured index metadata
for future typed queries. Queries can then reuse the policy instead of
repeating the paths. The syntax for queries is not designed yet. The core
derive must delegate the construction of configured output to a capability
of the inner target, instead of depending directly on the EQL crate. It is
still open whether `Layout` or another trait expresses that capability.

### Alternative: configuration on a plaintext wrapper

The user proposed `JsonPlaintext::new(value).with_ordering_path(path)`. It
can still produce the exact EQL wire format. Where the configuration comes
from is independent of the output representation.

An explicit
`EqlEncryptedJsonTree` target can accept that input and execute the same
configured JSON operation. The wrapper must be treated as an encryption
request, and not serialised as part of the plaintext. The current API does
not provide this wrapper.

This wrapper is attractive when paths come from run-time configuration.
However, it repeats a fixed policy at each call site, and needs a way to
reuse that policy for queries. For the fixed-policy example, prefer the
output newtype.

If the run-time wrapper is added, do not implement conversion from it into
fixed-policy targets at first. This avoids silently overriding or merging
conflicting policies. Neither syntax lets callers redefine EQL's required
fields or its cryptographic wire protocol.

A fixed Rust type describes the policy for new writes. Transparent Serde
deserialisation alone does not prove that a stored document used that
policy. The document header does not record all ordered paths. Policy
changes, and existing rows written with different policies, need explicit
compatibility and migration rules. Only then can the API claim stronger
guarantees when it reads.

## 14. Decrypt convenience methods need explicit context variants

**Status:** Partly done. #1404 implements `T::decrypt_from` and
`decrypt_from_with_context`, and the keyset pair, for one value. #1501
adds them for collections. The structural `decrypt_into` remains in
`target::legacy`.

**Required direction:** provide a method without context and a separate
`_with_context` method, mirroring encryption. The user prefers the name
`decrypt_from`.

**Recommendation:** use the pair directed at the destination in the
preferred public examples. `User::decrypt_from(encrypted, &keyset)` follows
Rust's `From` convention. `encrypted.decrypt_from(...)` would reverse it.

These are not settled user decisions. Do not change the declaration trait
only because its convenience spelling changes. Handle trait discoverability
with issue 5, and the capability for optional context with issue 12.

### Current behaviour

These methods exist today on the blanket extension trait `DecryptFrom`:

- `ciphertext.decrypt_into(cipher, context)`;
- `Plaintext::decrypt_from(ciphertext, cipher)`;
- `Plaintext::decrypt_from_with_context(ciphertext, cipher, context)`.

Since #1404, these three methods are in `target::legacy::DecryptFrom`. The
crate-root `DecryptFrom` is the owned trait, with `decrypt_from` and
`decrypt_from_with_context` and no `decrypt_into`.

`DecryptInto<P>` separately declares the opening operation. These method
and trait names are easy to confuse.

## 15. Coordinate the Go JSON work with the shared API redesign

The user identified
[pull request #1353](https://github.com/cipherstash/stack/pull/1353) as
work by a parallel agent. The pull request is currently a design document
for Go JSON, with implementation tasks #1348 to #1352, tracked by #1347.

These parts of it must be reconciled with the contracts for configured
targets, traits, and context developed here:

- its dynamic path for JSON and options;
- its public names;
- its context behaviour;
- its staged support for extraction.

Keep the compatible work on the catalog, the transport, the engine, and
testing. Do not design it twice, and do not implement it twice.

The [implementation plan](2026-10-24-stack-encrypt-api-plan.md) records the
specific points to reconcile, written after reading the pull request. This
is a local coordination item. No message or review was posted to that agent
or pull request.

## 16. Integrate the prior query design instead of reopening it

The user supplied **Stack Encrypt query design**, dated 21 October 2026. It
was read in full on 25 October 2026 from
`/Users/dan/Downloads/Stack Encrypt query design.md`. It is explicitly a
draft for discussion, with open questions. It proposes:

- index selection owned by the field;
- one index that answers each operator;
- typed field handles;
- one declaration of capabilities;
- shared rules for deriving and refusing queries.

The [implementation plan](2026-10-24-stack-encrypt-api-plan.md) now uses
that draft as the baseline. The plan records specific points to reconcile:

- this log's output-side derives and factories for configured options;
- JSON operators and extraction;
- context inputs;
- portability between the static and dynamic interfaces;
- when validation happens.

The user's clarification about the prototype replaced older compatibility
requirements. The decision of 7 November 2026 adds one back: the stored
format of Go rc.3 must not break. The source document was not changed.

## 17. Use the same name to select a definition for encryption and queries

**Status:** Still open. `.using(...)` is recommended. The final spelling is
not yet accepted.

The user finds it confusing that encryption uses `.using(...)` and queries
use `.on(...)`, and asked to consider one name for both. The recommendation
is `.using(...)`, because the selected definition or field supplies the
operation's policy.

Keep the bounds specific to each operation. This is a change of name, not
a merger of the two capabilities:

- Encryption selects the associated definition of the output target.
- Queries require a field, or a single-value target, that implements
  `QueryTarget<Op, Input>`.

The user also prefers `cipher.using(&field).query(op, input)`. They
explicitly require strict typestate: the request's type records which steps
are done, so the compiler refuses an incomplete request. They accept
supporting both orders. The plan recommends putting the definition first as
the canonical order. The order that starts with the operator then produces
the same typed request.

On the static path:

- a missing definition, or missing required context, must prevent awaiting
  the request;
- selecting a definition again must not silently replace the request's
  definition.

This log does not claim that the current `.query(...).on(...)`
implementation already provides this API.

## 18. A single ciphertext needs inputs that are consumed and cleaned up

**Status:** Decided on 25 October 2026, with the follow-up decisions below.
Partly done: #1404 and #1501 guard and wipe owned sources, and #1493 adds
lifecycle conformance. No completed audit is claimed.

### Decision on encoding traits and consumed input

**Decided on 25 October 2026.** Use `OpaqueEncode` and `OpaqueDecode` to
encode and decode single values. These names separate one opaque ciphertext
from target layouts.

Both direct `encrypt` and target-directed `encrypt_into` consume their
input, including the variants that take context. Both are responsible for
cleaning up the owned plaintext data they create. Explicit passthrough
fields move to the output.

The plan records:

- what cleanup each source must support;
- guarding immediately, before returning a request that has not been
  polled;
- cleaning up encoded buffers and scratch space on every ordinary exit
  path;
- the limits for copies held by the caller, custom serialisation,
  passthrough output, and ownership between the Go host and the guest.

`Serialize` alone cannot ensure that an `OpaqueBlob<T>` source is cleaned
up. Consuming a value and zeroising it are different things.

### Follow-up decision: use the existing Zeroize trait

Plaintext types must implement the existing `Zeroize` trait. Do not add a
cleanup trait of our own for now. For the proposed Serde blob, this means
`Serialize + Zeroize` on input, and `DeserializeOwned + Zeroize` on owned
decoding. Library guards must actually call the cleanup. Serde values that
are only partly built need separate handling.

### Decryption decision

Keep `keyset.decrypt` and `decrypt_with_context` for ordinary opaque
ciphertext. Keep `T::decrypt_from` and `decrypt_from_with_context` for
declared targets. On success, return an ordinary owned `T: Zeroize`. This
hands the cleanup responsibility to the caller.

Stack guards intermediate plaintext values while Stack is their owner. Support
results with an explicit drop guard, but do not make them the default.
`Zeroize` alone does not mean the value is cleaned up when dropped. This
does not resolve the separate requirement to clean up after a partial
deserialisation.

### Codec recommendation

Reuse Vitamin C's frame machinery with a mapping for blobs. The 0.8.0 Serde
implementation for transport already exists and guards serialisation
buffers. Its frame writer wipes allocations when they grow.

Do not reuse that mapping unchanged, for three reasons:

- It can lose whether an option is present: `Some(())` and `None` both
  encode as null.
- Maps require text keys.
- A successful `to_vec` returns a vector with no guard.

The
[opaque blobs](2026-10-24-stack-encrypt-api-plan.md#opaque-blobs) item in
the API plan records the codec now chosen: Vitamin C's storage profile.
Go rc.3 already writes that format. Neither the codec choice nor the `Zeroize`
bound establishes constant-time behaviour, or cleanup after partial
decoding.

### Priority update

First specify stable, versioned storage bytes. The existing frame codec was
designed for short-lived transport. Later improvements to zeroisation and
timing can follow without changing the stored format. The action needed
upstream is
[Vitamin C #519](https://github.com/cipherstash/vitaminc/issues/519).

## 19. First-release completeness and remaining review decisions

**Status:** The decisions below were accepted on 25 October 2026. The
detailed JSON operation contract is still under user review. Partly done:
#1492 enrols the JSON operations in conformance. Opening a child bound to
its parent is still open.

### Encoded ciphertext and equality

- Encoded ciphertext wrappers are first-class field targets. Their final
  names and package placement are decided last.
- ORE does not answer equality at first, even for integers.
- Allow for a future explicit capability for encodings that preserve
  equality. Never infer exact equality from ordering support for text or
  other lossy encodings.
- Keep the validation that checks for overlapping operator providers.
  Avoid silently changing existing definitions.

### The JSON first version must be comprehensive

The first JSON version must be comprehensive across Rust and the dynamic
interface for Go. It includes extraction, opening entries, listing and
counting children, and walks over subtrees. Claude's earlier Go plan
deferred walks. The new scope replaces that deferral.

The
[operation contract and examples](2026-10-25-stack-encrypt-json-operations.md)
lists:

- the operations required;
- the current evidence;
- the proposed Rust and dynamic APIs;
- how SQL uses them;
- the rules for missing paths and null;
- the acceptance checks for implementation.

Names and packaging are explicitly the last design activity.

### Further accepted decisions

- Custom Rust stages can stay explicitly Rust-only, and use `NotPortable`
  where dynamic export is not supported. Built-in stages keep parity between
  Rust and Go.
- Every check that does not need a key runs before keys are resolved or
  loaded.

## 20. Keysets chosen from plaintext, and optional provider policies

**Status:** Still open. The recommendations below are not yet accepted.

### Request

The user asked for three things:

- route a plaintext record to a keyset, by ID or name, taken from one of its
  fields;
- an assessment of Vitamin C's unused `AsyncCipher`;
- ZeroKMS lock context, including selectors for claims in the principal's
  JWT (JSON Web Token). Lock context is a ZeroKMS feature that binds a data
  key to claims about the authenticated identity, the principal, that makes
  the request.

Keyset and lock-context capabilities must stay optional, for future AWS KMS
and Vault backends. The
[provider capabilities assessment](2026-10-25-stack-encrypt-provider-capabilities.md)
gives the current evidence from the source, proposed static and dynamic
declarations, and the work needed for acceptance.

### Current facts

- Stack resolves keysets by ID or name, but each generation batch uses one
  keyset chosen beforehand.
- Stack deliberately coordinates provider requests outside Vitamin C's walk
  over leaves, and already implements the synchronous `Cipher`.
- Its layer for provider payloads supports lock context, but Stack Encrypt
  sends an empty lock context.
- The existing abstractions for data keys and index keys still embed
  ZeroKMS protocol types. Future providers need a neutral base plus optional
  capabilities, not empty implementations of required ZeroKMS features.

### Recommendations

- Derive key routing as an explicit target selector, and resolve it in the
  client executor.
- Split batches by the key, provider, and principal requirements they
  resolve to.
- Carry lock context as a separate typed provider policy, on both key
  generation and key retrieval.
- Reject unsupported required features before any I/O.
- Keep these four things separate: key routing, ciphertext context, search
  scope, and principal policy. Search scope is the set of values that index
  terms are derived under, such as a column and a tenant. A query can then
  match every row in that scope.
- Revisit cleanup of the cipher adapters during packaging. Do not lose
  batching across records, or native and WebAssembly support.

## 21. Packaging, naming, and retiring AsyncCipher

**Status:** Still open. The names and package moves are proposals. Pull request #1404 uses some agreed names. No package has moved.

The user favours removing Vitamin C's `AsyncCipher`, and moving encryption
behaviour for applications into Stack Encrypt. The
[packaging recommendation](2026-10-25-stack-encrypt-packaging.md) proposes:

- Stack owns value traversal, declarations, target adapters, index
  adapters, and execution;
- a small shared `stack-encrypt-format` crate contains codecs and typed
  encodings;
- a client crate specific to ZeroKMS;
- reusable primitives stay in Vitamin C.

It includes a dependency map with no cycles, and a glossary of public names.

Stack does not use `AsyncCipher`. Vitamin C's async helpers and tests do
use it. Retire that execution path together with its consumers, and move the
relevant test coverage. Deleting the trait alone is not complete.

The adapters for normalisation, PRF (pseudorandom function), and ORE also
depend on the existing value model. They need to be separated from their
primitives.

Moving the frame implementation refines the earlier recommendation about
who owns the codec. Coordinate the work on stable storage under
Vitamin C #519.

## 22. Customer-driven order of work: Go JSON and match search first

**Status:** Order of work set by the customer's needs. Merged work
reconciled on 7 November 2026. The conformance corpus is merged.

### The customer's needs come first

The customer needs Go JSON support. They also need dependable Bloom-filter
handling with tokenizers and token filters, including input of two
characters. The quality of a standalone Rust release is secondary.

- Claude's stack of JSON-tree pull requests, headed by #1363, has now
  merged. Revise the older Go plan in #1353 against it, and against the
  agreed API direction.
- Vitamin C #520 and #526 implement the storage profile: Vitamin C's versioned byte format for an opaque value that is stored. Review by a
  colleague, and the release, are pending. Stack still needs to adopt that
  release.

### What to freeze before the customer release

Freeze the public Go contract, and the stored binary and search semantics,
before the customer release. Internal plans can change behind that
interface.

Adopt and stabilise the Vitamin C codec in its current repository now.
Defer these:

- moving crates physically;
- retiring `AsyncCipher`;
- the final Rust derives.

The earlier exemption for prototype compatibility does not allow breaking
customer data. Since 7 November 2026, that applies from now, not only
after the final release, because the customer builds on Go rc.3.

### Short words in match search

The supplied `Short-ngrams.md` explores Bloom filters for short whole words,
and queries over variants. These must be kept separate from search for any
two-character substring.

The current tokenizer allows a length of 2. To support named filters and
Boolean alternatives, these need to grow:

- the current output of one match;
- the current shapes of a single query term and a range query term.

Resolve the scheme's leakage, its SQL representation, and its performance
before the release. Do not silently defer the customer's requirement.

### Reconciliation with merged work, 27 October 2026

This review compared `next` at `ffeed7adb3f7d8739cda53261046147852bffc82`
with the previous baseline, `ebdb5de0a`.

#### What the merged Go work provides

Pull requests #1372, #1373, #1378, and #1402 provide:

- the Go JSON catalog;
- configured targets;
- operators;
- reads that Rust verifies against the original request. A prepared read
  keeps its request, and Rust derives and checks the selectors and read keys
  again from that request when it opens rows;
- adapters for typed documents;
- documentation that runs as code.

Items #1347 to #1352 are closed. Pull requests #1369 and #1370 integrate
opaque storage in Go. Final Go releases still need the temporary Vitamin C
pseudo-version pins replaced. Rust dependencies stay on 0.8.0.

#### Cascaded tags and random order

Pull request #1379 adds cascaded tags: each container's tag covers the tags
of its children. It also randomises the order of stored entries and of
projections. A wildcard `->` returns an unspecified match, not the first
element of the document.

The format to freeze is the data written after #1379. The header version is
still 1, but that does not mean the data is compatible with the old
prototype AAD. Verification on read still does not authenticate that a
result is complete, that something is absent, or which database row it
came from.

#### Short-word terms

Pull request #1397 implements short-word terms that are deterministic and
domain-separated, inside the existing Bloom filter. EQL's pinned match configuration turns them on. This avoids a separate index for short words.

It is not the random-variant mechanism explored earlier. It does not by
itself resolve the user's concern about frequency and leakage. The native Go
index options still refuse configuration (#1112). The uncommitted research
on ngrams and the Go delivery document are unchanged.

#### Remaining work

The refreshed API plan and the JSON operation inventory mark landed work as
implemented. The remaining items include:

- the formal interoperability specification and conformance corpus;
- opening a child bound to its parent;
- configurable match pipelines in Go;
- direct typed EQL conversion;
- later, separating the roles of context.

The customer release does not wait for the final Rust traits or crate
moves.

### Reconciliation with merged work, 7 November 2026

This review compared `next` at `e4990e49b` with the previous baseline,
`ffeed7adb`. It read each pull request description, and the code where the
description was not enough. It ran no test suite.

#### What merged

- #1404 adds the owned API for one value. #1501 extends it to `Vec<S>`, and
  moves the Rust crates to Vitamin C 0.9.
- #1491 makes repeated Rust context extensions append in order, as Go
  already did.
- #1460, #1461, #1462, #1469, #1491, #1492, and #1493 add a conformance
  corpus that native Rust and the Go guest both run.
- #1444, #1445, #1446, #1451, and #1452 add element-scoped and jsonpath
  predicate queries over JSON documents, in the engine, EQL, and Go.
- #1500 documents Go `v0.1.0-rc.3`. That version was tagged on 2 November 2026.
- #1403 fixes findings on the release candidate, and bumps the crate
  versions that `stack-encrypt` 0.3.0 needs.

#### Remaining work on 7 November 2026

- the specification around the conformance corpus: versions, schemas,
  and the Python and TypeScript runners;
- opening a child bound to its parent;
- configurable match pipelines in Go;
- direct typed EQL conversion;
- freezing the release candidate's stored format;
- later, separating the roles of context.

#### Differences from the plan

#1501 encrypts `Vec<u8>` as one value. The plan had recommended encrypting
it byte by byte. On 7 November 2026, the user agreed with #1501: a byte
string is one value, and a `Vec` of byte strings is a collection.

#### What the reconciliation of 27 October 2026 checked

This review inspected the source and the existing tests. It did not run the
run-time or database test suites again, and it changed no production code.
