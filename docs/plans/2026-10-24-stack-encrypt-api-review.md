# Stack Encrypt API review

Started: 2026-10-24. Scope: the current Rust `stack-encrypt` API, starting
with encrypting one `i32` into opaque ciphertext and storing the result.

Companion: [complete public workflow examples](2026-10-24-stack-encrypt-public-examples.md),
an API design draft covering encryption, persistence, decryption, and queries.
The [directional context examples](2026-10-24-stack-encrypt-context-examples.md)
explore context sources and storage using Serde-inspired attribute syntax.

This is a running issue log. Add a numbered section as each issue is found;
keep observations, proposed changes, and unresolved decisions distinct.
All issues below remain unimplemented. Individual decisions are recorded
within each issue; proposed APIs are illustrative, not implemented.

## 1. Cipher trait mismatch and explicit context ergonomics

**Status:** Open.

### Current behavior

`KeysetCipher::encrypt` is an inherent method, not a trait method:

```rust
let ciphertext = keyset.encrypt(42_i32, ()).await?;
let ciphertext = keyset.encrypt(42_i32, "users/age").await?;
```

Vitamin C (`vitaminc-aead` 0.8.0) provides both `Cipher` and `AsyncCipher`.
Stack implements the synchronous `Cipher` trait on internal adapters after
fetching keys: `MintedKeys` seals leaves and `BoundKeys` opens them. Neither
public cipher implements `AsyncCipher`, so callers cannot use
`KeysetCipher` directly with generic Vitamin C code requiring that trait.

Each internal adapter implements only half of `Cipher`: `MintedKeys::open`
and `BoundKeys::seal` always return errors.

### Why the mismatch exists

`AsyncCipher` already supports batching through `seal_many` and `open_many`;
batching alone does not explain the separate API. Its methods receive each
leaf's derived AAD, while ZeroKMS needs the original structured context's
descriptor. That original context is not carried by the derived leaf AAD.
Stack's pending-operation layer also combines key requests across documents,
fields, and rows, beyond the trait's per-document batch interface.

These constraints need to survive any trait integration. The current
separation is deliberate, but leaves an interoperability gap and internal
implementations with unsupported operations.

### Requested API direction

Requiring an empty tuple for the common case of no application AAD is
unnecessary ceremony. Use distinct methods, following the convention used
elsewhere:

```rust
keyset.encrypt(42_i32).await?;
keyset.encrypt_with_context(42_i32, "users/age").await?;
```

The no-context method should select the same empty context currently
represented by `()`. This distinction should exist even if `KeysetCipher`
continues to use inherent methods rather than implementing a Vitamin C trait.

### Open design questions

- Can a context-bound adapter implement `AsyncCipher`, or should Vitamin C's
  interface preserve the original context explicitly?
- How does that integration preserve batching across multiple documents?
- Should sealing and opening be separate trait capabilities, avoiding methods
  that are present but always fail?
- Should decryption expose the corresponding `decrypt` /
  `decrypt_with_context` distinction?

**Source:** [cipher implementation and rationale](../../packages/stack-encrypt/src/cipher.rs)
(`KeysetCipher::encrypt`, `MintedKeys`, `BoundKeys`, and the module's batching
discussion). Vitamin C trait definitions are in `vitaminc-aead` 0.8.0,
`src/seal.rs`.

## 2. The Node / SealedValue boundary complicates opaque ciphertext storage

**Status:** Open.

### Current behavior

`KeysetCipher::encrypt` returns `StackCipherText`, an alias for Vitamin C's
`Node<SealedValue>`. Encrypting an `i32` produces `Single(SealedValue)`, but
the return type also admits sequences, maps, empty containers, and passthrough
nodes. It does not retain the plaintext type as a type parameter.

| Capability | `StackCipherText` tree | `SealedValue` leaf |
| --- | --- | --- |
| Debug printing (`{:?}`) | Yes | Yes |
| Serde serialization/deserialization | No | Yes |
| Canonical byte encoding | None | `to_bytes()` / `from_bytes()` |
| Direct Base64 conversion | None | None; encode the canonical bytes separately |

The leaf's canonical bytes include its keyset id, key retrieval metadata,
and local ciphertext. That versioned byte format is the storage commitment;
the leaf's Serde representation is not the same compatibility commitment.

### Caller impact

Even the scalar storage path requires exposing the container representation:

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

The caller must handle a shape mismatch that cannot occur for this input,
extract the leaf, and reconstruct the node to decrypt. There is no direct
`ciphertext.to_bytes()` or `serde_json::to_string(&ciphertext)` path. Base64
adds a separate encoding step. Collections additionally require the caller
to choose a representation preserving the tree structure and node variants.

Stored bytes are not sufficient by themselves to decrypt: the caller still
needs authorized ZeroKMS access and the same application context. The storage
API should make that requirement clear without exposing tree internals for
the simple scalar case.

### Proposed direction and open decisions

Provide a straightforward opaque ciphertext storage round trip for scalar
values, with direct byte conversion and reconstruction. Decide whether this
means a dedicated scalar result type, a wrapper, or conversion helpers on
the existing API.

Also decide whether Base64 and Serde should be supported conveniences, and
whether whole-tree serialization belongs in Stack or remains caller-owned.
If it remains caller-owned, make that distinction explicit and keep it out
of the simple scalar path. Preserve the existing canonical leaf encoding;
an ergonomic improvement should not require changing stored ciphertext.

**Sources:** [ciphertext alias and leaf encoding](../../packages/stack-encrypt/src/cipher.rs)
(`StackCipherText`, `SealedValue`) and
[storage documentation and public re-exports](../../packages/stack-encrypt/src/lib.rs).
Vitamin C's container definition is in `vitaminc-aead` 0.8.0,
`src/container.rs`.

## 3. Plaintext-side encryption has different syntax and context requirements

**Status:** Open.

### Current behavior

The current Vitamin C `Encrypt` trait describes a plaintext through `visit`;
it does not provide an `encrypt` method. Importing Stack's re-export of that
trait does not enable `10_i32.encrypt(&keyset)`. Vitamin C 0.8.0 documents
this trait as replacing the older visitor-based trait that drove a cipher
directly. Its `ContextTag` wrapper has encryption methods, but those require
Vitamin C cipher traits and do not make the syntax available on bare integers
or accept Stack's public ciphers directly.

Stack supplies its own blanket `EncryptInto` extension trait:

```rust
use stack_encrypt::{nonempty, EncryptInto, StackCipherText};

let ciphertext: StackCipherText = 10_i32
    .encrypt_into_with_context(&keyset, nonempty!("users/age"))
    .await?;
```

The output type selects the `EncryptFrom` implementation. For
`StackCipherText`, that implementation requires an `Encrypt + Clone` source
and an `AeadContext`, which must be nonempty.

Although `EncryptInto` also has `encrypt_into(&keyset)`, that method requires
the target's context to implement `Default`. `AeadContext` does not, so this
no-context form cannot produce `StackCipherText`. It is available for other
targets with default contexts, such as declarations carrying their own
contexts.

The scalar derive's implicit context choice is also a discoverability concern:
`#[stash(plaintext = i32)]` generates `type Context = CallerContext`, even
for a record containing only a `StackCipherText` field (whose own context is
`AeadContext`). The generated operation converts between those types. The
reviewer found that hidden choice surprising; whether it needs an API change
or clearer diagnostics/documentation remains undecided. The `Default` bound
belongs to `EncryptInto::encrypt_into`, not to the `EncryptFrom` trait itself.

### Caller impact and open decisions

Plaintext-side encryption exists, but is not a symmetric spelling of
`keyset.encrypt(value, context)`: it uses different method names, selects an
output through a target trait, adds a `Clone` bound for this output, and
refuses the empty context accepted by the inherent method.

Resolve the differing empty-context requirements alongside issue 1;
renaming alone would not make the two paths equivalent. This inconsistency
is separate from the receiver choice below.

### Receiver choice: plaintext or keyset?

**Decision (2026-10-24):** use only the keyset receiver for the ordinary
`encrypt` method:

```rust
tenant_keyset.encrypt(value).await?;
```

Do not add a plaintext-side `value.encrypt(&keyset)` counterpart.
**`EncryptInto` remains.** This decision concerns only the `encrypt` method,
not removal of the target-directed encryption API. Implementation is pending;
the current inherent method still requires its context argument (issue 1).

The two receiver forms express the same inputs and operation. Neither inherently provides
better type safety, ownership behavior, performance, or batching; those
depend on the signatures and implementation, not which argument is `self`.

| Consideration | Plaintext receiver | Keyset receiver |
| --- | --- | --- |
| Mental model | Transform this value using a capability | Ask this encryption capability to process a value |
| Discoverability | Requires importing an extension trait; methods appear on plaintext types | Encryption methods are found on the encryption handle |
| Fluent composition | Reads naturally after an expression producing plaintext | Reads naturally when selecting a keyset before an operation |
| Operational scope | Keyset and its authority appear as an argument | Keyset and its authority lead the call |
| API surface | Adds methods to primitives and application types | Keeps execution methods on library-owned handles |
| Generic integration | Can work through a cipher trait | Can work through a cipher trait |

**Rationale:** Stack performs an asynchronous operation through a configured KMS
capability; putting that capability first makes its scope visible and gives
callers one place to discover operations. Plaintext traits can describe how
values are represented without also owning the execution API.

Keeping both equivalent spellings adds documentation, completion, and naming
choices without adding capability. Familiarity with an earlier API is a
migration consideration, but does not by itself justify two permanent entry
points.

The target-directed `EncryptInto` surface can choose outputs other than
ordinary ciphertext and is retained explicitly. Its context inconsistency
remains open independently of this receiver decision. No decision about
decryption or batch method receivers is made here.

**Sources:** [plaintext-side methods and ciphertext target implementation](../../packages/stack-encrypt/src/target/operations.rs)
(`EncryptInto`, `EncryptFrom<S> for StackCipherText`) and
[context types](../../packages/stack-encrypt/src/target/context.rs)
(`AeadContext`). Vitamin C's source trait is in `vitaminc-aead` 0.8.0,
`src/plaintext/mod.rs`.

## 4. The scalar derive cannot declare a fixed literal context

**Status:** Direction agreed; implementation pending.

The desired combination is a derived output for a bare `i32`, a fixed
context declared on that output, and `10_i32.encrypt_into(&keyset)`.
The current macro rejects `#[stash(plaintext = i32, context = "example")]`:
the literal `context` attribute is supported only with `struct = ..`.

A supported derive-only workaround wraps the integer in a plaintext struct:

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

This form declares the field's context as the pair `("example", "value")`,
rendered as the ZeroKMS descriptor `example/value`, and uses defaultable
`DeclaredContext` for optional caller extensions. It is not a direct
conversion from a bare integer. A manual `EncryptFrom<i32>` implementation
can supply its own context; the ordinary literal attribute cannot express
that on a scalar derive today.

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

With a fixed context, the generated operation supplies that context and
exposes a defaultable caller-context type, enabling `encrypt_into`. Without
a fixed context, the ordinary scalar derive continues to use `CallerContext`
and requires `encrypt_into_with_context`. Preserve explicit `context_type`
and `context_field` configurations; their interaction with a fixed context
needs validation rules rather than a silent override.

This addresses the scalar gap at the derive layer without requiring
`CallerContext` itself to implement `Default` or changing the `EncryptFrom`
trait. A bare scalar has no input field from which the derive can extract
context; runtime context can still be supplied by the caller.

Additional caller context is accepted. The existing mechanism to reuse is
`DeclaredContext::under(own)`, exposed on operation descriptions through
`Encryption::under(own)`. `DeclaredContext` implements `Default`; its empty
default preserves the declared context unchanged. A caller extension is
combined as `(own, caller)`, never substituted for the declared context.

Recommended combination semantics follow this existing mechanism:

| Caller input | Effective structured context, with static context `C` |
| --- | --- |
| No extension | `C` |
| One extension `P` | `(C, P)` |
| Successive extensions `P`, then `Q` via `DeclaredContext::with` | `((C, P), Q)` |
| One extension containing the pair `(P, Q)` | `(C, (P, Q))` |

This is structured composition, not string concatenation. Order and grouping
matter, and decrypt must reproduce the same structure. `NonEmpty::with`
builds the corresponding pairs directly. The existing test
`under_gives_a_subtree_its_own_context_which_the_callers_extends` in
[target.rs](../../packages/stack-encrypt/tests/target.rs) verifies that an
operation's declared context plus a caller extension agrees with a directly
composed context.

The exact representation of a static literal (notably text versus a parsed
path label) still needs to be specified when implementing the derive, so
the descriptor and AEAD context remain consistent across encryption and
decryption. This decision is separate from retaining the `EncryptInto` trait.

**Sources:** [macro validation](../../packages/stack-encrypt-derive/src/shape.rs)
(`a_container_context_requires_a_struct`) and
[generated implementations](../../packages/stack-encrypt-derive/src/encrypt.rs)
(`struct_derive`, `value_derive`).

## 5. EncryptFrom does not define encrypt_from

**Status:** Open.

`EncryptFrom<S>` defines the associated type `Context`, the operation-description
constructor `encryption()`, and `indexes()`. It does not define a function
named `encrypt_from`.

A function with that name does exist, but on the blanket extension trait
`EncryptInto`: `Target::encrypt_from(&value, &keyset, context)` delegates to
`keyset.encrypt_as`. Calling that function requires `EncryptInto` in scope
and a target implementing `EncryptFrom<S>`.

This differs from the standard Rust naming relationship: `From<T>` defines
`from`, while `Into<T>` defines `into`. The names suggest that same
relationship here, but `EncryptFrom` declares an operation rather than
executing a conversion, and the target-side execution function belongs to
the source-side extension trait. That makes method discovery and the
required trait import surprising.

Review the trait and method names, or where the convenience function lives,
while preserving the distinction between declaring an operation and
executing it. No replacement design has been selected.

**Source:** [target operation traits](../../packages/stack-encrypt/src/target/operations.rs)
(`EncryptFrom`, `EncryptInto`, including `EncryptInto::encrypt_from`).

## 6. Plan builder encrypt_into reads like the execution method

**Status:** Open; revisit during the plan API discussion.

`Plan::value::<S>().encrypt_into::<T>()` is an inherent builder method that
selects an output target requiring `T: EncryptFrom<S>`. It does not implement
`EncryptInto` or execute encryption. Sharing the name with
`value.encrypt_into(&keyset).await?` caused confusion during this review.

Consider renaming the builder method to `target`:

```rust
Plan::value::<S>()
    .target::<StackCipherText>()
    .build()
```

This names the selection being made and distinguishes it from executing a
conversion. The rename is a proposal for later discussion, not a decision
or an implemented API change. `EncryptInto::encrypt_into` remains unchanged
by this proposal.

**Source:** [value plan builder](../../packages/stack-encrypt/src/plan/value.rs)
(`ValueStart::encrypt_into`).

## 7. Mixed encrypted and plaintext fields lack a direct output-derive spelling

**Status:** Passthrough attribute proposal accepted in principle; implementation pending.

For a `User` with encrypted `name` and `email` and plaintext `id` and
`created_at`, the fields-plan API directly supports `.encrypt(pick(..))`
and `.passthrough(pick(..))`. It batches the encrypted fields and returns
`FieldValues`; callers can extract those values into a typed storage struct.

The current `EncryptFrom` derive has no passthrough/copy attribute for source
fields. `#[stash(default)]` initializes an output from a default or expression;
it does not copy a field from the input. Merely keeping the original field
type does not select passthrough either: derived fields require target traits.

The proposed `#[stash(passthrough)]` attribute on output fields was accepted
as sensible: it copies the matching source field unchanged, alongside fields
whose types select encryption. Plaintext passthrough fields remain unencrypted and
unauthenticated; making a field part of the encryption context is a separate
choice, not implied by copying it.

This gap is specific to Stack's output-side `EncryptFrom` derive. Vitamin C
already has plaintext-side `#[derive(Encrypt, Decrypt)]` with
`#[aead(passthrough)]` on source fields. Stack's `keyset.encrypt(&user, aad)`
can consume that derived source, yielding a generic `StackCipherText` map
with sealed and passthrough nodes. It does not generate a named
`EncryptedUser` type or expose the output as typed Rust fields. Its map-entry
AAD derivation also differs from the per-field contexts of a Stack fields
plan; the two routes should not be presented as interchangeable storage
formats. There is currently no source-side derive that generates the typed
encrypted counterpart illustrated in this review.

**Sources:** [plan passthrough](../../packages/stack-encrypt/src/plan/build.rs)
(`FieldsBuilder::passthrough`) and
[derive field attributes](../../packages/stack-encrypt-derive/src/attrs.rs)
(`FieldAttrs`).

## 8. Clarify whole-value encryption, layouts, and searchable outputs

**Status:** Open architectural discussion; recommendations below are not decisions.

Three user workflows need clear support:

1. Serialize a complete value into bytes and encrypt those bytes as one
   opaque ciphertext.
2. Produce a chosen layout, such as `EncryptedUser`, with independently
   encrypted fields and explicit plaintext fields.
3. Produce a layout with additional encrypted forms or search terms, such
   as EQL targets.

The existing Vitamin C plaintext derive produces a structural ciphertext
tree, not a single encrypted serialization. It is a generic output layout
for workflow 2, not workflow 1. The distinction affects key count,
independent field access, visible structure, and authenticated boundaries.
Encoding the completed ciphertext tree into one byte string would not
change those properties into whole-value encryption.

### Recommended model

Distinguish the encryption granularity (one encoded value or selected
fields) from the output representation and its requested operations.
Workflow 3 should extend workflow 2 through field targets that request
ciphertext, terms, or both, rather than introducing a separate execution
system. The generic tree can remain a layout option without being the
mandatory scalar storage representation.

- **Whole-value path:** the follow-up review favors an explicit named
  wrapper, provisionally `OpaqueBlob<T>`, which owns serialization and
  deserialization through one library-selected codec. It produces one opaque
  persistable ciphertext; decrypting into `OpaqueBlob<T>` selects the matching
  decode path. Today callers can serialize into `Vec<u8>`, which Vitamin C
  treats as a single byte leaf, but still encounter the node/leaf storage gap.
- **Layout path:** select a target with `EncryptFrom`/`EncryptInto`, or a
  plan, with an explicit passthrough choice. A source-side derive that
  generates a target would be authoring convenience over the same system,
  not another set of encryption semantics.
- **Searchable layout path:** compose core encryption/index operations
  through targets. EQL adapters own their storage representation; Stack
  owns execution. Write and query operations must share the relevant
  context and normalization rules.

Keep source representation, requested operations, output encoding, and
execution distinct internally, while giving each workflow a short public
path. An application should not need to learn visitor machinery or plans
to encrypt and persist a scalar. Arbitrary serialization must not become an
implicit replacement for the typed normalization used by indexes.

Before selecting more trait names, write end-to-end examples for all three
workflows: encrypt, persist, load, decrypt, plus query for searchable targets.
Use those examples to evaluate the public surface and error messages.

### Follow-up: opinionated whole-value wrapper

The first public example now uses
`keyset.encrypt_with_context(OpaqueBlob::new(user), context)` rather than
manual JSON encoding. The wrapper name is provisional; the direction is to
make blob serialization an explicit library-owned behavior. The stored result
remains opaque ciphertext, and decryption returns an `OpaqueBlob<User>` that
can be unwrapped. The codec and its authenticated versioning must be specified;
the wrapper does not silently change how unwrapped structs are encrypted.

Constant-time serialization/deserialization is a desired property to
investigate, not a property established by choosing a binary codec or using
constant-time AEAD. The first revised example provisionally uses Serde traits,
whose arbitrary user implementations cannot carry that guarantee. Define
which lengths and shapes may be public and whether a stricter supported-type
profile is needed before promising secret-independent execution. The examples
document this unresolved boundary separately from the wrapper ergonomics.

Investigate `serdect` as part of that work. It is already a Stack Encrypt
dependency; check its encoding/decoding guarantees and their scope, and
evaluate applicability to ciphertext serialization and the proposed blob
codec. No whole-object constant-time guarantee or codec choice is inferred
from its use.

## 9. Ownership of the value-encryption API across Stack and Vitamin C

**Status:** Open architectural discussion; moving the traits is proposed,
not authorized implementation work.

The review has repeatedly crossed from Stack's target declarations into
Vitamin C's plaintext visitor traits, cipher traits, contexts, derives, and
ciphertext tree. The user proposes moving the encryption traits into Stack
Encrypt and retaining general primitives such as protected values and
randomness in Vitamin C.

**Recommendation:** Stack should own the public value-encryption model,
including the plaintext traits/derives, target declarations, contexts,
ciphertext persistence, and execution semantics. Vitamin C can retain
reusable cryptographic and memory-protection primitives. Moving files alone
does not resolve ambiguous names (`Encrypt` currently describes a source),
duplicate entry points, or the missing whole-value/storage path.

One Stack-owned core layer may serve Rust and language guests without
pulling in KMS transport or HTTP. Applications should still have one
coherent `stack_encrypt` entry point; an internal dependency split need not
become another public API users must understand.

### Migration constraints

- Today `stack-encrypt` depends on both `vitaminc-aead` and
  `vitaminc-encrypt`, while `vitaminc-encrypt` also depends on
  `vitaminc-aead`. Moving the latter's traits into the top-level Stack crate
  and making the existing backend depend on Stack would introduce a cycle.
  Move the value-level backend adapters too, or separate a lower-level
  core/primitive boundary.
- Context composition, type tags, ciphertext framing, index normalization,
  and binding transport frames have compatibility consequences. Preserve
  their existing encodings when changing ownership; any deliberate semantic
  change needs separate versioning and migration treatment.
- Retain one canonical trait/type identity. Compatibility re-exports can
  preserve an old path where dependencies permit; copied independent trait
  definitions would require duplicate implementations and adapters.
- Account for guest/FFI consumers and EQL target implementations, not just
  Rust application imports. The no-HTTP/WASM path must remain usable.

**Sources:** [Stack dependencies](../../packages/stack-encrypt/Cargo.toml),
[guest ABI dependencies](../../packages/stack-guest-abi/Cargo.toml), and
[EQL encryption adapters](../../packages/eql/crates/eql-bindings/src/encryption.rs).
The installed `vitaminc-encrypt` 0.8.0 manifest confirms its dependency on
`vitaminc-aead`.

## 10. Public encrypt_as duplicates encrypt_into

**Status:** Decision agreed; implementation pending.

`KeysetCipher::encrypt_as` is currently an inherent method requiring the
output to implement `EncryptFrom<S>`. It executes that target's operation
declaration. `EncryptInto::encrypt_into` and
`EncryptInto::encrypt_into_with_context` delegate to it, supplying either
the default context or the caller's context.

**Decision:** remove `encrypt_as` from the public API. Keep `encrypt_into`
and `encrypt_into_with_context` as the public target-directed entry points:

```rust
let encrypted: EncryptedInteger = value.encrypt_into(&keyset).await?;
let encrypted: EncryptedInteger = value
    .encrypt_into_with_context(&keyset, context)
    .await?;
```

The operation-execution machinery may remain internal; removing the public
method does not remove target declarations, batching, or execution. Public
examples should use the retained entry points when illustrating the proposed
API. Earlier descriptions of `encrypt_as` in this log describe current code.

This is distinct from issue 3's decision about ordinary encryption:
`keyset.encrypt(value)` remains the sole ordinary `encrypt` spelling, while
`value.encrypt_into(&keyset)` selects a particular output type. The
`encrypt_from` naming/location question in issue 5 remains open.

**Source:** [target operations](../../packages/stack-encrypt/src/target/operations.rs)
(`KeysetCipher::encrypt_as`, `EncryptInto`).

## 11. Context-field storage does not yet extract context from an input struct

**Status:** Open.

`#[stash(context_field)]` exists on derived output types. On encryption it
stores the supplied context in that output field; on decryption it uses the
stored context, optionally checking an independently supplied expected value.
It does not automatically select a field from a plaintext input struct.

The macro currently treats this field as the complete context and rejects
it alongside a literal `context`. Since `struct = User` requires a literal
context, that form cannot currently mark its `id` with `context_field`.
The public examples originally described passing the id explicitly without
explaining this distinction.

### Clarified model: context source and context storage are independent

Two similar scenarios must be distinguished:

1. The caller supplies context as a function argument; the encrypted output
   stores it for later use. This is the existing scalar-output
   `context_field` behavior.
2. The encryption declaration obtains context from one or more fields of
   the plaintext. Whether those values are also stored is a separate choice.

The second scenario can include storage too: read `User.id`, use it to bind
the encrypted fields, and carry it into `EncryptedUser.id`. The caller need
not pass the same value twice. Several fields, such as a tenant id and user
id, can supply a structured composite context.

| Context source | Stored in the encrypted output? | Recovery requirement |
| --- | --- | --- |
| Caller argument | Yes | Read the stored context; optionally check an independently supplied expected value |
| Caller argument | No | Supply the same context again |
| Plaintext field(s) | Yes | Reconstruct context from the stored field(s); optionally check expected values |
| Plaintext field(s) | No | Supply equivalent context independently before decrypting |

Store a source-derived context independently of the ciphertext that needs
it, so decrypt does not depend on first opening that ciphertext to discover
its own context. Binding ciphertext to a stored context authenticates that
relationship; it does not by itself establish that the entire record is at
the destination the application expected.

The derive should express source selection and output storage as separate
concepts, even if a shorthand covers the common read-and-store case. Avoid
assuming that one `context_field` attribute should silently perform both.
Syntax remains open. Define field ordering/grouping for composite context,
literal prefixes, optional caller extensions, `from` mappings, and expected
context checks. These capabilities are proposed, not implemented.

The recommended common-case shorthand is `context(field = "id")`, expanding
exactly to `encrypt(field = "id"), decrypt(field = "id")`. It selects the
same Rust field name on the two different inputs; it does not implicitly
copy or store that field. Keep the directional form for different names or
sources. Initially reject mixing shorthand and directional selectors to
avoid ambiguous precedence. The context examples now use this shorthand
for the plaintext-id-to-stored-id case.

**Sources:** [macro validation](../../packages/stack-encrypt-derive/src/shape.rs)
(`Record::parse`, `context_type`) and
[context-field output assembly](../../packages/stack-encrypt-derive/src/encrypt.rs)
(`assignments`, `value_derive`).

## 12. Default is not the same as optional caller context

**Status:** Open; exposed by the directional-context examples.

`EncryptInto::encrypt_into` and `DecryptFrom::decrypt_from` make the
no-context form available whenever the relevant associated `Context` type
implements `Default`. That works for deliberately defaultable types such as
`DeclaredContext` and `ExpectedContext`, and currently excludes
`CallerContext` and `AeadContext`.

However, a required caller value can have a Rust default: if a declaration
exposes `Context = u64`, the no-context form supplies zero. The directional
proposal `encrypt(caller = u64)` must not accidentally mean "optional, with
zero as the default".

Separate the application's context value type from the trait's caller-input
type or capability. Options include a non-defaultable `RequiredContext<T>`
wrapper that accepts ergonomic conversions from `T`, or a dedicated marker
controlling context-free entry points. No mechanism is decided yet.

This matters equally to required context on decrypt. Source-derived context
can require no encrypt argument, while decrypt may require an external
value or accept an optional expectation of stored context. Do not assume the
two associated input types must match, or that either always equals the
complete logical context used by encryption.

See the [context scenario examples](2026-10-24-stack-encrypt-context-examples.md)
for the proposed selectors and input requirements.

**Source:** [convenience methods](../../packages/stack-encrypt/src/target/operations.rs)
(`EncryptInto::encrypt_into`, `DecryptFrom::decrypt_from`).
