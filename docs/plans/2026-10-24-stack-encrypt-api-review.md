# Stack Encrypt API review

Started: 2026-10-24. Scope: the current Rust `stack-encrypt` API, starting
with encrypting one `i32` into opaque ciphertext and storing the result.

Companion: [complete public workflow examples](2026-10-24-stack-encrypt-public-examples.md),
an API design draft covering encryption, persistence, decryption, and queries.
The [directional context examples](2026-10-24-stack-encrypt-context-examples.md)
explore context sources and storage using Serde-inspired attribute syntax.
The [implementation plan](2026-10-24-stack-encrypt-api-plan.md) records
requirements, recommended decisions, sequencing, and completion criteria.

This is a running issue log. Add a numbered section as each issue is found;
keep observations, proposed changes, and unresolved decisions distinct.
All issues below remain unimplemented. Individual decisions are recorded
within each issue; proposed APIs are illustrative, not implemented.

**User clarification, 2026-10-25:** this API has never shipped beyond an
early prototype. Earlier suggestions to preserve old encodings or public
imports are superseded: backward compatibility and prototype data migration
are not requirements. New Rust, Go, guest, and EQL implementations must
agree with each other, but need not retain the prototype's representations.

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

**Subsequent decision:** ordinary encryption should produce one opaque
ciphertext; choose structural encryption through an explicit target, or
encode a composite plaintext first with `OpaqueBlob<T>`. The
[implementation plan](2026-10-24-stack-encrypt-api-plan.md) recommends
adapting a native single sealed leaf through the existing transcoder,
without serializing an entire encrypted tree or re-encrypting it.

**Collection decision, 2026-10-25:** direct `encrypt` handles a single-value
input and does not automatically lift over collections. Retain collection
composition through `EncryptInto`, including
`let encrypted: Vec<Ciphertext> = vec![1_i32, 3_i32].encrypt_into(&keyset).await?`.
Use `OpaqueBlob<Vec<T>>` to encode and seal a complete collection as one
ciphertext. This settles the previously reopened collection question.
The spelling for byte buffers (`Vec<u8>` versus an explicit bytes wrapper)
remains a separate detail to resolve.

Provide a straightforward opaque ciphertext storage round trip for scalar
values, with direct byte conversion and reconstruction. Decide whether this
means a dedicated scalar result type, a wrapper, or conversion helpers on
the existing API.

Also decide whether Base64 and Serde should be supported conveniences, and
whether whole-tree serialization belongs in Stack or remains caller-owned.
If it remains caller-owned, make that distinction explicit and keep it out
of the simple scalar path. The prototype's canonical leaf encoding is a
useful starting point, not a backward-compatibility obligation.

**Follow-up, 2026-10-25:** text conversions must use the existing
`Base64Text` / `Base85Text` wrappers from EQL bindings. Explore moving these
general encoding types below Stack/EQL and supporting ciphertext-specific
encoded field targets. The persisted ZeroKMS key tag must be extractable
simply in Rust and PL/pgSQL. A refinable-tag protocol is being designed
separately. The user clarified that ZeroKMS checks policy/logs against the
refined tag and returns the original tag for reconstruction of leaf AAD;
record these distinct roles in the implementation. The
[persistence requirements](2026-10-24-stack-encrypt-api-plan.md#typed-encodings-and-extractable-zerokms-tags)
record the proposals and the Base85/SQL decoding constraint.

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
  and binding transport frames must agree across the new consumers. They
  may change without preserving prototype data or providing migration.
- Retain one canonical trait/type identity. Update consumers directly;
  compatibility re-exports are unnecessary. Copied independent trait
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

## 13. JSON layouts and encrypted-output adaptation

**Status:** Open; initial assessment of the JSON tree implementation on
`next` at `b1049824b`. No replacement API selected.

**Agreed follow-up:** investigate replacing the EQL JSON adapter's
serialization round trips with direct typed conversions. This does not yet
select an extended visitor protocol or authorize a particular replacement
API.

`Layout<S>` describes a target selected by a value carrying runtime options.
It associates a `Target: EncryptFrom<S>` and an `Index`, and supplies an
`encryption(&self)` description plus the configured index for queries.
`EncryptFrom<S>::encryption()` instead selects a description by output type.
For JSON, both routes can produce `JsonDocument`: selecting that type uses
default options, while `Json::new(options)` can specify ordered paths and
whether the root is sealed. A plan retains those options for its queries.

This is broader than choosing a Rust record's field layout. JSON options
affect cryptographic structure, query capability, and information exposed
to the server. The same output type can represent different configurations;
the type alone does not identify them. The JSON tree belongs to the
searchable-layout workflow, rather than being an opaque serialized blob.

The existing `target::transcode` protocol serves a different stage: a
`Reader` hands completed ciphertext, structural markers, metadata, and terms
to a destination `Visitor`. `Encryption::transcode()` uses it to adapt
encrypted output without an intermediate serialization tree. It does not
choose JSON indexing options or generate missing search terms.

The new EQL adapter currently takes another route. `JsonTree` implements
`Layout<Value, Target = JsonTreeDocument>`, delegates encryption to the
engine's `Json` layout, and wraps its completed `JsonDocument` with EQL
version and column metadata. Its envelope conversion uses a
`serde_json::Value` intermediate; a private helper also named `transcode`
converts query/extraction types through `to_value`/`from_value`. Neither is
the existing `target::transcode` protocol. That protocol currently has no
JSON-document reader or visitor event. The conversion processes encrypted
output and query metadata; it is not a plaintext serialization bypass.

On decrypt, the EQL target validates its stored column against any supplied
expectation, reconstructs the engine document through the wire form, and
delegates opening to the engine. Its layout object is not required to
perform that conversion.

### Questions to resolve

- Keep encryption configuration distinct from encrypted-output adaptation.
  Decide whether `Layout` is the clearest public name for a configured
  target, especially alongside the earlier use of "layout" for output
  records.
- Decide how runtime target options fit the retained `EncryptInto` API;
  currently type-directed conversion selects the target's defaults, while
  plans accept a configured layout via `encrypt_with_layout`.
- Evaluate a direct typed JSON-document adapter versus extending the
  encrypted-output visitor. Avoid forcing the JSON protocol into generic
  map/sequence events that lose its header, shared document key, projection,
  and extraction semantics. A shared architectural boundary does not
  necessarily require one universal visitor.
- Consider whether a general configured-target abstraction should require
  an index: today's `Layout` requires one even though encryption-only
  targets can also need options.
- Preserve the link between write configuration and query configuration;
  a plan's reuse of the configured index is useful independently of naming.

**Sources:** [layout and operation descriptions](../../packages/stack-encrypt/src/target/operations.rs)
(`Layout`, `json_document`, `EncryptFrom<Value> for JsonDocument`),
[encrypted-output protocol](../../packages/stack-encrypt/src/target/transcode.rs),
[JSON options and document](../../packages/stack-encrypt/src/json/mod.rs),
and [EQL JSON adapter](../../packages/eql/crates/eql-bindings/src/v4/json_tree.rs)
(`JsonTree`, `JsonTreeDocument::envelope`, `transcode`, `DecryptInto`).

### Static Rust surface versus runtime configuration

The intended public Rust experience is traits and derives. Treat plans as
the lower-level composition interface supporting those APIs and the dynamic
FFI interface, rather than requiring Rust callers to write a plan for JSON.
The derive already emits plans; its implementation can retain that shared
execution path without making the plan builder the primary user example.

JSON already has a type-directed path. Given an initialized `cipher` and
its `keyset`, this uses existing methods and default JSON options:

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

This produces searchable JSON with a sealed root and no ordered paths.
The explicit decrypt context checks the expected column against the stored
identifier. The snippet is source-checked, not compiled here.

The earlier `SearchableEmail` example fixes its recipe in the target type:
ciphertext plus an equality term. `EncryptFrom::encryption()` takes no
configuration value. JSON's default target also fixes a recipe in its type.
What `Layout::encryption(&self)` adds is access to instance configuration:
one `JsonTreeDocument` output type can be produced with `$.age` ordered,
with `$.salary` ordered, or with different root settings, selected at
runtime. Its configured index also supplies the matching query behavior.

Search metadata itself does not require `Layout`. A custom target could
fix ordered JSON paths in a manual `EncryptFrom` implementation using the
existing JSON operation. A derive could eventually generate such a fixed
policy. Runtime-configured targets need an additional configuration input;
today `encrypt_into_with_context` accepts context but no layout/options,
and custom JSON configurations use the lower-level plan or `keyset.run`
path. Keep those options separate from cryptographic context.

The cryptographic distinction is separate from the API distinction: JSON
uses a specialized document operation with a shared document data key and
node/extraction semantics. It cannot be implemented merely by adding a
generic equality-term field to the ordinary ciphertext tree. That explains
the JSON operation, but does not by itself require a public `Layout` trait.

### Naming obscures roles

| Current type | Role |
| --- | --- |
| `serde_json::Value` | Plaintext input and recovered plaintext |
| `stack_encrypt::json::JsonOptions` | Runtime configuration |
| `stack_encrypt::target::Json` | Configured index; also implements `Layout` |
| `stack_encrypt::json::JsonDocument` | Encrypted engine document, including search metadata |
| `eql_bindings::v4::json_tree::JsonTree` | Configured EQL target/layout |
| `eql_bindings::v4::json_tree::JsonTreeDocument` | Encrypted EQL storage envelope |

Review names that state these roles, using `Encrypted` for ciphertext-bearing
documents, `Index` for index descriptions, and `Target` or `Config` for
configuration, with module paths distinguishing EQL from engine types.
No replacement names are selected. `Json`'s dual index/layout role should
be considered before simply renaming it.

### Candidate: a fixed-policy wrapper around the EQL output

**Proposal, not implemented or agreed syntax.** Attach the fixed policy to
an output newtype, while the inner library type owns the database format.
The alias below only clarifies the existing type's role; it is not a
library rename.

The later [implementation plan](2026-10-24-stack-encrypt-api-plan.md)
recommends a general typed-options factory, `target(options = factory)`,
instead of the JSON-specific attribute below. Dynamic callers deserialize
options into the same concrete type; Rust and Go support ship together.
This sketch is retained to explain the earlier alternative.

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
JSON operation for the inner target and wraps its completed output. It must
not invoke the ordinary scalar/record derivation on the wrapper, nor invoke
the inner target's default encryption and then try to add ordering terms.
It inherits the EQL target's caller-context and decrypt behavior. Serde's
existing `transparent` attribute preserves the EQL envelope; it does not
provide database-driver trait implementations, which remain a separate
integration concern. The root stays sealed under this candidate's defaults.

The generated declaration must also expose the configured index metadata
for future typed queries, so queries can reuse the policy instead of
repeating paths. The query-facing syntax remains undesigned. The core derive
must delegate configured output construction to a capability of the inner
target, rather than depending directly on the EQL crate. Whether to express
that capability through `Layout` or another trait remains open.

### Alternative: configuration on a plaintext wrapper

The user's proposed `JsonPlaintext::new(value).with_ordering_path(path)` can
still yield the exact EQL wire format. Configuration source and output
representation are independent: an explicit `EqlEncryptedJsonTree` target
can accept that input and execute the same configured JSON operation. The
wrapper must be treated as an encryption request, not serialized as part of
the plaintext. The current API does not provide this wrapper.

This is attractive when paths come from runtime configuration, but repeats
fixed policy at call sites and needs a way to reuse that policy for queries.
Prefer the output newtype for the fixed-policy example. If the runtime
wrapper is added, initially do not implement conversion from it into
fixed-policy targets: avoid silently overriding or merging conflicting
policies. Neither syntax permits callers to redefine EQL's required fields
or its cryptographic wire protocol.

A fixed Rust type describes the policy for new writes; transparent Serde
deserialization alone does not prove a stored document was produced with
that policy. Ordered paths are not all recorded in the document header.
Policy changes and heterogeneous existing rows need explicit compatibility
and migration semantics before claiming stronger read-time guarantees.

## 14. Decrypt convenience methods need explicit context variants

**Required direction:** provide a no-context method and a separate
`_with_context` method, mirroring the encrypt-side distinction. The user
prefers the name `decrypt_from`.

Today `ciphertext.decrypt_into(cipher, context)` exists on the blanket
`DecryptFrom` extension trait. `Plaintext::decrypt_from(ciphertext, cipher)`
and `Plaintext::decrypt_from_with_context(ciphertext, cipher, context)` also
exist on that trait. `DecryptInto<P>` separately declares the opening
operation. These method/trait names are easy to confuse.

**Recommendation:** use the destination-directed pair in the preferred
public examples. `User::decrypt_from(encrypted, &keyset)` follows Rust's
From convention; `encrypted.decrypt_from(...)` would reverse it. The
receiver and migration of the competing method remain recommendations to
confirm, not settled user decisions. Do not change the declaration trait
merely because its convenience spelling changes. Address trait discoverability
with issue 5 and optional-context capability with issue 12.

## 15. Coordinate the Go JSON work with the shared API redesign

The user identified [PR #1353](https://github.com/cipherstash/stack/pull/1353)
as parallel agent work. The PR is currently a Go JSON design document with
implementation tasks #1348 through #1352, tracked by #1347. Its dynamic
JSON/options path, public names, context behavior, and staged extraction
support must be reconciled with the configured-target and trait/context
contracts developed here. Preserve compatible catalog, transport, engine,
and testing work rather than designing or implementing it twice.

The [implementation plan](2026-10-24-stack-encrypt-api-plan.md) records
the concrete reconciliation points after reading the PR write-up. This is
a local coordination item; no message or review was posted to that agent
or PR.

## 16. Integrate the prior query design rather than reopening it

The user supplied **Stack Encrypt query design** (2026-10-21), read in full
on 2026-10-25 from `/Users/dan/Downloads/Stack Encrypt query design.md`.
It proposes field-owned index selection, one answering index per operator,
typed field handles, a single capability declaration, and shared query
derivation/refusals. It is explicitly a discussion draft with open questions.

The [implementation plan](2026-10-24-stack-encrypt-api-plan.md) now uses that
draft as the baseline and records concrete reconciliation points: our
output-side derives and configured options factories, JSON operators and
extraction, context inputs, static/dynamic portability, and validation
timing. Older compatibility requirements are superseded by the user's
prototype clarification. The source document was left unchanged.

## 17. Use consistent definition-selection names for encrypt and query

The user finds `.using(...)` for encryption and `.on(...)` for queries
confusing and asks to consider one name for both. Recommend `.using(...)`:
the selected definition or field supplies the operation's policy. Final
spelling is not yet accepted. Retain the operation-specific bounds:
encryption selects the output target's associated definition; queries
require a field or single-value target implementing `QueryTarget<Op, Input>`.
This is a naming change, not a merger of those capabilities.

The user also prefers `cipher.using(&field).query(op, input)` and explicitly
requires strict typestate. Supporting both orders is acceptable to them.
The plan recommends definition-first as canonical, with operator-first
converging to the same typed request. Missing definition/required context
must prevent awaiting on the static path; repeated selection must not
silently overwrite a request's definition. The current `.query(...).on(...)`
implementation is not claimed to already provide this API.

## 18. Single-ciphertext representation needs consuming, cleanup-aware inputs

**Decision, 2026-10-25:** use `OpaqueEncode` / `OpaqueDecode` for single-value
encoding/decoding, distinguishing one opaque ciphertext from target layouts.
Both direct `encrypt` and target-directed `encrypt_into` consume input and
are responsible for cleanup of owned plaintext artifacts, including the
context-taking variants. Explicit passthrough fields move to the output.
The plan records source cleanup capabilities,
immediate guarding before returning an unpolled request, cleanup of encoded
buffers/scratch on all ordinary exit paths, and boundaries for caller copies,
custom serialization, passthrough output, and Go host/guest ownership.
`Serialize` alone cannot establish cleanup of an `OpaqueBlob<T>` source.
Consumption and zeroization are distinct; no completed audit is claimed.

**Follow-up decision:** plaintext types must implement the existing
`Zeroize` trait; do not introduce our own cleanup trait for now. For the
proposed Serde blob, this means `Serialize + Zeroize` on input and
`DeserializeOwned + Zeroize` on owned decode. Library guards must actually
invoke cleanup; partially constructed Serde values need separate treatment.

**Decrypt decision:** retain `keyset.decrypt` / `decrypt_with_context` for
ordinary opaque ciphertext and `T::decrypt_from` /
`decrypt_from_with_context` for declared targets. Return an ordinary owned
`T: Zeroize` on success, transferring cleanup responsibility to the caller.
Stack guards plaintext intermediates while it owns them. Explicit
drop-guarded results should be supported without becoming the default;
`Zeroize` alone does not imply cleanup on drop. This does not resolve the
separate partial-deserialization cleanup requirement.

**Codec recommendation:** reuse Vitamin C frame machinery with a blob
mapping. The 0.8.0 transport Serde implementation already exists and guards
serialization buffers, and its frame writer wipes allocations on growth.
Do not reuse that mapping unchanged: option presence can be lost
(`Some(())` and `None` both encode as null), maps require text keys, and
successful `to_vec` returns an unguarded vector. See the
[codec assessment](2026-10-24-stack-encrypt-api-plan.md#blob-codec-assessment-vitamin-c-frames)
for the required work and Borsh fallback. Neither codec choice nor the
`Zeroize` bound establishes constant-time behavior or partial-decode cleanup.

**Priority update:** first specify stable, versioned storage bytes; the
existing frame codec was ephemeral transport. Further zeroization and timing
implementation improvements may follow without changing stored format.
The upstream action is
[Vitamin C #519](https://github.com/cipherstash/vitaminc/issues/519).

## 19. First-release completeness and remaining review decisions

**Accepted, 2026-10-25:** encoded ciphertext wrappers are first-class field
targets; final wrapper names/package placement come last. ORE does not
answer equality initially, even for integers. Preserve a future explicit
capability for equality-preserving encodings; never infer exact equality
from ordering support for text or other lossy encodings. Keep operator
provider overlap validation and avoid silently changing existing definitions.

The JSON first version must be comprehensive across Rust and dynamic/Go,
including extraction, opening entries, children/counts and subtree walks.
Claude's earlier Go plan deferred walks; the new scope supersedes that
deferral. The [operation contract and examples](2026-10-25-stack-encrypt-json-operations.md)
lists required operations, current evidence, proposed Rust/dynamic surfaces,
SQL use, missing-path/null semantics and implementation acceptance gates.
Names and packaging are explicitly the last design activity.

**Further accepted decisions:** custom Rust stages can remain explicitly
Rust-only with `NotPortable` for unsupported dynamic export; built-ins retain
Rust/Go parity. All key-independent checks precede key resolution/loading.
The detailed JSON operation contract is still under user review.

## 20. Plaintext-derived keysets and optional provider policies

The user requested routing a plaintext record to a keyset by ID/name from
one of its fields; assessment of Vitamin C's unused `AsyncCipher`; and
ZeroKMS lock context including principal JWT claim selectors. Keyset and
lock-context capabilities must remain optional for future AWS KMS/Vault
backends. See the [provider-capabilities assessment](2026-10-25-stack-encrypt-provider-capabilities.md)
for current source evidence, proposed static/dynamic declarations and
acceptance work.

Current facts: Stack resolves keysets by ID/name but generation batches use
one preselected keyset. Stack deliberately orchestrates provider requests
outside Vitamin C's leaf walk and already implements synchronous `Cipher`.
Its provider payload layer supports lock context but Stack Encrypt sends
empty lock context. The existing data/index key abstractions still embed
ZeroKMS protocol types; future providers need a neutral base plus optional
capabilities, not no-op implementations of mandatory ZeroKMS features.

Recommendations, not yet accepted: derive key routing as an explicit target
selector and resolve it in the client executor; partition batches by resolved
key/provider/principal requirements; carry lock context as a separate typed
provider policy on both generation and retrieval; reject unsupported required
features before I/O. Keep key routing, ciphertext context, search scope and
principal policy separate. Revisit cipher adapter cleanup during packaging
without discarding cross-record batching or native/WASM support.

## 21. Packaging, naming and retirement of AsyncCipher

The user favors removing Vitamin C `AsyncCipher` and moving application
encryption behavior into Stack Encrypt. The
[packaging recommendation](2026-10-25-stack-encrypt-packaging.md) proposes
Stack ownership of value traversal, declarations, target/index adapters and
execution; a small shared `stack-encrypt-format` crate for codecs and typed
encodings; a ZeroKMS-specific client crate; and reusable primitives remaining
in Vitamin C. It includes an acyclic dependency map and public name glossary.

Stack does not use `AsyncCipher`, but Vitamin C's async helpers and tests do.
Retire that execution path with its consumers and move relevant coverage;
do not treat deletion of the trait alone as complete. Normalization/PRF/ORE
adapters also depend on the existing value model and need separation from
their primitives. Moving the frame implementation refines the earlier codec
ownership recommendation; coordinate stable storage work under Vitamin C
#519. Names and package moves remain proposals, not implementation changes.
