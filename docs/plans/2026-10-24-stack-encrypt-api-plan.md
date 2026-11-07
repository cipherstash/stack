# Stack Encrypt API implementation plan

First written on 24 October 2026. Checked against the merged code on 27
October 2026.

Status: proposed implementation direction. This plan develops the [API
review log](2026-10-24-stack-encrypt-api-review.md), the [public
examples](2026-10-24-stack-encrypt-public-examples.md), and the [context
examples](2026-10-24-stack-encrypt-context-examples.md) into implementation
choices, and sets the criteria for finishing each one.

The plan marks which statements are the user's requirements and which are
recommendations that nobody has accepted yet. "The user" is the person who
asked for the review and who decides its open questions. The code examples
show proposed APIs, not working code in the current release.

## Summary

- The Go JSON foundations and Go opaque storage are merged. The customer
  work that remains is conformance to the contract, closing the remaining
  gaps in reads and configuration, and release readiness. See [Status on 27
  October 2026](#status-on-27-october-2026).
- The Go customer release comes first. The final Rust facade and the crate
  moves come after it, and do not hold it up.
- Until the customer release, nothing needs to stay compatible with the
  prototype API or its stored data. After it, the Go interface and the
  stored data must stay compatible.
- The [decision checkpoint](#decision-checkpoint-on-25-october-2026) lists
  the settled directions. The [remaining questions](#remaining-questions)
  table lists what is still open.

## Terms used in this plan

| Term | Meaning |
| --- | --- |
| AAD (additional authenticated data) | Data that encryption binds to a ciphertext without encrypting it. Decryption fails unless the same AAD is supplied again |
| AEAD (authenticated encryption with associated data) | The cipher that seals each value and authenticates its AAD |
| Blob | A value that `OpaqueBlob<T>` encodes as a whole and seals as one ciphertext |
| Bloom filter | The bit array that the match index stores. Each term sets some bits, so a query can test whether a value may contain the term |
| Cascaded tags | Each JSON container's authentication tag covers the tags of its children. #1379 added them |
| Column and keyset profile | The released configuration. It uses the column identity and the keyset selection, and accepts no row binding or search scope input |
| Configured target | A target together with typed options, such as a JSON target with a list of ordered paths |
| Context | Values bound into a ciphertext, such as a column name or a row ID. Decryption fails unless the same context is supplied again |
| Dynamic interface | The interface that takes declarations and requests as data instead of Rust types. Go uses it through the guest |
| EQL (Encrypt Query Language) | The SQL types and functions in `packages/eql` that store and query encrypted values in PostgreSQL |
| Facade | The proposed public Rust API of `stack-encrypt`: its traits, derives, and convenience methods |
| FFI (foreign function interface) | The boundary through which another language calls the Rust engine |
| Guest | The Rust engine compiled to WebAssembly, which the Go SDK runs |
| Key I/O | Any request to ZeroKMS to resolve, load, or derive keys |
| Keyset | A set of keys in ZeroKMS, the CipherStash key management service (KMS) |
| Open and seal | To seal a value is to encrypt and authenticate it. To open it is to authenticate and decrypt it |
| ORE (order-revealing encryption) | Index terms that reveal the order of the plaintexts, for range queries and sorting |
| OPE (order-preserving encryption) | Encryption whose ciphertexts keep the order of the plaintexts |
| Passthrough field | A field copied unencrypted from the plaintext type to the encrypted output |
| Plan | The lower-level description of which fields a conversion encrypts, indexes, or passes through. Derives and dynamic declarations compile to plans |
| Post-cascade profile | The JSON storage and search format as it is after #1379 added cascaded tags and randomised order. This is the format to freeze |
| Pseudo-version | A Go module version that names a commit instead of a released tag |
| Reads that Rust verifies against the original request | Go prepared reads. When the rows are opened, Rust derives the request again and checks every row against it |
| Row binding | Context that ties a ciphertext to one row, such as the row ID, so that it opens only for that row. Also called ciphertext binding |
| Search scope | The part of the context that also goes into index keys and search terms, such as a tenant ID. One query matches every row in the scope |
| Target | A type or dynamic name that says how a value is encrypted and stored, such as `JsonSearch` or `TextEq` |
| Target definition | The resolved, immutable form of a target's declaration: options, prepared indexes, context rules, and operation metadata |
| Typestate | A builder whose type changes with each call, so the compiler refuses to run an incomplete request |
| Vitamin C | CipherStash's cryptography library, `vitaminc`. Its codec encodes values as binary frames |

## Status on 27 October 2026

### Merged Go work

On 27 October 2026, this plan was checked against merged `next` at commit
`ffeed7adb3f7d8739cda53261046147852bffc82`. This Go work is merged:

- the Go JSON catalog, configured targets, queries, reads that Rust verifies
  against the original request, typed documents, and executable
  documentation (#1372, #1373, #1378, and #1402);
- Go adoption of opaque storage (#1369 and #1370).

The active customer work is now conformance to the contract, closing the
remaining gaps in reads and configuration, and release readiness. That work
does not implement those foundations again. See the refreshed [Go JSON
plan](https://github.com/cipherstash/stack/blob/docs/go-json-tree-plan/docs/plans/2026-10-24-go-json-tree.md)
and the [JSON operations
inventory](2026-10-25-stack-encrypt-json-operations.md).

### JSON storage and match changes in #1379 and #1397

Pull request #1379 added cascaded tags, and randomised the order of stored
entries and query projections. A wildcard `->` now selects an unspecified
element, so old SQL recipes that relied on the first element in document
order are invalid. Freeze the post-cascade profile. Compare query semantics
in tests, not the randomised byte order.

Pull request #1397 implements short whole-word terms in the shared Bloom
filter. Configurable native Go match options and broader tokeniser and
filter work remain. This paragraph records implementation status only. It
does not accept a stronger privacy claim for those terms.

### Temporary Vitamin C pins

Go's Vitamin C storage modules are temporarily pinned to pseudo-versions at
commit `06568ba93bd9`. The guard for a final release requires each
pseudo-version to be replaced with a released module tag. Prereleases can
keep pseudo-versions. Rust remains on Vitamin C 0.8.0 from crates.io.
Schedule the crate moves and the final Rust facade after the customer
release.

### Decisions made on 25 October 2026

The latest decisions about what to release:

- Encoded ciphertext field targets are accepted. These are fields whose
  stored output is the ciphertext as text, such as Base64.
- The comprehensive JSON contract for the first release, with Rust and
  dynamic examples, is in [JSON
  operations](2026-10-25-stack-encrypt-json-operations.md). The contract
  includes extraction and walks.
- ORE does not provide equality at first. Keep the option of a future
  explicit capability for encodings that preserve equality.
- Make stable blob storage bytes the priority, through [Vitamin
  C #519](https://github.com/cipherstash/vitaminc/issues/519). Improvements
  to zeroisation and timing can follow without changing the stored format.
- The review of names and packages is now in progress.

Where these decisions conflict with earlier sequencing recommendations in
this plan, these decisions apply.

### Follow-up decisions

- Custom Rust query stages can be explicitly Rust-only. They export to the
  dynamic interface as `NotPortable` until they are registered. Built-in
  capabilities keep parity between Rust and Go.
- Every validation that does not need keys runs before keys are resolved or
  loaded.
- The user is still reviewing the JSON operation contract. Its detailed API
  proposals are not approved as a set.
- The [provider
  capabilities](2026-10-25-stack-encrypt-provider-capabilities.md) companion
  assesses the new questions about keyset routing, lock context, and
  provider capabilities.

### Packaging review

The user favours retiring Vitamin C's `AsyncCipher`, and moving application
encryption behaviour into Stack. The [packaging and naming
recommendation](2026-10-25-stack-encrypt-packaging.md) defines:

- crate ownership;
- a dependency graph with no cycles;
- the proposed shared format crate;
- role-based public names;
- coordinated migration work.

The recommendation is a proposal for review. Nobody has accepted the
renames. None of the proposal is implemented.

### No compatibility with the prototype

On 25 October 2026, the user clarified the compatibility scope. This API has
existed only as an early prototype. Do not preserve its APIs, stored
ciphertexts, or encodings for backward compatibility. No legacy decoders,
compatibility aliases, deprecation period, or data migration is required.
Choose the coherent new design, and update its Rust, Go, guest, and EQL
consumers together.

Engine output must still agree with the SQL that consumes it. That is
current interoperability, not a requirement to support a legacy format. The
merged Go implementation does still keep a reader for the legacy JSON
encoding of opaque values. Record that reader as existing behaviour, not as
a new requirement to build machinery for migrating prototype data.

This exemption ends for the customer profiles when they are released. After
that, later refactors of the Rust API and packages must keep the Go
interface, and keep stored data and search compatible.

## Requirements established in the review

- The keyset directs ordinary encryption through `encrypt` and
  `encrypt_with_context`. Keep `EncryptInto` as a separate conversion
  interface directed by the target. Remove the redundant public
  `encrypt_as`.
- Encrypting a single value produces an opaque ciphertext. `OpaqueBlob<T>`
  explicitly encodes a composite value before sealing it as one value.
  Direct `encrypt` does not automatically apply itself to each item of a
  collection.
- Use `EncryptInto` to batch a collection, including `Vec<i32>` into
  `Vec<Ciphertext>` without caller context. This division was agreed on 25
  October 2026. The current recommendation for byte vectors follows the same
  collection rule, and uses `OpaqueBlob` for a whole vector. Compatibility
  with the prototype gives no reason to add an exception for raw bytes.
- Rust traits and derives are the main static interface. Plans support those
  declarations, and their lowering to the dynamic interface and FFI.
- Design static and dynamic support against the same contract for the engine
  and definitions. Deliver the Go customer interface first. Polished public
  Rust traits and derives can follow. Interoperability tests at the level of
  the Rust engine are still required, so this order does not introduce a
  second Go encryption implementation.
- Provide decrypt entry points with and without explicit context. The
  variant without context must not invent a default value for a required
  application input.
- `OpaqueEncode` and `OpaqueDecode` name the capabilities that represent a
  value as a single ciphertext. `encrypt` and `encrypt_into`, including
  their context-taking variants, consume their input. Both operations take
  responsibility for cleaning up owned plaintext and plaintext artefacts.
- Ownership alone does not implement zeroisation. Require `Zeroize` on
  plaintext types, and enforce cleanup through guarded storage and lifecycle
  checks. Deliberate passthrough fields move to the output instead of being
  erased.
- Keep EQL's contract between the engine and the SQL coherent, and keep the
  shared batching and execution behaviour. Prototype representations need
  not be preserved.
- Investigate the serialisation round trips in the EQL JSON adapter, and
  replace them with direct typed conversion. Keep the engine and the SQL in
  agreement.

## Recommended decision: general configured targets

Use a general contract: a target plus typed options. Do not add a public
`json_tree(...)` derive construct. Rust constructs concrete options
directly. The dynamic interface deserialises its options into that same
type.

JSON supplies the options type, the validation, and the implementation
behind the general mechanism. Sharing a contract does not require shared
input syntax, or static Rust configuration that passes through
deserialisation.

Three approaches were considered:

| Approach | Benefit | Limitation | Recommendation |
| --- | --- | --- | --- |
| Typed Rust options factory | The compiler checks the options type, and normal Rust APIs and tools work | The function itself is not portable, but its concrete output has a data form | Preferred static interface |
| Named policy type that holds options | Reusable and easy to discover | Adds a provider trait and a marker type where a function is enough | Optional later convenience |
| Target plus options as data | Can be written in Go declarations and dynamic data | Needs deserialisation and semantic validation | Dynamic interface, producing the same typed options |

The first recommendation put option field literals in Rust attributes, and
this recommendation replaces it. The first recommendation rejected a Rust
factory because its code cannot cross FFI. The rejection was too
restrictive: the common boundary is the factory's typed result, not the code
that builds it. This plan introduces no arbitrary encryption callback. The
factory only supplies configuration.

The target owns:

- its source capabilities, canonical output, and options and defaults;
- validation, the encryption description, and index and query capabilities;
- how its output is opened.

Context remains a separate input. Configuration does not supply arbitrary
execution callbacks. Configuration also does not let a caller redefine EQL's
wire fields.

Implement configuration as a target capability, with the working name
`ConfigurableTarget<S>`. The capability lowers into the existing operation
descriptions. Its associated options type has a data representation. Rust
factories return that type directly. Registered dynamic targets deserialise
into it.

Validate and normalise the options once, when a reusable declaration is
built. Both paths run the target's own semantic validator before key I/O.
Use validated deserialisation, for example a wire helper plus `TryFrom`. Do
not use a derived deserialiser that bypasses the checked builders. If the
public type promises validated invariants, keep any raw options fields
private.

Compile-time guarantees cover factory resolution and signatures, the
association between target and options, and typed builder arguments. They do
not mean that a string is a valid JSON path, or that the factory runs at
compile time. Building a JSON path can currently fail.

Start with a fallible factory contract,
`fn() -> Result<Target::Options, E>`, with errors converted to the engine's
configuration error path. Propagate errors without panics or `unwrap`. A
later macro for literal paths can add stronger static validation.

Resolve the factory once for each reusable configured declaration, and reuse
its normalised options for writes and queries. A factory can read mutable
external state, so its type alone cannot prove a fixed policy. Document that
providers of a fixed policy must be stable. Do not evaluate the provider
again when generating a query. Configuration that is meant to vary belongs
in a configured-target instance that the caller constructs explicitly.

Unlike today's `Layout`, the general capability must not require exactly one
index: a target can have none, or several. Adapt the existing JSON layout
internally during the migration. Do not expose two competing concepts of a
configured target.

For Go, the target catalog resolves registered targets. Custom Rust targets
remain possible without registration. The dynamic interface can address them
only once the guest build includes their adapter and descriptor.

## Candidate static syntax

`target(options = payroll_options)` names a Rust factory for the inner
target of a transparent newtype. The inner Rust type selects the output
representation and the associated options type. The spelling is a proposal.
The revised recommendation is typed factories for Rust, and typed
deserialisation for dynamic callers.

```rust
use eql_bindings::v4::json_tree::JsonTreeDocument as EqlEncryptedJsonTree;
use stack_encrypt::json::JsonOptions;
use stack_encrypt::sem::TermError;

fn payroll_options() -> Result<JsonOptions, TermError> {
    JsonOptions::new().ordering(["$.salary"])
}

#[derive(EncryptFrom, DecryptInto, Serialize, Deserialize)]
#[serde(transparent)]
#[stash(
    plaintext = serde_json::Value,
    transparent,
    target(options = payroll_options)
)]
struct EncryptedPayroll(EqlEncryptedJsonTree);
```

The factory body uses today's `JsonOptions` builder. The derive support is
proposed. The derive calls the factory, and type-checks its result against
the inner target's associated options type. The derive does not depend on
the meaning of JSON paths, or on JSON-specific option names. It does not
serialise or deserialise the factory's result.

The configured target constructs its output, and the derive wraps it. Serde
transparency keeps that output's wire envelope. SQL driver traits are a
separate integration requirement. The same factory attribute should work on
a field of a derived output record, under the existing rules for selecting
context.

```rust
let encrypted: EncryptedPayroll = payroll
    .encrypt_into_with_context(&keyset, column.clone())
    .await?;

let restored = serde_json::Value::decrypt_from_with_context(
    encrypted, &keyset, column,
).await?;
```

A fixed policy is a recipe for writes and queries. Transparent
deserialisation does not prove that an existing row was created with that
policy. In particular, the JSON header does not store the full policy of
ordered paths.

## Candidate dynamic representation and Go requirements

Pull request #1372 implements this: string targets and configured object
targets share the native options validator. Use the merged `JsonSearch`
identifier:

```json
{
  "payroll": {
    "context": ["employees", "payroll"],
    "target": {
      "name": "JsonSearch",
      "options": { "ordered": ["$.salary"] }
    }
  }
}
```

Keep `"target": "TextEq"` as shorthand for that target's default options.
The object form and the JSON target options are now implemented. Reject
unknown options, incompatible options, unsupported target names, and invalid
paths during declaration validation. Do not fall back to defaults silently.
Specify one consistent JSON wire format and context encoding across the
Rust, dynamic, Go, and database paths.

Go's generator and policy API must represent these same options, emit the
same declaration, and get the EQL value from the guest. Go must not assemble
the EQL envelope or reproduce JSON indexing. Discovery must expose the
options contract and the capabilities. Extend the existing target catalog
and resolver instead of installing a parallel JSON registry.

The dynamic registry calls the concrete target's options deserialiser. It
does not look up or call the Rust application's factory by name. A Go caller
supplies equivalent options as data. If a Rust policy must be exported,
serialise its resolved options, not the function's identifier. This contract
does not require every Rust-only target to depend on Serde: only targets
registered with the dynamic interface need data conversion.

These are now implemented:

- the catalog and guest;
- the JSON value kind;
- the strict JSON text parser;
- the generated Go target options.

Pull request #1373 adds operation input shapes and operand encodings. Pull
request #1378 adds typed Go document adapters. Remaining work includes:

- the formal versioned specification;
- a general lifecycle and caching for definitions;
- direct typed EQL conversion;
- separating the roles within context.

The current grammar for data plans is still a map of fields. The runtime
does not yet accept the illustrative versioned schema later in this plan.

Writes and queries must reuse the normalised configured target in Rust and
Go. An ordering query on an undeclared path must fail before key I/O.

Containment, path equality, ordering, and extraction need capability
metadata that can express their different shapes of operand and result. The
metadata cannot assume a single scalar query counterpart. Decryption must
use the stored cryptographic metadata and context. It must not require the
caller to remember the write's ordered paths.

## Accepted decrypt interface and return ownership

Decided on 25 October 2026: keep ordinary keyset-directed decryption for one
opaque ciphertext. Keep destination-directed `DecryptFrom` for declared
targets and layouts. Both paths have variants with and without context:

```rust
let value: i32 = keyset.decrypt(encrypted).await?;
let value: i32 = keyset.decrypt_with_context(encrypted, context).await?;

let plaintext = User::decrypt_from(encrypted, &keyset).await?;
let plaintext = User::decrypt_from_with_context(encrypted, &keyset, context)
    .await?;
```

These are separate call examples. They do not reuse one consumed ciphertext
in sequence. Direct decrypt mirrors direct encrypt, and `DecryptFrom`
mirrors the target-directed `EncryptInto`. The existing input capabilities
still decide whether a caller can leave out context. Do not add a competing
public `decrypt_into` method that takes the ciphertext as its receiver.

Successful decryption returns an ordinary owned `T: Zeroize`. Stack guards
the recovered bytes and intermediate plaintext for as long as they belong to
Stack. A successful return transfers responsibility for the value to the
caller. `Zeroize` does not automatically wipe that returned value on drop.

Support results with a drop guard when the caller explicitly asks for one,
without requiring a wrapper around every decrypted application struct. The
exact opt-in adapter is implementation design within this decision. Guarding
the completed value does not solve cleanup after a partial deserialisation.
That cleanup remains required work.

`User::decrypt_from(...)` reads as constructing a `User` from a ciphertext.
Calling `encrypted.decrypt_from(...)` would conflict with the usual From and
Into receiver convention, so keep the agreed destination receiver. The
destination-directed pair already exists on the blanket `DecryptFrom`
extension trait.

Today's ciphertext method is `encrypted.decrypt_into(cipher, context)`, also
on `DecryptFrom`. That method has no separate overload without context. The
current declaration trait `DecryptInto<P>` is a different layer, so do not
rename it by accident while settling how the methods are called.

Settle the names of declaration traits and convenience traits together with
review issue 5. The public examples use the destination-directed pair.
Remove the competing ciphertext method when implementing this interface.

## Recommended public traits and context input capabilities

Status: the user accepted this direction on 24 October 2026. Separate the
conversion methods from the `EncryptTarget` and `DecryptSource`
declarations. Use explicit capabilities for caller context instead of
`Default`. Implementation, complete signatures, and updates to call sites
remain pending.

This section settles the direction of work areas A and B, later in this
plan. Earlier examples keep their historical derive names until they are
migrated.

Keep two user-facing conversion traits, both provided by blanket
implementations in the library:

| Trait | Public methods | Receiver |
| --- | --- | --- |
| `EncryptInto` | `encrypt_into`, `encrypt_into_with_context` | Plaintext value; output inferred or selected |
| `DecryptFrom` | `decrypt_from`, `decrypt_from_with_context` | Plaintext destination type; ciphertext supplied as an argument |

These methods run declarations through the common engine and return the
existing batched awaitable value. Target implementers do not override
execution. The ordinary `keyset.encrypt` and `encrypt_with_context` remain
inherent methods, and do not gain an `encrypt` synonym on the plaintext.
Their accepted decrypt counterparts are `keyset.decrypt` and
`decrypt_with_context`.

Give the declaration traits names that state their role. From and Into names
would promise conversion methods that these traits do not define:

| Proposed declaration | Implemented on | Describes |
| --- | --- | --- |
| `target::EncryptTarget<P>` | Encrypted output or term target | How to produce this target from `P` |
| `target::DecryptSource<P>` | Recoverable encrypted output | How this stored value yields `P` |

The corresponding derives should use the same names. This replaces today's
declaration traits `EncryptFrom<P>` and `DecryptInto<P>`. It does not remove
the retained `EncryptInto` extension trait. A target that only produces
terms implements only `EncryptTarget`, so it has no decrypt method that
always fails.

Plaintext visitor traits remain a separate representation layer that Stack
owns. Moving or renaming them must keep a single canonical trait
implementation, and a consistent wire contract across the new consumers.
Compatibility with the prototype is not needed. Configured-target options
are another associated capability, not context.

Declaration methods continue to return operation descriptions that the core
owns. Encryption declarations do not receive the plaintext and the cipher
together. Decrypt declarations inspect the stored output and select how to
open it, without any key I/O. Plans, derives, and dynamic resolution reuse
those descriptions. Keep the declaration module public for custom targets,
and keep the normal method imports and derives available from the Stack
entry point.

Use `ContextInput` as the name of the associated type on each declaration
trait. `ContextInput` describes only what the caller must or can supply. It
is not the complete cryptographic context. The complete context can also
include a prefix, and fields selected from the plaintext or the stored
output. Encrypt and decrypt declare this type independently.

Recommended: input wrappers that the library owns, each with explicit
capabilities:

| Proposed input | Argument left out | Argument supplied | Meaning |
| --- | --- | --- | --- |
| `NoCallerContext` | Allowed | Not accepted | The declaration derives all context and takes no caller input |
| `RequiredContext<C>` | Not available | Required `C` | Supplies the context, or the missing component that the declaration selects |
| `OptionalContext<C>` | Allowed | Accepted `C` | For an ordinary ciphertext, leaving it out means empty context, and a supplied context is used directly |
| `ContextExtension<C>` | Allowed | Accepted `C` | Leaving it out keeps the declared base, and supplying it extends the base |
| `ExpectedContext<C>` | Allowed | Accepted `C` | Leaving it out rebuilds the stored context, and supplying it also checks that context |

`OptionalContext` does not append a synthetic empty prefix, and leaving out
an extension does not append `()`. `ExpectedContext` never extends the AAD.
The table specifies behaviour, and the names can change without changing it.
A requirement for nonempty input belongs to the accepted argument type or to
the validated resolved context, not to whether the input is optional.

Search targets still require a nonempty effective context. Ordinary scalar
ciphertext should accept the same empty context through both the keyset API
and the target-directed API.

Methods without context require an explicit, sealed `AllowsNoContext`
capability. `_with_context` methods require a matching `AcceptsContext`
capability with its accepted argument type. Neither capability is inferred
from `C: Default`. So `RequiredContext<u64>` stays required, even though
`u64` defaults to zero.

The helper methods accept ordinary argument values, or convenient checked
conversions. Users do not wrap values in `RequiredContext` or
`ExpectedContext` by hand at every call. Conversion errors propagate before
key I/O.

The wrappers that the core owns record presence and intent. Target
declarations select the sources and compose the context. For composite
required input, `C` can be a tuple or a named struct. It does not have to be
the full logical context. Keep the existing grouping rules and context
encodings.

Examples where encrypt and decrypt have different requirements:

| Declaration | Encrypt input | Decrypt input |
| --- | --- | --- |
| Caller row ID stored in output | `RequiredContext<u64>` | `ExpectedContext<u64>` |
| Source row ID also stored in output | `NoCallerContext` | `ExpectedContext<u64>` |
| Source row ID not recoverable before decrypt | `NoCallerContext` | `RequiredContext<u64>` |
| Static field base with optional unstored extension | `ContextExtension<C>` | `ContextExtension<C>` |

In the last row, decrypting a ciphertext that has an extension requires the
same extension. That the method without context is available does not
promise that it opens every ciphertext of that Rust type. Where a
declaration explicitly allows it, a derive can expose an optional extension
instead of `NoCallerContext`. Expected-context checks do not authenticate
stored data themselves. Successful cryptographic opening is still necessary.

The dynamic plan must encode the same requirements, source selectors, and
storage rules. Rust uses trait bounds to enforce which methods are
available, with or without context. The engine enforces the presence and
validity of dynamic input before key I/O. Omitted input, an explicit zero,
and an empty supplied value are three different things. Go generation can
expose convenient signatures from that metadata, but the guest stays
authoritative for runtime requests.

The implementation must prove these points:

- a call that leaves out required input fails to compile, even when
  `C: Default`;
- a target that accepts only no input rejects context;
- an optional extension and an expected context keep their different
  meanings;
- all nine directional scenarios in the [context
  examples](2026-10-24-stack-encrypt-context-examples.md) run through Rust
  and through dynamic plans.

Keep support for owned sources, and keep batching. This separation of traits
must not add a blanket `Clone` bound. The final signatures must show the
support for borrowed sources and for owned sources. They must not hide the
existing difference behind the rename.

## Go JSON implementation and PR #1353

The [Go JSON
plan](https://github.com/cipherstash/stack/blob/docs/go-json-tree-plan/docs/plans/2026-10-24-go-json-tree.md)
has been updated against merged `next`. Tracking issue #1347 and steps #1348
to #1352 are closed. #1372, #1373, and #1378 implement:

- the catalog;
- configured JSON targets;
- dynamic execution;
- operands specific to each operation;
- opening that Rust verifies against the original request;
- the generated typed Go front end.

Pull request #1402 supplies current documentation and the executable
database example.

The released target identifier is `JsonSearch`. Go uses `eql.JSONSearch`,
`JSONSearchQuery`, `JSONSearchLeafQuery`, and `JSONEntry`. Do not impose the
proposed `EncryptedJson` glossary as a rewrite before release. Keep the
distinctions between roles, and freeze the actual customer names before
later Rust renames.

Prepared Go reads keep their cipher and use `Open(ctx, rows)`. The engine
derives the trusted selectors and read keys again from the original request.
No new protocol for persistent guest handles is needed to implement that
verification.

State the remaining requirements explicitly:

- SQL for children and child counts exists, but there is no opener for
  plaintext children that is bound to their parent.
- Opening by selector accepts at most one entry for each document group.
- Use subtree reads to retrieve plaintext for all matches.
- General inputs for search scope and row binding remain unsupported for EQL
  targets. The existing column and keyset profile can be released without
  claiming them.

The JSON contract now uses randomised projection order and ciphertexts bound
by cascaded tags. Semantic parity and cross-opening are required. Comparing
raw term bytes is meaningful only with controlled test randomness. Go typed
JSON adapters follow `encoding/json`, while raw JSON goes through the
engine's strict parser. Do not claim that arbitrary Go encoders preserve
every input byte.

## Prior query design: baseline and reconciliation

### No ORE equality in the first API

Decided on 25 October 2026: ORE does not support equality in the first API,
for any plaintext type. Equality uses the field's declared index that
supports equality. Parameterise capability selection by the index, by the
encoding or domain of the plaintext, and by the options. A future explicit
exact or injective integer encoding can then opt in to equality, without
changing the query syntax or the operator's wire identity.

Never infer `Eq` only from support for ordering. Text and other lossy
encodings cannot establish plaintext equality. A future opt-in must keep the
rejection of overlaps, with one selected provider for each operator. It must
not silently invalidate existing `(Equality, Ore)` definitions.

This policy does not disable JSON scalar equality. JSON scalar equality uses
value selectors, not ORE or OPE terms.

### The query design draft of 21 October 2026

On 25 October 2026, the whole user-supplied **Stack Encrypt query design**
draft was read. The draft is dated 21 October 2026. It is 654 lines long, at
`/Users/dan/Downloads/Stack Encrypt query design.md`. The source document
was not changed.

The document is explicitly a discussion draft, based on an earlier snapshot
of `next`. Its historical claims about code and releases were not checked
again as part of this reading.

Use the draft as the baseline for query design. It is not a settled
specification, or a reason to redesign queries from scratch.

### Existing proposal to carry forward

- The caller selects an operator and a typed field or target handle. The
  field supplies its own configured index. Remove `DefaultIndex` and the
  caller's `.via`.
- Each field has at most one index that supports each operator. Refuse
  overlaps at declaration validation, instead of choosing an index by
  priority.
- Declare operators, index capabilities, and admitted source types once.
  Derive or verify typed lookup, dynamic lookup, and discovery from that
  declaration. Avoid another capability table in EQL.
- Share query derivation and refusals through the same semantic functions.
  In particular, tokenise match input once, and keep the tokens needed for
  probabilistic verification in the query object.
- Keep index and source types in typed field handles. Unsupported operators
  are compile errors on the typed path, and validation errors on the dynamic
  path.
- Model the analyser's handling of letter case once, in its stages, instead
  of stating it in both the match configuration and the operator.

The draft already proposes three designs to reuse:

- the query call `cipher.query(op::Matches, text).on(&field).await?`;
- typed `FieldRef` handles;
- a loaded configuration and analyser that the dynamic plan owns (`Loaded`
  and `Arc<DynAnalyzer>`).

These designs do not yet settle how our typed factory options, derived from
the output, are initialised and shared with convenient `encrypt_into` calls.

### Reconciliation with this review

1. **Generate handles from the same output-target declaration.** The query
   appendix proposes an `EncryptionPlan` derive on the plaintext side, and
   generated encrypted counterparts. Our agreed starting point is the
   output-side `EncryptTarget` and `DecryptSource` derives. Recommended:
   emit typed handles from that declaration, without restating indexes
   separately on the plaintext. A convenience derive on the source side can
   later generate the same target. Hand-written plans remain lower-level
   composition, not required usage.
2. **Settle who owns the results of typed factories.** A generic `Match<O>`
   can fix a policy identity in its type. An arbitrary factory can still
   compute different values on different calls. Carry a resolved
   configuration instance through writes and field handles, and settle the
   API for its owner and its initialisation. The draft's ownership in the
   dynamic plan is useful precedent. That precedent does not prove that all
   static factory results are compile-time constants.
3. **Separate portable options from execution types.** JSON's Rust factory
   and its dynamic deserialiser can construct the same `JsonOptions`. To
   allow generic and custom analyser stages, the draft's `Match<O>` and
   `Match<Dynamic>` deliberately have different execution types. Keep shared
   validated options and semantic implementations for the portable subset.
   Do not force all typed analysers through a serialisable enum of stages.
4. **Accepted portability scope.** Release built-in advertised capabilities
   in Rust and Go together. Downstream custom Rust stages can stay
   explicitly typed-only, with `NotPortable`, until they are registered.
   This qualifies the draft's blanket "lands in Rust first" rule. This
   qualification must not become permission to defer the Go JSON capability
   under this plan.
5. **Include JSON capabilities before fixing lookup representations.** The
   draft's dynamic enum of 16 shapes covers equality, match, and scalar
   ordering, but not the new JSON target. For containment, `AtPath`, and
   extraction, extend the operator identity, operand shapes, result shapes,
   capability validation, and overlap rules. The draft's interim validated
   index list, using one capability table, is a workable starting point. Its
   specific closed enum is not a decision.
6. **Use the agreed model for context and scope.** Replace the assumption
   that context is only a label with separate ciphertext binding and search
   scope. Row binding does not flow into search terms. `PrimaryKey` is
   eligible for context only. `ScopeKey` is eligible for both context and
   scope. Apply the same declared scope to index generation and to queries.
   Keep the requirement to return or supply row context when decrypting
   selected results.
7. **Accepted validation timing.** All checks that do not need keys come
   before keys are resolved or loaded, including checks on query input. This
   replaces the draft's possible resolution of a named keyset before those
   checks. Reuse the same validator for Go's `check_query` and for
   execution, instead of copying it or the tokenisation. Provider facts, and
   cryptographic checks that need keys, remain later stages. This rule for
   validating operations does not forbid explicit earlier calls that
   initialise a client or keyset.
8. **Apply the user's prototype scope.** These parts of the older document
   are not constraints here: decoding legacy match options, deprecation
   requirements, release-preservation requirements, and frozen Go wire
   formats. Keep the new Rust, Go, and EQL consumers aligned. The appendix's
   `cipher.encrypt(plan, value)` and plaintext derive are illustrative older
   proposals. They do not replace our agreed entry points.

ORE equality is now decided, as described in [No ORE equality in the first
API](#no-ore-equality-in-the-first-api). Integration work remains on:

- how typed field handles are constructed and spelled;
- dynamic `Index<ValueFrame>` compared with a shared boundary of semantic
  functions;
- the feasibility of checking match options at compile time;
- Go's `check_query`;
- updates to the architecture decision records (ADRs).

Type-safe ordering of stages does not by itself validate runtime numeric
values or string paths. Stronger claims about const checks need proof in the
implementation. Treat these items as specific integration decisions, not as
an open-ended query API task. Coordinate their Go interface with PR #1353.

## Recommended owner: a reusable typed target definition

Status: recommendation for review. Use an immutable target definition to
own:

- the resolved options;
- prepared indexes and analysers;
- the rules for selecting context;
- the operation metadata.

The output derive generates the definition's typed field accessors from the
same declaration that generates encryption. The definition contains no
plaintext, row values, credentials, or selected keyset. A field handle
borrows or shares that definition, and keeps its plaintext and index types.
It is not an independent name plus a newly constructed default index.

### One selector name for encryption and queries

On 25 October 2026, the user said that encryption's `using` and the query's
`on` are confusing, and asked for one name to be considered. Recommended:
`.using(...)` for both. In each case it selects the definition or field
whose declared policy governs the operation. This spelling is proposed, not
yet accepted.

Encryption still accepts the requested target's associated definition type.
A query still requires `QueryTarget<Op, Input>` on a selected field or
single-value definition. Sharing one name does not weaken either bound, or
make a whole multi-field record a query target. The older `on` examples in
the supplied query draft show its earlier spelling.

Proposed usage, assuming the previously described `EncryptedUser` target:

```rust
let users = EncryptedUser::definition()?;

let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?;

let query = cipher
    .using(&users.email())
    .query(op::Eq, "alice@example.com")
    .keyset(&keyset)
    .await?;
```

`definition()` gets the shared resolved definition of that mapping from
source to target. Plain `encrypt_into` gets the same definition internally,
and does not call the options factory separately. `.email()` is generated
from the declaration of the output field, not from a second schema that
someone maintains by hand. The method name `definition` is proposed. It
names a resolved declaration, not a builder that users must reconstruct
before every operation.

### Call order and strict typestate

On 25 October 2026, the user required strict typestate for the fluent API.
The user prefers the reading `cipher.using(&field).query(op, input)`, and is
open to supporting both call orders. Recommended: document the
definition-first form as the canonical query form, and support the
operator-first form through the same request states:

```rust
let a = cipher.using(&users.email()).query(op::Eq, email).await?;
let b = cipher.query(op::Eq, email).using(&users.email()).await?;
```

Both forms are proposed. The current implementation is query-first, followed
by `.on(...)`. This recommendation changes that interface.

| Starting state | Method | Resulting state |
| --- | --- | --- |
| Cipher | `using(&definition)` | Definition bound, no query selected |
| Definition bound | `query(op, input)` | Query with its definition, operator, and input known |
| Cipher | `query(op, input)` | Query waiting for a definition |
| Query waiting for a definition | `using(&definition)` | The same query state as the definition-first path |

The transition that brings the definition together with the operator and
input has the `QueryTarget<Op, Input>` bound. A handle bound in the
definition-first order does not need to fix the future operator in advance.
Combining the two determines the index. It also determines the context
requirements.

Only the executable state implements `IntoFuture`. A bound definition alone,
a query missing its definition, and a query missing required context cannot
be awaited.

A typed context-input transition completes required context. Cases with
optional input or no input start in a valid state with context left out. On
the static path, completing context must not be represented only as an
unchecked `Option` plus a runtime error for missing input.

Do not expose another `using` transition after a query's definition has been
selected, or another transition on the request that selects a query.
Supporting these two orders does not promise every permutation of keyset,
context, and operation selection. Specify those transitions separately,
starting with context supplied after its required type is known.

Share the final query request, validation, and execution implementation,
instead of duplicating them for each call order. Errors that depend on
input, such as an invalid path, still need runtime validation. Typestate
checks completeness and capability, not the meaning of arbitrary values.

The same rules apply to encryption requests. A fixed-policy `encrypt_into`
has an implicit definition, so a caller can await it without `using`.
Selecting an explicit compatible definition is a single transition before
execution. This does not add a new ordinary `encrypt` receiver, or require
callers with a fixed policy to bind definitions by hand.

Completion tests must include:

- both query orders, with identical semantics;
- compile-fail cases for unsupported operators and inputs, awaiting too
  early, missing required context, and selecting a definition twice.

Borrowed definitions and shared handles must stay valid for the lifetime of
the request.

### Fixed declarations

Initialise the fixed definition lazily, in a way that can fail, and keep
each successful result for reuse. Allow explicit initialisation at startup
through `EncryptedUser::definition()?`. The shorthand write initialises the
definition on demand, and returns any error through its awaitable value.
Factory errors must not panic or perform key I/O.

Do not cache initialisation failures permanently. Coordinate concurrent
first use so that successful initialisation happens once. Handle reentrant
and recursive initialisation in the implementation, instead of allowing a
deadlock.

The identity of a definition is the complete concrete declaration, including
the mapping from source to target and any generic policy parameters. It is
not only the ciphertext's output type. Different instantiations must not
share a cache slot by accident. This is an implementation requirement. It
does not claim that a static inside a generic Rust function is automatically
one per monomorphisation.

Fixed factories must describe stable application policy. They are not the
interface for reloading environment settings, or for options that differ for
each tenant. The cache makes writes and queries in one process share the
resolved policy. It does not prove that another process, or an older stored
row, uses that policy. Per-call context, source values, and keyset choice
remain separate inputs.

### Runtime declarations

Load or create a separate definition instance for runtime options. A
configured instance is not stored in the fixed-declaration cache. Use the
same type of definition and field handles, so that queries and writes share
that instance.

Proposed Rust spelling for a configurable library target:

```rust
let payroll = EqlEncryptedJsonTree::configure(options)?;

let encrypted: EqlEncryptedJsonTree = value
    .encrypt_into_with_context(&keyset, column)
    .using(&payroll)
    .await?;
```

Here `using` takes a resolved typed target definition, not a hand-built
plan. This requires a lazy conversion request: select the definition before
building the operation or calling a default factory. Awaiting the request
lowers it to the existing `Pending` and batch executor, and the shared
engine does not change. The definition's output and source types constrain
the conversion. Queries use the same definition, or its field handles, and
supply the required context and keyset for that call.

A fixed-policy wrapper such as `EncryptedPayroll` does not allow its
declared options to be overridden at runtime. Use the configurable
underlying target for the runtime case, so that nothing silently overrides a
fixed policy. The exact configuration APIs for runtime definitions with
several fields are still to be specified. They must select typed options
without introducing another execution mechanism.

Go's loaded dynamic plan owns its resolved definitions, and generated field
accessors reach those definitions. Go has no Rust factory to call. The guest
validates and builds the configuration once for each loaded declaration, and
then writes and queries use the loaded instance. A different runtime policy
is a different instance. It does not change an instance that operations in
progress are using.

### Implementation proof and boundary

Prove the cache and handle design early with:

- two fixed mappings;
- several generic instantiations;
- concurrent first use;
- an initialisation failure followed by a retry;
- separate runtime instances.

Prove that a query and its write use the same options without calling the
factory twice. Keep the source lifetimes, the support for owned sources,
batch lowering, and the builds without HTTP and for WebAssembly. A query on
a field without the operator must remain a compile error, with dynamic
equivalents checked at declaration or query validation.

Prefer this approach, with generated definitions, over requiring callers to
write a second plan or putting configuration state in each ciphertext. Plans
are still the lower-level implementation of the definition. Portable
serialisation of options and discovery of index capabilities remain part of
its dynamic contract. The definition object does not itself need to
serialise arbitrary Rust closures or custom analyser code.

## Single-ciphertext representation and plaintext ownership

Accepted on 25 October 2026:

- Use `OpaqueEncode` and `OpaqueDecode` to represent a value as a single
  ciphertext. They replace the working names `EncodeValue` and
  `DecodeValue`.
- Direct `encrypt` and target-directed `encrypt_into`, including their
  context-taking variants, consume their values. Both operations take
  responsibility for cleaning up owned plaintext.
- These are representation capabilities, and the engine still performs the
  cryptography. `EncryptTarget` and `DecryptSource` describe how encrypted
  outputs and layouts compose those operations.
- The lifecycle and cleanup scope below are part of the accepted design.
- The bound for plaintext cleanup is `Zeroize`. The implementation is not
  finished.

### Owned input is the direct API contract

`keyset.encrypt(value)` and its context-taking counterpart take an owned
single-value input. There is no implicit clone and no `Clone` bound.

For example, passing a `String` transfers it. A borrowed `&str` does not
transfer the storage it refers to. So it must not receive the same cleanup
promise. Do not add a silent fallback to borrowed input in the consuming
operation.

Decided on 25 October 2026: require `Zeroize` for plaintext types, and use a
guard that the library owns. For now, use that existing ecosystem trait,
instead of defining a new cleanup trait or another adapter for protected
ownership. `Zeroize` supplies the wiping operation, and the library must
arrange to call it on every supported exit path. A bound alone does not
arrange cleanup on drop.

Acquire protected ownership synchronously when creating the encryption
request, before returning its future or builder. The body of an `async fn`
does not run until the future is polled. If the first guard were inside that
body, a request that is never polled would drop its source in the ordinary
way. A synchronous constructor that returns the typed future can set up the
guard first. Every later builder transition moves that guarded ownership,
instead of making a new unprotected copy.

The representation trait can encode through a temporary internal borrow of
the guarded value, into a sensitive sink that the library owns. Public
consumption does not require giving an encoder unrestricted ownership of the
source, or an ordinary growable `Vec<u8>` for scratch work. Wipe and release
the source as soon as encoding no longer needs it. Keep the encoded
plaintext guarded until sealing completes. Keep the boundary of a
representation as a single leaf.

### Cleanup scope and implementation obligations

- Cover owned source storage, encoded buffers, codec scratch space, and any
  plaintext copies that the library creates. Use established wiping
  primitives that the compiler cannot remove, or protected storage. Do not
  rely on `clear()` or an ordinary drop alone.
- Cover success, errors in encoding, configuration, KMS, and AEAD, partly
  prepared batches, cancelled requests, and a request dropped before it is
  polled. Use drop guards for ordinary unwinding too. A process abort or a
  leaked future does not run destructors, so neither is covered.
- Avoid reallocations that leave uncleared buffers behind. Sensitive sinks
  that grow must have a cleanup strategy for their old allocations. Prevent
  plaintext from escaping in diagnostics, `Debug` output, caches, and
  instrumentation.
- On decrypt, protect the recovered bytes and partial decode state until
  cleanup, or until ownership passes successfully to the caller.
  Successfully returned plaintext is kept on purpose. After the return, its
  lifetime is the caller's responsibility, unless the return type itself is
  protected.
- A Rust move does not prove that all physical copies were erased. In
  particular, `Copy` inputs leave the caller's originals usable, and
  compiler temporaries may exist. The API promise that can be enforced
  covers supported owned storage and the artefacts that the library manages.
  It does not cover copies that the caller keeps, or every remnant in
  registers and on the stack. Check stronger claims with evidence from the
  compiled code.

The [zeroize documentation](https://docs.rs/zeroize/latest/zeroize/)
describes guards based on drop, wiping that the compiler cannot remove, and
the limits involving moves, stack copies, and reallocations. The source
currently uses `Protected<Vec<u8>>` at the AEAD boundary. That does not
establish cleanup of every caller value and intermediate from end to end.
This discussion is a design requirement, not a completed audit of
zeroisation in the source or the assembly.

### Consequences for blobs, layouts, and Go

`OpaqueBlob<T>` cannot promise to clean up the source from `T: Serialize`
alone. Require `T: Serialize + Zeroize` for the proposed blob input that
uses Serde. Owned blob decoding requires `T: DeserializeOwned + Zeroize`.
Ordinary application structs can derive `Zeroize`.

A generic Serde implementation can allocate or keep hidden copies, so strong
claims also need a supported contract for the codec and implementation.
Wrapping the final byte buffer does not make arbitrary user serialisation
code compliant.

In particular, `T: Zeroize` only supplies cleanup once a `T` exists. Suppose
a derived `Deserialize` allocates a `String` field and then fails on a later
field. The fields built so far drop in the ordinary way, without calling
`T::zeroize`. Even adding `ZeroizeOnDrop` to the enclosing struct cannot fix
a struct that was never constructed. Keep this as a concrete requirement for
decoder design and acceptance, and do not claim that the new bound solves
partial decoding.

### Blob codec assessment: Vitamin C frames

#### Stable storage format first

Decided on 25 October 2026, as the priority: first define a stable,
versioned binary storage profile. The codec was first designed for
short-lived transport, and stored blobs need a stronger compatibility
commitment. Improvements to zeroisation and constant-time implementation can
follow, provided they keep the meaning of the stored format.

Do not defer decisions that affect stored bytes, such as option presence,
type mapping, and versions. Do not claim timing or cleanup properties that
are not implemented. The `Zeroize` input bound and the ownership direction
remain. [Vitamin
C #519](https://github.com/cipherstash/vitaminc/issues/519), created for
this review, tracks this action. The issue explicitly separates storage
stability from the transport-only reasons in Vitamin C #332.

#### Storage profile implemented in Vitamin C and Go

By 27 October 2026, Vitamin C's dedicated storage profile, and its Go reader
and writer, addressed the format work from #519. That work is in Vitamin
C #520 and #526, carried onto upstream main by #544. Stack #1369 and #1370
adopt the Go codec: generated opaque structs call `vcffi.MarshalStorage` and
`UnmarshalStorage`.

The profile is versioned (`VCS` plus a version). It supports explicit
optional values and typed map keys, and it is separate from transport. Do
not report these properties of the transport mapping as defects of the new
storage profile:

- the ambiguity of `Some(())`;
- the rules that allow only text map keys.

Go generated shapes use `vc` tags and `GeneratedVersion2`. A reader rejects
unsupported future blob versions with a distinct error, and still falls back
to the old JSON encoding. Go storage mapping has these documented
qualifications:

- nil containers become empty;
- supported nonfinite floats round-trip;
- generation refuses unsupported opaque types.

Go pointers and Rust `Option` do not always write identical bytes, so
cross-reading tests and the normative corpus matter.

#### Remaining Rust and release work

Rust workspaces still use Vitamin C 0.8.0 from crates.io. So this work does
not implement the final proposed Rust `OpaqueBlob` facade. When that facade
is built, adopt the dedicated storage entry points, instead of reusing the
transport Serde codec for storage. Go's temporary pseudo-version dependency
must move to released module tags for a final Go release. A new evaluation
of serialisers is not on the critical path for customers.

Stable bytes do not establish constant-time behaviour or complete cleanup.
Keep the remaining work on guarded output, temporary buffers, partial
decoding, and values that the caller owns, without changing the stored
format. The JSON tree keeps its own node and envelope encoding. Freeze its
post-cascade profile separately from opaque blobs.

### Cleanup in target-directed encryption and at the Go boundary

The same consuming contract applies to target-directed `encrypt_into`. For a
structural target, declared passthrough fields move into the output on
purpose. Wipe encrypted source fields and temporary copies, not plaintext
fields that the caller explicitly chose to keep. Where possible, the fan-out
to ciphertext and index operations should read a guarded source, instead of
needing a plaintext clone for each operation.

As part of the Go implementation, specify cleanup for dynamic transport
between host and guest, and for JSON parsing buffers. The Rust guest cannot
erase Go caller objects that it never owned. Copies that the host manages
need cleanup by the host, and ordinary Go values do not gain Rust move
semantics. Document that boundary, instead of claiming that guest cleanup
erases every copy in the calling process.

Acceptance work:

- observe source cleanup and drop on successful and failing requests;
- test cancellation, and requests dropped before they are polled;
- cover nested source and blob cases;
- cover owned inputs that are not `Clone`.

Where necessary, inspect optimised code for wiping and copying behaviour.
Ordinary tests alone cannot prove that no copy remains. Do not infer a
current vulnerability, or a completed guarantee, from this design
discussion.

## Configured-target implementation sequence and completion criteria

Commitments to customers replace the earlier sequence, in which the Rust and
Go front ends moved in step. The foundational Go JSON work and the adoption
of opaque storage are now merged.

1. **Specify the implemented contract.** Keep the proposed schema envelopes
   distinct from the current field-map grammar. Record these in the formal
   interoperability specification and conformance fixtures:
   - target options;
   - operator input and result encodings;
   - grouped reads;
   - errors;
   - the column and keyset profile.
2. **Close the actual remaining customer gaps.** The gaps are opening a
   child bound to its parent, and complex ordered-path declarations if
   needed. The gaps also include configurable Go match options (#1112), and
   the tokeniser and filter pipeline. #1397 already supplies short
   whole-word matching through EQL. Confirm the leakage accepted for it, and
   freeze its index semantics, instead of planning it as unimplemented.
3. **Validate and freeze the release candidate.** Run the existing suites
   for the engine, for Go with the guest, and for PostgreSQL against the
   selected bundle. Keep numeric and null behaviour, tamper checks on
   cascaded tags, wildcard semantics, fallback semantics, known omission
   limitations, and post-cascade stored vectors. Tests that are already
   merged do not prove that this review ran a release build again.
4. **Release the dependencies and the customer interface.** For a final
   release, replace Vitamin C's temporary Go pseudo-version pins. The
   existing guard allows them in prereleases. Opaque storage is already
   integrated. Keep it separate from the JSON-tree storage profile. Build
   production guests and the matching SQL.
5. **Complete the Rust convenience APIs and packaging.** Implement public
   traits, derives, the definition lifecycle, and crate moves within the
   frozen Go and data contract. Direct EQL conversion is an optimisation
   that keeps the format.

Use one execution engine throughout. The final Rust facade and package
layout do not gate the existing Go JSON profile. Do not reimplement
configured JSON options, or reads that Rust verifies against the original
request: both are already merged.

### Required deliverable: dynamic interoperability specification

The user requires a formal specification of the dynamic interoperability
layer, developed during implementation. Do not write it afterwards as
documentation, after the Rust API has diverged from the Go API. The current
examples remain proposals until they are reconciled into that specification.
Adding this deliverable does not claim that the specification has been
written.

Recommended format: a versioned specification package that contains:

- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
  schemas;
- normative rules for semantics and wire format;
- executable conformance fixtures.

JSON Schema describes the structure of declarations, requests, and
responses. It is not the whole specification of behaviour or of the binary
transport. Keep application declarations of semantic types distinct from
JSON Schema's own `type`, `$defs`, and `$ref` vocabulary.

Required coverage:

- **Definition grammar.** Named ordinary types need no role. Naming a type
  does not make it eligible for scope. The grammar covers:
  - built-in and named types;
  - the optional `types` section;
  - inline role wrappers;
  - context selectors and scope eligibility;
  - passthrough and context storage;
  - targets and options;
  - query capabilities and defaults;
  - handling of unknown fields and extensions.
- **Semantic validation.** Resolve named types and field references, and
  reject invalid or cyclic references where they are unsupported. Enforce
  the capabilities of primary keys and scope keys recursively. Check that
  sources and outputs are compatible, and derive agreement between the write
  scope and the query scope. Do not imply that generic JSON Schema
  validators perform the engine's reference resolution or capability checks.
- **Operation contracts.** The contracts cover:
  - input presence;
  - the roles of context and scope;
  - target and definition identity;
  - results;
  - stable error codes and locations, without plaintext values;
  - validation stages;
  - which failures come before key I/O.
- **Wire mapping.** Specify the application binary interface (ABI) between
  host and guest, or reference its versioned specification. JSON authoring
  syntax must not silently redefine the binary transport. The mapping
  covers:
  - JSON and frame representations;
  - integer widths and ranges, and lossless numeric transport;
  - encodings of bytes and text;
  - missing compared with null;
  - context ordering and grouping;
  - the lowering of descriptors, AAD, and index scope;
  - normative references to the ciphertext and SQL envelope, and to tag
    extraction.
- **Versioning.** Explicit protocol and schema identifiers, handling of
  supported versions and capabilities, and rejection of unsupported
  features. Define future evolution without adding compatibility obligations
  for the prototype.

Conformance fixtures include accepted and rejected definitions and requests,
expected error codes and paths, normalised definitions, and deterministic
vectors for context and encoding. Run the same fixtures through Rust and
through the Go guest path, and through SQL extraction where relevant.
Compare randomised ciphertexts by cross-decryption and query behaviour, not
byte equality. Schema validation is one layer of the suite. Semantic
rejection tests are required even for structurally valid JSON.

Keep a single maintained contract. Prefer generating structural schemas and
capability metadata from the shared declaration models and catalog, where
that faithfully represents the specified grammar. Commit the generated
artefacts and check them for drift in CI.

Review generated schemas against the normative rules, instead of treating
Serde derives as a complete specification. This interface does not use HTTP.
Do not introduce OpenAPI, or a new transport, only to document it.

## Coverage of the complete review

The configured-target work above covers review issue 13 in depth. The full
API redesign also needs the work in this table. Each row names a concrete
deliverable. Recommendations do not silently settle the open decisions.

| Work area | Review issues | Required deliverable |
| --- | --- | --- |
| Public methods, traits, and ownership | 1, 3, 5, 9, 10, 14 | One map of signatures, imports, and receivers; operation-trait design; and migration of dependencies |
| Context contract | 1, 3, 4, 11, 12, 14 | Context rules for scalars and records, explicit optionality, and a matching dynamic representation |
| Ciphertext persistence | 2, 8 | Opaque scalar output, canonical bytes, Serde and Base64 behaviour, and a defined boundary with structural trees |
| Whole-value wrapper | 8 | Codec, authenticated format version, decode contract, and bounded timing claims |
| Mixed records and collections | 7, 8, 11 | Derive support for passthrough, renaming, and context fields, and retained collection batching |
| Configured targets and queries | 13 | Typed Rust factories, dynamic options, configuration lifetime, JSON conversion, and Go coverage |
| Names, integration, and release | 5, 6, 9, 10, 13, 14 | Final glossary, coordinated consumer updates, format fixtures, and executable public examples |
| Parallel Go JSON work | 15 | Reconcile PR #1353 and tasks #1348 to #1352 with this contract, and reuse compatible implementation work |
| Prior query design | 16 | Reuse the supplied field-owned query model, and reconcile handles, configuration ownership, JSON capabilities, and portability |
| Consistent definition selector | 17 | Choose one method name for encrypt and query. Recommended: `using`, with bounds specific to each operation |
| Single-ciphertext encoding and cleanup | 18 | `OpaqueEncode` and `OpaqueDecode`, consuming `encrypt` and `encrypt_into`, guarded lifetimes for sources and buffers, and an explicit cleanup scope |

### A. Consolidate the public Rust method and trait structure

This is the workstream for the Rust facade. Under the latest customer
ordering, make only the engine and contract changes that Go needs before its
release. Defer standalone Rust convenience work and the move of traits. The
sections below organise the full scope of the review, not the critical path
for customers.

Keep the agreed ordinary keyset receiver and the `EncryptInto` conversion
forms. Use the accepted destination-directed decrypt pair. Write out all
signatures, imports, bounds, and return types before renaming traits. Keep
the ordinary keyset `decrypt` and `decrypt_with_context` for opaque
ciphertexts. Remove redundant prototype conveniences without compatibility
shims.

Separate plaintext representation, target operation declarations, and
execution conveniences explicitly. Resolve two inconsistencies:

- `EncryptFrom` declares `encryption()`, while `encrypt_from` is on
  `EncryptInto`;
- `DecryptFrom` supplies methods, while `DecryptInto` describes opening.

A rename without a map of ownership and signatures leaves the discovery
problem unsolved.

Recommended: Stack owns the public model for encrypting values, and Vitamin
C keeps general primitives. Specify the dependency boundary before moving
code. Keep one canonical identity for each trait, and keep the builds
without HTTP and for WebAssembly. Reassess the original mismatch with
Vitamin C's cipher trait in that architecture. Do not add a public trait
implementation only for symmetry, if it cannot pass structured KMS context
or support the operations it advertises.

Completion criteria for work area A: representative scalar, blob, typed
record, searchable record, and JSON calls compile with the documented
imports, including from generic callers. The method inventory has no
unexplained duplicate execution path. Compile-fail tests cover the trait
capabilities that are not supported.

### B. Turn the context scenarios into a normative contract

The nine scenarios in the [context
examples](2026-10-24-stack-encrypt-context-examples.md) are the acceptance
matrix, not optional examples. Cover:

- a scalar's static context plus a caller extension;
- selecting a source field;
- caller input;
- storing context in the output;
- recovering context, or checking expected context, on decrypt.

Keep the accepted `field = "id"` shorthand as a selection on both inputs:
the plaintext on encrypt, and the stored output on decrypt. The shorthand
does not copy anything implicitly.

Fix the composition order and grouping once: the literal or field base, then
the composite row context, then any caller extension. Specify the exact
descriptor and AAD encoding for each case. An expected context checks the
stored context, and is not another extension. A caller must never need to
open a ciphertext to discover the context required to open that ciphertext.

Recommended: represent no input, required input, optional extension, and
optional expectation as explicit capabilities. Do not infer optionality from
the application's `Default` implementation. Settle the wrapper or trait
mechanism together with the public signatures. Resolve the existing mismatch
in empty context between ordinary scalar encryption and ciphertext targets.
Do not weaken the requirement for nonempty context on search targets while
doing so.

Give each rule for source, storage, and composition a dynamic representation
and a way to write it in Go. Reconcile the current EQL identifier
constraints with row and caller context explicitly. Do not bypass those
constraints, or drop context silently.

#### Separate ciphertext binding from search scope

Status: recommendation for the next discussion, not yet a decision.

Distinguish ciphertext binding from search scope. A row ID can bind a
ciphertext to its record without making every index term specific to that
row. The target definition should describe both scopes explicitly. Query
construction uses the same declared search scope as index generation.

For example, a searchable email can bind its ciphertext to
`(users.email, tenant_id, user_id)`, while its equality index is scoped to
`(users.email, tenant_id)`. A query can then run before the user ID is
known. Do not silently remove components from one generic context argument.
Index-key derivation and KMS descriptors must respect this separation too.
Changing only the leaf AAD is not a complete design.

Settle the conceptual split before choosing attribute names or exact tuple
encodings, and represent it in the dynamic definition as well.

The user's direction: allow ciphertext bound to a row, and document that
reads must supply the row ID to decrypt. Search scope should cover several
rows, such as a tenant. Including a row ID automatically would defeat
ordinary search.

#### Misuse-resistant API (recommendation, not accepted)

- Give the existing record `context(field = "id")` and its directional
  variants the meaning of ciphertext binding. Do not implicitly feed those
  selected fields or caller extensions into index keys or terms. This is a
  proposed clarification for searchable targets. Older examples did not
  distinguish the roles. Update them all together before implementation.
- Declare search scope separately, on the shared target definition. A named
  application scope input, such as `TenantScope`, can come from operation
  configuration or caller input. The capability proposal below also allows
  record-field selectors, when their types explicitly qualify as scopes.
- Writing index terms and constructing queries both require the same typed
  scope. A cipher bound to a tenant can supply the scope only through an
  explicit declared mapping. Never guess the scope from unrelated metadata.
- A binding input and a search-scope input are distinct capabilities, even
  when their underlying values have the same Rust type. Do not provide a
  blanket implicit conversion between the roles. If one operation needs both
  caller inputs, use named members in its typed input, not one unlabelled
  value routed to both operations.
- Missing required scope prevents awaiting a Rust request. Dynamic and Go
  validation reject it before key I/O. A default column-wide scope is not
  substituted when a tenant scope is missing. Searches without scope use an
  explicitly declared column-wide policy, and still bind the column
  identity.
- The effective ciphertext binding should include the declared search scope
  as well as the record binding. Then changing a supplied tenant also
  prevents opening the ciphertext. Index derivation uses only the column
  identity plus the search scope. Query requests never require
  record-binding input.
- Encrypted output must expose whatever the decrypt selector needs, or
  require it from the caller. Examples that project records must select the
  ID. No decrypt fallback drops row binding. Selecting a field as context
  does not implicitly store that field.

Working declaration spelling:
`#[stash(context(field = "id"), search_scope(caller = TenantScope))]`. The
spelling is illustrative. The spelling keeps the agreed directional-context
shorthand, and gives search an explicitly separate role. Dynamic definitions
must keep this separation, instead of providing one shared collection of
context values.

This design stops row IDs from spreading into search terms by accident. The
design cannot prove that the application chose a scope that contains several
rows. A user can deliberately put a row ID inside `TenantScope`. Do not
claim otherwise, or try to infer meaning from field names such as `id`. Use
explicit types, declarations, and documentation for that remaining
application choice.

#### Scope capability and role wrappers

Status: proposal under discussion.

Use both ideas together. Scope is the subset of context that search terms
are allowed to use. Semantic wrappers provide positive trait implementations
that identify that subset. The working capability names are
`CiphertextContext`, and `SearchScope: CiphertextContext`. These names
describe eligibility, not source selection, optionality, or encoding.

Integrate these capabilities with the existing context representation,
instead of introducing a competing serialiser. The previously agreed
`ContextInput` capabilities still describe whether the caller must supply a
value.

For example, `PrimaryKey<T>` implements eligibility for ciphertext context,
but not for search scope. `ScopeKey<T>` implements both, subject to the
inner value's supported context encoding. Generic parameters are Rust types,
such as `PrimaryKey<u64>`. By contrast, `PrimaryKey(42)` is a value
constructor.

The name `ScopeKey<T>` is preferred for the second wrapper. The user
accepted it in place of `Collection<T>`, because `Collection<T>` can read as
a container. These wrappers need the appropriate `Zeroize` support when they
are owned plaintext fields, consistent with the existing ownership decision.

Neither wrapper automatically adds the field to context or scope, stores it
in the encrypted output, or changes the plaintext's encryption layout. The
target declaration still selects sources. An illustrative declaration is
`context(field = "id"), search_scope(field = "tenant_id")`. With
`id: PrimaryKey<u64>` and `tenant_id: ScopeKey<u64>`, the selection is
valid, and selecting `id` as search scope is a compile-time error. This
makes typed field selection a reasonable alternative to the earlier
recommendation to accept only search scope supplied by the caller.

Requirements for misuse resistance:

- No blanket `SearchScope` implementation for every context type,
  serialisable type, raw number, or raw string. Using a value as scope is an
  explicit classification.
- A composite scope qualifies only when every component is a scope. A tuple
  that contains a primary key cannot become a scope only because it is a
  tuple. Context composites can contain either category.
- Do not pass scope eligibility through `Deref`, `AsRef`, or implicit
  conversions that remove a primary-key wrapper. Typed target and query
  handles keep the definition's concrete scope type, and do not accept any
  other type that implements `SearchScope` in its place. Distinct
  application newtypes can tell tenant and project scopes apart, even when
  their wire types are equal.
- Allow explicit opt-in by applications through a documented trait or derive
  contract. This is a semantic capability, not an unsafe-memory contract.
  Sealing every implementation cannot prove that a value groups several
  records, because a caller can still explicitly rewrap a row identifier as
  a scope. Guarantee that accidental mixing of roles is rejected, not
  business semantics.

Dynamic definitions must keep field roles, and the choice between context
and scope for each selection. Validate those roles before execution: a field
explicitly declared as a primary key is not eligible for scope. A plain JSON
number has no role by itself. Do not infer a role from the field name or the
wire encoding. Generated Go types can represent the distinction, while the
engine validates dynamic declarations.

Rust and dynamic lowering must produce the same canonical context and scope
values. Never use Rust type names as wire domains. Classifying a value as
scope is not evidence of authorisation to access a tenant.

Acceptance work:

- valid typed field scopes and caller scopes;
- rejected primary-key scopes and mixed-tuple scopes;
- no automatic selection of marked fields;
- exact agreement of scope type between write and query;
- equivalent dynamic validation.

#### Dynamic scope roles and validation

Recommended design: declare semantic types and source selectors in the
definition, validate them once on load, and supply values separately for
each operation. Do not let an individual request assert `scope_key` on an
arbitrary value to override the loaded definition. A definition author can
explicitly classify values, in the same way that a Rust author can construct
wrappers. This resists misuse. It is not authorisation, or proof that a
scope covers several rows.

Accepted clarification: `types` is optional, and contains reusable named
types. Fields can use built-in types or inline role wrappers. Ordinary
built-in or named values need no `kind`. Supported primitives remain
eligible for ciphertext context. Eligibility for search requires explicit
`scope_key` classification, or another explicitly supported type that can
act as a scope.

Illustrative declaration fragment. This is a proposed schema, not today's
wire API:

```json
{
  "types": {
    "UserId": { "kind": "primary_key", "value": "u64" },
    "TenantId": { "kind": "scope_key", "value": "u64" }
  },
  "fields": {
    "id": { "type": "UserId", "passthrough": true },
    "tenant_id": { "type": "TenantId", "passthrough": true }
  },
  "context": { "field": "id" },
  "search_scope": { "field": "tenant_id" }
}
```

This is the context-related part of a record target definition. Encrypted
email targets and their search options are declared separately, as usual.
The shared `field` shorthand selects plaintext fields on encrypt, and stored
fields on decrypt. It does not imply that the field exists in a query
request.

For a query on the derived email handle, the definition exposes a required
`TenantId` scope argument. No `UserId` argument is required, or accepted as
an alternative scope. A named or composite scope uses the same ordered
schema on the write and query paths, even though their source selectors
differ.

Loading a definition:

- resolves field references, and source and output types;
- computes the context and scope capabilities;
- verifies all composite components;
- rejects a primary-key search selector before key I/O;
- verifies that decrypt selectors are available from stored fields or
  declared caller input.

Compile the validated definition into an immutable handle that encrypt,
decrypt, and query operations share. There is no second scope policy
specific to queries.

At execution, validate these against the selected definition: presence,
nominal type when a typed handle supplies it, physical representation,
range, and composite shape. Raw wire values get their expected semantic type
from the definition. A raw value cannot prove where it came from in the
application. Unknown role overrides and mismatched nominal value handles are
rejected. A query never falls back to unscoped querying when a required
scope is absent.

When JSON is the authoring or request format, keep full-width integers
through lossless parsing. The frame transport already distinguishes the
supported integer widths.

Recommended Go generation uses distinct named ID types, and query methods
that take the required scope argument (`TenantID`, not `uint64` or an
untyped context map). Generated wrappers remain conveniences over the same
validated runtime definition. FFI callers that do not use generated code get
runtime errors for invalid declarations and requests. Do not claim that Go
shares Rust's ownership or trait-bound guarantees.

Lower the chosen scope and binding through the existing canonical context
machinery, keeping scalar widths, ordering, and grouping. The current
dynamic `context.rs` proves parity between runtime `ContextPiece` trees and
Rust context derivations. It does not distinguish the primary-key role from
the scope role. Add role validation before lowering removes those
distinctions. Keep the resolved scope and the resolved binding available
separately to their own operations.

Do not store role labels in every row only to recover them at runtime.
Definition identity and deployment remain explicit concerns of loading the
same policy. Add Rust, Go, and dynamic fixtures for valid scopes,
primary-key refusals, nested scopes, missing inputs, and identical derived
terms and AAD.

Completion criteria for work area B: all nine cases run through Rust and
dynamic declarations. Required input is enforced, altered or wrong context
is refused, and existing context encodings agree across all new
implementations.

### C. Finish the ciphertext and whole-value storage contracts

Accepted direction: a single-value plaintext encoding produces one opaque
`Ciphertext`. A normal application struct uses `OpaqueBlob<T>` to encode and
seal it as one value, or an explicit target for field-level encryption.
Serde alone does not imply automatic blob serialisation. A custom type can
explicitly implement the single-value encoding capability. The wrapper name
and the detailed persistence contract remain proposals.

Recommended persistence behaviour:

- canonical byte parsing and encoding;
- human-readable Serde as Base64 of those bytes;
- binary Serde as bytes;
- safe `Debug` behaviour.

Parsing an envelope does not authenticate it. Authentication happens during
decryption.

The existing transcoder for encrypted output can implement the adapter.
`Visitor::sealed` consumes `Node::Single(SealedValue)` and moves it into the
opaque wrapper. Keep the sealed value internally, instead of forcing a byte
serialisation at construction. There is no new encryption or KMS request. On
decrypt, the wrapper delegates to the same leaf-opening path, using a
single-node wrapper if the internal API requires one.

Do not convert maps, sequences, passthrough nodes, or sealed markers for
empty containers into this type only because they have a byte
representation. Serialising a whole encrypted tree keeps its several
ciphertexts and authentication boundaries, and does not produce single-value
encryption. The leaf visitor's errors for unsupported shapes are a defensive
check, not the intended way for users to discover the rule.

Constrain ordinary encryption to inputs that can be encoded as a single
value. Unsupported structural inputs are then rejected before encryption:
statically in Rust where possible, and during dynamic validation. Settle the
exact plaintext capability together with the representation traits. Do not
discover an unsupported shape only after keys have been minted.

Keep generic structural encryption and searchable JSON explicit. Specify
whether persistence of structural trees is supported, and in what stable
format. Coordinate any protocol changes with their consumers.

#### Typed encodings and extractable ZeroKMS tags

Requirements added on 25 October 2026:

- Converting a ciphertext to text returns the existing concrete encoding
  wrappers, not `String`.
- The user also wants to explore selecting an encoded ciphertext as a
  field's output type.
- The ZeroKMS key tag must be easy to extract from a stored ciphertext,
  including in PL/pgSQL. This supports a refinable-tag mechanism that is
  designed separately.

The storage and authentication contract is not yet fixed.

The current `eql-bindings::encoding::{Base64Text, Base85Text}` validate
canonical padded standard Base64, and the crate's RFC 1924 Base85 encoding,
respectively. Their private strings, encoding constructors, and validating
deserialisers make decoding infallible. They guarantee the text encoding,
not that the bytes form a ciphertext. Reuse these types, and add ordinary
fallible conveniences for parsing text, instead of requiring Serde to
construct them from text.

Recommended ownership: a small Vitamin C encoding component, re-exported by
Stack Encrypt and EQL. These byte and text utilities do not depend on
encryption, SQL, or EQL layouts. Keep TypeScript and schema integration
optional in the owning crate, and account for Rust's orphan rules when
moving the existing trait implementations. Do not make Stack Encrypt depend
on EQL only to reuse its text wrappers. Final placement of the component
remains a proposal.

Proposed ciphertext methods `to_base64` and `to_base85` return `Base64Text`
and `Base85Text`. Matching constructors accept the typed text, and still
return a ciphertext parse error when the decoded envelope is invalid.
Encoding validation, envelope parsing, and authentication are three
different guarantees. Use one canonical byte envelope under both encodings.

Accepted on 25 October 2026: support explicit encoded ciphertext field
targets. Use a storage wrapper specific to ciphertexts, with the working
names `Base64Ciphertext` and `Base85Ciphertext`, instead of making every
`Base64Text` an encryption target. The wrapper validates both the text and
the envelope, and serialises as the text string. The wrapper composes with
`EncryptTarget` and `DecryptSource`: seal once and then encode, and parse
before opening.

These names stay provisional until the final naming pass, but the encoded
target, as a capability in its own right, is settled. A structural output
can mix `Ciphertext` fields and encoded ciphertext fields without extra KMS
calls. Do not silently change the prescribed representation of EQL targets.

The current `SealedValue` v1 envelope already uses a simple prefix:
`version(1) | keyset_id(16) | iv(16) | tag_len(2, LE) | tag | local_ciphertext`.
The envelope's ZeroKMS tag begins at byte offset 35, with its length at
offsets 33 and 34. This shows that extraction can be simple. It is not a
commitment to keep those offsets.

Document the chosen version's layout, and keep it parseable without the
plaintext codec, key retrieval, or decryption. Prefer a checked borrowed
view of the header or envelope, with an accessor explicitly named `key_tag`.
Do not decompose the whole ciphertext, or confuse the key tag with the AEAD
tag. Extraction does not authenticate the returned tag.

Release a matching SQL and PL/pgSQL extraction helper, and Rust, Go, and SQL
fixtures, with the storage format. Check versions, lengths, and truncation
before slicing.

For text storage, prefer Base64 when SQL must inspect the header.
[PostgreSQL's binary string
functions](https://www.postgresql.org/docs/current/functions-binarystring.html)
include Base64 decoding and byte slicing, but not Base85 decoding. If SQL
extraction from a Base85 envelope is supported, supply an explicit decoder.
Do not leave Base85 decoding as an assumed capability.

PostgreSQL's Base64 output also inserts line breaks, unlike the canonical
Rust wrapper. Normalise the SQL output, or validate it against the same
canonical rules in cross-language tests. JSON-tree storage needs its own
header adapter, because its shared key header is distinct from each node's
ciphertext and parent tag.

The proposed refinement uses the ZeroKMS tag as an HMAC (hash-based message
authentication code) key, and replaces it with a derived tag. The user
clarified the decryption behaviour: ZeroKMS uses the refined tag for policy
checks and logging, and returns the original tag. The decrypt path uses that
returned original tag to rebuild the leaf AAD.

This resolves the conceptual conflict with binding the original tag into the
AEAD. After refinement, the stored or request tag and the tag used as
authentication input need not be identical. Keep those roles explicit in the
KMS response and the decrypt implementation. Tag extraction returns the tag
actually stored in the envelope. That tag may be the refined one.

Protocol details remain deferred. This is the intended behaviour, not a
claim that the current client or engine already implements it. Add
integration coverage for refinement and decryption when that work is merged.

#### Single values for encrypt, collections for EncryptInto

Decided on 25 October 2026: direct `encrypt` handles one single-value input,
and `EncryptInto` handles collection composition and batching. This replaces
the earlier open question about applying encryption to collections
automatically. The agreed public examples are:

```rust
let scalar: Ciphertext = keyset.encrypt(1_i32).await?;

let batch: Vec<Ciphertext> = vec![1_i32, 3_i32]
    .encrypt_into(&keyset)
    .await?;

let blob: Ciphertext = keyset
    .encrypt(OpaqueBlob::new(vec![1_i32, 3_i32]))
    .await?;
```

The batch produces two independent ciphertexts through the shared batch
executor. The blob encodes and seals the complete collection as one value.
Do not add implicit collection handling to direct `encrypt`. Do not add a
separate batch entry point only to provide what `EncryptInto` already
covers. Context-taking variants follow the same division.

Acceptance checks:

- reject direct `encrypt(Vec<i32>)` before execution;
- support `Vec<i32>` to `Vec<Ciphertext>` without context;
- keep target-directed opening and batching of collections;
- recover the blob as a whole collection.

Existing collection composition is kept. Opaque `Ciphertext`, and its target
support without context, are new work.

The current prototype treats `Vec<u8>` as one byte value, but that is not a
compatibility constraint. The latest recommendation is uniform collection
behaviour. `Vec<u8>` to `Vec<Ciphertext>` encrypts individual bytes, while
`OpaqueBlob<Vec<u8>>` encodes the complete vector as one value. Do not add a
conversion from `Vec<u8>` to `Ciphertext`, or a bytes wrapper, only to keep
prototype behaviour. A distinct raw-byte capability would need its own use
case, and the blob codec need not reproduce the prototype's raw-byte
encoding.

#### Blob codec, format, and timing requirements

For `OpaqueBlob<T>`, select:

- the codec, owned by the library;
- an authenticated codec or type discriminator, and a version;
- the schema-evolution policy;
- the error behaviour;
- the supported source and decoded types.

Authenticate before deserialising plaintext. Do not silently reinterpret an
ordinary byte ciphertext as a different encoding. Keep an explicit wrapper,
not an implicit Serde fallback.

The constant-time question needs a concrete conclusion. Assess:

- `serdect`;
- the codec;
- both sides of Serde: the value traits, and the serialiser and
  deserialiser;
- disclosure of length and shape;
- which custom implementations are allowed.

If arbitrary Serde types remain supported, do not promise constant-time
serialisation from end to end. If that property is required, select a
restricted profile separately. Constant-time behaviour cannot be inferred
from the wrapper or its encryption primitive.

Completion criteria for work area C: scalar and blob examples persist, and
reload through a new cipher instance. The examples reject invalid encodings
and verify fixtures for the selected format. The supported timing contract
and the codec version are documented.

### D. Complete record derives and preserve collection composition

Implement explicit passthrough and renaming of source fields, independently
of context selection and storage. Generate decrypt reconstruction for the
same record. Support nested targets with and without configuration. Report
incompatible context or source types at their declarations.

Keep the existing collection behaviour: `Vec<S>` to `Vec<T>` composes the
target operations into one logical batch, instead of awaiting each row
separately. Keep the key granularity per document and per leaf. One logical
batch does not promise one physical ZeroKMS request beyond the backend's
limits.

Completion criteria for work area D: the public examples of mixed records
and searchable records run. These examples include batch encrypt and
decrypt, nested targets, renamed passthrough fields, and stored context.
Dynamic and Go declarations produce equivalent semantics. A plaintext-side
derive that generates output types is a deferred convenience, not a
prerequisite for these workflows.

### E. Finish the configured policy's lifetime and query interface

Use the query-design baseline and reconciliation in [Prior query
design](#prior-query-design-baseline-and-reconciliation). The query model is
not an empty design space. A detailed proposal already exists for
field-owned index selection, typed handles, and shared derivation.

The direction of typed factories is established. The [target definition
section](#recommended-owner-a-reusable-typed-target-definition) now proposes
their owner. The owner is a shared immutable fixed definition or an explicit
runtime instance, with generated typed field handles. Review that proposal,
and prove its initialisation and lifetime behaviour, before treating the
claim of reuse after one resolution as implemented. Runtime configuration
with several fields, and the exact generated signatures, still need to be
specified.

Write complete static and Go examples for equality, JSON containment,
ordered paths, and extraction, all using the write policy. Specify query
results and the errors for unsupported operations. Keep those examples free
of mandatory hand-written plans. Keep direct typed EQL conversion, and
support in the catalog and guest, as deliverables of the configured-target
sequence.

### F. Make naming and coordinated integration part of completion

Use the [packaging glossary](2026-10-25-stack-encrypt-packaging.md) for:

- the proposed role-based JSON names;
- the retained `OpaqueBlob` and `Ciphertext` spellings;
- the shared format crate;
- the split between primitives and the application layer.

Keep the accepted names of the declaration and convenience traits.
Recommended: rename the plan builder's output-selection method to `target`,
and distinguish it from executing `EncryptInto`. New spellings and crate
moves still need review.

Remove replaced APIs directly, and update the EQL, Go, and guest consumers
together. There is no requirement to read prototype ciphertext or keep old
imports. Specify the selected encoding and cryptographic semantics, and set
up fixtures for that contract from now on.

Completion criteria for work area F:

- all public examples are executable tests;
- cross-opening and querying between the static and dynamic paths pass
  against the selected storage format;
- batching checks pass;
- the guest builds remain supported.

No new API is described as implemented until it meets its Rust and Go
acceptance criteria. These are the completion criteria for the full
redesign. The earlier Go release uses the gates for Go, the engine, and
storage in the [implementation
sequence](#configured-target-implementation-sequence-and-completion-criteria).
Those gates do not depend on the facade.

## Recommended order for the remaining design decisions

### Decision checkpoint on 25 October 2026

These directions are settled:

- single-value encryption directed by the keyset;
- collection batching directed by the target;
- explicit `OpaqueBlob`;
- conversion methods separate from the `EncryptTarget` and `DecryptSource`
  declarations;
- explicit context-input capabilities instead of `Default`;
- typed Rust options factories, and dynamic deserialisation into the same
  options;
- static and dynamic support together;
- shared typed definitions and field handles;
- a consistent `using` selector, with strict typestate and definition-first
  query spelling;
- `OpaqueEncode` and `OpaqueDecode`;
- consuming `encrypt` and `encrypt_into`, with guarded cleanup;
- ordinary keyset decrypt alongside the destination-directed decrypt pair,
  both with context variants, and both returning ordinary owned `T: Zeroize`
  results;
- separate ciphertext context and search scope, with `PrimaryKey` and
  `ScopeKey` eligibility;
- validation of roles when a dynamic definition is loaded, optional
  named-type declarations, and explicit scope eligibility;
- a versioned interoperability specification with shared conformance
  coverage;
- no backward compatibility with the prototype.

Do not reopen these choices only because older examples or descriptions of
work areas still use provisional wording.

### Remaining questions

The remaining product and API decisions are narrower. Keep them separate
from the obligations to specify and implement:

| Remaining question | Decision required |
| --- | --- |
| JSON contract completion | The main Go interface is implemented. Close the gaps in opening a child bound to its parent, and in formal conformance. Use the current semantics of cascaded tags and random order. Do not reopen operator design, or rename released Go APIs for cosmetic consistency |
| Key selection and optional provider policy | Review keyset selection derived from plaintext, routed execution scoped to a client, and ZeroKMS lock context, as optional provider capabilities. In the provider-capabilities companion, assess the neutral boundary between data keys and index keys, and the deliberate non-use of Vitamin C's `AsyncCipher` |
| Customer storage profiles | Go opaque storage is integrated. For the final release, replace the temporary Go dependency pins, and freeze the post-cascade JSON and search profiles. Rust blob conveniences and crate moves can follow |
| Configurable match and short input | #1397 implements deterministic short-word terms in the same Bloom filter. Broader configurable Go tokenisers and filters remain, including #1112. Reconcile the earlier privacy concern explicitly. Merging support does not prove that leakage is unchanged |
| Packaging and names (review in progress) | Review the packaging companion's shared format crate, value execution owned by Stack, a Vitamin C boundary of primitives only, retirement of `AsyncCipher`, the ZeroKMS client rename, and role-based JSON names. Encoded ciphertext field targets themselves are accepted. The accepted trait names, `ScopeKey`, and receiver choices are not open again |

### Next steps

Next, complete the specification of the supported contract, and close the
remaining customer gaps in configuration and reads. Then validate the
release candidate, and resolve the pins for the final release. The original
end-to-end JSON implementation is already done. Packaging remains deferred.
Keep the initial ORE equality policy unchanged.

Specification and implementation work still includes:

- exact grouping and encoding of context and scope;
- the dynamic grammar and version identifiers;
- error codes;
- binary envelope fields;
- Rust, Go, and SQL fixtures;
- the flow of the refined tag and the original tag.

Record candidate choices in the formal specification for review. Do not
treat every byte offset or adapter signature as a new architectural
decision. The initial recommendation for persistence remains ordinary Serde
composition for explicit layouts, without a new wire format for arbitrary
trees.

Cleanup implementation still needs:

- guarded encoder sinks;
- handling of partial decoding;
- checks for cancellation and drop;
- an explicit adapter for drop-guarded results.

Under the user's latest sequencing decision, implementation improvements can
follow the stable format. Keep the stored contract, and document the actual
guarantees, instead of claiming that the eventual goals are already met.
This plan does not imply a completed constant-time or zeroisation audit.

The caching of shared definitions, the behaviour on initialisation error and
retry, generic identity, and request lifetimes still need concrete
signatures and proof. That is implementation design within the recorded
ownership model. It is not a reason to reopen whether writes and queries
share a policy.

Passthrough implementation, transcoder adapters, collection composition,
moving traits, documentation updates, and acceptance tests remain work
items. These items are not reasons to describe the agreed API direction as
undecided. The prototype needs no backward-compatibility phase. The customer
release creates a new commitment for Go and for persisted data.
