# Stack Encrypt API implementation plan

Date: 2026-10-24. Status: proposed implementation direction, developed from
the [review log](2026-10-24-stack-encrypt-api-review.md),
[public examples](2026-10-24-stack-encrypt-public-examples.md), and
[context examples](2026-10-24-stack-encrypt-context-examples.md).

This document turns the review into implementation choices and completion
criteria. User requirements are distinguished from recommendations that
have not yet been accepted. Examples below are proposed APIs, not working
code for the current release.

**Latest delivery decisions, 2026-10-25:** encoded ciphertext field targets
are accepted. The comprehensive JSON first-release contract and Rust/dynamic
examples are in [JSON operations](2026-10-25-stack-encrypt-json-operations.md),
including extraction and walks. ORE does not provide equality initially;
retain a future explicit capability for equality-preserving encodings.
Prioritize stable blob storage bytes via
[Vitamin C #519](https://github.com/cipherstash/vitaminc/issues/519);
zeroization/timing implementation improvements may follow without changing
stored format. The naming/package review is now in progress. These decisions supersede
earlier sequencing recommendations below where they conflict.

**Follow-up decisions:** custom Rust query stages may be explicitly
Rust-only, with `NotPortable` on dynamic export until registered; built-in
capabilities retain Rust/Go parity. Every validation independent of keys
runs before key resolution/loading. The user is still reviewing the JSON
operation contract; its detailed API proposals are not collectively
approved. New keyset-routing, lock-context and provider-capability questions
are assessed in [provider capabilities](2026-10-25-stack-encrypt-provider-capabilities.md).

**Packaging review:** the user favors retiring Vitamin C `AsyncCipher` and
moving application encryption behavior into Stack. The
[packaging and naming recommendation](2026-10-25-stack-encrypt-packaging.md)
defines crate ownership, an acyclic dependency graph, the proposed shared
format crate, role-based public names and coordinated migration work. It is
a proposal for review, not an accepted rename or an implementation.

**Compatibility scope (user clarification, 2026-10-25):** this API has only
existed as an early prototype. Do not preserve its APIs, stored ciphertexts,
or encodings for backward compatibility. No legacy decoders, compatibility
aliases, deprecation period, or data migration is required. Choose the
coherent new design and update its Rust, Go, guest, and EQL consumers
together. Engine output must still agree with the SQL that consumes it;
that is current interoperability, not a legacy-format requirement.

## Requirements established in the review

- Ordinary encryption is keyset-directed, with `encrypt` and
  `encrypt_with_context`. Keep the separate target-directed `EncryptInto`
  conversion interface; remove redundant public `encrypt_as`.
- Single-value encryption produces opaque ciphertext; `OpaqueBlob<T>`
  explicitly encodes a composite value before sealing it as one value.
  Direct `encrypt` does not automatically lift over collections. Use
  `EncryptInto` for collection batching, including `Vec<i32>` into
  `Vec<Ciphertext>` without caller context. This division is agreed as of
  2026-10-25. The current byte-vector recommendation follows that same
  collection rule and uses `OpaqueBlob` for a whole vector; there is no
  prototype-compatibility reason to add a raw-byte exception.
- Rust traits and derives are the primary static interface. Plans support
  those declarations and dynamic/FFI lowering.
- Design and deliver static and dynamic support together. Go support is an
  acceptance criterion, not a later follow-up.
- Provide decrypt entry points with and without explicit context. The
  no-context variant must not invent a default required application value.
- `OpaqueEncode` / `OpaqueDecode` name the single-ciphertext representation
  capabilities. Both `encrypt` and `encrypt_into`, including their
  context-taking variants, consume input and take responsibility for
  cleaning up owned plaintext and plaintext artifacts. Ownership alone is
  not a zeroization implementation; require `Zeroize` on plaintext types
  and enforce cleanup through guarded storage and lifecycle checks. Deliberate passthrough
  fields transfer to the output rather than being erased.
- Keep EQL's engine/SQL contract coherent and retain shared batching/execution
  behavior; prototype representations need not be preserved.
- Investigate and replace the EQL JSON adapter's serialization round trips
  with direct typed conversion, maintaining engine/SQL agreement.

## Recommended decision: general configured targets

Use a general target-plus-typed-options contract. Do not add a public
`json_tree(...)` derive construct. Rust constructs concrete options directly;
the dynamic interface deserializes its options into that same type. JSON
supplies the options type, validation, and implementation behind the general
mechanism. Sharing a contract does not require sharing input syntax or
making static Rust configuration pass through deserialization.

Three approaches were considered:

| Approach | Benefit | Limitation | Recommendation |
| --- | --- | --- | --- |
| Typed Rust options factory | Compiler checks the options type; normal Rust APIs and tooling | The function itself is not portable, but its concrete output has a data form | Preferred static surface |
| Named policy type holding options | Reusable and discoverable | Adds a provider trait and marker type where a function can suffice | Optional later convenience |
| Target plus data options | Expressible in Go declarations and dynamic data | Requires deserialization and semantic validation | Dynamic surface, producing the same typed options |

This supersedes the initial recommendation to put option field literals in
Rust attributes. Rejecting a Rust factory because its code cannot cross FFI
was unnecessarily restrictive: the common boundary is its typed result,
not the code used to construct it. No arbitrary encryption callback is
introduced; the factory only supplies configuration.

The target owns its source capabilities, canonical output, options/defaults,
validation, encryption description, index/query capabilities, and opening
behavior. Context remains a separate input. Configuration does not supply
arbitrary execution callbacks or let a caller redefine EQL's wire fields.

Implement configuration as a target capability (working name:
`ConfigurableTarget<S>`), lowering into the existing operation descriptions.
Its associated options type has a data representation. Rust factories
return that type directly; registered dynamic targets deserialize into it.
Validate and normalize once when a reusable declaration is built. Both
paths use the same target-owned semantic validator, before key I/O. Use
validated deserialization, for example a wire helper plus `TryFrom`, rather
than a derived deserializer that bypasses checked builders. Keep any raw
options fields private if the public type promises validated invariants.

Compile-time guarantees cover factory resolution and signatures, the
target/options association, and typed builder arguments. They do not imply
that a string is a valid JSON path or that the factory evaluates at compile
time. JSON path construction is currently fallible. Begin with a fallible
factory contract, `fn() -> Result<Target::Options, E>`, with errors converted
to the engine's configuration error path. Propagate errors without panics
or `unwrap`; a later literal-path macro can add stronger static validation.

Resolve the factory once per reusable configured declaration and reuse its
normalized options for writes and queries. A factory can read mutable
external state, so its type alone cannot prove a fixed policy; document
that fixed-policy providers must be stable. Do not independently reevaluate
the provider when generating a query. Intentionally variable configuration
belongs in an explicitly constructed configured-target instance.

Unlike today's `Layout`, the general capability must not require one index:
targets may have none or multiple. Adapt the existing JSON layout internally
while migrating; do not expose two competing configured-target concepts.
The target catalog resolves registered targets for Go. Custom Rust targets
remain possible without registration, but cannot be dynamically addressed
until their adapter and descriptor are included in the guest build.

## Candidate static syntax

`target(options = payroll_options)` names a Rust factory for the inner
target of a transparent newtype. The inner Rust type selects the output
representation and associated options type. The spelling is proposed;
typed factories for Rust and typed deserialization for dynamic callers are
the revised recommendation.

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

The factory body uses today's `JsonOptions` builder; the derive support is
proposed. The derive calls the factory and type-checks its result against
the inner target's associated options type. It knows neither JSON path
semantics nor JSON-specific option names, and does not serialize or
deserialize the factory's result. The configured target constructs its
output, which the derive wraps. Serde transparency preserves that output's
wire envelope; SQL driver traits are a separate integration requirement.
The same factory attribute should work on a field of a derived output
record, with existing context selection rules.

```rust
let encrypted: EncryptedPayroll = payroll
    .encrypt_into_with_context(&keyset, column.clone())
    .await?;

let restored = serde_json::Value::decrypt_from_with_context(
    encrypted, &keyset, column,
).await?;
```

Fixed policy is a recipe for writes and queries. Transparent deserialization
does not attest that an existing row was created with that policy. In
particular, the full ordered-path policy is not stored in the JSON header.

## Candidate dynamic representation and Go requirements

Extend the existing string target with an object form, using the current
type name provisionally rather than deciding a registry rename here:

```json
{
  "payroll": {
    "context": ["employees", "payroll"],
    "target": {
      "name": "JsonTreeDocument",
      "options": { "ordered": ["$.salary"] }
    }
  }
}
```

Keep `"target": "TextEq"` as shorthand for that target's default options.
The object form is new: current dynamic targets accept only a string.
Reject unknown options, incompatible options, unsupported target names, and
invalid paths during declaration validation. Do not silently fall back to
defaults. Specify one consistent JSON wire format and context encoding
across the Rust, dynamic, Go, and database paths.

Go's generator and policy API must represent these same options, emit the
same declaration, and obtain the EQL value from the guest. Go must not
assemble the EQL envelope or reproduce JSON indexing. Discovery must expose
the options contract and capabilities; extend the existing target catalog
and resolver rather than installing a parallel JSON registry.
The dynamic registry invokes the concrete target options deserializer; it
does not look up or invoke the Rust application's factory by name. A Go
caller supplies equivalent options data. If a Rust policy must be exported,
serialize its resolved options, not its function identifier. This contract
does not require all Rust-only targets to depend on Serde; data conversion
is required for targets registered with the dynamic interface.

Current gaps: JSON tree is absent from EQL's catalog/target table, the
dynamic JSON index is refused with `JsonIndexPending`, target fields carry
only a name, and Go's generated target declarations carry no target options.
Supporting an index's option syntax in Go does not establish executable
JSON-tree support. Include JSON input transport for objects, arrays, scalar
roots, and null; preserve the engine's numeric semantics and reject values
the cross-language contract cannot faithfully represent.

Writes and queries must reuse the normalized configured target in Rust and
Go. An ordering query on an undeclared path must fail before key I/O.
Containment, path equality, ordering, and extraction need capability metadata
that can express their different operand/result shapes, not a single
assumed scalar query twin. Decryption must use stored cryptographic metadata
and context, not require the caller to remember the write's ordered paths.

## Accepted decrypt surface and return ownership

**Decision, 2026-10-25:** retain ordinary keyset-directed decryption for one
opaque ciphertext and destination-directed `DecryptFrom` for declared
targets/layouts. Both paths have context-free and context-taking variants:

```rust
let value: i32 = keyset.decrypt(encrypted).await?;
let value: i32 = keyset.decrypt_with_context(encrypted, context).await?;

let plaintext = User::decrypt_from(encrypted, &keyset).await?;
let plaintext = User::decrypt_from_with_context(encrypted, &keyset, context)
    .await?;
```

These are independent call examples, not sequential reuse of a consumed
ciphertext. Direct decrypt mirrors direct encrypt; `DecryptFrom` mirrors
target-directed `EncryptInto`. The existing input capabilities still govern
whether omission of context is available. Do not add a competing public
ciphertext-receiver `decrypt_into` method.

Successful decryption returns an ordinary owned `T: Zeroize`. Stack guards
recovered bytes and intermediate plaintext while it owns them; successful
return transfers responsibility for the value to the caller. `Zeroize` does
not automatically wipe that returned value on drop. Support explicitly
requested drop-guarded results without requiring a wrapper around every
decrypted application struct; the precise opt-in adapter is implementation
design within this decision. Guarding the completed value does not resolve
partial-deserialization cleanup, which remains required work.

This reads as constructing `User` from ciphertext. Calling
`encrypted.decrypt_from(...)` would conflict with the ordinary From/Into
receiver convention; retain the agreed destination receiver.
The destination-directed pair already exists on the blanket `DecryptFrom`
extension trait. Today's ciphertext method is
`encrypted.decrypt_into(cipher, context)`, also on `DecryptFrom`, and has
no separate context-free overload. The current declaration trait
`DecryptInto<P>` is another layer; do not rename it accidentally while
settling method ergonomics. Consolidate declaration and convenience-trait
naming with review issue 5. The public examples use the destination-directed
pair; remove the competing ciphertext method when implementing this surface.

## Recommended public traits and context input capabilities

Status: direction accepted by the user on 2026-10-24: separate conversion
methods from `EncryptTarget`/`DecryptSource` declarations, and use explicit
caller-context capabilities instead of `Default`. Implementation, complete
signatures, and call-site updates remain pending. This section resolves the
direction of work areas A and B below; earlier examples retain historical
derive names until their migration.

Keep two user-facing conversion traits, implemented by blanket library
implementations:

| Trait | Public methods | Receiver |
| --- | --- | --- |
| `EncryptInto` | `encrypt_into`, `encrypt_into_with_context` | Plaintext value; output inferred or selected |
| `DecryptFrom` | `decrypt_from`, `decrypt_from_with_context` | Plaintext destination type; ciphertext supplied as an argument |

These methods run declarations through the common engine and return the
existing batched awaitable. Target implementers do not override execution.
Ordinary `keyset.encrypt` and `encrypt_with_context` remain inherent methods
and do not gain a plaintext-side `encrypt` synonym. Their accepted decrypt
counterparts are `keyset.decrypt` and `decrypt_with_context`.

Give the declaration traits role names, rather than From/Into names that
promise conversion methods they do not define:

| Proposed declaration | Implemented on | Describes |
| --- | --- | --- |
| `target::EncryptTarget<P>` | Encrypted output or term target | How to produce this target from `P` |
| `target::DecryptSource<P>` | Recoverable encrypted output | How this stored value yields `P` |

The corresponding derives should use the same names. This replaces today's
declaration traits `EncryptFrom<P>` and `DecryptInto<P>`; it does not remove
the retained `EncryptInto` extension trait. A term-only target implements
only `EncryptTarget`: no decrypt method that always fails. Plaintext visitor
traits remain a separate Stack-owned representation layer; moving/renaming
them must retain a single canonical trait implementation and a consistent
wire contract across the new consumers; prototype compatibility is not needed.
Configured-target options are another associated capability, not context.

Declaration methods continue returning core-owned operation descriptions.
Encryption declarations do not receive the plaintext and cipher together;
decrypt declarations inspect stored output and select its opening, without
performing key I/O. Plans, derives, and dynamic resolution reuse those
descriptions. Keep the declaration module public for custom targets and
keep normal method imports/derives available from the Stack entry point.

Use `ContextInput` as the associated-type name on each declaration trait.
It describes only what the caller must or may supply. It is not the complete
cryptographic context, which can also include a prefix and fields selected
from plaintext or stored output. Encrypt and decrypt declare this type
independently.

Recommend library-owned input wrappers with explicit capabilities:

| Proposed input | Omitted argument | Supplied argument | Meaning |
| --- | --- | --- | --- |
| `NoCallerContext` | Allowed | Not accepted | Declaration derives all context and exposes no caller input |
| `RequiredContext<C>` | Unavailable | Required `C` | Supplies context or the missing component selected by the declaration |
| `OptionalContext<C>` | Allowed | Accepted `C` | For ordinary ciphertext: omission means empty context; supplied context is used directly |
| `ContextExtension<C>` | Allowed | Accepted `C` | Omission preserves the declared base; supply extends it |
| `ExpectedContext<C>` | Allowed | Accepted `C` | Omission reconstructs stored context; supply additionally checks it |

`OptionalContext` does not append a synthetic empty prefix, and omission
of an extension does not append `()`. `ExpectedContext` never extends AAD.
The table specifies behavior; names may be refined without changing it.
Nonempty requirements belong to the accepted argument type or validated
resolved context, not to whether an input is optional. Search targets still
require a nonempty effective context. Ordinary scalar ciphertext should
accept the same empty context through both keyset and target-directed APIs.

No-context methods require an explicit, sealed `AllowsNoContext` capability;
`_with_context` methods require a corresponding `AcceptsContext` capability
with its accepted argument type. Neither is inferred from `C: Default`.
`RequiredContext<u64>` consequently remains required even though `u64`
defaults to zero. The helpers accept ordinary argument values (or ergonomic
checked conversions); users do not manually wrap `RequiredContext` or
`ExpectedContext` at every call. Conversion errors propagate before key I/O.

The core-owned wrappers carry presence and intent; target declarations
perform source selection and context composition. For composite required
input, `C` may be a tuple or named struct; it does not have to be the full
logical context. Preserve existing grouping rules and context encodings.

Examples of independent encrypt/decrypt requirements:

| Declaration | Encrypt input | Decrypt input |
| --- | --- | --- |
| Caller row ID stored in output | `RequiredContext<u64>` | `ExpectedContext<u64>` |
| Source row ID also stored in output | `NoCallerContext` | `ExpectedContext<u64>` |
| Source row ID not recoverable before decrypt | `NoCallerContext` | `RequiredContext<u64>` |
| Static field base with optional unstored extension | `ContextExtension<C>` | `ContextExtension<C>` |

In the last row, decrypting an extended ciphertext requires supplying the
same extension; availability of the omitted method is not a promise that
it opens every ciphertext of that Rust type. A derive can expose an optional
extension instead of `NoCallerContext` where its declaration explicitly
allows that behavior. Expected-context checks do not authenticate stored
data themselves: successful cryptographic opening remains necessary.

The dynamic plan must encode the same requirements, source selectors, and
storage rules. Rust enforces omitted/supplied method availability with trait
bounds; the engine enforces dynamic input presence and validity before key
I/O. Omitted input, explicit zero, and an empty supplied value are distinct.
Go generation can expose convenient signatures using that metadata, but
the guest remains authoritative for runtime requests.

Implementation proof points: compile-fail required-input calls even for
`C: Default`, reject context for a no-input-only target, preserve optional
extension versus expectation semantics, and execute all nine directional
scenarios through Rust and dynamic plans. Preserve owned-source support
and batching; this trait separation must not add a blanket `Clone` bound.
The final signatures must show where borrowed and owned sources are
supported rather than concealing the existing difference behind the rename.

## Parallel Go JSON work: PR #1353

Read on 2026-10-24: [PR #1353](https://github.com/cipherstash/stack/pull/1353)
is an open documentation-only plan, not an implementation. Its write-up is
[The json_tree capability in the Go SDK](https://github.com/cipherstash/stack/blob/docs/go-json-tree-plan/docs/plans/2026-10-24-go-json-tree.md).
It tracks [#1347](https://github.com/cipherstash/stack/issues/1347), with
catalog, dynamic execution, queries, Go SDK, and extraction work in
[#1348](https://github.com/cipherstash/stack/issues/1348),
[#1349](https://github.com/cipherstash/stack/issues/1349),
[#1350](https://github.com/cipherstash/stack/issues/1350),
[#1351](https://github.com/cipherstash/stack/issues/1351), and
[#1352](https://github.com/cipherstash/stack/issues/1352).

Treat that work as an implementation dependency to reconcile, not a parallel
SDK design to recreate. Its engine-owned execution, catalog/generated Go
types, engine-validated options, and cross-language tests fit this plan.
Review the following differences before freezing interfaces:

- Route its JSON-specific option plumbing through the general target's
  typed options/deserialization boundary. Go tags may retain idiomatic
  syntax, but lower to target options rather than a second JSON policy path.
- Adapt the proposed `Layout` integration to the configured-target contract;
  no second executor or permanently competing public configuration model.
- Reconcile type/registry names and generated query accessors with the shared
  glossary and configured query capabilities. Its `At.*` accessor proposal
  is useful input, not an accepted Rust or Go naming decision here.
- Carry the agreed context requirements and paired method semantics into
  the relevant language interfaces without requiring identical language
  syntax. Distinguish JSON `null` as content from nullable SQL fields.
- Evaluate its JSON-text ABI recommendation for numeric fidelity and return
  types. This is compatible with direct typed EQL output adaptation: input
  transport text and an avoidable encrypted-output Serde round trip are
  different boundaries.
- Release scope is now decided: extraction, opening entries and walks ship
  in the comprehensive first version alongside writes/queries. The earlier
  Go plan's step-5 deferral is superseded by the linked JSON operation
  inventory; sequential internal PRs must not become a reduced release.
- Byte-for-byte parity tests need deterministic randomness as that plan
  proposes; normal randomized encryption needs cross-opening/query tests.

These are dependencies and recommendations recorded locally. No changes or
comments have been posted to the parallel PR or its issues.

## Prior query design: baseline and reconciliation

**Decision update, 2026-10-25:** ORE does not answer equality in the initial
API, for any plaintext type. Equality uses its declared equality-capable
index. Keep capability selection parameterized by the index, plaintext
encoding/domain and options, so a future explicit exact/injective integer
encoding can opt into equality without changing query syntax or wire
operator identity. Never infer `Eq` merely from ordering support: text and
other lossy encodings cannot establish plaintext equality. A future opt-in
must retain overlap rejection (one selected provider per operator) and
must not silently invalidate existing `(Equality, Ore)` definitions. This
policy does not disable JSON scalar equality, which uses value selectors
rather than ORE/OPE terms.

Read in full on 2026-10-25: the user-supplied **Stack Encrypt query design**,
dated 2026-10-21, at
`/Users/dan/Downloads/Stack Encrypt query design.md` (654 lines). The source
document was not modified. It is explicitly a discussion draft, based on
an earlier `next` snapshot; its historical code/release claims were not
revalidated as part of this reading. Use it as the query-design baseline,
not as a settled specification or a reason to redesign queries from scratch.

### Existing proposal to carry forward

- The caller selects an operator and a typed field/target handle. The field
  supplies its own configured index; remove `DefaultIndex` and caller `.via`.
- Each field has at most one index answering each operator. Refuse overlaps
  at declaration validation instead of choosing an index by priority.
- Declare operators, index capabilities, and admitted source types once;
  derive or verify typed lookup, dynamic lookup, and discovery from that
  declaration. Avoid another capability table in EQL.
- Share query derivation and refusals through the same semantic functions.
  In particular, tokenize match input once and retain the tokens needed for
  probabilistic verification in the query object.
- Retain index/source types in typed field handles. Unsupported operators
  are compile errors on the typed path and validated errors dynamically.
- Model analyzer case behavior once in its stages, rather than restating
  it in both the match configuration and the operator.

The draft already proposes the query call
`cipher.query(op::Matches, text).on(&field).await?`, typed
`FieldRef` handles, and a loaded configuration/analyzer owned by the dynamic
plan (`Loaded` / `Arc<DynAnalyzer>`). Those are substantive designs to reuse;
they do not yet settle how our output-derived typed factory options are
initialized and shared with convenient `encrypt_into` calls.

### Reconciliation with this review

1. **Generate handles from the same output-target declaration.** The query
   appendix proposes a plaintext-side `EncryptionPlan` derive and generated
   encrypted counterparts. Our agreed starting point is output-side
   `EncryptTarget`/`DecryptSource` derives. Recommend emitting typed handles
   from that declaration, without separately restating indexes on plaintext.
   A source-side convenience derive can later generate the same target.
   Hand-written plans remain lower-level composition, not mandatory usage.
2. **Resolve typed factory ownership.** A generic `Match<O>` can fix a policy
   identity in its type, but an arbitrary factory can still compute different
   values on different calls. Carry a resolved configuration instance through
   writes and field handles; settle the owner/initialization API. The draft's
   dynamic plan ownership is useful precedent, not proof that all static
   factory results are compile-time constants.
3. **Separate portable options from execution types.** JSON's Rust factory
   and dynamic deserializer can construct the same `JsonOptions`. The draft's
   `Match<O>` and `Match<Dynamic>` intentionally have different execution
   types to accommodate generic/custom analyzer stages. Preserve shared
   validated options and semantic implementations for the portable subset;
   do not force all typed analyzers through a serializable stage enum.
4. **Accepted portability scope.** Ship built-in advertised
   capabilities in Rust and Go together. Downstream custom Rust stages can
   remain explicitly typed-only with `NotPortable` until registered. This
   qualifies the draft's blanket "lands in Rust first" rule; it must not
   become permission to defer the Go JSON capability under this plan.
5. **Include JSON capabilities before fixing lookup representations.** The
   draft's 16-shape dynamic enum covers equality, match, and scalar ordering,
   not the new JSON target. Extend operator identity, operand/result shapes,
   capability validation, and overlap rules for containment, `AtPath`, and
   extraction. Its interim validated index list using one capability table
   is a viable starting point; the specific closed enum is not a decision.
6. **Use the agreed context/scope model.** Replace label-only assumptions
   with separate ciphertext binding and search scope. Row binding does not
   flow into search terms; `PrimaryKey` is context-eligible and `ScopeKey`
   is also scope-eligible. Apply the same declared scope to index generation
   and queries. Preserve the requirement to return or supply row context
   when decrypting selected results.
7. **Accepted validation timing.** All checks independent of keys precede
   key resolution/loading, including query-input checks. The draft's possible
   named-keyset resolution before those checks is superseded. Reuse the
   same validator for Go's `check_query` and execution rather than copying
   it or tokenization. Provider facts and cryptographic checks that require
   keys remain later stages. Explicit earlier client initialization/keyset
   calls are not retroactively prevented by this operation-validation rule.
8. **Apply the user's prototype scope.** Legacy match-option decoding,
   deprecation/release-preservation requirements, and frozen Go wire formats
   in the older document are not constraints here. Keep new Rust/Go/EQL
   consumers aligned. The appendix's `cipher.encrypt(plan, value)` and
   plaintext derive are illustrative older proposals, not replacements for
   our agreed entry points.

ORE/Eq is now decided as described above. Retain integration work on
typed field-handle construction/spelling, dynamic
`Index<ValueFrame>` versus a shared semantic-function boundary, feasibility
of compile-time match-option checks, Go's `check_query`, and ADR updates.
Type-safe stage ordering does not by itself validate runtime numeric values
or string paths; stronger const-check claims require implementation proof.
Use these as specific integration decisions rather than an unbounded query
API task. Coordinate their Go surface with PR #1353.

## Recommended owner: a reusable typed target definition

Status: recommendation for review. Use an immutable **target definition**
to own resolved options, prepared indexes/analyzers, context-selection rules,
and operation metadata. The output derive generates this definition's typed
field accessors from the same declaration that generates encryption. It
contains no plaintext, row values, credentials, or selected keyset. A field
handle borrows or shares that definition and retains its plaintext/index
types; it is not an independent name plus a newly constructed default index.

**Selector naming, 2026-10-25:** the user finds encryption's `using` and
query's `on` confusing and requests considering one name. Recommend
`.using(...)` for both: each selects the definition or field whose declared
policy governs the operation. This spelling is proposed, not yet accepted.
Encryption still accepts the requested target's associated definition type;
query still requires `QueryTarget<Op, Input>` on a selected field or
single-value definition. Shared naming does not weaken either bound or
make an entire multi-field record a query target. Older `on` examples in
the supplied query draft describe its earlier spelling.

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

`definition()` obtains the shared resolved definition of that source/target
mapping. Plain `encrypt_into` obtains the same definition internally. It
does not independently invoke the options factory. `.email()` is generated
from the output field declaration, not a hand-maintained second schema.
The method name `definition` is proposed; it names a resolved declaration,
not a builder that users must reconstruct before every operation.

### Call order and strict typestate

User requirement, 2026-10-25: use strict typestate for the fluent API. The
user prefers the reading `cipher.using(&field).query(op, input)` and is open
to supporting both call orders. Recommend definition-first as the canonical
documented query form, while supporting operator-first through the same
request states:

```rust
let a = cipher.using(&users.email()).query(op::Eq, email).await?;
let b = cipher.query(op::Eq, email).using(&users.email()).await?;
```

Both are proposed. The current implementation is query-first, followed by
`.on(...)`; this recommendation changes that interface.

| Starting state | Method | Resulting state |
| --- | --- | --- |
| Cipher | `using(&definition)` | Bound definition, no query selected |
| Bound definition | `query(op, input)` | Query with definition/operator/input known |
| Cipher | `query(op, input)` | Query awaiting a definition |
| Query awaiting a definition | `using(&definition)` | The same query state as the definition-first path |

The transition that brings the definition and operator/input together has
the `QueryTarget<Op, Input>` bound. A definition-first bound handle need not
pretend to know the future operator. Once combined, the index and context
requirements are determined. Only the executable state implements
`IntoFuture`; a bound definition alone, a query missing its definition, or
a query missing required context cannot be awaited. Required context is
completed by a typed context-input transition; optional/no-input cases
start with a valid omitted state. Context completion must not be represented
solely as an unchecked `Option` plus a runtime missing-input error on the
static path.

Do not expose another `using` transition after a query's definition has
been selected, or another query-selection transition on the request.
Supporting these two orders does not promise every permutation of keyset,
context, and operation selection. Specify those transitions separately,
starting with context supplied after its required type is known. Share
the final query request, validation, and execution implementation rather
than duplicate them per call order. Input-dependent errors such as an
invalid path still need runtime validation; typestate checks completeness
and capability, not arbitrary value semantics.

The same discipline applies to encryption requests: a fixed-policy
`encrypt_into` has an implicit definition and can be awaited without
`using`; selecting an explicit compatible definition is a one-time
transition before execution. This does not add a new ordinary `encrypt`
receiver or require fixed-policy callers to bind definitions manually.

Completion tests must include both query orders with identical semantics,
and compile-fail cases for unsupported operators/inputs, premature await,
missing required context, and repeated definition selection. Definition
borrows/shared handles must remain valid for the lifetime of the request.

### Fixed declarations

Use lazy, fallible initialization for the fixed definition, retaining each
successful result for reuse. Allow explicit startup initialization via
`EncryptedUser::definition()?`, while the shorthand write initializes it
on demand and returns any error through its awaitable. Factory errors must
not panic or perform key I/O; do not permanently cache initialization
failures. Coordinate concurrent first use so successful initialization is
performed once, and account for reentrant/recursive initialization in the
implementation rather than allowing a deadlock.

The identity is the complete concrete declaration (including source/target
mapping and generic policy parameters), not merely the ciphertext's output
type. Different instantiations must not share a cache slot by accident.
This is an implementation requirement, not a claim that a static inside a
generic Rust function is automatically per-monomorphization.

Fixed factories must describe stable application policy; they are not the
interface for reloading environment settings or tenant-specific options.
The cache makes writes and queries in one process share the resolved policy;
it does not prove another process or an older stored row uses that policy.
Per-call context, source values, and keyset choice remain separate inputs.

### Runtime declarations

Load/create a distinct definition instance for runtime options. A configured
instance is not stored in the fixed-declaration cache. Use the same type of
definition and field handles, so queries and writes share that instance.

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
building the operation or invoking a default factory. Its await lowers to
the existing `Pending`/batch executor; the shared engine remains unchanged.
The definition's output/source types constrain the conversion. Queries use
the same definition (or its field handles), supplying the required context
and keyset for that call.

A fixed-policy wrapper such as `EncryptedPayroll` does not expose runtime
override of its declared options. Use the configurable underlying target
for the runtime case, avoiding silent overrides of a fixed policy. Exact
configuration APIs for multi-field runtime definitions are still to be
specified; they must select typed options without introducing another
execution mechanism.

Go's loaded dynamic plan owns its resolved definitions and generated field
accessors reach those definitions. It has no Rust factory to invoke. The
guest validates and builds the configuration once per loaded declaration,
then writes/queries use the loaded instance. A different runtime policy is
a different instance; it does not mutate one used by in-flight operations.

### Implementation proof and boundary

Prove the cache/handle design early with two fixed mappings, multiple generic
instantiations, concurrent first use, initialization failure/retry, and
separate runtime instances. Prove a query and its write use the same options
without calling the factory twice. Preserve source lifetimes, owned-source
support, batch lowering, and no-HTTP/WASM builds. Queries on a field without
the operator must remain compile errors, with dynamic equivalents checked
at declaration/query validation.

Prefer this generated-definition approach over requiring callers to author
a second plan or putting configuration state in each ciphertext. Plans are
still the lower-level implementation of the definition. Portable option
serialization and index capability discovery remain part of its dynamic
contract; the definition object does not itself need to serialize arbitrary
Rust closures or custom analyzer code.

## Single-ciphertext representation and plaintext ownership

Accepted decisions, 2026-10-25: use `OpaqueEncode` / `OpaqueDecode` for
single-ciphertext representation, replacing the working names `EncodeValue`
/ `DecodeValue`. Both direct `encrypt` and target-directed `encrypt_into`
consume their values and take responsibility for owned plaintext cleanup,
including their context-taking variants. These are representation
capabilities; the engine still performs cryptography. `EncryptTarget` /
`DecryptSource` describe how encrypted outputs and layouts compose those
operations. The lifecycle and cleanup scope below are part of the accepted
design. The plaintext cleanup bound is `Zeroize`; implementation remains
to be completed.

### Owned input is the direct API contract

`keyset.encrypt(value)` and its context-taking counterpart take an owned
single-value input. No implicit clone and no `Clone` bound. For example,
passing a `String` transfers it; a borrowed `&str` does not transfer the
storage it refers to and must not receive the same cleanup promise. Do not
add a silent borrowed-input fallback to the consuming operation.

**Decision, 2026-10-25:** require `Zeroize` for plaintext types and use a
library-owned guard. Use the existing ecosystem trait rather than defining
a new cleanup trait or alternative protected-ownership adapter for now.
`Zeroize` supplies the operation; the library must arrange to invoke it on
every supported exit path. A bound alone does not arrange cleanup on drop.

Acquire protected ownership synchronously when creating the encryption
request, before returning its future/builder. An `async fn` body is not run
until polling, so placing the first guard inside that body would leave an
unpolled request with an ordinarily dropped source. A sync constructor
returning the typed future can establish the guard first. Every subsequent
builder transition moves that guarded ownership rather than making a new
unprotected copy.

The representation trait may encode through a temporary internal borrow of
the guarded value into a library-owned sensitive sink. Public consumption
does not require giving an encoder unrestricted ownership of the source or
an ordinary growable `Vec<u8>` for scratch work. Wipe and release the source
as soon as encoding no longer needs it; keep encoded plaintext guarded until
sealing completes. Preserve the single-leaf representation boundary.

### Cleanup scope and implementation obligations

- Cover owned source storage, encoded buffers, codec scratch, and any
  library-created plaintext copies. Use established non-elidable wiping
  primitives/protected storage rather than `clear()` or ordinary drop alone.
- Cover success, encoding/configuration/KMS/AEAD errors, partially prepared
  batches, request cancellation, and an unpolled request being dropped.
  Use drop guards for ordinary unwinding too; process abort or a leaked
  future is not a destructor guarantee.
- Avoid reallocations that abandon uncleared buffers; growing sensitive
  sinks must have a cleanup strategy for old allocations. Prevent plaintext
  from escaping in diagnostics, Debug, caches, and instrumentation.
- On decrypt, protect recovered bytes and partial decode state until cleanup
  or successful ownership transfer to the caller. Successful returned
  plaintext is intentionally retained; its subsequent lifetime is the
  caller's responsibility unless the return type itself is protected.
- A Rust move does not prove all physical copies were erased. In particular,
  `Copy` inputs leave caller-owned originals usable, and compiler temporaries
  may exist. The enforceable API promise concerns supported owned storage
  and library-managed artifacts, not caller-retained copies or erasure of
  every register/stack remnant. Verify stronger claims with compiler evidence.

The [zeroize documentation](https://docs.rs/zeroize/latest/zeroize/)
documents drop-based guards, non-elidable wiping, and limits involving
moves, stack copies, and reallocations. The source currently uses
`Protected<Vec<u8>>` at the AEAD boundary, but that does not establish
end-to-end cleanup of every caller value and intermediate. This discussion
is a design requirement, not a completed source/assembly zeroization audit.

### Consequences for blobs, layouts, and Go

`OpaqueBlob<T>` cannot promise source cleanup from `T: Serialize` alone.
Require `T: Serialize + Zeroize` for the proposed Serde-backed blob input;
owned blob decoding requires `T: DeserializeOwned + Zeroize`. Ordinary
application structs may derive `Zeroize`. A
generic Serde implementation can allocate or retain hidden copies, so strong
claims also require a supported codec/implementation contract; wrapping its
final byte buffer does not make arbitrary user serialization code compliant.

In particular, `T: Zeroize` only supplies cleanup once a `T` exists. If
derived `Deserialize` allocates a `String` field and fails on a later field,
the partially built fields ordinarily drop without invoking `T::zeroize`.
Even adding `ZeroizeOnDrop` to the enclosing struct cannot fix a struct
that was never constructed. Keep this as a concrete decoder design and
acceptance requirement; do not claim the new bound solves partial decoding.

### Blob codec assessment: Vitamin C frames

**Priority decision, 2026-10-25:** first define a stable, versioned binary
storage profile. The codec was originally ephemeral transport; stored blobs
need a stronger compatibility commitment. Zeroization and constant-time
implementation improvements can follow, provided they preserve stored
format semantics. Do not defer decisions that affect stored bytes (option
presence, type mapping, versions) or claim timing/cleanup properties not
implemented. The `Zeroize` input bound and ownership direction remain.
Track this action in
[Vitamin C #519](https://github.com/cipherstash/vitaminc/issues/519), created
for this review. It explicitly distinguishes storage stability from the
transport-only rationale in Vitamin C #332.

**Recommendation, 2026-10-25:** reuse Vitamin C's frame writer/parser as the
foundation for the library-owned blob codec, with a specified blob Serde
mapping. Do not adopt the existing transport Serde mapping unchanged.
The inspected dependency is `vitaminc-aead-frame` 0.8.0; its `serde` module
already provides `to_vec(&T)` and `from_slice::<T>(&[u8])`. Stack currently
uses that module for dynamic control data. Its module documentation
explicitly scopes it to transport data rather than plaintext to seal.

The implementation already guards the serializer output, temporary variant
buffers, and buffered map keys with `Zeroizing`. The underlying
`vitaminc-aead` frame writer grows into a fresh allocation and wipes the old
one. However, `to_vec` returns an ordinary `Vec<u8>` on success. Provide an
internal guarded-output entry point or sensitive sink for the blob path,
keeping the result guarded through sealing. Inspect remaining temporary
storage and custom Serde paths before asserting a complete cleanup contract.

The current mapping is not lossless for every ordinary Serde type:
`serialize_some` delegates directly to its value, while `None` and unit both
encode as null. Thus `Some(())` reads back as `None`; nested optional values
have the same ambiguity. The blob mapping must preserve option presence
explicitly, using an unambiguous representation, and test these cases.
The current map representation also requires text keys. Specify support or
explicit rejection for non-string map keys, and document enum/buffered Serde
limitations rather than advertising all `Serialize` types as round-trippable.

Frame parsing validates one complete frame before invoking `Deserialize`,
but that neither prevents type-level decode failures nor cleans up partial
application values. Resolve that cleanup boundary alongside format limits,
authenticated codec versioning, and cross-language fixtures. Reusing the
frame format is not a constant-time guarantee and does not make an opaque
blob a structurally encrypted JSON document.

[Borsh](https://docs.rs/borsh/latest/borsh/) remains a fallback if the blob
mapping would require disproportionate changes. It introduces
`BorshSerialize` / `BorshDeserialize` instead of the Serde traits, and has
writer-based serialization. Changing serialization libraries does not by
itself establish wiping or a constant-time contract. Prefer evaluating the
existing frame machinery against these requirements first.

The same consuming contract applies to target-directed `encrypt_into`.
For a structural target, declared passthrough fields intentionally
move into the output; wipe encrypted source fields and temporary copies,
not plaintext fields the caller explicitly chose to retain. Fan-out to
ciphertext and index operations should read a guarded source where possible
instead of requiring a plaintext clone per operation.

Specify cleanup for dynamic host/guest transport and JSON parsing buffers
as part of the Go implementation. The Rust guest cannot erase Go caller
objects it never owned; host-managed copies need host cleanup and ordinary
Go values do not acquire Rust move semantics. Document that boundary rather
than claiming guest cleanup erases every copy in the calling process.

Acceptance work: source-cleanup/drop observation on successful and failing
requests, cancellation/unpolled-request tests, nested source/blob cases,
and owned non-Clone inputs. Inspect optimized code for wipe/copy behavior
where necessary; ordinary tests alone cannot prove absence of every residual
copy. Do not infer a current vulnerability or a completed guarantee from
this design discussion.

## Configured-target implementation sequence and completion criteria

1. **Normalize the general contract.** Specify typed options, Rust factory
   signatures, validated dynamic deserialization, defaults, context
   inputs, capability discovery, errors, and the target
   object grammar. Create the versioned interoperability specification,
   schemas and initial conformance fixtures described below alongside this
   work. Build one target-owned validator and lowering path.
2. **Deliver JSON as a complete first implementation.** Add configured EQL
   JSON targets, direct typed output/input conversion, catalog/guest
   registration, and JSON transport. Keep engine and database encodings aligned.
3. **Expose both declarative front ends.** Add the generic Rust derive
   factory hook and Go generator/policy support, including field targets and
   standalone Rust wrappers. Neither front end reimplements encryption.
4. **Complete queries and reads in both languages.** Carry the configured
   target into query construction, expose extraction results, and standardize
   Rust's paired decrypt convenience methods. Settle the role-based JSON
   names as part of this public API work.
5. **Verify the complete slice before calling it supported.** Rust-written
   EQL JSON must open and query from Go, and vice versa, against PostgreSQL.
   Test defaults, ordered paths, both root settings, arrays/scalar roots/null,
   numeric boundaries, missing paths, context mismatch, and invalid options.
   Assert logical batching and verify fixtures for the chosen format. Compare
   semantics rather than ciphertext equality, since encryption is randomized.
   Run the shared interoperability conformance suite and gate schema/runtime
   drift in CI. Each implemented contract change updates its specification
   and fixtures in the same change.

These are implementation steps, not permission to ship a Rust-only phase.
The Go examples and cross-language acceptance tests are part of the feature.
Do not add the plaintext-configuration wrapper in this first change: the
dynamic target declaration already handles runtime options without adding
another policy location. Reconsider that convenience after both front ends
use the shared contract.

### Required deliverable: dynamic interoperability specification

**User requirement:** develop a formal specification of the dynamic
interoperability layer during implementation, not as documentation added
after the Rust and Go APIs have diverged. The current examples remain
proposals until reconciled into that specification; adding this deliverable
does not claim the specification has already been written.

**Recommended format:** a versioned specification package containing
[JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) schemas,
normative semantic and wire-format rules, and executable conformance
fixtures. JSON Schema describes declaration/request/response structure;
it is not the entire behavioral or binary transport specification. Keep
application semantic-type declarations distinct from JSON Schema's own
`type`, `$defs`, and `$ref` vocabulary.

Required coverage:

- Definition grammar: built-in and named types, optional `types` section,
  inline role wrappers, context selectors, scope eligibility, passthrough
  and context storage, targets/options, query capabilities, defaults, and
  unknown-field/extension handling. Named ordinary types need no role;
  naming a type does not grant scope eligibility.
- Semantic validation: resolve named types and field references, reject
  invalid/cyclic references where unsupported, enforce primary-key versus
  scope-key capabilities recursively, check source/output compatibility,
  and derive write/query scope agreement. Do not imply generic JSON Schema
  validators perform the engine's reference resolution or capability checks.
- Operation contracts: input presence and context/scope roles, target and
  definition identity, results, stable error codes and locations without
  plaintext values, validation stages, and which failures precede key I/O.
- Wire mapping: JSON and frame representations, integer widths/ranges and
  lossless numeric transport, bytes/text encodings, missing versus null,
  context ordering/grouping, descriptor/AAD/index-scope lowering, and
  normative references to the ciphertext/SQL envelope and tag extraction.
  Specify the host/guest ABI or reference its versioned specification;
  JSON authoring syntax must not silently redefine the binary transport.
- Versioning: explicit protocol/schema identifiers, supported-version and
  capability handling, and rejection of unsupported features. Define future
  evolution without adding compatibility obligations for the prototype.

Conformance fixtures include accepted and rejected definitions/requests,
expected error codes/paths, normalized definitions, and deterministic
context/encoding vectors. Exercise the same fixtures through Rust and the
Go guest path, plus SQL extraction where relevant. Randomized ciphertext
comparisons use cross-decryption and query behavior, not byte equality.
Schema validation is one layer of the suite; semantic rejection tests are
required even for structurally valid JSON.

Keep a single maintained contract: prefer generating structural schemas and
capability metadata from the shared declaration models/catalog where that
faithfully represents the specified grammar, with committed artifacts and
CI drift checks. Review generated schemas against normative rules rather
than treating Serde derives as a complete specification. Do not introduce
OpenAPI or a new transport solely to document this non-HTTP interface.

## Coverage of the complete review

The configured-target work above addresses issue 13 in depth. The full API
redesign also requires the following work. Each row identifies a concrete
deliverable; recommendations do not silently settle the open decisions.

| Work area | Review issues | Required deliverable |
| --- | --- | --- |
| Public methods, traits, and ownership | 1, 3, 5, 9, 10, 14 | One signature/import/receiver map, operation-trait design, and dependency migration |
| Context contract | 1, 3, 4, 11, 12, 14 | Scalar and record context rules, explicit optionality, and matching dynamic representation |
| Ciphertext persistence | 2, 8 | Opaque scalar output, canonical bytes, Serde/Base64 behavior, and a defined boundary with structural trees |
| Whole-value wrapper | 8 | Codec, authenticated format version, decode contract, and bounded timing claims |
| Mixed records and collections | 7, 8, 11 | Passthrough/renaming/context-field derive support and retained collection batching |
| Configured targets and queries | 13 | Typed Rust factories, dynamic options, configuration lifetime, JSON conversion and Go coverage |
| Names, integration, and release | 5, 6, 9, 10, 13, 14 | Final glossary, coordinated consumer updates, format fixtures, and executable public examples |
| Parallel Go JSON work | 15 | Reconcile PR #1353 and tasks #1348–#1352 with this contract; reuse compatible implementation work |
| Prior query design | 16 | Reuse the supplied field-owned query model; reconcile handles, configuration ownership, JSON capabilities, and portability |
| Consistent definition selector | 17 | Choose one method name for encrypt and query; recommend `using` with operation-specific bounds |
| Single-ciphertext encoding and cleanup | 18 | `OpaqueEncode`/`OpaqueDecode`, consuming encrypt and encrypt_into, guarded source/buffer lifetimes, and explicit cleanup scope |

### A. Settle the public method and trait structure first

Keep the agreed ordinary keyset receiver and `EncryptInto` conversion forms.
Use the accepted destination-directed decrypt pair. Write
out all signatures, imports, bounds, and return types before renaming traits.
Retain ordinary keyset `decrypt` / `decrypt_with_context` for opaque
ciphertexts, and remove redundant prototype conveniences without
compatibility shims.

Separate plaintext representation, target operation declarations, and
execution conveniences explicitly. Resolve why `EncryptFrom` declares
`encryption()` while `encrypt_from` lives on `EncryptInto`, and why
`DecryptFrom` supplies methods while `DecryptInto` describes opening. A
rename without an ownership/signature map leaves the discovery problem.

Recommendation: Stack owns the public value-encryption model; Vitamin C
retains general primitives. Specify the dependency boundary before moving
code, retaining one canonical trait identity and the no-HTTP/WASM builds.
Reassess the original Vitamin C cipher-trait mismatch in that architecture:
do not add a public trait implementation merely for symmetry if it cannot
carry structured KMS context or support its advertised operations.

Completion: representative scalar, blob, typed record, searchable record,
and JSON calls compile with the documented imports, including generic
callers. The method inventory has no unexplained duplicate execution path.
Compile-fail tests cover genuinely unsupported trait capabilities.

### B. Turn the context scenarios into a normative contract

The nine scenarios in the context document are the acceptance matrix, not
optional examples. Cover scalar static context plus caller extension,
source-field selection, caller input, output storage, and decrypt recovery
or expected-context checks. Preserve the accepted `field = "id"` shorthand
as selection on both inputs, without implicit copying.

Fix composition order and grouping once: literal/field base, composite row
context, and any caller extension. Specify the exact descriptor and AAD
encoding for each case. An expected context checks stored context; it is
not another extension. Never need to open ciphertext to discover the
context required to open that ciphertext.

Recommendation: represent no input, required input, optional extension,
and optional expectation as explicit capabilities. Do not infer optionality
from the application's `Default` implementation. Settle the wrapper or
trait mechanism alongside the public signatures. Resolve the existing
empty-context mismatch between ordinary scalar encryption and ciphertext
targets without weakening nonempty-context requirements for search targets.

Give each source/storage/composition rule a dynamic representation and Go
authoring path. Current EQL identifier constraints must be reconciled with
row/caller context explicitly, not bypassed or silently dropped.

**Next discussion — recommendation, not yet a decision:** distinguish
ciphertext binding from search scope. A row ID may bind a ciphertext to its
record without making every index term row-specific. The target definition
should explicitly describe both scopes; query construction uses the same
declared search scope as index generation. For example, a searchable email
may bind its ciphertext to `(users.email, tenant_id, user_id)` while its
equality index is scoped to `(users.email, tenant_id)`, allowing a query
before the user ID is known. Do not silently remove components from one
generic context argument. Index-key derivation/KMS descriptors must respect
this separation too; changing only leaf AAD is not a complete design.
Finalize the conceptual split before choosing attribute names or exact
tuple encodings, and represent it in the dynamic definition as well.

**User direction:** allow row-bound ciphertext and document that reads must
provide the row ID to decrypt. Search scope should cover multiple rows,
such as a tenant; automatically including a row ID defeats ordinary search.

**Misuse-resistant API recommendation (not yet accepted):**

- Give existing record `context(field = "id")` and its directional variants
  ciphertext-binding semantics. Do not implicitly feed those selected fields
  or caller extensions into index keys or terms. This is a proposed
  clarification for searchable targets; older examples did not distinguish
  the roles, and must be updated together before implementation.
- Declare search scope separately on the shared target definition. A named
  application scope input (for example `TenantScope`) can come from operation
  configuration/caller input. The capability proposal below also permits
  record-field selectors when their types explicitly qualify as scopes.
  The same typed scope is required for both
  writing index terms and constructing queries. A tenant-bound cipher may
  supply it only through an explicit declared mapping; never guess it from
  unrelated metadata.
- A binding input and a search-scope input are distinct capabilities even
  when their underlying values have the same Rust type. Do not provide
  blanket implicit conversion between the roles. If one operation needs both
  caller inputs, use named members in its typed input rather than one
  unlabelled value routed to both operations.
- Missing required scope prevents awaiting a Rust request; dynamic/Go
  validation rejects it before key I/O. A default column-wide scope is not
  substituted when a tenant scope is missing. Scope-free searches use an
  explicitly declared column-wide policy, with column identity still bound.
- The effective ciphertext binding should include the declared search scope
  as well as record binding, so changing a supplied tenant also prevents
  opening the ciphertext. Index derivation sees column identity plus search
  scope only. Query requests never require record binding input.
- Encrypted output must expose whatever the decrypt selector needs or
  require it from the caller. Record-projection examples must select the ID;
  there is no decrypt fallback which drops row binding. Selecting a field
  as context does not implicitly store that field.

Working declaration spelling:
`#[stash(context(field = "id"), search_scope(caller = TenantScope))]`.
The spelling is illustrative; it preserves the agreed directional-context
shorthand and gives search an explicitly separate role. Dynamic definitions
must preserve this separation rather than providing a shared context bag.

This prevents accidental propagation of row IDs into search terms; it
cannot prove the application chose a scope containing multiple rows. A user
can deliberately put a row ID inside `TenantScope`. Do not claim otherwise,
or attempt to infer semantics from field names such as `id`. Use explicit
types/declarations and documentation for that remaining application choice.

#### Scope capability and role wrappers — assessment

**Proposal under discussion:** use both ideas together. Scope is the subset
of context permitted for search terms; semantic wrappers provide positive
trait implementations identifying that subset. Working capability names:
`CiphertextContext` and `SearchScope: CiphertextContext`. These names describe
eligibility, not source selection, optionality, or encoding. Integrate with
the existing context representation rather than introducing a competing
serializer. The previously agreed `ContextInput` capabilities still describe
whether the caller must supply a value.

For example, `PrimaryKey<T>` implements ciphertext-context eligibility but
not search-scope eligibility. `ScopeKey<T>` implements both, subject to
the inner value's supported context encoding. Generic parameters are Rust
types (`PrimaryKey<u64>`); `PrimaryKey(42)` is a value constructor. Prefer
`ScopeKey<T>` as the name for the second wrapper; the user accepted this
name in preference to `Collection<T>`, which can read as a container.
These wrappers need the appropriate `Zeroize` support when they are owned
plaintext fields, consistent with the existing ownership decision.

Crucially, neither wrapper automatically adds the field to context or scope,
stores it in encrypted output, or changes the plaintext's encryption layout.
The target declaration still selects sources. An illustrative declaration
is `context(field = "id"), search_scope(field = "tenant_id")`. With
`id: PrimaryKey<u64>` and `tenant_id: ScopeKey<u64>`, the selection is
valid; selecting `id` as search scope is a compile-time error. This makes
typed field selection a reasonable alternative to the earlier recommendation
to accept only caller-supplied search scope.

Misuse-resistance requirements:

- No blanket `SearchScope` implementation for every context, serializable
  type, raw number, or raw string. Scope use is an explicit classification.
- Composite scopes qualify only when every component is a scope. A tuple
  containing a primary key cannot become a scope merely by tuple composition.
  Context composites may contain either category.
- Do not forward scope eligibility through `Deref`, `AsRef`, or implicit
  conversions that erase a primary-key wrapper. Typed target/query handles
  retain the definition's concrete scope type, rather than accepting any
  type implementing `SearchScope` interchangeably. Distinct application
  newtypes can distinguish tenant and project scopes with equal wire types.
- Permit explicit application opt-in through a documented trait/derive
  contract. This is a semantic capability, not an unsafe-memory contract.
  Sealing every implementation cannot prove that a value groups multiple
  records: a caller can still explicitly rewrap a row identifier as a scope.
  Guarantee rejection of accidental role mixing, not business semantics.

Dynamic definitions must retain field roles and context-versus-scope
selection. Validate those roles before execution: an explicitly declared
primary-key field is not scope-eligible. Plain JSON numbers carry no such
role by themselves; do not infer it from the field name or wire encoding.
Generated Go types can represent the distinction, while the engine validates
dynamic declarations. Rust and dynamic lowering must produce the same
canonical context/scope values; never use Rust type names as wire domains.
Scope classification is not evidence of authorization to access a tenant.

Acceptance work: valid typed field/caller scopes, rejected primary-key and
mixed-tuple scopes, no automatic selection of marked fields, exact scope
type agreement between write/query, and equivalent dynamic validation.

#### Dynamic scope roles and validation

**Recommended design:** declare semantic types and source selectors in the
definition, validate once on load, and supply values separately per operation.
Do not let an individual request assert `scope_key` on an arbitrary value
to override the loaded definition. A definition author can explicitly
classify values, just as a Rust author can construct wrappers; this is
misuse resistance, not authorization or proof of multi-row cardinality.

**Accepted clarification:** `types` is optional; it holds reusable named
types. Fields may use built-ins or inline role wrappers. Ordinary built-in
or named values need no `kind`. Supported primitives remain eligible for
ciphertext context, but search eligibility requires explicit `scope_key`
classification (or another explicitly supported scope-capable type).

Illustrative declaration fragment (proposed schema, not today's wire API):

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

This is the context-related portion of a record target definition; encrypted
email targets and their search options are declared separately as usual.
The shared `field` shorthand selects plaintext fields on encrypt and stored
fields on decrypt; it does not imply a field exists in a query request.
For a query on the derived email handle, the definition exposes a required
`TenantId` scope argument. No `UserId` argument is required or accepted as
an alternative scope. A named/composite scope uses the same ordered schema
on the write and query paths, regardless of their different source selectors.

Definition loading resolves field references and source/output types,
computes the context/scope capabilities, verifies all composite components,
and rejects a primary-key search selector before key I/O. It also verifies
decrypt selectors are available from stored fields or declared caller input.
Compile the validated definition into an immutable handle shared by encrypt,
decrypt and query operations. No second query-specific scope policy.

At execution validate presence, nominal type when supplied by a typed handle,
physical representation, range, and composite shape against the selected
definition. Raw wire values obtain their expected semantic type from the
definition; they cannot prove their application provenance. Unknown role
overrides or mismatched nominal value handles are rejected. No fallback to
unscoped querying when a required scope is absent. When JSON is the authoring
or request format, preserve full-width integers through lossless parsing;
the frame transport already distinguishes supported integer widths.

Recommended Go generation uses distinct named ID types and query methods
with the required scope argument (`TenantID` rather than `uint64` or an
untyped context map). Generated wrappers remain conveniences over the same
validated runtime definition; ungenerated FFI callers receive runtime errors
for invalid declarations/requests. Do not assert Go shares Rust's ownership
or trait-bound guarantees.

Lower the chosen scope and binding through the existing canonical context
machinery, retaining scalar widths, ordering and grouping. Current dynamic
`context.rs` proves parity between runtime `ContextPiece` trees and Rust
context derivations, but has no primary-key/scope-role distinction. Add role
validation before lowering erases those distinctions, and keep the separate
resolved scope and binding available to their respective operations.
Do not persist role labels in every row just to recover them at runtime;
definition identity and deployment remain explicit concerns of loading the
same policy. Add Rust/Go/dynamic fixtures for valid scopes, primary-key
refusals, nested scopes, missing inputs and identical derived terms/AAD.

Completion: all nine cases execute through Rust and dynamic declarations;
required input is enforced, altered/wrong context is refused, and existing
context encodings agree across all new implementations.

### C. Finish the ciphertext and whole-value storage contracts

Accepted direction: a single-value plaintext encoding produces one opaque
`Ciphertext`. A normal application struct uses `OpaqueBlob<T>` to encode
and seal it as one value, or an explicit target for field-level encryption;
Serde alone does not imply automatic blob serialization. A custom type can
explicitly implement the single-value encoding capability. The wrapper
name and detailed persistence contract remain proposals.
Recommend canonical byte parsing/encoding, human-readable Serde as Base64
of those bytes, binary Serde as
bytes, and safe Debug behavior. Parsing an envelope does not authenticate
it; authentication occurs during decrypt.

The existing encrypted-output transcoder can implement the adapter:
`Node::Single(SealedValue)` is consumed by `Visitor::sealed` and moved into
the opaque wrapper. Keep the sealed value internally rather than forcing
a byte serialization at construction. There is no new encryption or KMS
request. On decrypt the wrapper delegates to the same leaf-opening path,
using a single-node wrapper if the internal API requires it.

Do not convert maps, sequences, passthrough nodes, or sealed empty-container
markers into this type merely because they have a byte representation.
Serializing a whole encrypted tree retains its multiple ciphertexts and
authentication boundaries; it does not produce single-value encryption.
The leaf visitor's unsupported-shape errors are a defensive check, not the
desired public discovery mechanism. Constrain ordinary encryption to
single-value encodable inputs so unsupported structural inputs are rejected
before encryption, statically in Rust where possible and during dynamic
validation. Settle the exact plaintext capability with the representation
traits; do not discover an unsupported shape only after minting keys.

Keep generic structural encryption and searchable JSON explicit. Specify
whether structural-tree persistence is supported and under what stable
format. Any protocol changes must be coordinated with their consumers.

#### Typed encodings and extractable ZeroKMS tags

**Requirements added, 2026-10-25:** ciphertext text conversion returns the
existing concrete encoding wrappers, not `String`. The user also wants to
explore selecting an encoded ciphertext as a field's output type. The
ZeroKMS key tag must be easily extractable from stored ciphertext, including
in PL/pgSQL, to support a separately designed refinable-tag mechanism.
The storage/authentication contract is not yet locked in.

Current `eql-bindings::encoding::{Base64Text, Base85Text}` validates canonical
padded standard Base64 and the crate's RFC 1924 Base85 encoding respectively.
Their private strings, encoding constructors and validating deserializers
make decoding infallible. They guarantee the text encoding, not that the
bytes form a ciphertext. Reuse these types and add ordinary fallible text
parsing conveniences rather than requiring Serde to construct them from text.

Recommended ownership: a small Vitamin C encoding component, re-exported by
Stack Encrypt and EQL. These byte/text utilities do not depend on encryption,
SQL or EQL layouts. Keep TypeScript/schema integration optional in the owning
crate, accounting for Rust's orphan rules when moving the existing trait
implementations. Do not introduce a Stack Encrypt dependency on EQL merely
to reuse its text wrappers. Final component placement remains a proposal.

Proposed ciphertext methods return `Base64Text` / `Base85Text` from
`to_base64` / `to_base85`; corresponding constructors accept the typed text
and still return a ciphertext parse error when its decoded envelope is
invalid. Encoding validation, envelope parsing and authentication are three
different guarantees. Use one canonical byte envelope under both encodings.

**Accepted, 2026-10-25:** support explicit encoded ciphertext field targets.
Use a ciphertext-specific storage wrapper
(working names `Base64Ciphertext` / `Base85Ciphertext`) over making every
`Base64Text` an encryption target. The wrapper validates both text and
envelope, serializes as the text string, and composes with `EncryptTarget`
and `DecryptSource`: seal once, then encode; parse before opening. These
names remain provisional until the final naming pass; the first-class
encoded target capability is settled. A structural output
can mix `Ciphertext` and encoded ciphertext fields without additional KMS
calls. Do not silently change the prescribed representation of EQL targets.

The current `SealedValue` v1 envelope already uses a simple prefix:
`version(1) | keyset_id(16) | iv(16) | tag_len(2, LE) | tag | local_ciphertext`.
Its ZeroKMS tag begins at byte offset 35, with length at offsets 33–34.
This is evidence that extraction can be simple, not a commitment to keep
those offsets. Keep the chosen version's layout documented and parseable
without the plaintext codec, key retrieval, or decryption. Prefer a checked
borrowed header/envelope view and an accessor explicitly named `key_tag`
over decomposing the whole ciphertext or conflating it with the AEAD tag.
Extraction does not authenticate the returned tag.

Ship a matching SQL/PL/pgSQL extraction helper and Rust/Go/SQL fixtures with
the storage format. Check versions, lengths and truncation before slicing.
For text storage prefer Base64 when SQL must inspect the header:
[PostgreSQL](https://www.postgresql.org/docs/current/functions-binarystring.html)
has built-in Base64 decoding and byte slicing, but not Base85 decoding.
If SQL extraction from a Base85 envelope is supported, supply an explicit
decoder; do not leave it as an assumed capability. PostgreSQL Base64 output
also inserts line breaks, unlike the canonical Rust wrapper: normalize SQL
output or validate it against the same canonical rules in cross-language
tests. JSON-tree storage needs its own header adapter: its shared key header
is distinct from each node's ciphertext and parent tag.

The proposed refinement uses the ZeroKMS tag as an HMAC key and replaces it
with a derived tag. **User clarification:** at decryption, ZeroKMS uses the
refined tag for policy checks and logging, and returns the original tag.
The decrypt path uses that returned original tag to reconstruct leaf AAD.
This resolves the conceptual conflict with binding the original tag into
AEAD: the stored/request tag and the authentication tag input need not be
identical after refinement. Keep those roles explicit in the KMS response
and decrypt implementation. Tag extraction returns the tag actually stored
in the envelope, which may be refined. Protocol details remain deferred;
this is the intended behavior, not a claim that the current client/engine
already implements it. Add refinement/decrypt integration coverage when
that work lands.

**Decision, 2026-10-25:** direct `encrypt` handles one single-value input;
`EncryptInto` handles collection composition and batching. This supersedes
the earlier open question about automatic collection lifting. The agreed
public examples are:

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
executor; the blob encodes and seals the complete collection as one value.
Do not add implicit collection handling to direct `encrypt`, or a separate
batch entry point merely to provide functionality already covered by
`EncryptInto`. Context-taking variants follow the same division.

Acceptance checks: reject direct `encrypt(Vec<i32>)` before execution;
support context-free `Vec<i32>` to `Vec<Ciphertext>`; preserve target-directed
collection opening and batching; and recover the blob as a whole collection.
Existing collection composition is retained, while opaque `Ciphertext` and
its no-context target support are new work.

The current prototype treats `Vec<u8>` as one byte value, but that is not a
compatibility constraint. The latest recommendation is uniform collection
behavior: `Vec<u8>` to `Vec<Ciphertext>` encrypts individual bytes, while
`OpaqueBlob<Vec<u8>>` encodes the complete vector as one value. Do not add
`Vec<u8>` to `Ciphertext` conversion or a bytes wrapper solely to retain
prototype behavior. A distinct raw-byte capability would need its own use
case. The blob codec need not reproduce the prototype's raw-byte encoding.

For `OpaqueBlob<T>`, select the library-owned codec, authenticated codec/type
discriminator and version, schema-evolution policy, error behavior, and
supported source/decoded types. Authenticate before deserializing plaintext.
Do not silently reinterpret an ordinary byte ciphertext as a different
encoding. Preserve an explicit wrapper rather than implicit Serde fallback.

The constant-time question needs a concrete conclusion: assess `serdect`,
the codec, both sides of Serde (value traits and serializer/deserializer),
length/shape disclosure, and permitted custom implementations. If arbitrary
Serde types remain supported, do not promise end-to-end constant-time
serialization. Select a restricted profile separately if that property is
required; it cannot be inferred from the wrapper or its encryption primitive.

Completion: scalar and blob examples persist and reload through a fresh
cipher, reject invalid encodings, and verify fixtures for the selected
format. The supported timing contract and codec version are documented.

### D. Complete record derives and preserve collection composition

Implement explicit passthrough and source-field renaming, independently of
context selection and storage. Generate decrypt reconstruction for the
same record. Support nested targets with and without configuration, and
report incompatible context or source types at their declarations.

Keep the collection behavior already present: `Vec<S>` to `Vec<T>` composes
the target operations into one logical batch, rather than awaiting every
row separately. Preserve document/leaf key granularity; one logical batch
does not promise one physical ZeroKMS request beyond backend limits.

Completion: the public mixed-record and searchable-record examples run,
including batch encrypt/decrypt, nested targets, renamed passthrough fields,
and stored context. Dynamic/Go declarations produce equivalent semantics.
A plaintext-side derive generating output types is deferred convenience,
not a prerequisite for these workflows.

### E. Finish the configured policy's lifetime and query surface

Use the prior query-design baseline and reconciliation above. The query
model is not an empty design space: field-owned index selection, typed
handles, and shared derivation already have a detailed proposal.

The typed-factory direction is established. The target-definition section
above now proposes its owner: a shared immutable fixed definition, or an
explicit runtime instance, with generated typed field handles. Review that
proposal and prove its initialization/lifetime behavior before treating the
once-only reuse claim as implemented. Multi-field runtime configuration and
the exact generated signatures still require specification.

Write complete static and Go examples for equality, JSON containment,
ordered paths, and extraction, all using the write policy. Specify query
results and unsupported-operation errors. Keep those examples free of
mandatory hand-written plans. Preserve direct typed EQL conversion and
catalog/guest support as deliverables of the configured-target sequence.

### F. Make naming and coordinated integration part of completion

Use the [packaging glossary](2026-10-25-stack-encrypt-packaging.md) for the
proposed role-based JSON names, retained `OpaqueBlob`/`Ciphertext` spellings,
shared format crate and primitive/application split. Retain accepted
declaration/convenience trait names. Recommend renaming the plan builder's
output-selection method to `target`; distinguish it from executing
`EncryptInto`. New spellings and crate moves still require review.

Remove replaced APIs directly and update EQL, Go, and guest consumers
together. There is no requirement to read prototype ciphertext or preserve
old imports. Specify the selected encoding and cryptographic semantics,
and establish fixtures for that contract going forward.

Completion: all public examples are executable tests, static/dynamic
cross-opening and querying pass against the selected storage format, batching
checks pass, and the guest builds remain supported. No new API is described
as implemented until its Rust and Go acceptance criteria are met.

## Recommended order for the remaining design decisions

### Decision checkpoint, 2026-10-25

Settled direction: keyset-directed single-value encryption; target-directed
collection batching; explicit `OpaqueBlob`; conversion methods separate
from `EncryptTarget`/`DecryptSource` declarations; explicit context-input
capabilities instead of `Default`; typed Rust options factories and dynamic
deserialization into the same options; static and dynamic support together;
shared typed definitions and field handles; a consistent `using` selector
with strict typestate and definition-first query spelling; `OpaqueEncode`
/ `OpaqueDecode`; consuming encrypt and encrypt_into with guarded cleanup;
ordinary keyset decrypt alongside the destination-directed decrypt pair,
both with context variants and ordinary owned `T: Zeroize` results;
separate ciphertext context and search scope with `PrimaryKey`/`ScopeKey`
eligibility; definition-time role validation in the dynamic interface,
optional named-type declarations and explicit scope eligibility; and a
versioned interoperability specification with shared conformance coverage;
and no backward compatibility with the prototype. Do not reopen these
choices merely because older examples or work-area descriptions retain
provisional wording.

The remaining product/API decisions are narrower. Distinguish them from
specification and implementation obligations:

| Remaining question | Decision required |
| --- | --- |
| JSON contract review | User review is in progress. Review concrete operation recipes against the comprehensive required inventory, including stricter path validation and request-bound extraction. Custom-stage portability, validation timing and initial ORE equality policy are now accepted. |
| Key selection and optional provider policy | Review plaintext-derived keyset selection, client-scoped routed execution, and ZeroKMS lock context as optional provider capabilities. Assess the neutral data/index-key boundary and the intentional non-use of Vitamin C AsyncCipher in the provider-capabilities companion. |
| Stable blob profile | Specify supported Serde shapes, lossless options/enums/maps, authenticated codec versions and compatibility fixtures under Vitamin C #519. This is the immediate priority; format-preserving cleanup/timing improvements are follow-up work, with limitations documented honestly. |
| Packaging and names — review in progress | Review the packaging companion's shared format crate, Stack-owned value execution, primitive-only Vitamin C boundary, AsyncCipher retirement, ZeroKMS client rename and role-based JSON names. Encoded ciphertext field targets themselves are accepted. The accepted trait names, `ScopeKey`, and receiver choices are not open again. |

Next review the JSON operation document and its static/dynamic examples,
then turn the required inventory into implementation phases and formal
interoperability fixtures. Stable storage-format work is tracked upstream.
Finish remaining query integration details without reopening ORE equality.
The user has now requested the naming/package pass while JSON review
continues; that proposal is ready for review in the packaging companion.

Specification/implementation work still includes exact context/scope grouping
and encoding, dynamic grammar and version identifiers, error codes, binary
envelope fields, Rust/Go/SQL fixtures, and the refined-versus-original tag
flow. Record candidate choices in the formal specification for review; do
not treat every byte offset or adapter signature as a new architectural
decision. The initial persistence recommendation remains ordinary Serde
composition for explicit layouts, without a new arbitrary-tree wire format.

Cleanup implementation still needs guarded encoder sinks, partial decode
handling, cancellation/drop checks, and an explicit drop-guarded result
adapter. Under the user's latest sequencing decision, implementation
improvements may follow the stable format; preserve the stored contract and
document actual guarantees instead of claiming the eventual goals are
already satisfied. No completed constant-time/zeroization audit is implied.

The shared-definition caching, initialization error/retry behavior, generic
identity, and request lifetimes still need concrete signatures and proof.
That is implementation design within the recorded ownership model, not a
reason to reopen the question of whether writes and queries share a policy.

Passthrough implementation, transcoder adapters, collection composition,
trait relocation, documentation updates, and acceptance tests remain work
items. They are not reasons to characterize the agreed API direction as
undecided. No backward-compatibility phase is needed for the prototype.
