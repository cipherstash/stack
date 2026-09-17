---
status: accepted
date: 2026-09-13
extends: ADR-0003
---

# One context per target, threaded through the declaration tree

[ADR-0003](0003-declarative-targets-and-ciphertext-transcoding.md) gave targets
an associated `Context` type and a declaration they compose from core
operations. That settles what a caller must *supply*. It does not settle where
the supplied value *goes*, and the gap is load-bearing: a target that produces
a ciphertext and its index terms can hand each operation a different context,
and nothing — not the type system, not a runtime check, not a test — relates
them.

This ADR records how a context reaches the operations beneath it, and why the
answer is a type parameter rather than a convention.

## The problem

Every operation constructor takes its own context:

```rust
ciphertext::<S, K>(ctx_a).zip(equality::<S, K>(ctx_b))   // compiles
```

`Self::Context` is plumbing the implementation may route, reroute or discard.
`zip` combines builders and relates nothing. So a composite target can seal a
value under one context and index it under another.

The two mistakes fail differently, and that asymmetry is why this matters more
than it first appears:

| mistake | how it surfaces |
| --- | --- |
| ciphertext under the wrong context | ZeroKMS refuses the retrieve (its descriptor is HMAC'd into the key tag), or the AEAD rejects — loud, at first read |
| term under the wrong context | a valid term in a different domain. A probe built correctly never equals it |

A mis-contexted term produces no error, ever. Queries return nothing, and an
empty result is indistinguishable from no matching rows. The symptom appears in
the read path, possibly long after the write, and looks like missing data rather
than a fault.

Derived records are safe today because `#[derive(EncryptFrom)]` passes one
`context_expr` per field to that field's operations. The exposure is
hand-written *composite* targets — which EQL has (the SteVec/JSON ones), and
which any external consumer writes with no derive to save them.

Per-field contexts differing is **not** the problem; that is deliberate domain
separation. The problem is that within one field, the ciphertext and its terms
have no relation.

## Decision

### 1. Operations take no context; the tree carries one

`Encryption::build` gains the context as a parameter, and `zip` hands the same
value to both sides. A target cannot *route* the context it is handed — there
is no argument to forget, swap, or fill from the wrong variable, because there
is no argument.

```rust
ciphertext::<S, K>().accepting().zip(equality::<S, K>())    // one value reaches both
```

(`accepting` converts the ciphertext's context *type*, as decision 3 explains;
the value passes through.)

What this does not rule out is a target that gives each half a context of its
own, by name:

```rust
ciphertext().under(nonempty!("cipher")).zip(equality().under(nonempty!("term")))
```

That compiles, and the term is under a different context from the ciphertext.
It is the same construct, to the letter, as a record giving each of two
*fields* its own context (decision 2), and the tree cannot tell a two-context
target from a two-field record: the reason the runtime check in `zip` is
rejected below applies to the type system too. What changes is what the
divergence costs to write. It is two literals in the declaration, each naming
the context it sets, where before it was one supplied value reaching one side
and something else reaching the other — visible at review, where a routing
mistake was not.

### 2. `under` and `extend` are the only ways to change it, and each covers a whole subtree

A record gives its fields different contexts once each, visibly, instead of
threading six arguments:

```rust
age.under(nonempty!("users/age")).zip(email.under(nonempty!("users/email")))
```

`under` gives a subtree a context of its own, which a caller's context
extends if one is given — so the result can run under `()`. `extend` does the
same for a record that cannot make the caller's context optional, because
some *other* field of it is a bare leaf: the subtree's own context is
extended by the caller's, which stays required. `under` is available wherever
a `CallerContext` can become what the subtree needs, and `extend` wherever
the caller's context — a `CallerContext`, or an `AeadContext` for a record
that only seals — can; so a subtree may itself be a record whose own contexts
a caller's extends. An own context is a `NonEmpty<&'static str>`, so an empty
one is refused at compile time rather than at the first encryption.

Two further combinators change nothing about *which* context reaches a
subtree, only its type at the root. `accepting` converts the context a record
declares its caller supplies into the one its operations need, once, at the
root — a record storing its own context declares the `NonEmpty<T>` it stores
while its operations want a `CallerContext`. `map_with_context` hands the
output the context the tree ran under, which is how such a record fills the
stored field: under threading the context arrives when the description runs,
not when it is built.

### 3. The context is a type parameter, so the empty-context rule stays compile-time

`Encryption<'s, S, T, K, Ctx>`, where `zip` requires both sides to share `Ctx`:

- `ciphertext()` is `Encryption<.., AeadContext>` and `equality()` is
  `Encryption<.., CallerContext>` — each needs a real context
- `.under(nonempty!("users/age"))` yields `Encryption<.., DeclaredContext>` —
  now runnable under `()` or a caller's context
- zipping a bare leaf with own-context fields is a type error, which is correct

A ciphertext and a term need different kinds of context. Sealing uses only
the AEAD encoding, so `ciphertext()` is `Encryption<.., AeadContext>`, and a
record made only of ciphertexts may declare `context_type = AeadContext` and
accept an `IntoAad`-only type, exactly as the leaf does. Deriving a term uses
the PRF encoding as well, so a term needs a `CallerContext`. The two still
zip under one value: `accepting` lets the ciphertext take the term's
`CallerContext`, of which its own `AeadContext` is the AEAD half, and that
conversion is the only thing that happens to the context between the root
and the leaf. Nothing is narrowed — a ciphertext alone seals under exactly
what it did before this ADR.

The derive follows the same rule rather than its own. A field with a context
of its own gives its subtree that literal (`under`, or `extend` when the
record cannot make the caller's context optional). A field with none is
handed the record's context as it is, converted into whatever its type
declares it needs — unchanged for a leaf, composed with its own contexts by a
nested record, and, for a leaf reached through a record that may run under
`()`, refused at the field. The impl names concrete context types in its
bounds rather than adding a parameter: a parameter constrained only by an
associated-type binding is E0207, and the author is told "unconstrained type
parameter" instead of their mistake.

This is the part that cost a spike to find. Threading a single *runtime* value
(`Option<CallerContext>`) is simpler and wrong: `T::Context` is deliberately
heterogeneous — `CallerContext` for a leaf, `DeclaredContext` for a record whose
fields carry their own, `ExpectedContext<T>` for a `context_field` record — so
collapsing them makes a leaf reached without a context fail at *runtime*. Today
that is a compile error, with a `#[diagnostic::on_unimplemented]` message and UI
fixtures pinning it. Trading a compile-time guarantee to buy this one is not a
trade worth making, and the type parameter buys both.

### 4. A data-key request takes a context, not a descriptor

`Request::generate_data_key` and `retrieve_data_key` currently accept a built
`Descriptor`. Together with `Pending::request` and `SealedValue::from_parts` —
all public, all documented as the third-party SEM extension point — that lets a
downstream implementation mint under one context and authenticate under another
with no crate code in the path.

They take a context and render the descriptor themselves. The context is
anything `Into<AeadContext>`: a descriptor is rendered from the AEAD encoding
alone, and a ciphertext needs no more than that to seal, so the `IntoAad`-only
type a `StackCipherText` seals under can request the key it seals with. The
extension point stays; what goes is a *request* naming a descriptor that
disagrees with the context its data key is asked for under.

What does not go: `SealedValue::from_parts` still takes raw parts, so a
downstream SEM that seals its AEAD under one AAD and requests its key under
another remains expressible. That seam *is* the extension point, and closing
it is the product decision "seal the low-level request API" declines below.
This decision narrows the exposure to a downstream assembling a sealed value
by hand; it does not remove it.

### 5. Stored terms go through targets; standalone derivation is the query path

`KeysetCipher::{equality_term, match_terms, ore_term, ope_term}` remain: a query
probe has no ciphertext to agree with, so constraining it means nothing. They
are documented as the query-probe path, and a term that will be *stored* is
directed to a target, where it shares its ciphertext's context by
construction.

No code moves and nothing enforces this. It is the "convention and
documentation" option below, applied to the one place the type system cannot
reach: a probe and a stored term are the same bytes, and the term methods
cannot tell which they are producing.

### 6. Targets declare their sources; `FfiValue` is not one

A target names the plaintext it accepts (`TextEq` from `Protected<String>`), and
never an enum spanning every scalar. `EncryptFrom<FfiValue>` would make a
`UInt32`-into-`TextEq` a runtime error inside the crypto layer and leave every
valid pair unprovable.

The dynamic-to-static bridge is a dispatch at the FFI boundary: a match on the
value's variant against the plan's requested target. A plan and a value that
disagree fail there, as plan validation, with the offending field named — and
the whole plan is validated before any key is requested, so a fifty-field row
does not issue thirty requests before failing on the thirty-first.

### 7. Heterogeneous targets unify after `map`, not before

Targets differ per field, so there is no common output type. `map` applies to an
*unsettled* `Pending` and preserves its requests, so a binding maps each target
to its own node type and collects the results — one batch, strongly typed
targets right up to the point they become wire bytes.

A plan-driven caller collects those mapped `Pending`s with `Pending::all`, and
that is the right layer for it: a binding bridging a dynamic wire format to
static types has to hold per-field encryptions before combining them, and
naming the carrier costs nothing. What matters is the narrower property —
`encrypt_as(&source, context)` takes one context and feeds both halves — which
holds whether or not `Pending` appears in the binding's imports.

An `Encryption::all` was proposed here and implemented, then removed: a
declaration is produced by `encryption()`, which sees no source, so the length
of such a list is fixed per *type* and cannot come from a plan. The
homogeneous runtime-length case is already `EncryptFrom<Vec<S>> for Vec<T>`,
whose length comes from the source. A combinator that composed from the source
would serve the remaining case, and is not proposed until something needs it.

### 8. `ExpectedContext` stays permissive, deliberately

`#[stash(context_field)]` lets a record carry its context, and the default
`ExpectedContext` accepts whatever the record stores rather than checking it
against an expected value.

This is a decision, not an oversight, and the reason is the onboarding flow: add
`email_encrypted`, migrate, drop `email`, rename `email_encrypted` to `email`.
Every historical row still stores the pre-rename identifier, so a strict check
would reject all of them at the first read after a rename.

The consequence is acknowledged: an identifier that must survive renames cannot
also enforce placement. What it provides is a label, not a guarantee. A whole
self-consistent record moved from one column to another still opens — a confused
deputy, mitigated by client-side checking rather than by this mechanism. The
AEAD and descriptor bindings are unaffected: nobody reaches a key they are not
entitled to. Dropping the stored identifier entirely is the likelier end state
than tightening the check.

## Relation to vitaminc#341

That PR collapses `Aad`, `AadPiece` and `PrfContext` into one `Context` with
`IntoContext` as the only implementable trait, so a context's AAD and PRF
encodings agree by construction rather than by a test. It is the same
principle one layer down: #341 unifies how a context is *encoded*, this ADR
unifies how it is *routed*.

Two things here get simpler when it lands. The `accepting` step between a
ciphertext and the terms beside it — an `AeadContext` taken from a
`CallerContext` — disappears, because one `IntoContext` impl gives both
encodings and the two context types collapse into one. And `CallerContext`,
which exists to hold the two encodings of one value and keep them in
agreement, thins to a newtype over `Context` or goes entirely.

## Considered options

**Convention and documentation.** State the invariant on `EncryptFrom` and pin
the correct pattern with an example. Kept as the fallback, and worth doing
regardless — an external consumer reads that before writing a composite — but it
is enforcement by hope.

**Detect a mismatch at runtime in `zip`.** Rejected: `zip` cannot distinguish a
record legitimately combining differently-contexted *fields* from a target
illegitimately combining differently-contexted *operations*. It would reject
valid code or miss the bug. The type parameter has the same blind spot
(decision 1); what it adds is the two compile-time rules, not the distinction.

**Reserve `under` and `extend` for the derive**, so a hand-written declaration
could name a context only once, at its root. Not taken: a hand-written record
is a supported shape — the derive emits what one would write — and the derive
would need a private door into the same combinators. Open, if the residual in
decision 1 turns out to matter in practice.

**Thread one runtime context.** Rejected for the reason in decision 3: it costs
the compile-time empty-context guarantee.

**Seal the low-level request API.** Rejected: removing a documented extension
point is a product decision, and decision 4 closes the seam without it.

## Consequences

The routing of a context becomes structural rather than documented, and the
empty-context rule strengthens rather than weakens: `()` at a leaf is a type
error, and so is a target that discharges the context on one side of a `zip`
and leaves the other still needing it. The UI fixtures pin both:
`leaf_without_context.rs` and `nested_leaf_without_context.rs` the first,
`divergent_context_in_target.rs` the second. Two own contexts inside one target
remain expressible, as decision 1 says, because they are two fields as far as
the tree can tell.

It costs a type parameter through `Encryption`, every operation constructor,
every combinator, `EncryptFrom::Context`, and the derive's codegen. The UI
fixtures are sensitive to far less than this; budget for them, and treat a
worsened diagnostic as a defect rather than fixture noise.

It lands inside ADR-0003's implementation rather than after it. Once that merges
these are public signatures, and EQL builds roughly ninety-five (source, target)
pairs on them immediately — so the same change afterwards is a breaking one with
a real downstream.

What it does **not** fix: a term and a ciphertext written through two separate
top-level calls still have no relation to each other, because neither knows the
other exists. Decision 5 narrows this to callers who deliberately bypass the
target layer on the write side.
