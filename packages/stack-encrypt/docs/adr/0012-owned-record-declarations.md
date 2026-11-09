---
status: accepted
date: 2026-11-03
extends: ADR-0003, ADR-0004
---

# Records are owned targets, and the structural traits become a bridge

## Summary

This ADR calls a struct that is encrypted field by field a record. A
record is now declared with `#[derive(EncryptTarget, DecryptSource)]`. Encrypting a
record consumes the plaintext struct. The conversion wipes each field it
seals, and moves each field it stores in the clear, so nothing is copied.
The same derives also implement the older structural traits, `EncryptFrom`
and `DecryptInto`, so an owned record works wherever a structural record
does.

This ADR records five decisions, and the limits they leave to the caller.

## Context

The owned API is `EncryptInto` and `DecryptFrom`, over the declarations
`EncryptTarget` and `DecryptSource`. Each declaration has a `ContextInput`
type. That type says which context the caller can pass, and which context
the caller must pass. Before this change, the owned API covered one opaque
scalar, and a `Vec` of them.

Records were declared only with the structural traits, `EncryptFrom` and
`DecryptInto`. The derives, the typed fields of the plan builder, and the
dynamic lowering all used them. The structural traits work over a borrowed
plaintext, and take their context from `Default`.

The public examples show a mixed record: `id` stored in the clear, and
`name` and `email` sealed. A user writing that record had three problems:

- No derive consumed the plaintext and wiped it.
- There was no way to say "store this field in the clear".
- Nothing made the record's fields and the scalar API agree on contexts.

## Decision

### 1. One trait, with two forms of the description

`EncryptTarget<S>` keeps `encryption()`. That method describes the
encryption over `&S`. This change adds `owned_encryption()`. That method
describes the encryption over `S` by value, in `Owned` source mode.

The default `owned_encryption` guards the value in `Protected`, runs the
borrowed description over it, and wipes it before the pending request is
returned. `EncryptInto` used to do exactly this for a scalar, by hand. So a
declaration that only composes operations does not need to implement
anything new. `EncryptInto` now runs `owned_encryption`, and the collection
declaration runs it for each element.

| Declaration | Plaintext it is given | It returns | Who wipes the plaintext |
|---|---|---|---|
| `encryption()` | A borrowed `&S` | `Encryption<'s, S, T, K, Input>` | The caller, or the owner that guards the borrow |
| `owned_encryption()` | `S` by value | `Encryption<'s, S, T, K, Input, Owned>` | The declaration. The default guards the value and wipes it |
| `decryption(self, Input)` | The stored value | `Decryption<P, K>` | The engine until the call returns, then the caller |

### 2. A record divides its plaintext between its fields

A `struct = User` record that derives `EncryptTarget` composes the targets
of its fields directly.

- **The borrowed form** takes each field out of the borrow, with
  `Encryption::project`.
- **The owned form** divides the struct with a chain of `Encryption::split`
  calls. `split` is a new combinator in `Owned` mode. It gives two different
  parts of one value to two descriptions, under one context.
  - A `#[stash(passthrough)]` field is moved into the record by
    `passthrough::<_, _, Owned, _>()`, and never copied.
  - Each sealed field runs its own target's `owned_encryption`. So a
    `String` field is guarded and wiped by the `Ciphertext` target that
    seals it.

The function that divides the struct is a plain function pointer that
destructures it. The function captures nothing, so it cannot reach a
cipher. It can only move values. The selector of `project` has the same
limits. So the code enforces the rule that a conversion wipes what it seals
and moves what the caller keeps in the clear.

Each `split` runs the description of its first part while the other part
waits. `split` is given a `wipe` function for the waiting part. If the first
description panics, the waiting part is passed to `wipe` during the unwind,
and not dropped as it is. An owned column treats its unvisited elements the
same way. The derive writes each `wipe` to wipe the sealed fields that are
still waiting, and to leave the passthrough fields alone.

- The plaintext of a sealed field already implements `Zeroize`, as every
  `EncryptTarget` source does. So `wipe` adds no bound.
- A passthrough field is stored in the clear, so it needs no bound.

`EncryptInto` keeps the whole plaintext in a `Protected` guard until the
declaration and its context exist. So a declaration that panics while it is
being built also wipes the plaintext.

The destructure is exhaustive. The owned form does not guard the whole
value. So a plaintext field that the record neither seals nor moves would
be dropped without being wiped. Such a field is a compile error at the
`struct = ..` path instead. The decrypt side already refused a plaintext
that it could not rebuild.

On decryption, the fields open through `Decryption::zip_wiping`. A field
recovered before a later field is refused is wiped, as the recovered
elements of a column are.

A passthrough field is not encrypted and not authenticated (ADR-0010). Its
type must implement `Clone`, because the borrowed form copies it. Plans and
structural records run the borrowed form. The owned form never copies the
field, and a test with a `Clone` that panics checks that.

### 3. Caller context is a capability, composed through the tree

Two inputs join `NoCallerContext`, `RequiredContext<C>`, and
`OptionalContext<C>`:

- **`DeclaredScopes`.** The caller passes no context. Each field's context
  is the record's name, then the field's name. A record that contains this
  record passes it the field's context. A plan does the same. That context
  extends each of the inner record's contexts. A `struct` record takes this
  input, to encrypt and to decrypt.
- **`ExpectedContext<T>`**, an existing type that is now a `ContextInput`.
  If the caller leaves the context out, the record opens under the context
  it stores. If the caller passes a `NonEmpty<T>`, the stored context must
  also equal it. A `context_field` record takes this input to decrypt.

A `plaintext = T` record takes `RequiredContext<CallerContext>`, or
`RequiredContext<AeadContext>` with `context_type = AeadContext`. It takes
`RequiredContext<NonEmpty<T>>` when it stores its context. The core leaves
take the same wrappers around the context their operation needs. So a term
implements `EncryptTarget` alone, and no context is inferred from
`Default`.

A record field is given its own context, extended by the context of the
record that contains it, through `Encryption::under` (ADR-0004). `under` requires the field's input
to implement `From<CallerContext>`. That one bound produces the error at the
field:

- These inputs implement it: `OptionalContext`, a `RequiredContext` of a
  core context, and a nested record's `DeclaredScopes`.
- These inputs do not: `NoCallerContext`, and `RequiredContext<u64>`. A
  field whose target takes one of them is a compile error at that field.

Every field of a `plaintext` record is given the one context the record
requires. So a term in a record with `context_type = AeadContext` is a
compile error at the term. A call that leaves out a required context is a
compile error at the call.

A record does not accept a caller's scope or row binding yet. The API plan
(`docs/plans/2026-10-24-stack-encrypt-api-plan.md`) decides three things:

- A caller supplies such parts as `Scope::new(..)` and `Bind::new(..)`.
- A record declares each part it accepts.
- The search terms leave out a binding.

That work is tracked separately. Until it lands, a caller's row ID would
also scope the search terms. The plan rejects that.

### 4. The structural traits are a bridge, not a second declaration

Each owned derive also implements the structural traits:

- `EncryptTarget` also implements `EncryptFrom` and `Decryptable`.
  `EncryptFrom` converts the record's structural context into its owned
  input, at the root.
- `DecryptSource` also implements `DecryptInto` and `DecryptField`.

The core leaves implement both pairs by hand. So an owned record can be a
field of a structural record, or a typed plan field, with no second derive.
The plan builder gains `target::<T, _>()`, for a target that implements
only the owned traits, such as `Ciphertext`.

The dynamic lowering does not change. An equivalence test seals one record
three ways: through a hand-written `EncryptTarget`, through the derive, and
through the data plan. All three use one provider that records its
requests. The test finds the same descriptors and the same term bytes, and
each of the three decrypts the records of the other two.

The structural derives stay, because the plans and the dynamic engine still
use them. Removing them is a later decision, once every consumer has an
owned equivalent.

### 5. The structural `Vec` decrypts through the wiping path

`Vec<T>: DecryptInto<Vec<P>>` and `DecryptField<Vec<P>, _>` used to decrypt
through `Decryption::all`. When an element failed late, the elements
recovered before it were dropped without being wiped. The impls now decrypt
through `all_wiping`, as the owned column does.

That puts the bound `P: Zeroize` on those public impls. Every plaintext the
engine decrypts into already implements `Zeroize`. A structural caller with
a struct plaintext must derive it.

## Options considered

- **A `Zeroize` bound on the waiting part of `split`.** This would do the
  same work as the `wipe` function. It was rejected because the bound would
  also apply to the types of passthrough fields. Those fields are stored in
  the clear, so their types have no reason to implement `Zeroize`.
- **A non-exhaustive destructure (`..`).** This would let the plaintext
  type implement `Drop`, and so derive `ZeroizeOnDrop`. It was rejected
  because a field that the record does not name would then be dropped
  without being wiped. Nothing would report that field.
- **An optional caller extension (`ContextExtension<C>`).** An earlier
  version of this change let the caller extend every field's context. It
  was removed after the naming review of 8 November 2026. A row ID passed
  that way also scoped the search terms, so a query had to know the row.
  The plan replaces it with declared scopes and bindings.
- **A second declaration for the structural traits.** This was rejected.
  Two declarations of one record could disagree about contexts. The
  equivalence test shows that one declaration, bridged, gives the same
  bytes as the data plan.

## Consequences

- `user.encrypt_into(&keyset)` on a `struct` record wipes `name` and
  `email`, and moves `id`. Encrypting a `Vec<User>` into a
  `Vec<SearchableUser>` makes one key request. `User::decrypt_from(record,
  &cipher)` moves `id` back.
- A record's plaintext must implement `Zeroize`. The bound says who must
  wipe the plaintext. It is not a promise about copies the caller keeps, or
  temporaries the compiler makes. The limits in ADR-0010 still apply.

### What is left to the caller

These are deliberate limits. Each is documented on the type or method the
caller uses.

- **A decrypted plaintext is not wiped when it is dropped.** The owned form
  destructures the plaintext struct, and Rust does not allow that for a
  type that implements `Drop`. So the plaintext of a `struct` record cannot
  derive `ZeroizeOnDrop`. The caller must wrap the decrypted value in
  `Protected`, or call `zeroize` on it. The derive docs and the crate
  example show the wrapping.
- **A passthrough field is not encrypted and not authenticated.** Anyone
  with access to the stored record can read it, change it or remove it, and
  the sealed fields still decrypt. The attribute's name and its docs say so.
  A value that must be readable and tamper-evident belongs in the caller's
  context instead.
- **A `context_field` record decrypted with no expected context opens under
  whatever context it stores.** The stored context is not authenticated, so
  a ciphertext moved together with its stored context opens in its new
  place. The caller must pass the context it expects to get the check.
- **`Encryption::project_owned` drops the other fields of the struct
  without wiping them.** It suits a struct whose other fields contain
  nothing secret. A record divides its struct with `split` instead.

### What is not done yet

- Configured targets, such as a JSON index with options, cannot yet be
  fields of an owned record. The one configurable target's plaintext,
  `serde_json::Value`, does not implement `Zeroize`, so it cannot be an
  owned source. The attribute for a typed options factory waits for a
  document plaintext that can be wiped.
- `Option<T>` and tuple targets stay structural-only in this change.
