---
status: accepted
date: 2026-11-03
revised: 2026-11-09
extends: ADR-0003, ADR-0004
---

# Records are owned targets, and the structural traits become a bridge

## Summary

A record is a struct whose fields are encrypted one by one. Some of its
fields can be stored in the clear. This ADR records how a record is
declared, encrypted and decrypted:

- You derive `EncryptTarget` and `DecryptSource` on the encrypted struct.
  The plaintext struct carries no attributes.
- `user.encrypt_into(&keyset)` takes the plaintext by value. It encrypts and
  wipes each field it encrypts. It moves each passthrough field into the
  record, with no copy.
- `Protected::<User>::decrypt_from(record, &cipher)` decrypts the record
  into a `Protected`. The `Protected` wipes the plaintext when it is
  dropped.
- A record's name is its first scope, `#[stash(scope = "users")]`. Each
  field's context is the record's name, then the field's name. The caller
  adds nothing to it.
- The same derives implement the older structural traits, `EncryptFrom` and
  `DecryptInto`, until the API plan removes them.

The API plan, `docs/plans/2026-10-24-stack-encrypt-api-plan.md`, sets the
direction. This ADR is the part of it that the record derives build.

## Context

Stack Encrypt has two APIs for declaring what a value encrypts into:

- **The owned API.** The conversions `EncryptInto` and `DecryptFrom` run the
  declarations `EncryptTarget` and `DecryptSource`. Encryption takes the
  plaintext by value and wipes it. Before this change, it covered one value,
  and a `Vec` of values.
- **The structural API.** The declarations `EncryptFrom` and `DecryptInto`
  encrypt a borrowed plaintext. The record derives, the plan builder, and
  the dynamic engine used them. They take their context from `Default`.

A typical database row has some encrypted columns, such as `name` and
`email`, and some plain ones, such as `id` and `created_at`. To write that
row as a record, a developer needed three things that did not exist:

- a derive that takes the plaintext by value and wipes it;
- a way to say "store this field in the clear";
- one rule for the context of each field, shared with the one-value API.

## Decision

### 1. One declaration trait, with two forms of the description

`EncryptTarget<S>` keeps `encryption()`. It describes the encryption of a
borrowed `&S`. This change adds `owned_encryption()`. It describes the
encryption of `S` by value.

By default, `owned_encryption()` puts the value in a `Protected`, runs the
borrowed description over it, and wipes it before the pending request is
returned. A declaration that only composes operations therefore needs no new
code. `EncryptInto` runs `owned_encryption()`. So does a `Vec` of targets,
for each element.

| Method | Given | Who wipes the plaintext |
|---|---|---|
| `encryption()` | A borrowed `&S` | The caller, or the owner of the borrow |
| `owned_encryption()` | `S` by value | The declaration. By default, it guards the value and wipes it |
| `decryption(self, input)` | The stored record | The engine until the call returns. Then the caller, or the `Protected` the caller decrypts into |

### 2. A record divides its plaintext between its fields

A `struct = User` record composes the targets of its fields.

- **The borrowed form** takes each field out of the borrow, with
  `Encryption::project`.
- **The owned form** divides the struct with a chain of `Encryption::split`
  calls. `split` gives two different parts of one value to two descriptions,
  under one context.
  - A passthrough field is moved into the record, and never copied.
  - Each encrypted field runs its own target's `owned_encryption()`. So a
    `String` field is guarded and wiped by the `Ciphertext` target that
    encrypts it.

The function that divides the struct is a plain function pointer that
destructures it. It captures nothing, so it cannot reach a cipher. It can
only move values. The selector that `project` takes has the same limits.
This is how the code makes sure that a conversion wipes what it encrypts and
moves what it stores in the clear.

`split` runs the description of its first part while the second part waits.
It is given a `wipe` function for the waiting part. If the first description
panics, the waiting part is passed to `wipe`, so it is not dropped without
being wiped. The derive writes each `wipe` to wipe the encrypted fields that
are still waiting, and to leave the passthrough fields alone. A `Vec` treats
the elements it has not reached yet the same way.

`EncryptInto` keeps the whole plaintext in a `Protected` until the
declaration and its context have been built. So a declaration that panics
while it is being built still wipes the plaintext.

The destructure names every field. The owned form does not guard the whole
value. So a plaintext field that the record neither encrypts nor moves would
be dropped without being wiped. Such a field is a compile error instead.

That is one of the plan's two safety rules for records. The other is that a
field is stored in the clear only where `passthrough` is written on it.

On decryption, the fields are opened through `Decryption::zip_wiping`. If a
later field is refused, the fields already opened are wiped.

A passthrough field is not encrypted and not authenticated (ADR-0010). The
field's type must implement `Clone`, because the borrowed form copies it.
The owned form never copies it. A test with a `Clone` that panics checks
that.

### 3. The context of a record

A record's name is its first scope: `#[stash(struct = User, scope =
"users")]`. The field's name is the next scope. So the `email` field is
encrypted under `("users", "email")`. These are the record's declared
scopes, in the plan's terms.

Each declaration has a `ContextInput` type. The type says whether the caller
must pass a context, may pass one, or must not pass one. This change adds
two:

- **`DeclaredScopes`**, for a `struct` record. The caller passes no context.
  `encrypt_into_with_context` does not compile for such a record. A record
  that contains this record passes it the field's context, and so does a
  plan. That context extends each of the inner record's contexts.
- **`ExpectedContext<T>`**, for decrypting a record that stores its own
  context in a `context_field`. If the caller passes no context, the record
  opens under the context it stores. If the caller passes one, the stored
  context must equal it.

A `plaintext = T` record requires a `RequiredContext<CallerContext>`, or a
`RequiredContext<AeadContext>` with `context_type = AeadContext`. A record
that stores its context requires the `NonEmpty<T>` it stores. No context is
ever taken from `Default`.

A record gives each field its context through `Encryption::under`
(ADR-0004). `under` requires the field's input to implement
`From<CallerContext>`. That one bound gives a compile error at the field,
when the field's target cannot take a context from the record:

- These inputs implement it: `OptionalContext`, a `RequiredContext` of a
  core context, and the `DeclaredScopes` of a nested record.
- These do not: `NoCallerContext`, and a `RequiredContext` of another type,
  such as `RequiredContext<u64>`.

A record does not take a caller's scope or row binding yet. The plan decides
how it will:

- a record declares each part it accepts, as a scope or a binding;
- the caller passes them as `Scope::new(..)` and `Bind::new(..)`;
- the search terms leave out a binding, so a query still finds the row.

That work is tracked separately. If a record took a caller's row ID before
then, the row ID would also change the search terms. The plan rejects that.

### 4. A record decrypts into a `Protected`

The plaintext type of a `struct` record cannot wipe itself when it is
dropped. The owned form moves the fields out of the struct, and Rust does
not allow that for a type that implements `Drop`.

So the decrypt derive also implements `DecryptSource<Protected<P>>` for each
plaintext type `P` the record names. `Protected::<User>::decrypt_from(..)`
wraps the plaintext as soon as it is recovered. A `Vec` of records decrypts
into a `Vec<Protected<User>>`. `User::decrypt_from(..)` still works, and
returns a bare `User` that the caller must wipe.

A single `Ciphertext` decrypts into a `Protected` too:
`keyset.decrypt::<Protected<String>>(ct)`. Its bound is `Decrypt + Zeroize`,
as for the other stored types. So a target that is not a scalar, such as
`Vec<String>`, compiles, and opening refuses it. A compile error for that
case needs a trait for "a scalar, or a `Protected` of one". Rust allows
that trait to be implemented for both only in Vitamin C, the crate that
defines `FromScalar`.

### 5. The structural traits are a bridge

Each owned derive also implements the structural traits:

- `EncryptTarget` also implements `EncryptFrom` and `Decryptable`.
- `DecryptSource` also implements `DecryptInto` and `DecryptField`.

The core targets implement both pairs by hand. So an owned record can be a
field of a structural record, or a typed field of a plan, with no second
derive. The plan builder gains `target::<T, _>()`, for a target that
implements only the owned traits, such as `Ciphertext`.

The dynamic engine does not change. A test encrypts one record three ways:
with a hand-written `EncryptTarget`, with the derive, and with a data plan.
All three give the same descriptors and the same search term bytes, and each
decrypts the records of the other two.

The plan removes the structural traits, the `encrypt_as` and `decrypt_as`
calls, and the helpers in `target::legacy`. They stay until plans, EQL, Go,
and the guest have moved to the owned API.

### 6. The structural `Vec` decrypts through the wiping path

`Vec<T>: DecryptInto<Vec<P>>` and `DecryptField<Vec<P>, _>` used to decrypt
through `Decryption::all`. If an element failed late, the elements decrypted
before it were dropped without being wiped. They now decrypt through
`all_wiping`, as the owned `Vec` does.

That adds the bound `P: Zeroize` to those public impls. Every value the
engine decrypts into already implements `Zeroize`. A structural caller with
a struct plaintext must derive it.

## Options considered

- **A `Zeroize` bound on the waiting part of `split`.** This would do the
  same job as the `wipe` function. It was rejected because the bound would
  also apply to passthrough fields. Those are stored in the clear, so their
  types have no reason to implement `Zeroize`.
- **A destructure that does not name every field (`..`).** This would let
  the plaintext type implement `Drop`, and so wipe itself. It was rejected
  because a field that the record does not name would then be dropped
  without being wiped. Nothing would report it. Decrypting into a
  `Protected` gives the wipe on drop instead.
- **An optional extension from the caller (`ContextExtension<C>`).** An
  earlier version of this change let the caller extend every field's
  context, for example with a row ID. It was removed after the naming review
  of 8 November 2026. The row ID also changed the search terms, so a query
  had to know the row. The plan replaces it with declared scopes and
  bindings.
- **A second declaration for the structural traits.** It was rejected
  because two declarations of one record could disagree about contexts. The
  equivalence test shows that one declaration, bridged, gives the same bytes
  as a data plan.

## Consequences

- `user.encrypt_into(&keyset)` wipes `name` and `email`, and moves `id`.
  Encrypting a `Vec<User>` into a `Vec<EncryptedUser>` makes one key
  request.
- A record's plaintext must implement `Zeroize`. The bound says who wipes
  the plaintext. It promises nothing about copies the caller keeps, or
  copies the compiler makes. The limits in ADR-0010 still apply.

### What is left to the caller

These are deliberate. Each one is documented where the caller meets it.

- **Decrypting into a bare plaintext.** `User::decrypt_from(..)` returns a
  value that is not wiped when it is dropped. Use
  `Protected::<User>::decrypt_from(..)`.
- **A passthrough field is not encrypted and not authenticated.** Anyone who
  can write to the database can change it, and the encrypted fields beside
  it still decrypt. Do not decide access from it alone.
- **A `context_field` record decrypted with no expected context.** It opens
  under whatever context it stores. A record copied whole, with its stored
  context, opens in its new place. Pass the context you expect, to refuse a
  record from anywhere else.
- **`Encryption::project_owned` drops the other fields of the struct without
  wiping them.** Use it only when the other fields contain nothing secret. A
  record divides its struct with `split` instead.

### What is not done yet

- A caller's scope or row binding, declared on the record. See decision 3.
- The plan's `Planned` value does not yet check a context passed on
  decrypt the way `ExpectedContext` does. `ExpectedContext` is no longer
  documented: the derives still emit it, and a caller passes a
  `NonEmpty<T>` or nothing.
- Configured targets, such as a JSON index with options, cannot be fields of
  an owned record yet. Their plaintext, `serde_json::Value`, does not
  implement `Zeroize`.
- `Option<T>` and tuple targets have only the structural form.
