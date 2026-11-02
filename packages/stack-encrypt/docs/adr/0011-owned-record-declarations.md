---
status: accepted
date: 2026-11-03
extends: ADR-0003, ADR-0004
---

# Records declare themselves as owned targets, and the structural pair becomes a bridge

The owned API (`EncryptInto`, `DecryptFrom`, over `EncryptTarget` /
`DecryptSource` with explicit `ContextInput` capabilities) covered one
opaque scalar and then a column of them, while every record — the derives,
the plan builder's typed fields, the dynamic lowering — still spoke the
structural pair, `EncryptFrom` / `DecryptInto`, over a borrowed plaintext
with a `Default`-driven context. A user writing the mixed record the public
examples show (`id` in the clear, `name` and `email` sealed) had no derive
that consumed and wiped the plaintext, no way to say "carry this field
through", and no promise that the record's fields and the scalar API agreed
on anything but luck.

## Decision

### 1. One trait, two forms of the description

`EncryptTarget<S>` keeps `encryption()`, the description over `&S`, and
gains `owned_encryption()`, the description over `S` by value, in
`Owned` source mode. The default `owned_encryption` guards the value in
`Protected`, runs the borrowed description over it and wipes it before the
pending request is returned — exactly what `EncryptInto` did for a scalar
by hand — so a declaration that only composes operations implements nothing
new. `EncryptInto` now runs `owned_encryption`, and the collection
declaration runs each element's.

The signature map the plan asked for:

| Declaration | Over | Handed | Cleanup |
|---|---|---|---|
| `encryption()` | borrowed `&S` | `Encryption<'s, S, T, K, Input>` | the caller's, or the owner guarding the borrow |
| `owned_encryption()` | `S` by value | `Encryption<'s, S, T, K, Input, Owned>` | the declaration's: default guard-and-wipe |
| `decryption(self, Input)` | the stored value | `Decryption<P, K>` | the engine's until return, then the caller's |

### 2. A record divides its plaintext between its fields

A `#[derive(EncryptTarget)]` `struct = User` record composes the field
targets directly. Its borrowed form projects each field out of the borrow
(`Encryption::project`). Its owned form divides the struct with a chain of
`Encryption::split` calls, a new `Owned`-mode combinator that hands two
different parts of one value to two descriptions under one context: a
`#[stash(passthrough)]` field is moved into the record by
`passthrough::<_, _, Owned, _>()` and never copied, and each sealed field
runs its own target's `owned_encryption`, so a `String` field is guarded
and wiped by the `Ciphertext` target that seals it. The divider is a plain
function pointer that destructures the struct: it captures nothing, so like
`project`'s selector it cannot reach a cipher, and it only moves. That is
the accepted plaintext-ownership rule made mechanical: the conversion wipes
what it seals and transfers what the caller chose to keep in the clear.

A passthrough field is not encrypted and not authenticated (ADR-0010). It
is `Clone` because the borrowed form, which a plan or a structural record
runs, has to copy it; the owned form never does, and a test with a `Clone`
that panics holds it to that.

### 3. Caller context is a capability, composed through the tree

Two inputs join `NoCallerContext`, `RequiredContext<C>` and
`OptionalContext<C>`:

- `ContextExtension<C>`: omission keeps the declared contexts; a supplied
  part extends each of them. What a `struct` record takes, both ways.
- `ExpectedContext<T>` (the existing type, now a `ContextInput`): omission
  opens under the stored context; a supplied `NonEmpty<T>` also checks it.
  What a `context_field` record takes to open.

A `plaintext = T` record takes `RequiredContext<CallerContext>` (or of
`AeadContext` with `context_type`), and `RequiredContext<NonEmpty<T>>` when
it stores its context. The core leaves take the same wrappers around the
context their operation needs, so a term is an `EncryptTarget` alone, and
nothing is inferred from `Default`.

A record field is handed its pair extended by the caller's part through
`Encryption::under` (ADR-0004), which asks the field's input to be
`From<CallerContext>`. That one bound is the field-specific diagnostic: an
`OptionalContext`, a `RequiredContext` of a core context and a nested
record's `ContextExtension` satisfy it; a `NoCallerContext` target or a
`RequiredContext<u64>` target does not, and the error is reported at the
field. A `plaintext` record's fields are handed the one context the record
requires, so a term beside an `AeadContext`-only record is refused at the
term, and omitting a required context is refused at the call.

### 4. The structural pair is a bridge, not a second declaration

Both owned derives also emit the structural declarations: `EncryptTarget`
emits `EncryptFrom` (the record's legacy context converted into its owned
input at the root) and `Decryptable`; `DecryptSource` emits `DecryptInto`
and `DecryptField`. The core leaves implement both pairs by hand. So an
owned record is a field of a structural record and a typed plan field
without a second derive, and the plan builder gains `target::<T, _>()` for
a target that declares itself the owned way alone (`Ciphertext`). The
dynamic lowering is untouched: the equivalence test seals one record
through a hand-written `EncryptTarget`, the derive and the data plan,
against one recording provider, and finds the same descriptors, the same
term bytes and every author opening every author's record. The structural
derives stay, for the plans and the dynamic engine that still speak them;
their removal is a later decision, once every consumer has an owned
equivalent.

### 5. The structural `Vec` opens through the wiping path

`Vec<T>: DecryptInto<Vec<P>>` and `DecryptField<Vec<P>, _>` opened through
`Decryption::all`, which dropped the elements recovered before a late
failure as they were. They now open through `all_wiping`, as the owned
column does, which puts `P: Zeroize` on those public impls: every plaintext
the engine opens into carries it, and a structural caller with a struct
plaintext derives it.

## Consequences

- `user.encrypt_into(&keyset)` on a `struct` record wipes `name` and
  `email` and moves `id`; `Vec<User>` into `Vec<SearchableUser>` is one
  key request; `User::decrypt_from(record, &cipher)` moves `id` back.
- A record's plaintext is `Zeroize`. The bound is where the wiping
  obligation is declared, not a promise about caller-retained copies or
  compiler temporaries (ADR-0010's limits stand).
- Configured targets (a JSON index with options) are not yet owned-record
  fields: the one configurable target's plaintext, `serde_json::Value`, is
  not `Zeroize`, so it cannot be an owned source. The attribute for a
  typed options factory waits on a zeroizing document plaintext.
- `Option<T>` and tuple targets remain structural-only in this slice.
