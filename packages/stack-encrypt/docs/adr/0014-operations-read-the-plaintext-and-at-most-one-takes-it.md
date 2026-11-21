---
status: proposed
date: 2026-11-21
extends: ADR-0012
---

# An operation reads the plaintext by reference, and at most one takes it

## Summary

This ADR proposes how a declaration hands its plaintext to the operations
that encrypt it. It is the design for #1734, which asks that no plaintext
is ever copied.

- An operation that seals a value, or derives a term from it, reads the
  plaintext through a reference. Such an operation is a **reader**.
- An operation that needs the plaintext by value is a **taker**. A
  declaration has at most one, and it runs last, after every reader.
- No implementation turns "take the value" into "clone the value". A
  declaration that would need a second copy of the plaintext does not
  compile. A caller who wants a copy asks for one by name.
- The owned conversion, `encrypt_into`, holds the one value. It lends the
  value to the readers. Then it hands the value to the taker, or wipes it
  when there is none.

The status is `proposed`. Four questions are open, and a prototype answers
them before this is accepted. They are listed at the end.

## Context

### How a declaration receives its plaintext today

An `Encryption<'s, S, T, K, Ctx, M>` describes how a plaintext `S` becomes
an output `T`. Its last parameter is the source mode (`target/source.rs`):

- `Borrowed`, the default. The description is handed `&S`.
  `EncryptTarget::encryption()` describes this form.
- `Owned`. The description is handed `S` by value.
  `EncryptTarget::owned_encryption()` describes this form, and
  `encrypt_into` runs it (ADR-0012).

An operation says how it uses the plaintext through three traits:
`SourceMode::view` reads it in place, `ConsumeSource::take` takes it by
value, and `ShareSource::share` hands it to two operations.

The mode belongs to the whole description. It is not a property of each
operation.

### Three implementations copy the plaintext

1. `ConsumeSource for Borrowed` requires `S: Clone`, and implements `take`
   as `clone`. So an operation that takes the value clones it whenever the
   description is borrowed. Six operations take the value: `ciphertext`,
   `equality`, `ore`, `ope`, `ore_block` and `json_document`. Two only
   read it: `matching` and `json_terms`.
2. `ShareSource for Owned` requires `S: Clone`. `zip` hands a clone to
   every operation but the last.
3. `EncryptTarget::owned_encryption` has a default. It guards the value,
   runs the borrowed description over a reference to it, and wipes it. A
   target that writes only `encryption()` therefore takes the first copy
   on every `encrypt_into`, and nothing in its declaration says so.

The module's documentation gives the reason for this design: "Vitamin C's
`Encrypt` and `PrfValue`, and the order terms, consume the value they are
given, so an operation needs the plaintext by value."

### What the copies cost

Every copy is wiped, so no plaintext is left behind. The cost is that
each copy is one more place the plaintext sits in memory while a value is
sealed, and one more wipe that must be correct.

| What is written | Copies of the plaintext held while it is sealed |
|---|---|
| `TextEq` (`c` and `hm`), from Rust or Go | 3: the value, a clone for `c`, a clone for `hm` |
| `TextMatch` (`c` and `bf`) | 2: the bloom filter only reads |
| A storage-only EQL type (`Integer`, `Text`, …, 11 types) | 2 |
| `JsonTreeDocument`, the storage-only `Json`, a Go `JsonSearch` field | 2 copies of the whole document |

The same defect has been found three times in review, each time in a
different target, because the default in item 3 gives it to every new
target:

- `JsonDocument` copied the document before sealing it (found in the
  review of #1664, fixed there with an owned override).
- `JsonTreeDocument` does the same through two traits (found in the same
  review, to be fixed in #1687).
- The storage-only EQL types, and the Go guest's write path, do the same
  (found while planning that fix).

The `Clone` bound has a second cost. A Vitamin C plaintext type is
deliberately not `Clone`, so Stack Encrypt keeps its own `Date`,
`Timestamp` and `Decimal`, which duplicate Vitamin C's (#1734).

### What has changed

Vitamin C 0.10 is in the tree (#1732). It removes the reason the design
gives:

- `EncryptRef` describes a value to the encryption through a reference.
  `value.lend()` is an `Encrypt` source that reads the value where it is.
  Every type whose reference implements `Encrypt` has it.
- `SchemeVisitor` keys an order scheme from the PRF without copying the
  value.

So sealing a ciphertext no longer has to take the plaintext. Neither does
an equality term or an order term.

### Prior art: axum's extractors

The axum web framework has the same problem with an HTTP request. Many
extractors read the request's head, and the body can be consumed once.
Its answer is in its traits
([the order of extractors](https://docs.rs/axum/0.8.9/axum/extract/index.html#the-order-of-extractors)):

- `FromRequestParts` is given `&mut Parts`. A handler takes any number of
  these.
- `FromRequest` is given the `Request` by value. A handler takes one, as
  its last argument.
- `Handler` is implemented for a function only when every argument but
  the last is `FromRequestParts` and the last is `FromRequest`.
- A blanket implementation makes every `FromRequestParts` type a
  `FromRequest` too, so an extractor that only reads can be last. A
  marker type parameter, which the compiler infers, keeps that
  implementation from overlapping the direct ones.

A handler that reads the body twice, or reads it before another
extractor, does not implement `Handler`. No check runs at run time. The
plaintext is in the position of the request: many operations read it, and
at most one may consume it.

## Decision

### 1. An operation is a reader or a taker

A **reader** is built from `&S`. These are readers:

- sealing a ciphertext, through `EncryptRef`;
- every term: equality, match, and the order terms;
- the JSON index, which walks the document through a reference to seal
  its entries and derive its terms.

A **taker** is built from `S` by value. A taker is for a value that moves
into the output, such as a field stored in the clear, and for a plaintext
type that Vitamin C cannot encrypt through a reference.

A reader can stand where a taker is expected, by the blanket
implementation and marker that axum uses.

### 2. A declaration has any number of readers and at most one taker

One combinator composes the operations over one plaintext. It runs every
reader over a reference to the value. Then it moves the value into the
taker, if there is one.

- Two takers over one value have no implementation, so the declaration
  does not compile.
- The role comes from the operation's type, not from its position. The
  derive cannot use position, because the fields of an EQL type are in
  the order of the stored payload (`c` comes before `hm`). Each field
  type has one role, and the compiler infers it through the marker
  parameter. The derive emits the same call for every field.
- A record that divides its plaintext between its fields (`split`,
  ADR-0012) is unchanged. Each field receives a different part of the
  value. This decision is about several operations over the same value.

### 3. No implementation copies the plaintext

- `ConsumeSource for Borrowed` and `ShareSource for Owned`, the two
  implementations that clone, are removed.
- No public bound in Stack Encrypt or `eql-bindings` requires a plaintext
  to be `Clone`.
- A declaration that needs a second copy says so with a named adapter.
  The copy is then visible where the declaration is written.

### 4. The owned conversion holds the one value

`encrypt_into` guards the value, lends it to the readers, and then hands
it to the taker or wipes it. A refused context wipes it too.

The default owned form of ADR-0012 stays: guard the value, run the
description over a reference, wipe. It no longer copies, because no
operation run over a reference can clone. So a target that writes only
the borrowed form is correct without an owned override.

A declaration with a taker has no borrowed form. It can only be run with
the value.

## What is not claimed

- **An encoding is not a copy in this sense.** Sealing writes the value's
  encoding into a buffer, and `OpaqueBlob` encodes a whole value
  (ADR-0011). Those buffers are part of the work, and are wiped.
- **A decoded frame is a second value.** The dynamic interface decodes a
  `ValueFrame` into a typed value before it runs a target. This decision
  does not remove that step. It stops the further copy that follows it.
- **The stored format does not change.** Every operation derives the
  bytes it derives today.

## Options considered

- **Keep two modes, and give each copying target an owned override.**
  This is what #1664 and #1687 do. Each override is correct, and nothing
  stops the next target from inheriting the copy. Rejected as the end
  state. The overrides stay valid under this decision.
- **Owned only: every operation takes the value.** A value with a
  ciphertext and a term then needs a clone for all but one of them, which
  is the `Clone` bound again. Rejected.
- **Readers only, with no taker.** Simpler, and enough for every sealed
  field. A field stored in the clear moves into the output, and a
  plaintext type with no by-reference encoding needs the value. Rejected,
  because it would bring the copy back for those two cases.
- **Readers, and at most one taker, checked by the compiler.** Chosen.

## Consequences

- A write holds one copy of the plaintext: the caller's. A `TextEq`
  write drops from three, and a document is no longer copied.
- Stack Encrypt's `Date`, `Timestamp` and `Decimal` can be removed, and an
  order index can be bounded by Vitamin C's `Orderable` (#1734).
- It is a breaking change to the published crate. The operations'
  bounds change from `Encrypt + Clone` to `EncryptRef`, two public trait
  implementations are removed, and a hand-written `EncryptTarget` that
  relied on a clone must be rewritten.
- Fewer wipes need to be right. The heap hygiene tests stay, and one new
  test shows that a value with a ciphertext and several terms is not
  copied.
- The owned overrides added in #1664 and #1687 are no longer needed for
  correctness. They can stay or be removed.
- A wrong declaration fails as "the trait is not implemented". axum has
  the same weakness, and ships a macro to explain it. The traits need
  `#[diagnostic::on_unimplemented]` messages that say what went wrong.

## To confirm with a prototype

1. **Role inference through the derive.** Does the marker parameter
   resolve for a generic field type, and for a field of several terms
   such as `Encrypted<(EqualityTerm, MatchTerms)>`?
2. **Readable errors.** What does the compiler print for two takers, and
   for a taker in a declaration that is only lent the value?
3. **Every operation as a reader.** Do `equality`, the order terms and
   the JSON index derive the same bytes from a reference? Which plaintext
   types have no `EncryptRef`, and so need the taker?
4. **The dynamic interface.** Does the record path, which reads a
   `ValueFrame`, fit the same two roles?
