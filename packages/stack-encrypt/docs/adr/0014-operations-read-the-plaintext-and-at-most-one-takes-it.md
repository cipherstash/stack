---
status: accepted
date: 2026-11-21
revised: 2026-11-22
extends: ADR-0012
---

# An operation reads the plaintext by reference, and at most one takes it

## Summary

This ADR decides how a declaration hands its plaintext to the operations
that encrypt it. It is the design for #1734, which asks that no plaintext
is ever copied.

- An operation that seals a value, or derives a term from it, reads the
  plaintext through a reference. Such an operation is a **reader**.
- An operation whose output is the plaintext itself is a **taker**.
  `passthrough` is the only one.
- A declaration has any number of readers and at most one operation that
  is handed the value. The compiler checks this through the position of
  each operation in `zip`.
- No implementation copies a plaintext that is sealed or indexed. A
  plaintext type does not need `Clone`.
- The owned conversion, `encrypt_into`, holds the one value. Whichever
  operation is handed it wipes it, or moves it into the output.
- An order index is bounded by Vitamin C's `Orderable`. Stack Encrypt's
  `Date`, `Timestamp` and `Decimal`, and its two order traits, are
  removed.

**Revised on 22 November 2026.** The first version proposed that the
compiler infer each operation's role from its type, through a marker
parameter, as the axum web framework does. #1737 was written at the same
time and reaches the same rule a simpler way, by position. This revision
adopts that mechanism, and settles each point where the two disagreed.
[What changed in this revision](#what-changed-in-this-revision) lists
them. Dan accepted the revision on 22 November 2026.

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
   description is borrowed. Seven operations take the value:
   `ciphertext`, `equality`, `ore`, `ope`, `ore_block`, `json_document`
   and `passthrough`. Two only read it: `matching` and `json_terms`.
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
| A storage-only EQL type (`Integer`, `Text`, …: 10 types besides `Json`) | 2 |
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

Position does the work in axum. The last argument is the one taker, so
the compiler never has to choose which argument that is.

## Decision

### 1. An operation is a reader or a taker

A **reader** reads the plaintext through a reference. These are readers:

- sealing a ciphertext, through `EncryptRef`;
- the equality term, through `EncryptRef`;
- the match term, which reads the text as a `&str`;
- the order terms. `SchemeVisitor` keys the scheme without the value,
  and Vitamin C's `Orderable` is implemented for a reference to each
  type it orders;
- the JSON index, which walks the document through a reference to seal
  its entries and derive its terms;
- a query's value, and the checks made on it before a key is requested.
  This covers a typed query (`op`), a term the dynamic interface derives
  (`dynamic/term.rs`), and the query targets of `eql-bindings`.

A reader can also be handed the value itself. It then reads the value
where it is, and wipes it when it is done. It never needs a second copy.

A **taker** is an operation whose output is the plaintext.
`passthrough` is the only taker. Its value is stored in the clear.

A plaintext that is sealed or indexed is `Encrypt + EncryptRef`. Vitamin
C's own types and its derive provide both. A type with only a by-value
`Encrypt` adds `impl Encrypt for &T`. The first version kept the taker
for such a type. That is withdrawn: every plaintext has the same bound,
in both source modes.

### 2. A declaration has any number of readers, and one operation is handed the value

The source mode of ADR-0012 stays. A `Borrowed` description is handed
`&S`, and an `Owned` description is handed `S`.

`first.zip(second)` composes two operations over one plaintext:

- `second` is always a `Borrowed` description. It reads the plaintext
  through a reference, and it runs first.
- `first` is then handed what it would be handed alone: the same borrow
  in a `Borrowed` description, or the value in an `Owned` one.
- The output is `(first, second)`, in the order written.

So in an owned description, only the operation written first is handed
the value. Every other operation reads a borrow. An owned description is
not accepted as the argument of `zip`, because its mode is a different
type. Two operations that both take the value therefore do not compile.

- **The role comes from position, and nothing is inferred.** The derive
  emits the same chain for every type: the first field's operation,
  zipped with the rest.
- **The stored order does not limit this.** The first version rejected
  position because the fields of an EQL type are in the order of the
  stored payload (`c` comes before `hm`). `zip` runs its argument first
  and still returns the outputs in the order written, so the order of
  the payload and the order of running are separate.
- **Why not infer the role.** The first version made every reader a
  taker through a blanket implementation, and took the role from the
  operation's type. A declaration of two readers then matches more than
  one implementation, and the compiler asks for a type annotation. The
  review of the first version reports that a prototype of `TextEq`'s
  shape (`c` and `hm`) fails this way. axum does not have the problem,
  because position fixes its one taker.
- A record that divides its plaintext between its fields (`split`,
  ADR-0012) is unchanged. Each field receives a different part of the
  value. This decision is about several operations over the same value.

### 3. No implementation copies a plaintext that is sealed or indexed

- `ShareSource` is removed. `zip` lends the value.
- `ConsumeSource` stays, for `passthrough` alone. No other operation
  asks for it. The public `Index` trait's `operation` is bounded by
  `SourceMode`, where it was `ConsumeSource`. (Amended below: by
  `WipeSource`.)
- **A borrowed `passthrough` still copies its value, so that value is
  `Clone`.** This is ADR-0012's rule for a field stored in the clear,
  and it stands. The value is not sealed, so the copy is not a copy of a
  secret. The first version removed this implementation, and said a
  declaration with a taker has no borrowed form. That would take the
  required `EncryptTarget::encryption()` away from every record with a
  passthrough field, and with it borrowed runs, borrowed parents, and
  the borrowed `Vec` and `Option` forms. It is withdrawn.
- The copy happens only when a caller runs a whole record from a borrow,
  to keep the plaintext: `keyset.run(EncryptedUser::encryption(), &user,
  ..)`. An owned run (`encrypt_into`, a `Vec` or an `Option` of records,
  a nested record) moves a passthrough field into the output. Without
  the borrowed form, a caller who needs the plaintext afterwards would
  clone the whole value, its secrets included.
- No other public bound in Stack Encrypt or `eql-bindings` requires a
  plaintext to be `Clone`. `ValueFrame` and `JsonPlaintext` are not
  `Clone`.
- There is no adapter that copies a plaintext by name. The first version
  proposed one. Nothing needs it, and #1734 asks for no copies.

### 4. Whoever is handed the value wipes it

- `encrypt_into` guards the value with `Protected` while it builds the
  declaration and the context. Either step can panic. The owned
  description then takes over the value.
- The default owned form of ADR-0012 stays: guard the value, run the
  borrowed description over a reference, wipe. It no longer copies,
  because a borrowed reader does not clone. So a target that writes only
  the borrowed form is correct without an owned override, and every
  declaration has both forms.
- An owned description wipes the value on every path:
  - after it is read: Vitamin C wipes a value that is walked by value,
    and a term's scheme does the same;
  - when the context is refused, or an operation fails;
  - when the stack unwinds, through the `Protected` guard.
- **A gap on `next` is closed.** The public `ciphertext` operation in
  `Owned` mode drops a refused value without wiping it, because its `S`
  need not be `Zeroize`. A match term that is handed an owned value
  drops it as it is. The targets and the derive of this crate avoid both
  with their own wiping forms, but a caller who composes the public
  operations does not get them. An operation that seals or indexes in
  `Owned` mode now requires `S: Zeroize`, and wipes the value when the
  context is refused and when it has only read it. A JSON document keeps
  its own guard (`PlainJson`). How the bound is written is left to the
  implementation.

### 5. An order index is bounded by Vitamin C's `Orderable`

- Stack Encrypt's `value::Date`, `value::Timestamp` and `value::Decimal`
  are removed. They existed only to be `Clone`. Callers use Vitamin C's
  types, which `stack_encrypt::value` re-exports.
- An order index, an order term's target and an ordering operator are
  bounded by vitaminc-ore's `Orderable`. Stack Encrypt's `sem::Orderable`
  and `op::Ordered` are removed.
- Vitamin C's `Orderable` covers the types `op::Ordered` lists today: the
  integers of 16 bits and wider, `f32`, `f64`, `String`, and Vitamin C's
  date, timestamp and decimal. It covers a reference to each. It does
  not cover bytes or an 8-bit integer.
- **So an order index on bytes does not compile, with no trait of Stack
  Encrypt's own.** That is the typed half of #1611. On `next`,
  `sem::Orderable` covers `Vec<u8>` and `op::Ordered` does not, and #1611
  moves each bound from the first to the second. With both traits gone
  there is one list, and it is Vitamin C's.
- **Stack Encrypt no longer derives an order term from bytes.** On
  `next` the keyset's term functions (`ore_term`, `ope_term` and
  `ore_block_term`) take a `Vec<u8>`, because `sem::Orderable` covers
  it. That goes with the trait. No ordering operator compares bytes, so
  such a term answers no query and still reveals the order of the rows.
  Vitamin C orders bytes only into a target that is named
  (`scheme.target(Bytes)`), and Stack Encrypt does not offer that
  target. A stored row that carries a bytes order term still opens:
  #1611 reads it without naming the term.

## What is not claimed

- **An encoding is not a copy in this sense.** Sealing writes the value's
  encoding into a buffer, and `OpaqueBlob` encodes a whole value
  (ADR-0011). Those buffers are part of the work, and are wiped.
- **A decoded frame is a second value.** The dynamic interface decodes
  the caller's frame into one owned `ValueFrame` for each field before it
  runs a target. This decision does not remove that step. It stops the
  further copy that follows it: each field's value is read in place and
  wiped once, and a passthrough field's value is moved into the output.
- **A passthrough value can be copied.** It is stored in the clear, and a
  borrowed description copies it (decision 3).
- **The stored format does not change.** Every operation derives the
  bytes it derives today. The frozen vectors, the stored-row fixtures
  and the conformance corpus pass unchanged.

## Options considered

- **Keep two modes, and give each copying target an owned override.**
  This is what #1664 and #1687 do. Each override is correct, and nothing
  stops the next target from inheriting the copy. Rejected as the end
  state. The overrides stay valid under this decision.
- **Owned only: every operation takes the value.** A value with a
  ciphertext and a term then needs a clone for all but one of them, which
  is the `Clone` bound again. Rejected.
- **Readers only, with no taker.** Simpler, and enough for every sealed
  field. A field stored in the clear moves into the output. Rejected,
  because an owned record would then copy every passthrough field.
- **Infer each operation's role from its type, through a marker
  parameter.** The first version of this ADR. Rejected: it is ambiguous
  for two readers (decision 2), and position needs no inference.
- **Remove the borrowed `passthrough`.** It would leave no `Clone` bound
  at all. Rejected: it breaks the borrowed form of every record with a
  field stored in the clear (decision 3).
- **Readers by reference, and one operation handed the value, by
  position.** Chosen.

## Consequences

- **A typed Rust write holds one copy of the plaintext: the caller's
  value, moved in.** A `TextEq` write drops from three, and a document
  is no longer copied.
- **A write through the dynamic interface, which the Go SDK uses, holds
  the decoded frame of each field and no further copy.** It dropped one
  clone for each sealed or indexed field.
- It is a breaking change to the published crates:
  - a sealed or indexed plaintext is bounded by `Encrypt + EncryptRef`,
    where it was `Encrypt + Clone`. A plaintext with only a by-value
    `Encrypt` adds `impl Encrypt for &T`;
  - `zip` takes a borrowed description as its argument, and runs it
    first;
  - `ShareSource`, `Clone for ValueFrame` and `Clone for JsonPlaintext`
    are removed, and `Index::operation` has a new bound;
  - `Date`, `Timestamp` and `Decimal` are Vitamin C's. They are built
    from jiff's and rust_decimal's values, and none is `Clone`. The
    `jiff` and `rust_decimal` features are on by default, and a build
    with `default-features = false` names them to get the three types;
  - `sem::Orderable` and `op::Ordered` are removed, and the keyset's
    order term functions no longer take bytes;
  - an operation in `Owned` mode requires `S: Zeroize` (decision 4).
- The Go guest links jiff and rust_decimal in its plain build. Its size
  is measured before #1737 merges.
- Fewer wipes need to be right. The heap hygiene tests stay. One test
  asserts that a value with a ciphertext and several terms is not
  cloned, and one counts a single wipe for it.
- The owned overrides added in #1664 and #1687 are no longer needed for
  correctness. They can stay or be removed.
- A taker written as the argument of `zip` is refused as a mismatch of
  the source mode, not with a message of our own. The documentation of
  `zip` says which operation is handed the value.
- "Reader" and "taker" are defined in `packages/stack-encrypt/CONTEXT.md`.

## How the work lands

Three pull requests touch the same code. They land in this order:

1. **#1737** does items 1, 2 and 3 of #1734: every operation reads in
   place, and Vitamin C's `Date`, `Timestamp` and `Decimal` replace
   Stack Encrypt's. It is rebased onto `next`, which now has the typed
   JSON queries. It also takes on decision 4's wipe rule, the test that
   counts one wipe, and the measurement of the Go guest.
2. **The order bound** (item 4 of #1734, decision 5) removes
   `sem::Orderable` and `op::Ordered`, and with them the order term of
   bytes and its term-level tests. It goes in #1737 or in a pull request
   stacked on it.
3. **#1611** is rebased on top. Its commits that move each bound from
   `sem::Orderable` to `op::Ordered` are dropped, because the bound in
   step 2 replaces them. It keeps what only it has: a data plan refuses
   an order index on bytes, the Go generator refuses the tag, the
   conformance corpus and its documents follow, an old row with a bytes
   order term still opens, and the compile-fail tests, recorded again
   with Vitamin C's message.

## What changed in this revision

| Point | First version | Now | Why |
|---|---|---|---|
| How the one taker is checked | The role is inferred from each operation's type, through a marker | Position in `zip`: the first operation is handed the value | Inference is ambiguous for two readers. Position needs none, and `zip` keeps the written order |
| What a taker is | `passthrough`, and a plaintext with no by-reference encoding | `passthrough` alone | Every sealed or indexed plaintext is `Encrypt + EncryptRef` |
| Borrowed `passthrough` | Removed: a declaration with a taker has no borrowed form | Kept, with `Clone` on a value stored in the clear | Removing it breaks ADR-0012's borrowed forms |
| A named adapter that copies | Proposed | Dropped | Nothing needs it |
| Wiping an owned value | Stated, with no mechanism | The operation handed the value wipes it on every path, and `Owned` mode requires `Zeroize` | The public operations dropped a refused value unwiped |
| Queries and their checks | Not covered | Readers | #1734 names them, and they kept `Clone` |
| The dynamic interface | "A write holds one copy" | One decoded frame for each field, and no further copy | The first claim was true of the typed path only |
| `Date`, `Timestamp`, `Decimal`, and the order traits | "Can be removed" | Removed, and the order bound is Vitamin C's | #1734 asks for it, and it gives #1611 its typed refusal |
| An order term of bytes | Not covered | Removed | No operator compares bytes, and Vitamin C's bound does not cover them |

## The questions the first version left for a prototype

#1737 answers them in code.

1. **Role inference through the derive.** Not needed. The derive emits
   one chain, and position decides.
2. **Readable errors.** Two takers are a mismatch of the source mode at
   `zip`. A plaintext with no `EncryptRef` is refused by the bound, with
   the message of the `plaintext_needs_encrypt` compile-fail test.
3. **Every operation as a reader.** Each one reads a borrow in #1737:
   the ciphertext, the equality term, the order terms and the JSON
   index. #1737 reports that the frozen vectors and the conformance
   corpus pass unchanged. No plaintext type of Stack Encrypt lacks
   `EncryptRef`.
4. **The dynamic interface.** It fits. A data plan's sealed and indexed
   fields read their `ValueFrame` in place, and a passthrough field's
   value is moved into the output.

## Amended 2026-11-22 (#1737)

Decision 4 left the form of the `Zeroize` bound to the implementation.
#1737 writes it as a third mode trait, `WipeSource`.

- `Borrowed` implements it for every plaintext. `Owned` implements it for
  a plaintext that is `Zeroize`. So the bound applies in `Owned` mode
  only, as decision 4 says. A borrowed `&str` is still sealed.
- Every operation that seals or indexes is bounded by it: `ciphertext`,
  `equality`, `matching`, the three order terms, and `indexed`. So are
  `Index::operation` and `Indexes::operations`. Decision 3 named
  `SourceMode` for `Index::operation`. That bound is now `WipeSource`.
- The JSON operations keep `SourceMode`. A document has its own guard
  (`PlainJson`). `serde_json::Value` is not `Zeroize`. A JSON index
  run in `Owned` mode calls `json_terms` directly, and not through
  `Index`.
- A typed query hands its value to the index by value, so a query value
  is `Zeroize`.
- #1737 also lands decision 5. The typed path has no order term of bytes.
  A data plan can still declare an order index on bytes until #1611 refuses
  it. Until then the dynamic path derives that term by naming the `Bytes`
  target. So the stored rows and the conformance corpus do not change in
  #1737.
