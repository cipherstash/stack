---
status: accepted
date: 2026-10-18
---

# Leaves are authenticated; a container's membership and order are not

Automated reviews of vitaminc and of Stack Encrypt keep reporting the same
thing as a vulnerability: a sealed map does not authenticate which entries
it holds, and a sealed sequence does not authenticate its elements'
positions or its length. That is a deliberate decision, recorded here so a
reviewer can check a finding against it.

## Context

vitaminc seals a structured value leaf by leaf (ADR 0001). Each scalar is
sealed on its own, under an AAD derived from the caller's context and the
leaf's place in the value (`vitaminc-context`):

| Place | AAD | What it binds |
| --- | --- | --- |
| A single value | the caller's context | the context |
| A map entry's value | `for_map_entry(key)`: `PAE(domain, context, key)` | the context and the entry's key |
| A sequence element | `for_sequence_element()`: `PAE(domain, context, "element")` | the context, and that the leaf is an element, not a single value |
| An empty map or sequence | `for_empty_map()` / `for_empty_sequence()` | that the container was empty |
| `Some(x)` | `for_option_some()` | that the value was present |
| Every leaf, finally | `for_leaf(version)` | the wire-format version byte |

A leaf's plaintext also carries its type tag (`[tag] ++ payload`), so the tag
is under the AEAD too. Map keys travel in the clear and are bound by the
derivation above. Nested containers derive these contexts recursively.

The question is what the whole of a sealed container should authenticate:
just each leaf in its place, or also the set of entries and the order and
number of elements.

## Decision

**Each leaf is authenticated in its place. A container's membership, order
and length are not.**

What a reader can rely on, for every leaf it opens:

- the leaf's bytes and type tag are as they were sealed;
- it was sealed under this context, for this map key, as a sequence element
  or as a single value (not one moved into the other), and under this wire
  version;
- an empty-container marker or a `Some` marker is the structural fact it
  claims.

What is **not** authenticated:

- which entries a map holds. An entry can be missing, or a decrypt can be
  handed a map with some entries removed, and every remaining leaf still
  opens;
- a sequence's order, length or duplicates. Elements can come back in any
  order, as a subset, or repeated;
- anything across separate values or rows. Two leaves sealed under the same
  context and key are interchangeable; a caller who needs a leaf bound to its
  row puts the row's identity in the context.

## Why

vitaminc's main consumer, Stack Encrypt, stores values in databases. There, a
sealed container is not one document read back whole:

- **A sequence of records is a set of rows.** Encrypting a vector of structs
  is the same as inserting rows into a table. The database returns them in
  any order, and a query returns some of them, rarely all together.
  Authenticating position or length would make every ordinary query fail.
- **A record's fields are a row's columns.** A `SELECT` names some columns,
  almost never all of them. Authenticating a map's membership would make
  every partial read fail.

Per-leaf binding still gives the guarantees that matter for that model: a
value cannot be altered, given another type, moved to another field (the key
is bound), moved between a single value and a sequence element, or opened
under another context.

## Consequences

- **A reader that needs every field, or a fixed order, checks it itself.** A
  decrypt target that requires a field reports it missing; that is a shape
  mismatch, not a failed authentication. Stack Encrypt reports it as
  `Error::OpenedType` and keeps `Error::Aead` for a leaf that fails to open.
- **Review findings of this kind are not defects.** A finding that a map's
  membership, or a sequence's order, length or duplicates, is not
  authenticated describes this decision. The repositories' review guidance
  (`AGENTS.md`, `.github/copilot-instructions.md`) says so. A finding that a
  *leaf* is not bound to its context, key, role, type or version is still a
  defect.
- **Changing this is a wire-format change.** Binding an index, a length or a
  key set into the AAD changes every sealed container's bytes.

## Stricter authentication is opt-in, by type

Some uses do need a container authenticated as a whole: a tuple or a
positional record, where the position is the meaning, or a document always
read back in one piece. That will be something a caller asks for explicitly,
by choosing a type that carries the stricter rule, not a default and not a
runtime flag.

The model is serde's: the same Rust value can be encoded differently by
naming a different type for it, as `serde_bytes` encodes a `Vec<u8>` as
bytes rather than a sequence of integers (`serde_bytes::ByteBuf`, or
`#[serde(with = "serde_bytes")]`). Here a named wrapper type, or a derive
attribute on a struct, would select a sealing that binds each element's
index and the sequence's length, or a commitment over a struct's field set.
The default stays the database model above, so an ordinary value never
carries an obligation its reads cannot meet, and a caller who opts in states
it where it is visible: in the type.

None of these types exists yet. Designing them, including what a partial
read of a strictly sealed value means, is future work.

## Alternatives considered

- **Bind each element's index and the sequence's length into its AAD,
  always.** Detects reordering and truncation, and breaks every database
  read that returns rows in another order or in part. Rejected as the
  default; the basis of the opt-in for positional values.
- **Commit to a map's key set (for example, a sealed marker over the sorted
  keys).** Detects a missing or added entry, and breaks every partial
  `SELECT`. Rejected as the default; the basis of the opt-in for whole
  records.
- **A runtime flag on the encrypt and decrypt calls.** Easy to set on one
  side and forget on the other, and invisible in the type that is stored.
  Rejected: vitaminc prefers types that make the intended use the easy one.
