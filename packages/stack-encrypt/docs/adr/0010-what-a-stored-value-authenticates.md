---
status: accepted
date: 2026-10-18
amended: 2026-11-23
extends: vitaminc ADR 0002
---

# What a stored value authenticates

Automated reviews of Stack Encrypt keep reporting the same properties as
vulnerabilities. They are deliberate. This ADR says what a value Stack
Encrypt stores does and does not authenticate, so a reviewer can check a
finding against it. The sealing itself is vitaminc's, and the underlying
decision is vitaminc's ADR 0002 ("Leaves are authenticated; a container's
membership and order are not"). This applies it to what Stack Encrypt
stores.

## Decision

**Authenticated**, for every sealed leaf (`"c"`, and each leaf inside a
nested value): its bytes and type tag, the context it was sealed under
(including any extension parts and a record's context field), its map key
or its role as a sequence element, and the wire version. A leaf that opens
was sealed exactly so, under exactly that context.

**Not authenticated, by design:**

- **A container's membership, order and length.** Which entries a stored
  map holds, and a stored sequence's order, length and duplicates. A
  sequence of records is a set of rows, which a database returns in any
  order and in part. A record's fields are a row's columns, which a query
  selects in part.
- **A passthrough field.** It is stored in the clear so the record stays
  whole, and comes back exactly as the store holds it. Anyone who can write
  to the store can change it. The exception is a plan's context field: it
  is stored as a passthrough, but every other field was sealed under it, so
  a changed context field fails the expected-context check or leaves the
  sealed fields unable to open.
- **Which row a leaf belongs to**, unless the context names the row. Two
  leaves sealed under the same column context are interchangeable between
  rows. A caller who needs a value bound to its row puts the row's identity
  (or a tenant) in the context.

### The JSON index (`json_tree`)

A JSON index document is one sealed entry per node, and it authenticates
more than a container does. Each entry's ciphertext binds, beside its
context, the node's path selector, the slot it is stored at, and a digest
of its children's AEAD tags in their order (amended 2026-10-26, the
cascade). A node's tag therefore commits to every ciphertext beneath it:
the client opens the rows beneath the node a read names only if they are
exactly the ones sealed there, each under its parent and in its place,
however the database orders them. A row swapped, dropped, added,
reordered or moved under another parent is `Error::Aead`. The stored
order of the entries is random and carries no meaning, and the search
fields beside the ciphertexts (selectors, the projection, the self and
parent tags, the ordering terms) are not authenticated, like every
search term.

Three things stay outside it, by design, as they were before the cascade:

- **Another row's entry.** An entry returned with its own row's header
  opens, as any leaf sealed under the column context does (the row rule
  above).
- **Another element's node at the top of a read.** Every element of an
  array shares a selector, and the node a read names is checked by its
  selector and label alone, since nothing above it is read. So
  `$.items[0].price` opens in answer to a read of `$.items[1].price`.
  Beneath that node the cascade rules the substitution out.
- **Withheld rows.** Nothing says how many nodes a read should find, so a
  read the database answers with fewer whole subtrees, or none, opens to
  what it returned.

## Consequences

- **A typed open separates a failed leaf from a refused shape.** A leaf
  that does not open (wrong key, wrong context, altered bytes) is
  `Error::Aead`. A value whose every leaf opened but whose type or shape the
  target refuses, including a container missing a field the target needs,
  is a shape mismatch: `Error::OpenedType`, not `Aead`. The Go guest maps
  them to `STATUS_AUTH` and `STATUS_ENCODING`. One case cannot be
  separated before the open: a JSON index entry returned by `->` that does
  not open alone is either a container with children, whose ciphertext is
  sealed over children `->` does not return, or an altered entry, and
  nothing outside the ciphertext says which. That is `Error::JsonNotALeaf`,
  which names both causes and claims neither, and maps to
  `STATUS_ENCODING`.
- **Review findings of these kinds are not defects.** `AGENTS.md` lists
  them under "Review guidelines", and `.github/copilot-instructions.md`
  repeats them. A finding that a *leaf* is not bound to its context, key,
  role, type or version is still a defect.
- **Stricter authentication is opt-in, by type.** A caller who needs a
  sequence's positions or a record's field set authenticated will ask for it
  by naming a type that carries that rule, the way `serde_bytes` selects a
  different encoding by type (vitaminc ADR 0002). It is not a default and
  not a flag, and it does not exist yet.

## Amended 2026-11-23 (ADR-0016)

[ADR-0016](0016-a-context-is-a-field-path-and-named-parts.md) names the
parts of a context and lets a part be added after encryption. This changes
what "the context it was sealed under" covers.

**Authenticated by the leaf, as before:** the field path, and every
partition and label that was present at encryption. Each part is bound as
its wire name and its value. A leaf that opens was sealed under exactly
those parts. A label's stored copy, such as a row ID in a passthrough
field, is still not authenticated by itself: a changed copy leaves the
leaf unable to open.

**Authenticated by the key tag, and not by the leaf:** a part added by a
refinement. The key provider replays the chain of refinements before it
returns a key. The leaf's AAD does not change when a value is refined.

**Not authenticated, by design:**

- **A label refinement against rollback.** A label refinement is a local
  step that anyone who can write the row can compute. Someone who holds an
  older tag can write it back and drop a later label, or copy the value to
  another row and add that row's ID. A label that must resist this is set
  at encryption.
- **Which row a leaf belongs to**, unless a label names the row. This is
  the row rule above, in the new words: the label is `RecordId`.

A policy refinement is different. Only the key provider can produce its
step, and the provider refuses a chain that has been rolled back.

A finding that a label refinement can be undone by a writer is not a
defect. A finding that a part present at encryption is not bound to the
leaf is one.
