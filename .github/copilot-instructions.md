# Copilot instructions for cipherstash/stack

The project instructions are in `AGENTS.md`. When reviewing a pull request,
follow its "Review guidelines", in particular these known non-findings,
which are deliberate design decisions and not defects:

- A sealed container's membership, order and length are not authenticated:
  which entries a stored map holds, and a stored sequence's order, length
  and duplicates, are not bound into any AAD, because stored values are
  database rows and columns that come back in any order and in part. A
  target that refuses a container's shape is a shape mismatch
  (`Error::OpenedType`), not tampering (`Error::Aead`).
- A passthrough field is stored in the clear and is not authenticated,
  except a plan's context field, which every other field is sealed under.
- Two leaves sealed under the same context are interchangeable between rows;
  binding a value to its row is the caller's choice of context.

A leaf that is not bound to its context, map key, role (single value or
sequence element), type tag or wire version is still a defect. See
`packages/stack-encrypt/docs/adr/0010-what-a-stored-value-authenticates.md`.
