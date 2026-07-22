---
'@cipherstash/prisma-next': minor
---

Route v3 decoding from the EQL payload's own identifier, so encrypted columns
decode on paths that carry no column context.

Every EQL v3 payload carries a required `i` identifier (`{"t": "<table>", "c":
"<column>"}`), and ZeroKMS commits the cell's key to it — a payload relocated to
a different column cannot decrypt. That makes the identifier the authoritative
routing source, and it travels with the value rather than with the query.

The v3 cell codec previously took its `(table, column)` routing key only from the
SQL runtime's projected-column context, which meant two paths failed even though
the value knew exactly where it came from:

- **Relation `include()`** — the ORM decodes cells nested in a `json_agg` /
  `json_build_object` document through `decodeJson`, whose framework signature
  passes only the JSON value, with no column ref. This previously threw
  `decodeJson is not supported; envelopes do not round-trip through JSON`.
  Included encrypted columns now decode into ordinary envelopes that
  `decryptAll` batches alongside top-level ones.
- **Aggregates and computed projections** — the runtime resolves no column ref
  and deliberately passes `column: undefined`, so `decode` threw. It now routes
  from the payload.

`decode` reads the payload identifier first and falls back to the projected-column
context for a value carrying no usable identifier (a non-v3 or malformed
document), so existing well-routed reads are unaffected. `encodeJson` is
unchanged: it still renders the opaque `$encrypted*` marker, and is deliberately
not the inverse of `decodeJson` — the two serve different planes.
