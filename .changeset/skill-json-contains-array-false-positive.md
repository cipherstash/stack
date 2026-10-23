---
"stash": patch
---

The `stash-drizzle` and `stash-encryption` skills no longer describe EQL v3 JSON
containment (`contains` on a `types.Json` column) as exact with no false
positives. Containment follows jsonb `@>` semantics for objects and scalars, but
for an array of objects a needle's fields can match across different elements
of the array, so the query can return extra rows (#1231). The skills now say so,
and tell the reader to re-check the decrypted rows when an exact match on an
object inside an array matters.
