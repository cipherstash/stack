---
'@cipherstash/stack': minor
---

Fix encrypted `in`-list operands in the Supabase adapter, and widen the `is` /
`contains` type surfaces.

**`in()` on an encrypted column produced a request PostgREST rejects.** Every
encrypted operand is a serialized envelope, dense with `"` and `,`. postgrest-js
wraps a comma-bearing element as `"…"` but never escapes the quotes already
inside it, so `.in('email', […])` emitted

```
in.("{"v":1,"c":"…"}",…)
       ^ PostgREST ends the value here → PGRST100
```

Encrypted lists are now emitted through `filter(col, 'in', …)` with each element
quoted and escaped, matching what the `.or()` path already did. This affects
**v2 as well as v3** — v2's `("a@b.com")` composite literal is itself
quote-bearing and was equally broken.

**`not(col, 'in', […])` encrypted the whole list as a single ciphertext**, so
the filter silently matched nothing, and emitted an unparenthesized
`not.in.a,b`. Each element is now encrypted separately and the operand is
rendered as `not.in.(…)`. Passing a PostgREST list literal (`'(a,b)'`) for an
encrypted column now throws instead of silently matching nothing — pass an
array.

**`is(col, null)` is now allowed on every column**, including storage-only
encrypted ones (`types.Boolean`, `types.Integer`, …). `is` is never encrypted
and a NULL plaintext is stored as a SQL NULL, so `IS NULL` is not merely legal
there but the only predicate those columns support. `is(col, true)` remains a
compile error on encrypted columns.

**`contains()` accepts native operands on plaintext array and jsonb columns.** A
plaintext jsonb/array column falls through to PostgREST's native containment, so
`contains('tags', ['vip'])` and `contains('meta', { plan: 'pro' })` now
typecheck. A plaintext SCALAR column does not: `@>` is undefined on `text`, so
the operand type follows the column's own shape and a scalar rejects every
containment operand. Encrypted match columns still take a `string` token.
Relatedly, `.or([{ op: 'contains' }])` now emits PostgREST's `cs` operator for
plaintext columns too — previously only encrypted conditions were translated, so
a plaintext containment reached the wire as `.contains.` and failed to parse.

**Direct `contains()` / `not(col, 'contains', …)` now serialize their operand.**
postgrest-js builds an array operand as `cs.{a,b}` with no element quoting, so
`contains('tags', ['with,comma'])` reached Postgres as two elements; and its
`not()` stringifies the operand outright, emitting `not.contains.with,comma`
(no braces, and the wrong operator token) or `[object Object]` for a jsonb
operand. Both paths now build the containment literal the `.or()` path already
built, and emit the `cs` token.

**`.or()` no longer drops a condition after an unbalanced brace or paren.** A
scalar operand containing `{` left the parser's depth counter stranded above
zero, so no later comma separated a condition and everything behind it was
swallowed into that operand. With a plaintext column first, the group was then
forwarded verbatim — running the swallowed condition against a ciphertext column
with a plaintext operand. Braces are now quoted on emit (they are structural to
PostgREST inside `or=(…)`), and the parser falls back to quote-only splitting
when its depth tracking does not balance.

**`is(col, true)` is now rejected on every encrypted column, not just the
storage-only ones.** The boolean form was gated on the filterable keys, which
exclude storage-only columns but keep queryable encrypted ones — so
`is(emailTextSearchColumn, true)` compiled and emitted `IS TRUE` against a jsonb
ciphertext.

**In-list operands encrypt in one crossing per column.** The element-wise `in` /
`not.in` encoding above spent one ZeroKMS round-trip per element; terms are now
grouped by column and each group takes a single `bulkEncrypt` call, matching the
Drizzle v3 path. Falls back to per-term encryption for clients without
`bulkEncrypt`, and rejects a bulk response whose length does not match the list
rather than silently truncating the predicate.
