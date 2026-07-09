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

**`contains()` accepts native operands on plaintext columns.** A plaintext
jsonb/array column falls through to PostgREST's native containment, so
`contains('tags', ['vip'])` and `contains('meta', { plan: 'pro' })` now
typecheck. Encrypted match columns still take a `string` token. Relatedly,
`.or([{ op: 'contains' }])` now emits PostgREST's `cs` operator for plaintext
columns too — previously only encrypted conditions were translated, so a
plaintext containment reached the wire as `.contains.` and failed to parse.
