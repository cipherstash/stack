---
'@cipherstash/stack': patch
---

Fix the Supabase adapter's `.or()` string parser mis-splitting conditions, and pin `contains()` on a mixed union column key to the encrypted operand.

An `.or()` string is only rebuilt from its parse when it references an encrypted column — otherwise the caller's string is forwarded verbatim — so each of these corrupts precisely the mixed encrypted/plaintext case.

**Quotes were tracked only at brace depth 0.** A `}` inside a quoted array element or jsonb string value closed the literal early, and the next `"` re-opened quoting, so the following top-level comma never split: `.or('tags.cs.{"a}b"},email.eq.secret')` parsed as a single condition and silently absorbed `email.eq.secret` into the operand. Quotes are now opaque at every depth.

**A stray `}` or `)` drove the depth counter negative**, after which no comma split again. `}` and `)` are not PostgREST reserved characters, so `a}b` is a valid unquoted operand and `.or('nickname.eq.a}b,id.eq.1')` dropped `id.eq.1`. Depth now floors at zero.

**`in`-list elements were split on every comma, ignoring quotes.** `.or('email.in.("a,b",c)')` parsed as three elements with the quotes still embedded; on an encrypted column each fragment was encrypted as its own term, so the intended element never matched. Elements are now split on top-level commas and unquoted, the inverse of what the rebuild emits.

**A parenthesized operand was read as a list for every operator.** Only `in` and the range operators (`ov`, `sl`, `sr`, `nxr`, `nxl`, `adj`) take a paren-delimited operand; elsewhere `(` is an ordinary character. `email.eq.(foo)` parsed as `['foo']` and encrypted a JS array rather than the string, matching nothing.

**A string operand spelling `null`, `true` or `false` is now quoted.** PostgREST reads a bare `null` as SQL NULL, so `.or([{ column: 'name', op: 'eq', value: 'null' }])` emitted `name.eq.null` and compared against NULL instead of the three-character string.

**`contains(col, …)` where `col` is a union spanning an encrypted and a plaintext column** accepted an array or object operand. The union is now only as permissive as its strictest member: any declared encrypted column in the union pins the operand to `string`. A literal column argument was never affected.
