---
'@cipherstash/stack': patch
---

Fix reading a nested EQL v2 DynamoDB attribute that was stored under a grouped
field.

A v2 grouped column registered its build key on the BARE LEAF, so a field inside
a group was written as `<group>.<leaf>__source` while the schema knew it only as
`<leaf>`. The v3 rewrite made attribute matching exact-dotted-path only, for both
generations, which orphaned every such attribute: it read back as raw base64
inside a `{ data }` success, with only a debug-level log — invisible at the
default log level. Silent wrong data on the one path that exists for backward
compatibility.

The bare-leaf fallback is restored for `{ storedEqlVersion: 2 }` reads only.
It stays off for v3, where full dotted paths are registered precisely so a
nested leaf cannot collide with a same-named top-level column — matching by
bare leaf there rewrote a plaintext sibling as an envelope and handed it to the
FFI as a decrypt target. Writes are EQL v3-only and stay strict.

If you carried a v2 grouped column forward as a top-level v3 column, you can
also declare it by its dotted path with the original DB name —
`'details.amount': types.TextEq('amount')` — which reproduces the v2 identifier
exactly.
