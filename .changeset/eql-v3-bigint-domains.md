---
'@cipherstash/stack': minor
---

Add the EQL v3 bigint domain family to the public DSL: `types.Bigint`,
`types.BigintEq`, `types.BigintOrdOre`, and `types.BigintOrd`, backed by the
`public.bigint*` concrete domains. Plaintext is a JS `bigint`, round-tripped
losslessly across the protect-ffi 0.28 boundary (i64 bounds enforced at the
FFI — out-of-range values surface as encryption errors). Index emission follows
the numeric rule: `bigint_eq` → unique (hm); `bigint_ord`/`bigint_ord_ore` →
ore (equality answered via ob).
