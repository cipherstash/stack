---
'@cipherstash/stack': patch
---

Re-vendor the EQL v3 SQL bundle and align the v3 DSL to it: encrypted type domains now live in the `public` schema (`public.text`, `public.integer`, …) rather than `eql_v3`, and the boolean domain is `public.boolean` (was `eql_v3.bool`). The `eql_v3` schema now holds only the operator-backing functions, and the index-term constructors (`hmac_256`, `ore_block_256`, `bloom_filter`) moved to `eql_v3_internal`. This keeps the SDK's emitted domain names byte-matched to the installed bundle so `CREATE TABLE`/cast resolution succeeds.
