---
'@cipherstash/stack-drizzle': minor
---

New `encryptedIndexes` helper on the `/v3` entry: spread
`...encryptedIndexes(t)` in `pgTable`'s third-argument callback and it derives
the recommended functional indexes for every encrypted column in the table —
named `<table>_<column>_<capability>`, tracked by `drizzle-kit generate` like
any other index. The mapping comes from the same per-domain capability record
the operator layer gates on, so the emitted indexes and the operators that
engage them cannot drift: equality → btree on `eql_v3.eq_term`, ordering →
btree on `eql_v3.ord_term` (on the numeric/date/timestamp `_ord` domains one
index serves `=` and range — their injective ordering term answers equality
and no `eq_term` overload exists; the non-injective `text_ord` / `text_ord_ore`
also carry `hm` and get an `eq_term` index alongside), ORE ordering →
`eql_v3.ord_term_ore`, free-text →
GIN on `eql_v3.match_term`, encrypted JSON → GIN on
`(eql_v3.to_ste_vec_query(col)::jsonb) jsonb_path_ops`. Storage-only and
non-encrypted columns emit nothing. Closes the #753 gap where integrations
emitted query operators but no index DDL, so encrypted predicates
sequential-scanned by default.

Also fixed: `isEqlV3Column` / `getEqlV3Column` no longer blow the stack when
handed a column from `pgTable`'s extras callback — drizzle-orm ≤0.45's
`ExtraConfigColumn.getSQLType()` recurses into itself, so the domain is now
recovered from the column's custom-type params instead of calling it.
