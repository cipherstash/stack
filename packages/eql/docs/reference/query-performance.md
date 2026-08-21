# Writing fast queries against EQL columns

> **This page has moved.** Query and index performance for `eql_v3` encrypted columns is now covered in **[Database Indexes for Encrypted Columns](./database-indexes.md)**, alongside the index recipes themselves.

Getting EQL-encrypted queries competitive with plain PostgreSQL comes down to one pattern: **index a functional expression over the term extractor, and let bare-form predicates engage it.** The details — and the traps — live in the database-indexes guide:

- [Creating indexes](./database-indexes.md#creating-indexes) — the `eql_v3.eq_term` / `ord_term` / `match_term` recipes (no operator class on a column).
- [How index engagement works](./database-indexes.md#how-index-engagement-works) — extractor inlining and structural matching.
- [Range queries and the `ORDER BY` sort-key trap](./database-indexes.md#range-queries-and-order-by) — write `ORDER BY` against the column's ordering extractor (`eql_v3.ord_term(col)` on `_ord`) to avoid a Sort node.
- [`GROUP BY` / `DISTINCT`](./database-indexes.md#group-by--distinct) — group on the column's extractor, not the raw column, to stay inside `work_mem` (`eql_v3.eq_term(col)` on `hm`-carrying domains; `eql_v3.ord_term(col)` on the numeric-and-time ordering domains, which have no `eq_term`).
- [GIN indexes for JSONB containment](./database-indexes.md#gin-indexes-for-jsonb-containment) — `public.eql_v3_json_search` document search.
- [Building indexes on large tables](./database-indexes.md#performance-building-indexes-on-large-tables) — `maintenance_work_mem`, btree-vs-hash build scaling, the de-TOAST floor.
- [Diagnosing queries with `EXPLAIN`](./database-indexes.md#diagnosing-queries-with-explain).

For which operators each domain variant supports, see the [SQL support matrix](./sql-support.md).

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20query-performance.md)
