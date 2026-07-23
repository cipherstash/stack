---
name: stash-indexing
description: Create and verify PostgreSQL indexes on EQL v3 encrypted columns — functional-index recipes over the term extractors (eql_v3.eq_term, ord_term, ord_term_ore, match_term, to_ste_vec_query) mapped to the types.* domains, what works without superuser on Supabase and managed Postgres versus the ORE opclass restriction, which domains have no index option, the ORDER BY / GROUP BY query shapes that engage an index, building indexes on large tables, and the EXPLAIN verification checklist. Use when creating or reviewing a schema migration that adds an encrypted column, adding an index to an encrypted column, diagnosing a slow encrypted query or an EXPLAIN plan showing Seq Scan, or answering whether encrypted columns can be indexed on Supabase or managed PostgreSQL.
---

# Indexing Encrypted Columns (EQL v3)

Encrypted columns **can** be indexed, and on any non-trivial table they **should** be. The model is one rule, uniform across every encrypted domain: **index a functional expression over the column's term extractor — never an operator class on the column itself.** The extractors are inlinable SQL functions, so bare-form predicates (`WHERE col = $1`, `WHERE col < $1`, `col @@ $1`) engage the index with no query rewriting.

This covers EQL v3 — the bundle `stash eql install` applies (`@cipherstash/eql`). An integration that is otherwise correct (encrypted at rest, searchable, exact round-trip) but has no index on its encrypted predicates will sequential-scan every encrypted query; that is the default outcome unless you put these indexes in place — the integrations emit query operators, not index DDL (see [Where the Index DDL Goes](#where-the-index-ddl-goes)).

## When to Use This Skill

- Writing or reviewing a schema migration that adds or changes an encrypted (`eql_v3_*`) column.
- Deciding which indexes an encrypted column supports — or explaining why a column has none.
- An encrypted query is slow, or `EXPLAIN` shows a `Seq Scan` where you expected an index.
- `stash db validate` reports "No indexes on an encrypted column".
- Answering whether encrypted columns can be indexed on Supabase or managed PostgreSQL (yes — see the superuser section).

## Which Columns Support Which Index

Capability is fixed by the column's domain type, chosen at schema definition via the `types.*` factories. `T` ranges over `Integer`, `Smallint`, `Bigint`, `Date`, `Timestamp`, `Numeric`, `Text`, `Real`, `Double`; `<t>` is the lowercase SQL name (`eql_v3_integer_eq`, `eql_v3_text_ord`, …).

| Schema factory | Postgres domain | Terms carried | Index recipes |
|---|---|---|---|
| `types.TEq` | `public.eql_v3_<t>_eq` | `hm` | equality (`eq_term`) |
| `types.TOrd` | `public.eql_v3_<t>_ord` | `op` | **one** ordering index (`ord_term`) — serves equality, range, and `ORDER BY` |
| `types.TOrdOre` | `public.eql_v3_<t>_ord_ore` | `ob` | **one** ORE ordering index (`ord_term_ore`) — equality + range; superuser installs only |
| `types.TextMatch` | `public.eql_v3_text_match` | `bf` | free-text match (`match_term`) |
| `types.TextSearch` | `public.eql_v3_text_search` | `hm`, `op`, `bf` | equality + ordering/range + match (three indexes) |
| `types.Json` | `public.eql_v3_json_search` | `sv` (ste_vec) | containment GIN + field-level ordering |
| `types.T` (bare), `types.Boolean` | `public.eql_v3_<t>` | none | **none — storage-only by design** |

Note the `_ord` rows: those domains have **no `eq_term` overload at all** — `eql_v3.eq` on them inlines to an ordering-term comparison (`ord_term(a) = ord_term(b)`), so the single ordering btree is the index that serves `=` as well. Do not add an `eq_term` index to an `_ord` / `_ord_ore` column.

The last row is deliberate, not a gap: a bare `types.Text` / `types.Integer` / `types.Boolean` column carries no query terms, so there is nothing to index and nothing to query server-side. If a column needs an index, it needs a term-carrying domain first.

## The Recipes

Every recipe is a functional index over the extractor, followed by `ANALYZE` (see [Making a Query Engage the Index](#making-a-query-engage-the-index) for why `ANALYZE` is mandatory). Name indexes descriptively (`users_email_eq`, `events_at_ord`) — it makes `EXPLAIN` output and maintenance legible.

### Equality — `eql_v3.eq_term`

For the domains carrying `hm`: `_eq` and `text_search`. (On `_ord` / `_ord_ore` columns, equality rides the ordering index below — there is no `eq_term` overload for those domains.)

```sql
CREATE INDEX users_email_eq ON users USING btree (eql_v3.eq_term(encrypted_email));
ANALYZE users;

SELECT * FROM users WHERE encrypted_email = $1;
-- Index Scan using users_email_eq
--   Index Cond: (eql_v3.eq_term(encrypted_email) = eql_v3.eq_term($1))
```

`btree` is the safe default: it serves `=` exactly as well as `hash` with no query-side cost, and its build scales (see [Building Indexes at Scale](#building-indexes-at-scale)). `USING hash` is fine for small and mid-size tables, but a hash index *build* degrades badly past a few million rows.

### Ordering and Range — `eql_v3.ord_term`

For the OPE-backed ordering domains: `_ord` and `text_search`.

```sql
CREATE INDEX events_at_ord ON events USING btree (eql_v3.ord_term(encrypted_at));
ANALYZE events;

SELECT * FROM events WHERE encrypted_at < $1;
```

`eql_v3.ord_term` returns a `bytea`-backed domain, so this btree binds PostgreSQL's **default** `bytea_ops` operator class — nothing to install, no privilege required, works on Supabase and managed Postgres. The `<` `<=` `>` `>=` operators inline to comparisons on the extractor, so natural-form range predicates match the index — and on `_ord` columns so does `=`, since equality on those domains also inlines to `ord_term`. One index, every scalar predicate. (`ORDER BY` needs the extractor form — see [Query-Shape Traps](#query-shape-traps).)

### ORE Ordering — `eql_v3.ord_term_ore` (superuser installs only)

For the `_ord_ore` domains only:

```sql
CREATE INDEX events_at_ord_ore ON events USING btree (eql_v3.ord_term_ore(encrypted_at));
```

This one depends on an operator class the EQL installer can only create as **superuser**. On non-superuser installs it has a *silent* failure mode — read [Supabase and Managed Postgres](#supabase-and-managed-postgres-what-actually-needs-superuser) before using it. Prefer `types.TOrd` unless you specifically need ORE ordering on a self-hosted, superuser-installed database.

### Free-Text Match — `eql_v3.match_term`

For the bloom-filter domains: `text_match` and `text_search`. Engages the `@@` match operator:

```sql
CREATE INDEX users_name_match ON users USING gin (eql_v3.match_term(encrypted_name));
ANALYZE users;

SELECT * FROM users WHERE encrypted_name @@ $1;
-- Bitmap Index Scan on users_name_match
```

### JSON Containment — `eql_v3.to_ste_vec_query`

For `public.eql_v3_json_search` (`types.Json`) document containment (`@>`):

```sql
CREATE INDEX orders_data_gin
  ON orders USING gin (eql_v3.to_ste_vec_query(data_encrypted)::jsonb jsonb_path_ops);
ANALYZE orders;

SELECT * FROM orders WHERE data_encrypted @> $1::eql_v3.query_json;
-- Bitmap Index Scan on orders_data_gin
```

The needle must be typed — `$1::eql_v3.query_json` or another `public.eql_v3_json_search` value. A bare untyped literal falls through to native `jsonb @>` and skips the index. Note `jsonb_path_ops` indexes `@>` only, not `<@`.

### Field-Level Ordering Inside Encrypted JSON

For ordered access to a single field of a `types.Json` document, index the ordering extractor over the path:

```sql
CREATE INDEX orders_total_ord
  ON orders USING btree (eql_v3.ord_term(data_encrypted -> '<selector>'::text));

SELECT * FROM orders ORDER BY eql_v3.ord_term(data_encrypted -> '<selector>'::text) LIMIT 10;
```

- `<selector>` is the deterministic selector hash the encryption client emits (each `sv` element's `s` field) — **not** a plaintext JSONPath. Obtain it via the client's selector query encoding (see `stash-encryption` on JSONPath selectors).
- The `->` operand must be typed (`::text`); a bare literal falls through to native `jsonb ->`.
- The extracted term is `bytea`-backed like top-level `ord_term` — default btree opclass, no superuser.
- Entry-to-entry `=` / `<>` and exact `GROUP BY` / `DISTINCT` on extracted fields are **not supported** (an extracted entry carries no value selector). Use document containment with the GIN index above for exact field equality.

## Supabase and Managed Postgres: What Actually Needs Superuser

**Only one thing on this page needs superuser: the ORE operator class behind `_ord_ore`.** Everything else — equality btree/hash, `_ord`/`text_search` ordering btree, match GIN, JSON containment GIN, field-level ordering — installs and engages with a plain non-superuser role. Do not generalize the ORE warning into "encrypted columns can't be indexed on Supabase"; the default ordering path (`_ord`, via CLLW-OPE) binds Postgres's native `bytea` btree operator class and needs nothing installed.

The `_ord_ore` restriction, precisely: its btree ordering depends on a hand-written operator class created by the EQL installer, and `CREATE OPERATOR CLASS` requires superuser. On platforms whose installer role is not superuser (cloud-hosted Supabase, most managed Postgres), the installer detects this and **disables the `_ord_ore` domains** — using one raises `feature_not_supported` with a hint naming the alternatives.

**The silent-failure mode to check for:** if an `_ord_ore` column somehow exists without the opclass, `CREATE INDEX … USING btree (eql_v3.ord_term_ore(col))` does **not** fail — PostgreSQL binds the generic `record_ops` instead. The index builds, occupies space, and never engages. Verify which opclass an ORE index actually bound:

```sql
SELECT i.relname, oc.opcname
  FROM pg_index x
  JOIN pg_class i    ON i.oid = x.indexrelid
  JOIN pg_opclass oc ON oc.oid = x.indclass[0]
 WHERE i.relname = 'events_at_ord_ore';
-- ore_block_256_operator_class  → ORE ordering, index engages
-- record_ops                    → opclass was skipped at install; index is inert
```

`_ord` has no such failure mode.

## Making a Query Engage the Index

Functional-index engagement is **structural**: the planner inlines the operator into the same extractor expression the index was built on and matches the expression trees syntactically. All three of these must hold:

1. **The value must carry the term the index extracts.** `eq_term` needs `hm`, `ord_term` needs `op`, `ord_term_ore` needs `ob`, `match_term` needs `bf`, containment needs the ste_vec. The domain rows in the table above tell you which terms a column's values carry; a value with only a bloom term will never drive an equality index.
2. **The index must be created after the data carries the term.** If you change which terms a column's values carry (e.g. re-encrypt under a different domain), recreate the index — a functional index built before the term existed will not match.
3. **The query operand must be typed** so the encrypted operator resolves, not the native `jsonb` one. A typed parameter (`$1`) or an explicit cast to the domain works; a bare `::jsonb` literal falls through to native jsonb semantics and skips the index. The Drizzle, Prisma Next, and Supabase integrations emit correctly-typed operands already — this requirement only bites hand-written SQL.

And after **every** index build: **run `ANALYZE`**. `CREATE INDEX` on an expression gathers no statistics for that expression, so until `ANALYZE` runs the planner has no histogram for `eql_v3.eq_term(col)` and can misjudge — or ignore — the index it just built.

## Query-Shape Traps

**The `ORDER BY` sort-key trap.** The planner inlines operators in *predicates*, not *sort keys*: `ORDER BY col` adds a `Sort` node even when the ordering index exists and the `WHERE` clause is using it. To stream rows out of the index already ordered, write the sort key in extractor form:

```sql
SELECT * FROM events
  WHERE encrypted_at < $1
  ORDER BY eql_v3.ord_term(encrypted_at) DESC
  LIMIT 10;
```

The natural-form Top-N sort scales linearly with the rows passing `WHERE`; at scale that is the difference between seconds and milliseconds. The Drizzle integration's `asc`/`desc` already emit `ORDER BY eql_v3.ord_term(col)` for you.

**The `value::jsonb` projection trap.** `SELECT col::jsonb … ORDER BY col` folds the cast into the scan and sorts on `(col)::jsonb` — which matches no index. Project the column raw, wrap the ordered query in a subquery and cast outside the `LIMIT`, or sidestep it entirely with `ORDER BY eql_v3.ord_term(col)`.

**`GROUP BY` / `DISTINCT` on the extractor, not the raw column.** `GROUP BY col` hashes the entire encrypted payload (1–2 KB per row); the estimated hash table blows past `work_mem`, so the planner falls back to `GroupAggregate` — sorting kilobyte rows and spilling to disk. Group on the term instead:

```sql
SELECT eql_v3.eq_term(encrypted_email), count(*)
  FROM users
  GROUP BY eql_v3.eq_term(encrypted_email);
```

The term is small and deterministic, so `HashAggregate` fits in `work_mem` with no tuning. If an ORM insists on grouping the raw column, raising `work_mem` is the rescue knob — but the extractor form is the design.

## Building Indexes at Scale

Query performance and *build* performance are separate axes; on large encrypted tables the build is the one that bites.

- **Raise `maintenance_work_mem` for the build session** — the single highest-leverage knob. The 64 MB default spills a multi-million-row build to disk early:

  ```sql
  SET maintenance_work_mem = '2GB';
  CREATE INDEX ...;
  ANALYZE ...;
  ```

- **Prefer `btree` over `hash` for equality at scale.** Build characteristics differ sharply:

  | Access method | Build | Scales past cache? | Parallel build? |
  |---|---|---|---|
  | btree | sort, then sequential bulk-load | yes | yes |
  | GIN | batched buffer build | yes | no |
  | hash | random bucket fill | **no** | no |

  A hash build scatters rows to random buckets; once the index outgrows cache it goes random-I/O-bound (a 10M-row hash build has been observed to stall after 17 hours; the btree equivalent built without drama). A btree on `eql_v3.eq_term(col)` serves `=` identically.

- **The de-TOAST floor.** A functional index build de-TOASTs the whole stored value once per row to evaluate the extractor — for large `eql_v3_json_search` documents this sets an unavoidable floor on build rate, identical across access methods. Run large builds on fast native storage (containerized Postgres on a virtualized filesystem — e.g. Docker Desktop on macOS — is the worst case).

- **Diagnose a slow build** from a second session:

  ```sql
  SELECT phase, tuples_done, tuples_total,
         round(100.0 * tuples_done / nullif(tuples_total, 0), 1) AS pct
  FROM pg_stat_progress_create_index;
  ```

  A steady `tuples_done` rate is healthy; a rate that decays over time is the cache/memory wall — raise `maintenance_work_mem`, and if it's a hash index, rebuild as btree.

## Verifying with EXPLAIN

The first move on any slow encrypted query is `EXPLAIN (COSTS OFF)`:

- ✓ `Index Scan using <your-index>` — the functional index is engaged.
- ✓ `Bitmap Index Scan on <your-index>` — same, for set-style predicates (`@@`, `@>`).
- ✓ `Index Cond:` referencing the extractor (`eql_v3.eq_term(…)`, `eql_v3.ord_term(…)`) — the inlined predicate matched.
- ✗ `Seq Scan` — no index used; work through [Troubleshooting](#troubleshooting).
- ✗ `Filter:` showing the raw operator (`col < '…'`) — inlining did not happen. Usual causes: a pinned `search_path` on a customized extractor function, a `plpgsql` body where a `sql` one is expected, or the planner genuinely judging another plan cheaper.
- ✗ A `Sort` node above an Index Scan — natural-form `ORDER BY`; switch the sort key to the extractor form.

Once the plan shape is right, `EXPLAIN ANALYZE` for actual timings.

## Troubleshooting

Index not being used:

1. **Verify the value carries the term:**

   ```sql
   SELECT encrypted_email::jsonb ? 'hm' AS has_hmac,
          encrypted_email::jsonb ? 'ob' AS has_ore_block,
          encrypted_email::jsonb ? 'bf' AS has_bloom
   FROM users LIMIT 1;
   ```

2. **Verify the operand is typed** (`$1` or `$1::public.eql_v3_text_eq` — not `$1::jsonb`).
3. **Recreate the index** if the column's term composition changed after it was built.
4. **Run `ANALYZE`.** Also note: on very small tables a `Seq Scan` is the *correct* plan — don't chase it below a few thousand rows.

**`=` returns zero rows**: equality needs the domain's equality-serving term — `hm` on `_eq` / `text_search`, the ordering term (`op` / `ob`) on `_ord` / `_ord_ore`. A bare storage-only domain has neither; confirm the column's domain and that the client is emitting the term.

**ORE index never engages:** run the `pg_opclass` query from the [superuser section](#supabase-and-managed-postgres-what-actually-needs-superuser) — a `record_ops` binding means the index is inert.

## Where the Index DDL Goes

**The integrations emit the query operators for you — none applies index DDL on its own. Making sure these indexes exist is always your job.** This skill is the general model — recipes, engagement rules, verification. How to apply it in a specific integration lives in that integration's skill:

- **Drizzle** — `encryptedIndexes(t)` from `@cipherstash/stack-drizzle/v3` derives the recommended indexes for every encrypted column in the table, or declare individual expression indexes in the schema DSL. See `stash-drizzle` § Indexing Encrypted Columns.
- **Prisma Next** — Prisma's schema language cannot express functional indexes; the DDL goes in a migration in the adapter's flow. See `stash-prisma-next`.
- **Supabase** — a `supabase/migrations/` file; no superuser needed (see above). See `stash-supabase`.
- **Raw SQL / plain PostgreSQL** — the recipes in this skill, in whatever migration tool owns the schema. Never ad-hoc in production.

## When to Create Indexes During an Encryption Rollout

- **Fresh encrypted column (new table or new field):** ship the `CREATE INDEX` in the **same migration** that adds the column. Every value written carries its terms from day one, so the index is correct from the first row.
- **Encrypting an existing column** (the `stash encrypt` lifecycle): create the indexes **after `stash encrypt backfill` completes and before switching reads** to the encrypted column. Building after backfill is one bulk pass instead of per-row index maintenance across the whole backfill, and the reads you cut over to engage an index from the first query. Remember `ANALYZE` after the build. See `stash-encryption` § "Rolling Encryption Out to Production" for the full lifecycle.

## Reference

- `stash-encryption` — the `types.*` domain catalog, wire-format operators and ordering, and the rollout/cutover lifecycle.
- `stash-cli` — `stash eql install`, `stash db validate` (its "No indexes on an encrypted column" Info finding is resolved by this skill), `stash encrypt backfill` / `cutover`.
- `stash-drizzle`, `stash-supabase`, `stash-prisma-next` — per-integration query patterns; index DDL placement per the section above.
