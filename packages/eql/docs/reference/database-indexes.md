# Database Indexes for Encrypted Columns

EQL supports PostgreSQL indexes on encrypted columns to make queries competitive with plain-PostgreSQL workloads. This guide covers how to create them, how they engage, and how to keep both queries *and* index builds fast at scale.

The model is simple and uniform across every encrypted-domain type: **index a functional expression over the term extractor**, never an operator class on the column. The extractor returns a small per-row term whose return type already carries a default operator class, and the extractors are inlinable — so bare-form queries (`WHERE col = $1`, `ORDER BY col`) engage the index without any query rewriting.

## Table of Contents

- [Creating Indexes](#creating-indexes)
- [How Index Engagement Works](#how-index-engagement-works)
- [Index Usage Requirements](#index-usage-requirements)
- [Query Patterns That Use Indexes](#query-patterns-that-use-indexes)
- [GIN Indexes for JSONB Containment](#gin-indexes-for-jsonb-containment)
- [Best Practices](#best-practices)
- [Performance: Building Indexes on Large Tables](#performance-building-indexes-on-large-tables)
- [Diagnosing Queries with EXPLAIN](#diagnosing-queries-with-explain)
- [Troubleshooting](#troubleshooting)

---

## Creating Indexes

Each capability has one canonical functional-index recipe. Type the column as the domain variant that carries the term (see [SQL support matrix](./sql-support.md)), then index the matching extractor:

```sql
-- Equality (hash index on the eq_term extractor) — the hm-carrying domains:
-- public.<T>_eq / text_ord / text_ord_ope / text_ord_ore / text_search / text_search_ore
CREATE INDEX users_email_eq
  ON users USING hash (eql_v3.eq_term(encrypted_email));

-- Ordering / range (btree index on the ord_term extractor) — public.<T>_ord / _ord_ope
CREATE INDEX events_at_ord
  ON events USING btree (eql_v3.ord_term(encrypted_at));

-- Text match (bloom-filter fuzzy match `@@` — GIN on the match_term extractor) — public.eql_v3_text_match / text_search / text_search_ore
CREATE INDEX users_name_match
  ON users USING gin (eql_v3.match_term(encrypted_name));

ANALYZE users;
```

> **No operator class on a column or domain.** `eql_v3` deliberately does **not** ship an `encrypted_operator_class`. Operators resolve against the domain's `jsonb` base type, so an opclass on the column would bypass the encrypted surface. Always index through the extractor. (This also means no superuser is required to *query* — functional indexes work on Supabase and managed PostgreSQL.)

> **ORE requires an *install* privilege; OPE does not.** The `ord_term` btree recipe above needs nothing installed: the default `_ord` domains order via CLLW-OPE, and `eql_v3.ord_term` returns a `bytea`-backed type whose *native* btree operator class the planner already has. The block-ORE domains (`_ord_ore`, `text_search_ore`) instead depend on the operator class the installer creates for the ORE term type — and `CREATE OPERATOR CLASS` is superuser-gated in stock PostgreSQL. Whether a managed platform allows it is per-platform, not a blanket rule: AWS RDS and Aurora PostgreSQL allow it for the master user, while cloud-hosted Supabase, Cloud SQL, and Azure Flexible Server refuse it (see [Install privileges](./permissions.md#install-privileges) for the details and sources). Where the install role can't create the opclass, the installer detects this and **disables the ORE-carrying domains** (`_ord_ore`, `text_search_ore`, and their `eql_v3.query_*` twins): using one raises `feature_not_supported` with a `HINT` naming the alternatives (see [U-003](../upgrading/v3.0.md#u-003-non-superuser-installs-disable-the-ore-backed-domains)). Where the opclass installed, index an `_ord_ore` column through its own extractor:
>
> ```sql
> CREATE INDEX events_at_ord_ore ON events USING btree (eql_v3.ord_term_ore(encrypted_at));
> ```

> **Equality on the ordering domains splits on term injectivity.** The numeric-and-time ordering terms (OPE and ORE alike) are **injective** — distinct plaintexts produce distinct terms — so equality can ride the ordering term: those `_ord` / `_ord_ope` / `_ord_ore` domains carry no `hm`, there is **no `eq_term` overload** for them, and `eql_v3.eq` inlines to an ordering-term comparison (`ord_term(a) = ord_term(b)`). One ordering btree serves `=`, range, and `ORDER BY` — do not create an `eq_term` index on a numeric `_ord` column; the overload does not exist. Text ordering terms are **non-injective** and cannot be relied on for equality, so the text ordering domains (`text_ord`, `text_ord_ope`, `text_ord_ore`, and the `text_search` variants) also carry `hm` and answer `=` via `eq_term` — give those columns an equality index alongside the ordering one.

### When to Create Indexes

Create indexes on encrypted columns when:

- The table has a significant number of rows (typically > 1000).
- You frequently query the column by the matching operator.
- The column is typed as a variant that carries the required term (`_eq` for equality, `_ord` for range/ordering, `text_match` for bloom fuzzy match `@@`). On the numeric-and-time `_ord` domains the ordering variant serves `=` too — no `_eq` twin needed; see the injectivity note above.

---

## How Index Engagement Works

The extractors (`eql_v3.eq_term`, `eql_v3.ord_term`, `eql_v3.ord_term_ore`, `eql_v3.match_term`) are inlinable `LANGUAGE sql` functions — a single `SELECT`, `IMMUTABLE`, no pinned `search_path`. PostgreSQL inlines them at planning time, so a bare-form predicate is rewritten into the same expression as the index and matches it structurally:

```sql
SELECT * FROM users WHERE encrypted_email = $1;
-- planner inlines `=` to: eql_v3.eq_term(encrypted_email) = eql_v3.eq_term($1)
-- Index Cond on USING hash (eql_v3.eq_term(encrypted_email))
```

The match is **syntactic on the expression tree**: the predicate's extractor call must be the same function and argument shape as the index's defining expression. The planner does not reason about semantic equivalence, which is why `ORDER BY` needs special care (see [Range and ORDER BY](#range-queries-and-order-by) below) and why pinning `search_path` on an extractor would silently disable inlining and revert queries to sequential scans.

---

## Index Usage Requirements

For PostgreSQL to use a functional index on an encrypted column, **all** of these must hold:

### 1. The value must carry the required term

Capability travels in the payload, chosen by the encryption client and reflected in the column's domain variant:

- **Equality** needs the domain's equality-serving term. On the `hm`-carrying domains (`public.<T>_eq`, `public.eql_v3_text_ord`, `public.eql_v3_text_ord_ope`, `public.eql_v3_text_ord_ore`, `public.eql_v3_text_search`, `public.eql_v3_text_search_ore`) that is `hm` (hmac_256), driven through `eql_v3.eq_term`. On the numeric-and-time `_ord` / `_ord_ope` / `_ord_ore` domains it is the **ordering term itself** (`op` / `ob`) — injective for those types, so `eql_v3.eq` compares ordering terms and the ordering index serves equality (see [Creating Indexes](#creating-indexes)).
- **Range / ordering** needs an ordering term — `op` (ope_cllw) on `public.<T>_ord` / `_ord_ope` / `public.eql_v3_text_search`, or `ob` (ore_block_256) on `public.<T>_ord_ore` / `public.eql_v3_text_search_ore`.
- **Text match** (`@@`) needs a `bf` (bloom_filter) term — `public.eql_v3_text_match`, `public.eql_v3_text_search`, or `public.eql_v3_text_search_ore`.

A value with only a bloom term will not drive an equality index, and vice versa.

### 2. The index must be created after the data carries the term

If you populate a column, then later change which terms its values carry, recreate the index — a functional index built before the term is present will not match.

### 3. The query operand must be typed

The comparison value must resolve to the encrypted operator, not the native `jsonb` one. A typed parameter (`$1`, which CipherStash Proxy supplies) or an explicit cast works:

```sql
-- ✓ resolves the encrypted operator → uses the index
WHERE encrypted_email = $1;
WHERE encrypted_email = $1::eql_v3.query_text_eq;

-- ✗ a bare jsonb literal falls through to native jsonb semantics
WHERE encrypted_email = '{"hm":"abc"}'::jsonb;
```

Cast an explicit operand to the matching **query-operand domain** (`eql_v3.query_<T>_<variant>`), not the column's storage domain: query payloads are term-only, and the storage domains' CHECK requires the ciphertext key `c` that query payloads deliberately omit.

---

## Query Patterns That Use Indexes

### Equality Queries

A column typed as an `hm`-carrying domain (`public.<T>_eq`, `text_ord`, `text_ord_ope`, `text_ord_ore`, or a `text_search` variant) with a hash index on `eql_v3.eq_term(col)`:

```sql
CREATE INDEX users_email_eq ON users USING hash (eql_v3.eq_term(encrypted_email));
ANALYZE users;

SELECT * FROM users WHERE encrypted_email = $1;
-- Index Scan using users_email_eq
--   Index Cond: (eql_v3.eq_term(encrypted_email) = eql_v3.eq_term($1))
```

On a numeric-and-time `_ord` / `_ord_ope` / `_ord_ore` column there is no `eq_term` — `=` inlines to the ordering extractor instead, so the same equality predicate engages the ordering btree from the [range recipe below](#range-queries-and-order-by):

```sql
SELECT * FROM events WHERE encrypted_at = $1;
-- Index Scan using events_at_ord
--   Index Cond: (eql_v3.ord_term(encrypted_at) = eql_v3.ord_term($1))
```

### Range Queries and ORDER BY

Type the column as an `_ord` / `_ord_ope` variant and build a btree on `eql_v3.ord_term(col)` (for an `_ord_ore` column, use `eql_v3.ord_term_ore(col)`):

```sql
CREATE INDEX events_at_ord ON events USING btree (eql_v3.ord_term(encrypted_at));
ANALYZE events;
```

`eql_v3.ord_term` returns `eql_v3_internal.ope_cllw`, a domain over `bytea`, so this btree resolves to `bytea_ops` — PostgreSQL's **default** operator class for the base type. Nothing to install, no privilege needed, and the opfamily already contains the `<` `<=` `>` `>=` the planner needs.

> **Why this matters on managed PostgreSQL.** The `_ord_ore` path depends on a hand-written btree operator class for the `eql_v3_internal.ore_block_256` *composite*, created by a `DO` block that is skipped (with only a `NOTICE`, which most migration tooling swallows) when the installing role cannot create operator classes. If that opclass is absent, `CREATE INDEX … btree (eql_v3.ord_term_ore(col))` does **not** fail — PostgreSQL binds `record_ops` instead. The index builds, occupies space, and never engages, because the ORE comparison operators are not members of `record_ops`. A silently useless index is worse than a rejected one. `_ord` has no such failure mode.
>
> Check which opclass an existing index actually bound:
>
> ```sql
> SELECT i.relname, oc.opcname
>   FROM pg_index x
>   JOIN pg_class i   ON i.oid = x.indexrelid
>   JOIN pg_opclass oc ON oc.oid = x.indclass[0]
>  WHERE i.relname = 'events_at_ord_ore';
> -- ore_block_256_operator_class  → ORE ordering, index engages
> -- record_ops                    → opclass was skipped at install; index is inert
> ```

The `<`, `<=`, `>`, `>=` operators inline to comparisons on `eql_v3.ord_term`, so natural-form range predicates match the index:

```sql
SELECT * FROM events WHERE encrypted_at < $1 ORDER BY encrypted_at DESC LIMIT 10;
```

**The sort-key trap.** The planner inlines operators in *predicates*, but it does **not** rewrite *sort keys*. `ORDER BY col` and `ORDER BY eql_v3.ord_term(col)` are not interchangeable to the planner, even though the ordering term is order-preserving. So the query above uses the index for the `WHERE` clause but still adds a `Sort` node for the `ORDER BY` (a Top-N sort because of the `LIMIT`). To stream rows out of the index already ordered — no `Sort` node — write the sort key in extractor form:

```sql
SELECT * FROM events
  WHERE encrypted_at < $1
  ORDER BY eql_v3.ord_term(encrypted_at) DESC
  LIMIT 10;
```

The natural-form Top-N sort scales linearly with the number of rows passing `WHERE`; at large row counts and moderate selectivity that is the difference between seconds and milliseconds. **For ordered range queries, write `ORDER BY` against the column's ordering extractor.**

> **The `value::jsonb` projection trap.** If you `SELECT col::jsonb … ORDER BY col`, PostgreSQL folds the cast into the scan output and uses `(col)::jsonb` as the sort key — which matches no index. Either project the column raw, or wrap the ordered query in a subquery so the cast applies outside the `LIMIT`. (Writing `ORDER BY eql_v3.ord_term(col)` sidesteps this entirely — it is structurally distinct from `(col)::jsonb`.)

### GROUP BY / DISTINCT

**Group and deduplicate on the extractor, not the raw column.** The extractor form is the only recipe that scales:

```sql
SELECT eql_v3.eq_term(encrypted_email), count(*)
  FROM users
  GROUP BY eql_v3.eq_term(encrypted_email);
```

Why the raw column does not scale: `GROUP BY col` uses the entire encrypted payload (1–2 KB per row) as the hash key. PostgreSQL estimates a hash table far larger than the default `work_mem` (4 MB), refuses `HashAggregate`, and falls back to `GroupAggregate` — sorting kilobyte-sized rows and spilling to disk. The `eql_v3.eq_term(col)` key is a small deterministic term, so the hash table fits in `work_mem` and the planner picks `HashAggregate` reliably — without any deployment-wide tuning. If you cannot rewrite the query (an ORM grouping the raw column), bumping `work_mem` to fit the estimated hash table is the rescue knob, but the extractor form is the design.

Pick the extractor the domain actually has: `eq_term` exists only on the `hm`-carrying domains. On a numeric-and-time `_ord` / `_ord_ope` / `_ord_ore` column, group on the ordering extractor instead — `GROUP BY eql_v3.ord_term(col)` (or `ord_term_ore(col)`). The ordering term is injective for those types, so it is an exact grouping key, and the column's ordering btree covers it.

#### `SELECT DISTINCT` is keyed on `eq_term`

`SELECT DISTINCT` on an encrypted column has the same scaling problem as `GROUP BY` on the raw column, plus a correctness one: the raw jsonb payload includes the randomised ciphertext `c`, so two rows holding identical plaintext never compare equal on the raw column and `DISTINCT` never collapses them. [CipherStash Proxy](https://github.com/cipherstash/proxy) rewrites `DISTINCT` on an encrypted column to key on its equality term instead:

```sql
-- as written
SELECT DISTINCT enc FROM t;

-- as rewritten by Proxy
SELECT DISTINCT ON (eql_v3.eq_term(enc)) enc FROM t;
```

Because dedup is equality-based, this requires the column's domain to carry an equality term. A storage-only domain with no `eq_term` overload — `public.eql_v3_boolean`, which ships no `_eq` / `_ord` variant (see [SQL support](./sql-support.md)) — cannot be deduplicated this way; `DISTINCT` on it is a capability error rather than a silent fallback to comparing raw ciphertext.

#### `SELECT DISTINCT … ORDER BY` additionally requires `ord_term`

Ordering an encrypted column under `DISTINCT` needs `eql_v3.ord_term(col)` too. PostgreSQL requires every `ORDER BY` expression under `DISTINCT ON` to appear in the select list, so Proxy pushes the query into a subquery that projects the ordering term, then applies `ORDER BY` in a non-`DISTINCT` outer query around it:

```sql
-- as written
SELECT DISTINCT enc FROM t ORDER BY enc;

-- as rewritten by Proxy (conceptually — column names/aliases are preserved)
SELECT enc FROM (
  SELECT DISTINCT ON (eql_v3.eq_term(enc)) enc, eql_v3.ord_term(enc) AS order_term
    FROM t
) sub
ORDER BY order_term;
```

The ordering term (`order_term` above) is never returned to the client. This rewrite happens entirely in Proxy — EQL SQL only supplies the `eq_term` / `ord_term` extractors it relies on.

### Field-level ordering index (ste_vec elements)

Entry-to-entry `=` / `<>` and exact `GROUP BY` / `DISTINCT` on extracted
encrypted-JSON fields are not supported. An extracted path entry carries no
value selector, and its `op` ordering bytes are lossy for some scalar types.
Use document containment with the GIN index below for exact field equality.

For ordered field-level access, index `eql_v3.ord_term(doc -> '<selector>'::text)` (a btree) and write `ORDER BY eql_v3.ord_term(doc -> '<selector>'::text)` — the same sort-key rule as above. The extracted CLLW-OPE term is a bytea domain that orders under the DEFAULT btree operator class, so this index needs no superuser-installed operator class (it works on Supabase / managed Postgres). The `<selector>` value is the deterministic selector hash the crypto layer emits in each `sv` element's `s` field, not a plaintext JSONPath. The operand on `->` must be typed (`-> '<sel>'::text`); a bare untyped literal falls through to native `jsonb ->`.

---

## GIN Indexes for JSONB Containment

For document-level containment (`@>`) on `public.eql_v3_json_search` columns, use a GIN index over the ste_vec query shape. The typed `@>` overload inlines to a native `jsonb @>` over `eql_v3.to_ste_vec_query(col)::jsonb`, so a GIN index on the same expression engages (`jsonb_path_ops` indexes `@>` only, not `<@`):

```sql
CREATE INDEX orders_data_gin
  ON orders USING gin ((eql_v3.to_ste_vec_query(data_encrypted)::jsonb) jsonb_path_ops);
ANALYZE orders;

SELECT * FROM orders WHERE data_encrypted @> $1::eql_v3.query_json;
-- Bitmap Index Scan on orders_data_gin
```

The needle must be typed — `$1::eql_v3.query_json` or another `public.eql_v3_json_search`. A bare untyped literal falls through to native `jsonb @>`.

### GIN vs B-tree / hash

| Feature        | hash / btree on extractor      | GIN on `to_ste_vec_query` |
| -------------- | ------------------------------ | ------------------------- |
| **Use case**   | equality, range, ordering      | JSONB document containment |
| **Operators**  | `=`, `<>`, `<`, `>`, `<=`, `>=` | `@>`                     |
| **Expression** | `eql_v3.eq_term` / `ord_term`  | `eql_v3.to_ste_vec_query(col)::jsonb` |

---

## Best Practices

1. **Type the column as the right variant first.** The variant (`_eq` / `_ord` / `text_match`) is what makes the operator — and therefore the index — resolve. There is no separate database-side config step.
2. **Run `ANALYZE` after every index build.** `CREATE INDEX` on an *expression* gathers no statistics on that expression; without `ANALYZE` the planner has no histogram for `eql_v3.eq_term(col)` and can misjudge the index it just built.
3. **Verify with `EXPLAIN`** — see [Diagnosing Queries with EXPLAIN](#diagnosing-queries-with-explain).
4. **Name indexes descriptively** (`users_email_eq`, `events_at_ord`) for easier management.
5. **Drop unused indexes.** If a column no longer needs a capability, drop the corresponding functional index — duplicate indexes compete for cache and slow writes.

---

## Performance: Building Indexes on Large Tables

Everything above is about query time. Index *build* time is a separate axis, and on large encrypted tables it is the one that bites: a functional index that queries in a millisecond can still take hours — or fail to finish — to `CREATE`. Three things govern it.

### `maintenance_work_mem`, not `work_mem`

`CREATE INDEX` draws on `maintenance_work_mem` (default 64 MB — far too small for a multi-million-row build; the sort or bucket fill spills to disk early and the build goes I/O-bound). Raise it for the session before a large build:

```sql
SET maintenance_work_mem = '2GB';   -- per-build; only one build runs at a time
CREATE INDEX … ;
```

It is the single highest-leverage knob for build time. On a managed deployment where you cannot set it per session, raise it for the maintenance window.

### Index type decides whether the build scales

For *query* performance the access method is settled by capability (`hash` or `btree` on `eq_term` for equality, `btree` on the ordering extractor — OPE and ORE alike, `GIN` for bloom / ste_vec). For *build* performance at scale they are not equivalent:

| Access method | Build algorithm                                   | Scales past cache? | Parallel build? |
| ------------- | ------------------------------------------------- | ------------------ | --------------- |
| **btree**     | sort, then bulk-load bottom-up — sequential writes | yes               | yes (`max_parallel_maintenance_workers`) |
| **GIN**       | batched buffer build                              | yes                | no              |
| **hash**      | fill buckets keyed by hash value                  | **no**             | no              |

A hash build scatters consecutive heap rows to random buckets; once the index outgrows `shared_buffers` + OS cache it becomes random-I/O-bound and cannot be parallelised. A btree build sorts first, then writes sequentially across parallel workers.

**For equality functional indexes on large tables, prefer `btree` over `hash`.** `eql_v3.eq_term(col)` returns a small deterministic term; a btree on it serves `=` exactly as well as a hash index, with no query-side cost, and the build goes from pathological to routine:

```sql
CREATE INDEX … USING btree (eql_v3.eq_term(col));   -- large tables
CREATE INDEX … USING hash  (eql_v3.eq_term(col));   -- small / medium tables
```

A `hash` functional index on a 10M-row encrypted-JSONB column has been observed to run 17 hours to 73% and stall; the `btree` equivalent with `maintenance_work_mem` raised builds without drama. Hash is fine up to mid-six-figure row counts — but its *build* does not scale.

### The de-TOAST floor

A functional index over a large encrypted column [de-TOASTs](https://www.postgresql.org/docs/current/storage-toast.html) the whole stored value once per row to evaluate the extractor — and an `public.eql_v3_json_search` document is large. This cost is unavoidable and identical across access methods; it sets the build's *floor* rate. (There is no partial de-TOAST — `doc -> 'selector'::text` materialises the entire document.)

### Storage matters more than it does for queries

Index builds are I/O-heavy in a way steady-state queries are not. Containerised PostgreSQL on a virtualised filesystem — notably Docker Desktop on macOS — pays a steep penalty: the random TOAST reads a functional-index build performs are the worst case for a VM I/O layer. For large builds, run PostgreSQL on native storage / fast NVMe.

### Diagnosing a slow build

`pg_stat_progress_create_index` is the build-time analogue of `EXPLAIN`. From a second session while `CREATE INDEX` runs:

```sql
SELECT phase, tuples_done, tuples_total,
       round(100.0 * tuples_done / nullif(tuples_total, 0), 1) AS pct
FROM pg_stat_progress_create_index;
```

A steady `tuples_done` rate means the build is healthy. A rate that **decays over time** is the cache/memory wall — raise `maintenance_work_mem`, and if it is a hash index, rebuild it as a btree.

---

## Diagnosing Queries with EXPLAIN

The first move on a slow EQL query is `EXPLAIN (COSTS OFF)`. Look for:

- **`Index Scan using <your-index>`** — the planner is using the functional index. ✓
- **`Bitmap Index Scan on <your-index>`** — same, for set-style predicates (`@>`). ✓
- **`Index Cond:`** referencing the extractor (`eql_v3.eq_term(…)`, `eql_v3.ord_term(…)`) — the inlined predicate matched the index. ✓
- **`Seq Scan`** — no index used. Investigate.
- **`Filter:` showing the raw operator** (`col < '…'`) — inlining did not happen. Usual causes: a pinned `search_path` on a customised function (`\sf <function>` shows any `SET search_path` clause), a `plpgsql` body where a `sql` one is expected, or the planner judging another plan cheaper.
- **`Sort` node above an Index Scan** — natural-form `ORDER BY`; expected for that shape. Switch the sort key to the column's ordering extractor to eliminate it.

Once a plan looks right, repeat with `EXPLAIN ANALYZE` to measure actual timings.

---

## Troubleshooting

**Index not being used:**

1. **Verify the value carries the term.** Equality needs `hm` on the `hm`-carrying domains (the ordering term serves it on numeric-and-time `_ord` / `_ord_ore`), range needs `op` (or `ob` on an `_ord_ore` column), containment needs `bf`:
   ```sql
   SELECT encrypted_email::jsonb ? 'hm' AS has_hmac,
          encrypted_email::jsonb ? 'op' AS has_ope,
          encrypted_email::jsonb ? 'ob' AS has_ore_block,
          encrypted_email::jsonb ? 'bf' AS has_bloom
   FROM users LIMIT 1;
   ```
2. **Verify the operand is typed** (`$1::eql_v3.query_text_eq`, not `$1::jsonb` — and not the storage domain `public.eql_v3_text_eq`, whose CHECK requires the ciphertext key query payloads omit).
3. **Recreate the index** if the column's terms changed after the index was built.
4. **Run `ANALYZE`** — very small tables may still choose a sequential scan, which is correct.

**`=` returns zero rows:** equality requires the value to carry the domain's equality-serving term — `hm` on the `hm`-carrying domains (`_eq`, `text_ord`, `text_ord_ore`, the `text_search` variants), the ordering term (`op` / `ob`) on the numeric-and-time `_ord` / `_ord_ore` domains. Confirm the column's domain variant and that the client is emitting the term.

---

## See Also

- [SQL support matrix](./sql-support.md) — which operators work against which domain variant.
- [EQL Functions Reference](./eql-functions.md) — complete function API.
- [EQL with JSON and JSONB](./json-support.md) — `public.eql_v3_json_search` worked examples.
- [Configuration Tutorial](../tutorials/proxy-configuration.md) — setting up encrypted columns end to end.

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20database-indexes.md)
