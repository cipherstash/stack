# EQL on Supabase and managed PostgreSQL

EQL's `eql_v3` surface is designed to work on Supabase and other managed
PostgreSQL deployments where you cannot run as superuser, cannot install
custom operator classes, and cannot edit `postgresql.conf` per session.

There is **no separate Supabase build of EQL**. The single installer
(`release/cipherstash-encrypt.sql`) is the same artefact you install
everywhere. This page explains *why* `eql_v3` runs on Supabase unchanged,
and the small number of things you do differently on a managed platform.

## Why `eql_v3` works on Supabase

Earlier EQL relied on PostgreSQL operator classes to make encrypted
comparisons engage indexes. Operator classes require elevated privileges
and Supabase [does not support custom operators](https://github.com/supabase/supautils/issues/72),
so that recipe needed a cut-down build.

`eql_v3` removes the dependency entirely. Every encrypted column is typed as
a `jsonb`-backed **domain** in the `public` schema (for example
`public.eql_v3_text_eq`, `public.eql_v3_integer_ord`, `public.eql_v3_json`), and search is driven by
**functional indexes over small term-extractor functions** rather than an
operator class on the column:

- `eql_v3.eq_term(col)` — the equality (`hm` / hmac_256) term.
- `eql_v3.ord_term(col)` — the ordering (`op` / ope_cllw) term.
- `eql_v3.ord_term_ore(col)` — the block-ORE ordering (`ob` / ore_block_256) term.
- `eql_v3.match_term(col)` — the text-containment (`bf` / bloom_filter) term.

These extractors are inlinable (`LANGUAGE sql`, single `SELECT`, `IMMUTABLE`,
no pinned `search_path`), so the planner rewrites a bare-form predicate into
the same expression as the index and matches it structurally — no per-query
rewriting required. Creating a functional index needs no superuser and no
operator class, so the recipe is identical on Supabase, RDS, Cloud SQL, and a
self-hosted server:

```sql
-- Equality (hash index on the eq_term extractor)
CREATE INDEX users_email_eq ON users USING hash (eql_v3.eq_term(encrypted_email));

-- Ordering / range (btree index on the ord_term extractor)
CREATE INDEX events_at_ord ON events USING btree (eql_v3.ord_term(encrypted_at));

-- Text containment (GIN index on the match_term extractor)
CREATE INDEX users_name_match ON users USING gin (eql_v3.match_term(encrypted_name));

ANALYZE users;
```

`eql_v3` deliberately ships **no** `encrypted_operator_class`, so there is
nothing operator-class-shaped to install and nothing that needs superuser.
See [Database Indexes for Encrypted Columns](./docs/reference/database-indexes.md)
for the full recipes, GIN containment, and large-table build guidance.

## Typed columns, not database-side config

`eql_v3` has **no database-side configuration API**. The earlier
`config_add_table` / `config_add_column` / `config_add_index` functions are
gone. The searchable surface of a column is fixed by the **domain variant you
type it as**, and which index terms travel in a value's payload is decided by
the encryption client — [CipherStash Proxy](https://github.com/cipherstash/proxy)
or [CipherStash Stack](https://github.com/cipherstash/stack):

- `public.<T>_eq` carries an `hm` term — supports `=` / `<>`, `GROUP BY`, `DISTINCT`.
- `public.<T>_ord` (and the `_ord_ope` twin) carries an `op` term — adds `<` `<=` `>` `>=`, `ORDER BY`, `MIN` / `MAX`. `public.<T>_ord_ore` is the block-ORE (`ob`) equivalent.
- `public.eql_v3_text_match` carries a `bf` term — supports bloom-filter token match (`@@` / `eql_v3.matches`; `@>` / `<@` raise).
- `public.eql_v3_text_search` carries all three terms — equality, ordering, and bloom-filter token match (`@@` / `eql_v3.matches`) on `text`. `public.eql_v3_text_search_ore` is its block-ORE equivalent.

Configuring those columns is a client-side concern. See:

- [CipherStash Proxy configuration tutorial](./docs/tutorials/proxy-configuration.md)
- [CipherStash Stack schema reference](https://cipherstash.com/docs/stack/cipherstash/encryption/schema)

## Operators on Supabase

In `eql_v3`, each supported SQL operator is an alias for an EQL function, so
implementation and behaviour are identical whether you write the operator or
the function. The operator forms are inlinable and engage the functional
indexes above, so the operator form is the recommended one. The function
equivalents exist for environments or query builders where the bare operator
is awkward to express.

| Operator | Function equivalent                                | Example                                                            |
| -------- | -------------------------------------------------- | ----------------------------------------------------------------- |
| `=`      | `eql_v3.eq(col, $1)`                               | `SELECT * FROM users WHERE eql_v3.eq(encrypted_email, $1)`        |
| `<>`     | `eql_v3.neq(col, $1)`                              | `SELECT * FROM users WHERE eql_v3.neq(encrypted_email, $1)`       |
| `<`      | `eql_v3.lt(col, $1)`                               | `SELECT * FROM events WHERE eql_v3.lt(encrypted_at, $1)`          |
| `<=`     | `eql_v3.lte(col, $1)`                              | `SELECT * FROM events WHERE eql_v3.lte(encrypted_at, $1)`         |
| `>`      | `eql_v3.gt(col, $1)`                               | `SELECT * FROM events WHERE eql_v3.gt(encrypted_at, $1)`          |
| `>=`     | `eql_v3.gte(col, $1)`                              | `SELECT * FROM events WHERE eql_v3.gte(encrypted_at, $1)`         |
| `@@`     | `eql_v3.matches(col, $1)`                          | `SELECT * FROM users WHERE eql_v3.matches(encrypted_name, $1)`    |

`eql_v3.eq` / `neq` / `lt` / `lte` / `gt` / `gte` / `matches`
are each overloaded for `(domain, domain)`, `(domain, jsonb)`,
and `(jsonb, domain)`, so a `jsonb` operand is accepted directly and resolved
against the typed side.

### Equality `=`

Operator form (recommended — engages the index):

```sql
SELECT * FROM users WHERE encrypted_email = $1;
```

Function form (equivalent):

```sql
SELECT * FROM users WHERE eql_v3.eq(encrypted_email, $1);
```

### Range and ordering `<` `<=` `>` `>=`

The column must be typed as an `_ord` / `_ord_ope` variant (or `text_search`) so
it carries the `op` term — or as an `_ord_ore` / `text_search_ore` variant, which
carries `ob`. Prefer the `op`-backed domains on Supabase: their ordered
functional indexes bind `bytea_ops`, the base type's default operator class,
whereas block-ORE needs a superuser-created operator class that is silently
skipped here (leaving an index that builds but never engages).

```sql
SELECT * FROM events WHERE encrypted_at < $1;
SELECT * FROM events WHERE eql_v3.lt(encrypted_at, $1);
```

### `ORDER BY`

Ordering uses the same ordering term as range comparisons, on an `_ord` /
`_ord_ope` / `text_search` column (`op`), or an `_ord_ore` / `text_search_ore`
column (`ob`, via `eql_v3.ord_term_ore`). The `<`/`>` operators inline in
*predicates*, but the planner does **not** rewrite *sort keys* — so to stream
rows out of the btree already ordered (no `Sort` node), write the sort key in
extractor form:

```sql
SELECT * FROM events
  WHERE encrypted_at < $1
  ORDER BY eql_v3.ord_term(encrypted_at) DESC
  LIMIT 10;
```

Writing the sort key as `eql_v3.ord_term(col)` is the way to order encrypted
rows directly out of the btree. See the
[sort-key trap](./docs/reference/database-indexes.md#range-queries-and-order-by)
for the full explanation.

### Aggregates `MIN` / `MAX`

`MIN` / `MAX` are exposed on the ordered variants as
`eql_v3.min(public.<T>_ord)` / `eql_v3.max(public.<T>_ord)` (and the
`_ord_ore` twin). Type the column as `_ord`, or cast at the call site:

```sql
SELECT eql_v3.min(encrypted_at) FROM events;
SELECT eql_v3.max(encrypted_amount::public.eql_v3_integer_ord) FROM orders;
```

## Text matching (not `LIKE`)

There is **no SQL `LIKE` / `ILIKE` pattern matching on encrypted text in
`eql_v3`**. The `LIKE` / `ILIKE` operators (`~~` / `~~*`) are blocked on every
encrypted domain variant and raise an "operator not supported" exception.

Text search is now **bloom-filter token matching** via the `@@` operator
(`eql_v3.matches`) on a column typed `public.eql_v3_text_match` or
`public.eql_v3_text_search`. This tests whether the encrypted text matches the
(encrypted) search terms — a probabilistic ngram match, not a SQL pattern match
and not containment (the `@>` / `<@` containment operators raise on these
domains):

```sql
-- Column typed public.eql_v3_text_match or public.eql_v3_text_search,
-- with: CREATE INDEX ... USING gin (eql_v3.match_term(encrypted_name));
SELECT * FROM users WHERE encrypted_name @@ $1;
SELECT * FROM users WHERE eql_v3.matches(encrypted_name, $1);
```

Case sensitivity and tokenisation are properties of how the value was
encrypted (token filters configured in the client), not of the SQL operator.
See the [SQL support matrix](./docs/reference/sql-support.md) for which
operator resolves on which variant.

## Encrypted JSON documents

`public.eql_v3_json_search` is the structured-encryption (ste_vec) document domain. It
supports document containment (`@>` / `<@`), field access (`->` / `->>`), and
the `eql_v3.jsonb_path_*` helper functions, all without operator classes:

```sql
-- Document containment (GIN-indexable on Supabase)
SELECT * FROM orders WHERE data_encrypted @> $1::eql_v3.query_json;

-- Field access (selector is the deterministic selector hash, typed as text)
SELECT data_encrypted -> '<selector>'::text FROM orders;
```

For containment indexing, build a GIN index over the query shape — see
[GIN Indexes for JSONB Containment](./docs/reference/database-indexes.md#gin-indexes-for-jsonb-containment).
Worked examples are in [EQL with JSON and JSONB](./docs/reference/json-support.md).

## Typed operands matter

For the encrypted operator (and therefore the functional index) to resolve,
the comparison operand must carry a known type — a typed parameter (`$1`,
which CipherStash Proxy supplies) or an explicit cast:

```sql
-- ✓ resolves the encrypted operator → uses the index
WHERE encrypted_email = $1;
WHERE encrypted_email = $1::public.eql_v3_text_eq;

-- ✗ a bare jsonb literal falls through to native jsonb semantics
WHERE encrypted_email = '{"hm":"abc"}'::jsonb;
```

CipherStash Proxy rewrites bound parameters so the encrypted operator and any
functional indexes are selected automatically. When bypassing the Proxy, type
the parameter yourself.

## See also

- [Database Indexes for Encrypted Columns](./docs/reference/database-indexes.md) — functional-index and GIN recipes, plus large-table build guidance.
- [SQL support matrix](./docs/reference/sql-support.md) — which operators work against which domain variant.
- [EQL Functions Reference](./docs/reference/eql-functions.md) — complete function and operator API.
- [EQL with JSON and JSONB](./docs/reference/json-support.md) — `public.eql_v3_json_search` worked examples.
- [CipherStash Proxy configuration tutorial](./docs/tutorials/proxy-configuration.md) — setting up encrypted columns end to end.

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20SUPABASE.md)
