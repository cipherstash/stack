# SQL support matrix for EQL

This page summarises which SQL operators and language features work against EQL-encrypted columns, and which encrypted-domain **type** each one requires.

EQL ships its searchable-encryption surface as PostgreSQL **domains in the `public` schema**:

- **per-scalar encrypted-domain types** — `public.eql_v3_integer`, `public.eql_v3_text`, `public.eql_v3_timestamp`, … — one family of domain *variants* per scalar; and
- **an encrypted-JSON document type** — `public.eql_v3_json_search` — for structured-encryption (ste_vec) JSONB.

The capability of a column is fixed by the **domain variant you type it as**. There is no database-side `add_search_config` / `add_column` step: which index terms travel in a value's payload is decided by the encryption client ([CipherStash Proxy](https://github.com/cipherstash/proxy) / [CipherStash Stack](https://github.com/cipherstash/stack)), and the column's domain variant is what makes the matching operators resolve. Unsupported operators are not silent no-ops — they route to blocker functions that `RAISE` an "operator not supported" exception (a `NULL` operand still raises; the blockers are deliberately not `STRICT`).

---

## Encrypted-domain scalar types (`public.<T>`)

Each scalar type `<T>` is a family of `jsonb`-backed domains in `public`. The catalog scalar tokens that ship today are:

`smallint`, `integer`, `bigint`, `numeric`, `real`, `double`, `date`, `timestamp`, `text`, `boolean`, `json` (the bare `public.eql_v3_json` scalar domain is storage-only, like `boolean` — the *queryable* JSON document domain is `public.eql_v3_json_search`, [below](#publiceql_v3_json_search-structured-encryption-for-json)).

(See [Adding a Scalar Encrypted-Domain Type](./adding-a-scalar-encrypted-domain-type.md) for how the family is generated.) The domains live in the `public` schema, so they survive `DROP SCHEMA eql_v3 CASCADE` — dropping `eql_v3` removes the query operators, extractors, and aggregates (the blockers, bound to `eql_v3_internal` functions, survive) but leaves the `public`-typed columns and their data intact. Their extracted index-term types are the self-contained `eql_v3_internal` SEM types (`eql_v3_internal.hmac_256`, `eql_v3_internal.ope_cllw`, `eql_v3_internal.ore_block_256`, `eql_v3_internal.bloom_filter`).

Every scalar generates a storage-only variant plus the query variants its capabilities allow:

| Domain variant                | Index term carried        | Extractor (for indexing) | `=` `<>` | `<` `<=` `>` `>=` | `MIN` / `MAX` | `@@` |
| ----------------------------- | ------------------------- | ------------------------ | :------: | :---------------: | :-----------: | :-------: |
| `public.<T>`                  | none (storage only)       | —                        |    ❌    |        ❌         |      ❌       |    ❌     |
| `public.<T>_eq`               | `hm` (hmac_256)           | `eql_v3.eq_term(col)`    |    ✅    |        ❌         |      ❌       |    ❌     |
| `public.<T>_ord` / `_ord_ope` | `op` (ope_cllw)           | `eql_v3.ord_term(col)` |  ✅    |        ✅         |      ✅       |    ❌     |
| `public.<T>_ord_ore`          | `ob` (ore_block_256)      | `eql_v3.ord_term_ore(col)`   |    ✅    |        ✅         |      ✅       |    ❌     |
| `public.eql_v3_text_match`           | `bf` (bloom_filter)       | `eql_v3.match_term(col)` |    ❌    |        ❌         |      ❌       |    ✅\*   |
| `public.eql_v3_text_search`          | `hm` + `op` + `bf`        | all three extractors     |    ✅    |        ✅         |      ✅       |    ✅\*   |
| `public.eql_v3_text_search_ore`      | `hm` + `ob` + `bf`        | all three extractors     |    ✅    |        ✅         |      ✅       |    ✅\*   |

\* On `text_match` / `text_search` / `text_search_ore`, `@@` (`eql_v3.matches`) is **bloom-filter token matching** (probabilistic ngram match), **not** containment and **not** SQL `LIKE`. The containment operators `@>` / `<@` **raise** on these domains. See [Indexing](#indexing).

Notes:

- The bare `public.<T>` variant carries no index term and **blocks every comparison operator** — it is storage / decryption only. Type the column as `_eq` or `_ord` (or cast at the call site, e.g. `col::public.eql_v3_integer_ord` — this succeeds only if the stored payloads already carry the `op` term; otherwise the domain CHECK raises) when you need to query.
- `_ord` and `_ord_ope` are **twins**: byte-identical surfaces backed by the CLLW-OPE term. `op` is a hex-encoded, order-preserving ciphertext compared by native bytea ordering after hex-decode (no custom comparison protocol, and `eql_v3_internal.ope_cllw` is a domain over `bytea`, so a functional btree on `eql_v3.ord_term(col)` uses the default operator class and needs no superuser). `_ord` is the recommended name; `_ord_ope` documents the scheme explicitly.
- `_ord_ore` exposes the **same ordered surface** backed by the block-ORE term (`ob`) instead, compared by the custom N-block protocol. Use it when you specifically need block-ORE. Caveat: its btree operator class is created by a superuser-gated `DO` block that is **skipped (with only a `NOTICE`)** without that privilege. When it is missing, `CREATE INDEX … btree (eql_v3.ord_term_ore(col))` still *succeeds* — PostgreSQL falls back to `record_ops` on the composite — but that opfamily does not contain the ORE comparison operators, so the index never engages and the ordering it stores is not the ORE ordering. Verify with `\d+` that the index opclass is `ore_block_256_operator_class`, not `record_ops`.
- For `<T> = text`, the ordering variants carry **more** than the table's generic cells say: `text_ord` / `text_ord_ope` carry `hm` **+** `op`, and `text_ord_ore` carries `hm` **+** `ob`, each with an `eql_v3.eq_term(col)` extractor alongside the ordering one. `=` / `<>` route through `hm` (exact HMAC) — ordering terms over text are not equality-lossless, unlike the numeric-and-time types where the injective ordering term serves equality directly.
- `text_ord` accepts the empty string (its `op` term is well-formed and sorts first). `text_ord_ore` **rejects** it: encrypting `""` yields an empty ORE term (`ob: []`) that the domain CHECK refuses.
- `=` / `<>` is the only searchable surface for `_eq`. On `_ord` variants the equality operators are available too (alongside the ordered ones).
- `boolean` is **storage-only** by design — a two-value column has too little cardinality for any searchable index to be safe, so it ships only `public.eql_v3_boolean` (no `_eq` / `_ord`).
- `LIKE` / `ILIKE` (`~~` / `~~*`) do not work on any scalar domain variant — but unlike the other ❌ cells they fail at operator *resolution* (PostgreSQL's "operator does not exist"), since no `~~` blocker is defined, rather than with the EQL "operator not supported" exception. Text matching is the bloom-filter `@@` (`eql_v3.matches`) on `text_match`, not `LIKE`.
- `MIN` / `MAX` are exposed only on the ordered variants, as `eql_v3.min(public.<T>_ord)` / `eql_v3.max(...)` (and likewise on `_ord_ope` / `_ord_ore`) — see [EQL Functions Reference](./eql-functions.md#eql_v3min--eql_v3max-per-domain).

---

## SQL operator support

A ✅ means the operator resolves on a column typed as that domain variant. A ❌ means the operator is blocked (it raises) for that variant.

| SQL operator              | Meaning                        | `public.<T>` | `_eq` | `_ord` / `_ord_ore` / `_ord_ope` | `text_match` | `text_search` | `text_search_ore` |
| ------------------------- | ------------------------------ | :----------: | :---: | :-----------------: | :----------: | :-----------: | :---------------: |
| `=`                       | Equality                       |      ❌      |  ✅   |         ✅          |      ❌      |      ✅       |        ✅         |
| `<>` / `!=`               | Inequality                     |      ❌      |  ✅   |         ✅          |      ❌      |      ✅       |        ✅         |
| `<` `<=` `>` `>=`         | Ordered comparison             |      ❌      |  ❌   |         ✅          |      ❌      |      ✅       |        ✅         |
| `@@`                      | Bloom-filter token match       |      ❌      |  ❌   |         ❌          |      ✅      |      ✅       |        ✅         |
| `@>` / `<@`               | Containment — **raises** (use `@@`) |  ❌      |  ❌   |         ❌          |      ❌      |      ❌       |        ❌         |
| `LIKE` `ILIKE` (`~~`/`~~*`) | SQL pattern match            |      ❌      |  ❌   |         ❌          |      ❌      |      ❌       |        ❌         |
| `IS NULL` / `IS NOT NULL` | Null check                     |      ✅      |  ✅   |         ✅          |      ✅      |      ✅       |        ✅         |

Notes:

- A SQL `NULL` column value is not encrypted, so `IS NULL` / `IS NOT NULL` always work regardless of variant.
- `@@` on `text_match` / `text_search` / `text_search_ore` tests whether the encrypted text **matches** the (encrypted) search terms via the bloom filter (n-gram token match, not containment; `@>` / `<@` raise here). This replaces the old `LIKE`/`ILIKE`-on-`match`-index recipe: there is no `LIKE` on encrypted text — use `@@`.

---

## SQL syntax / feature support

This matrix covers higher-level SQL constructs. As above, ✅ requires the column to be typed as a variant that carries the necessary term.

| SQL feature                          | Notes                                                                                  | Required variant |
| ------------------------------------ | -------------------------------------------------------------------------------------- | ---------------- |
| `WHERE col = …` / `<>`               |                                                                                        | `_eq`, `_ord`, `text_search`, `text_search_ore` |
| `WHERE col <` / `<=` / `>` / `>=`    |                                                                                        | `_ord`, `text_search`, `text_search_ore` |
| `WHERE col BETWEEN … AND …`          | desugars to `>=` and `<=`                                                               | `_ord`, `text_search`, `text_search_ore` |
| `WHERE col @@ …`                     | bloom-filter token match (text)                                                        | `text_match`, `text_search`, `text_search_ore` |
| `WHERE col @> …`                     | document containment (`public.eql_v3_json_search` only; raises on text match)           | `public.eql_v3_json_search` |
| `WHERE col IN (…)`                   | desugars to `=`                                                                         | `_eq`, `_ord`, `text_search`, `text_search_ore` |
| `ORDER BY col`                       | meaningful only with an ordering term                                                   | `_ord`, `text_search`, `text_search_ore` |
| `GROUP BY col` / `DISTINCT`          | needs an equality term                                                                  | `_eq`, `_ord`, `text_search`, `text_search_ore` |
| `MIN(col)` / `MAX(col)`              | `eql_v3.min(public.<T>_ord)` / `max` — type the column as `_ord` or cast at the call site (`eql_v3.min(col::public.eql_v3_integer_ord)`) | `_ord`, `text_search`, `text_search_ore` |
| `COUNT(col)` / `COUNT(DISTINCT col)` | plain `COUNT(col)` needs no term; `DISTINCT` needs an equality term                     | any / `_eq` for `DISTINCT` |
| `JOIN … ON lhs.col = rhs.col`        | both sides must share the same keyset and a matching variant                            | `_eq`, `_ord`, `text_search`, `text_search_ore` |

Notes:

- **`_ord` in the "requires" column is shorthand for all three ordering variants** — `_ord`, its explicit twin `_ord_ope`, and the block-ORE `_ord_ore`. Every row that lists `_ord` holds for all three (they share the operator surface, and `eql_v3.min` / `max` are generated for each); `_ord_ope` and `_ord_ore` are spelled out in the domain-variant table above.
- **Cross-column / cross-table comparisons** (joins, `IN (subquery)`, set-operation dedup) require both sides to have been encrypted with the *same* keyset and a matching variant.
- **`ORDER BY`** without an ordering term will not produce a meaningful order — type the column as an `_ord` variant when ordering matters.
- **Aggregates beyond `MIN` / `MAX`** (`SUM`, `AVG`, …) are not supported on encrypted values — decrypt at the application boundary and aggregate client-side.
- **Parameter binding**: [CipherStash Proxy](https://github.com/cipherstash/proxy) rewrites bound parameters so the encrypted operator and any functional indexes are selected. When bypassing the proxy, type the parameter with the matching **query-operand domain** — `$1::eql_v3.query_integer_ord`, `$1::eql_v3.query_text_eq`, … — so the encrypted operator resolves rather than the native `jsonb` one. Every queryable variant has an `eql_v3.query_<T>_<variant>` twin, and query payloads must use it: they are term-only (no ciphertext), so casting one to the *storage* domain (`public.eql_v3_integer_ord`) fails its CHECK, and a bare uncast literal is ambiguous between the query and `jsonb` overloads and will not resolve.

---

## Indexing

`eql_v3` indexes through a **functional index on the term extractor**, never an operator class on a column. The extractor's return type carries a default opclass, and the extractors are inlinable, so bare-form queries (`WHERE col = $1`, `ORDER BY col`) engage the index:

```sql
-- Equality (hash index on eq_term)
CREATE INDEX users_email_eq ON users USING hash (eql_v3.eq_term(encrypted_email));

-- Ordering / range (btree index on ord_term; use ord_term_ore for an _ord_ore column)
CREATE INDEX events_at_ord ON events USING btree (eql_v3.ord_term(encrypted_at));

-- Text match (bloom fuzzy match — GIN on match_term)
CREATE INDEX users_name_match ON users USING gin (eql_v3.match_term(encrypted_name));
```

See [Database Indexes for Encrypted Columns](./database-indexes.md) for the full recipes, GIN containment, and performance guidance.

---

## `public.eql_v3_json_search`: structured encryption for JSON

`public.eql_v3_json_search` is the encrypted-JSON document domain (built on the structured-encryption "ste_vec" model). A JSONB document is encrypted into a searchable vector (`sv`) of terms — one element per path inside the document — each carrying:

- `s` — a deterministic **selector** hash for the JSON path (always present); and
- one or more **value terms** depending on the JSON type of the leaf at that path.

Selectors locate a path; value terms let EQL compare the value at that path.

### Index terms by JSON node type

Each JSON node emits a **path entry** and a **value entry**. Exact equality is the value entry's job — a value selector `SEL(type-tag ‖ path ‖ canonical(value))` whose *presence* in the document is an injective match (no per-node term). Ordering is the path entry's `op` term, present only on String / Number nodes. The `Equality` column below is document-containment equality (`@>` on the value selector), which is exact for **every** node type; ordering is the extract-surface capability of `->`.

| JSON node type           | Path-entry term (alongside `s`)  | Equality (containment `@>`)      | Ordering (`<` … `>=`, `ORDER BY`, `MIN`/`MAX`) |
| ------------------------ | -------------------------------- | :------------------------------: | :--------------------------------------------: |
| Object `{ … }`           | — (tag-only value entry)         | ✅ (structural)                  | ❌                                             |
| Array `[ … ]`            | — on the container; each element also appears as its own `sv` entry with its own leaf terms | ✅ (structural) | ❌            |
| String `"…"`             | `op` (variable-width CLLW OPE)   | ✅                               | ✅                                             |
| Number (integer/numeric) | `op` (CLLW OPE)                  | ✅                               | ✅                                             |
| Boolean / JSON null      | — (tag-only value entry)         | ✅                               | ❌                                             |

Exact equality is always value-selector presence (`@>`), injective for every type — the per-value `hm` term was retired in 3.0.0. `op` is a CLLW OPE term that preserves order on the extract surface (`->`); it is *not* used for equality (it is lossy for `text` / `bigint` / `numeric`). JSON `null` here refers to a `null` literal *inside* the document — a SQL `NULL` column is not encrypted at all.

### Operators and functions on `public.eql_v3_json_search`

| SQL form                         | Resolves to                                        | Returns / notes |
| -------------------------------- | -------------------------------------------------- | --------------- |
| `doc @> needle` / `needle <@ doc` | `eql_v3."@>"` / `eql_v3."<@"`                      | document containment (also the exact field-equality mechanism via value-selector needles); GIN-indexable via `eql_v3.to_ste_vec_query(doc)::jsonb` — see [GIN Indexes for JSONB Containment](./database-indexes.md#gin-indexes-for-jsonb-containment). `needle` must be typed (`$1::eql_v3.query_json` or another `public.eql_v3_json_search`). |
| `doc -> 'sel'::text` / `doc -> N` | `eql_v3."->"`                                     | field / 0-based array-element access; returns `public.eql_v3_json_entry`. |
| `doc ->> 'sel'::text`            | `eql_v3."->>"`                                     | the matching entry serialized as `text` (ciphertext JSON, **not** decrypted plaintext). |
| entry-to-entry `=` `<>`          | fail-loud blocker                                      | extracted path entries carry no exact value selector; use `@>` containment for equality. |
| extracted-leaf `<` `<=` `>` `>=` | `eql_v3.ord_term(public.eql_v3_json_entry)`       | ordered comparison on an extracted String / Number leaf. |
| `MIN` / `MAX` of extracted leaf  | `eql_v3.min(public.eql_v3_json_entry)` / `max`         | over an extracted ordered leaf. |
| `eql_v3.jsonb_path_query(doc, sel)` | path query                                      | set-returning; yields encrypted entries. Also `jsonb_path_query_first`, `jsonb_path_exists`. |
| `eql_v3.jsonb_array_length/elements(doc)` | array helpers                  | length / set-returning encrypted elements. (`jsonb_array_elements_text` was removed in 3.0 — a bare-ciphertext stream is no longer independently decryptable.) |

> **Typed operands (important).** The selector / needle operand must carry a **known type** — a typed parameter (`$1`, which the Proxy supplies) or an explicit cast (`doc -> 'sel'::text`, `$1::eql_v3.query_json`). A bare untyped literal (`doc -> 'sel'`) resolves to the **native `jsonb` operator** (PostgreSQL reduces the `public.eql_v3_json_search` domain to its `jsonb` base type for an unknown-typed RHS) and silently returns native jsonb semantics instead of the encrypted operator.

### Blocked JSONB operators

These native PostgreSQL JSONB operators are **blocked** on `public.eql_v3_json_search` (they `RAISE`, rather than falling through to native whole-document semantics): root-document `=` `<>` `<` `<=` `>` `>=`, and `?`, `?|`, `?&`, `@?`, `@@`, `#>`, `#>>`, `-`, `#-`, `||`. Use containment (`@>`), field access (`->` / `->>`), or the `eql_v3.jsonb_path_*` functions instead.

See [EQL with JSON and JSONB](./json-support.md) for worked examples.

---

## See also

- [EQL Functions Reference](./eql-functions.md) — full list of functions and operators.
- [Database Indexes for Encrypted Columns](./database-indexes.md) — functional-index and GIN recipes, plus performance guidance.
- [EQL with JSON and JSONB](./json-support.md) — end-to-end `public.eql_v3_json_search` examples.
- Client-side searchable-encryption configuration — [CipherStash Stack schema reference](https://cipherstash.com/docs/stack/cipherstash/encryption/schema) and [CipherStash Proxy](https://github.com/cipherstash/proxy).

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20sql-support.md)
