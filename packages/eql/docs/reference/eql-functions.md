# EQL Functions Reference

A reference for the functions and operators EQL exposes for querying encrypted data in PostgreSQL. The surface lives in the **`eql_v3`** schema and is organised around the per-scalar encrypted-domain types (`public.<T>` and variants) and the encrypted-JSON document type (`public.eql_v3_json_search`).

> **There is no database-side configuration API.** Which index terms a value carries is chosen by the encryption client ([CipherStash Proxy](https://github.com/cipherstash/proxy) / [CipherStash Stack](https://github.com/cipherstash/stack)); a column's capability is fixed by the **domain variant** you type it as. See [SQL support matrix](./sql-support.md) for the variant/operator table.

## Table of Contents

- [Operators](#operators)
- [Function Equivalents](#function-equivalents)
- [Index Term Extraction](#index-term-extraction)
- [Encrypted JSON (`public.eql_v3_json_search`)](#encrypted-json-publiceql_v3_json_search)
- [Aggregate Functions](#aggregate-functions)
- [Diagnostics](#diagnostics)

---

## Operators

EQL overloads standard PostgreSQL operators on the encrypted-domain types. Type the column as the variant that carries the term, and the operator resolves (and engages a matching [functional index](./database-indexes.md)). Operands must be typed — a typed parameter (`$1`, supplied by the Proxy) or an explicit cast — or they fall through to native `jsonb`.

### Equality — `=` `<>`

On `public.<T>_eq`, `public.<T>_ord` / `_ord_ope` / `_ord_ore`, and `public.eql_v3_text_search` / `_search_ore`. Equality compares the `hm` term where the domain carries one (the `_eq` domains and the text ordering/search domains) and otherwise compares the ordering term directly — the numeric-and-time ordering terms are injective, so those domains carry no `hm` and `eql_v3.eq` inlines to an ordering-term comparison:

```sql
SELECT * FROM users WHERE encrypted_email = $1;
SELECT * FROM users WHERE encrypted_email = $1::eql_v3.query_text_eq;
SELECT * FROM users WHERE encrypted_email <> $1;
```

(Explicit casts use the **query-operand** domain `eql_v3.query_<T>_<variant>` — query payloads are term-only and fail the storage domain's CHECK, which requires the ciphertext key `c`.)

### Range — `<` `<=` `>` `>=`

On `public.<T>_ord` / `_ord_ope` / `_ord_ore` and `public.eql_v3_text_search` / `_search_ore` (carry an ordering term):

```sql
SELECT * FROM events WHERE encrypted_at <  $1::eql_v3.query_timestamp_ord;
SELECT * FROM events WHERE encrypted_at >= $1::eql_v3.query_timestamp_ord;

-- Ordering (write the sort key as the extractor to engage the index — see Database Indexes)
-- `encrypted_at` is a `timestamp_ord` column, so its extractor is `ord_term`.
SELECT * FROM events ORDER BY eql_v3.ord_term(encrypted_at) DESC;
```

### Text match — `@@`

On `public.eql_v3_text_match` / `public.eql_v3_text_search` /
`public.eql_v3_text_search_ore` (carry a `bf` bloom term). This is **probabilistic ngram-bloom matching** (`eql_v3.matches`), not SQL `LIKE`, not JSONB containment, and not the containment operators — `@>` / `<@` **raise** on these domains:

```sql
SELECT * FROM docs WHERE encrypted_content @@ $1::eql_v3.query_text_match;
```

`LIKE` / `ILIKE` (`~~` / `~~*`) are **not** part of the `eql_v3` surface — use `@@`.

### JSON containment / path — `public.eql_v3_json_search`

`@>` / `<@`, `->` / `->>`, and the path functions on `public.eql_v3_json_search` are documented in [EQL with JSON and JSONB](./json-support.md).

---

## Function Equivalents

For environments that cannot use custom operators (e.g. some managed platforms), each operator has a function form, generated per domain variant. They take the same domain types as the operators above:

```sql
eql_v3.eq(a, b)   -- =        (on _eq / _ord / _ord_ope / _ord_ore / text_search / text_search_ore)
eql_v3.neq(a, b)  -- <>
eql_v3.lt(a, b)   -- <        (on _ord / _ord_ope / _ord_ore / text_search / text_search_ore)
eql_v3.lte(a, b)  -- <=
eql_v3.gt(a, b)   -- >
eql_v3.gte(a, b)  -- >=
eql_v3.matches(a, b)        -- @@  (bloom fuzzy match, on text_match / text_search / text_search_ore)
```

JSON document containment has its own function forms (`eql_v3.jsonb_contains` / `jsonb_contained_by` / `jsonb_document_contains`) — see [EQL with JSON and JSONB](./json-support.md).

**Example:**

```sql
SELECT * FROM users WHERE eql_v3.eq(encrypted_email, $1::eql_v3.query_text_eq);
SELECT * FROM events WHERE eql_v3.lt(encrypted_at, $1::eql_v3.query_timestamp_ord);
```

There are no `like` / `ilike` function forms — text matching is `eql_v3.matches` (`@@`) on a `text_match` value.

---

## Index Term Extraction

These extract the index term from an encrypted-domain value. They are generated per eq/ord/match-capable variant of every scalar type, are inlinable (so a functional index on the extractor engages), and return the self-contained `eql_v3_internal` SEM index-term types. See [Adding a Scalar Encrypted-Domain Type](./adding-a-scalar-encrypted-domain-type.md).

```sql
-- Equality term (hm)
eql_v3.eq_term(a public.eql_v3_integer_eq)        RETURNS eql_v3_internal.hmac_256
-- Ordering term, CLLW-OPE (op) — the default
eql_v3.ord_term(a public.eql_v3_integer_ord)      RETURNS eql_v3_internal.ope_cllw
eql_v3.ord_term(a public.eql_v3_integer_ord_ope)  RETURNS eql_v3_internal.ope_cllw
-- Ordering term, block-ORE (ob)
eql_v3.ord_term_ore(a public.eql_v3_integer_ord_ore)      RETURNS eql_v3_internal.ore_block_256
-- Text-match term (bf)
eql_v3.match_term(a public.eql_v3_text_match)  RETURNS eql_v3_internal.bloom_filter
```

**Example — functional indexes on the extracted terms** (see [Database Indexes](./database-indexes.md)):

```sql
CREATE INDEX ON users USING hash  (eql_v3.eq_term(salary_eq));
CREATE INDEX ON users USING btree (eql_v3.ord_term(salary_ord));
CREATE INDEX ON users USING gin   (eql_v3.match_term(name_match));
```

> The full per-domain operator / wrapper / blocker surface (and the `public.<T>` / `_eq` / `_ord` / `_ord_ope` / `_ord_ore` domain types themselves) is documented in [SQL support](./sql-support.md#encrypted-domain-scalar-types-publict) and the [scalar encrypted-domain type reference](./adding-a-scalar-encrypted-domain-type.md).

> **`eq_term` / `ord_term` also back `SELECT DISTINCT`.** [CipherStash Proxy](https://github.com/cipherstash/proxy) keys `DISTINCT` on an encrypted column by `eq_term` (dedup by plaintext equality, not raw ciphertext) and, when combined with `ORDER BY` on an encrypted column, additionally requires `ord_term`. A domain with no `eq_term` (e.g. the storage-only `public.eql_v3_boolean`) cannot be deduplicated. See [`GROUP BY` / `DISTINCT`](./database-indexes.md#group-by--distinct) for the rewrite Proxy performs.

The `public.eql_v3_json_search` document type extracts its entry ordering term
with `eql_v3.ord_term(public.eql_v3_json_entry)`. The low-level
`eql_v3.ope_term(public.eql_v3_json_entry)` exposes the same lossy `op` bytes for
explicit OPE-equivalence inspection only; entry equality operators are blocked.
`eq_term(json_entry)` is retained as a deprecated compatibility alias.
See [json-support.md](./json-support.md).

---

## Encrypted JSON (`public.eql_v3_json_search`)

The full encrypted-JSONB function surface — containment, `->` / `->>`, `eql_v3.jsonb_path_query` / `_first` / `_exists`, `eql_v3.jsonb_array_length` / `_elements`, `eql_v3.to_ste_vec_query`, `eql_v3.jsonb_document_contains`, the envelope accessors `eql_v3.meta_data` / `eql_v3.ciphertext` / `eql_v3.selector`, and the GIN helpers — is documented in **[EQL with JSON and JSONB](./json-support.md)**. (`eql_v3.jsonb_array_elements_text` was removed in 3.0 — a bare-ciphertext stream is no longer independently decryptable; use `eql_v3.jsonb_array_elements`.)

---

## Aggregate Functions

### `eql_v3.min()` / `eql_v3.max()` (per-domain)

Returns the minimum or maximum encrypted value on an ordered encrypted-domain column. Defined per ord-capable variant of every scalar type (`public.<T>_ord`, `public.<T>_ord_ope`, `public.<T>_ord_ore`, plus `public.eql_v3_text_search` / `_search_ore`); the input type selects the aggregate via PostgreSQL's overload resolution.

```sql
-- integer — generated for every ordered variant of every scalar type.
eql_v3.min(public.eql_v3_integer_ord)      RETURNS public.eql_v3_integer_ord
eql_v3.max(public.eql_v3_integer_ord)      RETURNS public.eql_v3_integer_ord
eql_v3.min(public.eql_v3_integer_ord_ore)  RETURNS public.eql_v3_integer_ord_ore
eql_v3.max(public.eql_v3_integer_ord_ore)  RETURNS public.eql_v3_integer_ord_ore
```

Comparison routes through the variant's `<` / `>` operator, which uses that variant's ordering term — the `op` CLLW-OPE term on `_ord` / `_ord_ope`, the `ob` block-ORE term on `_ord_ore` — no decryption. The state function is `STRICT`, so `NULL` inputs are skipped and an all-`NULL` input set returns `NULL`.

**Example:**

```sql
-- ord-capable column (e.g. price_encrypted typed as public.eql_v3_integer_ord)
SELECT eql_v3.min(price_encrypted) FROM products;
SELECT eql_v3.max(price_encrypted) FROM products WHERE category = 'electronics';

-- On a generic jsonb column, cast to the right domain
SELECT eql_v3.min(price_jsonb::public.eql_v3_integer_ord) FROM products;
```

`MIN` / `MAX` over a value extracted from an `public.eql_v3_json_search` document use `eql_v3.min(public.eql_v3_json_entry)` / `max` — see [json-support.md](./json-support.md).

`SUM` / `AVG` and other arithmetic aggregates are **not** supported on encrypted columns (they would require homomorphic encryption) — decrypt at the application boundary. `MIN` / `MAX` only need comparator-revealing terms.

**See also:** [SQL support matrix](./sql-support.md) for the per-variant capability table.

---

## Diagnostics

- **`eql_v3.version() RETURNS text`** — the installed EQL release version, baked in at build time. First check when behaviour doesn't match the docs: `SELECT eql_v3.version();`
- **`eql_v3.lints() RETURNS SETOF record (severity, category, object_name, message)`** — installation self-checks (missing opclass, misconfigured objects, …): `SELECT * FROM eql_v3.lints();`

---

## See Also

- [EQL Configuration Tutorial](../tutorials/proxy-configuration.md) — setting up encrypted columns end to end.
- [Database Indexes](./database-indexes.md) — functional-index recipes and performance.
- [JSON/JSONB Support](./json-support.md) — `public.eql_v3_json_search` worked examples.
- [SQL support matrix](./sql-support.md) — operators by domain variant.
- [Payload / wire format](../../crates/eql-bindings/README.md) — canonical encrypted-payload wire types (envelope + index terms).
- Client-side index configuration — [CipherStash Stack schema reference](https://cipherstash.com/docs/stack/cipherstash/encryption/schema).

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20eql-functions.md)
