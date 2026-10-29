# EQL Functions Reference

A reference for the functions and operators EQL exposes for querying encrypted data in PostgreSQL. The surface lives in the **`eql_v3`** schema and is organised around the per-scalar encrypted-domain types (`public.<T>` and variants) and the encrypted-JSON document type (`public.eql_v3_json_search`).

> **There is no database-side configuration API.** Which index terms a value carries is chosen by the encryption client ([CipherStash Proxy](https://github.com/cipherstash/proxy) / [CipherStash Stack](https://github.com/cipherstash/stack)); a column's capability is fixed by the **domain variant** you type it as. See [SQL support matrix](./sql-support.md) for the variant/operator table.

## Table of Contents

- [Operators](#operators)
- [Function Equivalents](#function-equivalents)
- [Index Term Extraction](#index-term-extraction)
- [Encrypted JSON (`public.eql_v3_json_search`)](#encrypted-json-publiceql_v3_json_search)
- [Range queries in EQL v4: `eql_v4.between`](#range-queries-in-eql-v4-eql_v4between)
- [One array element in EQL v4: `eql_v4.json_tree_element_match`](#one-array-element-in-eql-v4-eql_v4json_tree_element_match)
- [A compiled predicate in EQL v4: `eql_v4.json_tree_match`](#a-compiled-predicate-in-eql-v4-eql_v4json_tree_match)
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

## Range queries in EQL v4: `eql_v4.between`

EQL v4 is the same SQL installed as the `eql_v4` schema, for values written by Stack Encrypt (`release/cipherstash-encrypt-v4.sql`). Everything above applies to it with `eql_v4` in place of `eql_v3`. It also has one thing EQL v3 does not: a range query that is **one operand**, so a statement cannot pair the low bound of one query with the high bound of another.

Every ordered family has a **range query domain** per ordering term, beside its single-bound query domains:

| Range domain | Bounds | Column domains it applies to |
|---|---|---|
| `eql_v4.query_<T>_range_ore` | two block-ORE terms (`ob` hex strings) | `public.eql_v4_<T>_ord_ore`, `public.eql_v4_text_search_ore` |
| `eql_v4.query_<T>_range_ope` | two CLLW-OPE terms (`op` hex strings) | `public.eql_v4_<T>_ord`, `public.eql_v4_<T>_ord_ope`, `public.eql_v4_text_search` |

`<T>` is any ordered family: `integer`, `smallint`, `bigint`, `date`, `timestamp`, `numeric`, `text`, `real`, `double`. A range value is `{"v": 4, "i": {...}, "lo": <term>, "hi": <term>}`: each bound is the single-bound query domain's `ob` (ORE) or `op` (OPE) value, in a `{v, i, lo, hi}` envelope, with no ciphertext `c`. Both are one lowercase hex string: a block ORE bound starts `0202` or `0203` and an OPE bound `00` or `01`, and the range domain refuses any other bound with `check_violation` (an EQL v3 `ob` array among them; see [U-003](../upgrading/v3.1.md#u-003-an-order-term-is-one-hex-string-checked-when-it-is-written)). Stack Encrypt does not build this envelope yet: build it from the `ob` or `op` of two single-bound queries of the column's type.

```sql
-- true when lo <= column <= hi, both bounds included
eql_v4.between(a public.eql_v4_integer_ord_ore, r eql_v4.query_integer_range_ore) RETURNS boolean
eql_v4.between(a public.eql_v4_integer_ord,     r eql_v4.query_integer_range_ope) RETURNS boolean
eql_v4.between(a public.eql_v4_integer_ord_ope, r eql_v4.query_integer_range_ope) RETURNS boolean

```

`between` reads each bound with an internal accessor, `eql_v4_internal.lo(r)` and `eql_v4_internal.hi(r)`, which return the bound as the column's order term type. They are not part of the public surface.

**Example**, on an OPE column, which indexes on every install:

```sql
CREATE INDEX ON users USING btree (eql_v4.ord_term(age));

SELECT * FROM users WHERE eql_v4.between(age, $1::eql_v4.query_integer_range_ope);
```

- `eql_v4.between` is an inlinable SQL function, so the planner sees `ord_term(age) >= lo AND ord_term(age) <= hi`, and a btree on the column's order term serves it as one range scan: `eql_v4.ord_term(col)` for an OPE column (`_ord`, `_ord_ope`, and `_search` for text), `eql_v4.ord_term_ore(col)` for an ORE one (`_ord_ore`, and `_search_ore` for text).
- **An ORE column needs the `eql_v4_internal.ore_block_256` btree operator class**, for its index and so for an ORE range scan. The installer creates that class only when it runs with superuser privileges. Otherwise (on Supabase and other managed roles) it skips it and disables the ORE column domains and the ORE range domains: a value cast to `_ord_ore` or `_search_ore` raises `feature_not_supported`, naming the OPE and equality alternatives, and a value cast to a `query_<T>_range_ore` domain raises the same error, naming the family's `_range_ope` domain. On such an install, use an OPE column and its `_range_ope` domain, which need nothing more.
- Always write it schema-qualified. `BETWEEN` is an SQL keyword, so a bare `between(...)` does not parse.
- **Always cast the range parameter to its exact range domain**, as in `$1::eql_v4.query_integer_range_ore`. PostgreSQL resolves a function's domain arguments as their base type, `jsonb`, and every `between` overload takes jsonb domains. So an uncast `$1`, a `jsonb` parameter, or a range of the wrong term (an OPE range on an `_ord_ore` column) or the wrong family matches several overloads, and the statement fails with SQLSTATE 42725 (`function eql_v4.between(...) is not unique`) when it is parsed, before it runs. This differs from the single-bound operators: `col < $1` resolves an untyped `$1`.
- A `NULL` range matches no row. So does a range whose low bound is above its high bound, as with SQL `BETWEEN`; the SQL does not reorder the bounds.
- The `eql_bindings::v4` Rust types (`IntegerRangeOreQuery`, …) and the Go `encrypt/eql` types of the same names hold a range value, so it binds as one parameter.

---

## One array element in EQL v4: `eql_v4.json_tree_element_match`

On an encrypted JSON document (`public.eql_v4_json_search`), equality at a path is a containment needle (`col @> $1::eql_v4.query_json`) and a range at a path is an ordering over every match (`eql_v4.json_tree_path_query(col, $sel)`). Each can be answered by a different element of an array. So the two together ask "some contact is a Sibling, and some contact, maybe another one, has more than five calls", which is more rows than the plaintext query asks for:

```
exists($.contacts[*] ? (@.relationship == "Sibling" && @.calls > 5))
```

`eql_v4.json_tree_element_match` asks that question: **some one element** satisfies every part of the predicate.

```sql
eql_v4.json_tree_element_match(e public.eql_v4_json_search, p eql_v4.query_json_elements) RETURNS boolean

SELECT id FROM people
 WHERE eql_v4.json_tree_element_match(profile, $1::eql_v4.query_json_elements);
```

The operand `eql_v4.query_json_elements` is one parameter, `{"m": [member, …]}`, with one member per field of the element the predicate tests. Stack Encrypt's `element_match` query operator derives it. Each member holds:

- `t`: the tokens of a subtree read of the field's path through the array (`$.contacts[*].relationship`), one per element below a bound, in element order, then the **probe**, the token of the element at the bound;
- one or two bounds, each an ordering operand of the shape `eql_v4.query_json_leaf` holds: `gt` or `gte` for the lower bound, `lt` or `lte` for the upper. Equality is `gte` and `lte` at one value.

The function opens the row's document once, finds the node each token of every member names (the node `eql_v4.json_tree_subtree_indexed` returns for that token at `d = 0`), and pairs the members' nodes by `k`, the token's place in its list. The members' tokens were expanded to one bound in one order, so one `k` is one element. It is true when some `k` has a node for every member, inside that member's bounds. Nothing beneath a node is read.

- **Every field must be at an ordered path.** The comparison is on the ordering term, which a leaf carries only at a path the column's index orders (`ordered=`). Stack Encrypt refuses a member whose path is not ordered.
- **Equality is folded.** Equality here is the ordering term's equality: text compares after case and accents are folded (`"Sibling"`, `"sibling"` and `"Síbling"` are equal), and numbers compare as 64-bit floats, so two integers past 2⁵³ can be equal. That suits an enum-like field. Exact equality at a path is containment (`@>`), which this function does not provide per element.
- **An array longer than the bound raises.** The probe finds a node only when the array is longer than the bound. Then the function raises SQLSTATE `22023` (`invalid_parameter_value`) rather than answer over part of the array. Derive the operand with a bound past the longest array (`wildcard_bound`, 64 by default). The server tells the probe apart without any marker: every other token names the field, at the selector the member's bounds carry, and the probe names the element, at the array's selector.
- **No index serves it.** The function is PL/pgSQL, so the planner cannot see into it: it filters the rows it is given. Narrow them first with an indexed predicate on the same values, such as `col @> $1::eql_v4.query_json` for the equality half.
- **What it reveals** is what its parts reveal sent alone: a subtree read's tokens for each field, to the bound, with the probes, and each bound's ordering term. See [What a query shows](./json-tree-leakage.md#what-a-query-shows).

`eql_v4.json_tree_subtree_indexed(e, tokens text[], budget integer DEFAULT 64) RETURNS TABLE (k integer, entry public.eql_v4_json_entry)` is the subtree read with `k` on every row: the 1-based place in `tokens` of the token whose node the row sits in. `eql_v4.json_tree_subtree` is the same read without `k`. Past the budget, the sealed root comes back alone with `k = 0`. The same pairing by `k` can be written by hand, one parameter per token list and bound:

```sql
WHERE EXISTS (
  SELECT 1
  FROM eql_v4.json_tree_subtree_indexed(col, $1::text[], 0) AS r
  JOIN eql_v4.json_tree_subtree_indexed(col, $2::text[], 0) AS c ON c.k = r.k
  WHERE r.entry ->> 'd' = '0' AND c.entry ->> 'd' = '0'
    AND r.entry >= $3::eql_v4.query_json_leaf AND r.entry <= $3::eql_v4.query_json_leaf
    AND c.entry > $4::eql_v4.query_json_leaf)
```

That form does not check the probe: on a row whose array is longer than the bound it answers over the first elements only. Prefer the function.

---

## A compiled predicate in EQL v4: `eql_v4.json_tree_match`

On plaintext `jsonb`, one function answers a whole filter: `jsonb_path_match(col, $1, $2)`, a jsonpath predicate and its variables. An application that compiles a filter language into SQL can target that shape with one template and two parameters. On an encrypted JSON document (`public.eql_v4_json_search`) the database cannot evaluate a path or a value, so `@@` with a `jsonpath` is blocked, `jsonb_path_match` matches nothing ([Native jsonb functions read the envelope](json-tree-leakage.md#native-jsonb-functions-read-the-envelope)), and each question is its own operator. `eql_v4.json_tree_match` takes the whole filter as one parameter again: Stack Encrypt's `match` query operator compiles the jsonpath predicate on the client into a tree of those operators' operands, and the function evaluates the tree.

```sql
eql_v4.json_tree_match(e public.eql_v4_json_search, p eql_v4.query_json_predicate) RETURNS boolean

SELECT id FROM people WHERE eql_v4.json_tree_match(profile, $1::eql_v4.query_json_predicate);
SELECT id FROM people WHERE profile @@ $1::eql_v4.query_json_predicate;
```

The operand `eql_v4.query_json_predicate` is a boolean tree, serialised as JSON. Each node is an object with one key, which names its kind:

| node | true when | the same question, written out |
|---|---|---|
| `{"and": [node, …]}`, `{"or": [node, …]}` | every child is, or one child is | `… AND …`, `… OR …` |
| `{"not": node}` | the child is false | `NOT …` |
| `{"contains": needle}` | the document contains the needle, an `eql_v4.query_json` | `col @> needle` |
| `{"exists": selector}` | the document has a node at the path | `eql_v4.json_tree_path_exists(col, selector)` |
| `{"cmp": {"gt" \| "gte": leaf, "lt" \| "lte": leaf}}` | the first entry at the bounds' selector is inside every bound, each an `eql_v4.query_json_leaf` | `(col -> s) > gt AND (col -> s) < lt` |
| `{"elements": predicate}` | one element of an array satisfies every member, an `eql_v4.query_json_elements` | `eql_v4.json_tree_element_match(col, predicate)` |

Each leaf is checked by the CHECK of its own domain, and `and` and `or` take at least one child.

- **The answer is the hand-written WHERE's, NULL included.** `and`, `or` and `not` follow SQL's three-valued logic, and a `cmp` leaf is NULL where the path is absent or its node has no ordering term, as `(col -> s) < $1` is. Stack Encrypt compiles a jsonpath comparison so that the tree answers as `jsonb_path_match` does over the plaintext: `$.age < $n` is a node at `$.age`, not a JSON `null`, whose leaf compares; `$.age != $n` is a node there that is not the value. So an absent path is false under every comparison and `null` false under an ordering, as jsonpath has them, and an ordering of a boolean is unknown (NULL), as jsonpath's comparison of two kinds is.
- **Where the tree and jsonpath part.** In four places, each a property of the stored document or of the ordering terms. A path is read as written, so an array where the predicate names no `[*]` is not unwrapped as jsonpath's lax mode unwraps it (`$.tags == "a"` over `{"tags": ["a"]}` is true to jsonpath, false here). Nor is a value that is not an array wrapped where the predicate does name `[*]`: `$.tags[*] == "a"` over `{"tags": "a"}`, `exists($.tags[*])` over a scalar `tags` and `exists($.items[*] ? (@.sku == "x"))` over `{"items": {"sku": "x"}}` are true to jsonpath and false here, since `$.tags[*]` and `$.tags` have different selectors. A comparison of a string with a number, which jsonpath answers unknown, is false under `==` and true under `!=`, since the terms do not record a value's kind. An ordering compares the ordering terms, so text is case- and accent-folded, as every ordering at a path is; so does each condition of a filter with more than one, which compiles to an element leaf.
- **Cast the operand.** `col @@ $1::eql_v4.query_json_predicate`. An untyped operand on the right of `@@` matches both this operator and the blocked `jsonpath` one, and PostgreSQL refuses the statement with SQLSTATE 42725 (`operator is not unique`). A `jsonpath` operand still raises `operator @@ is not supported`.
- **Element leaves raise as their function does.** An array longer than the bound the predicate was compiled to raises SQLSTATE `22023`. Children are read in order and the read stops at the first child that decides the answer, so an element leaf the answer does not depend on is not read and does not raise.
- **The document is opened once.** It is decompressed once per row, and indexed once when the tree has an element leaf, however many leaves read it.
- **No index serves it.** The tree is evaluated inside a PL/pgSQL function, which the planner cannot see into: `json_tree_match` and `@@` filter the rows they are given, a sequential scan unless something else narrows them. The same predicate written out per operator (the right-hand column above) engages the GIN index on `eql_v4.json_tree_query(col)` and the functional btrees on `eql_v4.ord_term(col -> s)`, and is the fast path. Use `match` where one template matters more than the plan, and put an indexed predicate beside it where you can.
- **What it reveals** is what its leaves reveal sent one by one, and the boolean shape of the filter. See [What a query shows](./json-tree-leakage.md#what-a-query-shows).

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
