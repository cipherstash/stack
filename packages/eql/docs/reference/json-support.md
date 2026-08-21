# EQL with JSON and JSONB

EQL encrypts, decrypts, and searches JSON / JSONB documents using structured encryption (ste_vec), exposed as the **`public.eql_v3_json_search`** document domain. A `public.eql_v3_json_search` column stores an encrypted document whose every path is searchable — without decryption — via containment (which provides **exact field equality for every value type**), field/array access, and range comparisons on extracted leaves.

## On this page

- [Storing encrypted JSON](#storing-encrypted-json)
- [Typed operands (important)](#typed-operands-important)
- [Querying `public.eql_v3_json_search`](#querying-publiceql_v3_json_search)
  - [Containment queries (`@>`, `<@`)](#containment-queries--)
  - [Selector-with-constraint range queries](#selector-with-constraint-range-queries-index-accelerated)
  - [Field extraction (`jsonb_path_query`)](#field-extraction-jsonb_path_query)
  - [JSON path operators (`->`, `->>`)](#json-path-operators----)
  - [Array operations](#array-operations)
  - [Grouping data](#grouping-data)
- [`eql_v3` functions for JSONB and ste_vec](#eql_v3-functions-for-jsonb-and-ste_vec)
- [How ste_vec indexing works](#how-ste_vec-indexing-works)

## Storing encrypted JSON

Type the column as `public.eql_v3_json_search`. There is no database-side `add_search_config` step — which terms a document carries is decided by the encryption client ([CipherStash Proxy](https://github.com/cipherstash/proxy) / [CipherStash Stack](https://github.com/cipherstash/stack)); typing the column as `public.eql_v3_json_search` is what makes the encrypted operators and functions resolve.

```sql
CREATE TABLE users (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  encrypted_json public.eql_v3_json_search
);
```

Insert and read through CipherStash Proxy or CipherStash Stack, which encrypt the document into the ste_vec payload on write and decrypt it on read:

```sql
SELECT encrypted_json FROM users;   -- decrypted by the client on the way out
```

The stored value is the encrypted ste_vec document — an envelope (`v`, `i`, and the key header `h`) plus the `sv` array of encrypted, per-path entries. The document has **no root `c`**: the root document ciphertext lives on the root `sv` entry. Every entry encrypts under the document's single data key, so the key-retrieval material is stored **once** in `h` rather than repeated inside every entry; each entry's `c` is the raw AEAD output, and its nonce is derived from its own selector. Decrypting any entry therefore needs `h` + the entry's `s` + `c` — the client reassembles these (the `->` extractor grafts `h` onto every entry it returns, so an extracted `public.eql_v3_json_entry` stays self-contained decryptable).

## Typed operands (important)

`public.eql_v3_json_search` is a PostgreSQL **domain over `jsonb`**. PostgreSQL resolves `domain OP untyped_literal` to the **native** `jsonb` operator, because it flattens the domain to its base type when the right-hand side is an unknown-typed literal. A bare literal therefore **bypasses the encrypted operator (and the blockers) and silently returns native jsonb semantics** — typically a root-key lookup that yields `NULL` — instead of querying the encrypted document or raising.

Always give the operand a known type:

```sql
-- ✅ correct — typed operand resolves to the eql_v3 operator
WHERE doc @> $1::eql_v3.query_json
WHERE doc -> 'age_selector'::text > $1::eql_v3.query_integer_ord
WHERE doc -> $1::text > $2::eql_v3.query_integer_ord   -- selector bound as a text
                                                       -- parameter (the CipherStash
                                                       -- Proxy interface)

-- ⚠ wrong — the bare untyped selector resolves to native jsonb -> text, so the
-- extraction is a plain root-key lookup (NULL) and the comparison falls through
-- to native jsonb semantics instead of the encrypted operator
WHERE doc -> 'email' > $1::eql_v3.query_integer_ord
```

(Note there is no entry-level `=` — exact field equality goes through containment; see [Grouping data](#grouping-data) for why, and the range example above for what extracted entries *do* support.)

This is **intrinsic to the domain type-kind**, not a bug: the only way to remove it would be to make `public.eql_v3_json_search` a base type (losing free `jsonb` interop). The CipherStash Proxy always passes typed parameters, so applications routing through the Proxy are unaffected; the caveat matters only for hand-written ad-hoc SQL.

## Querying `public.eql_v3_json_search`

### Containment queries (`@>`, `<@`)

`@>` tests whether the encrypted document contains a structure; `<@` is the reverse. The needle must be **typed** — another `public.eql_v3_json_search` or an `eql_v3.query_json`:

```sql
SELECT * FROM examples
WHERE encrypted_json @> $1::eql_v3.query_json;
```

This is the encrypted equivalent of the plaintext `jsonb_column @> '{"top":{"nested":["a"]}}'`.

**Containment is also the exact field-equality mechanism.** Each leaf's *value* is tokenized into its own selector (a value-inclusive selector `SEL(type-tag ‖ path ‖ canonical(value))`), so a value-selector's *presence* in the stored document is an exact, injective match. To match a field exactly, the client emits a `query_json` needle carrying that value selector, and the same `@>` engages — exactly for **every** value type, including `text`, `bigint`, and `numeric` (`"café"` ≠ `"cafe"`; `9007199254740993` ≠ `9007199254740992`):

```sql
-- account.email exactly equals a value — exact for every type, via containment
SELECT * FROM examples WHERE encrypted_json @> $1::eql_v3.query_json;
```

> **Trust boundary:** PostgreSQL can verify only selector presence; it cannot
> recover the plaintext or prove that a selector represents the path/value a
> caller claims. Exact equality therefore depends on CipherStash Client or
> CipherStash Proxy generating the `query_json` needle for the correct column,
> path, type, and canonical value. Hand-crafted or untrusted needles are opaque
> selector-set queries, not database-validated plaintext predicates.

For large tables, back containment with a GIN index. The typed `@>` overload inlines to a native `jsonb @>` over `eql_v3.to_ste_vec_query(col)::jsonb`, so a GIN index on the same expression engages:

```sql
CREATE INDEX examples_json_gin
  ON examples USING gin ((eql_v3.to_ste_vec_query(encrypted_json)::jsonb) jsonb_path_ops);
ANALYZE examples;

SELECT * FROM examples WHERE encrypted_json @> $1::eql_v3.query_json;
```

See [GIN Indexes for JSONB Containment](./database-indexes.md#gin-indexes-for-jsonb-containment) for the full setup.

### Field extraction (`jsonb_path_query`)

Extract fields by **selector hash** — a deterministic identifier the crypto layer emits for a JSON path (not a path string like `$.field`). Selectors are generated during encryption by CipherStash Proxy / CipherStash Stack.

```sql
-- All entries matching a selector
SELECT eql_v3.jsonb_path_query(encrypted_json, 'abc123def456...') FROM examples;

-- First match only
SELECT eql_v3.jsonb_path_query_first(encrypted_json, 'abc123def456...') FROM examples;

-- Does the selector exist?
SELECT eql_v3.jsonb_path_exists(encrypted_json, 'abc123def456...') FROM examples;
```

### JSON path operators (`->`, `->>`)

`->` returns the matched entry as a `public.eql_v3_json_entry`; `->>` returns it serialized as `text` (ciphertext JSON, not decrypted plaintext). The selector operand must be typed:

```sql
-- Field access by selector (returns public.eql_v3_json_entry)
SELECT encrypted_json -> 'selector_hash'::text FROM examples;

-- Field access as text (returns the entry as ciphertext text)
SELECT encrypted_json ->> 'selector_hash'::text FROM examples;

-- Array element by 0-based index (returns public.eql_v3_json_entry)
SELECT encrypted_json -> 0 FROM examples;
```

An extracted `public.eql_v3_json_entry` supports ordered comparison with
**another extracted entry** through `<` / `<=` / `>` / `>=` and
`eql_v3.ord_term` (String / Number leaves):

```sql
SELECT * FROM examples
WHERE encrypted_json -> 'a_selector'::text < encrypted_json -> 'b_selector'::text;
```

Entry-to-entry `=` / `<>` are fail-loud blockers. A path entry carries no value
selector, and comparing its `op` ordering bytes would be lossy for
`text` / `bigint` / `numeric`. For exact field equality, use document
containment (above), which is exact for every type.

### Selector-with-constraint range queries (index-accelerated)

An extracted leaf compares directly against a **per-type ordering operand** in natural operator form, so a single-field RANGE constraint (`col -> '$.age' > 21`) is expressible without a whole-entry needle — and matches a functional index on `eql_v3.ord_term`:

```sql
SELECT * FROM examples
WHERE encrypted_json -> 'age_selector'::text  >  $1::eql_v3.query_integer_ord;   -- range
SELECT * FROM examples
WHERE encrypted_json -> 'name_selector'::text >  $1::eql_v3.query_text_ord;       -- text range
```

Both sides resolve through `eql_v3.ord_term` — byte-comparison on the deterministic CLLW-OPE `op` term. A functional index `USING btree (eql_v3.ord_term(encrypted_json -> 'selector'::text))` engages for every one of them.

**Equality is not an extract operation.** `=` / `<>` between two extracted
entries, or between an extracted entry and a query operand
(`-> 'sel' = $1::query_<T>_ord`), **raise `operator is not supported`**. An
extracted leaf is a *path* entry carrying no value selector, so it cannot
express exact equality—and `op` byte-comparison is lossy for
`text` / `bigint` / `numeric` (`"café"` == `"cafe"`;
`9007199254740993` == `9007199254740992`). The operators are blocked rather
than omitted because an unbound `=` could fall back to native whole-envelope
`jsonb = jsonb`. Route field equality through document containment instead
(`@> $1::eql_v3.query_json`), which is exact for every type.

| leaf family | extract-surface operators | exact equality |
|---|---|---|
| `integer`, `smallint`, `bigint`, `numeric`, `real`, `double`, `text` | `<` `<=` `>` `>=` (ranges) | via document containment (`@>`) |
| `date`, `timestamp` | *none* — a date-in-JSON is a text leaf | via containment on the text leaf |

> **Dates and timestamps in JSON are strings.** JSON (RFC 8259) has no date or timestamp type — applications marshal temporal values into ISO-8601 / RFC 3339 strings, so a "date leaf" is a **text leaf**: order it via `eql_v3.query_text_ord` (ISO-8601 string order *is* chronological order) and match it exactly via document containment (`@>`). The temporal operands (`eql_v3.query_date_ord`, `eql_v3.query_timestamp_ord`, and their `_ope` twins) are not part of this surface — every operator on them raises `operator is not supported`. No client can produce a temporal SteVec ordering term anyway, so nothing is lost.

The ordering operands are `eql_v3.query_<T>_ord` and its explicit twin `eql_v3.query_<T>_ord_ope`, for the families that serve ordering. `eql_v3.query_text_search` is also blocked on this surface (SteVec has no match/bloom capability — a leaf carries no `match_term`). The scalar `eql_v3.query_<T>_eq` operand is **not** bound to `public.eql_v3_json_entry`: extract-surface equality does not exist; field equality is document containment.

> **The range operand must be encrypted for the same column, and as the same JSON scalar type, as the leaf.** Field scoping comes from the `->` extraction, not the operand: an `op` term encodes the plaintext and the column, carrying no selector, so one operand is comparable against whichever leaf you extract — which also means an operand encrypted for a *different column*, or a different JSON scalar type (a number term against a string leaf), has non-corresponding bytes and **silently returns zero rows**. The SQL layer only compares terms and cannot detect the mismatch; aligning the operand's column and type with the leaf is the client's / CipherStash Proxy's responsibility.
>
> **"Same JSON scalar type" is stricter than it sounds: encrypt numbers as *floats*.** A stored JSON number leaf is always f64-encoded; cipherstash-client encodes a **`Float`** plaintext identically, but an **`Int`** plaintext takes a different (raw-cast) path, so an integer-encrypted range operand against an integer JSON field produces non-corresponding bytes and silently matches zero rows. For a JSON *number* leaf, encrypt the range operand as a float (`2` → `2.0`); for a JSON *string* leaf, as text.

### Array operations

```sql
-- Length of an encrypted array node
SELECT eql_v3.jsonb_array_length(encrypted_array_field) FROM examples;

-- Elements as encrypted entries (each carries s, c, and the grafted key
-- header h — the complete decryption unit)
SELECT eql_v3.jsonb_array_elements(encrypted_array_field) FROM examples;
```

> **Note (3.0.0):** `eql_v3.jsonb_array_elements_text` (a `SETOF text` stream of
> bare per-element ciphertexts) was **removed** with the envelope wire format.
> An entry's `c` is raw AEAD output whose nonce derives from the entry's `s`
> and whose key material lives in the document's `h`, so a bare ciphertext
> stream is not decryptable. Use `eql_v3.jsonb_array_elements`, whose entry rows
> carry `s`, `c`, and the grafted `h`.

### Grouping data

Exact `GROUP BY` / `DISTINCT` on an extracted encrypted-JSON field is not
available: the extracted path entry has no value selector, and its `op` term is
not an exact equality key. Decrypt before grouping, or model the value as a
separate equality-indexed scalar column when server-side grouping is required.

`MIN` / `MAX` over an extracted ordered leaf use the `eql_v3.min(public.eql_v3_json_entry)` / `max` aggregates.

## `eql_v3` functions for JSONB and ste_vec

### Core functions

- **`eql_v3.ste_vec(val jsonb) RETURNS jsonb[]`** — extracts the ste_vec index array from an encrypted payload.
- **`eql_v3.jsonb_document_contains(a public.eql_v3_json_search, b public.eql_v3_json_search) RETURNS boolean`** — true if every selector in `b` is present in `a` (selector-subset containment); backs the `@>` operator.
- **`eql_v3.jsonb_contains(a jsonb, b jsonb)` / `eql_v3.jsonb_contained_by(a jsonb, b jsonb)`** — function-form containment entrypoints for platforms that cannot type an operator call (Supabase PostgREST RPC, for example); same result as `@>` / `<@` (a parity test pins this).
- **`eql_v3.jsonb_array(val jsonb) RETURNS jsonb[]`** — function-form array accessor for the same platforms.
- **`eql_v3.to_ste_vec_query(val public.eql_v3_json_search) RETURNS eql_v3.query_json`** — the GIN-indexable query shape `@>` inlines to.
- **`eql_v3.meta_data(val jsonb)`** — envelope accessor: returns `{i, v, h}` (the key header `h` included so an extracted entry can be decrypted). **`eql_v3.ciphertext(val jsonb)`** — returns the `c` field; on the ste_vec surface `c` is raw AEAD output, decryptable only together with the entry's `s` and the document `h`. **`eql_v3.selector(val jsonb)` / `(entry public.eql_v3_json_entry)`** — selector accessor.

### Path query functions

- **`eql_v3.jsonb_path_query(val jsonb, selector text)`** — entries matching the selector.
- **`eql_v3.jsonb_path_query_first(val jsonb, selector text)`** — first match.
- **`eql_v3.jsonb_path_exists(val jsonb, selector text) RETURNS boolean`** — selector presence.

### Array functions

- **`eql_v3.jsonb_array_length(val jsonb) RETURNS integer`**
- **`eql_v3.jsonb_array_elements(val jsonb)`** — one `public.eql_v3_json_entry` row per element (the key header `h` grafted on so each is self-contained decryptable).

### Entry comparison / aggregate

- **`eql_v3.ope_term(entry public.eql_v3_json_entry)`** — low-level access to the deterministic `op` bytes; `NULL` for a term-less leaf. It does not back an equality operator and is lossy for `text` / `bigint` / `numeric`; use only for deliberate OPE-equivalence bucketing, never exact equality. The old `eq_term(json_entry)` name remains only as a deprecated compatibility alias.
- **`eql_v3.ord_term(entry public.eql_v3_json_entry)`** — ordering term (backs `<` … `>=`); returns SQL `NULL` when the leaf carries no `op` term.
- **`eql_v3.min(public.eql_v3_json_entry)` / `eql_v3.max(...)`** — MIN / MAX over an extracted ordered leaf.

For GIN-indexable JSONB containment, see [GIN Indexes for JSONB Containment](./database-indexes.md#gin-indexes-for-jsonb-containment) (`USING gin ((eql_v3.to_ste_vec_query(col)::jsonb) jsonb_path_ops)`).

### Blocked operators

The native `jsonb` operators `?`, `?|`, `?&`, `@?`, `@@`, `#>`, `#>>`, `-`, `#-`, `||`, root-document `=` `<>` `<` `<=` `>` `>=`, single-entry containment, containment against a native `jsonb` operand (`doc @> jsonb` and every other operand mix, both directions), and entry-to-entry `=` / `<>` are **blocked** — they `RAISE` rather than running plaintext-jsonb or lossy ordering-term equality semantics. Use document containment for exact equality and extracted-entry ordering only for ranges.

> **`eql_v3_json_search` vs `eql_v3_json`:** this page is about the *queryable* document domain. A sibling `public.eql_v3_json` domain also exists — **storage only**, every operator a blocker. Use it for encrypted JSON you never query in the database; use `eql_v3_json_search` when you need containment/selector queries.

## How ste_vec indexing works

Structured Encryption (ste_vec) makes a JSONB document searchable by:

1. **Flattening the structure** — each unique path to a leaf gets a deterministic selector hash.
2. **Tokenizing paths and values into selectors** — each path emits a *path* entry (`{s, c}`, plus an `op` CLLW-OPE ordering term for String / Number leaves), and each value emits a *value* entry whose selector `SEL(type-tag ‖ path ‖ canonical(value))` bakes in the value — so the selector's presence is an exact, injective equality match. (The per-value `hm` equality term was retired in 3.0.0; exact equality is now value-selector presence, not a MAC comparison.) A value entry's `c` encrypts a fixed sentinel, not the value — the value is already committed by the selector; the sentinel keeps a value entry distinguishable from a genuine empty-string leaf.
3. **Storing the `sv` array** — all encrypted entries live in the document's `sv` vector, alongside the once-per-document key header `h`. Every entry encrypts under the document's single data key with a nonce derived from its own selector, so equal values at different paths — and the sentinel across value entries — never produce identical ciphertexts.

**Example document:**

```json
{
  "account": {
    "email": "alice@example.com",
    "roles": ["admin", "owner"]
  }
}
```

**Creates selectors for** `$` (root), `$.account`, `$.account.email` (and its value), `$.account.roles` (and each role value).

**Querying:** containment (`@>`) checks that all required selectors exist in the target's `sv` array (a value selector's presence is the exact-equality match):

```sql
-- Find records where account.email = "alice@example.com"
WHERE encrypted_data @> $1::eql_v3.query_json;
```

Encryption and selector generation are handled by CipherStash Proxy or CipherStash Stack, not by EQL directly.

---

### Didn't find what you wanted?

[Click here to let us know what was missing from our docs.](https://github.com/cipherstash/encrypt-query-language/issues/new?template=docs-feedback.yml&title=[Docs:]%20Feedback%20on%20json-support.md)
