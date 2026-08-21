# Setting up encrypted columns with CipherStash Proxy

This tutorial walks through an end-to-end round trip: defining encrypted columns with EQL, configuring searchable encryption in the encryption client, and inserting and querying data through [CipherStash Proxy](https://github.com/cipherstash/proxy).

## How the pieces fit together

EQL (the `eql_v3` schema) and the encryption client split responsibilities:

| Responsibility | Owner |
| --- | --- |
| Encrypted-column **types** and **operators** (`public.eql_v3_text_eq`, `public.eql_v3_json_search`, `=`, `@>`, …) | **EQL** (this repo) |
| PostgreSQL **functional indexes** on the term extractors | **EQL** / you |
| **Which columns are encrypted** and **which index terms** each carries | The **encryption client** — [CipherStash Proxy](https://github.com/cipherstash/proxy) / [CipherStash Stack](https://github.com/cipherstash/stack) |
| Performing **encryption / decryption** on the wire | The encryption client |

> **There is no database-side configuration API in `eql_v3`.** Earlier versions configured searchable encryption with database functions (`add_column`, `add_search_config`). That surface has been removed — configuration now lives entirely in the client. The database's only job is to *store* the encrypted columns (typed as `eql_v3` domains) and *resolve* the encrypted operators.

## Prerequisites

- EQL installed into your database (the `eql_v3` surface). See the [README](../../README.md#installation).
- A running CipherStash Proxy (or a CipherStash Stack client) configured for your workspace.

## 1. Define encrypted columns

Type each column as the `eql_v3` domain **variant** for the capability you need (see the [SQL support matrix](../reference/sql-support.md) for the full list):

```sql
-- equality-searchable encrypted text
ALTER TABLE users  ADD COLUMN encrypted_email public.eql_v3_text_eq;

-- range/ordering-searchable encrypted timestamp
ALTER TABLE events ADD COLUMN encrypted_at    public.eql_v3_timestamp_ord;

-- full-text (bloom) searchable encrypted text
ALTER TABLE users  ADD COLUMN encrypted_name  public.eql_v3_text_match;

-- searchable encrypted JSON document
ALTER TABLE users  ADD COLUMN encrypted_profile public.eql_v3_json_search;
```

The variant fixes the column's searchable surface: `_eq` for `=`, `_ord` for ordering/range, `text_match` for `@@` token matching, `public.eql_v3_json_search` for encrypted JSON. The bare `public.eql_v3_<T>` variant is storage/decryption only.

## 2. Configure searchable encryption in the client

Tell the encryption client which columns to encrypt and which index terms to emit. This is **client-side configuration**, not SQL:

- **CipherStash Stack** — define the columns and indexes in the schema. See the [CipherStash Stack schema reference](https://cipherstash.com/docs/stack/cipherstash/encryption/schema).
- **CipherStash Proxy** — configure the encrypted columns in the Proxy's mapping config. See [CipherStash Proxy](https://github.com/cipherstash/proxy).

The terms the client emits (`hm` for equality, `op` for ordering — `ob` on the `_ord_ore` variants, `bf` for match, ste_vec for JSON) must match the column's domain variant from step 1 — e.g. configure an equality index for a column typed `public.eql_v3_text_eq`.

## 3. Create functional indexes

Index the term extractor so queries engage an index. Each capability has one recipe (full detail in [Database Indexes](../reference/database-indexes.md)):

```sql
CREATE INDEX users_email_eq  ON users  USING hash  (eql_v3.eq_term(encrypted_email));
CREATE INDEX events_at_ord   ON events USING btree (eql_v3.ord_term(encrypted_at));
CREATE INDEX users_name_match ON users USING gin   (eql_v3.match_term(encrypted_name));
ANALYZE users;
```

## 4. Insert and read through the Proxy

Run writes and reads through CipherStash Proxy. On insert, the Proxy encrypts the plaintext into the EQL payload (envelope `v`/`i`/`c` plus the configured index terms — see the [payload / wire format](../../crates/eql-bindings/README.md)); on read, it decrypts automatically.

```sql
-- Through the Proxy: the plaintext is encrypted on the way in
INSERT INTO users (encrypted_email)
VALUES ('{"v":3,"k":"pt","p":"test@example.com","i":{"t":"users","c":"encrypted_email"}}');

-- Through the Proxy: the ciphertext is decrypted on the way out
SELECT encrypted_email FROM users;
```

> Run directly against the database (bypassing the Proxy) and you will see the stored `jsonb` ciphertext payload, not plaintext.

## 5. Searching data

Type the query operand (the Proxy supplies typed parameters automatically; in hand-written SQL, cast). For the full operator surface see the [SQL support matrix](../reference/sql-support.md) and [EQL Functions Reference](../reference/eql-functions.md).

**Equality** (`public.eql_v3_text_eq`):

```sql
SELECT * FROM users WHERE encrypted_email = $1;
-- operator-free form (e.g. Supabase):
SELECT * FROM users WHERE eql_v3.eq(encrypted_email, $1::eql_v3.query_text_eq);
```

**Range / ordering** (`public.eql_v3_timestamp_ord`):

```sql
SELECT * FROM events WHERE encrypted_at < $1 ORDER BY eql_v3.ord_term(encrypted_at) DESC;
```

**Full-text match** (`public.eql_v3_text_match`) — bloom-filter token matching (`@@`), not `LIKE` (and not the containment operators, which raise on this domain):

```sql
SELECT * FROM users WHERE encrypted_name @@ $1::eql_v3.query_text_match;
```

**Encrypted JSON** (`public.eql_v3_json_search`) — containment and field access; see [EQL with JSON and JSONB](../reference/json-support.md):

```sql
SELECT * FROM users WHERE encrypted_profile @> $1::eql_v3.query_json;
SELECT encrypted_profile -> 'email_selector'::text FROM users;
```

## Frequently asked questions

**Can I use EQL without an encryption client?** No — encryption and decryption are performed by CipherStash Proxy or CipherStash Stack. EQL provides the database-side types, operators, and indexes; the client provides the crypto and the configuration.

**How do I choose which columns are searchable, and how?** In the client configuration (CipherStash Stack schema / Proxy mapping), matched to the column's `eql_v3` domain variant. There are no database-side `add_column` / `add_search_config` calls.

**Which operators are available on which column?** See the [SQL support matrix](../reference/sql-support.md).

**Where is the data format documented?** See the [payload / wire format](../../crates/eql-bindings/README.md) for the scalar envelope and index terms, and [EQL with JSON and JSONB](../reference/json-support.md) for the `public.eql_v3_json_search` document format.

## Troubleshooting

**Operator resolves to native `jsonb` / returns `NULL` instead of searching.** The query operand was an untyped literal, so PostgreSQL flattened the `eql_v3` domain to `jsonb`. Type the operand with the matching query-operand domain (`$1::eql_v3.query_text_eq`, `$1::eql_v3.query_json`) — the Proxy does this automatically.

**`=` returns no rows.** The column's values do not carry an `hm` equality term. Confirm the client is configured to emit the right term for the column's variant (step 2), and that data was written through the Proxy after configuring it.

**Index not used.** Build the functional index on the extractor (step 3), run `ANALYZE`, and confirm the operand is typed. See [Database Indexes — Troubleshooting](../reference/database-indexes.md#troubleshooting).
