# Encrypt Query Language (EQL)

[![Test EQL](https://github.com/cipherstash/encrypt-query-language/actions/workflows/test-eql.yml/badge.svg?branch=main)](https://github.com/cipherstash/encrypt-query-language/actions/workflows/test-eql.yml)
[![Release EQL](https://github.com/cipherstash/encrypt-query-language/actions/workflows/release.yml/badge.svg?branch=main)](https://github.com/cipherstash/encrypt-query-language/actions/workflows/release.yml)

Encrypt Query Language (EQL) is a set of abstractions for transmitting, storing, and interacting with encrypted data and indexes in PostgreSQL.

> [!TIP]
> **New to EQL?**
> EQL is the basis for searchable encryption functionality when using [CipherStash Stack](https://github.com/cipherstash/stack) and/or [CipherStash Proxy](https://github.com/cipherstash/proxy).

Store encrypted data alongside your existing data:

- Encrypted data is stored using a `jsonb` column type
- Query encrypted data with specialized SQL functions (equality, range, full-text, etc.)
- Index encrypted columns to enable searchable encryption

## Table of Contents

- [Installation](#installation)
  - [Local development (fastest)](#local-development-fastest)
  - [Install into an existing database](#install-into-an-existing-database)
  - [dbdev](#dbdev)
- [EQL Components](#eql-components)
  - [Release artifacts](#release-artifacts)
- [Database Permissions](#database-permissions)
- [Getting started](#getting-started)
  - [Enable encrypted columns](#enable-encrypted-columns)
- [Encrypt configuration](#encrypt-configuration)
- [Performance](#performance)
- [Documentation](#documentation)
- [CipherStash integrations using EQL](#cipherstash-integrations-using-eql)
- [Versioning](#versioning)
  - [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Installation

### Local development (fastest)

Run a Postgres image with EQL pre-installed:

```sh
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres \
  ghcr.io/cipherstash/postgres-eql:17
```

EQL is installed automatically on first boot. Pin a specific version with `:17-<eql-version>` (see [releases](https://github.com/cipherstash/encrypt-query-language/releases) for available versions). Other PostgreSQL majors are available as `:14`, `:15`, `:16`. See [`docker/README.md`](./docker/README.md) for the full tag scheme and details.

### Install into an existing database

Use the `stash` CLI (recommended):

```sh
npx stash eql install
```

It connects using `DATABASE_URL` (or `--database-url` for a one-shot run), checks your role's
capabilities first (`npx stash eql preflight` runs the same checks standalone), installs as a
non-superuser, and prints any optional superuser-gated statements it skipped instead of failing
on them. On platforms where schema changes must go through a migration tool, generate a
migration instead: `npx stash eql migration --supabase` (or `--drizzle`).

<details>
<summary>Alternative: apply the raw SQL yourself</summary>

1. Download the latest EQL install script:

   ```sh
   curl -sLo cipherstash-encrypt.sql https://github.com/cipherstash/encrypt-query-language/releases/latest/download/cipherstash-encrypt.sql
   ```

2. Run this command to install the custom types and functions:

   ```sh
   psql -f cipherstash-encrypt.sql
   ```

> [!WARNING]
> The bundle is ~6,000 statements and `psql -f` sends one statement per protocol round trip. Over a
> pooled or high-latency connection — or under a platform command-time ceiling (some managed
> platforms kill commands after a fixed limit) — this can time out **partway**, leaving a
> half-installed schema. If you cannot use the CLI, apply the file over a direct (non-pooled)
> connection, or split it at statement boundaries and apply each chunk as a single command.

</details>


## EQL Components

EQL installs the following components into the `eql_v3` schema:

| Name                                                | Entity Type   | Purpose                                                              |
| --------------------------------------------------- | ------------- | ------------------------------------------------------------------- |
| `eql_v3`                                            | Schema        | Holds EQL operators, term extractors, comparison wrappers, and aggregates |
| `public.<T>`, `public.<T>_eq`, `public.<T>_ord`     | Domain types  | Per-scalar encrypted columns (one family per scalar: `integer`, `text`, `timestamp`, …) |
| `public.eql_v3_json_search`                                | Domain type   | Searchable encrypted JSON (structured-encryption) documents          |
| `public.eql_v3_json`                                       | Domain type   | Encrypted JSON, storage-only (no query surface)                      |
| `eql_v3.eq_term` / `ord_term` / `match_term`        | Functions     | Index-term extractors for functional indexes                        |


### `eql_v3` Schema

The `eql_v3` schema holds the operators, term extractors, comparison wrappers, and `MIN` / `MAX` aggregates for the encrypted-domain types. The encrypted-domain types themselves live in `public` (see below), and the internal SEM index-term types live in `eql_v3_internal`.

Encrypted columns are typed as `public` domains (e.g. `public.eql_v3_text_eq`, `public.eql_v3_json_search`), and the searchable surface available on a column is fixed by its domain **variant** — there is no database-side configuration state. Storage-only variants (`public.eql_v3_text`, `public.eql_v3_json`, …) carry no query surface at all; the searchable JSON domain is `public.eql_v3_json_search`. Which index terms a value carries is decided by the encryption client (CipherStash Stack / CipherStash Proxy).

The domain types deliberately live in `public`, not `eql_v3`, so application tables survive an EQL uninstall: `DROP SCHEMA eql_v3 CASCADE` removes the operators, extractors, and aggregates but leaves the `public`-typed columns (and their data) intact. Re-running the install script is safe for columns and data — but note it begins with that same `DROP SCHEMA eql_v3 CASCADE`, which also **cascade-drops any functional indexes** built on the `eql_v3` extractors. After a re-install or upgrade, re-create your encrypted-column indexes and `ANALYZE` (see [Database Indexes](docs/reference/database-indexes.md)).


### Release artifacts

EQL v3 releases ship three artifacts under one identity: the SQL + docs
GitHub release, the Rust `eql-bindings` crate, and the TypeScript
`@cipherstash/eql` npm package. The language packages bundle the exact SQL
installer they were generated against.


## Database Permissions

The canonical reference is **[EQL permissions & grants](docs/reference/permissions.md)** — install privileges (including the one superuser-gated component, the ORE operator class, and which managed platforms allow it), the per-query-path grant matrix, and the operator-free function equivalents. The short version:

- **Installing** needs `CREATE` on the database plus `CREATE`/`USAGE` on `public` — no superuser, except for the optional block-ORE operator class. Altering the tables that receive encrypted columns requires table *ownership* (PostgreSQL has no grantable `ALTER` table privilege).
- **The installer issues no `GRANT`s.** Access to `eql_v3` / `eql_v3_internal` is strictly opt-in per role.
- **A runtime role** that queries encrypted columns typically needs:

```sql
GRANT USAGE ON SCHEMA eql_v3 TO your_app_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3 TO your_app_user;
-- The public operators inline into eql_v3_internal, so query roles need it too:
GRANT USAGE ON SCHEMA eql_v3_internal TO your_app_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3_internal TO your_app_user;
-- User table access (normal application permissions)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE your_tables TO your_app_user;
```

See [permissions.md](docs/reference/permissions.md) for the pgcrypto-schema grant the ORE variants additionally need, and for narrowing grants per query path.


### dbdev

> [!WARNING]
> The version released on dbdev may not be in sync with the version released on GitHub until we automate the publishing process.

You can find the EQL extension on [dbdev's extension catalog](https://database.dev/cipherstash/eql) with instructions on how to install it.

## Getting started

Once EQL is installed in your PostgreSQL database, you can start using encrypted columns in your tables.

### Enable encrypted columns

Define encrypted columns using a `public` encrypted-domain type. Type the column as the **variant** for the capability you need — `public.eql_v3_text_eq` for equality, `public.<T>_ord` for range/ordering, `public.eql_v3_text_match` for full-text, `public.eql_v3_json_search` for searchable encrypted JSON (`public.eql_v3_json` is the storage-only flavour). Each is stored as `jsonb` with a `CHECK` constraint that validates the encrypted payload.

**Example:**

```sql
-- Step 1: Create a table with an equality-searchable encrypted column
CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    encrypted_email public.eql_v3_text_eq
);

-- Step 2: Add a functional index on the term extractor (engages bare-form queries)
CREATE INDEX users_email_eq ON users USING hash (eql_v3.eq_term(encrypted_email));
```

See the [SQL support matrix](docs/reference/sql-support.md) for every variant and [Database Indexes](docs/reference/database-indexes.md) for the index recipes.

> [!NOTE]
> You must use [CipherStash Proxy](https://github.com/cipherstash/proxy) or [CipherStash Stack](https://github.com/cipherstash/stack) to encrypt and decrypt data. EQL provides the database functions and types, while these tools handle the actual cryptographic operations.

## Encrypt configuration

In order to enable searchable encryption, you will need to configure your CipherStash integration appropriately.

- If you are using [CipherStash Proxy](https://github.com/cipherstash/proxy), see [this guide](docs/tutorials/proxy-configuration.md).
- If you are using [CipherStash Stack](https://github.com/cipherstash/stack), use the [CipherStash Stack schema](https://cipherstash.com/docs/stack/cipherstash/encryption/schema).

## Performance

Query latency for searchable-encryption operations stays low across data set sizes. The numbers below are query-only medians (no decryption) from a full benchmark run against EQL 2.3 on PostgreSQL 17, across four row-count tiers. (The JSON rows predate the 3.0 ste_vec redesign — field equality is now value-selector containment — so treat them as indicative, not current.)

| Family | Scenario | 10k | 100k | 1M | 10M |
|---|---|--:|--:|--:|--:|
| **JSON** | contains/functional | 0.66 ms | 0.65 ms | 0.68 ms | 6.8 ms |
| JSON | field_eq/functional | 0.98 ms | 0.98 ms | 0.90 ms | 0.92 ms |
| JSON | field_order/functional | 0.74 ms | 0.77 ms | 0.77 ms | 0.84 ms |
| **ORE** | range_gt_100 | 4.1 ms | 6.7 ms | 6.9 ms | 8.1 ms |
| ORE | range_lt_hybrid_ordered_10 | — | 1.1 ms | 1.2 ms | 1.2 ms |
| **EXACT** | eql_hash | 0.43 ms | 0.44 ms | 0.43 ms | 0.46 ms |
| **MATCH** | eql_bloom | 1.0 ms | 2.5 ms | 18 ms | 216 ms |
| **GROUP_BY** | low_cardinality — encrypted | 2.7 ms | 28 ms | 179 ms | 1.47 s |
| GROUP_BY | low_cardinality — plaintext baseline | 1.5 ms | 9.9 ms | 36 ms | 430 ms |
| **COMBO** | top_n_filtered_group_by | 0.84 ms | 1.1 ms | 5.5 ms | 43 ms |

Full methodology, per-scenario SQL, planner index choices, and EXPLAIN plans are in the [`cipherstash/benches`](https://github.com/cipherstash/benches) repository.

## Documentation

### API Documentation

All EQL functions and types are fully documented with Doxygen-style comments in the source code.

**Install Doxygen** (required for documentation generation):

```bash
# macOS
brew install doxygen

# Ubuntu/Debian
apt-get install doxygen

# Other platforms: https://www.doxygen.nl/download.html
```

**Generate API documentation:**

```bash
# Using mise
mise run docs:generate

# Or directly with doxygen
doxygen Doxyfile
```

The generated HTML documentation will be available at `docs/api/html/index.html`.

### Documentation Standards

All SQL functions, types, and operators include:
- **@brief** - Short description of purpose
- **@param** - Parameter descriptions with types
- **@return** - Return value description and type
- **@example** - Usage examples
- **@throws** - Exception conditions
- **@note** - Important notes and caveats

For contribution guidelines, see the [development guide](./DEVELOPMENT.md).

### Validation Tools

Verify documentation quality using these scripts:

```bash
# Using mise (validates coverage and tags)
mise run docs:validate

# Or run individual checks
./tasks/docs/validate/coverage.sh       # Check 100% coverage
./tasks/docs/validate/required-tags.sh  # Validate @brief, @param, @return
./tasks/docs/validate/documented-sql.sh # Validate SQL syntax
```

Documentation validation runs automatically in CI for all pull requests.

## CipherStash integrations using EQL

These frameworks use EQL to enable searchable encryption functionality in PostgreSQL.

| Framework   | Repo                                       |
| ----------- | ------------------------------------------ |
| CipherStash Stack  | [CipherStash Stack](https://github.com/cipherstash/stack) |
| Protect.php | [Protect.php](https://github.com/cipherstash/protectphp) |
| CipherStash Proxy | [CipherStash Proxy](https://github.com/cipherstash/proxy) |

## Versioning

EQL is distributed as a versioned install script (`cipherstash-encrypt.sql`) published with each [GitHub release](https://github.com/cipherstash/encrypt-query-language/releases). Track the release tag you installed; re-running the install script is idempotent and upgrades the `eql_v3` surface in place.

You can check the version installed in a database by running:

```sql
SELECT eql_v3.version();
```

### Upgrading

To upgrade to the latest version of EQL, you can simply run the install script again.

1. Download the latest EQL install script:

   ```sh
   curl -sLo cipherstash-encrypt.sql https://github.com/cipherstash/encrypt-query-language/releases/latest/download/cipherstash-encrypt.sql
   ```

2. Run this command to install the custom types and functions:

   ```sh
   psql -f cipherstash-encrypt.sql
   ```

> [!NOTE]
> Re-running the install script is safe for your columns and data (the domain types live in `public` and survive). It does, however, begin with `DROP SCHEMA eql_v3 CASCADE`, which cascade-drops any **functional indexes** built on the `eql_v3` extractors — re-create them and `ANALYZE` after every upgrade (see [Database Indexes](docs/reference/database-indexes.md)).

#### Using dbdev?

Follow the instructions in the [dbdev documentation](https://database.dev/cipherstash/eql) to upgrade the extension to your desired version.

## Troubleshooting

### Common Errors

**A query returns no rows / silently runs native `jsonb` semantics**
- **Cause**: the query operand was an untyped literal, so PostgreSQL flattened the `eql_v3` domain to its `jsonb` base type and resolved the native operator
- **Solution**: type the operand with the matching query-operand domain — `WHERE col = $1::eql_v3.query_text_eq` (CipherStash Proxy supplies typed parameters automatically)

**Error: "operator not supported" (raised)**
- **Cause**: the operator is blocked for the column's domain variant (e.g. `<` on an `_eq` column, or `LIKE` on any encrypted column)
- **Solution**: type the column as a variant that carries the required term (see the [SQL support matrix](docs/reference/sql-support.md)); use `@@` rather than `LIKE` for text match

**`=` returns no rows on a populated column**
- **Cause**: the column's values do not carry an `hm` equality term
- **Solution**: confirm the encryption client is configured to emit the equality term for the column's variant, and that data was written after configuring it

### Getting Help

- Check the [full documentation](./docs/README.md)
- Review [CipherStash Proxy configuration guide](./docs/tutorials/proxy-configuration.md)
- Report issues at [https://github.com/cipherstash/encrypt-query-language/issues](https://github.com/cipherstash/encrypt-query-language/issues)

## Contributing

See the [development guide](./DEVELOPMENT.md) for information on developing and extending EQL.
