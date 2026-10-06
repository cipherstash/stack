# Generate sqlc code for Encrypt Query Language columns

This example configures [sqlc](https://github.com/sqlc-dev/sqlc) for a `users` table with two Encrypt Query Language (EQL) columns.
It also defines the queries that generate the `userdb` package.
`sqlc generate` ran for these SQL and YAML files.

The Golang SDK for CipherStash Stack is planned and does not exist yet.
The generated package names the planned `encrypt/eql` package, so it does not build in this repository.
The [Go example index](../README.md) lists every example and what was checked.

## What you will learn

- Define the EQL domains and table columns that sqlc reads.
- Map each EQL domain spelling to its planned Go type.
- Generate typed methods from queries that use EQL columns.

## Define the EQL domains and table columns

- **Purpose:** Understand the schema files that sqlc reads.
- **Related:** [The plan's database design](../../2026-10-04-plan-builder.md#databases), [the generated `userdb` package](../internal/userdb/README.md)

`eql-domains.sql` gives sqlc small domain declarations because sqlc cannot parse the EQL installation bundle.
The domain spelling must match `schema.sql` and the matching override.

[`eql-domains.sql`, lines 1 to 6](eql-domains.sql#L1-L6)

```sql
-- For sqlc only: sqlc cannot parse the EQL install bundle. Spell each domain
-- exactly as schema.sql and query.sql do, or its db_type override never matches.
CREATE SCHEMA eql_v3;

CREATE DOMAIN public.eql_v3_text_eq AS jsonb;
CREATE DOMAIN eql_v3.query_text_eq AS jsonb;
```

`schema.sql` uses one `public.eql_v3_text_eq` EQL column for each encrypted field.

[`schema.sql`, lines 1 to 5](schema.sql#L1-L5)

```sql
CREATE TABLE users (
    id    bigint                 PRIMARY KEY,
    email public.eql_v3_text_eq  NOT NULL,
    name  public.eql_v3_text_eq  NOT NULL
);
```

Read the index's [three rules for sqlc with EQL columns](../README.md#use-sqlc-with-eql-columns) before you change these spellings.

## Map each domain to its Go type

- **Purpose:** Follow the sqlc inputs and type overrides into the generated package.
- **Related:** [The plan's model design](../../2026-10-04-plan-builder.md#models), [the generated `userdb` package](../internal/userdb/README.md)

`sqlc.yaml` reads the domain file before the table schema.
It writes package `userdb` into `../internal/userdb`.

[`sqlc.yaml`, lines 3 to 16](sqlc.yaml#L3-L16)

```yaml
  - engine: postgresql
    schema:
      - eql-domains.sql
      - schema.sql
    queries: query.sql
    gen:
      go:
        package: userdb
        out: ../internal/userdb
        overrides:
          - db_type: "public.eql_v3_text_eq"
            go_type: { import: github.com/cipherstash/stack/languages/golang/encrypt/eql, type: TextEq }
          - db_type: "eql_v3.query_text_eq"
            go_type: { import: github.com/cipherstash/stack/languages/golang/encrypt/eql, type: TextEqQuery }
```

Run `sqlc generate` in this directory to generate the package again with sqlc v1.31.1.

## Generate typed query methods

- **Purpose:** See how the SQL produces typed create, read, list, and search methods.
- **Related:** [The users sqlc store](../users/README.md), [the generated query methods](../internal/userdb/README.md)

`query.sql` defines four methods through sqlc's query annotations.
The email search casts its parameter directly to `eql_v3.query_text_eq`.

[`query.sql`, lines 7 to 13](query.sql#L7-L13)

```sql
-- name: ListUsers :many
SELECT * FROM users ORDER BY id;

-- One cast, straight to the query domain: sqlc types a parameter by its first
-- cast, so ::jsonb::eql_v3.query_text_eq would generate json.RawMessage.
-- name: FindUsersByEmail :many
SELECT * FROM users WHERE email = sqlc.arg(email)::eql_v3.query_text_eq;
```

The direct cast lets the override generate an `eql.TextEqQuery` parameter.
