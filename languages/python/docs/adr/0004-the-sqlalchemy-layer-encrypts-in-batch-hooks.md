---
status: accepted
date: 2026-11-11
ticket: "none yet"
extends: ADR-0002, ADR-0003
---

# The SQLAlchemy layer encrypts in batch hooks

`stackencrypt.sqlalchemy` lets an app use the SQLAlchemy ORM with encrypted fields, and make no SDK call of its own:

```python
class Base(DeclarativeBase):
    type_annotation_map = eql_type_map

configure_encryption(engine, [Customer])

with Session(engine) as session:
    session.add(Customer(email="a@example.com", level=3))
    session.commit()
    found = session.scalars(select(Customer).where(Customer.email == "a@example.com")).one()
```

This Architecture Decision Record (ADR) records the decisions that shape the layer. Each one had a real choice. Most would be costly to change once apps depend on them.

## Background

Before the layer, an app called `cipher.encrypt` before each insert, and `cipher.decrypt` after each select. It also built each query term with `cipher.eq`, and wrote the cast in the SQL itself. `examples/customer-directory/app_sqlalchemy.py` did this until the layer replaced it.

Each encrypted value needs its own data key from ZeroKMS, CipherStash's key service. The engine fetches the keys for one call in bulk: up to 500 keys in each request. Two live tests show this: `test_1001_one_field_models_make_three_key_requests` and `test_1001_rows_open_with_three_key_requests` in `tests/test_encrypt_live.py`.

## Decision 1: batch hooks, not a column type

### The options

**A. A column type.** A SQLAlchemy `TypeDecorator` encrypts each value as SQLAlchemy writes it, and decrypts each value as it reads a row. This is the usual SQLAlchemy way to change a column's values.

**B. Hooks that work on a whole statement or result (chosen).**

- Writes: a `before_execute` hook on the engine. For each `INSERT` or `UPDATE` on a configured table, it encrypts the parameters of every row with one `Cipher.encrypt_rows` call.
- Reads: the `load` and `refresh` events of each class record the objects a query builds. A `do_orm_execute` hook then decrypts them, with one `Cipher.decrypt_rows` call for each class and set of fields. It sets the plaintext with `set_committed_value`, so the objects are not marked as changed.

### Why B

SQLAlchemy passes a column type one value at a time. So 100 rows would make 100 key requests. With B, they make one. The live test `test_100_objects_make_one_key_request_to_insert_and_one_to_load` in `tests/test_sqlalchemy_live.py` shows this.

### What B needed

- `Cipher.encrypt_rows` and `Cipher.decrypt_rows`. They take dicts that contain only some of the declared fields. An `UPDATE` has only the changed columns, plus keys such as the primary key for the `WHERE`.
- The engine refuses a row that leaves out a field of the plan. So these methods build a smaller plan for each set of fields. A value from the smaller plan opens and searches under the full plan. The live test `test_a_row_updated_with_some_fields_decrypts_and_searches_with_the_full_model` shows this.
- Every row in one call must contain the same declared fields. Then every value is checked before the one batch of key requests. SQLAlchemy sends one set of columns for each statement, so the hook meets this rule.

## Decision 2: one setup call with an explicit list of classes

`configure_encryption(engine, [Customer, Order])` takes the engine and the classes to encrypt. It does not find declared classes by itself, such as from the `Base` registry. An explicit list shows which tables are encrypted. A class imported late would otherwise be missed, with no error.

It checks each class first, and raises `DeclarationError` before any query:

| Code | The class has |
|---|---|
| `declaration_not_mapped` | no SQLAlchemy mapping |
| `declaration_table_mismatch` | a `__tablename__` that is not the table in `stackencrypt.model` |
| `declaration_column_name` | an encrypted field whose column has another name |
| `declaration_column_type` | an encrypted field whose column is not its marker's EQL type |
| `declaration_unique_column` | an encrypted field with a unique constraint |
| `declaration_already_configured` | a configuration from an earlier call |

The hooks use field names, and SQLAlchemy uses column names in statement parameters. So a column with another name, such as `mapped_column("email_address")`, is refused for now.

## Decision 3: refuse what would store or send plaintext

The hooks can change only the parameters passed beside a statement. Three cases would put plaintext where the hooks cannot reach it. Each one raises an error before anything is sent.

- **A value inside the SQL**, such as `insert(Customer).values(email=...)`. It raises `DeclarationError` with `declaration_inline_value`.
- **An operator that would send a value as plaintext**, such as `like`, `contains`, `between`, or `in_` with a subquery. It raises `QueryError` with `query_unsupported` when the app builds the query. The value could also never match an EQL value.
- **A unique constraint on an encrypted column.** Each EQL value contains new random ciphertext, so the constraint never finds a duplicate. A unique index on `eql_v4.eq_term(col)` works instead.

The allowed operators are:

- `==`, `<`, `<=`, `>`, and `>=`. Each one sends a query term made by the `Cipher` method of the same meaning.
- `!=`, as `NOT (col = term)`.
- `in_` and `not_in` with a list, as one equality term for each value, joined with `OR`.
- `is_(None)`, `is_not(None)`, `asc()`, and `desc()`. These send no value.

The comparisons answer ADR-0002's open question. On the ORM, the field is named by the class attribute, such as `Customer.email`. The column type reads the attribute's name and calls the `Cipher` with it.

## Decision 4: the column type comes from the marker

`eql_type_map` is for SQLAlchemy's `type_annotation_map`. It maps each hint, such as `Annotated[str, TextEq]`, to an `EqlType` with that marker. The SQL type is the marker's `sql_domain`. So a model names no SQL type, and the type cannot disagree with the marker.

The other option was an explicit type in each column, such as `mapped_column(Encrypted(TextEq))`. That repeats the marker in the hint.

## Decision 5: the database indexes come from the markers

Each marker lists its EQL indexes, such as `eq` for `TextEq`. When SQLAlchemy maps a class, the SDK adds one database index for each:

| EQL index | Database index |
|---|---|
| `eq` | `hash (eql_v4.eq_term(col))` |
| `ope` | `btree (eql_v4.ord_term(col))` |
| `ore_block` | `btree (eql_v4.ord_term_ore(col))` |
| `match` | `gin (eql_v4.match_term(col))` |

- The indexes are added when a class is mapped, not when a column joins a table. Alembic's `add_column` puts the new column on a temporary table, and creates that table's indexes. So an index added there was created twice.
- If the model declares its own index on the same term of the same column, the SDK adds none for that term. The customer directory example needs this. Its unique btree index on `eq_term(email)` also serves the search.

The other option was to declare each index by hand. An index that is missing, or on the wrong function, makes a search slow with no error.

## Decision 6: two Alembic hooks for env.py

- `render_item` writes `stackencrypt.sqlalchemy.EqlType(stackencrypt.TextEq)` into a migration, with its imports.
- `process_revision_directives` changes two kinds of step:
  - A change of an existing column to an EQL type becomes `op.execute` of an `ALTER` with `USING col::jsonb::<EQL type>`. PostgreSQL refuses the change without it, even with no rows. The cast changes an empty column, and refuses a column with plaintext rows.
  - A type change between an EQL type and itself is dropped. Alembic compares types as text: `eql_v4_text_eq` from the database, and `public.eql_v4_text_eq` from the model.

The other option was to leave the `USING` clause to the app, as a hand edit in each migration.

## Decision 7: writes check passthrough values

The write hook sends every declared field to `encrypt_rows`, not only the encrypted ones. So a passthrough value is checked as `encrypt` checks it, and stored unchanged. For example, a `datetime` with no time zone raises `value_naive_datetime`. An update of passthrough fields alone makes no key request.

Reads do not check passthrough values, as `decrypt_rows` reads only the encrypted fields.

## What was run

- `tests/test_sqlalchemy.py` and `tests/test_sqlalchemy_migrations.py` run without credentials. They cover the checks, the refused operators, the indexes, and the Alembic rendering.
- `tests/test_sqlalchemy_live.py` runs the hooks against ZeroKMS and PostgreSQL. It covers writes, reads, relationship loads, reads after a commit, search, and the request counts.
- `tests/test_sqlalchemy_migrations_live.py` runs `alembic revision --autogenerate` and `alembic upgrade` on an existing table. A second `autogenerate` writes nothing. With `enable_seqscan` off, `EXPLAIN` shows each index in use.

## Consequences

- A query result is read in full before it is returned, so that its objects can be decrypted in one batch. A query that streams its rows does not stream.
- A Core query, such as `conn.execute(text(...))`, is not decrypted. It returns EQL values.
- The layer imports SQLAlchemy. The rest of the package still does not. SQLAlchemy is not a runtime dependency.
- `do_orm_execute` is registered on every session in the process. It acts only on objects of configured classes.

## Open

- `between`, as two comparisons. The engine has no range term for EQL types (ADR-0003, amendment).
- `matches` through the ORM. ADR-0003 says the layer should hide `target_limit` and `verify`.
- Core queries.
- The reverse migration of a change to an EQL type.
- Installing EQL from a migration.
