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
- Reads of columns: the same hook decrypts the result columns that are encrypted fields, as in `select(Customer.email, Customer.plan)`. It makes one `decrypt_rows` call for each class and set of fields.

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

A comparison with another SQL expression is allowed when the expression holds no Python value, such as another column. It sends no value. An expression that holds one, such as `literal("x")` or `func.lower("x")`, is refused: the hooks cannot encrypt a value inside an expression. SQLAlchemy itself compares columns this way when it copies a statement.

The allowed operators are:

- `==`, `<`, `<=`, `>`, and `>=`. Each one sends a query term made by the `Cipher` method of the same meaning.
- `!=`, as `NOT (col = term)`.
- `in_` and `not_in` with a list, as one equality term for each value, joined with `OR`.
- `is_(None)` and `is_not(None)`. These send no value.
- The sort operators, which sort by the order term (Decision 9).

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

## Decision 8: a match search removes its false matches, with limits

`.match(text)` on a field with a match index is `col @@ term`. A match index is a Bloom filter, so the database can return rows that do not hold the text. ADR-0003 says the layer should hide this. So after the query, the session hook runs `MatchQuery.verify` on each row, and removes the rows that fail.

Removing rows after the query is right only in some places. So `.match()` works only when all three of these are true:

1. The statement is a `select` run through a session.
2. The match is a condition of the `WHERE`, joined with `AND` if there are others. Or it is a branch of an `or_` whose branches are all match searches, or `and_` of them (see "An `or_` of match searches" below).
3. The result includes whole objects of the class, so the column is loaded.

Anything else raises `QueryError` with `query_unsupported` before the query is sent:

| Use | Why it is refused |
|---|---|
| In an `or_` with a condition that is not a match search | A row kept by the other condition would be removed. |
| In `not_(...)` | The rows to keep are the false matches, which the hook cannot find. |
| `select(Profile.plan)` | The matched column is not in the result, so `verify` cannot run. |
| `func.count()` | The count includes the false matches. |
| `update` or `delete` | The false matches would be changed in the database. |
| A query on a connection | No hook can remove rows from its result. |

### An `or_` of match searches

A search box that looks in several text fields is an `or_` of match searches, such as `or_(Activity.name.match(q), Activity.town.match(q))`. The hook accepts an `or_` whose branches are all match searches, or `and_` of them. It keeps a row if any branch passes `verify`. A branch fails for a row when its field is NULL, or when an outer join gives no object for its class. With `AND` alone, such a row never comes back, because its `@@` is NULL. With `or_`, another branch can bring it back.

This gives exactly the rows that `verify` would keep over the whole table. A match search never leaves out a row that `verify` would keep:

- `verify` keeps a value only if it contains every 3-character token of the search text.
- Each of those tokens sets bits in the value's stored Bloom filter, so `@@` returns the row.

So the database returns every row that any branch would keep, plus some false matches. `verify` on each branch removes the false matches.

An `or_` with any other condition is still refused. When the match branch fails `verify`, the hook cannot tell whether the other condition kept the row. A match under `not_` is still refused, inside an `or_` or around one.

Each branch can add false matches before a `LIMIT`. So with a wide `or_`, a page is short more often.

### A LIMIT can return fewer rows

The database applies a `LIMIT` before the hook removes rows. So `.limit(10)` can return fewer than 10 rows, even when more rows match.

| Option | Cost |
|---|---|
| **A. Return fewer rows (chosen)** | The page can be short. |
| B. Raise the limit with `target_limit` | An extra query for a histogram of the stored filters, on each search. Without it, there is no finite limit. |
| C. Query again with an `OFFSET` | Several queries for one search, and rows can change between them. |

A never returns a row that does not hold the text. B or C can come later, if an app needs exact page sizes.

## Decision 9: sort by the order term

A bare `ORDER BY col` on an EQL v4 column sorts in a wrong order, with no error. On values 98, 120, 150, and 175 in an `IntegerOrd` column, it gave 98, 150, 175, 120. A sort with new ciphertext gave another order.

The cause is in EQL v4. It defines `<` and the other comparisons for its column types. But a sort needs a default sort order for the type, and the EQL domains have none. So PostgreSQL sorts the stored JSON. The same test gave the same wrong order with the EQL v4 on the `next` branch as of 2026-11-11. `main` has no EQL v4. The EQL docs say a bare `ORDER BY col` works, but they were written for EQL v3.

`ORDER BY eql_v4.ord_term(col)` sorts by the plaintext. The EQL docs also recommend that form for v3, because only that form uses the index (`packages/eql/docs/reference/database-indexes.md`, "The sort-key trap").

### The options

| Option | Result | Cost |
|---|---|---|
| A. Fix it in EQL | A bare sort works for every SDK and for SQL written by hand. | An EQL change and release. |
| **B. Sort by the order term in the layer (chosen)** | It works now, and the sort uses the SDK's index. | The layer works around EQL. Go, TypeScript, and SQL written by hand still get the wrong order. |
| C. A test marked as an expected failure | Nothing changes yet. | Sorts through the layer stay wrong. |

### What B does

- `.asc()`, `.desc()`, `.nulls_first()`, and `.nulls_last()` on an encrypted column sort by `eql_v4.ord_term(col)`, or `eql_v4.ord_term_ore(col)` for an `ore_block` marker.
- A bare `order_by(col)` and `sqlalchemy.asc(col)` do not go through the column type's operators. So the hooks rewrite the `ORDER BY` of each `select`: the session hook for a query in a session, and the engine hook for a query on a connection. The rewrite covers every `select` in a statement, subqueries included, and a column of a table, an alias, or a subquery. A label or a string name in the `ORDER BY`, such as `order_by("level")`, would sort by the selected column. SQLAlchemy matches a string to a column only when it compiles the statement. So the rewrite looks the name up as SQLAlchemy does: among the labels, then the selected columns, then the columns of the `FROM` tables. A name that belongs to an encrypted column becomes the order term of that column. A name that two `FROM` tables share, and that is not selected, raises `QueryError`, because the rewrite cannot tell which column is meant. The statement is copied only when an `ORDER BY` changes. The engine hook rewrites every `select`. SQLAlchemy marks a select as ORM when it names a mapped class or attribute, as `select(Run.label)` does, even when it runs on a connection. A select from a session reaches the engine hook already rewritten, and is left as it is.
- Sorting a column with no order index raises `QueryError` with `query_unsupported`. Before, it gave the order of the stored JSON, with no error.

If EQL gains a sort order for its v4 column types, the rewrite can stay. The order term is also the form that uses the index.

## What was run

- `tests/test_sqlalchemy.py` and `tests/test_sqlalchemy_migrations.py` run without credentials. They cover the checks, the refused operators, the indexes, and the Alembic rendering.
- `tests/test_sqlalchemy_live.py` runs the hooks against ZeroKMS and PostgreSQL. It covers writes, reads, relationship loads, reads after a commit, search, match search, and the request counts. A false match of the Bloom filter cannot be made on purpose. So the tests that show rows being removed replace `verify` with a function that refuses one row.
- `tests/test_sqlalchemy_migrations_live.py` runs `alembic revision --autogenerate` and `alembic upgrade` on an existing table. A second `autogenerate` writes nothing. With `enable_seqscan` off, `EXPLAIN` shows each index in use.

## Consequences

- A query result is read in full before it is returned, so that its objects can be decrypted in one batch. A query that streams its rows does not stream.
- A query run on a connection, not a session, is not decrypted. It returns EQL values, and the app calls `cipher.decrypt_rows`. A connection has no hook that can change a result. A session query of columns is decrypted.
- The layer imports SQLAlchemy. The rest of the package still does not. SQLAlchemy is not a runtime dependency.
- `do_orm_execute` is registered on every session in the process. It acts only on objects of configured classes.

## Open

- `between`, as two comparisons. The engine has no range term for EQL types (ADR-0003, amendment).
- Exact page sizes for `.match()` with a `LIMIT`: option B or C of Decision 8.
- The reverse migration of a change to an EQL type.
- Installing EQL from a migration.
- A sort order for the EQL v4 column types in EQL itself, option A of Decision 9.
