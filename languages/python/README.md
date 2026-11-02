# stackencrypt

`stackencrypt` is the Python SDK for CipherStash Stack. It encrypts the fields of a Python model into values you store in PostgreSQL with EQL v4. EQL is CipherStash's set of PostgreSQL types for encrypted values.

This is a stub. The package is not released. Today it can encrypt a model, decrypt it again, and search an encrypted column by equality.

## Before you start

You need three things:

- CipherStash credentials. Set `CS_CLIENT_ACCESS_KEY`, `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, and `CS_CLIENT_KEY`. Or log in with `stash auth login`.
- A PostgreSQL database.
- The EQL v4 bundle installed in that database.

To build the EQL v4 bundle from this repository and install it, run these commands from the repository root:

```sh
mise -C packages/eql run build
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f packages/eql/release/cipherstash-encrypt-v4.sql
```

## Create the table

Each encrypted column has an EQL v4 type. A model field marked `TextEq` is stored in a `public.eql_v4_text_eq` column. The index on `eql_v4.eq_term(email)` lets equality queries use the index instead of reading every row.

```sql
CREATE TABLE users (
    email public.eql_v4_text_eq,
    age   int
);
CREATE INDEX users_email_eq ON users USING hash (eql_v4.eq_term(email));
```

## Encrypt a row

Declare the model with `stackencrypt.model`, then encrypt it with a `Cipher`:

```python
import dataclasses
from typing import Annotated

import psycopg
import stackencrypt
from stackencrypt import Passthrough, TextEq


@stackencrypt.model("users")
@dataclasses.dataclass
class User:
    email: Annotated[str, TextEq]
    age: Annotated[int, Passthrough]


cipher = stackencrypt.Cipher(User)
rows = cipher.encrypt([User(email="a@example.com", age=3)])

with psycopg.connect(DATABASE_URL) as conn:
    conn.execute(
        "INSERT INTO users (email, age) VALUES (%s, %s)",
        (rows[0]["email"], rows[0]["age"]),
    )
```

`encrypt` returns one dict per model. A sealed field such as `email` is a `str` of EQL JSON. psycopg sends it with a plain `%s`. PostgreSQL reads it as the column's type, so the insert needs no cast. A `Passthrough` field such as `age` is the value itself.

`encrypt` checks every value before it sends anything. A value of the wrong type, such as `True` for an `int` field, raises `stackencrypt.InvalidValueError`. The error names the field. It never contains the value.

## Read the rows back

Read the rows with psycopg's `dict_row`, then decrypt them with the same `Cipher`:

```python
from psycopg.rows import dict_row

with psycopg.connect(DATABASE_URL) as conn:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT email, age FROM users")
        users = cipher.decrypt(cur.fetchall())   # a list of User
```

`decrypt` builds whole `User` instances, so the `SELECT` must name every declared column, passthrough columns included. A row without one raises `stackencrypt.DecryptError` with the code `decrypt_missing_column`. Other columns in the row are ignored.

A passthrough `datetime` field needs a `timestamptz` column. psycopg reads a `timestamp` column as a naive `datetime`, with no `tzinfo`. `decrypt` refuses a naive `datetime` with `value_naive_datetime`, as `encrypt` does.

`decrypt` checks every row before it sends anything. A value stored under another table or column raises `DecryptError` with the code `decrypt_foreign_row`. A passthrough value of another type than the field declares raises `InvalidValueError`. When any row fails, `decrypt` returns no instances.

## Search by equality

`cipher.query` takes a field's name and a value, and returns a query term as a `str`. Cast the term to the field's query type in the SQL:

```python
term = cipher.query("email", "a@example.com")
with psycopg.connect(DATABASE_URL) as conn:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT email, age FROM users WHERE email = %s::eql_v4.query_text_eq",
            (term,),
        )
        users = cipher.decrypt(cur.fetchall())
```

The query type is the marker's `query_sql_domain`. For `TextEq` it is `eql_v4.query_text_eq`. The `users_email_eq` index from "Create the table" lets PostgreSQL find the row without reading every row.

`query` sends no request to CipherStash after the first operation of the process. The term is made from a key that the first operation loads.

A field whose marker answers no query, such as `Text` or `Passthrough`, raises `stackencrypt.QueryError` with the code `query_unsupported`. A name that is not a declared field raises `QueryError` with the code `query_unknown_field`. The value is checked as `encrypt` checks it.

## Declare a SQLAlchemy relationship

A SQLAlchemy relationship is not a column. Every annotated field needs a marker, so write a relationship in one of two ways:

- **A collection,** such as an author's books: leave the relationship without an annotation. The decorator never reads it.
- **One object,** such as a book's author: mark it `Ignore`. The SDK then leaves it out.

```python
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from stackencrypt import Ignore


class Base(DeclarativeBase):
    pass


@stackencrypt.model("authors")
class Author(Base):
    __tablename__ = "authors"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    name: Mapped[Annotated[str, TextEq]]
    books = relationship("Book", back_populates="author")   # a list of Book


@stackencrypt.model("books")
class Book(Base):
    __tablename__ = "books"
    id: Mapped[Annotated[int, Passthrough]] = mapped_column(primary_key=True)
    author_id: Mapped[Annotated[int, Passthrough]] = mapped_column(ForeignKey("authors.id"))
    author: Mapped[Annotated["Author", Ignore]] = relationship(back_populates="books")
```

Do not mark a collection `Ignore`. SQLAlchemy reads the type directly inside `Mapped[...]`, and it does not look inside `Annotated`. So `Mapped[Annotated[list["Book"], Ignore]]` does not give a list. The cost of the unannotated form is that a type checker does not know the type of `books`.

If a book can have no author, write `Optional["Author"]`. Then the relationship must name its target, as `relationship("Author")` does:

```text
author: Mapped[Annotated[Optional["Author"], Ignore]] = relationship("Author", back_populates="books")
```

With this form, a new `Book` has `author` set to `None` until you set it. A bare `relationship()` fails here, because SQLAlchemy takes `Optional["Author"]` as the target.

`Author` must be defined before `Book`, because the decorator evaluates `"Author"` in the hint when `Book`'s class statement runs.

## Run the tests

From `languages/python`:

```sh
mise run test        # no credentials needed
mise run test:live   # needs the four CS_* variables and EQL_TEST_DATABASE_URL
```

`mise run test:live` installs the EQL v4 bundle into the database that `EQL_TEST_DATABASE_URL` names. Use a database you can throw away.
