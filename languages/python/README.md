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

Declare the model with `stackencrypt.model`, then encrypt it with a `Cipher`. Set `DATABASE_URL` to your database's connection string first.

```python
import dataclasses
import os
from typing import Annotated

import psycopg
import stackencrypt
from stackencrypt import Passthrough, TextEq

DATABASE_URL = os.environ["DATABASE_URL"]


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

`cipher.eq` takes a field's name and a value, and returns a query term as a `str`. Cast the term to the field's query type in the SQL:

```python
term = cipher.eq("email", "a@example.com")
with psycopg.connect(DATABASE_URL) as conn:
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT email, age FROM users WHERE email = %s::eql_v4.query_text_eq",
            (term,),
        )
        users = cipher.decrypt(cur.fetchall())
```

The query type is the marker's `query_sql_domain`. For `TextEq` it is `eql_v4.query_text_eq`. The `users_email_eq` index from "Create the table" lets PostgreSQL find the row without reading every row.

A query method sends no request to CipherStash after the first operation of the process. The term is made from a key that the first operation loads.

A field that does not support the operator raises `stackencrypt.QueryError` with the code `query_unsupported`. For `eq`, examples are `Text`, `Passthrough`, `IntegerOrd`, and `TextMatch`. A name that is not a declared field raises `QueryError` with the code `query_unknown_field`. The value is checked as `encrypt` checks it.

## Search by order

A field whose marker has an order index, such as `IntegerOrd`, supports `lt`, `lte`, `gt`, and `gte`. Each takes a field's name and a value, and returns a term as a `str`. Use the SQL operator of the same meaning: `<`, `<=`, `>`, or `>=`. For example, `cipher.gte("level", 3)` returns a term for `WHERE level >= %s::eql_v4.query_integer_ord`.

The errors are the same as for `eq`. A `TextEq` field, for example, does not support `gte`.

There is no `between` yet. For a range, use `gte` and `lte` together: `WHERE level >= %s::eql_v4.query_integer_ord AND level <= %s::eql_v4.query_integer_ord`.

## Search by match

A field whose marker has a match index, such as `TextMatch`, supports `matches`. It takes a field's name and the text to find, and returns a `MatchQuery`. Its `term` goes in the SQL with `@@`: `WHERE notes @@ %s::eql_v4.query_text_match`.

A match search can return rows that do not hold the text. So decrypt the rows, then pass the field's values to `q.verify`. It returns one `bool` for each value, in order. Keep the rows that are `True`. `verify` checks that a value holds every 3-character piece of the text. The pieces can be in any order, so it is not an exact substring check.

To size the `LIMIT`, call `q.target_limit(want, rows=..., histogram=...)`. It returns how many rows to fetch so that `want` of them pass `verify`, 99 times in 100. It returns `None` when it cannot promise a number. Then fetch page by page. Without a `histogram`, it always returns `None`. The method's docstring gives the SQL that reads the histogram.

A `MatchQuery` keeps the search text, because `verify` needs it. Python cannot wipe a `str`, so the text stays in memory until Python frees the object. `repr` does not show it.

## Encrypt or decrypt only some fields

To update one column, you do not need a whole model. `cipher.encrypt_rows` takes a list of dicts from field name to value. Each dict can contain only some of the declared fields. For example, `cipher.encrypt_rows([{"email": "b@example.com", "id": 1}])` returns `[{"email": '{"c": ...}', "id": 1}]`.

- Each declared field's value is replaced, as `encrypt` writes it.
- Every other key, such as `id`, is kept unchanged.
- Every row in one call must contain the same declared fields. Then one call sends one batch of key requests.

The values are checked as `encrypt` checks them. A row that is not a mapping raises `InvalidValueError` with the code `value_row_shape`. So do rows that contain different declared fields.

`cipher.decrypt_rows` is the reverse. It takes dicts of stored values that contain some of the declared fields, and returns dicts with the plaintext. Other keys are kept unchanged. It follows the same rules, and raises the same errors as `decrypt`. A row that is not a mapping raises `DecryptError` with the code `decrypt_row_shape`. So do rows that contain different declared fields.

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

## What a printed model shows

`repr` and `str` of a declared model show `<sealed>` in place of each encrypted field. A passthrough field shows its value:

```text
User(email=<sealed>, age=3)
```

A log line that formats the model, such as `log.info("%s", user)`, uses `str`, so it shows `<sealed>` too.

Nothing else is hidden. These all contain the plaintext:

- a log line that formats a field, such as `log.info(user.email)`
- `dataclasses.asdict`, Pydantic's `model_dump`, `vars`, and `__dict__`
- `pickle.dumps(user)`, and anything a debugger reads from the attributes

If the class defines its own `__repr__`, `__str__`, or `__rich_repr__`, the decorator refuses it. `__rich_repr__` is the method the `rich` library prints through. To keep your own methods, pass `redact=False` to `stackencrypt.model`. Your methods must then hide the plaintext themselves.

## Do not change a class after you declare it

`Cipher(User)` checks that the class is as the decorator left it: the same type hints, the same constructor, and the same printing methods. A changed class raises `stackencrypt.DeclarationError` with the code `declaration_class_changed`. With `redact=False`, the printing methods are yours, so `Cipher` does not check them.

After a `Cipher` is made, nothing checks the class again. So the SDK cannot detect a change made after that point.

## Store a UUID key

A model field cannot be a `uuid.UUID`. The decorator refuses it with the code `declaration_type_mismatch`. Use one of these two ways instead:

- Leave the key column out of the model. `encrypt` never writes a column the model does not declare, and `decrypt` ignores one. Insert and select the key yourself, beside the encrypted values.
- Declare the field as `Annotated[str, Passthrough]`. Convert with `str(key)` before `encrypt`. Select the column as `id::text`, because psycopg reads a `uuid` column as a `uuid.UUID`, and `decrypt` refuses that for a `str` field.

## What is not supported yet

- Range queries with `between`. Use `gte` and `lte` together.
- Encrypted JSON documents.
- Lock contexts and identity-bound encryption.
- More than one keyset, and a choice of keyset.
- An async API.

## Use it from several threads

`encrypt`, `decrypt`, and the query methods are synchronous. There is no async form yet.

Each call releases the GIL while the encryption runs. The GIL is CPython's global interpreter lock. So other Python threads keep running during a call, and calls from several threads run at the same time. Within one call, the requests to CipherStash go out one at a time.

A process has one connection to CipherStash. The first call of any `Cipher` makes it, reads the credentials, and loads the default keyset. Every `Cipher` in the process then uses that connection. If you change the `CS_*` variables or log in again, restart the process.

Make one `Cipher` for each model, and share it between threads with no lock. Do not make a new `Cipher` for each web request. Making one checks the model and the credentials. When no access key is set in the environment, it also reads your CipherStash profile from disk.

If you press Ctrl-C during a call, the call finishes first. Python then raises `KeyboardInterrupt`, and the `Cipher` still works. A call cannot be cancelled.

Each request to ZeroKMS, CipherStash's key service, times out after 10 seconds. A request for an access token times out after 30 seconds. The SDK makes one on the first call when no fresh token is stored, and again shortly before the token expires. A call that makes several requests can take longer in total. You cannot change these timeouts yet.

## Run the tests

From `languages/python`:

```sh
mise run test                 # no credentials needed
mise run test:deterministic   # no credentials needed
mise run test:live            # needs the four CS_* variables and EQL_TEST_DATABASE_URL
```

`mise run test:deterministic` builds a test version of the extension. Its keys come from a fixed seed, not from CipherStash. The tests in `tests_deterministic/` then open the EQL rows the Go SDK stored under that seed. They also check that Python seals the same values to the same terms. Run `mise run build` afterwards to get a normal build back.

`mise run test:live` installs the EQL v4 bundle into the database that `EQL_TEST_DATABASE_URL` names. Use a database you can throw away. It also runs this README: the SQL block and the Python blocks, in order, in a schema of their own.
