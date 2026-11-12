# Findings from the customer directory example

Measured on 9 November 2026, on one macOS machine, against real ZeroKMS. The SDK was a dev-profile build. Do not use these times as release-build figures.

## Gaps in the SDK or its documentation

Items 5, 6, and 7 were found before the SQLAlchemy layer existed. Items 1 to 7 each now have a status line.

### 1. The README does not warn about Pydantic's `ValidationError`

`Customer` is a Pydantic model that contains plaintext. By default, Pydantic prints the rejected input in a `ValidationError`. FastAPI's default 422 response also repeats the input: the example's first run returned `"input":"bad"`.

The README's list of what still shows plaintext names `model_dump`, `vars`, `pickle`, and others. It does not name either of these.

The example sets `hide_input_in_errors=True` and replaces FastAPI's 422 response. `tests/test_app.py` covers both.

Suggested action: add both to the README's list, with the setting that hides the input.

Status: addressed. The README's list in "What a printed model shows" now names both. It gives `hide_input_in_errors=True` for the `ValidationError`, and says that FastAPI's 422 response needs its own handler: with that setting, `errors()` still contains the input (checked with Pydantic 2.14.3).

### 2. The README has no recipe for a database-generated key

The README covers a UUID key only. A required integer `id` on the model cannot work, because the model is encrypted before PostgreSQL creates the `id`.

The example leaves `id` out of the model. It works, but the model then cannot return the `id`.

Suggested action: add the database-generated case to "Store a UUID key".

Status: addressed. "Store a UUID key" now covers a key the database generates, for psycopg and for the SQLAlchemy layer.

### 3. `decrypt` does not say whether it keeps row order

Neither the `decrypt` docstring nor the README says that results come back in the order of the input rows. An application that needs a column outside the model must pair it with the decrypted result by position.

The example avoids this by not returning `id`. I did not test the order.

Suggested action: state the guarantee, and add a test for it.

Status: addressed. The README and the `Cipher.decrypt` docstring state that the instances come back in the order of the rows. `tests_deterministic/test_order.py` checks it, with the rows in reverse order.

### 4. The README does not cover uniqueness on an encrypted column

The README shows only a hash index, and PostgreSQL cannot make a hash index unique. This B-tree index works:

```sql
CREATE UNIQUE INDEX customers_email_unique ON customers (eql_v4.eq_term(email));
```

A second insert with the same email raises `UniqueViolation` with SQLSTATE 23505. `EXPLAIN` shows an index scan on this index for `WHERE email = %s::eql_v4.query_text_eq`, with `enable_seqscan` off.

Suggested action: document the unique index, and say that equal emails produce equal terms.

Status: addressed. The SQLAlchemy section of the README explains `declaration_unique_column`. It says that equal values have equal `eq` terms, and shows a unique index on `eql_v4.eq_term(email)`.

### 5. The README has no write or read path for SQLAlchemy

The README shows how to declare a SQLAlchemy model, including relationships. It does not show an insert or a query. `app_sqlalchemy.py` needed three things that the README does not mention:

- A custom column type. The tests fail with `sa.Text`, `sa.String`, or `sa.JSON` in its place.
- `sa.insert(Customer.__table__)` with the rows from `encrypt`, in place of `Session.add`.
- A `sa.cast` of the query term to `eql_v4.query_text_eq`.

The `id` column works when it is marked `Ignore`. Search with these statements uses the unique index, as `EXPLAIN` shows with `enable_seqscan` off.

Python ADR-0002 mentions a later SQLAlchemy layer. Until it exists, this is hand-written code for each application.

Suggested action: add this recipe to the README, or say that the layer is planned.

Status: addressed by the SQLAlchemy layer, `stackencrypt.sqlalchemy`. `app_sqlalchemy.py` now calls `configure_encryption([Customer])`. Its endpoints use `session.add` and `session.scalars`, with no SDK calls. The README section "Use it with the SQLAlchemy ORM" shows the write and the read.

### 6. `Session.add` sends plaintext to PostgreSQL before it fails

`Session.add` with a normal `Customer` object fails with a `DataError`, and no row is stored. But the plaintext has already reached the PostgreSQL server. The error text quotes the start of the value, even with `hide_parameters=True`:

```text
DETAIL:  Token "zed" is invalid.
CONTEXT:  JSON data, line 1: zed...
```

The example logs only PostgreSQL's primary message, so this text is not in its log. An application that logs the exception would write part of the plaintext. A PostgreSQL server that logs errors could also record it. I did not check the server's log.

Suggested action: warn about this in the README. The later SQLAlchemy layer could refuse this case before anything is sent.

Status: addressed by the SQLAlchemy layer. Its write hook encrypts the values before SQLAlchemy sends the statement, so `Session.add` sends no plaintext. I did not check this example's PostgreSQL log again.

### 7. A decrypted SQLAlchemy object is not connected to a session

`select(Customer)` returns ciphertext dicts in `.email` and `.name`. `decrypt` returns new objects that SQLAlchemy reports as transient, with `id` set to `None`. So the usual pattern of loading an object, changing it, and committing it does not work.

Suggested action: state this limit in the README.

Status: addressed by the SQLAlchemy layer. A session query builds its objects as usual. The read hook then decrypts them in place with `set_committed_value`, so they are not marked as changed (ADR-0004). `tests/test_sqlalchemy_live.py` checks `session.dirty` after a load.

### 8. Two `decrypt` errors from the engine do not name the row

Most `decrypt` errors name the row and the field, such as `row 317, field "email"`. Two codes name the field only, when the engine finds the problem:

- `decrypt_malformed`, for a value with an `i` that is not the field's EQL type. The engine refuses it before any key request.
- `decrypt_kind_mismatch`, for a value sealed as another type. The engine finds it after the value opens, so after the key requests.

In a batch of 500 rows, the user must then search every row for the bad value. The Go SDK has the same gap: `Client.open` in `languages/golang/encrypt/records.go` returns the engine's error unchanged. Review thread 1509-F7 reported it for Python.

The SDK could find the row for `decrypt_malformed` by running the engine's check again one row at a time. That needs a copy of every row's ciphertext on every call, and it cannot help with `decrypt_kind_mismatch` without new key requests. It would also make Python differ from Go.

Suggested action: have the engine name the row in both refusals, so that Python and Go both get it. Issue #1508 already asks the engine to name the field in `decrypt_kind_mismatch`. Until then, state in the README and the `Cipher.decrypt` docstring that these two codes do not name the row.

## Timings

| Step | Time |
|---|---|
| `import app`, including `Cipher(Customer)` | 0.15 s |
| First `encrypt` of one customer, two runs | 0.95 s and 1.25 s |
| Next `encrypt` of one customer | about 0.22 s |
| `query` after the first call | 0.002 s |
| `psycopg.connect` and close | 0.011 s |
| 20 single-customer `encrypt` calls in sequence | 7.5 s |
| 20 single-customer `encrypt` calls on 20 threads | 0.73 s |

The first request after start-up costs about 1 second more than later requests. The example has no warm-up call, as decided.

## README claims that held

- One `Cipher` can be shared between threads with no lock. The concurrency test passed, and the timings above show the calls overlap.
- `query` makes no noticeable request after the first call. It took 0.002 s.
- A Pydantic class works as both the FastAPI request body and the `stackencrypt` model. `default_factory` is accepted.
- `repr` shows `<sealed>` for encrypted fields.
- Rows written by the psycopg app decrypt in the SQLAlchemy app, and the reverse. A test covers both directions.
- `decrypt` is all or nothing. One row stored under another table name made a whole list request fail with `decrypt_foreign_row`.
- Missing credentials stop the app at start-up, with `stack_auth_not_authenticated` and a message that says how to log in.

## Limits of this example

- It was not run on Python 3.9, the SDK's oldest supported version. It ran on 3.14 only.
- The statement that uv does not notice a Rust change is not tested. `mise run setup` always reinstalls the SDK.
- Dependabot does not update this example's `uv.lock`.
- CI does not run the tests, so the example can break with no CI failure.
- The tests print a Starlette warning that recommends `httpx2` in place of `httpx`. I left `httpx` in place, because I could not verify `httpx2`.
