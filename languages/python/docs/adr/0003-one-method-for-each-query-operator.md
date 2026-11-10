---
status: accepted
date: 2026-11-10
ticket: "none yet"
extends: ADR-0002
---

# One method for each query operator

`Cipher` has one method for each operator the engine supports on a field. `query` is removed.

```python
term = users.eq("email", "a@example.com")
term = users.gte("age", 30)
term = users.between("age", 18, 65)
q = users.matches("name", "ali")
```

The field is still named by a string, as ADR-0002 decided.

This Architecture Decision Record (ADR) records the call shape for equality, order, and match queries. It replaces the last paragraph of ADR-0002's decision. That paragraph said that an operator could come later as `op=`.

## Background

The engine already derives order and match terms. The Go SDK uses them: its generated code has `Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between`, and `Matches` (`languages/golang/encrypt/doc.go`). Python's core calls the same engine function, `dynamic::query_term`, but always with `OpSpec::Eq` (`crates/core/src/query.rs`). So Python needs a way to name the operator.

Equality and order answers are exact. A match answer is not. The match index stores a Bloom filter, so the database can return rows that do not contain the search text. The application must decrypt the rows, then remove those that do not match. Go's `MatchQuery` has `TargetLimit` and `Verify` for this.

## The options

### A. An operator argument

```python
users.query("age", 30, op="gte")
```

- Today's calls do not change, because `op` defaults to `"eq"`.
- With `op` typed as a `Literal`, a type checker finds a misspelt operator.

### B. One method for each operator (chosen)

```python
users.gte("age", 30)
```

- It is the usual Python style for a small, fixed set of operations.
- A type checker finds a misspelt method.

Neither option lets a type checker find a field that does not support the operator, such as `users.gte("email", x)`. The field is a string, so a type checker cannot know its indexes. Both options raise `QueryError` with `query_unsupported` at run time, before any request. Go finds this at compile time, because its generator writes only the methods each field supports. Python has no generator.

So the choice is about readability, not safety.

## Decision

B.

- `eq`, `lt`, `lte`, `gt`, and `gte` take a field name and a value. Each returns the term as a `str`.
- `between(field, low, high)` returns one `str` term that contains both bounds. Both bounds are included. A range the wrong way round is not refused. It matches no row, as SQL's `BETWEEN` does.
- `query` is removed. The package is not released, so no user code breaks. Keeping it would give two ways to make an equality term.
- `matches(field, text)` returns a match query object, not a `str`. The object has:
  - `term`: the term as a `str`.
  - `target_limit(want, rows=..., histogram=..., confidence=...)`: the number of rows to fetch so that at least `want` of them pass `verify`, at the given confidence. The default confidence is 99%. It returns `None` when the engine cannot work out a finite number. The caller then fetches page by page.
  - `verify(values)`: takes the decrypted values of the field as a list of `str`, and returns one `bool` for each, in order.

The method names are the engine's operator names, as in Go.

`verify` takes strings, not decrypted objects. It works the same for every class kind, and the match query object does not need to read a field from an object.

## Consequences

- The match query object contains the search text as plaintext until Python frees it. `verify` needs the text, because the engine cuts it into tokens again. Go has the same limit. The object must never show the text in `repr` or in an error.
- `verify` is not an exact substring check. It returns `True` when the value contains every 3-character token of the search text, in any order.
- `target_limit` needs statistics from the database: a row count, and for a finite answer a histogram of the stored filters' set-bit counts. `packages/stack-encrypt/src/op/stats.rs` gives the SQL for both.
- `between` needs a second SQL cast on each order marker. The SQL is `eql_v4.between(col, %s::eql_v4.query_integer_range_ope)`, not `BETWEEN`. The Python markers in `_eql.py` do not name the range casts yet, so `eql-codegen py-eql` must add them.
- The README, the tests, and the customer directory example change from `query` to `eq`.
- The later SQLAlchemy layer should hide `target_limit` and `verify`. ORM users do not expect a search to return rows that do not match.
