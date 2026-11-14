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
- `between(field, low, high)` will return one `str` term that contains both bounds. Both bounds are included. A range the wrong way round is not refused. It matches no row, as SQL's `BETWEEN` does. `between` waits for the engine. See "Amendment, 2026-11-10".
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
- `between` needs a second SQL cast on each order marker. The SQL is `eql_v4.between(col, %s::eql_v4.query_integer_range_ope)`, not `BETWEEN`. The Python markers in `_eql.py` do not name the range casts yet. Go's type table does not name them either.
- The README, the tests, and the customer directory example change from `query` to `eq`.
- The later SQLAlchemy layer should hide `target_limit` and `verify`. ORM users do not expect a search to return rows that do not match.

## Amendment, 2026-11-10: `between` waits for the engine

The engine does not build a `between` term for an EQL type yet. A core test asked it for one on an `IntegerOrd` field. The engine refused, with the reason `operator_not_answered`. The comment at the top of `packages/eql/crates/eql-codegen/src/range.rs` says the same. The EQL test `packages/eql/tests/encryption/tests/v4_range.rs` builds its ranges by hand from two single-bound terms.

The Go SDK has the same limit. Its generator writes only the methods the engine supports, so a Go field of an EQL order type has no `Between`.

So Python leaves out `between` for now, and stays at the same level as Go. A range search uses `gte` and `lte`:

```sql
WHERE level >= %s::eql_v4.query_integer_ord AND level <= %s::eql_v4.query_integer_ord
```

We did not choose to build the range in Python from two single-bound terms. Python would then contain its own copy of EQL's range format. No test would keep that copy the same as EQL's.

`between` comes when the engine supports it for EQL types. That is a change to `packages/stack-encrypt`. It would give `between` to Go too. The call shape above stays the plan.
