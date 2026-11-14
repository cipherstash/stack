---
status: accepted
date: 2026-11-02
ticket: "#1391, the first ticket that adds `query`, as the spec (#1341) says"
extends: ADR-0001
amended_by: ADR-0003, ADR-0004
---

# A query names its field by a string

`Cipher.query` takes the field's name as a `str`, and one value:

```python
term = users.query("email", "a@example.com")
```

The call returns the equality query term as a `str`.
There is no operator argument. The first version answers equality only.

The spec in #1341 says the first ticket that adds `query` decides its call shape. This Architecture Decision Record (ADR) records that decision.

## The options

### A. The field's name as a string (chosen)

```python
users.query("email", "a@example.com")
```

- A works for every class kind that core supports: dataclasses, attrs, Pydantic, `NamedTuple`, and SQLAlchemy.
- Core reads only the declaration. Core does not change the user's class.
- A misspelt name fails at the first call, before any request, with `query_unknown_field`. The message lists the fields that have a query.
- A type checker cannot find a misspelt name. An editor's "rename symbol" does not update the string.

### B. The class attribute

```python
users.query(User.email, "a@example.com")
```

- A type checker and an editor see the name. A misspelt name fails before the program runs. A rename updates every call.
- With a typed attribute, such as `Field[str]`, a type checker can also check the value's type.
- B matches the SQLAlchemy style, `User.email == x`.
- B does not work for a plain dataclass, attrs, or Pydantic class. A dataclass field with no default has no class attribute, so `User.email` raises `AttributeError`. A field with a default gives the default value, not the field.
- So core would have to put an attribute on the class for each field. Core does not change the user's class today. ADR-0001 stores the declaration on the class, and adds no attribute that a field would use.

## Decision

A, for now.

B stays open for the later SQLAlchemy layer. A SQLAlchemy model already has a column attribute for each field, so B works there without core changing the class. The layer reads the attribute's name and calls core with the string. The spec in #1341 keeps that layer out of scope for now.

> **Answered by ADR-0004.** On the SQLAlchemy ORM, a query names the field by the class attribute, as in `select(Customer).where(Customer.email == x)`. The column type reads the attribute's name, and calls the `Cipher` with it. The `Cipher` methods still take a string.

A does not block B. A later version can accept a string or an attribute in the same position. A caller who passes a string sees no change.

An operator can come later as a keyword argument, such as `op=`. A caller who passes none still gets equality.

> **Replaced by ADR-0003.** The paragraph above is no longer the plan. ADR-0003 gives each operator its own method, such as `eq` and `gte`, and removes `query`. The field is still named by a string, as this ADR decided.

## Consequences

- `query_unknown_field` and `query_unsupported` are raised in Python, by `Cipher.query`, before the extension is called.
- A typo is found when the call runs, not when a type checker runs. The error message lists the fields that have a query, so the caller can correct the name.
- The SQLAlchemy layer's spec decides whether it accepts `User.email`.
