# Python SDK scorecard: the eight principles for every language SDK

Written on 4 November 2026, against the code that closes spec #1341. G1 to G8 are the eight principles in [`docs/sdk-design-principles.md`](../../../docs/sdk-design-principles.md), "Principles for every language SDK".

Each principle is marked:

- **held:** the code follows it, and a test or a check shows that.
- **strained:** the code follows part of it, or follows it with a known gap.
- **not tested:** nothing runs to show it either way.

## Summary

| Principle | Mark |
|---|---|
| G1. One engine, and the SDK never executes | held |
| G2. A language SDK takes its host language's shape | held |
| G3. Run each check at the earliest stage the language allows | strained |
| G4. One declaration serves the write, the query and the read | held |
| G5. Batch by default | held |
| G6. A second way in has to earn its place | strained |
| G7. State the design, and run its claims | held |
| G8. Usage first, then reference | held |

## G1. One engine, and the SDK never executes: held

- `Cipher.encrypt`, `decrypt`, and each query method make one call into the extension, in `python/stackencrypt/_cipher.py`. The Python layer has no loop over rows, and no loop over a model's values.
- `Cipher.encrypt_rows` and `decrypt_rows` are the exceptions. They loop over the rows in Python. For each row, they check that the row is a mapping with the same declared fields as row 0. They then pass those fields' values to the extension. They do not read, convert, or check a value. The extension does that, as for `encrypt` and `decrypt`.
- The Python layer does loop over the declared fields in two places. `Cipher` lists them once, to build the plan. A query method searches them to name a field it refuses. Neither loop touches a value.
- The extension hands the engine one frame for the whole call, and reads back the engine's whole output. Encryption, decryption, and term derivation all run in `stack-encrypt`.
- The declaration check asks the engine. When the class statement runs, the decorator calls `_engine.check_plan`, and the engine refuses a plan it cannot run. `Cipher` later builds the same plan with `_engine.build_plan`.
- The EQL type rules are not copied. `crates/core` compiles the Go guest's resolver, `languages/golang/encrypt/guest/src/targets.rs`, in place. `python/stackencrypt/_eql.py` is generated from the EQL catalog, and `tests-python.yml` fails on a hand edit.
- The bytes match the Go SDK's. `tests_deterministic/test_go_rows.py` opens the rows the Go SDK stored, and seals the same values to the same terms.

## G2. A language SDK takes its host language's shape: held

- A model is a Python class with a decorator and `typing.Annotated` hints. Dataclasses, attrs, Pydantic, `NamedTuple`, and SQLAlchemy classes all work (`tests/_declaration_cases.py`).
- `encrypt` returns dicts that psycopg inserts with a plain `%s`. `decrypt` takes the rows of psycopg's `dict_row`. `tests/test_encrypt_live.py` runs both against PostgreSQL.
- Errors are exceptions with a code and a message, and a field and a reason where one applies. They are not result objects.
- The words a user writes are the engine's: `TextEq`, `Passthrough`, and the EQL type names.
- The README lists the engine capabilities the SDK does not offer yet, under "What is not supported yet".

## G3. Run each check at the earliest stage the language allows: strained

- Held: a declaration is checked when the `class` statement runs, not at the first call (ADR-0001, `tests/_declaration_cases.py`). Values are checked before any request (`tests/test_values.py`).
- Held: the package ships `py.typed` and a stub for the extension, `_engine.pyi`. So mypy and pyright check the call shapes.
- Strained: the principle asks a dynamic language to ship rules for type checkers and linters. The SDK ships none. A type checker cannot tell that `Annotated[int, TextEq]` pairs the wrong type with a marker. The class statement is the first stage that refuses it.

## G4. One declaration serves the write, the query and the read: held

- `Cipher(User)` builds one plan from the declaration. `encrypt`, the query methods, and `decrypt` all use that plan.
- `encrypt_rows` and `decrypt_rows` use a smaller plan with only the fields a row contains. It is built from the same declaration, with the same table, field names, and markers. `test_a_row_updated_with_some_fields_decrypts_and_searches_with_the_full_model` in `tests/test_encrypt_live.py` shows that its values decrypt and search under the full plan.
- No call takes a context or an index choice. A query method, such as `eq` or `gte`, takes a field name and a value only (Python ADR-0002 and ADR-0003, under `docs/adr/`). The engine picks the index that supports the operator.
- `test_a_query_term_finds_the_one_matching_row` in `tests/test_encrypt_live.py` runs `encrypt`, `eq`, and `decrypt` on one `Cipher` against PostgreSQL. The README test runs the same three steps.
- A context that changes per caller, such as a tenant, is not supported yet. The README lists it.

## G5. Batch by default: held

- `encrypt` and `decrypt` take a list. One call makes one key request for every 500 values, in sequence. `tests/test_encrypt_live.py` counts 3 requests for 1001 values, each way.
- Each query method is the single-value call the principle allows: one field, one search value. It makes no key request after the first call of the process.
- A model's fields of different types go in one request.

## G6. A second way in has to earn its place: strained

Strained, not held: the two gaps below have no test.

- There is one way to declare a model: `stackencrypt.model`. Every class library goes through it. `tests/_declaration_cases.py` declares one model with each of dataclasses, attrs, Pydantic, `NamedTuple`, and SQLAlchemy.
- No test shows that each refusal fires for every one of the five libraries.
- There is one package, `stackencrypt`.
- The SQLAlchemy layer, `stackencrypt.sqlalchemy`, is a second way to encrypt and decrypt. ADR-0004 records its design. It passes the four tests:
  1. **A need the first way cannot meet.** An ORM app uses `Session` and its own objects. With `cipher.encrypt` alone, `examples/customer-directory/app_sqlalchemy.py` could not use `Session` at all.
  2. **The same output, through the same code.** The hooks call `encrypt_rows` and `decrypt_rows`, which run the same `_engine.encrypt` and `_engine.decrypt`. Search terms come from the same `Cipher` methods. `test_a_row_updated_with_some_fields_decrypts_and_searches_with_the_full_model` shows that a value from a smaller plan opens and searches under the full plan. The example's `test_each_app_reads_what_the_other_wrote` shows the two ways read each other's rows.
  3. **The same guarantees, at the same stage.** The declaration is the same decorator. Every value, passthrough values included, is checked before any key request. Errors contain no value. A match search runs `verify` for the app. One difference: the read hook makes one `decrypt_rows` call for each class and set of fields, not one call for the whole result. If a later call fails, the query raises, and the app gets no result.
  4. **Someone owns it.** It has the README section "Use it with the SQLAlchemy ORM", ADR-0004, and four test files. `mise run test` and the `live` job of `tests-python.yml` run them. The owners of this repository, `@cipherstash/developers` in `.github/CODEOWNERS`, own it with the rest of the Python SDK.
- No test checks what SQLAlchemy logs with `echo=True`. The write hook runs before that log, so the log should show EQL values.

## G7. State the design, and run its claims: held

- The design is in four places: spec #1341, Python ADR-0001, Python ADR-0002, and the Python section of `docs/sdk-design-principles.md`.
- The design depends on two claims. Each was run before it was written down. Each is in `docs/gate-facts/`, with what was run and what was not.
- The sync contract is run from the public API: `tests/test_concurrency_live.py` and `tests_deterministic/test_concurrency.py`.

## G8. Usage first, then reference: held

- `README.md` opens with the steps from credentials to a found row, in order. The reference sections follow.
- The usage steps run in CI. `tests/test_readme_live.py` runs the README's SQL and Python blocks in order, in the `live` job. `tests/test_readme.py` compiles the Python blocks on every pull request that changes the Python tree. `tests-python.yml` lists the paths that count.
- There is no agent skill for Python yet. A PyPI release and a skill are out of scope for spec #1341.

## What this scorecard does not show

- The live tests run only in the `live` job. That job skips on a pull request from a fork.
- Nobody but the author has followed the README on a clean machine. The scripted run in `tests/test_readme_live.py` is the evidence for that step instead.
