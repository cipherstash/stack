---
status: proposed
date: 2026-10-16
extends: ADR-0007, ADR-0008 (packages/stack-encrypt/docs/adr)
ticket: the Python SDK discovery ticket, backlog item 1 (its 15 October 2026 amendment)
---

# A declaration is checked when Python defines the class, by construction

The Python SDK declares a model with one class decorator.
The decorator carries the context, reads the `Annotated` hints, asks the
engine to check the plan, and stores the result on the class.
The check runs as the `class` statement finishes, every time, wherever the
class is defined.
The call site takes the class: `Cipher(User)`.
No public name is a plan or returns one.

This is the trade-off memo for backlog item 1's first question, written as
the ADR the gate will accept or amend.
The reviewers decide (the ticket, decision 7).

## The problem

The Python SDK discovery ticket says the engine checks a declaration "when Python defines the
class" (week-1 step 2) and "at import" (decisions 6 and 20).
The first tracer checked at `build()`:

```python
plan = Cipher(Plan.of(User).context("users").build())
```

That is import time only when the statement sits at module level.
Put it in a function, a fixture or a lazy factory and a forgotten field is
found at the first write, which can be in production.
Nothing fires when the `class` statement finishes.
So the ticket's sentence held by convention, and the amendment asks which
it must be: by construction or by convention.

The same amendment asks for the model contract.
The tracer used `@dataclass`, which is one way to meet the contract and
not the contract itself.

## Options considered

### 1. By convention: a plan statement beside the class

`Plan.of(User).context("users").build()` as the tracer wrote it.

- The check runs where the statement runs.
  The ticket's sentence is a description, not a guarantee.
- The user holds a plan object and hands it to `Cipher`.
  Go principle 7 ("the user never sees the plan") is Go-only, but its
  reason is not: a plan is engine vocabulary the user cannot act on
  (principle order, rule 3).
- The context is a method call, apart from the class it describes.
- No ordering question with other decorators.

### 2. By construction: a class decorator (recommended)

```python
import stackencrypt as stash

@stash.model("users")
@dataclass
class User:
    email: Annotated[str, stash.TextEq]
    age: Annotated[int, stash.Passthrough]
    nickname: str          # DeclarationError here, at the class statement

cipher = stash.Cipher(User)
```

- The check runs as the class is defined, always.
  A class defined inside a function is checked when that function runs,
  which is still "when Python defines the class".
- The context sits on the class.
  One class, one context, which is how SQLAlchemy and Django already think
  (one class, one table).
  The engine stamps the EQL identifier `i.t` from the first context piece,
  so that piece and the table name should be the same word.
- A class the user does not own is declared by the same callable:
  `stash.model("users")(ThirdPartyModel)`.
  A decorator is a function; applying it after the fact is the same way in,
  through the same code, so principle G6 holds with one way.
  The reader `Plan.of` leaves the public surface.
- The decorator must be outermost.
  See "Decorator order" below for what happens when it is not.

### 3. By construction: a base class or metaclass

`class User(stash.Model)` with `__init_subclass__` running the check.

- Also runs at class definition.
- Rejected: the first user's classes already have a base
  (`DeclarativeBase`, `pydantic.BaseModel`), and `NamedTuple` takes none.
  Two metaclasses do not combine.
  Python's current idiom for "this class is one of these" is the decorator
  (`dataclass`, `attrs.define`, `registry.mapped`), not the base class.

### 4. Both the decorator and `Plan.of`

Rejected by principle G6, test 1: the only need named for `Plan.of`, a
class the user does not own, is met by calling the decorator as a function.

## Decision

Option 2.

1. **The check at class definition is a requirement, not a description.**
   Principle G3 says run each check at the earliest stage the language
   allows.
   For a declaration, the earliest moment it exists is the end of the
   `class` statement.
   A decorator, a metaclass and `__init_subclass__` all reach that moment.
   The decorator is the one that also works with the bases the first
   user's classes already have (option 3).
2. **One decorator, and it carries the context.**
   `@stash.model("users")`, with one argument: the table.
   The engine's target context is exactly a table and a column, and the
   column is the field's name, so the class needs nothing more.
   The name is open to the reviewers; the alternatives are
   `@stash.encrypted(...)` and `@stash.declare(...)`.
   The argument is documented once as the engine's `context`.
   A record that names its own tenant (the engine's `context_field`) is
   a record-level setting in the plan grammar, so if the SDK supports it,
   it is a second decorator argument and not a field marker.
   The first version does not support it; a tenant attaches to the cipher.
3. **The decorator does four things and nothing else.**
   It reads the hints, builds the field map, asks the engine to check the
   plan, and stores the result on the class under one dunder attribute.
   It makes no network request and needs no credentials.

   Two checks run, and they are not the same check:
   - **Python's**: every field carries a marker (rule A), and the decorator
     is outermost (the constructor check in decision 5).
   - **The engine's**: the plan grammar, which indexes the declared kind
     admits (`dynamic::admits`), and whether a named EQL type is one the
     build can produce.
     The call is `dynamic::record::plan_with` with the target resolver,
     the same call the Go generator makes through `se_plan_check`.
4. **The call site takes the class.** `Cipher(User)`.
   `Cipher` refuses a class the decorator has not seen, with the remedy in
   the message.
   No public name is called a plan or returns one.

   `DeclarationError` and that refusal are built from structured facts:
   the field name and the engine's `Reason`, as the language-integration
   guide gives them, never by parsing the engine's message text.
   No message carries a value.
   A dataclass default is a value, so a message names the field and not
   its default.
5. **The model contract is a `Protocol`, not a dataclass.**
   A model class must give:
   - field hints that `typing.get_type_hints(cls, include_extras=True)`
     returns, each carrying its stash markers in `Annotated`;
   - a constructor that accepts every declared field as a keyword argument;
   - attribute access by field name on an instance.

   The first two are checked at decoration.
   The constructor check reads `inspect.signature(cls)` and accepts a
   `**kwargs` parameter.
   The third is checked only when a row is read; Python cannot check it
   earlier.
   `is_dataclass` is not the guard: it rejects classes that meet the
   contract.
6. **Plaintext crosses the binding as a frame built in Rust.**
   On `next` the engine reads a record as a `ValueFrame` and holds no
   tree type for plaintext.
   The extension reads the model's attributes straight into a frame, and
   builds the model instance straight from the decrypted frame.
   No plaintext passes through a Python `dict` on the way in or out.
   The model instance is the one plaintext copy Python owns, and Python
   cannot wipe a `str` or `bytes`, so that copy is documented as the
   user's.
   The plan the decorator sends is a frame too; its grammar is the guide's.
7. **Rule A is assumed and not decided here.**
   Every field carries a marker; a plain field carries `Passthrough`.
   Backlog item 1.2 decides it after the user test.
   The decorator is what makes the rule fire at class definition.
8. **The marker spelling is the recommended option for item 1.1, not a
   decision of this ADR.**
   A sealed field's marker names an EQL type, such as `TextEq`.
   The marker names are generated from the EQL catalog by `eql-codegen`,
   the way the Go SDK's `encrypt/eql` package is, so Python holds no
   table that maps a kind and an index to an EQL type (principle G1).
   `Passthrough` is the one hand-written marker: a field stored as it is,
   and the engine's word for it (principle G2).
   Markers are names, not calls.

   | Field | Spelling |
   | --- | --- |
   | Encrypted, equality index | `Annotated[str, stash.TextEq]` |
   | Encrypted, no index | `Annotated[str, stash.Text]` |
   | Not encrypted | `Annotated[int, stash.Passthrough]` |

   Whether the kind can also come from the Python type (`str` for text)
   instead of the marker is the user-test question of item 1.1.
   An earlier draft of this ADR spelled a field as a kind marker plus an
   index marker (`stash.Text, stash.Equality`).
   That spelling needs a Python copy of the catalog's kind-and-index
   table, which is what G1 forbids, so it was dropped at review.

9. **A model never prints a sealed value, by default.**
   The decorator writes `__repr__` and `__str__` on the class it
   decorates and on the encrypted type the SDK returns.
   Both print the passthrough fields and `[sealed]` in place of each
   sealed field's value, the format of Go's generated `String` and
   `LogValue`.
   The same markers that drive encryption drive the print, so a sealed
   field added later is hidden the day it is added; no per-field
   `repr=False` is needed, and none is read.
   Python's `logging` calls `__str__`, so logs are covered by the same
   methods.
   `@stash.model("users", redact=False)` is the class-level opt-out.
   A class that defines its own `__repr__` or `__str__` by hand is
   refused at the class statement with the remedy named (`redact=False`,
   or remove the method); the decorator does not replace a method the
   user wrote.
   The methods `dataclass`, attrs and Pydantic generate are replaced,
   since the decorator is outermost.
   This is Go's `stashgen -redact` made the default, which Python can do
   because the decorator holds the user's class and a generator does not.
   A linter rule that reports a print of an opted-out model is open
   (principle G3).

## What was run

A probe on 2026-10-16, Python 3.14.2, attrs 26.1.0, pydantic 2.14.1,
SQLAlchemy 2.1.4, with stand-in markers and no engine.
The restart's test suite carries these as tests; the probe is not
committed.

| Class style | Reader finds the markers | kwargs constructor | `getattr` |
| --- | --- | --- | --- |
| `@dataclass` | yes | yes | yes |
| `@dataclass(slots=True)` under the decorator | yes | yes | yes |
| `NamedTuple` | yes | yes | yes |
| `@attrs.define` | yes | yes | yes |
| `pydantic.BaseModel` | yes | yes (keyword-only) | yes |
| SQLAlchemy `DeclarativeBase` | yes, through `Mapped[Annotated[...]]` | yes (`**kwargs`) | yes |

Two more facts from the probe:

- SQLAlchemy writes its hints as `Mapped[Annotated[str, ...]]`.
  The reader found the markers by looking through the `Mapped` wrapper,
  and SQLAlchemy ignored the unknown marker objects and mapped the column.
  Which wrappers the core reader looks through is decided with the
  SQLAlchemy layer (backlog item 2); the core must not import SQLAlchemy.
- With `@dataclass(slots=True)` **above** the decorator (the wrong order),
  the stored attribute survived, because `dataclass` copies the class
  dictionary.
  What fails is the constructor check: at decoration time the class has no
  `__init__` yet, so its signature is `()`.
  The decorator therefore reports the wrong order itself, naming the fix.

A second rig on 2026-10-20 put the engine call inside the decorator.
It used the prototype's built extension only as the engine entry
(`plan_with` behind its `check_plan`), with every `CS_*` variable unset:

| Class | Who refused | Where it fired |
| --- | --- | --- |
| a good declaration | nobody; the engine resolved the target to `TextEq` | the class statement |
| a field with no marker | Python's check | the class statement |
| `Match` on an `Int64` field | the engine: "the declared type has no such index" | the class statement |

The rig ran against `main`'s engine, before the frame change on `next`.
The claim it tests, that a decorator reaches the engine as the class is
defined, does not depend on the plan's wire form.
The rig is not committed.

Not run: the error text a user sees, which the restart builds from the
engine's structured reason fields; and the replacement of the
`__repr__` that attrs and Pydantic generate, which the probe did not cover.

## Consequences

- The restart plan carries the language-integration guide's checklist
  (its section 11): the frame conformance corpus byte for byte, a
  differential fuzz target over the Python codec, plaintext hygiene tests
  for the extension's copies, a frozen stored-rows fixture, the engine and
  frame-format versions named in the wheel's release notes, and the
  cross-language fixtures read from the Python tests.
  The first test is the guide's section 10 bytes reproduced from Python.
- Importing a module that declares a model imports the native extension.
  The check needs the engine's rules and holds no copy of them
  (principle G1).
  It makes no network request.
- "Was this class declared?" is an import-time check, not a type-check.
  pyright and mypy see the decorator as identity, `type[T] -> type[T]`,
  and cannot require a decorated class at `Cipher(User)`.
  This is a strain against G3 that backlog item 1.3 (a generate step, or a
  typed wrapper) may close.
- The decorator stacks above every other decorator.
  The documentation says so once, and the constructor check reports the
  wrong order with the fix.
- A class the user does not own gains one dunder attribute.
  That is what `dataclass` and `attrs` do too.
- One context per class.
  What varies per caller, such as a tenant, attaches to the cipher through
  the engine's extend (principle G4), not to the class.
- `Plan`, `PlanBuilder` and `PlanSpec` leave the public surface.
  The engine's plan grammar still exists behind the decorator; the user
  never names it.
- The marker set is generated, so a new EQL type needs no change to the
  declaration reader.
  The reader passes a marker's name to the engine as the plan's `target`,
  and the engine decides whether the catalog produces it.
  A new kind (`date`, `timestamp`, `decimal` landed on `next`) needs a
  codec in the shell for the value's bytes and a regeneration of the
  markers, and nothing else in Python.
- Python has less kind ambiguity than Go.
  Go's `time.Time` can mean a date or a timestamp.
  Python's `datetime.date` and `datetime.datetime` are different types, so
  the hint alone can pick the kind when those kinds land.
- The week-1 step 2 sentence becomes true by construction, and the
  scorecard marks G3 "held" for the declaration check.
- Backlog item 1 still owes two memos: 1.1 (`Annotated` against other
  shapes) and 1.3 (typing the encrypted output).
  This ADR takes `Annotated` as the input they compare against, which is
  decision 5's default.
