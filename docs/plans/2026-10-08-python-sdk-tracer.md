# Python SDK Tracer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Python SDK tracer that declares encrypted fields with `Annotated` hints, encrypts a batch of models through the Rust engine, stores them in EQL v3 Postgres columns, finds them with an equality query, and decrypts them back — in one end-to-end path.

**Architecture:** A thin PyO3 shell (`languages/python`) over `stack-encrypt`. Python builds a **data plan** — a plain dict matching `dynamic::record`'s wire grammar — and hands it plus the values to the engine. The engine does all encryption, term derivation and EQL framing; Python never loops over fields, batches requests or encodes EQL. The EQL types come from `eql_bindings::encryption::targets`, wrapped as a `TargetResolver` exactly as the Go guest does. Sync calls only: a single Tokio runtime drives the engine's `Pending` futures with the GIL released.

**Tech Stack:** Rust (PyO3 0.23+, maturin), Python 3.9+ (`abi3`), `stack-encrypt`, `eql-bindings` (feature `stack-encrypt`), psycopg 3, pytest.

**Spec:** Linear CIP-4340, "Python SDK: requirements for discovery and a working prototype". Supporting design: [`docs/sdk-design-principles.md`](../sdk-design-principles.md), [`docs/plans/2026-10-04-plan-builder.md`](2026-10-04-plan-builder.md).

## Global Constraints

- **Base branch: `origin/main`** (@ 6f388478c or later). Corrected 2026-10-08: this said `feat/stack-encrypt-required-type` (PR #1096), because `main` had no `target` form in the data plan. #1095 and #1096 were then **squash-merged** into main, so `git merge-base --is-ancestor` still reports the branch as unmerged while the content is there. Verify by content, not ancestry — on `origin/main`: `FieldPlan.target: Option<String>`, the grammar line `{ "context": …, "target": "<EQL type name>", "type": … }`, and `"type"` **required on every field with a term output**. Both templates Task 4 needs are on main too.
- **Nothing is published.** No PyPI release, no `stash` tarball change, no `skills/` entry, no docs-site page.
- **Sync only.** Async is backlog item 4.
- **Location: `languages/python`**, its own Cargo workspace, excluded from the root workspace — the same arrangement as `languages/typescript/packages/protect-ffi`, and for the same reason (it takes a cross-workspace path dependency on `eql-bindings`).
- **`eql-bindings` resolves by path, never from a registry.** `scripts/lint-no-eql-registry-pins.mjs` fails the build otherwise.
- **Engine vocabulary in the public API**: `context`, `encrypt_into`, `passthrough`, `equality`, `match`, `ore`. Principle G2.
- **Six wheel targets**, matching what protect-ffi ships: `darwin-arm64`, `darwin-x64`, `linux-arm64-gnu`, `linux-x64-gnu`, `linux-x64-musl`, `win32-x64-msvc`. Record build time, cache behaviour and toolchain setup for each.
- **Rust toolchain is 1.94.1**, pinned in the root `mise.toml`. `languages/python` inherits it; do not add a second pin.
- **No plaintext in any log or error message.** Repo-wide rule.
- **Python code must not loop over fields, batch requests or encode EQL.** Pass check 5 of the spec. Enforced by Task 9's scorecard and by review.

## Review Focus

Five input classes the spec implies but which no task's happy path exercises. Each has a test attached to the task that owns the code.

1. **A Python `int` outside the declared width.** `2**63` into an `Int64` field. The spec names this as a risk and requires fail-closed. Test in Task 3.
2. **A model field with no stash annotation.** Decision 20 says error at import, not silent passthrough. Test in Task 3.
3. **A value of the wrong Python type for the declared field type.** A `str` into a field declared `Int64`. The engine's kind check must refuse it before any key is minted. Test in Task 4.
4. **`None` in an encrypted field.** The spec is silent. A tracer that seals `None` as a string, or panics, are both wrong; refuse it with a named error. Test in Task 5.
5. **An empty batch.** `encrypt([])` under batch-by-default. Must return an empty list and make **no** ZeroKMS request, not fail and not send an empty request. Test in Task 5.

---

## File Structure

```
languages/python/
  Cargo.toml                  # own workspace; members = ["."]
  Cargo.lock                  # committed
  pyproject.toml              # maturin backend, abi3-py39
  README.md                   # usage first: the round trip, in order (G8)
  src/
    lib.rs                    # #[pymodule] stackencrypt._engine
    runtime.rs                # the one Tokio runtime; block_on with the GIL released
    convert.rs                # PyObject <-> FfiValue, both directions
    targets.rs                # TargetResolver over eql_bindings::encryption::targets
    errors.rs                 # engine errors -> Python exception types
  python/
    stackencrypt/
      __init__.py             # public surface
      _markers.py             # Equality/Match/Ore/Passthrough/EQL, Int64 & friends
      _declare.py             # read Annotated hints -> data plan dict
      plan.py                 # Plan.of(cls).context(...).build()
      cipher.py               # Cipher: encrypt/decrypt/query, sync
      errors.py               # DeclarationError, PlanError, EngineError
  tests/
    test_declare.py           # pure; no engine, no network
    test_plan.py              # engine plan parse + refusals; no network
    test_roundtrip.py         # live ZeroKMS
    test_bytes.py             # byte check against the Rust fixture
    test_postgres.py          # live ZeroKMS + EQL v3 Postgres
    fixtures/
      record.json             # local fixture; the shared one is not on main
  scorecard.md                # G1-G8, one page
.github/workflows/tests-python.yml
```

Responsibilities, so the boundaries are not guessed:

- `_declare.py` turns a class into the **data plan dict** and nothing else. It never touches values and never calls the engine. This is the file the declaration-shape backlog item will rewrite, so nothing else may know how an annotation is spelled.
- `convert.rs` is the only place a Python object becomes an `FfiValue`. Width checks live here, because that is where the Python `int` is still a Python `int`.
- `targets.rs` is the only place that names an EQL type. It asks the engine's resolver for descriptors; it holds no table of EQL names.
- `cipher.py` holds no field logic. It hands a plan and a list of rows to the engine in one call.

---

### Task 1: The crate builds, and `import stackencrypt` works

**Files:**
- Create: `languages/python/Cargo.toml`
- Create: `languages/python/pyproject.toml`
- Create: `languages/python/src/lib.rs`
- Create: `languages/python/python/stackencrypt/__init__.py`
- Create: `languages/python/README.md`
- Create: `languages/python/tests/test_declare.py` (one import test for now)
- Modify: `Cargo.toml` (root) — add `languages/python` to `exclude`
- Modify: `AGENTS.md` — Repository Layout entry
- Modify: `SECURITY.md` — package list entry

**Interfaces:**
- Consumes: nothing.
- Produces: the Python module `stackencrypt`, and the native submodule
  `stackencrypt._engine` exposing `version() -> str`.

- [ ] **Step 1: Write the failing test**

`languages/python/tests/test_declare.py`:

```python
def test_engine_module_loads():
    import stackencrypt

    assert isinstance(stackencrypt.engine_version(), str)
    assert stackencrypt.engine_version() != ""
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd languages/python && python -m pytest tests/test_declare.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'stackencrypt'`.

- [ ] **Step 3: Write the workspace manifest**

`languages/python/Cargo.toml`:

```toml
# Its own Cargo workspace, excluded from the root one. The reason is the
# `eql-bindings` path dependency below: that crate is a member of the EQL
# workspace (`packages/eql`), which pins its own vitaminc. Cargo accepts a
# path dep across workspaces, and keeping the workspaces separate is what
# stops the root resolver pulling EQL's graph into every stack-* build.
# `languages/typescript/packages/protect-ffi` is arranged the same way for
# the same reason.
[workspace]
resolver = "2"
members = ["."]

[package]
name = "stackencrypt-python"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
# maturin imports this as `stackencrypt._engine`.
name = "_engine"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.23", features = ["abi3-py39", "extension-module"] }
stack-encrypt = { path = "../../packages/stack-encrypt" }
# Never a registry version: the Rust that EMITS a payload and the SQL that
# STORES one must move together. `scripts/lint-no-eql-registry-pins.mjs`
# enforces this.
eql-bindings = { path = "../../packages/eql/crates/eql-bindings", features = [
  "stack-encrypt",
] }
vitaminc-aead-value = { workspace = false, version = "*" }
tokio = { version = "1", features = ["rt-multi-thread"] }
```

Resolve `vitaminc-aead-value` to the exact version `packages/stack-encrypt/Cargo.toml` names rather than `*`; copy the requirement verbatim from there in Step 4.

- [ ] **Step 4: Match the vitaminc requirement to stack-encrypt's**

```bash
grep -n 'vitaminc-aead-value' packages/stack-encrypt/Cargo.toml
```

Copy the version requirement into `languages/python/Cargo.toml`, replacing the `workspace = false, version = "*"` placeholder. A mismatch here produces two `FfiValue` types with the same name and an error that names neither file.

- [ ] **Step 5: Write the Python packaging manifest**

`languages/python/pyproject.toml`:

```toml
[build-system]
requires = ["maturin>=1.7,<2.0"]
build-backend = "maturin"

[project]
name = "stackencrypt"
version = "0.0.0"
description = "Searchable encryption for Python, over the CipherStash Stack engine. Tracer; not released."
requires-python = ">=3.9"
classifiers = ["Private :: Do Not Upload"]

[project.optional-dependencies]
test = ["pytest>=8", "psycopg[binary]>=3.2"]

[tool.maturin]
# The Rust extension is a submodule of the pure-Python package, so the
# declaration code can be edited without a recompile.
module-name = "stackencrypt._engine"
python-source = "python"
features = ["pyo3/extension-module"]
```

- [ ] **Step 6: Write the module entry point**

`languages/python/src/lib.rs`:

```rust
//! The PyO3 shell. It is deliberately thin: a plan and values go in, values
//! come out. Everything that encrypts, derives a term or frames an EQL
//! payload happens in `stack-encrypt`, so a later move to a different FFI
//! replaces this crate and nothing above it.

use pyo3::prelude::*;

/// The `stack-encrypt` version this wheel was built against. The one export
/// that needs no engine state, so it is what proves the wheel loads.
#[pyfunction]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(version, module)?)?;
    Ok(())
}
```

- [ ] **Step 7: Write the Python surface**

`languages/python/python/stackencrypt/__init__.py`:

```python
"""Searchable encryption for Python, over the CipherStash Stack engine.

Tracer. The public names here are meant to continue into the real SDK; the
code behind them is not.
"""

from stackencrypt import _engine

__all__ = ["engine_version"]


def engine_version() -> str:
    """The engine version this wheel was built against."""
    return _engine.version()
```

- [ ] **Step 8: Build and run the test**

```bash
cd languages/python && pip install maturin && maturin develop --extras test
python -m pytest tests/test_declare.py -v
```

Expected: PASS.

- [ ] **Step 9: Write the README, usage first**

`languages/python/README.md`. Principle G8 — the steps to run the round trip, in order, before any reference material:

```markdown
# stackencrypt (tracer)

A tracer for the Python SDK. Not released, and not for production.

## Run the round trip

1. Install the toolchain:

       pip install maturin
       cd languages/python && maturin develop --extras test

2. Set credentials (or run `npx stash auth login` first):

       export CS_WORKSPACE_CRN=... CS_CLIENT_ID=... CS_CLIENT_KEY=... CS_CLIENT_ACCESS_KEY=...

3. Start Postgres with EQL v3 installed, and point the tests at it:

       export DATABASE_URL=postgres://...

4. Run it:

       python -m pytest tests -v

## What it does

See `scorecard.md` for which of the eight SDK design principles hold, strain
or are untested.
```

- [ ] **Step 10: Add the workspace exclusion**

In the root `Cargo.toml`, inside `exclude`, after the two WASI guest entries:

```toml
  # The PyO3 shell: its own workspace, because it takes a path dependency on
  # `eql-bindings` from the EQL workspace. See languages/python/Cargo.toml.
  "languages/python",
```

- [ ] **Step 11: Verify the root workspace still resolves**

```bash
cargo metadata --locked --format-version 1 > /dev/null && echo OK
cd languages/python && cargo check && cargo fmt --check && cargo clippy --all-targets
```

Expected: all succeed. If the root command fails with a lock error, the
exclusion is wrong — a path listed in both `members` and `exclude` is an
error, and a path in neither is pulled in implicitly.

**`cargo build` is deliberately not the check here.** `pyo3`'s
`extension-module` feature tells the crate not to link libpython: the
interpreter resolves those symbols when it imports the module. A plain
`cargo build` therefore fails at link with dozens of `Undefined symbols …
"_PyBytes_AsString"` lines, on a crate that is perfectly correct. maturin is
what passes `-undefined dynamic_lookup`, so **`maturin develop` in Step 8 is
the real link check** and `cargo check` is the compile check. This said
`cargo build` until 2026-10-08; it cannot work with `extension-module` on.

- [ ] **Step 12: Update the meta files**

In `AGENTS.md`, under Repository Layout, after the `languages/golang` entry:

```markdown
- `languages/python`: The Python SDK tracer (`stackencrypt`) — a PyO3 shell over
  `stack-encrypt`, with `eql-bindings` by path for the EQL types. A **fourth
  Cargo workspace**, excluded from the root one for the same reason
  protect-ffi's is. Nothing here is published: no PyPI release, and the wheel
  matrix in `tests-python.yml` exists to measure build cost, not to ship.
  Tracer scope and the backlog of open design questions are in
  `docs/plans/2026-10-08-python-sdk-tracer.md`.
```

Also correct the "Three Cargo workspaces, not one" bullet under "Working on
the Rust crates" to four, naming this one.

In `SECURITY.md`, add `stackencrypt` to the package list with a note that it
is unpublished.

- [ ] **Step 13: Commit**

```bash
git add languages/python Cargo.toml AGENTS.md SECURITY.md
git commit -m "feat(python): a PyO3 shell that loads, in its own Cargo workspace"
```

---

### Task 2: Python values cross to `FfiValue` and back

**Files:**
- Create: `languages/python/src/convert.rs`
- Create: `languages/python/src/errors.rs`
- Create: `languages/python/python/stackencrypt/errors.py`
- Modify: `languages/python/src/lib.rs`
- Create: `languages/python/tests/test_convert.py`

**Interfaces:**
- Consumes: Task 1's `stackencrypt._engine`.
- Produces:
  - Rust: `convert::to_ffi(&Bound<'_, PyAny>, Option<ValueKind>) -> Result<FfiValue, ConvertError>`
    and `convert::from_ffi(Python<'_>, FfiValue) -> PyResult<PyObject>`.
  - Python: `stackencrypt._engine.roundtrip(value, kind)` — conversion both
    ways with no encryption, so the codec is testable without credentials.
  - Python: `stackencrypt.errors.DeclarationError`, `PlanError`, `EngineError`,
    all deriving from `StackEncryptError`.
  - Python: `stackencrypt.Int64`, `Int32`, `Float64`, `Text`, `Bool` — the
    width-bearing annotation types, re-exported from `_markers`.

- [ ] **Step 1: Write the failing test**

`languages/python/tests/test_convert.py`:

```python
import pytest

from stackencrypt import Float64, Int64, Text, _engine
from stackencrypt.errors import EngineError


def test_text_roundtrips():
    assert _engine.roundtrip("bob@example.com", "Utf8Str") == "bob@example.com"


def test_int_roundtrips_as_int_not_float():
    result = _engine.roundtrip(34, "Int64")
    assert result == 34
    assert isinstance(result, int)
    assert not isinstance(result, float)


def test_float_roundtrips_as_float():
    result = _engine.roundtrip(34.0, "Float64")
    assert isinstance(result, float)


# Review Focus 1: a Python int has no width, so the shell is the last place
# that can refuse an out-of-range one. The engine would take the tag and
# derive a term for whatever it was truncated to.
def test_int_over_the_declared_width_is_refused():
    with pytest.raises(EngineError, match="Int64"):
        _engine.roundtrip(2**63, "Int64")


def test_negative_int_under_the_declared_width_is_refused():
    with pytest.raises(EngineError, match="Int64"):
        _engine.roundtrip(-(2**63) - 1, "Int64")


# Review Focus 3: a str where an Int64 is declared.
def test_wrong_python_type_for_the_declared_kind_is_refused():
    with pytest.raises(EngineError):
        _engine.roundtrip("34", "Int64")


def test_bool_is_not_an_int():
    # `isinstance(True, int)` is True in Python, so a bool reaches an Int64
    # field unless the conversion checks bool first.
    with pytest.raises(EngineError):
        _engine.roundtrip(True, "Int64")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd languages/python && python -m pytest tests/test_convert.py -v
```

Expected: FAIL — `module 'stackencrypt._engine' has no attribute 'roundtrip'`.

- [ ] **Step 3: Write the error types**

`languages/python/src/errors.rs`:

```rust
//! Engine and shell failures as Python exceptions. No plaintext reaches a
//! message here: a refusal names the field, the declared kind and the kind
//! that arrived, never the value.

use pyo3::create_exception;
use pyo3::exceptions::PyException;

create_exception!(_engine, StackEncryptError, PyException);
create_exception!(_engine, DeclarationError, StackEncryptError);
create_exception!(_engine, PlanError, StackEncryptError);
create_exception!(_engine, EngineError, StackEncryptError);

/// A conversion failure, before any key is minted.
#[derive(Debug)]
pub enum ConvertError {
    /// A value of another kind than the field declares.
    Kind { declared: String, got: String },
    /// An integer outside the declared kind's range.
    Range { declared: String },
    /// A kind name no `ValueKind` has.
    UnknownKind { name: String },
    /// A Python type the codec has no mapping for.
    Unsupported { got: String },
}

impl From<ConvertError> for pyo3::PyErr {
    fn from(error: ConvertError) -> Self {
        match error {
            ConvertError::Kind { declared, got } => EngineError::new_err(format!(
                "field declares {declared}, got a value of kind {got}"
            )),
            ConvertError::Range { declared } => {
                EngineError::new_err(format!("integer out of range for {declared}"))
            }
            ConvertError::UnknownKind { name } => {
                PlanError::new_err(format!("no value kind named {name}"))
            }
            ConvertError::Unsupported { got } => {
                EngineError::new_err(format!("no encoding for Python type {got}"))
            }
        }
    }
}
```

- [ ] **Step 4: Write the conversion**

`languages/python/src/convert.rs`:

```rust
//! The only place a Python object becomes an `FfiValue`, and the only place
//! one becomes a Python object again.
//!
//! Width lives here on purpose. A Python `int` is arbitrary precision, so
//! `34` says nothing about `Int64` versus `Int32`, and the engine derives a
//! different ORE term for each. The declared kind arrives with the value and
//! is checked before the value crosses, which is the earliest stage this
//! language allows (principle G3).

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyFloat, PyInt, PyString};
use stack_encrypt::dynamic::{FfiValue, ValueKind};

use crate::errors::ConvertError;

/// The `ValueKind` a plan's `"type"` string names.
pub fn kind(name: &str) -> Result<ValueKind, ConvertError> {
    stack_encrypt::dynamic::read(name).ok_or_else(|| ConvertError::UnknownKind {
        name: name.to_owned(),
    })
}

/// One Python value as an `FfiValue`, checked against `declared` when the
/// field has one.
pub fn to_ffi(
    value: &Bound<'_, PyAny>,
    declared: Option<ValueKind>,
) -> Result<FfiValue, ConvertError> {
    // `isinstance(True, int)` is true in Python, so bool comes first or every
    // bool reaches an integer field.
    let produced = if value.is_instance_of::<PyBool>() {
        FfiValue::Bool(value.extract::<bool>().map_err(|_| ConvertError::Kind {
            declared: label(declared),
            got: "Bool".to_owned(),
        })?)
    } else if value.is_instance_of::<PyInt>() {
        integer(value, declared)?
    } else if value.is_instance_of::<PyFloat>() {
        FfiValue::Float64(value.extract::<f64>().map_err(|_| ConvertError::Kind {
            declared: label(declared),
            got: "Float64".to_owned(),
        })?)
    } else if value.is_instance_of::<PyString>() {
        FfiValue::String(value.extract::<String>().unwrap().into_bytes())
    } else if value.is_instance_of::<PyBytes>() {
        FfiValue::Bytes(value.extract::<Vec<u8>>().unwrap())
    } else {
        return Err(ConvertError::Unsupported {
            got: value
                .get_type()
                .name()
                .map(|name| name.to_string())
                .unwrap_or_else(|_| "?".to_owned()),
        });
    };

    if let Some(declared) = declared {
        let got = stack_encrypt::dynamic::Value::kind_of(&produced);
        if got != declared {
            return Err(ConvertError::Kind {
                declared: format!("{declared:?}"),
                got: format!("{got:?}"),
            });
        }
    }
    Ok(produced)
}

/// A Python integer narrowed to the declared kind, or refused. With no
/// declared kind the value takes `Int64`, which is the transitional
/// behaviour the data plan's optional `"type"` allows; fill `"type"` and
/// this branch is unreachable.
fn integer(
    value: &Bound<'_, PyAny>,
    declared: Option<ValueKind>,
) -> Result<FfiValue, ConvertError> {
    let declared = declared.unwrap_or(ValueKind::Int64);
    let label = format!("{declared:?}");
    match declared {
        ValueKind::Int64 => value
            .extract::<i64>()
            .map(FfiValue::Int64)
            .map_err(|_| ConvertError::Range { declared: label }),
        ValueKind::Int32 => value
            .extract::<i32>()
            .map(FfiValue::Int32)
            .map_err(|_| ConvertError::Range { declared: label }),
        ValueKind::Float64 => Err(ConvertError::Kind {
            declared: label,
            got: "Int64".to_owned(),
        }),
        other => Err(ConvertError::Kind {
            declared: format!("{other:?}"),
            got: "Int64".to_owned(),
        }),
    }
}

/// An `FfiValue` as a Python object. The declared kind decides what comes
/// back, which is why a field with a term output must declare one: a host
/// with no type to infer from cannot tell an Integer from a Float, or bytes
/// from a String.
pub fn from_ffi(py: Python<'_>, value: FfiValue) -> PyResult<PyObject> {
    Ok(match value {
        FfiValue::Bool(inner) => inner.into_pyobject(py)?.to_owned().into_any().unbind(),
        FfiValue::Int32(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::Int64(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::Float64(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::String(bytes) => String::from_utf8_lossy(&bytes)
            .into_pyobject(py)?
            .into_any()
            .unbind(),
        FfiValue::Bytes(bytes) => PyBytes::new(py, &bytes).into_any().unbind(),
        other => {
            return Err(crate::errors::EngineError::new_err(format!(
                "no Python mapping for {other:?}"
            )))
        }
    })
}

fn label(declared: Option<ValueKind>) -> String {
    declared.map_or_else(|| "no kind".to_owned(), |kind| format!("{kind:?}"))
}
```

If `FfiValue`'s variant names or `Value::kind_of` differ on the base branch,
read them and adjust — `git show origin/feat/stack-encrypt-required-type:packages/stack-encrypt/src/dynamic/value.rs`
and the `vitaminc_aead_value::FfiValue` definition are the sources. Do not
guess a variant name; the compiler names the right one.

- [ ] **Step 5: Expose the round trip and the errors**

In `languages/python/src/lib.rs`, add:

```rust
mod convert;
mod errors;

/// A value through the codec and back, with no encryption. Here so the
/// conversion rules — especially the integer width checks — are testable
/// without credentials or a database.
#[pyfunction]
#[pyo3(signature = (value, kind = None))]
fn roundtrip(py: Python<'_>, value: &Bound<'_, PyAny>, kind: Option<&str>) -> PyResult<PyObject> {
    let declared = kind.map(convert::kind).transpose()?;
    let crossed = convert::to_ffi(value, declared)?;
    convert::from_ffi(py, crossed)
}
```

and in `_engine`:

```rust
    module.add_function(wrap_pyfunction!(roundtrip, module)?)?;
    module.add("StackEncryptError", py.get_type::<errors::StackEncryptError>())?;
    module.add("DeclarationError", py.get_type::<errors::DeclarationError>())?;
    module.add("PlanError", py.get_type::<errors::PlanError>())?;
    module.add("EngineError", py.get_type::<errors::EngineError>())?;
```

Take `py: Python<'_>` as the `#[pymodule]` function's first argument to reach
`get_type`.

- [ ] **Step 6: Write the Python error and marker surface**

`languages/python/python/stackencrypt/errors.py`:

```python
"""The exception types the engine raises, re-exported from the extension."""

from stackencrypt._engine import (
    DeclarationError,
    EngineError,
    PlanError,
    StackEncryptError,
)

__all__ = [
    "StackEncryptError",
    "DeclarationError",
    "PlanError",
    "EngineError",
]
```

`languages/python/python/stackencrypt/_markers.py`:

```python
"""Annotation markers.

Two kinds live here. A **width type** (`Int64`, `Text`) resolves the field's
`ValueKind`, which the engine needs because a Python `int` carries no width
and `34` and `34.0` derive different ORE terms. An **index marker**
(`Equality`, `Match`, `Ore`) names what a query against the field may do.

The names follow the engine's vocabulary, not Python's: `context`,
`passthrough`, `equality`, `match`, `ore` (principle G2).
"""

from dataclasses import dataclass
from typing import Optional

# Width types. The value is the engine's `ValueKind` name, which the plan's
# `"type"` key carries verbatim.
Text = "Utf8Str"
Int64 = "Int64"
Int32 = "Int32"
Float64 = "Float64"
Bool = "Bool"


@dataclass(frozen=True)
class Index:
    """An index on a field, named by the engine's own output key."""

    key: str


Equality = Index("eq")
Match = Index("match")
Ore = Index("ore")


@dataclass(frozen=True)
class Passthrough:
    """The field is stored as it is, unsealed and unauthenticated."""


@dataclass(frozen=True)
class EQL:
    """An EQL v3 target: the engine frames this field as an EQL type.

    `index` says what a query may do. The EQL type's NAME is not written
    here — the engine's resolver is asked for a producible type whose
    plaintext kind and index set match, so no EQL knowledge lives in Python.
    `name` overrides that, for a type the match rule cannot reach.
    """

    index: Optional[Index] = None
    name: Optional[str] = None
```

Re-export from `__init__.py`:

```python
from stackencrypt._markers import (
    EQL,
    Bool,
    Equality,
    Float64,
    Int32,
    Int64,
    Match,
    Ore,
    Passthrough,
    Text,
)
```

Extend `__all__` with those names.

- [ ] **Step 7: Build and run the tests**

```bash
cd languages/python && maturin develop --extras test
python -m pytest tests/test_convert.py -v
```

Expected: PASS, all eight.

- [ ] **Step 8: Commit**

```bash
git add languages/python
git commit -m "feat(python): the value codec, with integer width checked before a value crosses"
```

---

### Task 3: A class with `Annotated` hints becomes a data plan

**Files:**
- Create: `languages/python/python/stackencrypt/_declare.py`
- Create: `languages/python/python/stackencrypt/plan.py`
- Modify: `languages/python/python/stackencrypt/__init__.py`
- Modify: `languages/python/tests/test_declare.py`

**Interfaces:**
- Consumes: Task 2's `stackencrypt._markers` and `stackencrypt.errors`.
- Produces:
  - `stackencrypt.plan.PlanSpec` — a frozen dataclass holding
    `model: type`, `context: tuple[str, ...]`, `fields: dict[str, dict]`.
    `fields` is the data plan dict, in `dynamic::record`'s wire grammar.
  - `stackencrypt.Plan.of(cls) -> PlanBuilder`, `PlanBuilder.context(*pieces)
    -> PlanBuilder`, `PlanBuilder.build() -> PlanSpec`.
  - This task's `build()` validates only what Python can see. Task 4 sends
    the dict to the engine, which validates the rest.

- [ ] **Step 1: Write the failing test**

Replace `languages/python/tests/test_declare.py` with:

```python
from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import EQL, Equality, Int64, Passthrough, Plan, Text
from stackencrypt.errors import DeclarationError


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]
    id: Annotated[int, Int64, Passthrough()]


def test_engine_module_loads():
    import stackencrypt

    assert isinstance(stackencrypt.engine_version(), str)


def test_a_target_field_carries_context_and_type_but_no_outputs():
    spec = Plan.of(User).context("users").build()

    assert spec.fields["email"]["context"] == ["users", "email"]
    assert spec.fields["email"]["type"] == "Utf8Str"
    # A target field and an outputs field are exclusive in the wire grammar.
    assert "outputs" not in spec.fields["email"]
    assert spec.fields["email"]["target"] == {"index": "eq", "kind": "Utf8Str"}


def test_a_passthrough_field_carries_outputs_and_no_target():
    spec = Plan.of(User).context("users").build()

    assert spec.fields["age"]["outputs"] == ["passthrough"]
    assert "target" not in spec.fields["age"]


# Review Focus 2: decision 20 — a field with no stash annotation stops the
# program at import, it does not quietly become a passthrough.
def test_a_field_with_no_stash_annotation_is_refused():
    @dataclass
    class Loose:
        email: Annotated[str, Text, EQL(Equality)]
        nickname: str

    with pytest.raises(DeclarationError, match="nickname"):
        Plan.of(Loose).context("users").build()


# Review Focus 1, at the declaration layer: an index needs a width, so a
# field annotated with an index but no width type cannot resolve its type.
def test_an_indexed_field_with_no_width_type_is_refused():
    @dataclass
    class Untyped:
        age: Annotated[int, EQL(Equality)]

    with pytest.raises(DeclarationError, match="age"):
        Plan.of(Untyped).context("users").build()


def test_an_empty_context_is_refused():
    with pytest.raises(DeclarationError, match="context"):
        Plan.of(User).build()


def test_a_model_with_no_fields_is_refused():
    @dataclass
    class Empty:
        pass

    with pytest.raises(DeclarationError):
        Plan.of(Empty).context("users").build()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd languages/python && python -m pytest tests/test_declare.py -v
```

Expected: FAIL — `cannot import name 'Plan'`.

- [ ] **Step 3: Write the annotation reader**

`languages/python/python/stackencrypt/_declare.py`:

```python
"""Read a class's `Annotated` hints into the engine's data plan grammar.

This file is the whole of the declaration shape. Nothing else knows how an
annotation is spelled, because backlog item 1 may replace the spelling after
comparing it with other Python-style shapes.

The grammar it writes, per `dynamic::record`:

    { <field>: { "context": [...], "outputs": [...], "type": "<kind>" } }
    { <field>: { "context": [...], "target": {...},  "type": "<kind>" } }

`"outputs"` and `"target"` are exclusive. `"type"` is optional in the engine
today and becomes required on every field with a term output (#1096), so it
is always written here.
"""

from __future__ import annotations

from typing import Any, get_type_hints

from stackencrypt._markers import EQL, Index, Passthrough
from stackencrypt.errors import DeclarationError

_WIDTH_NAMES = {"Utf8Str", "Int64", "Int32", "Float64", "Bool"}


def _annotations(cls: type) -> dict[str, tuple[Any, ...]]:
    """Each field's `Annotated` extras, keyed by field name."""
    hints = get_type_hints(cls, include_extras=True)
    found: dict[str, tuple[Any, ...]] = {}
    for name, hint in hints.items():
        found[name] = getattr(hint, "__metadata__", ())
    return found


def fields(cls: type, context: tuple[str, ...]) -> dict[str, dict]:
    """The data plan's field map for `cls`, under `context`.

    Fails closed: every field of the class must carry a stash annotation.
    A field the plan does not name is refused by the engine on every row
    anyway, so saying so here moves the error from the first write to
    import.
    """
    annotated = _annotations(cls)
    if not annotated:
        raise DeclarationError(f"{cls.__name__} declares no fields")

    plan: dict[str, dict] = {}
    for name, extras in annotated.items():
        width = next((e for e in extras if e in _WIDTH_NAMES), None)
        target = next((e for e in extras if isinstance(e, EQL)), None)
        indexes = tuple(e for e in extras if isinstance(e, Index))
        passthrough = any(isinstance(e, Passthrough) for e in extras)

        if target is None and not indexes and not passthrough:
            raise DeclarationError(
                f"{cls.__name__}.{name} carries no stash annotation. "
                f"Every field must declare one; use Passthrough() for a "
                f"field stored as it is."
            )

        spec: dict[str, Any] = {"context": [*context, name]}

        if passthrough:
            if target is not None or indexes:
                raise DeclarationError(
                    f"{cls.__name__}.{name} is both a passthrough and encrypted"
                )
            spec["outputs"] = ["passthrough"]
            if width is not None:
                spec["type"] = width
            plan[name] = spec
            continue

        if width is None:
            raise DeclarationError(
                f"{cls.__name__}.{name} is indexed but declares no width type. "
                f"A Python int carries no width, and 34 and 34.0 derive "
                f"different terms, so the engine needs one: add Int64, "
                f"Float64, Text or another width type to the annotation."
            )
        spec["type"] = width

        if target is not None:
            if indexes:
                raise DeclarationError(
                    f"{cls.__name__}.{name} names both an EQL target and a "
                    f"bare index; a target carries its own indexes"
                )
            spec["target"] = _target(target, width)
        else:
            spec["outputs"] = ["c", *(index.key for index in indexes)]

        plan[name] = spec

    return plan


def _target(target: EQL, width: str) -> dict:
    """The target request for a field.

    Either an explicit EQL type name, or the pair the shell resolves against
    the engine's own target descriptors. The pair is not an EQL name, which
    is the point: Python states what the field holds and what a query must
    do, and the engine says which of its types that is.
    """
    if target.name is not None:
        return {"name": target.name}
    if target.index is None:
        return {"kind": width}
    return {"index": target.index.key, "kind": width}
```

- [ ] **Step 4: Write the plan builder**

`languages/python/python/stackencrypt/plan.py`:

```python
"""`Plan.of(Model).context(...).build()`.

A plan is the declaration without the values: reusable, and validated once.
The same plan serves the write, the query and the read (principle G4), so a
query cannot drift onto a different context from the write.

`build()` here checks what Python can see. The engine checks the rest when
the plan is parsed, which `Cipher` does once at construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from stackencrypt import _declare
from stackencrypt.errors import DeclarationError


@dataclass(frozen=True)
class PlanSpec:
    """A built plan: the model it came from, and the engine's field map."""

    model: type
    context: tuple[str, ...]
    fields: dict[str, dict[str, Any]]


class PlanBuilder:
    """The chain between `Plan.of` and `build`."""

    def __init__(self, model: type) -> None:
        self._model = model
        self._context: tuple[str, ...] = ()

    def context(self, *pieces: str) -> "PlanBuilder":
        """The context every field is sealed under, extended by field name."""
        self._context = pieces
        return self

    def build(self) -> PlanSpec:
        if not self._context:
            raise DeclarationError(
                f"{self._model.__name__} has no context: call "
                f".context('<table>') before .build()"
            )
        return PlanSpec(
            model=self._model,
            context=self._context,
            fields=_declare.fields(self._model, self._context),
        )


class Plan:
    """The entry point. `Plan.of(User)` reads `User`'s annotations."""

    @staticmethod
    def of(model: type) -> PlanBuilder:
        return PlanBuilder(model)
```

- [ ] **Step 5: Export and run the tests**

Add to `__init__.py`:

```python
from stackencrypt.plan import Plan, PlanSpec
```

and to `__all__`: `"Plan"`, `"PlanSpec"`.

```bash
cd languages/python && python -m pytest tests/test_declare.py -v
```

Expected: PASS, all seven. No rebuild needed — this task is pure Python.

- [ ] **Step 6: Commit**

```bash
git add languages/python
git commit -m "feat(python): Annotated hints become a data plan, failing closed on an undeclared field"
```

---

### Task 4: The engine parses the plan, and refuses a bad one

**Files:**
- Create: `languages/python/src/targets.rs`
- Modify: `languages/python/src/lib.rs`
- Modify: `languages/python/python/stackencrypt/plan.py`
- Create: `languages/python/tests/test_plan.py`

**Interfaces:**
- Consumes: Task 3's `PlanSpec.fields`, Task 2's `convert` and `errors`.
- Produces:
  - Rust: `targets::Resolver` — a `TargetResolver` over
    `eql_bindings::encryption::targets`, and
    `targets::select(kind: Option<ValueKind>, index: Option<&str>) ->
    Result<TargetDescriptor, PyErr>`.
  - Python: `stackencrypt._engine.check_plan(fields: dict) -> dict` — parses
    the plan through the engine, raising on a refusal, and returning each
    target field's resolved `{name, sql_domain, query_sql_domain}`.
  - Python: `PlanSpec.domains: dict[str, dict]`, filled by `build()`.

- [ ] **Step 1: Write the failing test**

`languages/python/tests/test_plan.py`:

```python
"""The engine's own plan checks. No credentials and no database: parsing a
plan mints no key, so these run everywhere."""

from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import EQL, Equality, Int64, Match, Passthrough, Plan, Text
from stackencrypt.errors import PlanError


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


def test_a_good_plan_resolves_its_target_to_an_eql_type_and_domain():
    spec = Plan.of(User).context("users").build()

    resolved = spec.domains["email"]
    assert resolved["name"] == "TextEq"
    assert resolved["sql_domain"] == "public.eql_v3_text_eq"
    assert resolved["query_sql_domain"] == "eql_v3.query_text_eq"


def test_a_passthrough_field_has_no_domain():
    spec = Plan.of(User).context("users").build()

    assert "age" not in spec.domains


def test_an_unknown_eql_type_name_is_refused():
    @dataclass
    class Wrong:
        email: Annotated[str, Text, EQL(name="NoSuchType")]

    with pytest.raises(PlanError, match="NoSuchType"):
        Plan.of(Wrong).context("users").build()


# A match index is text-only. The engine's `admits` check is what refuses it
# on an integer, and it must fire at plan time, not at the first write.
def test_an_index_the_declared_type_does_not_admit_is_refused():
    @dataclass
    class Wrong:
        age: Annotated[int, Int64, Match]

    with pytest.raises(PlanError):
        Plan.of(Wrong).context("users").build()


def test_a_kind_and_index_pair_no_eql_type_serves_is_refused():
    @dataclass
    class Wrong:
        flag: Annotated[bool, "Bool", EQL(Match)]

    with pytest.raises(PlanError):
        Plan.of(Wrong).context("users").build()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd languages/python && python -m pytest tests/test_plan.py -v
```

Expected: FAIL — `PlanSpec` has no attribute `domains`.

- [ ] **Step 3: Write the resolver**

`languages/python/src/targets.rs`:

```rust
//! The EQL types this wheel holds, as the engine's `TargetResolver`.
//!
//! `eql-bindings` already provides a by-name dispatch over its catalog
//! (`eql_bindings::encryption::targets`), so this is a wrapper and not a
//! second copy of anything. `languages/golang/encrypt/guest/src/targets.rs`
//! is the same wrapper for the WASI guest; the difference is only that this
//! one is always the EQL build, because a native wheel has no second build
//! to choose between.
//!
//! Selection by (kind, index) rather than by EQL name is deliberate. It
//! keeps every EQL name out of Python: the declaration says the field holds
//! text and a query must compare it for equality, and the engine answers
//! `TextEq`. Principle G1 — the SDK declares, the engine decides.

use pyo3::prelude::*;
use stack_encrypt::dynamic::{TargetDescriptor, TargetError, TargetResolver, ValueKind};

use crate::errors::PlanError;

/// `eql-bindings`' dispatch as the engine's resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct Resolver;

impl TargetResolver for Resolver {
    fn targets(&self) -> Vec<TargetDescriptor> {
        eql_bindings::encryption::targets::targets()
            .iter()
            .map(describe)
            .collect()
    }

    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a stack_encrypt::KeysetCipher<'_, K>,
        label: &stack_encrypt::Label,
        plaintext: stack_encrypt::dynamic::FfiValue,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, TargetError> {
        eql_bindings::encryption::targets::encrypt(name, keyset, label, plaintext)
            .map_err(convert)
    }

    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a stack_encrypt::StackCipher<K>,
        label: &stack_encrypt::Label,
        stored: &[u8],
    ) -> Result<stack_encrypt::Pending<'a, stack_encrypt::dynamic::FfiValue, K>, TargetError> {
        eql_bindings::encryption::targets::decrypt(name, cipher, label, stored).map_err(convert)
    }

    fn query<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a stack_encrypt::KeysetCipher<'_, K>,
        label: &stack_encrypt::Label,
        plaintext: stack_encrypt::dynamic::FfiValue,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, TargetError> {
        eql_bindings::encryption::targets::query(name, keyset, label, plaintext).map_err(convert)
    }
}

/// The producible type whose plaintext kind is `kind` and whose index set
/// contains `index`. Exactly one must match, or the pair is refused: two
/// matches means the catalog cannot be addressed this way and the
/// declaration needs an explicit name.
pub fn select(kind: ValueKind, index: Option<&str>) -> PyResult<TargetDescriptor> {
    let resolver = Resolver;
    let mut matching: Vec<TargetDescriptor> = resolver
        .targets()
        .into_iter()
        .filter(|target| target.producible)
        .filter(|target| target.plaintext == Some(kind))
        .filter(|target| match index {
            None => target.indexes.is_empty(),
            Some(key) => target.indexes.iter().any(|carried| carried == key),
        })
        .collect();

    match matching.len() {
        1 => Ok(matching.remove(0)),
        0 => Err(PlanError::new_err(format!(
            "no EQL type holds {kind:?} with index {}",
            index.unwrap_or("none")
        ))),
        _ => Err(PlanError::new_err(format!(
            "{} EQL types hold {kind:?} with index {}: name one with \
             EQL(name=...) — {}",
            matching.len(),
            index.unwrap_or("none"),
            matching
                .iter()
                .map(|target| target.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ))),
    }
}

/// A named type's descriptor, for an explicit `EQL(name=...)`.
pub fn named(name: &str) -> PyResult<TargetDescriptor> {
    Resolver
        .resolve(name)
        .map_err(|error| PlanError::new_err(format!("{error}")))
}

fn describe(entry: &eql_bindings::encryption::targets::Entry) -> TargetDescriptor {
    // Field-for-field from eql-bindings' own catalog entry. If its shape
    // differs on the base branch, read
    // `packages/eql/crates/eql-bindings/src/encryption/targets.rs` and map
    // what is there; the Go guest's `describe` in
    // `languages/golang/encrypt/guest/src/targets.rs` is the reference.
    todo_describe(entry)
}

fn convert(error: eql_bindings::encryption::targets::Error) -> TargetError {
    // Likewise: mirror the Go guest's `convert`.
    todo_convert(error)
}
```

`describe` and `convert` are the two functions this plan cannot write
blind — they depend on `eql-bindings`' catalog entry and error types, which
differ between branches. Copy both from
`languages/golang/encrypt/guest/src/targets.rs` on the base branch:

```bash
git show origin/feat/stack-encrypt-required-type:languages/golang/encrypt/guest/src/targets.rs \
  | sed -n '/^fn describe/,$p'
```

Replace the two `todo_*` placeholders with what that file does, and delete
the placeholders. **Do not leave them in.**

- [ ] **Step 4: Expose the plan check**

In `languages/python/src/lib.rs`:

```rust
mod targets;

/// Parse a data plan through the engine, and resolve each target field.
///
/// Parsing mints no key and makes no request, so this runs with no
/// credentials — which is the point: a declaration error is an import-time
/// error, not a first-write error (principle G3).
///
/// Returns `{field: {name, sql_domain, query_sql_domain}}` for the target
/// fields, which is what the caller needs to write the SQL casts.
#[pyfunction]
fn check_plan(py: Python<'_>, fields: &Bound<'_, PyAny>) -> PyResult<PyObject> {
    let (wire, domains) = plan::resolve(fields)?;
    // The engine's own checks: context, outputs, exclusivity, a type that
    // admits each index, a target name the resolver knows.
    stack_encrypt::dynamic::record::plan_with(wire, &targets::Resolver)
        .map_err(|error| errors::PlanError::new_err(format!("{error}")))?;
    convert::domains_to_py(py, domains)
}
```

Write `plan::resolve` in a new `languages/python/src/plan.rs`: it walks the
Python dict, turns each field's `"target"` request (`{"name": ...}` or
`{"kind": ..., "index": ...}`) into the resolved EQL type name, substitutes
that name into the wire value as `"target": "<name>"`, and collects the
descriptor's `sql_domain` and `query_sql_domain` for the return. Everything
else in the dict passes through to `FfiValue::Object` unchanged.

- [ ] **Step 5: Call it from `build()`**

In `languages/python/python/stackencrypt/plan.py`, add `domains` to
`PlanSpec` and fill it:

```python
@dataclass(frozen=True)
class PlanSpec:
    model: type
    context: tuple[str, ...]
    fields: dict[str, dict[str, Any]]
    domains: dict[str, dict[str, str]]
```

and in `PlanBuilder.build()`, after `_declare.fields(...)`:

```python
        fields = _declare.fields(self._model, self._context)
        # The engine's checks, and the resolved EQL type for each target
        # field. No credentials needed: parsing a plan mints no key.
        domains = _engine.check_plan(fields)
        for name, resolved in domains.items():
            # The wire value carries the resolved NAME, not the pair.
            fields[name]["target"] = resolved["name"]
        return PlanSpec(
            model=self._model,
            context=self._context,
            fields=fields,
            domains=domains,
        )
```

Import `_engine` at the top of `plan.py`.

Note this changes Task 3's `test_a_target_field_carries_context_and_type_but_no_outputs`,
which asserted the pair form. Update that assertion to the resolved name:

```python
    assert spec.fields["email"]["target"] == "TextEq"
```

- [ ] **Step 6: Build and run both test files**

```bash
cd languages/python && maturin develop --extras test
python -m pytest tests/test_declare.py tests/test_plan.py -v
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add languages/python
git commit -m "feat(python): the engine parses the plan and names the EQL type, at import"
```

---

### Task 5: Encrypt and decrypt a batch, live

**Files:**
- Create: `languages/python/src/runtime.rs`
- Create: `languages/python/python/stackencrypt/cipher.py`
- Modify: `languages/python/src/lib.rs`
- Modify: `languages/python/python/stackencrypt/__init__.py`
- Create: `languages/python/tests/test_roundtrip.py`
- Create: `languages/python/tests/conftest.py`

**Interfaces:**
- Consumes: Tasks 2-4.
- Produces:
  - Rust: `runtime::block_on<T>(py: Python<'_>, future) -> T` — the one
    runtime, with the GIL released across the call.
  - Python: `stackencrypt._engine.Engine` — `Engine()` discovers credentials;
    `.encrypt(fields, rows) -> list[bytes]`;
    `.decrypt(fields, records) -> list[dict]`;
    `.query(fields, field, value) -> bytes`.
  - Python: `stackencrypt.Cipher` — `Cipher(plan)`, `.encrypt(models)`,
    `.decrypt(records)`, `.query(field, value)`. All sync.

- [ ] **Step 1: Write the failing test**

`languages/python/tests/conftest.py`:

```python
import os

import pytest

_CREDENTIALS = ("CS_WORKSPACE_CRN", "CS_CLIENT_ID", "CS_CLIENT_KEY")


@pytest.fixture(scope="session")
def live():
    """Skip when the session has no CipherStash credentials."""
    missing = [name for name in _CREDENTIALS if not os.environ.get(name)]
    if missing:
        pytest.skip(f"no credentials: {', '.join(missing)}")
```

`languages/python/tests/test_roundtrip.py`:

```python
"""Live ZeroKMS. Skipped without credentials."""

from dataclasses import dataclass
from typing import Annotated

import pytest

from stackencrypt import EQL, Cipher, Equality, Int64, Passthrough, Plan, Text
from stackencrypt.errors import EngineError


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


@pytest.fixture(scope="module")
def cipher(live):
    return Cipher(Plan.of(User).context("users").build())


def test_a_batch_round_trips(cipher):
    users = [User(email=f"user{n}@example.com", age=30 + n) for n in range(5)]

    records = cipher.encrypt(users)
    assert len(records) == 5

    back = cipher.decrypt(records)
    assert [user.email for user in back] == [user.email for user in users]
    assert [user.age for user in back] == [user.age for user in users]
    assert all(isinstance(user, User) for user in back)


def test_a_batch_makes_one_key_request(cipher):
    # Principle G5. The counter is the engine's; the assertion is that a
    # batch of five does not make five requests.
    users = [User(email=f"b{n}@example.com", age=n) for n in range(5)]
    before = cipher.key_requests
    cipher.encrypt(users)
    assert cipher.key_requests - before == 1


# Review Focus 5: an empty batch must not reach ZeroKMS at all.
def test_an_empty_batch_returns_empty_and_makes_no_request(cipher):
    before = cipher.key_requests
    assert cipher.encrypt([]) == []
    assert cipher.key_requests == before


# Review Focus 4: the spec is silent on None. Refuse it with a named error
# rather than sealing it as something else.
def test_none_in_an_encrypted_field_is_refused(cipher):
    with pytest.raises(EngineError, match="email"):
        cipher.encrypt([User(email=None, age=1)])


def test_a_query_term_is_bytes(cipher):
    term = cipher.query("email", "user0@example.com")
    assert isinstance(term, bytes)
    assert term


def test_querying_a_field_the_plan_does_not_name_is_refused(cipher):
    with pytest.raises(EngineError, match="nickname"):
        cipher.query("nickname", "x")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd languages/python && python -m pytest tests/test_roundtrip.py -v
```

Expected: FAIL — `cannot import name 'Cipher'`. Without credentials the
fixture skips instead; set them, or this task cannot be verified.

- [ ] **Step 3: Write the runtime**

`languages/python/src/runtime.rs`:

```rust
//! One Tokio runtime for the process, and the sync bridge over it.
//!
//! The engine's `Pending` is `IntoFuture`, so every operation is async even
//! though the tracer's surface is sync (decision 8: both eventually, over
//! one engine path; sync first). `block_on` is therefore the whole of the
//! sync path — there is no second engine entry for it.
//!
//! The GIL is released across the call. The work inside is a ZeroKMS HTTPS
//! round trip, so holding the GIL would stop every other Python thread for
//! the duration of a network call — and a native shell is the one binding
//! that can simply let go of it.

use std::sync::OnceLock;

use pyo3::prelude::*;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Runtime::new().expect("a Tokio runtime for the stackencrypt engine")
    })
}

/// Drive `future` to completion with the GIL released.
pub fn block_on<F>(py: Python<'_>, future: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    py.allow_threads(|| runtime().block_on(future))
}
```

- [ ] **Step 4: Write the engine handle**

Add to `languages/python/src/lib.rs` a `#[pyclass] Engine` holding a
`StackCipher`. Construction:

```rust
/// A handle on the engine, with its credentials already discovered.
///
/// `StackCipher::new()` does the discovery: `CS_CLIENT_ID` + `CS_CLIENT_KEY`
/// first, then the profile `stash auth login` writes, through
/// `stack_auth::AutoStrategy`. That is decision 10 satisfied by the engine,
/// so no credential code lives here.
#[pyclass]
struct Engine {
    cipher: stack_encrypt::StackCipher<
        stack_encrypt::kms::StackKms<stack_auth::AutoStrategy>,
    >,
    key_requests: std::sync::atomic::AtomicU64,
}

#[pymethods]
impl Engine {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        let cipher = runtime::block_on(py, stack_encrypt::StackCipher::new())
            .map_err(|error| errors::EngineError::new_err(format!("{error}")))?;
        Ok(Self {
            cipher,
            key_requests: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// How many ZeroKMS requests this handle has made. Principle G5's
    /// evidence: a batch of five rows must move this by one.
    #[getter]
    fn key_requests(&self) -> u64 {
        self.key_requests.load(std::sync::atomic::Ordering::Relaxed)
    }
}
```

Then `encrypt`, `decrypt` and `query` methods, each: build the plan with
`record::plan_with(.., &targets::Resolver)`, convert the rows with
`convert::to_ffi` using each field's declared kind, call
`record::encrypt_with` / `decrypt_with` / `query`, and `runtime::block_on`
the resulting `Pending`. An empty row list returns `Ok(vec![])` **before**
touching the cipher, so no request is made. Increment `key_requests` once
per `block_on` that actually ran a pending.

Check the source against the plan first — `record::check_source` is what
refuses a row the plan does not match, and it decides before any pending
exists.

- [ ] **Step 5: Write the Python surface**

`languages/python/python/stackencrypt/cipher.py`:

```python
"""`Cipher` — the sync call site.

It holds no field logic. One call hands the engine the whole plan and every
row, because the engine batches (principle G5) and the SDK never executes
(principle G1). A loop over fields here would be the bug this file exists to
avoid.
"""

from __future__ import annotations

from typing import Any, Iterable

from stackencrypt import _engine
from stackencrypt.plan import PlanSpec


class Cipher:
    """Encrypt, decrypt and build query terms under one plan."""

    def __init__(self, plan: PlanSpec) -> None:
        self._plan = plan
        self._engine = _engine.Engine()

    @property
    def key_requests(self) -> int:
        """ZeroKMS requests made so far. Evidence for principle G5."""
        return self._engine.key_requests

    def encrypt(self, models: Iterable[Any]) -> list[bytes]:
        """A batch of models as stored records, in one key request."""
        rows = [self._row(model) for model in models]
        return self._engine.encrypt(self._plan.fields, rows)

    def decrypt(self, records: Iterable[bytes]) -> list[Any]:
        """A batch of stored records back as the plan's model type."""
        rows = self._engine.decrypt(self._plan.fields, list(records))
        return [self._plan.model(**row) for row in rows]

    def query(self, field: str, value: Any) -> bytes:
        """One query term for `field`. A query takes one value (G5)."""
        return self._engine.query(self._plan.fields, field, value)

    def _row(self, model: Any) -> dict[str, Any]:
        """A model as the engine's row: field name to value, nothing else.

        This reads the declared fields off the model. It does not decide
        anything about them — no per-field encryption, no term derivation,
        no EQL. `check_source` in the engine is what refuses a row that does
        not match the plan.
        """
        return {name: getattr(model, name) for name in self._plan.fields}
```

- [ ] **Step 6: Build and run the tests**

```bash
cd languages/python && maturin develop --extras test
python -m pytest tests/test_roundtrip.py -v
```

Expected: PASS, all seven, against live ZeroKMS.

- [ ] **Step 7: Commit**

```bash
git add languages/python
git commit -m "feat(python): a batch encrypts and decrypts in one key request, sync"
```

---

### Task 6: The shell and Rust agree on the bytes

**Files:**
- Create: `languages/python/src/bin/parity.rs`
- Create: `languages/python/src/tree.rs` (the record-tree walk, shared by the lib and the bin)
- Modify: `languages/python/Cargo.toml` (a `[[bin]]`)
- Modify: `languages/python/src/engine.rs` (use `tree`)
- Create: `languages/python/tests/test_bytes.py`

**Interfaces:**
- Consumes: Task 5's `Cipher`.
- Produces: the `parity` binary — `parity seal` prints
  `{"plan", "plaintext", "record", "term"}` as JSON (EQL bytes and term
  base64); `parity open` reads a record JSON on stdin and prints the
  plaintext.

**Revised 2026-10-13.** The first version committed a Rust-made
`tests/fixtures/record.json`. Its equality term is an HMAC under the
workspace keyset, so the committed bytes passed only in the workspace that
generated them — the same hazard as the EQL SQLx selector constants.
Producing the Rust side **at test time** dissolves that: both halves run
under the same credentials in one run, so the comparison holds in every
workspace and in CI, and nothing keyed to a keyset is committed.

What the check proves, stated carefully: Python never encrypts (G1). Both
sides run ONE engine; what differs is everything in front of it. So this is
the one test that catches the shell drifting from the engine's grammar —
`convert.rs` tagging `34` as the wrong width, `plan.rs` dropping `"type"`,
`engine.rs` rebuilding the record tree wrongly — while every other test
stays green. Ciphertexts are never byte-equal (fresh IV per seal), so the
bit-for-bit comparison is the deterministic **term**; the ciphertext is
checked by cross-opening instead.

- [ ] **Step 1: Write the failing test** — `tests/test_bytes.py`, four
  tests: both sides build the same plan; the shell opens a record Rust
  sealed; Rust opens a record the shell sealed; the equality term is
  byte-identical. The Rust side runs via `subprocess` as
  `cargo run --quiet --bin parity -- <mode>`; `cargo run` compiles once and
  caches.

- [ ] **Step 2: Run it** — Expected: FAIL, `cargo run` exits non-zero: no
  bin named `parity`.

- [ ] **Step 3: Write the binary.** It builds the SAME data plan the Python
  test builds, as an `FfiValue` literal, parses it with `record::plan_with`
  under `targets::Resolver`, and: `seal` runs `encrypt_with` over one row
  and `query` for `email`, printing plan, plaintext, record and term;
  `open` reads a record from stdin, rebuilds the tree, runs `decrypt_with`,
  prints the plaintext. The tree walk lives ONCE, in `src/tree.rs`, used by
  both `engine.rs` and the bin — a copy is how the two sides stop agreeing.

- [ ] **Step 4: Run the tests** — Expected: PASS, 4/4, live.

- [ ] **Step 5: Commit** — `test(python): byte parity with Rust, produced
  at test time under one keyset`.

---

### Task 7: The full path, through Postgres

**Files:**
- Create: `languages/python/tests/test_postgres.py`
- Modify: `languages/python/tests/conftest.py`
- Modify: `languages/python/README.md`

**Interfaces:**
- Consumes: Tasks 4-5. Uses `PlanSpec.domains[field]["sql_domain"]` and
  `["query_sql_domain"]` for the casts, so no EQL domain name is written in
  Python.
- Produces: the end-to-end evidence for pass check 1.

- [ ] **Step 1: Write the failing test**

Add to `conftest.py`:

```python
@pytest.fixture(scope="session")
def database_url(live):
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("no DATABASE_URL")
    return url
```

`languages/python/tests/test_postgres.py`:

```python
"""The whole path: declare, encrypt a batch, insert, query by the encrypted
field, decrypt the batch. Needs live ZeroKMS and Postgres with EQL v3."""

from dataclasses import dataclass
from typing import Annotated

import psycopg
import pytest

from stackencrypt import EQL, Cipher, Equality, Int64, Passthrough, Plan, Text


@dataclass
class User:
    email: Annotated[str, Text, EQL(Equality)]
    age: Annotated[int, Int64, Passthrough()]


@pytest.fixture(scope="module")
def plan():
    return Plan.of(User).context("users").build()


@pytest.fixture(scope="module")
def cipher(live, plan):
    return Cipher(plan)


@pytest.fixture
def table(database_url, plan):
    """A table whose encrypted column takes the domain the engine named."""
    domain = plan.domains["email"]["sql_domain"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute("drop table if exists py_users")
        connection.execute(
            f"create table py_users (id bigserial primary key, "
            f"email {domain}, age bigint)"
        )
        yield connection
        connection.execute("drop table if exists py_users")


def test_insert_query_and_decrypt(cipher, plan, table):
    users = [User(email=f"p{n}@example.com", age=20 + n) for n in range(4)]

    records = cipher.encrypt(users)
    with table.cursor() as cursor:
        cursor.executemany(
            "insert into py_users (email, age) values (%s, %s)",
            [(record, user.age) for record, user in zip(records, users)],
        )

    # The query term, cast to the query domain the engine named.
    term = cipher.query("email", "p2@example.com")
    query_domain = plan.domains["email"]["query_sql_domain"]
    with table.cursor() as cursor:
        cursor.execute(
            f"select email, age from py_users where email = %s::{query_domain}",
            (term,),
        )
        found = cursor.fetchall()

    assert len(found) == 1

    [user] = cipher.decrypt([row[0] for row in found])
    assert user.email == "p2@example.com"


def test_a_term_for_a_value_that_is_not_stored_finds_nothing(cipher, plan, table):
    records = cipher.encrypt([User(email="present@example.com", age=1)])
    with table.cursor() as cursor:
        cursor.execute(
            "insert into py_users (email, age) values (%s, %s)", (records[0], 1)
        )

    term = cipher.query("email", "absent@example.com")
    query_domain = plan.domains["email"]["query_sql_domain"]
    with table.cursor() as cursor:
        cursor.execute(
            f"select count(*) from py_users where email = %s::{query_domain}",
            (term,),
        )
        [[count]] = cursor.fetchall()

    # A zero here is the right answer. It is also what a type mismatch looks
    # like, which is why the test above asserts a positive match first.
    assert count == 0
```

- [ ] **Step 2: Start a database and run the test**

```bash
# EQL v3 into a local Postgres, the same installer CI uses.
npx stash eql install --eql-version 3
export DATABASE_URL=postgres://...
cd languages/python && python -m pytest tests/test_postgres.py -v
```

Expected: FAIL first (no table helper or a wrong cast), then PASS once the
domains are right.

- [ ] **Step 3: Check how the record reaches psycopg**

If the insert fails on the parameter type, the record bytes need an explicit
adapter. Read what `Engine.encrypt` returns — if it is JSON bytes, pass it as
`str` or cast in SQL (`%s::jsonb::<domain>`). Fix it in the test, not by
reshaping the engine's output; what the engine returns is the EQL value and
is contract.

- [ ] **Step 4: Run the whole suite**

```bash
cd languages/python && python -m pytest tests -v
```

Expected: PASS throughout.

- [ ] **Step 5: Commit**

```bash
git add languages/python
git commit -m "test(python): the whole path, insert and query through EQL v3 Postgres"
```

---

### Task 8: CI builds six wheels and runs the live path

**Files:**
- Create: `.github/workflows/tests-python.yml`
- Modify: `scripts/__tests__/ffi-binding-step-order.test.mjs` — add the live
  job to `BINDING_EXEMPT_JOBS`
- Create: `languages/python/wheel-build-times.md`

**Interfaces:**
- Consumes: Tasks 1-7.
- Produces: per-target wheel build times, recorded for the FFI comparison
  (backlog item 3), and the live job for pass check 4.

- [ ] **Step 1: Write the failing test**

The guard here is an existing repo test, so run it first to see it fail once
the workflow exists. Write the workflow, then:

```bash
node --test scripts/__tests__/ffi-binding-step-order.test.mjs
```

Expected: FAIL — the new live job receives `CS_*` secrets and does not build
the protect-ffi binding, which the test requires of every credentialed job.

- [ ] **Step 2: Write the workflow**

`.github/workflows/tests-python.yml`. Three jobs:

**`unit`** — no credentials. `maturin develop`, then
`pytest tests/test_convert.py tests/test_declare.py tests/test_plan.py`.
Runs on every PR touching `languages/python/**`, `packages/stack-encrypt/**`
or `packages/eql/crates/eql-bindings/**`. Use `Swatinem/rust-cache`;
`scripts/__tests__/eql-suite-ci.test.mjs` wants it on every job that
compiles Rust.

**`wheels`** — a matrix of the six targets, with `maturin build --release
--target <triple>` and the build time recorded:

```yaml
    strategy:
      fail-fast: false
      matrix:
        include:
          - target: aarch64-apple-darwin
            runner: macos-14
            label: darwin-arm64
          - target: x86_64-apple-darwin
            runner: macos-14
            label: darwin-x64
          - target: aarch64-unknown-linux-gnu
            runner: ubuntu-24.04-arm
            label: linux-arm64-gnu
          - target: x86_64-unknown-linux-gnu
            runner: ubuntu-24.04
            label: linux-x64-gnu
          - target: x86_64-unknown-linux-musl
            runner: ubuntu-24.04
            label: linux-x64-musl
          - target: x86_64-pc-windows-msvc
            runner: windows-2022
            label: win32-x64-msvc
```

`fail-fast: false` is required by the spec's risk table: a target that does
not build is a **finding** for the FFI comparison, not a stop. Record each
target's wall time, whether the Rust cache hit, and any extra toolchain step
into the step summary, and upload the wheels as an artifact.

**`live`** — credentials and a database. In this order:

1. `./.github/actions/require-cs-secrets` — **first**, before anything else.
   `ffi-binding-step-order.test.mjs` asserts this pre-flight leads every
   credentialed job.
2. `./.github/actions/integration-db` with `db: postgres`.
3. `./.github/actions/integration-setup` — this is what runs
   `stash eql install --eql-version 3`.
4. `maturin develop --extras test`, then `pytest tests -v`.

Skip it on fork PRs, as the other `integration-*` jobs do.

- [ ] **Step 3: Add the exemption with a reason**

In `scripts/__tests__/ffi-binding-step-order.test.mjs`, add to
`BINDING_EXEMPT_JOBS`:

```js
  // tests-python.yml's live job encrypts through `languages/python`'s own
  // PyO3 shell over stack-encrypt, not through @cipherstash/protect-ffi.
  // It takes CS_* credentials, so the binding rule reaches it, but there is
  // no `index.node` on its path to build and building one would add a cargo
  // compile to a job that already pays for maturin.
  'tests-python.yml:live': 'PyO3 shell over stack-encrypt; no protect-ffi on this path',
```

Match the key format the file already uses — read the existing entries
rather than assuming `file:job`.

- [ ] **Step 4: Run the guard**

```bash
node --test scripts/__tests__/ffi-binding-step-order.test.mjs
node --test scripts/__tests__/eql-suite-ci.test.mjs
```

Expected: PASS.

- [ ] **Step 5: Record the wheel numbers**

After the first green `wheels` run, write
`languages/python/wheel-build-times.md`: a row per target with cold time,
warm time, whether `Swatinem/rust-cache` hit, and any toolchain setup the
target needed (a cross linker, a musl target, a Windows SDK). This file is
backlog item 3's input, and the spec names it as a week-1 goal — it is a
deliverable, not a log.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/tests-python.yml scripts/__tests__/ffi-binding-step-order.test.mjs languages/python/wheel-build-times.md
git commit -m "ci(python): six wheel targets with timings, and the live path"
```

---

### Task 9: The scorecard

**Files:**
- Create: `languages/python/scorecard.md`
- Modify: `docs/sdk-design-principles.md` — a Python section
- Modify: `languages/python/README.md`

**Interfaces:**
- Consumes: everything. This task reports, it does not build.
- Produces: the one-page scorecard that pass check 6 requires.

- [ ] **Step 1: Write the scorecard**

`languages/python/scorecard.md`. One row per principle G1-G8, each marked
**held**, **strained** or **not tested**, each pointing at the code or the
failure that shows it. Not a summary of intent — evidence. Expected marks,
to be corrected against what actually happened:

| | Mark | Evidence |
|---|---|---|
| G1. One engine, the SDK never executes | held | `cipher.py` has no field loop; EQL names resolve through `targets::select`, so no EQL knowledge is in Python; `test_bytes.py` proves the bytes are the engine's |
| G2. The SDK takes the host language's shape | strained | engine words kept (`context`, `passthrough`, `equality`); but `Plan.of(User).context(...)` is not an obviously Pythonic shape, and backlog item 1 tests it with Python developers |
| G3. Run each check at the earliest stage | strained | `build()` at import catches an undeclared field, a missing width, an index the type refuses, an unknown EQL name. pyright and mypy catch none of them — Python has no mapped types, so the encrypted output is weakly typed. Backlog item 1 |
| G4. One declaration for write, query and read | held | `test_postgres.py` writes, queries and reads through one `PlanSpec`; no call takes a context or an index |
| G5. Batch by default | held | `test_a_batch_makes_one_key_request`; `test_an_empty_batch_returns_empty_and_makes_no_request` |
| G6. A second way in must earn its place | not tested | one declaration shape, one call site. Async is backlog item 4 and must run the same engine path |
| G7. State the design, and run its claims | held | this file, plus the untested list below |
| G8. Usage first, then reference | held | `README.md` leads with the round trip |

Add an explicit **not tested** list: async, `match` and `ore` queries, lock
context, identity, OIDC, more than one keyset, cipher-directed encryption,
Django, data pipelines, and the SQLAlchemy layer. Naming them is the point —
principle G7.

- [ ] **Step 2: Write the Python section of the principles**

In `docs/sdk-design-principles.md`, after "Principles for the Go SDK", add
"Principles for the Python SDK" with what week 1 settled and what it did
not. Write only what the tracer has evidence for; a principle with no
evidence belongs in "Not yet decided", which is where the declaration
shape, the call site and the async surface go until their gates.

- [ ] **Step 3: Record the open questions the tracer surfaced**

Add to the scorecard a short list of questions week 1 raised that the spec's
backlog does not name. At least these two, from the design session on
2026-10-07:

- **Packaging of the SQLAlchemy layer.** A separate PyPI distribution
  (`stackencrypt-sqlalchemy`) or an extra on one package
  (`stackencrypt[sqlalchemy]`). The argument for separate: the core wheel is
  compiled for six targets, so an adapter inside it republishes six wheels
  for a pure-Python change — and the repo's TypeScript already splits its
  adapters out of core for the same reason. Backlog item 2 covers the call
  site, not the shipping unit, so this is unowned.
- **Width types in the annotation.** `Annotated[int, Int64, ...]` carries
  the width because a Python `int` has none, but it means every numeric
  declaration names a Rust-shaped type. Whether Python developers accept
  that is part of backlog item 1's user test.

- [ ] **Step 4: Add a changeset decision**

No changeset. Nothing here is published — `languages/python` is a new
unpublished workspace, and the `skills/` tarball is untouched. Note this
explicitly in the PR body so the `changeset-bot` warning is answered rather
than ignored.

- [ ] **Step 5: Run the whole suite one more time**

```bash
cd languages/python && python -m pytest tests -v
cargo build --release
cd /Users/yuji/Work/Repos/stack && node --test scripts/__tests__/ffi-binding-step-order.test.mjs
pnpm run code:check
```

Expected: all pass. `code:check` because the workflow and the guard edit are
in the Biome scope.

- [ ] **Step 6: Commit**

```bash
git add languages/python docs/sdk-design-principles.md
git commit -m "docs(python): the week-1 scorecard, and the Python section of the principles"
```

---

## Self-Review

**Spec coverage.** The spec's six-step path maps to Tasks 3 (declare), 4
(check at import), 5 (encrypt a batch in one request), 7 (insert, query,
decrypt). Its six pass checks map to Tasks 7 (check 1), 6 (check 2), 8
(checks 3 and 4), 9 (checks 5 and 6). The four tasks it names for the
tracer's build — binding, location, sync calls, credentials — are Tasks 1,
1, 5 and 5. Wheel builds are Task 8. The scorecard is Task 9.

Two spec items are deliberately **not** tasks here: `match` and `ore`
queries (backlog item 5), and the SQLAlchemy layer (backlog item 2). The
spec puts both after week 1.

**Known gap.** `targets.rs`'s `describe` and `convert` cannot be written
from the spec — they depend on `eql-bindings`' catalog entry and error types
on the base branch. Task 4 Step 3 names the exact command to read them from
the Go guest and says to delete the placeholders. This is the one place the
plan hands over a lookup rather than code, and it is marked.

**Type consistency.** `PlanSpec` gains `domains` in Task 4, which changes an
assertion written in Task 3; Task 4 Step 5 says so and gives the
replacement. `_engine.Engine` is introduced in Task 5 and used only by
`cipher.py`. `Index.key` carries the engine's own output key (`eq`,
`match`, `ore`) in both `_markers.py` and `_declare.py`.

**Review Focus coverage.** Integer width in Task 2; undeclared field in Task
3; wrong type for the declared kind in Tasks 2 and 4; `None` in Task 5;
empty batch in Task 5. All five have tests in the task that owns the code.
