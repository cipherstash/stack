//! The PyO3 shell. It is deliberately thin: a plan and values go in, values
//! come out. Everything that encrypts, derives a term or frames an EQL
//! payload happens in `stack-encrypt`, so a later move to a different FFI
//! replaces this crate and nothing above it.

use pyo3::prelude::*;
use pyo3::types::PyAny;

mod convert;
mod errors;

/// This shell's own version. The one export that needs no engine state, so
/// it is what proves the wheel loads.
///
/// It is deliberately not the `stack-encrypt` version: that crate exposes no
/// version constant, and `env!("CARGO_PKG_VERSION")` here reads this crate's
/// manifest. A wheel that wanted to report the engine's version would have
/// to be handed it at build time, which is a thing to add when something
/// needs it rather than a thing to fake now.
#[pyfunction]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// A value through the codec and back, with no encryption.
///
/// Here so the conversion rules — especially the integer width checks — are
/// testable with no credentials and no database. It is not part of the SDK's
/// surface; `stackencrypt/__init__.py` does not re-export it.
#[pyfunction]
#[pyo3(signature = (value, kind = None))]
fn roundtrip(py: Python<'_>, value: &Bound<'_, PyAny>, kind: Option<&str>) -> PyResult<Py<PyAny>> {
    let declared = kind.map(convert::kind).transpose()?;
    let crossed = convert::to_ffi(value, declared)?;
    convert::from_ffi(py, crossed)
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(roundtrip, module)?)?;
    module.add(
        "StackEncryptError",
        py.get_type::<errors::StackEncryptError>(),
    )?;
    module.add(
        "DeclarationError",
        py.get_type::<errors::DeclarationError>(),
    )?;
    module.add("PlanError", py.get_type::<errors::PlanError>())?;
    module.add("EngineError", py.get_type::<errors::EngineError>())?;
    Ok(())
}
