//! The PyO3 shell. It is deliberately thin: a plan and values go in, values
//! come out. Everything that encrypts, derives a term or frames an EQL
//! payload happens in `stack-encrypt`, so a later move to a different FFI
//! replaces this crate and nothing above it.

use pyo3::prelude::*;

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

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(version, module)?)?;
    Ok(())
}
