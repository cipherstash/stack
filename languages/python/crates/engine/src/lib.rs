//! The pyo3 extension: `stackencrypt._engine`.
//!
//! Deliberately thin: this crate only converts between Python and Rust at
//! the boundary. Logic belongs in `stackencrypt-core` and `stack-encrypt`.

use pyo3::prelude::*;

/// The two build facts the package exposes: `(version, engine_commit)`.
///
/// `version` is this crate's version, which maturin also writes into the
/// wheel's metadata, so `stackencrypt.__version__` and
/// `importlib.metadata.version("stackencrypt")` agree by construction.
/// `engine_commit` is the commit of `stack-encrypt` the build was taken from.
#[pyfunction]
fn build_info() -> (&'static str, &'static str) {
    (
        env!("CARGO_PKG_VERSION"),
        stackencrypt_core::engine_commit(),
    )
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(build_info, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use pyo3::prelude::*;

    /// Links libpython and runs the module function: the proof that the
    /// engine crate's tests build outside a wheel (the task puts libpython on
    /// the loader path).
    #[test]
    fn module_exposes_build_info() {
        Python::initialize();
        Python::attach(|py| {
            let module = pyo3::wrap_pymodule!(super::_engine)(py);
            let (version, commit): (String, String) = module
                .getattr(py, "build_info")
                .expect("build_info is exported")
                .call0(py)
                .expect("build_info takes no argument")
                .extract(py)
                .expect("a pair of strings");
            assert_eq!(version, env!("CARGO_PKG_VERSION"));
            assert_eq!(commit, stackencrypt_core::engine_commit());
        });
    }
}
