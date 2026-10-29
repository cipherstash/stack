//! The pyo3 extension: `stackencrypt._engine`.
//!
//! Deliberately thin: this crate only converts between Python and Rust at
//! the boundary. Logic belongs in `stackencrypt-core` and `stack-encrypt`.

use pyo3::prelude::*;
use stackencrypt_core::credentials;
use stackencrypt_core::plan::{self, Column};
use stackencrypt_core::refusal::Refusal;

/// A refusal as the tuple the Python side raises: `(code, message, field,
/// reason)`.
type RefusalTuple = (String, String, Option<String>, Option<String>);

fn to_tuple(refused: Refusal) -> RefusalTuple {
    (refused.code, refused.message, refused.field, refused.reason)
}

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

/// The engine's check of a model's plan, run when the class is declared.
///
/// `fields` is `(name, eql_type)` per plan field in declaration order, with
/// `eql_type` `None` for a passthrough field. Returns `None` when the engine
/// accepts the plan, or its refusal as `(code, message, field, reason)`. The
/// Python side raises it as a `DeclarationError`.
#[pyfunction]
fn check_plan(table: &str, fields: Vec<(String, Option<String>)>) -> Option<RefusalTuple> {
    let fields: Vec<(&str, Column<'_>)> = fields
        .iter()
        .map(|(name, eql_type)| {
            let column = eql_type.as_deref().map_or(Column::Passthrough, Column::Eql);
            (name.as_str(), column)
        })
        .collect();
    plan::check(table, &fields).err().map(to_tuple)
}

/// Find the credentials as every SDK does: `CS_CLIENT_ACCESS_KEY` and
/// `CS_WORKSPACE_CRN`, then the profile store. Makes no request. Returns
/// `None` when they are found, or the refusal as `(code, message, field,
/// reason)`.
///
/// Nothing keeps the strategy yet: `Cipher` only needs to know that the
/// credentials are there. The ticket that makes the first request keeps it.
#[pyfunction]
fn detect_credentials() -> Option<RefusalTuple> {
    credentials::detect().err().map(to_tuple)
}

/// Gate fact 2 (#1384): block for `millis` on a multi-thread tokio runtime
/// with the GIL released, the way an engine call will. Returns the
/// milliseconds the call blocked for, measured in Rust.
#[cfg(feature = "gate-probe")]
#[pyfunction]
fn _probe_detached_sleep(py: Python<'_>, millis: u64) -> u64 {
    py.detach(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_time()
            .build()
            .expect("a tokio runtime builds");
        let started = std::time::Instant::now();
        // The sleep is made inside the runtime: tokio's timer needs one.
        runtime.block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
        });
        started.elapsed().as_millis() as u64
    })
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(build_info, module)?)?;
    module.add_function(wrap_pyfunction!(check_plan, module)?)?;
    module.add_function(wrap_pyfunction!(detect_credentials, module)?)?;
    #[cfg(feature = "gate-probe")]
    module.add_function(wrap_pyfunction!(_probe_detached_sleep, module)?)?;
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
