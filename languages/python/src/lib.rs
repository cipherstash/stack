//! The PyO3 shell. It is deliberately thin: a plan and values go in, values
//! come out. Everything that encrypts, derives a term or frames an EQL
//! payload happens in `stack-encrypt`, so a later move to a different FFI
//! replaces this crate and nothing above it.

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

mod convert;
mod engine;
mod errors;
mod plan;
mod runtime;
mod targets;
mod tree;

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

/// Parse a data plan through the engine, and resolve each target field.
///
/// Parsing mints no key and makes no request, so this runs with no
/// credentials — which is the point: a declaration error is an import-time
/// error, not a first-write error (principle G3).
///
/// Returns `{field: {name, sql_domain, query_sql_domain}}` for the target
/// fields, which is what the caller needs to write its SQL casts. A plan
/// with no target field returns an empty dict.
#[pyfunction]
fn check_plan(py: Python<'_>, fields: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    let (wire, resolved) = plan::resolve(fields)?;
    // The engine's own checks: context, the outputs/target exclusivity, a
    // type on every field with a term output, a type that admits each index,
    // and a target name the resolver knows.
    stack_encrypt::dynamic::record::plan_with(wire, &targets::Resolver)
        .map_err(|error| errors::PlanError::new_err(format!("{error}")))?;

    let domains = PyDict::new(py);
    for field in resolved {
        let entry = PyDict::new(py);
        entry.set_item("name", field.name)?;
        entry.set_item("sql_domain", field.sql_domain)?;
        entry.set_item("query_sql_domain", field.query_sql_domain)?;
        domains.set_item(field.field, entry)?;
    }
    Ok(domains.into_any().unbind())
}

#[pymodule]
fn _engine(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add_function(wrap_pyfunction!(version, module)?)?;
    module.add_function(wrap_pyfunction!(roundtrip, module)?)?;
    module.add_function(wrap_pyfunction!(check_plan, module)?)?;
    module.add_class::<engine::Engine>()?;
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
