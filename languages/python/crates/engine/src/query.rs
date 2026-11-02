//! `query` at the boundary: one value checked as `encrypt` checks it, and
//! the engine's equality term back as a `str`.
//!
//! `Cipher.query` has already refused a name that is not a declared field,
//! and a field with no `eq` index (the spec in #1341, "Errors"). Core
//! checks the second again from the plan, before the client is built.

use pyo3::prelude::*;
use stackencrypt_core::query as core;
use stackencrypt_core::refusal::Refusal;

use crate::encrypt::{field_value, Plan};
use crate::errors::raise;

/// The equality query term for `value` on the sealed field `field`.
///
/// The value is checked first, by exact type and range, with no request.
/// Then the shared client is built on the first call in the process, and
/// the engine derives the term with the GIL released. A term needs no
/// request of its own.
#[pyfunction]
pub fn query(
    py: Python<'_>,
    plan: &Plan,
    field: &str,
    value: &Bound<'_, PyAny>,
) -> PyResult<String> {
    let found = plan
        .plan
        .fields()
        .iter()
        .zip(&plan.kinds)
        .find(|(candidate, _)| candidate.name == field);
    let Some((declared, &kind)) = found else {
        return Err(raise(py, not_sealed(field)));
    };
    let Some((_, engine_kind)) = declared.eql else {
        return Err(raise(py, not_sealed(field)));
    };
    let read = field_value(value, declared, kind)?.map_err(|refused| raise(py, refused))?;
    let value = read.value();
    py.detach(|| core::query(&plan.plan, field, engine_kind, value))
        .map_err(|refused| raise(py, refused))
}

fn not_sealed(field: &str) -> Refusal {
    Refusal {
        code: "stack_encrypt_unknown".to_owned(),
        message: format!(
            "field {field:?} reached the engine's query, but it is not a sealed field of the \
             plan. Cipher.query should have refused it. Report this message as a stackencrypt \
             bug."
        ),
        field: Some(field.to_owned()),
        reason: None,
    }
}
