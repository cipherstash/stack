//! The query functions at the boundary: one value checked as `encrypt`
//! checks it, and the engine's term for one operator back as a `str`.
//!
//! `Cipher` has already refused a name that is not a declared field, and a
//! field that does not answer the operator (the spec in #1341, "Errors").
//! Core checks the second again from the plan, before the client is built.

use pyo3::prelude::*;
use stackencrypt_core::query::{self as core, OpSpec};
use stackencrypt_core::refusal::Refusal;

use crate::encrypt::{field_value, Plan};
use crate::errors::raise;

/// The query term for the operator named `operator` and `value` on the
/// sealed field `field`.
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
    operator: &str,
    value: &Bound<'_, PyAny>,
) -> PyResult<String> {
    let Some(op) = OpSpec::parse(operator) else {
        return Err(raise(py, unknown_operator(field, operator)));
    };
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
    py.detach(|| core::query(&plan.plan, field, op, engine_kind, value))
        .map_err(|refused| raise(py, refused))
}

/// The names of the operators the field `field` answers, from the plan
/// alone, with no request. A passthrough field answers none.
#[pyfunction]
pub fn operators(py: Python<'_>, plan: &Plan, field: &str) -> PyResult<Vec<&'static str>> {
    let sealed = plan
        .plan
        .fields()
        .iter()
        .any(|candidate| candidate.name == field && candidate.eql.is_some());
    if !sealed {
        return Ok(Vec::new());
    }
    core::operators(&plan.plan, field).map_err(|refused| raise(py, refused))
}

fn unknown_operator(field: &str, operator: &str) -> Refusal {
    Refusal {
        code: "stack_encrypt_unknown".to_owned(),
        message: format!(
            "the operator {operator:?} reached the engine's query, but the engine has no such \
             operator. Cipher should have refused it. Report this message as a stackencrypt bug."
        ),
        field: Some(field.to_owned()),
        reason: None,
    }
}

fn not_sealed(field: &str) -> Refusal {
    Refusal {
        code: "stack_encrypt_unknown".to_owned(),
        message: format!(
            "field {field:?} reached the engine's query, but it is not a sealed field of the \
             plan. Cipher should have refused it. Report this message as a stackencrypt bug."
        ),
        field: Some(field.to_owned()),
        reason: None,
    }
}
