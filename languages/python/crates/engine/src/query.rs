//! The query functions at the boundary: one value checked as `encrypt`
//! checks it, and the engine's term for one operator back as a `str`.
//!
//! `Cipher` has already refused a name that is not a declared field, and a
//! field that does not answer the operator (the spec in #1341, "Errors").
//! Core checks the second again from the plan, before the client is built.

use pyo3::prelude::*;
use pyo3::types::PyList;
use stackencrypt_core::query::{self as core, Op};
use stackencrypt_core::refusal::Refusal;

use crate::encrypt::{field_value, Plan};
use crate::errors::raise;
use crate::values::Read;

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
    let Some(op) = Op::parse(operator) else {
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
    // A nullable field reads None as a missing value, which has no term.
    if declared.nullable && value.is_none() {
        return Err(raise(py, no_term_for_none(field, engine_kind.name())));
    }
    let read = field_value(value, declared, kind)?.map_err(|refused| raise(py, refused))?;
    let value = read.value();
    py.detach(|| core::query(&plan.plan, field, op, engine_kind, value))
        .map_err(|refused| raise(py, refused))
}

/// For each of `values`, decrypted values of the match field `field`,
/// whether it holds every token of the match text `text`. Each value is
/// read as `encrypt` reads the field's values. Runs with the GIL released,
/// with no key and no request.
#[pyfunction]
pub fn verify(
    py: Python<'_>,
    plan: &Plan,
    field: &str,
    text: &Bound<'_, PyAny>,
    values: &Bound<'_, PyList>,
) -> PyResult<Vec<bool>> {
    let found = plan
        .plan
        .fields()
        .iter()
        .zip(&plan.kinds)
        .find(|(candidate, _)| candidate.name == field && candidate.eql.is_some());
    let Some((declared, &kind)) = found else {
        return Err(raise(py, not_sealed(field)));
    };
    let text = field_value(text, declared, kind)?.map_err(|refused| raise(py, refused))?;
    let items: Vec<Bound<'_, PyAny>> = values.iter().collect();
    let mut read: Vec<Read<'_>> = Vec::with_capacity(items.len());
    for item in &items {
        read.push(field_value(item, declared, kind)?.map_err(|refused| raise(py, refused))?);
    }
    let texts: Vec<&str> = read
        .iter()
        .map(as_text)
        .collect::<Option<_>>()
        .ok_or_else(|| raise(py, not_text(field)))?;
    let Some(query) = as_text(&text) else {
        return Err(raise(py, not_text(field)));
    };
    py.detach(|| core::verify(&plan.plan, field, query, &texts))
        .map_err(|refused| raise(py, refused))
}

/// How many rows to fetch for the match term `term` on `field` so that
/// `want` of them verify: `None` when no finite number can be promised.
/// Uses no key and makes no request.
#[pyfunction]
#[pyo3(signature = (plan, field, term, want, rows, histogram=None, confidence=None))]
#[allow(clippy::too_many_arguments)]
pub fn target_limit(
    py: Python<'_>,
    plan: &Plan,
    field: &str,
    term: &str,
    want: u64,
    rows: u64,
    histogram: Option<Vec<(u32, u64)>>,
    confidence: Option<f64>,
) -> PyResult<Option<u64>> {
    core::target_limit(
        &plan.plan,
        field,
        term,
        want,
        rows,
        histogram.as_deref(),
        confidence,
    )
    .map_err(|refused| raise(py, refused))
}

fn no_term_for_none(field: &str, kind: &str) -> Refusal {
    Refusal {
        code: "value_none".to_owned(),
        message: format!(
            "field {field:?}: is None. A missing value is stored as SQL NULL, with no \
             term. Search for it with `IS NULL`."
        ),
        field: Some(field.to_owned()),
        reason: Some(kind.to_owned()),
    }
}

fn as_text<'r>(read: &'r Read<'_>) -> Option<&'r str> {
    match read.value() {
        stackencrypt_core::values::Value::Text(text) => Some(text),
        _ => None,
    }
}

fn not_text(field: &str) -> Refusal {
    Refusal {
        code: "stack_encrypt_unknown".to_owned(),
        message: format!(
            "field {field:?} reached the engine's verify, but it is not a text field. Cipher \
             should have refused it. Report this message as a stackencrypt bug."
        ),
        field: Some(field.to_owned()),
        reason: None,
    }
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
