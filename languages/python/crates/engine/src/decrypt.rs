//! `decrypt` at the boundary: the rows psycopg returned into the engine's
//! stored record, and the opened values into instances of the model class.
//!
//! Every row is read and checked with the GIL held, before any key request
//! (the spec in #1341, "Errors"): it is a mapping, it has every plan field's
//! column, each EQL column is EQL JSON stored under this table and column,
//! and each passthrough value has the field's exact type. Then the GIL is
//! released and the engine opens the whole list. The instances are built
//! only after every value has been turned into a Python object, so a call
//! that fails returns no instance.

use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};
use stackencrypt_core::decrypt::{self as core, Row, Rows};
use stackencrypt_core::encrypt::Field;
use stackencrypt_core::refusal::Refusal;
use stackencrypt_core::values::Scalar;

use crate::encrypt::Plan;
use crate::errors::raise;
use crate::values::{read, to_python, PyKind};

/// Decrypt `rows` under `plan` into instances of `cls`, one per row, built
/// with the plan's fields as keyword arguments.
///
/// An empty list returns an empty list and touches nothing.
#[pyfunction]
pub fn decrypt<'py>(
    py: Python<'py>,
    plan: &Plan,
    cls: &Bound<'py, PyAny>,
    rows: Vec<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    if rows.is_empty() {
        return Ok(PyList::empty(py));
    }
    let mut stored = Rows::with_capacity(rows.len());
    for (at, row) in rows.iter().enumerate() {
        stored.push(stored_row(plan, row, at)?);
    }
    let opened = py
        .detach(|| core::decrypt(&plan.plan, stored))
        .map_err(|refused| raise(py, refused))?;
    // Every value first, then every instance: a value Python cannot hold
    // fails the call before any constructor runs.
    let mut arguments = Vec::with_capacity(opened.len());
    for values in opened {
        let kwargs = PyDict::new(py);
        for (field, value) in plan.plan.fields().iter().zip(values) {
            kwargs.set_item(&field.name, python_value(py, field, value)?)?;
        }
        arguments.push(kwargs);
    }
    let out = PyList::empty(py);
    for kwargs in arguments {
        // The class's own constructor: an error it raises propagates as it is.
        out.append(cls.call((), Some(&kwargs))?)?;
    }
    Ok(out)
}

/// One row as the engine's stored row, checked.
fn stored_row(plan: &Plan, row: &Bound<'_, PyAny>, at: usize) -> PyResult<Row> {
    let py = row.py();
    if !row.is_instance(mapping(py)?)? {
        return Err(raise(
            py,
            Refusal {
                code: "decrypt_row_shape".to_owned(),
                message: format!(
                    "row {at} is a {}, not a mapping of column names to values. Read the \
                     rows with psycopg's dict_row: cursor(row_factory=dict_row).",
                    type_name(row)
                ),
                field: None,
                reason: None,
            },
        ));
    }
    let mut stored = Row::new();
    for (field, kind) in plan.plan.fields().iter().zip(&plan.kinds) {
        if !row.contains(&field.name)? {
            return Err(raise(
                py,
                Refusal {
                    code: "decrypt_missing_column".to_owned(),
                    message: format!(
                        "row {at} has no column {:?}. Select every declared column of the \
                         model, passthrough columns included.",
                        field.name
                    ),
                    field: Some(field.name.clone()),
                    reason: None,
                },
            ));
        }
        let value = row.get_item(&field.name)?;
        let in_row = |refused: Refusal| {
            raise(
                py,
                Refusal {
                    message: format!("row {at}, {}", refused.message),
                    ..refused
                },
            )
        };
        match &field.eql {
            Some(_) => stored
                .eql(&plan.plan, field, &eql_text(field, &value)?)
                .map_err(in_row)?,
            None => passthrough(&mut stored, field, *kind, &value).map_err(in_row)?,
        }
    }
    Ok(stored)
}

/// An EQL column's JSON text, as UTF-8 bytes: from a `str`, from `bytes`
/// that are UTF-8, or from a `dict` the driver already parsed.
fn eql_text(field: &Field, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let py = value.py();
    let malformed = |what: String| {
        raise(
            py,
            Refusal {
                code: "decrypt_malformed".to_owned(),
                message: format!("field {:?}: the column value {what}.", field.name),
                field: Some(field.name.clone()),
                reason: None,
            },
        )
    };
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(text.to_cow()?.as_bytes().to_vec());
    }
    if let Ok(bytes) = value.cast::<PyBytes>() {
        let bytes = bytes.as_bytes();
        return match std::str::from_utf8(bytes) {
            Ok(_) => Ok(bytes.to_vec()),
            Err(_) => Err(malformed("is bytes that are not UTF-8".to_owned())),
        };
    }
    if value.cast::<PyDict>().is_ok() {
        return match dumps(py)?.call1((value,)) {
            Ok(text) => Ok(text.cast::<PyString>()?.to_cow()?.as_bytes().to_vec()),
            Err(_) => Err(malformed("is a dict that is not JSON".to_owned())),
        };
    }
    if value.is_none() {
        return Err(malformed(
            "is None, a SQL NULL, not an EQL value".to_owned(),
        ));
    }
    Err(malformed(format!(
        "is a {}, not the str, bytes or dict of an EQL value",
        type_name(value)
    )))
}

/// A passthrough column's value, checked by exact type as on `encrypt`.
fn passthrough(
    stored: &mut Row,
    field: &Field,
    kind: PyKind,
    value: &Bound<'_, PyAny>,
) -> Result<(), Refusal> {
    let named = |refused: Refusal| Refusal {
        message: format!("field {:?}: {}", field.name, refused.message),
        field: Some(field.name.clone()),
        reason: Some("passthrough".to_owned()),
        ..refused
    };
    let read = match read(value, kind, "passthrough") {
        Ok(Ok(read)) => read,
        Ok(Err(refused)) => return Err(named(refused)),
        Err(error) => {
            return Err(named(Refusal {
                code: "decrypt_malformed".to_owned(),
                message: format!("the value could not be read: {error}"),
                field: None,
                reason: None,
            }))
        }
    };
    stored.passthrough(field, read.value()).map_err(|misfit| {
        named(Refusal {
            code: misfit.code().to_owned(),
            message: "the value is outside what the engine stores.".to_owned(),
            field: None,
            reason: None,
        })
    })
}

/// An opened value as the Python object of its field.
fn python_value(py: Python<'_>, field: &Field, value: Scalar) -> PyResult<Py<PyAny>> {
    let ranged = matches!(value, Scalar::Date(_) | Scalar::Timestamp(_));
    to_python(py, value).map_err(|error| {
        if !ranged {
            return error;
        }
        raise(
            py,
            Refusal {
                code: "decrypt_not_representable".to_owned(),
                message: format!(
                    "field {:?}: the opened value is outside the range Python's datetime \
                     holds.",
                    field.name
                ),
                field: Some(field.name.clone()),
                reason: None,
            },
        )
    })
}

fn mapping(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    static MAPPING: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    let mapping = MAPPING.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        Ok(py.import("collections.abc")?.getattr("Mapping")?.unbind())
    })?;
    Ok(mapping.bind(py))
}

fn dumps(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    static DUMPS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    let dumps = DUMPS.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        Ok(py.import("json")?.getattr("dumps")?.unbind())
    })?;
    Ok(dumps.bind(py))
}

fn type_name(value: &Bound<'_, PyAny>) -> String {
    value.get_type().name().map_or_else(
        |_| "value of an unknown type".to_owned(),
        |name| name.to_string(),
    )
}
