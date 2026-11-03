//! `encrypt` at the boundary: the models' attributes into the engine's
//! input frame, and the engine's rows into Python dicts.
//!
//! The frame is written straight from the attributes, with the GIL held,
//! and every value is checked while it is written: the whole list is
//! refused before any request (the spec in #1341, "Errors"). Then the GIL
//! is released and the engine runs on the shared client. The dicts are
//! built from the engine's output; no plaintext passes through a Python
//! dict on the way in.

use std::cell::RefCell;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyType};
use stackencrypt_core::encrypt::plaintext::{Encrypt, MapSink, SeqSink, Sink, SourceError};
use stackencrypt_core::encrypt::{self as core, Column, Field, ModelPlan, ValueFrame};
use stackencrypt_core::refusal::Refusal;
use stackencrypt_core::values::{self, Kind};

use crate::errors::raise;
use crate::values::{read, to_python, PyKind, Read};

/// One plan field as the decorator hands it over: `(name, eql_type, kind,
/// value_type)`.
type FieldSpec<'py> = (String, Option<String>, Option<String>, Bound<'py, PyType>);

/// A model's plan, built once by `Cipher` and passed to every call.
#[pyclass(frozen, module = "stackencrypt._engine")]
pub struct Plan {
    pub(crate) plan: ModelPlan,
    /// The Python type each field's value must have, in plan order.
    pub(crate) kinds: Vec<PyKind>,
}

/// Build the plan for a model stored in `table`.
///
/// `fields` is `(name, eql_type, kind, value_type)` per plan field in
/// declaration order: the EQL type's name and its kind for a sealed field,
/// both `None` for a passthrough, and the Python type the field's
/// annotation declares. The decorator checked that the type matches the
/// kind, and that a passthrough type is one the engine carries.
#[pyfunction]
pub fn build_plan(py: Python<'_>, table: &str, fields: Vec<FieldSpec<'_>>) -> PyResult<Plan> {
    let mut kinds = Vec::with_capacity(fields.len());
    let mut specs = Vec::with_capacity(fields.len());
    for (name, eql_type, kind, value_type) in fields {
        let eql = match (eql_type, kind) {
            (Some(eql_type), Some(kind)) => {
                let kind = Kind::parse(&kind).ok_or_else(|| {
                    raise(
                        py,
                        declaration_fault(&name, &format!("kind {kind:?} has no Python type")),
                    )
                })?;
                kinds.push(PyKind::of_kind(kind));
                Some((eql_type, kind))
            }
            (None, None) => {
                let kind = PyKind::of_type(py, &value_type)?.ok_or_else(|| {
                    raise(
                        py,
                        declaration_fault(&name, "its type is not one a passthrough stores"),
                    )
                })?;
                kinds.push(kind);
                None
            }
            _ => {
                return Err(raise(
                    py,
                    declaration_fault(&name, "an EQL type without a kind, or a kind without one"),
                ))
            }
        };
        specs.push(Field { name, eql });
    }
    let plan = ModelPlan::new(table, specs).map_err(|refused| raise(py, refused))?;
    Ok(Plan { plan, kinds })
}

fn declaration_fault(field: &str, what: &str) -> Refusal {
    Refusal {
        code: "declaration_type_mismatch".to_owned(),
        message: format!(
            "field {field:?} reached the engine with {what}. The decorator should have \
             refused it. Report this message as a stackencrypt bug."
        ),
        field: Some(field.to_owned()),
        reason: None,
    }
}

/// Encrypt `models` under `plan`: one dict per model, with a `str` of EQL
/// JSON for each sealed field and the value itself for each passthrough.
///
/// An empty list returns an empty list and touches nothing. Otherwise the
/// values are read and checked first, then the shared client is built on
/// the first call in the process, and the engine runs with the GIL
/// released.
#[pyfunction]
pub fn encrypt<'py>(
    py: Python<'py>,
    plan: &Plan,
    models: Vec<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    if models.is_empty() {
        return Ok(PyList::empty(py));
    }
    let rows = models.len();
    let frame = input_frame(py, plan, &models)?;
    let encrypted = py
        .detach(|| core::encrypt(&plan.plan, frame, rows))
        .map_err(|refused| raise(py, refused))?;
    let out = PyList::empty(py);
    for columns in encrypted {
        let row = PyDict::new(py);
        for (field, column) in plan.plan.fields().iter().zip(columns) {
            let value = match column {
                Column::Eql(json) => json.into_pyobject(py)?.into_any().unbind(),
                Column::Passthrough(scalar) => to_python(py, &scalar)?,
            };
            row.set_item(&field.name, value)?;
        }
        out.append(row)?;
    }
    Ok(out)
}

/// The models as the engine's input frame, every value read and checked.
pub(crate) fn input_frame(
    py: Python<'_>,
    plan: &Plan,
    models: &[Bound<'_, PyAny>],
) -> PyResult<ValueFrame> {
    let failed = RefCell::new(None);
    let source = Models {
        plan,
        models,
        failed: &failed,
    };
    core::frame_of(source).map_err(|error| {
        failed.into_inner().unwrap_or_else(|| {
            raise(
                py,
                Refusal {
                    code: "stack_encrypt_unknown".to_owned(),
                    message: format!("the models could not be written as a frame: {error}"),
                    field: None,
                    reason: None,
                },
            )
        })
    })
}

/// How many times the shared engine client has been built in this process.
/// For the tests: two `Cipher` instances share one.
#[pyfunction]
pub fn client_builds() -> u64 {
    stackencrypt_core::client::build_count()
}

/// How many requests the shared client has sent to ZeroKMS in this process,
/// the keyset load included. For the tests.
#[pyfunction]
pub fn request_count() -> u64 {
    stackencrypt_core::client::request_count()
}

/// `value` read as `field`'s Python type and checked against the range of
/// its kind, as `encrypt` and `query` both take it. A refusal names the
/// field, with the kind as its reason.
///
/// The outer error is Python's own, such as one a `__index__` raises.
pub(crate) fn field_value<'a>(
    value: &'a Bound<'_, PyAny>,
    field: &Field,
    kind: PyKind,
) -> PyResult<Result<Read<'a>, Refusal>> {
    let engine_kind = field.eql.as_ref().map(|(_, kind)| *kind);
    let reason = engine_kind.map_or("passthrough", Kind::name);
    let named = |refused: Refusal| Refusal {
        message: format!("field {:?}: {}", field.name, refused.message),
        field: Some(field.name.clone()),
        reason: Some(reason.to_owned()),
        ..refused
    };
    let read = match read(value, kind, reason)? {
        Ok(read) => read,
        Err(refused) => return Ok(Err(named(refused))),
    };
    // The range rules first, so a misfit is refused with its own code
    // and the field's name, not as the sink's error.
    if let Err(misfit) = values::scalar(engine_kind, read.value()) {
        let what = match engine_kind {
            Some(kind) => format!("the value does not fit {}.", kind.name()),
            None => "the value is outside what the engine stores.".to_owned(),
        };
        return Ok(Err(named(Refusal {
            code: misfit.code().to_owned(),
            message: what,
            field: None,
            reason: None,
        })));
    }
    Ok(Ok(read))
}

/// The models as the engine's source: a sequence of maps, one entry per
/// plan field, read from each model's attribute of that name.
///
/// A value the rules refuse, or an attribute read that raises, stops the
/// walk. The error is kept in `failed` and raised after, because the sink's
/// own error type cannot carry it: the spec wants a property that raises to
/// propagate unchanged, and a refused value to name its field.
struct Models<'a, 'py> {
    plan: &'a Plan,
    models: &'a [Bound<'py, PyAny>],
    failed: &'a RefCell<Option<PyErr>>,
}

impl Models<'_, '_> {
    /// Keep `error` to raise after the walk, and stop the walk.
    fn stop<E: stackencrypt_core::encrypt::plaintext::Error>(&self, error: PyErr) -> E {
        *self.failed.borrow_mut() = Some(error);
        E::source(SourceError::msg("a value was refused"))
    }

    fn write_field<S: Sink>(
        &self,
        sink: S,
        model: &Bound<'_, PyAny>,
        field: &Field,
        kind: PyKind,
    ) -> Result<S::Ok, S::Error> {
        // The attribute, as the user's class gives it: a property that
        // raises propagates unchanged.
        let attribute = model
            .getattr(&field.name)
            .map_err(|error| self.stop(error))?;
        let read = match field_value(&attribute, field, kind) {
            Ok(Ok(read)) => read,
            Ok(Err(refused)) => return Err(self.stop(raise(model.py(), refused))),
            Err(error) => return Err(self.stop(error)),
        };
        let engine_kind = field.eql.as_ref().map(|(_, kind)| *kind);
        // A passthrough is written as a plain scalar: the plan's
        // `"passthrough"` output carries the field's frame as it is, so a
        // passthrough node here would come back nested in one.
        values::write(sink, engine_kind, read.value())
    }
}

impl Encrypt for Models<'_, '_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let fields = self.plan.plan.fields();
        let mut rows = sink.seq(Some(self.models.len()))?;
        for model in self.models {
            let mut row = rows.element()?.map(Some(fields.len()))?;
            for (field, kind) in fields.iter().zip(&self.plan.kinds) {
                let entry = row.entry(&field.name)?;
                self.write_field(entry, model, field, *kind)?;
            }
            row.end()?;
        }
        rows.end()
    }
}
