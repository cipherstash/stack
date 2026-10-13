//! The engine handle: one `StackCipher`, and the three operations over it.
//!
//! This is the whole of what Python can ask the engine to do. Each method
//! takes the data plan and the values, hands them to
//! `stack_encrypt::dynamic::record` in ONE call, and converts what comes
//! back. No field loop lives here: a batch of rows is one `FfiValue::Array`
//! in and one `CipherText::Sequence` out, and the engine's `encrypt_with`
//! zips every target field of every row into one ZeroKMS request
//! (principle G5).
//!
//! # What a stored record is, from here
//!
//! The engine's result is a tree, `CipherText::Map` per row, and inside it
//! one `Map` per field keyed by output: a target field's EQL JSON rides as a
//! passthrough byte node under `"eql"`, a passthrough field's value under
//! `"passthrough"`, and a ciphertext under `"c"`. The first two are
//! `FfiValue`s in a box and come straight out; the third is a sealed
//! subtree with no byte form this shell knows, so a plan that produces one
//! is refused here with the field named. The tracer's path has no such
//! field — EQL targets and passthroughs only — and the refusal is what keeps
//! that a decision rather than a surprise.
//!
//! So `encrypt` returns, per row, a dict of field name to column value, and
//! `decrypt` takes the same dicts back and rebuilds the tree. That is the
//! shape SQL wants, and it means no record ever needs a serialised form.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList};
use stack_encrypt::dynamic::record::{self, Plan, EQL_KEY};
use stack_encrypt::dynamic::{FfiValue, Scope};
use stack_encrypt::kms::StackKms;
use stack_encrypt::{CipherText, StackCipher, StackCipherText};

use crate::errors::EngineError;
use crate::{convert, plan as wire, runtime, targets};

/// The passthrough output key, as `dynamic::record` spells it. `EQL_KEY` is
/// exported; this one is not, and the module docs fix both as wire format.
const PASSTHROUGH_KEY: &str = "passthrough";

/// A handle on the engine, with its credentials already discovered.
///
/// `StackCipher::new()` does the discovery: `CS_CLIENT_ID` + `CS_CLIENT_KEY`
/// first, then the profile `stash auth login` writes, through
/// `stack_auth::AutoStrategy`. That is decision 10 satisfied by the engine,
/// so no credential code lives here.
#[pyclass]
pub struct Engine {
    cipher: StackCipher<StackKms<stack_auth::AutoStrategy>>,
    /// ZeroKMS requests this handle has driven. Counted per `block_on` that
    /// ran a pending, which is one per batch: the evidence for principle G5.
    key_requests: AtomicU64,
}

#[pymethods]
impl Engine {
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        let cipher = runtime::block_on(py, StackCipher::new()).map_err(engine)?;
        Ok(Self {
            cipher,
            key_requests: AtomicU64::new(0),
        })
    }

    #[getter]
    fn key_requests(&self) -> u64 {
        self.key_requests.load(Ordering::Relaxed)
    }

    /// A batch of rows as stored records, in one key request.
    ///
    /// Each row is a dict of field name to value, each record a dict of
    /// field name to column value. An empty batch returns empty and touches
    /// nothing: no plan is parsed, no key is minted.
    fn encrypt(
        &self,
        py: Python<'_>,
        fields: &Bound<'_, PyAny>,
        rows: Vec<Bound<'_, PyDict>>,
    ) -> PyResult<Py<PyAny>> {
        if rows.is_empty() {
            return Ok(PyList::empty(py).into_any().unbind());
        }
        let plan = parse(fields)?;
        let source = FfiValue::Array(
            rows.iter()
                .map(|row| source_row(row, &plan))
                .collect::<PyResult<Vec<_>>>()?,
        );
        let keyset = self.cipher.default_keyset();
        let pending =
            record::encrypt_with(&keyset, source, &plan, &targets::Resolver).map_err(engine)?;
        let tree = runtime::block_on(py, pending).map_err(engine)?;
        self.key_requests.fetch_add(1, Ordering::Relaxed);

        let out = PyList::empty(py);
        for row in rows_of(tree)? {
            out.append(stored_row(py, row, &plan)?)?;
        }
        Ok(out.into_any().unbind())
    }

    /// A batch of stored records back as rows, in one key request.
    fn decrypt(
        &self,
        py: Python<'_>,
        fields: &Bound<'_, PyAny>,
        records: Vec<Bound<'_, PyDict>>,
    ) -> PyResult<Py<PyAny>> {
        if records.is_empty() {
            return Ok(PyList::empty(py).into_any().unbind());
        }
        let plan = parse(fields)?;
        let tree = CipherText::Sequence(
            records
                .iter()
                .map(|record| record_tree(record, &plan))
                .collect::<PyResult<Vec<_>>>()?,
        );
        let scope = Scope::Keyset(self.cipher.default_keyset());
        // `None`: the expected context label only applies to a plan whose
        // context comes from a FIELD of the record (`context_field`), where
        // the opener checks the stored one against it. This plan declares
        // its context, so there is nothing to expect.
        let pending =
            record::decrypt_with(scope, tree, &plan, None, &targets::Resolver).map_err(engine)?;
        let opened = runtime::block_on(py, pending).map_err(engine)?;
        self.key_requests.fetch_add(1, Ordering::Relaxed);

        let FfiValue::Array(rows) = opened else {
            return Err(EngineError::new_err(
                "the engine opened a batch to something other than a list of rows",
            ));
        };
        let out = PyList::empty(py);
        for row in rows {
            out.append(convert::from_ffi(py, row)?)?;
        }
        Ok(out.into_any().unbind())
    }

    /// One query term for `field`, as the bytes the EQL query domain takes.
    fn query(
        &self,
        py: Python<'_>,
        fields: &Bound<'_, PyAny>,
        field: &str,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let plan = parse(fields)?;
        let declared = plan
            .fields()
            .iter()
            .find(|candidate| candidate.name() == field)
            .ok_or_else(|| {
                EngineError::new_err(format!("{field}: the plan names no such field"))
            })?;
        if declared.target().is_none() {
            return Err(EngineError::new_err(format!(
                "{field}: not an EQL target field, so it answers no query"
            )));
        }
        let value = convert::to_ffi(value, declared.field_type())
            .map_err(|error| in_field(field, error.into()))?;
        let keyset = self.cipher.default_keyset();
        let pending =
            record::query(&keyset, &plan, field, value, &targets::Resolver).map_err(engine)?;
        let term = runtime::block_on(py, pending).map_err(engine)?;
        self.key_requests.fetch_add(1, Ordering::Relaxed);
        Ok(PyBytes::new(py, &term).into_any().unbind())
    }
}

/// The plan, parsed through the engine with the EQL resolver. Parsed on
/// every call: it is a few allocations and no I/O, and a handle that cached
/// one would have to decide when two Python dicts are the same plan.
fn parse(fields: &Bound<'_, PyAny>) -> PyResult<Plan> {
    let (wire, _) = wire::resolve(fields)?;
    record::plan_with(wire, &targets::Resolver).map_err(engine)
}

/// One Python row as the engine's source row, each value checked against
/// the kind its field declares. The refusal names the field: the engine's
/// own would too, but this one is raised before the engine sees the row.
fn source_row(row: &Bound<'_, PyDict>, plan: &Plan) -> PyResult<FfiValue> {
    let mut pairs = Vec::with_capacity(plan.fields().len());
    for field in plan.fields() {
        let Some(value) = row.get_item(field.name())? else {
            return Err(EngineError::new_err(format!(
                "{}: the row has no such field",
                field.name()
            )));
        };
        let value = convert::to_ffi(&value, field.field_type())
            .map_err(|error| in_field(field.name(), error.into()))?;
        pairs.push((field.name().to_owned(), value));
    }
    Ok(FfiValue::Object(pairs))
}

/// The rows of an encrypted batch. One row in gives `Map`, a batch gives
/// `Sequence`; `encrypt` always sends a batch, so `Map` here is a defect.
fn rows_of(tree: StackCipherText) -> PyResult<Vec<Vec<(String, StackCipherText)>>> {
    let CipherText::Sequence(rows) = tree else {
        return Err(EngineError::new_err(
            "the engine sealed a batch to something other than a sequence",
        ));
    };
    rows.into_iter()
        .map(|row| match row {
            CipherText::Map(fields) => Ok(fields),
            _ => Err(EngineError::new_err(
                "the engine sealed a row to something other than a map",
            )),
        })
        .collect()
}

/// One stored row as a Python dict: field name to the value its column
/// takes. A target field's EQL JSON comes out as `bytes`; a passthrough's
/// value comes out as itself.
fn stored_row(
    py: Python<'_>,
    row: Vec<(String, StackCipherText)>,
    plan: &Plan,
) -> PyResult<Py<PyAny>> {
    let out = PyDict::new(py);
    for (name, node) in row {
        let CipherText::Map(outputs) = node else {
            return Err(EngineError::new_err(format!(
                "{name}: the engine's output for the field is not an output map"
            )));
        };
        let field = plan
            .fields()
            .iter()
            .find(|field| field.name() == name)
            .ok_or_else(|| EngineError::new_err(format!("{name}: not a field of the plan")))?;
        let key = if field.target().is_some() {
            EQL_KEY
        } else if field.has_ciphertext() {
            return Err(EngineError::new_err(format!(
                "{name}: a field with a bare ciphertext output has no column form \
                 in this shell; declare an EQL target or a passthrough"
            )));
        } else {
            PASSTHROUGH_KEY
        };
        let value = passthrough_value(&name, key, outputs)?;
        out.set_item(name, convert::from_ffi(py, value)?)?;
    }
    Ok(out.into_any().unbind())
}

/// The `FfiValue` a passthrough node under `key` carries.
fn passthrough_value(
    field: &str,
    key: &str,
    outputs: Vec<(String, StackCipherText)>,
) -> PyResult<FfiValue> {
    let node = outputs
        .into_iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, node)| node)
        .ok_or_else(|| EngineError::new_err(format!("{field}: no {key} node in the output")))?;
    let CipherText::Passthrough(payload) = node else {
        return Err(EngineError::new_err(format!(
            "{field}: the {key} node is not a passthrough"
        )));
    };
    let payload: Box<dyn Any + Send> = payload;
    payload
        .downcast::<FfiValue>()
        .map(|value| *value)
        .map_err(|_| EngineError::new_err(format!("{field}: the {key} node holds no value")))
}

/// A Python record dict back as the engine's row tree, the inverse of
/// `stored_row`. A target field's bytes go back under `"eql"`, a
/// passthrough's value under `"passthrough"`, each as the boxed `FfiValue`
/// the engine's own opener downcasts to.
fn record_tree(record: &Bound<'_, PyDict>, plan: &Plan) -> PyResult<StackCipherText> {
    let mut row = Vec::with_capacity(plan.fields().len());
    for field in plan.fields() {
        let name = field.name();
        let Some(value) = record.get_item(name)? else {
            return Err(EngineError::new_err(format!(
                "{name}: the record has no such field"
            )));
        };
        let (key, value) = if field.target().is_some() {
            let bytes = value.extract::<Vec<u8>>().map_err(|_| {
                EngineError::new_err(format!("{name}: a stored EQL value is bytes"))
            })?;
            (EQL_KEY, FfiValue::Bytes(bytes.into()))
        } else if field.has_ciphertext() {
            return Err(EngineError::new_err(format!(
                "{name}: a field with a bare ciphertext output has no column form \
                 in this shell; declare an EQL target or a passthrough"
            )));
        } else {
            let value = convert::to_ffi(&value, field.field_type())
                .map_err(|error| in_field(name, error.into()))?;
            (PASSTHROUGH_KEY, value)
        };
        let payload: Box<dyn Any + Send> = Box::new(value);
        row.push((
            name.to_owned(),
            CipherText::Map(vec![(key.to_owned(), CipherText::Passthrough(payload))]),
        ));
    }
    Ok(CipherText::Map(row))
}

/// An engine error as `EngineError`, message only. The engine's messages
/// carry no plaintext by their own rule, so `Display` is safe to forward.
fn engine(error: impl std::fmt::Display) -> PyErr {
    EngineError::new_err(error.to_string())
}

/// A shell refusal with the field named in front.
fn in_field(field: &str, error: PyErr) -> PyErr {
    Python::attach(|py| EngineError::new_err(format!("{field}: {}", error.value(py))))
}
