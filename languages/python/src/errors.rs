//! Engine and shell failures as Python exceptions.
//!
//! **No plaintext reaches a message here.** A refusal names the declared
//! kind, the kind that arrived, and the Python type — never the value. That
//! is a repo-wide rule, and a width refusal is exactly where it is tempting
//! to break it ("34 does not fit int32" reads well and leaks the value).

use pyo3::create_exception;
use pyo3::exceptions::PyException;

create_exception!(_engine, StackEncryptError, PyException);
create_exception!(_engine, DeclarationError, StackEncryptError);
create_exception!(_engine, PlanError, StackEncryptError);
create_exception!(_engine, EngineError, StackEncryptError);

/// A conversion failure, raised before any key is minted.
#[derive(Debug)]
pub enum ConvertError {
    /// A value of another kind than the field declares.
    Kind { declared: &'static str, got: String },
    /// An integer outside the declared kind's range. Kept distinct from
    /// `Kind` because the remedy differs: a wider declared type, not a
    /// different value.
    Range { declared: &'static str },
    /// A kind name no `ValueKind` has. A declaration defect, so it raises
    /// `PlanError` rather than `EngineError`.
    UnknownKind { name: String },
    /// A Python type the codec has no encoding for.
    Unsupported { got: String },
    /// An `FfiValue` variant with no Python counterpart. Reachable only on
    /// the way back out, and only for a kind this shell does not yet
    /// produce.
    NoPythonMapping { got: String },
}

impl From<ConvertError> for pyo3::PyErr {
    fn from(error: ConvertError) -> Self {
        match error {
            ConvertError::Kind { declared, got } => EngineError::new_err(format!(
                "field declares {declared}, got a value of kind {got}"
            )),
            ConvertError::Range { declared } => {
                EngineError::new_err(format!("integer out of range for {declared}"))
            }
            ConvertError::UnknownKind { name } => PlanError::new_err(format!(
                "no value kind named {name}: the names are vitaminc's \
                 (bool, int32, int64, uint32, uint64, float32, float64, \
                 string, bytes, array, object)"
            )),
            ConvertError::Unsupported { got } => {
                EngineError::new_err(format!("no encoding for Python type {got}"))
            }
            ConvertError::NoPythonMapping { got } => {
                EngineError::new_err(format!("no Python mapping for value kind {got}"))
            }
        }
    }
}
