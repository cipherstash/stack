//! A refusal as the Python exception the SDK defines for it.
//!
//! The exception classes live in `stackencrypt._errors`, in Python, so that
//! the pure-Python checks and the extension raise the same ones. The class
//! is chosen by the code's prefix, as the spec's "Errors" section assigns
//! them: `value_*` is `InvalidValueError`, `stack_auth_*` is
//! `AuthenticationError`, and anything else is the base `StashError`.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use stackencrypt_core::refusal::Refusal;

/// The exception for `refused`, ready to raise.
pub fn raise(py: Python<'_>, refused: Refusal) -> PyErr {
    match exception(py, &refused) {
        Ok(error) => error,
        // The SDK's own module failed to import or to build the exception.
        // Nothing to do but say so, with the refusal in the message.
        Err(error) => PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
            "stackencrypt could not raise {}: {} ({error})",
            refused.code, refused.message
        )),
    }
}

fn exception(py: Python<'_>, refused: &Refusal) -> PyResult<PyErr> {
    let class = if refused.code.starts_with("value_") {
        "InvalidValueError"
    } else if refused.code.starts_with("stack_auth_") {
        "AuthenticationError"
    } else {
        "StashError"
    };
    let errors = py.import("stackencrypt._errors")?;
    let class = errors.getattr(class)?;
    let args = PyTuple::new(py, [&refused.code, &refused.message])?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("field", refused.field.as_deref())?;
    kwargs.set_item("reason", refused.reason.as_deref())?;
    let instance = class.call(args, Some(&kwargs))?;
    Ok(PyErr::from_value(instance))
}
