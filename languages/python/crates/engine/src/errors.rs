//! A refusal as the Python exception the SDK defines for it.
//!
//! The exception classes live in `stackencrypt._errors`, in Python, so that
//! the pure-Python checks and the extension raise the same ones. The class
//! is chosen by the code's prefix, as the spec's "Errors" section assigns
//! them: `value_*` is `InvalidValueError`, `decrypt_*` is `DecryptError`, `query_*` is `QueryError`,
//! `stack_auth_*` and the engine's context and keyset refusals are
//! `AuthenticationError`, and anything else is the base `StashError`.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use stackencrypt_core::refusal::Refusal;

/// The engine codes the spec's "Errors" puts under `AuthenticationError`
/// besides `stack_auth_*`: a context the value was not sealed under, and a
/// value from a keyset this call does not open.
const AUTHENTICATION: [&str; 2] = [
    "stack_encrypt_context_mismatch",
    "stack_encrypt_foreign_keyset",
];

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
    } else if refused.code.starts_with("decrypt_") {
        "DecryptError"
    } else if refused.code.starts_with("query_") {
        "QueryError"
    } else if refused.code.starts_with("stack_auth_")
        || AUTHENTICATION.contains(&refused.code.as_str())
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The class `raise` picks for `code`, by name.
    fn class_of(code: &str) -> String {
        Python::initialize();
        Python::attach(|py| {
            // `stackencrypt._errors` from the source tree. The package is
            // registered empty, so its `__init__`, which imports this
            // extension, does not run.
            let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../python/stackencrypt");
            let package = pyo3::types::PyModule::new(py, "stackencrypt").unwrap();
            package.setattr("__path__", vec![dir]).unwrap();
            py.import("sys")
                .unwrap()
                .getattr("modules")
                .unwrap()
                .set_item("stackencrypt", package)
                .unwrap();
            let refused = Refusal {
                code: code.to_owned(),
                message: "a message".to_owned(),
                field: None,
                reason: None,
            };
            raise(py, refused).get_type(py).name().unwrap().to_string()
        })
    }

    #[test]
    fn a_context_or_keyset_refusal_is_an_authentication_error() {
        assert_eq!(
            class_of("stack_encrypt_foreign_keyset"),
            "AuthenticationError"
        );
        assert_eq!(
            class_of("stack_encrypt_context_mismatch"),
            "AuthenticationError"
        );
        assert_eq!(
            class_of("stack_auth_not_authenticated"),
            "AuthenticationError"
        );
    }

    #[test]
    fn each_prefix_has_its_class() {
        assert_eq!(class_of("value_none"), "InvalidValueError");
        assert_eq!(class_of("decrypt_malformed"), "DecryptError");
        assert_eq!(class_of("query_unsupported"), "QueryError");
        assert_eq!(class_of("stack_encrypt_aead"), "StashError");
    }
}
