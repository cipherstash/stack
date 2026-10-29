//! An engine error, in the four fields every SDK error has.

use miette::Diagnostic;

/// An engine error as the Python side raises it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The engine's diagnostic code, with `::` replaced by `_`:
    /// `stack_encrypt_dynamic_plan`.
    pub code: String,
    /// The engine's message, with its help after it where it gives one.
    pub message: String,
    /// The plan field at fault, where the engine names one.
    pub field: Option<String>,
    /// The engine's reason token, such as `no_fields`, where it gives one.
    pub reason: Option<String>,
}

impl Refusal {
    /// The code and message of `error`, with no field or reason.
    pub fn of(error: &dyn Diagnostic) -> Self {
        let message = match error.help() {
            Some(help) => format!("{error} {help}"),
            None => error.to_string(),
        };
        Self {
            code: error.code().map_or_else(
                || "stack_unknown".to_owned(),
                |code| python_code(&code.to_string()),
            ),
            message,
            field: None,
            reason: None,
        }
    }
}

/// An engine diagnostic code as the SDK's `code`: `stack_encrypt::aead`
/// becomes `stack_encrypt_aead`.
pub fn python_code(engine_code: &str) -> String {
    engine_code.replace("::", "_")
}

#[cfg(test)]
mod tests {
    use super::python_code;

    #[test]
    fn engine_codes_replace_the_path_separator() {
        assert_eq!(python_code("stack_encrypt::aead"), "stack_encrypt_aead");
        assert_eq!(
            python_code("stack_kms::load_keyset_forbidden"),
            "stack_kms_load_keyset_forbidden"
        );
    }
}
