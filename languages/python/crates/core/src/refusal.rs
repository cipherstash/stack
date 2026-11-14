//! An engine error, in the four fields every SDK error has.

use miette::Diagnostic;

/// An engine error as the Python side raises it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The engine's diagnostic code, with `::` replaced by `_`:
    /// `stack_encrypt_dynamic_plan`.
    pub code: String,
    /// The engine's message, with its help after it where it gives one. A
    /// caller whose engine help names a Rust API writes its own message.
    pub message: String,
    /// The plan field at fault, where the engine names one.
    pub field: Option<String>,
    /// The engine's reason token, such as `no_fields`, where it gives one.
    pub reason: Option<String>,
}

impl Refusal {
    /// The code and message of `error`, with no field or reason. The
    /// engine's help follows the message as a sentence of its own: most
    /// engine messages end with no full stop.
    pub fn of(error: &dyn Diagnostic) -> Self {
        let text = error.to_string();
        let message = match error.help() {
            Some(help) if text.ends_with(['.', '!', '?']) => format!("{text} {help}"),
            Some(help) => format!("{text}. {help}"),
            None => text,
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
    use super::{python_code, Refusal};

    /// An engine error with a message and a help, written by hand: this
    /// crate has no derive for errors.
    #[derive(Debug)]
    struct WithHelp {
        message: &'static str,
    }

    impl std::fmt::Display for WithHelp {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.message)
        }
    }

    impl std::error::Error for WithHelp {}

    impl miette::Diagnostic for WithHelp {
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            Some(Box::new("stack_test::joined"))
        }

        fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            Some(Box::new("Do this."))
        }
    }

    #[test]
    fn the_message_and_its_help_are_two_sentences() {
        let joined = Refusal::of(&WithHelp {
            message: "the plan has no field",
        });
        assert_eq!(joined.message, "the plan has no field. Do this.");
        let ended = Refusal::of(&WithHelp {
            message: "the plan has no field.",
        });
        assert_eq!(ended.message, "the plan has no field. Do this.");
    }

    #[test]
    fn engine_codes_replace_the_path_separator() {
        assert_eq!(python_code("stack_encrypt::aead"), "stack_encrypt_aead");
        assert_eq!(
            python_code("stack_kms::load_keyset_forbidden"),
            "stack_kms_load_keyset_forbidden"
        );
    }
}
