//! Every failure the addon reports, as the object JavaScript receives.
//!
//! A failure is a [`RecipherErrorFields`]: an [`ErrorKind`] a caller switches
//! on, a stable code, a message, and the engine's `reason` and `field` where
//! it gives them. An engine error is mapped here, once, by its variant. The
//! engine's errors never hold a plaintext, a key, a token or a ciphertext,
//! and nothing here adds one.

use miette::Diagnostic;
use napi_derive::napi;
use stack_encrypt::ErrorPayload;

/// The closed set of things that can go wrong, for a caller to switch on.
#[napi(string_enum = "snake_case")]
#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A declaration the engine refused.
    Declaration,
    /// A value the SDK or the engine refused: a type it does not encrypt,
    /// or a value outside what its type holds.
    Value,
    /// No credentials, or credentials that were refused.
    Credential,
    /// ZeroKMS refused a request, or could not be reached.
    Zerokms,
    /// A value sealed under another keyset than the one asked to open it.
    ForeignKeyset,
    /// A value opened under another context than the one it was sealed
    /// under, found before any key was requested.
    ContextMismatch,
    /// A ciphertext that did not open: damaged, altered, not a ciphertext,
    /// or holding a value of another type than the one asked for.
    Open,
    /// The call was cancelled before it finished.
    Cancelled,
    /// A failure that is not the caller's to fix: the native build did not
    /// load, or the engine or the addon did something the SDK does not
    /// expect.
    Internal,
}

/// A failure, as JavaScript receives it.
#[napi(object)]
#[derive(Debug, PartialEq, Eq)]
pub struct RecipherErrorFields {
    /// What kind of failure it is.
    pub kind: ErrorKind,
    /// Stable: the engine's diagnostic code, such as `stack_encrypt::aead`,
    /// vitaminc's code for a value it refused, such as `ERR_INTEGER_RANGE`,
    /// or the SDK's own, such as `recipher::not_a_ciphertext`.
    pub code: String,
    /// What went wrong, with the engine's help after it where it gives one.
    pub message: String,
    /// The engine's reason token, such as `no_fields`, where it gives one.
    pub reason: Option<String>,
    /// The field at fault, where one is known.
    pub field: Option<String>,
}

impl RecipherErrorFields {
    /// A failure of the SDK's own, with no reason or field.
    pub(crate) fn new(kind: ErrorKind, code: &str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.to_owned(),
            message: message.into(),
            reason: None,
            field: None,
        }
    }

    /// The failure for an engine error, of the kind its variant names.
    pub(crate) fn engine(error: &stack_encrypt::Error) -> Self {
        Self::diagnostic(kind_of(error), error, Some(error.payload()))
    }

    /// The failure for a diagnostic of `kind`, with the structured fields of
    /// `payload` where there is one.
    pub(crate) fn diagnostic(
        kind: ErrorKind,
        error: &dyn Diagnostic,
        payload: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Self {
        let text = error.to_string();
        let message = match error.help() {
            Some(help) if text.ends_with(['.', '!', '?']) => format!("{text} {help}"),
            Some(help) => format!("{text}. {help}"),
            None => text,
        };
        let text_of = |key: &str| {
            payload
                .as_ref()
                .and_then(|payload| payload.get(key))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Self {
            kind,
            code: error
                .code()
                .map_or_else(|| "recipher::unknown".to_owned(), |code| code.to_string()),
            message,
            reason: text_of("reason"),
            field: text_of("field"),
        }
    }

    /// An `internal` failure: something the SDK does not expect happened.
    pub(crate) fn internal(code: &str, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, code, message)
    }
}

/// The kind of an engine error.
fn kind_of(error: &stack_encrypt::Error) -> ErrorKind {
    use stack_encrypt::Error;
    match error {
        Error::Kms(stack_encrypt::kms::Error::Auth(_)) | Error::Config(_) => ErrorKind::Credential,
        Error::Kms(_) | Error::KeysetLoad { .. } | Error::NoKeyset => ErrorKind::Zerokms,
        Error::Aead | Error::OpenedType { .. } => ErrorKind::Open,
        Error::ForeignKeyset { .. } => ErrorKind::ForeignKeyset,
        Error::ContextMismatch { .. } => ErrorKind::ContextMismatch,
        Error::Input(_) | Error::Blob(_) | Error::Term(_) => ErrorKind::Value,
        Error::Plan(_) => ErrorKind::Declaration,
        // A decrypt target that did not open a field it declares, a
        // destination that takes no such output, and two pendings confined
        // to different keysets are each a fault in the code that drove the
        // engine (here, this addon), never in the caller's ciphertext.
        Error::NotOpened | Error::UnsupportedShape | Error::KeysetMismatch { .. } => {
            ErrorKind::Internal
        }
        _ => ErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorKind, RecipherErrorFields};

    #[test]
    fn an_aead_failure_is_an_open_failure_with_the_engine_code() {
        let error = RecipherErrorFields::engine(&stack_encrypt::Error::Aead);
        assert_eq!(error.kind, ErrorKind::Open);
        assert_eq!(error.code, "stack_encrypt::aead");
        // The engine's message, then its help as a sentence of its own.
        assert!(error.message.starts_with("AEAD operation failed"));
        assert!(error.message.contains(". Open the value under the context"));
    }

    #[test]
    fn a_fault_in_driving_the_engine_is_internal() {
        for error in [
            stack_encrypt::Error::NotOpened,
            stack_encrypt::Error::UnsupportedShape,
        ] {
            assert_eq!(
                RecipherErrorFields::engine(&error).kind,
                ErrorKind::Internal
            );
        }
    }
}
