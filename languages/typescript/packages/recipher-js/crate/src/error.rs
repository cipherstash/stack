//! Every failure the addon reports, in the form of the object JavaScript
//! receives.
//!
//! Each error is a miette diagnostic: an error with a code, a message and
//! optional help. An error comes from one of three places:
//!
//! - the engine: the Stack Encrypt engine, the `stack-encrypt` crate;
//! - the value bridge, the `recipher-value-napi` crate that converts
//!   JavaScript values, as a [`Refusal`](recipher_value_napi::Refusal);
//! - the SDK itself, as an [`Error`].
//!
//! [`RecipherErrorFields::diagnostic`] turns any of them into a
//! [`RecipherErrorFields`]. That object has the error's code, message,
//! help, documentation URL, severity, structured fields and causes. No
//! error here contains a plaintext, a key, a token or a ciphertext.
//!
//! A cause is an error that led to another error. For a cause that is one
//! of the engine's own diagnostics, the failure includes its code and
//! message. A cause from another library is reported as
//! [`UNDESCRIBED_CAUSE`] and nothing else. Its message is text that the
//! engine does not control, so the addon never copies it.

use std::error::Error as StdError;

use miette::Diagnostic;
use napi_derive::napi;
use stack_encrypt::ErrorPayload;

/// The SDK's own errors. They cover what the addon refuses before the
/// engine reads it, and what goes wrong between the engine and JavaScript.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub(crate) enum Error {
    /// A value outside the engine's value model, or a value that Node-API
    /// failed to read.
    #[error("the value cannot be encrypted: it is not one the engine reads")]
    #[diagnostic(code(recipher::value))]
    Value,
    /// A getter in the application threw while the addon read the value.
    #[error(
        "reading the value threw. The thrown error is not kept, because its message may hold the value"
    )]
    #[diagnostic(code(recipher::threw))]
    Threw,
    /// A value other than a string, given to `encrypt`.
    #[error("this build encrypts a string only")]
    #[diagnostic(code(recipher::not_a_string))]
    NotAString,
    /// `decrypt` given something that is not a `Ciphertext`.
    #[error("decrypt takes a Ciphertext")]
    #[diagnostic(
        code(recipher::not_a_ciphertext),
        help("Read stored bytes with Ciphertext.fromBytes.")
    )]
    NotACiphertext,
    /// `Ciphertext.fromBytes` given something that is not bytes.
    #[error("a ciphertext is read from a Uint8Array")]
    #[diagnostic(code(recipher::not_bytes))]
    NotBytes,
    /// A test cipher's seed that is not 32 bytes.
    #[error("a test cipher's seed is a Uint8Array of 32 bytes")]
    #[diagnostic(code(recipher::testing_seed))]
    TestingSeed,
    /// `createTesting`, called in a build without the test cipher.
    // A build with the test cipher never returns this error.
    #[cfg_attr(feature = "testing", allow(dead_code))]
    #[error("this native build has no test cipher")]
    #[diagnostic(
        code(recipher::no_testing),
        help("Build it with `pnpm --filter @cipherstash/recipher build:debug`.")
    )]
    NoTesting,
    /// A call whose engine work returned no result.
    #[error("the engine returned no result")]
    #[diagnostic(
        code(recipher::outcome),
        help("Report this as a bug in @cipherstash/recipher.")
    )]
    NoResult,
    /// A result that could not be made into a JavaScript value.
    #[error("the result could not be given to JavaScript")]
    #[diagnostic(
        code(recipher::build_value),
        help("Report this as a bug in @cipherstash/recipher.")
    )]
    BuildValue,
}

/// How serious a failure is, as the diagnostic states it.
#[napi(string_enum = "snake_case")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A failure: the call did not do what was asked.
    Error,
    /// Something a caller should look at.
    Warning,
    /// A suggestion.
    Advice,
}

impl From<miette::Severity> for Severity {
    fn from(severity: miette::Severity) -> Self {
        match severity {
            miette::Severity::Error => Self::Error,
            miette::Severity::Warning => Self::Warning,
            miette::Severity::Advice => Self::Advice,
        }
    }
}

/// A failure, as JavaScript receives it.
#[napi(object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipherErrorFields {
    /// The error's code. A code is stable, so a caller can match on it.
    /// The code is one of three kinds:
    ///
    /// - a diagnostic's code, such as the engine's `stack_encrypt::aead`;
    /// - the code of vitaminc, CipherStash's cryptography library, for a
    ///   value it refused, such as `ERR_INTEGER_RANGE`;
    /// - the SDK's own code, such as `recipher::not_a_ciphertext`.
    pub code: String,
    /// What went wrong, in one line.
    pub message: String,
    /// What to do about the error, when the error says.
    pub help: Option<String>,
    /// A documentation page for the error, when it has one.
    pub url: Option<String>,
    /// How serious the failure is. The severity is `error` unless the
    /// diagnostic states another one.
    pub severity: Severity,
    /// The error's structured fields, keyed by `snake_case` name. For
    /// example, a ZeroKMS failure has `request_kind`. The map is empty when
    /// the error has no fields.
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// The errors that caused this one, outermost first.
    pub causes: Vec<ErrorCause>,
    /// The field at fault, when it is known.
    pub field: Option<String>,
    /// The record at fault, when it is known. The fault is in the record's
    /// declaration, in a row of it, or in a stored row of it.
    pub record: Option<String>,
}

/// One error in a failure's cause chain.
#[napi(object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorCause {
    /// The cause's code, when the cause is one of the engine's own errors.
    pub code: Option<String>,
    /// The message of the engine's error. For an error from another
    /// library, the message is this fixed text:
    /// `an error from another library`.
    pub message: String,
}

/// The message reported for a cause from another library.
pub const UNDESCRIBED_CAUSE: &str = "an error from another library";

/// The most causes the addon reads from a cause chain. A chain this long
/// is a loop or a bug. The limit means a looping chain cannot make the walk
/// run forever.
const MAX_CAUSES: usize = 16;

/// One cause in a cause chain.
enum Cause<'a> {
    /// One of the engine's errors, found as a diagnostic source.
    Ours(&'a dyn Diagnostic),
    /// Any error found as a plain source.
    Foreign(&'a (dyn StdError + 'static)),
}

/// Returns the cause of a diagnostic: its diagnostic source if it has one,
/// or else its plain source.
fn next_of(diagnostic: &dyn Diagnostic) -> Option<Cause<'_>> {
    diagnostic
        .diagnostic_source()
        .map(Cause::Ours)
        .or_else(|| diagnostic.source().map(Cause::Foreign))
}

/// Returns the error's causes, in order. After the first cause that is not
/// a diagnostic, the walk follows only plain sources, to the end of the
/// chain.
fn causes_of(error: &dyn Diagnostic) -> Vec<ErrorCause> {
    let mut out = Vec::new();
    let mut next = next_of(error);
    while let Some(cause) = next {
        if out.len() == MAX_CAUSES {
            break;
        }
        next = match cause {
            Cause::Ours(diagnostic) => {
                out.push(ErrorCause {
                    code: diagnostic.code().map(|code| code.to_string()),
                    message: diagnostic.to_string(),
                });
                next_of(diagnostic)
            }
            Cause::Foreign(foreign) => {
                out.push(ErrorCause {
                    code: None,
                    message: UNDESCRIBED_CAUSE.to_owned(),
                });
                foreign.source().map(Cause::Foreign)
            }
        };
    }
    out
}

impl RecipherErrorFields {
    /// Returns the failure for any diagnostic. The structured fields come
    /// from `payload`, when there is one. The failure's `field` is the
    /// payload's `field`, when the payload has one.
    pub(crate) fn diagnostic(
        error: &dyn Diagnostic,
        payload: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Self {
        let fields = payload.unwrap_or_default();
        Self {
            // Every error the addon reports has a code, so JavaScript never
            // receives this fallback.
            code: error
                .code()
                .map_or_else(|| "recipher::unknown".to_owned(), |code| code.to_string()),
            message: error.to_string(),
            help: error.help().map(|help| help.to_string()),
            url: error.url().map(|url| url.to_string()),
            severity: error.severity().map_or(Severity::Error, Severity::from),
            field: fields
                .get("field")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            causes: causes_of(error),
            fields,
            record: None,
        }
    }

    /// Returns the failure for an engine error, with its structured fields.
    pub(crate) fn engine<E: ErrorPayload>(error: &E) -> Self {
        Self::diagnostic(error, Some(error.payload()))
    }
}

impl From<Error> for RecipherErrorFields {
    fn from(error: Error) -> Self {
        Self::diagnostic(&error, None)
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorCause, RecipherErrorFields, Severity, UNDESCRIBED_CAUSE};

    #[test]
    fn an_aead_failure_keeps_the_engine_code_message_and_help() {
        let error = RecipherErrorFields::engine(&stack_encrypt::Error::Aead);
        assert_eq!(error.code, "stack_encrypt::aead");
        // The message is the engine's one-line message. The help is a
        // separate field, and is never appended to the message.
        assert_eq!(error.message, stack_encrypt::Error::Aead.to_string());
        assert!(error
            .help
            .as_deref()
            .is_some_and(|help| help.starts_with("Open the value under the context")));
        assert_eq!(error.url, None);
        // A diagnostic that states no severity is an error.
        assert_eq!(error.severity, Severity::Error);
        assert!(error.causes.is_empty());
    }

    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    #[error("inner")]
    #[diagnostic(code(probe::inner))]
    struct Inner(#[source] std::io::Error);

    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    #[error("outer")]
    #[diagnostic(
        code(probe::outer),
        help("try again"),
        url("https://example.com/outer"),
        severity(Warning)
    )]
    struct Outer(
        #[source]
        #[diagnostic_source]
        Inner,
    );

    #[test]
    fn a_diagnostic_keeps_its_help_url_fields_and_causes() {
        let secret = "library text that may quote a value";
        let outer = Outer(Inner(std::io::Error::other(secret)));
        let payload = [
            ("field".to_owned(), "age".into()),
            ("count".to_owned(), 3.into()),
        ]
        .into_iter()
        .collect();
        let error = RecipherErrorFields::diagnostic(&outer, Some(payload));
        assert_eq!(error.code, "probe::outer");
        assert_eq!(error.message, "outer");
        assert_eq!(error.help.as_deref(), Some("try again"));
        assert_eq!(error.url.as_deref(), Some("https://example.com/outer"));
        assert_eq!(error.severity, Severity::Warning);
        // Every payload field reaches the failure, and the payload's
        // `field` also sets the typed `field`.
        assert_eq!(error.fields["count"], 3);
        assert_eq!(error.field.as_deref(), Some("age"));
        // The engine's own cause keeps its code. The other library's cause
        // is reported as one from another library, and its message is not
        // copied.
        assert_eq!(
            error.causes,
            [
                ErrorCause {
                    code: Some("probe::inner".to_owned()),
                    message: "inner".to_owned(),
                },
                ErrorCause {
                    code: None,
                    message: UNDESCRIBED_CAUSE.to_owned(),
                },
            ]
        );
        assert!(!format!("{error:?}").contains(secret));
    }

    #[test]
    fn an_error_of_the_sdks_own_has_its_code_message_and_help() {
        let error = RecipherErrorFields::from(Error::NotACiphertext);
        assert_eq!(error.code, "recipher::not_a_ciphertext");
        assert_eq!(error.message, "decrypt takes a Ciphertext");
        assert_eq!(
            error.help.as_deref(),
            Some("Read stored bytes with Ciphertext.fromBytes.")
        );
        assert_eq!(error.severity, Severity::Error);
        assert!(error.fields.is_empty() && error.causes.is_empty());
    }

    /// Returns one of each variant of [`Error`]. The match has no wildcard,
    /// so the crate does not compile when a new variant has no entry here.
    fn every_error() -> Vec<Error> {
        let all = vec![
            Error::Value,
            Error::Threw,
            Error::NotAString,
            Error::NotACiphertext,
            Error::NotBytes,
            Error::TestingSeed,
            Error::NoTesting,
            Error::NoResult,
            Error::BuildValue,
        ];
        for error in &all {
            match error {
                Error::Value
                | Error::Threw
                | Error::NotAString
                | Error::NotACiphertext
                | Error::NotBytes
                | Error::TestingSeed
                | Error::NoTesting
                | Error::NoResult
                | Error::BuildValue => {}
            }
        }
        all
    }

    #[test]
    fn every_error_has_a_recipher_code_of_its_own() {
        let mut codes = std::collections::BTreeSet::new();
        for error in every_error() {
            let code = RecipherErrorFields::from(error).code;
            assert!(
                stack_encrypt::diagnostic::is_code_of("recipher", &code),
                "{code} is not `recipher::` and a snake_case name"
            );
            assert!(codes.insert(code.clone()), "{code} is used twice");
        }
    }
}
