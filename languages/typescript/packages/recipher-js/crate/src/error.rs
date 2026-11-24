//! Every failure the addon reports, as the object JavaScript receives.
//!
//! A failure is a [`RecipherErrorFields`]: an [`ErrorKind`] a caller switches
//! on, and the engine's diagnostic as it stands: its stable code, message,
//! help, documentation URL, severity, structured fields and causes. An engine error is
//! mapped here, once, by its variant. The engine's errors never hold a
//! plaintext, a key, a token or a ciphertext, and nothing here adds one.
//!
//! A cause that is one of the engine's own diagnostics gives its code and
//! message. A cause from another library gives [`UNDESCRIBED_CAUSE`] and
//! nothing else: its message is text the engine does not vouch for, and is
//! never copied.

use std::error::Error;

use miette::Diagnostic;
use napi_derive::napi;
use stack_encrypt::ErrorPayload;

/// The closed set of things that can go wrong, for a caller to switch on.
#[napi(string_enum = "snake_case")]
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// How serious a failure is, as the engine's diagnostic states it.
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
    /// What kind of failure it is.
    pub kind: ErrorKind,
    /// Stable: the engine's diagnostic code, such as `stack_encrypt::aead`,
    /// vitaminc's code for a value it refused, such as `ERR_INTEGER_RANGE`,
    /// or the SDK's own, such as `recipher::not_a_ciphertext`.
    pub code: String,
    /// What went wrong, in one line.
    pub message: String,
    /// What to do about it, where the error knows.
    pub help: Option<String>,
    /// A documentation page for the error, where it has one.
    pub url: Option<String>,
    /// How serious it is: `error` unless the engine's diagnostic says
    /// otherwise.
    pub severity: Severity,
    /// The error's structured fields, by `snake_case` name: a refused
    /// plan's `field` and `reason`, a ZeroKMS failure's `request_kind`.
    /// Empty where the error has none.
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// The errors behind this one, outermost first.
    pub causes: Vec<ErrorCause>,
    /// The engine's reason token, such as `no_fields`, where it gives one.
    pub reason: Option<String>,
    /// The field at fault, where one is known.
    pub field: Option<String>,
    /// The record at fault, where one is known: a declaration, a row or a
    /// stored row of it.
    pub record: Option<String>,
}

/// One error in a failure's cause chain.
#[napi(object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorCause {
    /// The cause's code, where it is one of the engine's own errors.
    pub code: Option<String>,
    /// The engine error's message. For an error from another library, the
    /// fixed text `an error from another library`.
    pub message: String,
}

/// What a cause from another library is reported as.
pub const UNDESCRIBED_CAUSE: &str = "an error from another library";

/// How deep the cause chain is followed. A chain this long is a loop or a
/// bug, and a bounded walk cannot be made to spin.
const MAX_CAUSES: usize = 16;

/// One link of a cause chain.
enum Cause<'a> {
    /// One of the engine's errors, reached as a diagnostic source.
    Ours(&'a dyn Diagnostic),
    /// Anything reached as a plain source.
    Foreign(&'a (dyn Error + 'static)),
}

/// The cause after a diagnostic: its diagnostic source, or else its plain
/// source.
fn next_of(diagnostic: &dyn Diagnostic) -> Option<Cause<'_>> {
    diagnostic
        .diagnostic_source()
        .map(Cause::Ours)
        .or_else(|| diagnostic.source().map(Cause::Foreign))
}

/// The error's causes, in order. Once the chain leaves the diagnostics it
/// follows plain sources to the end.
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
    /// A failure of the SDK's own, with no help, fields or causes.
    pub(crate) fn new(kind: ErrorKind, code: &str, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.to_owned(),
            message: message.into(),
            help: None,
            url: None,
            severity: Severity::Error,
            fields: serde_json::Map::new(),
            causes: Vec::new(),
            reason: None,
            field: None,
            record: None,
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
        let fields = payload.unwrap_or_default();
        let text_of = |key: &str| {
            fields
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Self {
            kind,
            code: error
                .code()
                .map_or_else(|| "recipher::unknown".to_owned(), |code| code.to_string()),
            message: error.to_string(),
            help: error.help().map(|help| help.to_string()),
            url: error.url().map(|url| url.to_string()),
            severity: error.severity().map_or(Severity::Error, Severity::from),
            reason: text_of("reason"),
            field: text_of("field"),
            causes: causes_of(error),
            fields,
            record: None,
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
    use super::{ErrorCause, ErrorKind, RecipherErrorFields, Severity, UNDESCRIBED_CAUSE};

    #[test]
    fn an_aead_failure_is_an_open_failure_with_the_engine_code() {
        let error = RecipherErrorFields::engine(&stack_encrypt::Error::Aead);
        assert_eq!(error.kind, ErrorKind::Open);
        assert_eq!(error.code, "stack_encrypt::aead");
        // The message is the engine's one line. Its help is a field of
        // its own, never appended.
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
        let error = RecipherErrorFields::diagnostic(ErrorKind::Value, &outer, Some(payload));
        assert_eq!(error.code, "probe::outer");
        assert_eq!(error.message, "outer");
        assert_eq!(error.help.as_deref(), Some("try again"));
        assert_eq!(error.url.as_deref(), Some("https://example.com/outer"));
        assert_eq!(error.severity, Severity::Warning);
        // Every payload field crosses, and `field` is also the typed one.
        assert_eq!(error.fields["count"], 3);
        assert_eq!(error.field.as_deref(), Some("age"));
        // The engine's own cause keeps its code. The other library's is
        // named as one and its message is not copied.
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

    /// Every code the SDK gives an error of its own, in order. A caller
    /// branches on a code and a documentation page is written for each, so
    /// a new one is added here by hand.
    const SDK_CODES: &[&str] = &[
        "recipher::binding_interface",
        "recipher::build_value",
        "recipher::changed_while_read",
        "recipher::context",
        "recipher::declaration",
        "recipher::engine_result",
        "recipher::field_type",
        "recipher::index",
        "recipher::kind",
        "recipher::load",
        "recipher::no_field",
        "recipher::no_testing",
        "recipher::not_a_ciphertext",
        "recipher::not_a_document",
        "recipher::not_a_kind",
        "recipher::not_a_record",
        "recipher::not_a_row",
        "recipher::not_a_scalar",
        "recipher::not_a_stored_row",
        "recipher::not_a_value",
        "recipher::not_bytes",
        "recipher::not_json",
        "recipher::not_plain",
        "recipher::not_sealed",
        "recipher::null",
        "recipher::opened_type",
        "recipher::outcome",
        "recipher::plain_object",
        "recipher::reserved_field",
        "recipher::reserved_key",
        "recipher::sparse_array",
        "recipher::testing_seed",
        "recipher::threw",
        "recipher::too_deep",
        "recipher::undefined",
        "recipher::unknown",
        "recipher::unpaired_surrogate",
        "recipher::uuid",
        "recipher::value",
    ];

    /// The `recipher::` codes written in the files of `dir`, as string
    /// literals in either quote.
    fn codes_written_in(dir: &std::path::Path, found: &mut std::collections::BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                codes_written_in(&path, found);
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for quote in ['"', '\''] {
                let start = format!("{quote}recipher::");
                for (at, _) in text.match_indices(&start) {
                    let literal = &text[at + 1..];
                    let end = literal.find(quote).unwrap();
                    let _ = found.insert(literal[..end].to_owned());
                }
            }
        }
    }

    #[test]
    fn every_sdk_code_is_well_formed_and_listed() {
        let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut found = std::collections::BTreeSet::new();
        codes_written_in(&package.join("crate/src"), &mut found);
        codes_written_in(&package.join("src"), &mut found);
        for code in &found {
            assert!(
                stack_encrypt::diagnostic::is_code_of("recipher", code),
                "{code} is not `recipher::` and a snake_case name"
            );
        }
        assert_eq!(
            found.iter().map(String::as_str).collect::<Vec<_>>(),
            SDK_CODES
        );
    }
}
