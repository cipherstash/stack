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
//! of CipherStash's own diagnostics, the failure includes its code and
//! message. A diagnostic is CipherStash's own when its code is in one of
//! [`OWN_CODES`]. Any other cause, a diagnostic of another library
//! included, is reported as [`UNDESCRIBED_CAUSE`] and nothing else. Its
//! message is text that CipherStash does not control, so the addon never
//! copies it.

use std::error::Error as StdError;

use miette::Diagnostic;
use napi_derive::napi;
use stack_encrypt::dynamic::ValueKind;
use stack_encrypt::ErrorPayload;

/// The SDK's own errors. They cover what the addon refuses before the
/// engine reads it, and what goes wrong between the engine and JavaScript.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub(crate) enum Error {
    /// `undefined` given as a value.
    #[error("`undefined` cannot be encrypted")]
    #[diagnostic(
        code(recipher_js::undefined),
        help("Use `null` for a value that is not there.")
    )]
    Undefined,
    /// An `RcUuid`. The engine accepts a UUID, but this version of the SDK
    /// has no kind and no TypeScript type for one, so it refuses an `RcUuid`.
    #[error("this version of the SDK does not encrypt a UUID yet")]
    #[diagnostic(code(recipher_js::uuid), help("Encrypt the UUID as a string instead."))]
    Uuid,
    /// A value outside the engine's value model, or a value that Node-API
    /// failed to read.
    #[error("the value cannot be encrypted: it is not one the engine reads")]
    #[diagnostic(code(recipher_js::value))]
    Value,
    /// A getter in the application threw while the addon read the value.
    #[error(
        "reading the value threw. The thrown error is not kept, because its message may hold the value"
    )]
    #[diagnostic(code(recipher_js::threw))]
    Threw,
    /// An array inside an array, given as one value.
    #[error("an array inside an array cannot be encrypted as one value")]
    #[diagnostic(
        code(recipher_js::not_a_scalar),
        help("To encrypt the inner array as a JSON document, wrap it in `json(..)`.")
    )]
    NotAScalar,
    /// An object given as one value.
    #[error("a plain object cannot be encrypted as one value")]
    #[diagnostic(
        code(recipher_js::plain_object),
        help("To encrypt the object as a JSON document, wrap it in `json(..)`.")
    )]
    PlainObject,
    /// The engine refused to encrypt a value in the form it was given.
    #[error("the engine could not encrypt the value in the form it was given")]
    #[diagnostic(code(recipher_js::not_sealed))]
    NotSealed,
    /// `decrypt` given something that is not a `Ciphertext`.
    #[error("decrypt accepts a Ciphertext, or an array of ciphertexts")]
    #[diagnostic(
        code(recipher_js::not_a_ciphertext),
        help("Read stored bytes with Ciphertext.fromBytes.")
    )]
    NotACiphertext,
    /// `Ciphertext.fromBytes` given something that is not bytes.
    #[error("a ciphertext is read from a Uint8Array")]
    #[diagnostic(code(recipher_js::not_bytes))]
    NotBytes,
    /// A kind that is not one of `kinds`.
    #[error("the kind is not one of `kinds`")]
    #[diagnostic(
        code(recipher_js::not_a_kind),
        help("Pass a kind that the package exports, such as `kinds.string`.")
    )]
    NotAKind,
    /// A ciphertext that decrypted to another kind than the one named.
    #[error("the value decrypted, but it was not encrypted as `{kind}`, the kind given for the ciphertext")]
    #[diagnostic(code(recipher_js::opened_type))]
    OpenedType { kind: ValueKind },
    /// A ciphertext named as JSON that decrypted to text that is not JSON.
    #[error("the value decrypted, but it is not a JSON document")]
    #[diagnostic(code(recipher_js::not_a_document))]
    NotADocument,
    /// A test cipher's seed that is not 32 bytes.
    #[error("a test cipher's seed is a Uint8Array of 32 bytes")]
    #[diagnostic(code(recipher_js::testing_seed))]
    TestingSeed,
    /// `createTesting`, called in a build without the test cipher.
    // A build with the test cipher never returns this error.
    #[cfg_attr(feature = "testing", allow(dead_code))]
    #[error("this native build has no test cipher")]
    #[diagnostic(
        code(recipher_js::no_testing),
        help("Build it with `pnpm --filter @cipherstash/recipher build:debug`.")
    )]
    NoTesting,
    /// A declaration that `record(..)` did not make.
    #[error("the value given as a record is not a record declaration")]
    #[diagnostic(
        code(recipher_js::not_a_record),
        help("Declare a record with `record(..)`.")
    )]
    NotARecord,
    /// A field declared with something other than `encrypt(..)` or
    /// `passthrough()`.
    #[error("the field is not declared with `encrypt(..)` or `passthrough()`")]
    #[diagnostic(code(recipher_js::declaration))]
    Declaration,
    /// A field whose name the engine reserves.
    #[error("the field's name is one that the engine reserves")]
    #[diagnostic(
        code(recipher_js::reserved_field),
        help("Give the field another name.")
    )]
    ReservedField,
    /// A field's kind that is not one of `kinds`.
    #[error("`{name}` is not one of `kinds`")]
    #[diagnostic(code(recipher_js::kind))]
    Kind { name: String },
    /// A field's index that is not one of the indexes the SDK names.
    #[error("`{name}` is not an index")]
    #[diagnostic(code(recipher_js::index))]
    Index { name: String },
    /// A field's null mode that the engine does not have. A null mode says
    /// how the engine stores a field's null.
    #[error("`{mode}` is not a null mode")]
    #[diagnostic(code(recipher_js::null), help("A null mode is `sealed` or `sql`."))]
    Null { mode: String },
    /// A field path that could not be written as a context.
    ///
    /// A context is a value that a ciphertext is bound to, and decrypting
    /// needs the same context. A field's context is its field path: the
    /// record's name, then the field's name.
    #[error("the record's name and the field's name could not be written as a field path")]
    #[diagnostic(code(recipher_js::context))]
    Context,
    /// A record name the engine refuses as a segment of a field path.
    #[error("the engine refuses the record name as the first part of a field path")]
    #[diagnostic(
        code(recipher_js::record_name),
        help("Use a record name that is not empty and contains no character that the engine refuses in a field path, such as `/`.")
    )]
    RecordName,
    /// A field name that the record does not encrypt. The record does not
    /// declare the name, the name is a passthrough field's, or the name is
    /// not a string. A passthrough field is stored as given, without
    /// encryption.
    #[error("the record declares no encrypted field of that name")]
    #[diagnostic(
        code(recipher_js::no_field),
        help("Name a field that the record declares with `encrypt(..)`. A passthrough field has no ciphertext.")
    )]
    NoField,
    /// A row that is not an object of the record's fields.
    #[error("the row is not an object with the record's fields")]
    #[diagnostic(code(recipher_js::not_a_row))]
    NotARow,
    /// A row's value that is not of its field's kind.
    #[error("the value is not of the field's kind, `{kind}`, or does not fit that kind")]
    #[diagnostic(code(recipher_js::field_type))]
    FieldType { kind: ValueKind },
    /// A stored row that does not have the record's shape. A stored row is
    /// what encrypting a row returns.
    #[error("the stored row does not have the record's shape: {what}")]
    #[diagnostic(code(recipher_js::not_a_stored_row))]
    NotAStoredRow { what: &'static str },
    /// A stored row from the engine that the SDK cannot read.
    #[error("the engine's stored row does not have the shape that the SDK reads: {what}")]
    #[diagnostic(
        code(recipher_js::engine_result),
        help("Report this as a bug in @cipherstash/recipher.")
    )]
    EngineResult { what: &'static str },
    /// A call whose engine work returned no result.
    #[error("the engine returned no result")]
    #[diagnostic(
        code(recipher_js::outcome),
        help("Report this as a bug in @cipherstash/recipher.")
    )]
    NoResult,
    /// A result that could not be made into a JavaScript value.
    #[error("the result could not be given to JavaScript")]
    #[diagnostic(
        code(recipher_js::build_value),
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
    /// - the value bridge's code for a scalar it refused, such as
    ///   `ERR_INTEGER_RANGE`;
    /// - the SDK's own code, such as `recipher_js::not_a_ciphertext`.
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
    /// example, a refused plan has `field` and `reason`. A ZeroKMS failure
    /// has `request_kind`. A plan is the engine's rules for encrypting a
    /// record. The map is empty when the error has no fields.
    #[napi(ts_type = "Record<string, unknown>")]
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

/// The code prefixes of CipherStash's own diagnostics: the engine's
/// crates and this SDK's. A cause whose code has another prefix is from
/// another library, and its message is not copied.
const OWN_CODES: [&str; 5] = [
    "stack_encrypt",
    "stack_kms",
    "stack_auth",
    "stack_profile",
    "recipher_js",
];

/// Whether `diagnostic` is one of CipherStash's own, by its code.
fn is_own(diagnostic: &dyn Diagnostic) -> bool {
    diagnostic.code().is_some_and(|code| {
        let code = code.to_string();
        OWN_CODES
            .iter()
            .any(|prefix| stack_encrypt::diagnostic::is_code_of(prefix, &code))
    })
}

/// One cause in a cause chain.
enum Cause<'a> {
    /// A diagnostic, found as a diagnostic source. It is CipherStash's own
    /// only when [`is_own`] says so.
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
/// one of CipherStash's own diagnostics, the walk follows only plain
/// sources, to the end of the chain.
fn causes_of(error: &dyn Diagnostic) -> Vec<ErrorCause> {
    let mut out = Vec::new();
    let mut next = next_of(error);
    while let Some(cause) = next {
        if out.len() == MAX_CAUSES {
            break;
        }
        next = match cause {
            Cause::Ours(diagnostic) if is_own(diagnostic) => {
                out.push(ErrorCause {
                    code: diagnostic.code().map(|code| code.to_string()),
                    message: diagnostic.to_string(),
                });
                next_of(diagnostic)
            }
            Cause::Ours(diagnostic) => {
                out.push(ErrorCause {
                    code: None,
                    message: UNDESCRIBED_CAUSE.to_owned(),
                });
                diagnostic.source().map(Cause::Foreign)
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
            code: error.code().map_or_else(
                || "recipher_js::unknown".to_owned(),
                |code| code.to_string(),
            ),
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

    /// Returns this failure, with the name of the record at fault.
    pub(crate) fn in_record(mut self, record: &str) -> Self {
        self.record = Some(record.to_owned());
        self
    }

    /// Returns this failure, with the name of the field at fault, or with
    /// no field.
    pub(crate) fn at_field(mut self, field: Option<&str>) -> Self {
        self.field = field.map(str::to_owned);
        self
    }

    /// Returns the engine's `reason` field, such as `no_fields`, when the
    /// error's fields include one.
    pub(crate) fn reason(&self) -> Option<&str> {
        self.fields
            .get("reason")
            .and_then(serde_json::Value::as_str)
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
    use stack_encrypt::dynamic::ValueKind;

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
    #[diagnostic(code(stack_encrypt::probe_inner))]
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
                    code: Some("stack_encrypt::probe_inner".to_owned()),
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
        let error = RecipherErrorFields::from(Error::Undefined);
        assert_eq!(error.code, "recipher_js::undefined");
        assert_eq!(error.message, "`undefined` cannot be encrypted");
        assert_eq!(
            error.help.as_deref(),
            Some("Use `null` for a value that is not there.")
        );
        assert_eq!(error.severity, Severity::Error);
        assert!(error.fields.is_empty() && error.causes.is_empty());
    }

    /// A diagnostic from another library, whose message quotes a value.
    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    #[error("library text that may quote a value")]
    #[diagnostic(code(other_library::refused))]
    struct ForeignDiagnostic;

    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    #[error("outer")]
    #[diagnostic(code(stack_encrypt::probe_outer))]
    struct WrapsForeign(
        #[source]
        #[diagnostic_source]
        ForeignDiagnostic,
    );

    #[test]
    fn a_diagnostic_cause_from_another_library_is_not_copied() {
        let error = RecipherErrorFields::diagnostic(&WrapsForeign(ForeignDiagnostic), None);
        assert_eq!(
            error.causes,
            [ErrorCause {
                code: None,
                message: UNDESCRIBED_CAUSE.to_owned(),
            }]
        );
        assert!(!format!("{error:?}").contains("quote a value"));
    }

    /// A diagnostic that is its own diagnostic source: a looping chain.
    #[derive(Debug)]
    struct DiagnosticLoop;

    impl std::fmt::Display for DiagnosticLoop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("loop")
        }
    }

    impl std::error::Error for DiagnosticLoop {}

    impl miette::Diagnostic for DiagnosticLoop {
        fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
            Some(Box::new("stack_encrypt::probe_loop"))
        }

        fn diagnostic_source(&self) -> Option<&dyn miette::Diagnostic> {
            Some(self)
        }
    }

    /// An error that is its own source: a looping chain of plain errors.
    #[derive(Debug)]
    struct SourceLoop;

    impl std::fmt::Display for SourceLoop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("library text that may quote a value")
        }
    }

    impl std::error::Error for SourceLoop {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    #[derive(Debug, thiserror::Error, miette::Diagnostic)]
    #[error("outer")]
    #[diagnostic(code(stack_encrypt::probe_outer))]
    struct WrapsSourceLoop(#[source] SourceLoop);

    #[test]
    fn a_looping_diagnostic_chain_stops_at_the_limit() {
        let error = RecipherErrorFields::diagnostic(&DiagnosticLoop, None);
        assert_eq!(error.causes.len(), super::MAX_CAUSES);
        assert!(error
            .causes
            .iter()
            .all(|cause| cause.code.as_deref() == Some("stack_encrypt::probe_loop")));
    }

    #[test]
    fn a_looping_chain_of_plain_errors_stops_at_the_limit() {
        let error = RecipherErrorFields::diagnostic(&WrapsSourceLoop(SourceLoop), None);
        assert_eq!(error.causes.len(), super::MAX_CAUSES);
        assert!(error
            .causes
            .iter()
            .all(|cause| cause.code.is_none() && cause.message == UNDESCRIBED_CAUSE));
    }

    /// Returns one of each variant of [`Error`]. The match has no wildcard,
    /// so the crate does not compile when a new variant has no entry here.
    fn every_error() -> Vec<Error> {
        let name = || "x".to_owned();
        let all = vec![
            Error::Undefined,
            Error::Uuid,
            Error::Value,
            Error::Threw,
            Error::NotAScalar,
            Error::PlainObject,
            Error::NotSealed,
            Error::NotACiphertext,
            Error::NotBytes,
            Error::NotAKind,
            Error::OpenedType {
                kind: ValueKind::String,
            },
            Error::NotADocument,
            Error::TestingSeed,
            Error::NoTesting,
            Error::NotARecord,
            Error::Declaration,
            Error::ReservedField,
            Error::Kind { name: name() },
            Error::Index { name: name() },
            Error::Null { mode: name() },
            Error::Context,
            Error::RecordName,
            Error::NoField,
            Error::NotARow,
            Error::FieldType {
                kind: ValueKind::Int8,
            },
            Error::NotAStoredRow { what: "x" },
            Error::EngineResult { what: "x" },
            Error::NoResult,
            Error::BuildValue,
        ];
        for error in &all {
            match error {
                Error::Undefined
                | Error::Uuid
                | Error::Value
                | Error::Threw
                | Error::NotAScalar
                | Error::PlainObject
                | Error::NotSealed
                | Error::NotACiphertext
                | Error::NotBytes
                | Error::NotAKind
                | Error::OpenedType { .. }
                | Error::NotADocument
                | Error::TestingSeed
                | Error::NoTesting
                | Error::NotARecord
                | Error::Declaration
                | Error::ReservedField
                | Error::Kind { .. }
                | Error::Index { .. }
                | Error::Null { .. }
                | Error::Context
                | Error::RecordName
                | Error::NoField
                | Error::NotARow
                | Error::FieldType { .. }
                | Error::NotAStoredRow { .. }
                | Error::EngineResult { .. }
                | Error::NoResult
                | Error::BuildValue => {}
            }
        }
        all
    }

    /// Returns the help that `error` states, or `None` for an error that
    /// leaves nothing for the caller to do. The match has no wildcard, so a
    /// new variant needs an entry here.
    fn help_of(error: &Error) -> Option<&'static str> {
        match error {
            Error::Undefined => Some("Use `null` for a value that is not there."),
            Error::Uuid => Some("Encrypt the UUID as a string instead."),
            Error::NotAScalar => {
                Some("To encrypt the inner array as a JSON document, wrap it in `json(..)`.")
            }
            Error::PlainObject => {
                Some("To encrypt the object as a JSON document, wrap it in `json(..)`.")
            }
            Error::NotACiphertext => Some("Read stored bytes with Ciphertext.fromBytes."),
            Error::NotAKind => {
                Some("Pass a kind that the package exports, such as `kinds.string`.")
            }
            Error::NoTesting => {
                Some("Build it with `pnpm --filter @cipherstash/recipher build:debug`.")
            }
            Error::NotARecord => Some("Declare a record with `record(..)`."),
            Error::ReservedField => Some("Give the field another name."),
            Error::Null { .. } => Some("A null mode is `sealed` or `sql`."),
            Error::RecordName => Some(
                "Use a record name that is not empty and contains no character that the engine refuses in a field path, such as `/`.",
            ),
            Error::NoField => Some(
                "Name a field that the record declares with `encrypt(..)`. A passthrough field has no ciphertext.",
            ),
            Error::EngineResult { .. } | Error::NoResult | Error::BuildValue => {
                Some("Report this as a bug in @cipherstash/recipher.")
            }
            Error::Value
            | Error::Threw
            | Error::NotSealed
            | Error::NotBytes
            | Error::OpenedType { .. }
            | Error::NotADocument
            | Error::TestingSeed
            | Error::Declaration
            | Error::Kind { .. }
            | Error::Index { .. }
            | Error::Context
            | Error::NotARow
            | Error::FieldType { .. }
            | Error::NotAStoredRow { .. } => None,
        }
    }

    #[test]
    fn every_error_states_its_help_and_no_other() {
        for error in every_error() {
            let help = help_of(&error);
            let fields = RecipherErrorFields::from(error);
            assert_eq!(fields.help.as_deref(), help, "{}", fields.code);
        }
    }

    #[test]
    fn every_error_has_a_recipher_code_of_its_own() {
        let mut codes = std::collections::BTreeSet::new();
        for error in every_error() {
            let code = RecipherErrorFields::from(error).code;
            assert!(
                stack_encrypt::diagnostic::is_code_of("recipher_js", &code),
                "{code} is not `recipher_js::` and a snake_case name"
            );
            assert!(codes.insert(code.clone()), "{code} is used twice");
        }
    }
}
