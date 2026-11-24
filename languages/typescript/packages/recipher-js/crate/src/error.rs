//! Every failure the addon reports, as the object JavaScript receives.
//!
//! An error is a miette diagnostic: the engine's, the value bridge's
//! [`Refusal`](recipher_value_napi::Refusal), or one of the SDK's own in
//! [`Error`]. [`RecipherErrorFields::diagnostic`] turns any of them into a
//! [`RecipherErrorFields`]: its code, message, help, documentation URL,
//! severity, structured fields and causes. No error here holds a plaintext,
//! a key, a token or a ciphertext.
//!
//! A cause that is one of the engine's own diagnostics gives its code and
//! message. A cause from another library gives [`UNDESCRIBED_CAUSE`] and
//! nothing else: its message is text the engine does not vouch for, and is
//! never copied.

use std::error::Error as StdError;

use miette::Diagnostic;
use napi_derive::napi;
use stack_encrypt::dynamic::ValueKind;
use stack_encrypt::ErrorPayload;

/// The SDK's own errors: what the addon refuses before the engine sees it,
/// and what goes wrong between the engine and JavaScript.
#[derive(Debug, thiserror::Error, Diagnostic)]
pub(crate) enum Error {
    /// `undefined` given as a value.
    #[error("`undefined` is not a value")]
    #[diagnostic(
        code(recipher::undefined),
        help("Use `null` for a value that is not there.")
    )]
    Undefined,
    /// A `VcUuid`, which the engine's value model does not hold.
    #[error("a UUID cannot be encrypted yet: the engine's value model does not hold one")]
    #[diagnostic(code(recipher::uuid), help("Encrypt its text instead."))]
    Uuid,
    /// A value outside the engine's value model, or one Node-API failed to
    /// read.
    #[error("the value cannot be encrypted: it is not one the engine reads")]
    #[diagnostic(code(recipher::value))]
    Value,
    /// A getter of the application's threw while the value was read.
    #[error(
        "reading the value threw. The thrown error is not kept, because its message may hold the value"
    )]
    #[diagnostic(code(recipher::threw))]
    Threw,
    /// An array inside an array, given as one value.
    #[error("an array inside an array is not a value")]
    #[diagnostic(code(recipher::not_a_scalar), help("Wrap it in json(..)."))]
    NotAScalar,
    /// An object given as one value.
    #[error("an object is not a value")]
    #[diagnostic(code(recipher::plain_object), help("Wrap it in json(..)."))]
    PlainObject,
    /// A value that is not a JSON document the engine seals.
    #[error("the value is not a JSON document the engine seals: {what}")]
    #[diagnostic(code(recipher::not_json))]
    NotJson { what: &'static str },
    /// A JSON document nested deeper than the engine's parser reads.
    #[error(
        "the value is not a JSON document the engine seals: it is nested deeper than 127 levels of arrays and objects"
    )]
    #[diagnostic(code(recipher::too_deep))]
    JsonTooDeep,
    /// The engine refused to seal a value as it was given.
    #[error("the engine could not seal the value as given")]
    #[diagnostic(code(recipher::not_sealed))]
    NotSealed,
    /// `decrypt` given something that is not a `Ciphertext`.
    #[error("decrypt takes a Ciphertext, or an array of them")]
    #[diagnostic(
        code(recipher::not_a_ciphertext),
        help("Read stored bytes with Ciphertext.fromBytes.")
    )]
    NotACiphertext,
    /// `Ciphertext.fromBytes` given something that is not bytes.
    #[error("a ciphertext is read from a Uint8Array")]
    #[diagnostic(code(recipher::not_bytes))]
    NotBytes,
    /// A kind that is not one of `kinds`.
    #[error("a ciphertext opens as one of `kinds`, such as `kinds.string`")]
    #[diagnostic(code(recipher::not_a_kind))]
    NotAKind,
    /// A ciphertext that opened as another kind than the one named.
    #[error("the value opened, but it was not sealed as the kind named, {kind}")]
    #[diagnostic(code(recipher::opened_type))]
    OpenedType { kind: ValueKind },
    /// A ciphertext named JSON that opened as text that is not JSON.
    #[error("the value opened, but it is not a JSON document")]
    #[diagnostic(code(recipher::not_a_document))]
    NotADocument,
    /// A test cipher's seed that is not 32 bytes.
    #[error("a test cipher's seed is a Uint8Array of 32 bytes")]
    #[diagnostic(code(recipher::testing_seed))]
    TestingSeed,
    /// `createTesting` in a build without the test cipher.
    // A build with the test cipher never raises it.
    #[cfg_attr(feature = "testing", allow(dead_code))]
    #[error("this native build has no test cipher")]
    #[diagnostic(
        code(recipher::no_testing),
        help("Build it with `pnpm --filter @cipherstash/recipher build:debug`.")
    )]
    NoTesting,
    /// A declaration that `record(..)` did not make.
    #[error("the value is not a record")]
    #[diagnostic(
        code(recipher::not_a_record),
        help("Declare a record with record(..).")
    )]
    NotARecord,
    /// A field declared with something other than `encrypt(..)` or
    /// `passthrough()`.
    #[error("a field is declared with encrypt(..) or passthrough()")]
    #[diagnostic(code(recipher::declaration))]
    Declaration,
    /// A field named with a name the engine reserves.
    #[error("the field's name is one the engine reserves")]
    #[diagnostic(code(recipher::reserved_field), help("Name the field something else."))]
    ReservedField,
    /// A field's kind that is not one of `kinds`.
    #[error("`{name}` is not one of `kinds`")]
    #[diagnostic(code(recipher::kind))]
    Kind { name: String },
    /// A field's index that is not one the SDK names.
    #[error("`{name}` is not an index")]
    #[diagnostic(code(recipher::index))]
    Index { name: String },
    /// A field's null mode that is not one the engine has.
    #[error("`{mode}` is not a null mode")]
    #[diagnostic(code(recipher::null), help("A null mode is `sealed` or `sql`."))]
    Null { mode: String },
    /// A field path that could not be written as a context.
    #[error("the field path could not be written")]
    #[diagnostic(code(recipher::context))]
    Context,
    /// A record name the engine refuses as a segment of a field path.
    #[error("the record name is not a plain segment of a field path")]
    #[diagnostic(
        code(recipher::record_name),
        help("Use a record name that is not empty and holds no character the engine refuses in a field path, such as `/`.")
    )]
    RecordName,
    /// A field named that the record does not seal: no such field, a
    /// passthrough field, or a name that is not a string.
    #[error("the record declares no sealed field of that name")]
    #[diagnostic(
        code(recipher::no_field),
        help("Name a field the record declares with encrypt(..). A passthrough field has no ciphertext.")
    )]
    NoField,
    /// A row that is not an object of the record's fields.
    #[error("a row is an object of the record's fields")]
    #[diagnostic(code(recipher::not_a_row))]
    NotARow,
    /// A row's value that is not of its field's kind.
    #[error("the value is not of the field's kind, {kind}, or does not fit it")]
    #[diagnostic(code(recipher::field_type))]
    FieldType { kind: ValueKind },
    /// A stored row that does not have the record's shape.
    #[error("the stored row does not have the record's shape: {what}")]
    #[diagnostic(code(recipher::not_a_stored_row))]
    NotAStoredRow { what: &'static str },
    /// A stored row from the engine that the SDK cannot read.
    #[error("the engine's stored row does not have the shape the SDK reads: {what}")]
    #[diagnostic(
        code(recipher::engine_result),
        help("Report this as a bug in @cipherstash/recipher.")
    )]
    EngineResult { what: &'static str },
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
    /// Stable: the diagnostic's code, such as `stack_encrypt::aead`,
    /// vitaminc's code for a value it refused, such as `ERR_INTEGER_RANGE`,
    /// or the SDK's own, such as `recipher::not_a_ciphertext`.
    pub code: String,
    /// What went wrong, in one line.
    pub message: String,
    /// What to do about it, where the error knows.
    pub help: Option<String>,
    /// A documentation page for the error, where it has one.
    pub url: Option<String>,
    /// How serious it is: `error` unless the diagnostic says otherwise.
    pub severity: Severity,
    /// The error's structured fields, by `snake_case` name: a refused
    /// plan's `field` and `reason`, a ZeroKMS failure's `request_kind`.
    /// Empty where the error has none.
    pub fields: serde_json::Map<String, serde_json::Value>,
    /// The errors behind this one, outermost first.
    pub causes: Vec<ErrorCause>,
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
    Foreign(&'a (dyn StdError + 'static)),
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
    /// The failure for any diagnostic, with the structured fields of
    /// `payload` where there is one. `field` is the payload's `field`, where
    /// it names one.
    pub(crate) fn diagnostic(
        error: &dyn Diagnostic,
        payload: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Self {
        let fields = payload.unwrap_or_default();
        Self {
            // Every error the addon reports has a code; this is never seen.
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

    /// The failure for an engine error, with its structured fields.
    pub(crate) fn engine<E: ErrorPayload>(error: &E) -> Self {
        Self::diagnostic(error, Some(error.payload()))
    }

    /// This failure, naming the record at fault.
    pub(crate) fn in_record(mut self, record: &str) -> Self {
        self.record = Some(record.to_owned());
        self
    }

    /// This failure, naming the field at fault, or none.
    pub(crate) fn at_field(mut self, field: Option<&str>) -> Self {
        self.field = field.map(str::to_owned);
        self
    }

    /// The engine's reason token, such as `no_fields`, where the error's
    /// fields hold one.
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
        let error = RecipherErrorFields::diagnostic(&outer, Some(payload));
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
    fn an_error_of_the_sdks_own_has_its_code_message_and_help() {
        let error = RecipherErrorFields::from(Error::Undefined);
        assert_eq!(error.code, "recipher::undefined");
        assert_eq!(error.message, "`undefined` is not a value");
        assert_eq!(
            error.help.as_deref(),
            Some("Use `null` for a value that is not there.")
        );
        assert_eq!(error.severity, Severity::Error);
        assert!(error.fields.is_empty() && error.causes.is_empty());
    }

    /// One of every variant of [`Error`]. The match has no wildcard, so a
    /// variant added without a row here does not compile.
    fn every_error() -> Vec<Error> {
        let name = || "x".to_owned();
        let all = vec![
            Error::Undefined,
            Error::Uuid,
            Error::Value,
            Error::Threw,
            Error::NotAScalar,
            Error::PlainObject,
            Error::NotJson { what: "bytes" },
            Error::JsonTooDeep,
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
                | Error::NotJson { .. }
                | Error::JsonTooDeep
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
