//! The full error behind the most recent failed export, for
//! [`se_last_error`](crate::abi::se_last_error).
//!
//! A failing export returns a status number in its packed result: that stays
//! the fast path a host acts on, byte-compatible with the vitaminc guest.
//! Beside it, the export records the error that produced the number — its
//! miette code, message, help, URL, severity, structured fields and causes —
//! as one value in the transport codec every input and output already uses
//! ([`encode`]). A host that wants the detail calls `se_last_error` after a
//! non-zero status; a call that succeeds pays nothing.
//!
//! # Lifecycle
//!
//! Every export runs through [`abi::export`](crate::abi::export), which
//! [`clear`]s the stored error when the export starts and makes sure one is
//! stored when it fails ([`ensure`]): the error the export recorded itself,
//! or a [`GuestError`] for its status if it recorded none. Guests are
//! single-threaded and the host serialises calls into one instance, so "the
//! most recent failed call" is well defined.
//!
//! The encoded error is a buffer in the [registry](crate::buffers) from the
//! moment it is stored: [`clear`] wipes and frees it, `se_last_error` hands
//! it to the host (who releases it with `se_dealloc`, like any output), and
//! a shutdown's [`buffers::wipe_all`] wipes it
//! with everything else. Handing it over empties the slot, so a second
//! `se_last_error` returns zero.
//!
//! # What may be in it
//!
//! Everything the encoder writes obeys the rule on `stack-profile`'s
//! `ErrorPayload` trait: the guests only record errors from the four crates
//! that implement it, and [`GuestError`]s, whose text is fixed. A cause
//! from another library contributes a description a guest vouches for
//! ([`describe_std`], or the guest's own describer), and otherwise only that
//! it was one; its message is never copied.

use std::borrow::Cow;
use std::cell::Cell;
use std::error::Error;

use miette::{Diagnostic, Severity};
use vitaminc_aead_value::{transport as codec, FfiValue};

use crate::buffers;
use crate::status::{STATUS_ENCODING, STATUS_INTERNAL, STATUS_STATE};

thread_local! {
    /// The registered buffer holding the encoded last error, if any. Keyed
    /// by the pointer the registry handed out, provenance intact, as the
    /// registry keys it.
    static LAST: Cell<Option<(*mut u8, usize)>> = const { Cell::new(None) };
}

/// How deep the cause chain is followed. A chain this long is a loop or a
/// bug, and a bounded walk cannot be made to spin.
const MAX_CAUSES: usize = 16;

/// What a cause from another library is reported as when nothing vouches
/// for its message.
pub const UNDESCRIBED_CAUSE: &str = "an error from another library";

/// A failure with no library error behind it: input the guest's own
/// boundary refused, a call out of order, or an export that failed without
/// recording why.
///
/// Its text is fixed or names a field of the guest's own input (a config
/// key), never the value: what [`ensure`] and the guests record where they
/// have only a status number.
#[derive(Debug, thiserror::Error, Diagnostic)]
#[non_exhaustive]
pub enum GuestError {
    /// The input failed the export's own validation before any library
    /// saw it: bytes that are not the transport codec, a pointer/length
    /// pair outside linear memory, a config or option of the wrong shape.
    #[error("malformed input: {0}")]
    #[diagnostic(code(stack_guest_abi::malformed_input))]
    Malformed(Cow<'static, str>),
    /// The call is out of order: an operation before the guest's init
    /// export, or after its shutdown, or init twice.
    #[error("call out of order: {0}")]
    #[diagnostic(
        code(stack_guest_abi::out_of_order),
        help("Initialise the instance once before any operation, and make no call after it is shut down.")
    )]
    OutOfOrder(Cow<'static, str>),
    /// An unexpected failure inside the guest: a caught panic, a response
    /// that did not match its request. Never the caller's input.
    #[error("internal failure: {0}")]
    #[diagnostic(code(stack_guest_abi::internal))]
    Internal(Cow<'static, str>),
    /// An export failed with a status and recorded nothing more. The status
    /// is all there is to say.
    #[error("the call failed with status {0}")]
    #[diagnostic(code(stack_guest_abi::status))]
    Status(u32),
}

impl GuestError {
    /// The error's structured fields.
    pub fn fields(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Status(status) => [("status".to_owned(), (*status).into())]
                .into_iter()
                .collect(),
            Self::Malformed(_) | Self::OutOfOrder(_) | Self::Internal(_) => serde_json::Map::new(),
        }
    }

    /// The status this error stands for.
    pub fn status(&self) -> u32 {
        match self {
            Self::Malformed(_) => STATUS_ENCODING,
            Self::OutOfOrder(_) => STATUS_STATE,
            Self::Internal(_) => STATUS_INTERNAL,
            Self::Status(status) => *status,
        }
    }

    /// Record this error as the last one and return its status: the one
    /// call a guest makes where it would otherwise return a bare number.
    pub fn fail(self) -> u32 {
        record(&self, self.fields());
        self.status()
    }
}

/// A [`GuestError::Malformed`], recorded; returns `STATUS_ENCODING`.
pub fn malformed(detail: impl Into<Cow<'static, str>>) -> u32 {
    GuestError::Malformed(detail.into()).fail()
}

/// A [`GuestError::OutOfOrder`], recorded; returns `STATUS_STATE`.
pub fn out_of_order(detail: impl Into<Cow<'static, str>>) -> u32 {
    GuestError::OutOfOrder(detail.into()).fail()
}

/// A [`GuestError::Internal`], recorded; returns `STATUS_INTERNAL`.
pub fn internal(detail: impl Into<Cow<'static, str>>) -> u32 {
    GuestError::Internal(detail.into()).fail()
}

/// Describe a cause from the standard library or serde_json under the rule:
/// an I/O error by its kind, a JSON error by its kind and position, never
/// either's own message. `None` for anything else.
pub fn describe_std(cause: &(dyn Error + 'static)) -> Option<String> {
    if let Some(io) = cause.downcast_ref::<std::io::Error>() {
        return Some(format!("I/O error: {}", io.kind()));
    }
    if let Some(json) = cause.downcast_ref::<serde_json::Error>() {
        let kind = match json.classify() {
            serde_json::error::Category::Io => "read error",
            serde_json::error::Category::Syntax => "syntax error",
            serde_json::error::Category::Data => "unexpected data",
            serde_json::error::Category::Eof => "unexpected end of input",
        };
        return Some(format!(
            "JSON error: {kind} at line {} column {}",
            json.line(),
            json.column()
        ));
    }
    None
}

/// Encode an error as the value [`se_last_error`](crate::abi::se_last_error)
/// returns: an object of
///
/// - `code`: the miette code, such as `stack_encrypt::foreign_keyset`
/// - `message`: the error's `Display`
/// - `help`, `url`: when the error has them
/// - `severity`: `"error"`, `"warning"` or `"advice"`
/// - `fields`: the error's structured fields (its `ErrorPayload`)
/// - `causes`: a list of `{code?, message}`, following the error's
///   diagnostic sources while they last and its plain sources after
///
/// A cause that is a miette diagnostic gives its code and message: it is
/// one of the four crates' errors, which obey the rule. One that is not
/// gives what `describe` vouches for, or [`UNDESCRIBED_CAUSE`].
pub fn encode(
    error: &dyn Diagnostic,
    fields: serde_json::Map<String, serde_json::Value>,
    describe: &dyn Fn(&(dyn Error + 'static)) -> Option<String>,
) -> FfiValue {
    let mut entries = Vec::with_capacity(7);
    if let Some(code) = error.code() {
        entries.push(("code".to_owned(), text(code.to_string())));
    }
    entries.push(("message".to_owned(), text(error.to_string())));
    if let Some(help) = error.help() {
        entries.push(("help".to_owned(), text(help.to_string())));
    }
    if let Some(url) = error.url() {
        entries.push(("url".to_owned(), text(url.to_string())));
    }
    let severity = match error.severity().unwrap_or(Severity::Error) {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Advice => "advice",
    };
    entries.push(("severity".to_owned(), text(severity)));
    entries.push((
        "fields".to_owned(),
        FfiValue::Object(
            fields
                .into_iter()
                .map(|(key, value)| (key, json_value(value)))
                .collect(),
        ),
    ));
    entries.push((
        "causes".to_owned(),
        FfiValue::Array(causes(error, describe)),
    ));
    FfiValue::Object(entries)
}

/// One link of the cause chain.
enum Cause<'a> {
    /// One of the four crates' errors, reached as a diagnostic source.
    Ours(&'a dyn Diagnostic),
    /// Anything reached as a plain source.
    Foreign(&'a (dyn Error + 'static)),
}

/// The error's causes, in order. A diagnostic source is preferred over a
/// plain source, since it is the same error with its code; once the chain
/// leaves the diagnostics it follows plain sources to the end.
fn causes(
    error: &dyn Diagnostic,
    describe: &dyn Fn(&(dyn Error + 'static)) -> Option<String>,
) -> Vec<FfiValue> {
    let mut out = Vec::new();
    let mut next = next_of(error);
    while let Some(cause) = next {
        if out.len() == MAX_CAUSES {
            break;
        }
        let (code, message, after) = match cause {
            Cause::Ours(diagnostic) => (
                diagnostic.code().map(|code| code.to_string()),
                diagnostic.to_string(),
                next_of(diagnostic),
            ),
            Cause::Foreign(foreign) => (
                None,
                describe(foreign).unwrap_or_else(|| UNDESCRIBED_CAUSE.to_owned()),
                foreign.source().map(Cause::Foreign),
            ),
        };
        let mut entry = Vec::with_capacity(2);
        if let Some(code) = code {
            entry.push(("code".to_owned(), text(code)));
        }
        entry.push(("message".to_owned(), text(message)));
        out.push(FfiValue::Object(entry));
        next = after;
    }
    out
}

/// The cause after a diagnostic: its diagnostic source, or else its plain
/// source.
fn next_of(diagnostic: &dyn Diagnostic) -> Option<Cause<'_>> {
    diagnostic
        .diagnostic_source()
        .map(Cause::Ours)
        .or_else(|| diagnostic.source().map(Cause::Foreign))
}

/// A string leaf.
fn text(value: impl Into<String>) -> FfiValue {
    FfiValue::String(value.into().into())
}

/// A structured field as a transport value.
fn json_value(value: serde_json::Value) -> FfiValue {
    match value {
        serde_json::Value::Null => FfiValue::Null,
        serde_json::Value::Bool(value) => FfiValue::Bool(value),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                FfiValue::UInt64(value)
            } else if let Some(value) = number.as_i64() {
                FfiValue::Int64(value)
            } else {
                FfiValue::Float64(number.as_f64().unwrap_or(f64::NAN))
            }
        }
        serde_json::Value::String(value) => text(value),
        serde_json::Value::Array(items) => {
            FfiValue::Array(items.into_iter().map(json_value).collect())
        }
        serde_json::Value::Object(entries) => FfiValue::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key, json_value(value)))
                .collect(),
        ),
    }
}

/// Record `error` as the last error, with its structured fields and
/// [`describe_std`] for causes from other libraries. Replaces any error
/// already recorded in this call.
pub fn record(error: &dyn Diagnostic, fields: serde_json::Map<String, serde_json::Value>) {
    record_with(error, fields, &describe_std);
}

/// [`record`], with a guest's own describer for causes from the libraries
/// it is built over. The describer returns `None` for a cause it does not
/// vouch for.
pub fn record_with(
    error: &dyn Diagnostic,
    fields: serde_json::Map<String, serde_json::Value>,
    describe: &dyn Fn(&(dyn Error + 'static)) -> Option<String>,
) {
    let mut bytes = Vec::new();
    // An error that does not encode (it cannot: every leaf is a string, a
    // number or a container) leaves the last error empty rather than half
    // written; the status still says what happened.
    if codec::encode_value(encode(error, fields, describe), &mut bytes).is_err() {
        clear();
        return;
    }
    store(bytes);
}

/// Store encoded bytes as the last error, wiping any before them.
fn store(bytes: Vec<u8>) {
    clear();
    let len = bytes.len();
    let ptr = buffers::register(bytes);
    LAST.with(|last| last.set(Some((ptr, len))));
}

/// Make sure an error is recorded for a failed call: if the call recorded
/// none, a [`GuestError`] for its status.
pub fn ensure(status: u32) {
    if is_set() {
        return;
    }
    let error = match status {
        STATUS_ENCODING => GuestError::Malformed("the input failed validation".into()),
        STATUS_STATE => GuestError::OutOfOrder("no operation can run in this state".into()),
        STATUS_INTERNAL => GuestError::Internal("an unexpected failure".into()),
        other => GuestError::Status(other),
    };
    record(&error, error.fields());
}

/// Whether an error is recorded.
pub fn is_set() -> bool {
    LAST.with(|last| last.get().is_some())
}

/// Wipe and free the recorded error, if any.
pub fn clear() {
    if let Some((ptr, len)) = LAST.with(Cell::take) {
        // SAFETY: the pair is the one `buffers::register` returned for the
        // bytes `store` registered, and nothing else holds it: the host is
        // only given it by `take_registered`, which empties the slot first.
        unsafe { buffers::dealloc(ptr, len) };
    }
}

/// Drop the slot without freeing: for a shutdown that is about to wipe the
/// whole registry, where freeing first would be a double wipe and keeping
/// the slot would leave it naming freed memory.
pub(crate) fn forget() {
    LAST.with(|last| last.set(None));
}

/// Hand the recorded error's registered buffer over, emptying the slot:
/// what `se_last_error` returns to the host, which releases it with
/// `se_dealloc`.
pub fn take_registered() -> Option<(*mut u8, usize)> {
    LAST.with(Cell::take)
}

/// Take the recorded error's bytes out of the registry: for a native
/// caller, a test, that has no host to release them.
pub fn take() -> Option<Vec<u8>> {
    let (ptr, len) = take_registered()?;
    // SAFETY: as in `clear`; the slot was emptied above.
    unsafe { buffers::take(ptr, len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> FfiValue {
        codec::decode_value(&mut codec::Reader::new(bytes)).expect("an encoded error decodes")
    }

    fn get<'a>(value: &'a FfiValue, key: &str) -> Option<&'a FfiValue> {
        match value {
            FfiValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn string(value: Option<&FfiValue>) -> Option<String> {
        match value? {
            FfiValue::String(s) => String::from_utf8(s.risky_ref().to_vec()).ok(),
            _ => None,
        }
    }

    #[derive(Debug, thiserror::Error, Diagnostic)]
    #[error("outer")]
    #[diagnostic(code(test::outer), help("do the thing"))]
    struct Outer {
        #[source]
        #[diagnostic_source]
        inner: Inner,
    }

    #[derive(Debug, thiserror::Error, Diagnostic)]
    #[error("inner")]
    #[diagnostic(code(test::inner))]
    struct Inner {
        #[source]
        io: std::io::Error,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("marker-foreign")]
    struct Foreign;

    #[test]
    fn an_error_encodes_with_its_code_help_fields_and_causes() {
        let error = Outer {
            inner: Inner {
                io: std::io::Error::new(std::io::ErrorKind::NotFound, "marker-io"),
            },
        };
        let fields = [("count".to_owned(), 2.into())].into_iter().collect();
        record(&error, fields);
        let value = decode(&take().expect("recorded"));
        assert_eq!(string(get(&value, "code")).as_deref(), Some("test::outer"));
        assert_eq!(string(get(&value, "message")).as_deref(), Some("outer"));
        assert_eq!(string(get(&value, "help")).as_deref(), Some("do the thing"));
        assert!(get(&value, "url").is_none());
        assert_eq!(string(get(&value, "severity")).as_deref(), Some("error"));
        assert!(matches!(
            get(get(&value, "fields").expect("fields"), "count"),
            Some(FfiValue::UInt64(2))
        ));
        let Some(FfiValue::Array(causes)) = get(&value, "causes") else {
            panic!("causes is a list");
        };
        assert_eq!(causes.len(), 2);
        assert_eq!(
            string(get(&causes[0], "code")).as_deref(),
            Some("test::inner")
        );
        assert_eq!(string(get(&causes[0], "message")).as_deref(), Some("inner"));
        assert!(
            get(&causes[1], "code").is_none(),
            "an I/O error has no code"
        );
        assert_eq!(
            string(get(&causes[1], "message")).as_deref(),
            Some("I/O error: entity not found"),
            "an I/O error is described by its kind, never its message"
        );
        assert!(!is_set(), "taking the error empties the slot");
    }

    #[test]
    fn a_foreign_cause_nobody_vouches_for_gives_no_message() {
        #[derive(Debug, thiserror::Error, Diagnostic)]
        #[error("wrapper")]
        #[diagnostic(code(test::wrapper))]
        struct Wrapper(#[source] Foreign);
        record(&Wrapper(Foreign), serde_json::Map::new());
        let value = decode(&take().expect("recorded"));
        let Some(FfiValue::Array(causes)) = get(&value, "causes") else {
            panic!("causes is a list");
        };
        assert_eq!(
            string(get(&causes[0], "message")).as_deref(),
            Some(UNDESCRIBED_CAUSE)
        );
    }

    #[test]
    fn ensure_records_a_guest_error_only_when_nothing_was_recorded() {
        clear();
        ensure(STATUS_STATE);
        let value = decode(&take().expect("recorded"));
        assert_eq!(
            string(get(&value, "code")).as_deref(),
            Some("stack_guest_abi::out_of_order")
        );

        let _ = malformed("the selector is not an object");
        ensure(STATUS_INTERNAL);
        let value = decode(&take().expect("recorded"));
        assert_eq!(
            string(get(&value, "message")).as_deref(),
            Some("malformed input: the selector is not an object"),
            "the error the call recorded wins over the status fallback"
        );

        ensure(42);
        let value = decode(&take().expect("recorded"));
        assert_eq!(
            string(get(&value, "code")).as_deref(),
            Some("stack_guest_abi::status")
        );
        assert!(matches!(
            get(get(&value, "fields").expect("fields"), "status"),
            Some(FfiValue::UInt64(42))
        ));
    }

    #[test]
    fn clearing_wipes_and_frees_the_registered_buffer() {
        let _ = internal("boom");
        assert!(is_set());
        clear();
        assert!(!is_set());
        assert!(take().is_none());
    }

    /// One row per variant of an enum, written `pattern => value`. The
    /// patterns are the arms of a match with no wildcard, so a variant with
    /// no row fails to compile, and each value must match its own pattern.
    macro_rules! variants {
        ($($pattern:pat => $value:expr),+ $(,)?) => {{
            let rows = vec![$({
                let value = $value;
                assert!(matches!(value, $pattern), "{value:?} is not {}", stringify!($pattern));
                value
            }),+];
            for row in &rows {
                match row {
                    $($pattern => {})+
                }
            }
            rows
        }};
    }

    /// Every [`GuestError`] has a code in this crate's namespace and
    /// `snake_case`.
    #[test]
    fn every_guest_error_has_a_code_of_this_crate() {
        let errors = variants![
            GuestError::Malformed(_) => GuestError::Malformed("x".into()),
            GuestError::OutOfOrder(_) => GuestError::OutOfOrder("x".into()),
            GuestError::Internal(_) => GuestError::Internal("x".into()),
            GuestError::Status(_) => GuestError::Status(9),
        ];
        for error in &errors {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            let name = code.strip_prefix("stack_guest_abi::").unwrap_or_default();
            assert!(
                name.starts_with(|c: char| c.is_ascii_lowercase())
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{code}"
            );
        }
    }
}
