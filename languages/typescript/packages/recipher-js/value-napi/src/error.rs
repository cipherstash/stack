//! The error a walk or a build carries through the sink traits, and how it
//! comes back to JavaScript as the error it was.

use napi::{Error, Status};
use vitaminc_aead::plaintext::{self, SourceError};

use crate::scalar::ConversionError;

/// Why a JavaScript value was refused, for a caller that reports it by
/// its code.
///
/// Each variant is a diagnostic: a stable code, a message, and help where
/// there is something to do. No message holds any part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum Refusal {
    /// An object that is neither plain nor one of the wrapper classes.
    #[error(
        "a Map, a Set, a class instance or another object that is not plain cannot be encrypted"
    )]
    #[diagnostic(code(recipher_js::not_plain), help("Make it a plain object first."))]
    NotPlain,
    /// A property named `__proto__`, `constructor` or `prototype`.
    #[error("an object has a property named `__proto__`, `constructor` or `prototype`, which is refused in both directions")]
    #[diagnostic(code(recipher_js::reserved_key))]
    ReservedKey,
    /// A value nested past the limit: [`MAX_DEPTH`](crate::MAX_DEPTH), or
    /// the limit given for a JSON document.
    #[error("the value is nested deeper than {limit} levels")]
    #[diagnostic(code(recipher_js::too_deep))]
    TooDeep {
        /// The most levels of arrays and objects the value may nest.
        limit: usize,
    },
    /// An array with a hole.
    #[error("an array has a hole")]
    #[diagnostic(
        code(recipher_js::sparse_array),
        help("Write `undefined` or `null` where a value is missing.")
    )]
    SparseArray,
    /// A typed array other than a `Uint8Array`, or a `DataView`.
    #[error(
        "only a Buffer or a Uint8Array is bytes; another typed array or a DataView is refused"
    )]
    #[diagnostic(code(recipher_js::not_bytes))]
    NotBytes,
    /// A function, a symbol or another type with no value in the model.
    #[error("a function, a symbol or another type JavaScript has no value of cannot be encrypted")]
    #[diagnostic(code(recipher_js::not_a_value))]
    NotAValue,
    /// A property removed while its object was being read.
    #[error("an object changed while it was read")]
    #[diagnostic(code(recipher_js::changed_while_read))]
    ChangedWhileRead,
    /// A string or a property name with an unpaired surrogate.
    #[error(
        "a string or a property name has an unpaired surrogate, so it has no exact UTF-8 form"
    )]
    #[diagnostic(code(recipher_js::unpaired_surrogate))]
    UnpairedSurrogate,
    /// A value that a JSON document cannot hold.
    #[error("a JSON document cannot hold {0}")]
    #[diagnostic(code(recipher_js::not_json))]
    NotJson(NoJsonForm),
    /// A scalar outside what its type holds. A `TypeError` with the same
    /// code is pending in JavaScript.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Scalar(#[from] ConversionError),
}

/// A value that has no form in a JSON document. Each variant displays as
/// what the value is, and never as the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NoJsonForm {
    /// `undefined`.
    #[error("`undefined`")]
    Undefined,
    /// `NaN`, `Infinity` or `-Infinity`.
    #[error("a number that is not finite")]
    NonFinite,
    /// A whole `number` from 2^53 up to 2^64, either side of zero. A
    /// `number` that large may not have the digits that were written.
    #[error(
        "a whole number from 2^53 up to 2^64 held as a `number`, whose digits may not be the \
         ones written; give it as a `bigint`"
    )]
    UnsafeInteger,
    /// A `bigint` below -2^63 or above 2^64 - 1.
    #[error("a `bigint` outside the 64-bit range (below -2^63 or above 2^64 - 1)")]
    BigIntRange,
    /// A `Buffer`, a typed array or a `DataView`.
    #[error("bytes")]
    Bytes,
    /// A `Date` or a wrapper class instance.
    #[error("a date, a timestamp, a decimal or a UUID; write it as text")]
    Typed,
}

/// A failure on the JavaScript side of a walk or a build: a getter threw, a
/// string had an unpaired surrogate, a value was of a type that cannot be
/// encrypted, a tree was too deep.
///
/// A napi [`Error`] is not `Send`, so it cannot travel inside a
/// [`SourceError`]; this carries its status and reason, which is all a
/// caller needs to hand it back to JavaScript. A [`Status::PendingException`]
/// means the original JavaScript exception is still pending in the engine,
/// and returning this error lets it surface unchanged.
///
/// When the fault is this crate's refusal of a value, [`refusal`](Self::refusal)
/// says which one, so a caller never reads the reason's text to find out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct JsFault {
    status: Status,
    reason: String,
    refusal: Option<Refusal>,
}

impl JsFault {
    pub(crate) fn new(status: Status, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
            refusal: None,
        }
    }

    /// This crate's refusal of a value, with the reason JavaScript sees.
    pub(crate) fn refused(refusal: Refusal, reason: impl Into<String>) -> Self {
        Self {
            status: Status::InvalidArg,
            reason: reason.into(),
            refusal: Some(refusal),
        }
    }

    /// A refused scalar, whose `TypeError` is pending in JavaScript.
    pub(crate) fn pending(error: ConversionError) -> Self {
        Self {
            status: Status::PendingException,
            reason: error.to_string(),
            refusal: Some(Refusal::Scalar(error)),
        }
    }

    /// Which refusal this is, when it is one of this crate's. `None` for a
    /// failure of Node-API itself, or an exception the application threw.
    pub fn refusal(&self) -> Option<Refusal> {
        self.refusal
    }

    /// The fault a sink's source error carries, or the error's own text
    /// when it carries none.
    pub(crate) fn of_source(error: &SourceError) -> Self {
        match error.inner().downcast_ref::<JsFault>() {
            Some(fault) => fault.clone(),
            None => Self::new(Status::InvalidArg, error.to_string()),
        }
    }

    /// The napi status of the failure. [`Status::PendingException`] means a
    /// JavaScript exception is still pending: return this error to
    /// JavaScript before running any more JavaScript, so the exception
    /// surfaces as it was thrown.
    pub fn status(&self) -> Status {
        self.status
    }

    /// The failure's message.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The napi error for a source error, which is a [`JsFault`] when the
    /// source was a JavaScript value and some other error otherwise.
    pub fn from_source(error: &SourceError) -> Error {
        match error.inner().downcast_ref::<JsFault>() {
            Some(fault) => fault.clone().into(),
            None => Error::new(Status::InvalidArg, error.to_string()),
        }
    }
}

impl From<Error> for JsFault {
    fn from(error: Error) -> Self {
        Self {
            status: error.status,
            reason: error.reason.clone(),
            refusal: None,
        }
    }
}

impl From<JsFault> for Error {
    fn from(fault: JsFault) -> Self {
        Error::new(fault.status, fault.reason)
    }
}

impl plaintext::Error for JsFault {
    fn source(error: SourceError) -> Self {
        Self::of_source(&error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::plaintext::Error as _;

    #[test]
    fn a_fault_reports_the_status_and_reason_it_was_made_with() {
        let fault = JsFault::new(Status::GenericFailure, "the getter threw");
        assert_eq!(fault.status(), Status::GenericFailure);
        assert_eq!(fault.reason(), "the getter threw");
    }

    #[test]
    fn a_fault_round_trips_through_a_napi_error() {
        let fault = JsFault::new(Status::PendingException, "getter threw");
        let error: Error = fault.clone().into();
        assert_eq!(error.status, Status::PendingException);
        assert_eq!(error.reason, "getter threw");
        assert_eq!(JsFault::from(error), fault);
    }

    #[test]
    fn a_source_error_carrying_a_fault_is_that_fault() {
        let fault = JsFault::new(Status::InvalidArg, "unpaired surrogate");
        let wrapped = SourceError::new(fault.clone());
        assert_eq!(JsFault::source(wrapped), fault);
        let wrapped = SourceError::new(fault.clone());
        let error = JsFault::from_source(&wrapped);
        assert_eq!(
            (error.status, error.reason.as_str()),
            (Status::InvalidArg, "unpaired surrogate")
        );
    }

    #[test]
    fn a_source_error_from_elsewhere_keeps_its_message() {
        let wrapped = SourceError::msg("frame is malformed");
        assert_eq!(
            JsFault::source(wrapped),
            JsFault::new(Status::InvalidArg, "frame is malformed")
        );
        let error = JsFault::from_source(&SourceError::msg("frame is malformed"));
        assert_eq!(error.status, Status::InvalidArg);
        assert_eq!(error.reason, "frame is malformed");
    }

    /// One of every refusal. The match has no wildcard, so a variant added
    /// without a row here does not compile.
    fn every_refusal() -> Vec<Refusal> {
        use crate::scalar::ConversionError as C;
        let all = vec![
            Refusal::NotPlain,
            Refusal::ReservedKey,
            Refusal::TooDeep { limit: 128 },
            Refusal::SparseArray,
            Refusal::NotBytes,
            Refusal::NotAValue,
            Refusal::ChangedWhileRead,
            Refusal::UnpairedSurrogate,
            Refusal::NotJson(NoJsonForm::Undefined),
            Refusal::Scalar(C::IntegerRange),
            Refusal::Scalar(C::InvalidDate),
            Refusal::Scalar(C::InvalidTimestamp),
            Refusal::Scalar(C::InvalidDecimal),
            Refusal::Scalar(C::NonFiniteDecimal),
            Refusal::Scalar(C::InvalidUuid),
        ];
        for refusal in &all {
            match refusal {
                Refusal::NotPlain
                | Refusal::ReservedKey
                | Refusal::TooDeep { .. }
                | Refusal::SparseArray
                | Refusal::NotBytes
                | Refusal::NotAValue
                | Refusal::ChangedWhileRead
                | Refusal::UnpairedSurrogate
                | Refusal::NotJson(_) => {}
                Refusal::Scalar(scalar) => match scalar {
                    C::IntegerRange
                    | C::InvalidDate
                    | C::InvalidTimestamp
                    | C::InvalidDecimal
                    | C::NonFiniteDecimal
                    | C::InvalidUuid => {}
                },
            }
        }
        all
    }

    #[test]
    fn every_refusal_has_a_code_of_its_own() {
        use miette::Diagnostic;
        let mut codes = std::collections::BTreeSet::new();
        for refusal in every_refusal() {
            let code = refusal.code().expect("a code").to_string();
            match refusal {
                // A refused scalar keeps the code its `TypeError` is thrown
                // with.
                Refusal::Scalar(scalar) => assert_eq!(code, scalar.code()),
                _ => {
                    let name = code.strip_prefix("recipher_js::").expect("the namespace");
                    assert!(
                        !name.is_empty()
                            && name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                        "{code}"
                    );
                }
            }
            assert!(codes.insert(code.clone()), "{code} is used twice");
        }
    }

    #[test]
    fn a_fault_says_which_refusal_it_is() {
        let refused = JsFault::refused(Refusal::NotPlain, "only plain objects");
        assert_eq!(refused.refusal(), Some(Refusal::NotPlain));
        assert_eq!(refused.status(), Status::InvalidArg);
        // The reason JavaScript sees is unchanged by the variant.
        assert_eq!(refused.reason(), "only plain objects");

        let pending = JsFault::pending(crate::scalar::ConversionError::InvalidUuid);
        assert_eq!(pending.status(), Status::PendingException);
        assert_eq!(
            pending.refusal(),
            Some(Refusal::Scalar(crate::scalar::ConversionError::InvalidUuid))
        );

        // A failure of Node-API's own is no refusal.
        let napi = JsFault::from(Error::new(Status::GenericFailure, "napi failed"));
        assert_eq!(napi.refusal(), None);
    }
}
