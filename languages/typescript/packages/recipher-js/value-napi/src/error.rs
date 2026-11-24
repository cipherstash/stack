//! The error a walk or a build carries through the sink traits, and how it
//! comes back to JavaScript as the error it was.

use napi::{Error, Status};
use vitaminc_aead::plaintext::{self, SourceError};

/// A failure on the JavaScript side of a walk or a build: a getter threw, a
/// string had an unpaired surrogate, a value was of a type that cannot be
/// encrypted, a tree was too deep.
///
/// A napi [`Error`] is not `Send`, so it cannot travel inside a
/// [`SourceError`]; this carries its status and reason, which is all a
/// caller needs to hand it back to JavaScript. A [`Status::PendingException`]
/// means the original JavaScript exception is still pending in the engine,
/// and returning this error lets it surface unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct JsFault {
    status: Status,
    reason: String,
}

impl JsFault {
    pub(crate) fn new(status: Status, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
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
            reason: error.reason,
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
        match error.inner().downcast_ref::<JsFault>() {
            Some(fault) => fault.clone(),
            None => Self::new(Status::InvalidArg, error.to_string()),
        }
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
}
