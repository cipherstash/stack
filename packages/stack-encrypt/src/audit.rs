//! Audit metadata: facts about a call that ZeroKMS writes to its audit log.
//!
//! Every encrypt and decrypt asks ZeroKMS for data keys. ZeroKMS logs each
//! request with the identity that made it. [`AuditMetadata`] adds the facts
//! only the application knows, such as why it needs the key, so the log
//! can say what a request was for as well as who made it.
//!
//! Attach it to one call with [`Pending::audit`](crate::Pending::audit) or
//! to a plan chain with its `.audit(..)` method. It is optional: a call
//! without it sends no audit metadata, as it always has.
//!
//! On the wire this is the key request's *unverified context*. It is a
//! different thing from the contexts elsewhere in this crate, which are
//! bound into the ciphertext and needed again to decrypt.

use std::fmt;

use serde_json::{Map, Value};

use crate::kms::UnverifiedContext;

/// Facts about one call, sent to ZeroKMS with its key requests and written
/// to the ZeroKMS audit log.
///
/// Typical facts are the purpose of the call, a request or trace id, and
/// the end user the call acts for.
///
/// ```
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{AuditMetadata, Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let keyset = cipher.default_keyset();
/// let stored: Ciphertext = keyset.encrypt(String::from("sk_live_1234")).await?;
///
/// let api_key: String = keyset
///     .decrypt(stored)
///     .audit(
///         AuditMetadata::new()
///             .with("purpose", "list issues")
///             .with("request_id", "req_01J9Z3"),
///     )
///     .await?;
/// assert_eq!(api_key, "sk_live_1234");
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
///
/// # What ZeroKMS does with it
///
/// - **ZeroKMS does not verify it.** The client asserts these facts and
///   ZeroKMS records them as given. No key depends on them, so nothing may
///   rely on them for access control.
/// - **It is not needed to decrypt.** The metadata on a decrypt may differ
///   from the metadata on the encrypt, or be absent.
/// - **It is one map per request.** Every key request a call makes carries
///   the same metadata. A batch makes one request, so it carries one map.
///
/// # What it must not hold
///
/// The metadata lands in ZeroKMS logs. It must not hold plaintext,
/// anything derived from plaintext, or secrets. Values such as IP
/// addresses and user agents are personal data: this crate sends only what
/// the application passes, and adds nothing of its own.
///
/// # Values
///
/// A value is any JSON value. A number must fit a signed 64-bit integer or
/// a 64-bit float, as ZeroKMS reads it: an unsigned integer above
/// `i64::MAX` is refused with [`AuditError::NumberOutOfRange`] when the
/// metadata is attached, before any request, rather than sent as a float
/// that has lost digits.
#[derive(Clone, Default, PartialEq)]
pub struct AuditMetadata {
    fields: Map<String, Value>,
}

impl AuditMetadata {
    /// Metadata with no facts. Attaching it sends no audit metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the fact `key`, replacing a fact already under that key.
    ///
    /// ```
    /// use stack_encrypt::AuditMetadata;
    /// use serde_json::json;
    ///
    /// let metadata = AuditMetadata::new()
    ///     .with("purpose", "export")
    ///     .with("rows", 250)
    ///     .with("filters", json!({ "team": "platform" }));
    /// assert_eq!(metadata.len(), 3);
    /// ```
    pub fn with(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        // A fact already under this key is replaced, as documented.
        let _replaced = self.fields.insert(key.into(), value.into());
        self
    }

    /// The number of facts.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether there are no facts. Attaching empty metadata sends none.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The metadata as ZeroKMS takes it, or `None` when there is nothing to
    /// send.
    ///
    /// # Errors
    ///
    /// [`AuditError::NumberOutOfRange`] for a number ZeroKMS cannot hold
    /// exactly.
    pub(crate) fn to_unverified(&self) -> Result<Option<UnverifiedContext>, AuditError> {
        if self.fields.is_empty() {
            return Ok(None);
        }
        for (key, value) in &self.fields {
            if !fits(value) {
                return Err(AuditError::NumberOutOfRange { key: key.clone() });
            }
        }
        // Every number was checked above, so this conversion cannot change
        // one, and every other JSON shape has a ZeroKMS form. A failure here
        // would be a ZeroKMS type that no longer reads JSON; it is reported,
        // never a panic.
        serde_json::from_value(Value::Object(self.fields.clone()))
            .map(Some)
            .map_err(|_| AuditError::NotAnObject)
    }
}

/// Whether every number in `value` has an exact ZeroKMS form: a signed
/// 64-bit integer or a 64-bit float.
fn fits(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.is_i64() || number.is_f64(),
        Value::Array(items) => items.iter().all(fits),
        Value::Object(fields) => fields.values().all(fits),
        Value::Null | Value::Bool(_) | Value::String(_) => true,
    }
}

/// Shows the keys and not the values: the values are the caller's facts,
/// and a debug log is not the audit log.
impl fmt::Debug for AuditMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditMetadata")
            .field("keys", &self.fields.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Metadata from a JSON object, such as one built with `serde_json::json!`.
///
/// ```
/// use stack_encrypt::AuditMetadata;
/// use serde_json::json;
///
/// let metadata = AuditMetadata::try_from(json!({
///     "purpose": "list issues",
///     "request_id": "req_01J9Z3",
/// }))?;
/// assert_eq!(metadata.len(), 2);
///
/// assert!(AuditMetadata::try_from(json!(["not", "an", "object"])).is_err());
/// # Ok::<(), stack_encrypt::AuditError>(())
/// ```
impl TryFrom<Value> for AuditMetadata {
    type Error = AuditError;

    /// # Errors
    ///
    /// [`AuditError::NotAnObject`] for any JSON value but an object.
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Object(fields) => Ok(Self::from(fields)),
            _ => Err(AuditError::NotAnObject),
        }
    }
}

impl From<Map<String, Value>> for AuditMetadata {
    fn from(fields: Map<String, Value>) -> Self {
        Self { fields }
    }
}

/// Audit metadata that could not be sent as given.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum AuditError {
    /// The JSON value given as metadata was not an object. ZeroKMS takes a
    /// map of facts.
    #[error("audit metadata must be a JSON object")]
    #[diagnostic(
        code(stack_encrypt::audit_not_an_object),
        help("Pass a JSON object, such as `json!({{ \"purpose\": \"list issues\" }})`.")
    )]
    NotAnObject,
    /// A number in the metadata does not fit a signed 64-bit integer or a
    /// 64-bit float, so ZeroKMS would log a different number. `key` is the
    /// top-level key it was found under.
    #[error("audit metadata `{key}` holds a number ZeroKMS cannot record exactly")]
    #[diagnostic(
        code(stack_encrypt::audit_number_out_of_range),
        help("Send an integer above `i64::MAX` as a string.")
    )]
    NumberOutOfRange { key: String },
    /// Two calls carrying different audit metadata were merged into one
    /// batch (`zip`, `all`). A batch makes one key request, which carries
    /// one map. Refused before any request.
    #[error("merged calls carry different audit metadata")]
    #[diagnostic(
        code(stack_encrypt::audit_mismatch),
        help(
            "Attach the metadata once, to the merged call, or give every part the same metadata."
        )
    )]
    Mismatch,
}

impl crate::ErrorPayload for AuditError {
    fn payload(&self) -> Map<String, Value> {
        use crate::diagnostic::payload;
        match self {
            Self::NumberOutOfRange { key } => payload([("key", key.clone().into())]),
            Self::NotAnObject | Self::Mismatch => Map::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn len_counts_distinct_keys() {
        let empty = AuditMetadata::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let two = empty.with("a", 1).with("b", 2).with("a", 3);
        assert!(!two.is_empty());
        assert_eq!(two.len(), 2);
    }

    #[test]
    fn empty_metadata_sends_nothing() {
        assert_eq!(AuditMetadata::new().to_unverified(), Ok(None));
    }

    #[test]
    fn metadata_converts_to_the_same_json() {
        let metadata = AuditMetadata::try_from(json!({
            "purpose": "list issues",
            "attempt": 2,
            "ratio": 0.5,
            "flags": [true, null],
            "nested": { "team": "platform" },
        }))
        .unwrap();
        let unverified = metadata.to_unverified().unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&unverified).unwrap(),
            json!({
                "purpose": "list issues",
                "attempt": 2,
                "ratio": 0.5,
                "flags": [true, null],
                "nested": { "team": "platform" },
            })
        );
    }

    #[test]
    fn a_later_fact_replaces_an_earlier_one() {
        let metadata = AuditMetadata::new()
            .with("purpose", "first")
            .with("purpose", "second");
        assert_eq!(metadata, AuditMetadata::new().with("purpose", "second"));
    }

    #[test]
    fn an_unsigned_integer_above_i64_max_is_refused() {
        let metadata = AuditMetadata::new().with("nested", json!({ "big": u64::MAX }));
        assert_eq!(
            metadata.to_unverified(),
            Err(AuditError::NumberOutOfRange {
                key: "nested".into()
            })
        );
        let fits = AuditMetadata::new().with("max", i64::MAX);
        assert!(fits.to_unverified().unwrap().is_some());
    }

    #[test]
    fn only_an_object_converts() {
        for value in [json!(null), json!(1), json!("purpose"), json!([])] {
            assert_eq!(AuditMetadata::try_from(value), Err(AuditError::NotAnObject));
        }
    }

    #[test]
    fn debug_shows_keys_not_values() {
        let shown = format!(
            "{:?}",
            AuditMetadata::new().with("user", "alice@example.com")
        );
        assert!(shown.contains("user"));
        assert!(!shown.contains("alice"));
    }
}
