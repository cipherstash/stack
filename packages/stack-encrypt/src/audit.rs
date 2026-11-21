//! Audit metadata: facts about a call that ZeroKMS writes to its audit log.
//!
//! Every encrypt and decrypt asks ZeroKMS for data keys. ZeroKMS logs each
//! request with the identity that made it. [`AuditMetadata`] adds facts
//! that only the application knows, such as the purpose of the call.
//!
//! To send it, call `.audit(..)` on a call before you await it. These
//! decrypt methods show how, with an example:
//!
//! - [`KeysetCipher::decrypt`](crate::KeysetCipher::decrypt) and
//!   [`decrypt_with_context`](crate::KeysetCipher::decrypt_with_context),
//!   for one value;
//! - [`KeysetCipher::decrypt_tree`](crate::KeysetCipher::decrypt_tree) and
//!   [`StackCipher::decrypt`](crate::StackCipher::decrypt), for a tree of
//!   values.
//!
//! A derived record's decrypt,
//! [`DecryptFrom::decrypt_from`](crate::DecryptFrom::decrypt_from), and
//! every encrypt call take `.audit(..)` in the same way. Audit metadata is
//! optional: a call without it sends none.
//!
//! In the ZeroKMS protocol, audit metadata is the key request's
//! *unverified context*. Audit metadata is not one of the contexts
//! described elsewhere in this crate. Those contexts are bound into the
//! ciphertext. The same context is needed to decrypt.

use std::fmt;
use std::sync::Arc;

use crate::kms::{UnverifiedContext, UnverifiedContextValue};

/// Audit metadata in the form ZeroKMS takes, ready to send, or `None` for
/// none. Shared, so a call that makes several key requests sends it with
/// each one without a copy.
pub(crate) type Unverified = Option<Arc<UnverifiedContext>>;

/// Facts about one call that ZeroKMS writes to its audit log.
///
/// Typical facts are the purpose of the call, a request id, a trace id,
/// and the end user that the call acts for. Add each fact with
/// [`with`](Self::with), then pass the metadata to `.audit(..)` on the
/// call. The decrypt methods show this with examples, starting at
/// [`KeysetCipher::decrypt`](crate::KeysetCipher::decrypt).
///
/// ```
/// use stack_encrypt::AuditMetadata;
///
/// let metadata = AuditMetadata::new()
///     .with("purpose", "list issues")
///     .with("request_id", "req_01J9Z3");
/// assert_eq!(metadata.len(), 2);
/// ```
///
/// # Rules
///
/// - **ZeroKMS does not verify the facts.** The application states them
///   and ZeroKMS records them as given. No key depends on them, so do not
///   use them for access control.
/// - **A decrypt does not need them.** A decrypt can send different facts
///   from the encrypt, or none.
/// - **Do not send plaintext or secrets.** ZeroKMS writes the facts to its
///   logs. Do not send anything derived from plaintext either. An IP
///   address or a user agent is personal data. This crate sends only what
///   you pass, and adds nothing.
/// - **A call sends one map.** A call can make more than one key request:
///   one to generate keys, and one to retrieve keys for each keyset it
///   decrypts values from. Each request is sent with the same facts. A call
///   that requests no data key sends none, and still succeeds: see
///   [`Audited`].
///
/// # Values
///
/// [`AuditValue`] lists the types that a value can have. ZeroKMS records
/// each value as you give it, with one exception: a float that is not
/// finite is sent as `null`. Metadata contains only those values, so
/// attaching it to a call cannot fail.
#[derive(Clone, Default, PartialEq)]
pub struct AuditMetadata {
    fields: UnverifiedContext,
}

impl AuditMetadata {
    /// Metadata with no facts. A call given empty metadata sends none.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the fact `key`. A fact already under that key is replaced.
    ///
    /// ```
    /// use stack_encrypt::AuditMetadata;
    ///
    /// let metadata = AuditMetadata::new()
    ///     .with("purpose", "export")
    ///     .with("rows", 250)
    ///     .with("tables", vec!["users", "orders"])
    ///     .with("filters", AuditMetadata::new().with("team", "platform"));
    /// assert_eq!(metadata.len(), 4);
    /// ```
    pub fn with(mut self, key: impl Into<String>, value: impl Into<AuditValue>) -> Self {
        // A fact already under this key is replaced, as documented.
        let _replaced = self.fields.0.insert(key.into(), value.into().0);
        self
    }

    /// The number of facts.
    pub fn len(&self) -> usize {
        self.fields.0.len()
    }

    /// Whether there are no facts. A call given empty metadata sends none.
    pub fn is_empty(&self) -> bool {
        self.fields.0.is_empty()
    }

    /// The metadata as ZeroKMS takes it, or `None` when there is nothing to
    /// send.
    pub(crate) fn into_unverified(self) -> Unverified {
        if self.fields.0.is_empty() {
            None
        } else {
            Some(Arc::new(self.fields))
        }
    }
}

/// Shows the keys and not the values. The values are the caller's facts.
/// A debug log is not the audit log.
impl fmt::Debug for AuditMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys = self.fields.0.keys().collect::<Vec<_>>();
        keys.sort();
        f.debug_struct("AuditMetadata")
            .field("keys", &keys)
            .finish()
    }
}

/// One value in [`AuditMetadata`].
///
/// ZeroKMS records each value as you give it. There is one exception: a
/// float that is not finite is sent as `null`. See [Numbers](#numbers).
///
/// You do not name this type. [`AuditMetadata::with`] converts to it from:
///
/// - a `bool`;
/// - text: `&str` or `String`;
/// - a float: `f32` or `f64`;
/// - an integer of type `i8`, `i16`, `i32`, `i64`, `u8`, `u16`, or `u32`;
/// - `None`, sent as JSON `null`;
/// - `Some` of any of these;
/// - a `Vec` of any of these;
/// - another [`AuditMetadata`], for a nested map.
///
/// # Numbers
///
/// ZeroKMS reads a number as a signed 64-bit integer or a 64-bit float.
/// A `u64` above `i64::MAX` fits neither exactly, so there is no conversion
/// from `u64`. Convert the number with `i64::try_from`, or send it as text.
///
/// ```
/// use stack_encrypt::AuditMetadata;
///
/// let rows: u64 = 250;
/// let metadata = AuditMetadata::new()
///     .with("rows", i64::try_from(rows).ok())
///     .with("cursor", u64::MAX.to_string());
/// assert_eq!(metadata.len(), 2);
/// ```
///
/// JSON has no form for a float that is not finite: `NaN` or an infinity.
/// That float is sent as `null`, so the audit log does not show which of
/// the three it was. To record that, send the float as text.
#[derive(Clone, PartialEq)]
pub struct AuditValue(Option<UnverifiedContextValue>);

/// Shows nothing of the value. The value is the caller's fact. A debug log
/// is not the audit log.
impl fmt::Debug for AuditValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditValue").finish_non_exhaustive()
    }
}

impl From<bool> for AuditValue {
    fn from(value: bool) -> Self {
        Self(Some(UnverifiedContextValue::Bool(value)))
    }
}

/// The integer types that always fit a signed 64-bit integer.
macro_rules! from_integer {
    ($($integer:ty),+) => {$(
        impl From<$integer> for AuditValue {
            fn from(value: $integer) -> Self {
                Self(Some(UnverifiedContextValue::I64(i64::from(value))))
            }
        }
    )+};
}
from_integer!(i8, i16, i32, i64, u8, u16, u32);

impl From<f64> for AuditValue {
    fn from(value: f64) -> Self {
        Self(
            value
                .is_finite()
                .then_some(UnverifiedContextValue::F64(value)),
        )
    }
}

impl From<f32> for AuditValue {
    fn from(value: f32) -> Self {
        Self::from(f64::from(value))
    }
}

impl From<String> for AuditValue {
    fn from(value: String) -> Self {
        Self(Some(UnverifiedContextValue::String(value)))
    }
}

impl From<&str> for AuditValue {
    fn from(value: &str) -> Self {
        Self::from(value.to_owned())
    }
}

/// `None` is sent as JSON `null`.
impl<T: Into<AuditValue>> From<Option<T>> for AuditValue {
    fn from(value: Option<T>) -> Self {
        Self(value.and_then(|value| value.into().0))
    }
}

impl<T: Into<AuditValue>> From<Vec<T>> for AuditValue {
    fn from(values: Vec<T>) -> Self {
        Self(Some(UnverifiedContextValue::List(
            values.into_iter().map(|value| value.into().0).collect(),
        )))
    }
}

/// A nested map of facts.
impl From<AuditMetadata> for AuditValue {
    fn from(metadata: AuditMetadata) -> Self {
        Self(Some(UnverifiedContextValue::Map(metadata.fields.0)))
    }
}

/// A call with [audit metadata](AuditMetadata) attached. `.audit(..)` on a
/// [`Pending`](crate::Pending) returns this type.
///
/// You can only await it. Awaiting runs the call, and sends the metadata
/// with every data-key request that the call makes.
///
/// # A call that requests no data key
///
/// ZeroKMS logs data-key requests, and the metadata is sent with those
/// requests. Some calls make none:
///
/// - a query term, because the cipher derives it from the index key of
///   the keyset;
/// - a record that has only terms and passthrough fields;
/// - a call over no values, such as an absent value (`None`) or an empty
///   list.
///
/// Such a call sends no metadata, and it still succeeds. ZeroKMS released
/// no data key for the call. So its log has no data-key request to add
/// the facts to, with or without metadata.
///
/// The last case depends on the data, not on the code. So an audited call
/// with nothing to send is not an error: a program that audits every
/// decrypt must not fail on an empty list.
///
/// # Attach the metadata once, last
///
/// An audited call has no `.audit(..)` and no `zip`. A batch does not take
/// an audited call. So you attach the metadata once, last, to the whole
/// call. A call cannot be given two different maps.
///
/// Merge the calls first, then attach the metadata:
///
/// ```
/// use stack_encrypt::{AuditMetadata, Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
/// let purpose = AuditMetadata::new().with("purpose", "import");
///
/// let (first, second): (Ciphertext, Ciphertext) = keyset
///     .encrypt(1i64)
///     .zip(keyset.encrypt(2i64))
///     .audit(purpose)
///     .await?;
/// # let _ = (first, second);
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
///
/// An audited call does not merge. The following code does not compile:
///
/// ```compile_fail
/// use stack_encrypt::{AuditMetadata, Ciphertext, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
/// let purpose = AuditMetadata::new().with("purpose", "import");
///
/// let (first, second): (Ciphertext, Ciphertext) = keyset
///     .encrypt(1i64)
///     .audit(purpose)
///     .zip(keyset.encrypt(2i64))
///     .await?;
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
#[must_use = "an audited call does nothing until it is awaited"]
pub struct Audited<C> {
    call: C,
    // Not named `audit`. With a field of that name, rustc reports a second
    // `.audit(..)` as "private field, not a method".
    metadata: Unverified,
}

impl<C> Audited<C> {
    /// Wrap `call`, so that its key requests are sent with `metadata`.
    pub(crate) fn new(call: C, metadata: AuditMetadata) -> Self {
        Self {
            call,
            metadata: metadata.into_unverified(),
        }
    }

    /// The call, and the metadata to send with its key requests.
    pub(crate) fn into_parts(self) -> (C, Unverified) {
        (self.call, self.metadata)
    }
}

/// Shows the call and nothing of the metadata.
impl<C: fmt::Debug> fmt::Debug for Audited<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Audited")
            .field("call", &self.call)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    /// What `metadata` sends, as JSON: `None` when it sends nothing.
    fn sent(metadata: AuditMetadata) -> Option<Value> {
        metadata
            .into_unverified()
            .map(|unverified| serde_json::to_value(&*unverified).unwrap())
    }

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
        assert_eq!(sent(AuditMetadata::new()), None);
        assert_eq!(
            sent(AuditMetadata::new().with("purpose", "export")),
            Some(json!({ "purpose": "export" }))
        );
    }

    #[test]
    fn every_kind_of_value_is_sent_as_given() {
        let metadata = AuditMetadata::new()
            .with("flag", true)
            .with("text", "list issues")
            .with("owned", String::from("req_01J9Z3"))
            .with("i8", i8::MIN)
            .with("i16", i16::MIN)
            .with("i32", i32::MIN)
            .with("i64", i64::MAX)
            .with("u8", u8::MAX)
            .with("u16", u16::MAX)
            .with("u32", u32::MAX)
            .with("f32", 0.5f32)
            .with("f64", 0.25)
            .with("null", None::<bool>)
            .with("some", Some(7))
            .with("list", vec![Some(1), None])
            .with("nested", AuditMetadata::new().with("team", "platform"));
        assert_eq!(
            sent(metadata),
            Some(json!({
                "flag": true,
                "text": "list issues",
                "owned": "req_01J9Z3",
                "i8": i8::MIN,
                "i16": i16::MIN,
                "i32": i32::MIN,
                "i64": i64::MAX,
                "u8": u8::MAX,
                "u16": u16::MAX,
                "u32": u32::MAX,
                "f32": 0.5,
                "f64": 0.25,
                "null": null,
                "some": 7,
                "list": [1, null],
                "nested": { "team": "platform" },
            }))
        );
    }

    #[test]
    fn a_float_that_is_not_finite_is_sent_as_null() {
        let metadata = AuditMetadata::new()
            .with("nan", f64::NAN)
            .with("infinity", f32::INFINITY)
            .with("finite", f64::MAX);
        assert_eq!(
            sent(metadata),
            Some(json!({ "nan": null, "infinity": null, "finite": f64::MAX }))
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
    fn debug_shows_keys_not_values() {
        let metadata = AuditMetadata::new()
            .with("user", "alice@example.com")
            .with("purpose", "export");
        assert_eq!(
            format!("{metadata:?}"),
            r#"AuditMetadata { keys: ["purpose", "user"] }"#
        );
        assert_eq!(
            format!("{:?}", AuditValue::from("alice@example.com")),
            "AuditValue { .. }"
        );
        let audited = format!("{:?}", Audited::new("the call", metadata));
        assert_eq!(audited, r#"Audited { call: "the call", .. }"#);
    }
}
