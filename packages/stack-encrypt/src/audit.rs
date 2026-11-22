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

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

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
///
/// # From data
///
/// A language binding has the facts as data, not as Rust values. For that
/// case, `AuditMetadata` implements serde's `Deserialize`. It reads a map
/// that has text keys, from any serde format.
///
/// ```
/// use serde_json::json;
/// use stack_encrypt::AuditMetadata;
///
/// let metadata: AuditMetadata = serde_json::from_value(json!({
///     "purpose": "export",
///     "rows": 250,
///     "tables": ["users", "orders"],
/// }))?;
/// let built = AuditMetadata::new()
///     .with("purpose", "export")
///     .with("rows", 250)
///     .with("tables", vec!["users", "orders"]);
/// assert_eq!(metadata, built);
/// # Ok::<(), serde_json::Error>(())
/// ```
///
/// A value in the data follows the rules of [`AuditValue`]. Five kinds of
/// data are refused, because ZeroKMS has no form for them:
///
/// - data that is not a map, at the top level;
/// - bytes;
/// - an integer that does not fit a signed 64-bit integer;
/// - a key that is not text;
/// - a key that appears twice in one map.
///
/// The message of this reader names the kind of data that was refused. The
/// message does not show a key or a value.
///
/// One limit comes from the format, and not from this reader. `serde_json`
/// reads a JSON number above `u64::MAX` as a float, before this reader sees
/// the number. So that number is sent as a float, and it is not refused.
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

/// Reads metadata from a map that has text keys. The type documents the
/// rules, under "From data".
impl<'de> Deserialize<'de> for AuditMetadata {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `deserialize_any`, not `deserialize_map`: asked for a map, a format
        // that holds another kind of data writes the error itself, and
        // serde_json's shows the data. Asked for anything, the format hands
        // the data to the visitor, which refuses it without showing it.
        deserializer.deserialize_any(MetadataVisitor)
    }
}

/// Refuse the scalars that serde's own message would show. For a scalar
/// that a visitor does not take, serde's default error prints the scalar:
/// `invalid type: string "..."`. Each method here gives `$message` in its
/// place. serde's defaults pass the narrower integers, `f32`, a `char` and
/// owned or borrowed text to these methods. Its messages for the other
/// kinds (null, bytes, a list, a map) name the kind and show no content.
macro_rules! refuse_without_showing {
    ($message:expr; $($method:ident($scalar:ty)),+ $(,)?) => {$(
        fn $method<E: de::Error>(self, _: $scalar) -> Result<Self::Value, E> {
            Err(E::custom($message))
        }
    )+};
}

/// The message for top-level data that is a scalar.
const NOT_A_MAP: &str = "a scalar where a map of audit metadata belongs";

/// Reads the top-level map. Anything else is refused, `null` included.
struct MetadataVisitor;

impl<'de> Visitor<'de> for MetadataVisitor {
    type Value = AuditMetadata;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map of audit metadata")
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<AuditMetadata, A::Error> {
        read_map(map)
    }

    refuse_without_showing! {
        NOT_A_MAP;
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_i128(i128),
        visit_u128(u128), visit_f64(f64), visit_str(&str),
    }
}

/// Read one map of facts. A key that appears twice is refused: the builder
/// replaces a fact on purpose, but data that names a key twice is a mistake
/// in the sender.
fn read_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<AuditMetadata, A::Error> {
    let mut metadata = AuditMetadata::new();
    while let Some(Key(key)) = map.next_key()? {
        let Fact(value) = map.next_value()?;
        if metadata.fields.0.insert(key, value.0).is_some() {
            return Err(de::Error::custom("a key that appears twice in one map"));
        }
    }
    Ok(metadata)
}

/// The message for a key that is a scalar other than text.
const KEY_NOT_TEXT: &str = "a key that is not text";

/// One key of a map of facts: text, and nothing else.
struct Key(String);

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // `deserialize_any`, for the reason [`AuditMetadata`]'s reader
        // gives.
        deserializer.deserialize_any(KeyVisitor).map(Key)
    }
}

struct KeyVisitor;

impl Visitor<'_> for KeyVisitor {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a text key")
    }

    fn visit_str<E: de::Error>(self, key: &str) -> Result<String, E> {
        Ok(key.to_owned())
    }

    fn visit_string<E: de::Error>(self, key: String) -> Result<String, E> {
        Ok(key)
    }

    refuse_without_showing! {
        KEY_NOT_TEXT;
        visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_i128(i128),
        visit_u128(u128), visit_f64(f64),
    }
}

/// One value, read from data.
struct Fact(AuditValue);

impl<'de> Deserialize<'de> for Fact {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(FactVisitor).map(Fact)
    }
}

/// The message for an integer that ZeroKMS cannot read exactly. It does not
/// show the integer: serde's own message would.
const INTEGER_TOO_WIDE: &str = "an integer that does not fit a signed 64-bit integer";

/// Reads one value. Each method goes through the same `From` conversion
/// that [`AuditMetadata::with`] uses, so data and Rust values follow one
/// set of rules. serde's defaults pass the narrower integers to
/// `visit_i64` and `visit_u64`, and `f32` to `visit_f64`. Bytes have no
/// method here, so serde's default refuses them.
struct FactVisitor;

impl<'de> Visitor<'de> for FactVisitor {
    type Value = AuditValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bool, an integer, a float, text, null, a list or a map")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<AuditValue, E> {
        Ok(AuditValue::from(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<AuditValue, E> {
        Ok(AuditValue::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<AuditValue, E> {
        i64::try_from(value)
            .map(AuditValue::from)
            .map_err(|_| E::custom(INTEGER_TOO_WIDE))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<AuditValue, E> {
        i64::try_from(value)
            .map(AuditValue::from)
            .map_err(|_| E::custom(INTEGER_TOO_WIDE))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<AuditValue, E> {
        i64::try_from(value)
            .map(AuditValue::from)
            .map_err(|_| E::custom(INTEGER_TOO_WIDE))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<AuditValue, E> {
        Ok(AuditValue::from(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<AuditValue, E> {
        Ok(AuditValue::from(value))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<AuditValue, E> {
        Ok(AuditValue::from(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<AuditValue, E> {
        Ok(AuditValue(None))
    }

    fn visit_none<E: de::Error>(self) -> Result<AuditValue, E> {
        Ok(AuditValue(None))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<AuditValue, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<AuditValue, A::Error> {
        let mut values = Vec::new();
        while let Some(Fact(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(AuditValue::from(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<AuditValue, A::Error> {
        read_map(map).map(AuditValue::from)
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

    /// The same metadata, on the call `wrap` makes of this one: what
    /// attaching a credential to an audited call does.
    pub(crate) fn rewrap<D>(self, wrap: impl FnOnce(C) -> D) -> Audited<D> {
        Audited {
            call: wrap(self.call),
            metadata: self.metadata,
        }
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

    // ---- from data -------------------------------------------------------

    /// `value` as a frame, the form a language binding sends, read back as
    /// metadata.
    fn from_frame<T: serde::Serialize>(value: &T) -> Result<AuditMetadata, String> {
        use crate::AsProtectedRef as _;
        let frame = vitaminc_aead_frame::serde::to_vec(value).expect("the value is a frame");
        // `risky_ref`: the reader takes plain bytes, and the frame holds this
        // test's own values, which are not secret.
        vitaminc_aead_frame::serde::from_slice(frame.as_protected_ref().risky_ref())
            .map_err(|e| e.to_string())
    }

    /// One entry, `{"fact": value}`, as a frame.
    fn fact<T: serde::Serialize>(value: T) -> Result<AuditMetadata, String> {
        from_frame(&std::collections::BTreeMap::from([("fact", value)]))
    }

    /// Bytes, written as a frame's bytes leaf and not as a list of integers.
    struct Bytes<'a>(&'a [u8]);

    impl serde::Serialize for Bytes<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.0)
        }
    }

    fn every_kind() -> Value {
        json!({
            "flag": true,
            "text": "list issues",
            "negative": -7,
            "positive": 250,
            "float": 0.25,
            "null": null,
            "list": [1, null, "two", [3]],
            "nested": { "team": "platform", "deeper": { "rows": 2 } },
        })
    }

    fn every_kind_built() -> AuditMetadata {
        AuditMetadata::new()
            .with("flag", true)
            .with("text", "list issues")
            .with("negative", -7)
            .with("positive", 250)
            .with("float", 0.25)
            .with("null", None::<bool>)
            .with(
                "list",
                vec![
                    AuditValue::from(1),
                    AuditValue::from(None::<bool>),
                    AuditValue::from("two"),
                    AuditValue::from(vec![3]),
                ],
            )
            .with(
                "nested",
                AuditMetadata::new()
                    .with("team", "platform")
                    .with("deeper", AuditMetadata::new().with("rows", 2)),
            )
    }

    #[test]
    fn data_reads_as_the_builder_builds() {
        // Owned text, borrowed text, and a frame: the three ways text and
        // numbers reach the reader.
        let owned: AuditMetadata = serde_json::from_value(every_kind()).unwrap();
        assert_eq!(owned, every_kind_built());
        let text = every_kind().to_string();
        let borrowed: AuditMetadata = serde_json::from_str(&text).unwrap();
        assert_eq!(borrowed, every_kind_built());
        assert_eq!(from_frame(&every_kind()), Ok(every_kind_built()));
        // What is read is what is sent.
        assert_eq!(sent(owned), Some(every_kind()));
    }

    #[test]
    fn an_empty_map_reads_as_empty_metadata() {
        let empty: AuditMetadata = serde_json::from_value(json!({})).unwrap();
        assert!(empty.is_empty());
        assert_eq!(sent(empty), None);
    }

    #[test]
    fn an_integer_of_any_width_is_read_when_it_fits() {
        let max = AuditMetadata::new().with("fact", i64::MAX);
        let min = AuditMetadata::new().with("fact", i64::MIN);
        assert_eq!(
            fact(i8::MIN),
            Ok(AuditMetadata::new().with("fact", i8::MIN))
        );
        assert_eq!(
            fact(u32::MAX),
            Ok(AuditMetadata::new().with("fact", u32::MAX))
        );
        assert_eq!(fact(i64::MIN), Ok(min.clone()));
        assert_eq!(fact(i64::MAX.unsigned_abs()), Ok(max.clone()));
        assert_eq!(fact(i128::from(i64::MIN)), Ok(min));
        assert_eq!(fact(u128::from(i64::MAX.unsigned_abs())), Ok(max));
    }

    #[test]
    fn an_integer_that_does_not_fit_is_refused_and_not_shown() {
        let above = i64::MAX.unsigned_abs() + 1;
        let refused = [
            (fact(above), above.to_string()),
            (fact(u64::MAX), u64::MAX.to_string()),
            (fact(i128::from(above)), above.to_string()),
            (
                fact(i128::from(i64::MIN) - 1),
                (i128::from(i64::MIN) - 1).to_string(),
            ),
            (fact(u128::MAX), u128::MAX.to_string()),
        ];
        for (result, integer) in refused {
            let message = result.expect_err("the integer does not fit");
            assert!(!message.contains(&integer), "{message}");
        }
        // A frame's reader gives one fixed message for a refused value. JSON
        // passes on the reader's own message, so that message is checked here.
        let json = serde_json::from_value::<AuditMetadata>(json!({ "fact": u64::MAX }));
        let message = json.expect_err("the integer does not fit").to_string();
        assert!(message.contains(INTEGER_TOO_WIDE), "{message}");
        assert!(!message.contains(&u64::MAX.to_string()), "{message}");
    }

    #[test]
    fn a_float_follows_the_rules_of_the_builder() {
        assert_eq!(fact(0.5f32), Ok(AuditMetadata::new().with("fact", 0.5f32)));
        assert_eq!(fact(0.25f64), Ok(AuditMetadata::new().with("fact", 0.25)));
        let null = AuditMetadata::new().with("fact", None::<bool>);
        assert_eq!(fact(f64::NAN), Ok(null.clone()));
        assert_eq!(fact(f32::INFINITY), Ok(null.clone()));
        assert_eq!(fact(f64::NEG_INFINITY), Ok(null));
    }

    #[test]
    fn bytes_are_refused_and_not_shown() {
        let message = fact(Bytes(b"secret")).expect_err("bytes have no form");
        assert!(!message.contains("secret"), "{message}");
        let in_a_list = fact(vec![Bytes(b"secret")]).expect_err("bytes have no form");
        assert!(!in_a_list.contains("secret"), "{in_a_list}");
        // A frame's reader gives one fixed message. serde's own reader of
        // bytes passes on this reader's words.
        let bytes = serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(b"secret");
        let message = Fact::deserialize(bytes)
            .map(|_| ())
            .expect_err("bytes have no form")
            .to_string();
        assert!(message.contains("a bool, an integer, a float"), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    #[test]
    fn a_key_that_appears_twice_is_refused() {
        for text in [
            r#"{ "purpose": "first", "purpose": "second" }"#,
            r#"{ "nested": { "purpose": "first", "purpose": "second" } }"#,
            r#"{ "list": [{ "purpose": "first", "purpose": "second" }] }"#,
        ] {
            let message = serde_json::from_str::<AuditMetadata>(text)
                .expect_err("the key appears twice")
                .to_string();
            assert!(message.contains("a key that appears twice"), "{message}");
            assert!(!message.contains("first") && !message.contains("second"));
        }
        // The same key in two different maps is two facts.
        let apart = r#"{ "purpose": "a", "nested": { "purpose": "b" } }"#;
        assert_eq!(
            serde_json::from_str::<AuditMetadata>(apart).unwrap().len(),
            2
        );
    }

    #[test]
    fn only_a_map_is_metadata_and_the_error_does_not_show_the_data() {
        // Each value holds a marker, as text or as digits. No message may
        // show one.
        let shown = ["marker", "424242"];
        for not_a_map in [
            json!(null),
            json!(["marker", 424242]),
            json!("marker"),
            json!(424242),
            json!(-424242),
            json!(424242.5),
            json!(true),
        ] {
            let owned = serde_json::from_value::<AuditMetadata>(not_a_map.clone())
                .expect_err("not a map")
                .to_string();
            let text = not_a_map.to_string();
            let borrowed = serde_json::from_str::<AuditMetadata>(&text)
                .expect_err("not a map")
                .to_string();
            for message in [owned, borrowed] {
                assert!(message.contains("a map of audit metadata"), "{message}");
                assert!(!shown.iter().any(|s| message.contains(s)), "{message}");
                assert!(!message.contains("true"), "{message}");
            }
        }
        // The wide integers and one character reach the same refusal.
        use serde::de::value::{CharDeserializer, Error, I128Deserializer, U128Deserializer};
        let wide = [
            AuditMetadata::deserialize(I128Deserializer::<Error>::new(-424242)),
            AuditMetadata::deserialize(U128Deserializer::<Error>::new(424242)),
            AuditMetadata::deserialize(CharDeserializer::<Error>::new('q')),
        ];
        for result in wide {
            let message = result.expect_err("not a map").to_string();
            assert_eq!(message, NOT_A_MAP);
        }
        assert!(from_frame(&None::<bool>).is_err());
        assert!(from_frame(&"marker").is_err());
    }

    #[test]
    fn a_key_that_is_not_text_is_refused_and_not_shown() {
        use serde::de::value::{Error, MapDeserializer};
        fn refused<'de, K>(key: K) -> String
        where
            K: serde::de::IntoDeserializer<'de, Error>,
        {
            let map = MapDeserializer::<_, Error>::new(std::iter::once((key, true)));
            AuditMetadata::deserialize(map)
                .expect_err("the key is not text")
                .to_string()
        }
        for message in [
            refused(424242u64),
            refused(-424242i64),
            refused(424242i128),
            refused(424242u128),
            refused(424242.5f64),
            refused(true),
        ] {
            assert_eq!(message, KEY_NOT_TEXT);
        }
        // serde's own message for a key of another kind names the kind, and
        // says what the reader takes.
        let unit = refused(());
        assert!(unit.contains("a text key"), "{unit}");
        // Text keys are read, owned or borrowed.
        let owned = MapDeserializer::<_, Error>::new(std::iter::once((String::from("k"), true)));
        let borrowed = MapDeserializer::<_, Error>::new(std::iter::once(("k", true)));
        let want = AuditMetadata::new().with("k", true);
        assert_eq!(AuditMetadata::deserialize(owned).unwrap(), want);
        assert_eq!(AuditMetadata::deserialize(borrowed).unwrap(), want);
    }

    #[test]
    fn serde_json_reads_a_number_above_u64_as_a_float() {
        // The limit the type documents: serde_json gives this reader a
        // float, so the reader cannot refuse the number as an integer.
        let wide: AuditMetadata =
            serde_json::from_str(r#"{ "fact": 99999999999999999999999 }"#).unwrap();
        assert_eq!(wide, AuditMetadata::new().with("fact", 1e23));
    }

    #[test]
    fn an_optional_value_reads_as_the_value_or_as_null() {
        use serde::de::value::Error;
        let none = FactVisitor.visit_none::<Error>().unwrap();
        assert_eq!(none, AuditValue::from(None::<bool>));
        let some = FactVisitor.visit_some(json!(7)).unwrap();
        assert_eq!(some, AuditValue::from(7));
    }
}
