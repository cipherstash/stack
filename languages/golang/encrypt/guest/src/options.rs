//! The per-call options object, and the keyset selector it carries.
//!
//! Every export that touches a keyset takes one more codec-encoded
//! argument: a frame object with one required key, `keyset`, whose
//! value is a tagged object naming the keyset the call binds to, and on
//! `se_decrypt_record` one optional key, `context` (below):
//!
//! | selector          | meaning |
//! |-------------------|---------|
//! | `{"default": {}}` | the cipher's default keyset (the one named at `se_cipher_init`, else the client's) |
//! | `{"name": <string>}` | the keyset with that name, loaded on first use |
//! | `{"id": <16 bytes>}` | the keyset with that id (raw UUID bytes), loaded on first use |
//! | `{"any": {}}`     | **decrypt only**: open leaves from whichever keyset each was sealed under, one batched retrieval per keyset (chunked at the client's request limit, 500 keys) |
//!
//! Every variant is spelled; there is no zero-length or omitted-field
//! sentinel, so a host that means the default says so. A name is validated
//! at parse (ZeroKMS's own rules for keyset names), so a malformed
//! selector is refused before the cipher is consulted. On the sealing and
//! term exports the selector picks the keyset that mints; on the opening
//! exports it is a *constraint*: `{"name"}`, `{"id"}` and `{"default"}`
//! refuse a leaf sealed under any other keyset before any key is retrieved
//! ([`STATUS_FOREIGN_KEYSET`](crate::status::STATUS_FOREIGN_KEYSET)), and `{"any"}` lifts the constraint. `{"any"}`
//! on a sealing or term export is [`STATUS_ENCODING`]: there is no keyset
//! to mint under. Anything else — another key, a second key, a wrong value
//! type, an id that is not 16 bytes — is [`STATUS_ENCODING`].
//!
//! `context` is the context the host expects a record's context field to
//! hold, for a plan that takes its context from a field (the plan-level
//! `"context_field"` key of `dynamic::record::plan`): a string that parses
//! as a plain label, `"tenants/acme"`, which the engine checks against each
//! record's stored context field before any key is retrieved and refuses
//! with [`STATUS_CONTEXT_MISMATCH`](crate::status::STATUS_CONTEXT_MISMATCH).
//! Omitted, each record opens under the context it stores. It is the data
//! form of the Rust chain's `open(record).context(expected)`. On
//! `se_encrypt_record` and `se_term` it is [`STATUS_ENCODING`]: a plan that
//! names a context field reads the context from each value when it seals,
//! and a term's context arrives as its own argument. A `context` that is
//! not a string, or not a plain label, is [`STATUS_ENCODING`] too.
//!
//! This object is a cross-language contract: every binding builds it, so
//! it is objects, strings, bytes and nothing else, and this module is its
//! one home. The Go bindings plan points here.

use stack_encrypt::dynamic::Scope;
use stack_encrypt::{KeysetCipher, Label, StackCipher};
use stack_kms::{IdentifiedBy, IndexKeySource};
use uuid::Uuid;
use zerokms_protocol::Name;

use stack_encrypt::dynamic::frame::serde::from_slice;
use stack_guest_abi::last_error::malformed;

use crate::status::fail_error;
#[cfg(any(doc, test))]
use crate::status::STATUS_ENCODING;

/// Which keyset a call binds to. See the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetSelector {
    /// The cipher's default keyset.
    Default,
    /// A keyset by name, already validated against ZeroKMS's naming rules.
    Name(Name),
    /// A keyset by id.
    Id(Uuid),
    /// Whichever keyset each leaf was sealed under; opening only.
    Any,
}

/// Which side of the boundary an options object is parsed for: the sealing
/// and term exports need a keyset to mint under, so `{"any"}` is refused
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// `se_encrypt_record`, `se_term`.
    Mint,
    /// `se_decrypt_record`.
    Open,
}

/// The parsed options object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub keyset: KeysetSelector,
    /// The context the host expects a record's context field to hold;
    /// opening only. See the [module docs](self).
    pub context: Option<Label>,
}

/// Parse the options frame a host sent for `side`. Anything outside the
/// shape in the [module docs](self) is [`STATUS_ENCODING`], with a message
/// that names what was wrong and never a value.
pub fn parse_options(bytes: &[u8], side: Side) -> Result<Options, u32> {
    let wire: wire::Options =
        from_slice(bytes).map_err(|e| malformed(format!("the options: {e}")))?;
    let keyset = KeysetSelector::from(wire.keyset);
    if side == Side::Mint {
        if wire.context.is_some() {
            return Err(malformed(
                r#"the "context" option is for decrypting a record only"#,
            ));
        }
        if keyset == KeysetSelector::Any {
            return Err(malformed(r#"{"any"} names no keyset to encrypt under"#));
        }
    }
    Ok(Options {
        keyset,
        context: wire.context.map(|context| context.0),
    })
}

/// Parse a bare keyset selector frame, as `se_keyset` takes it. One
/// definition, `wire::Selector`, serves this and [`parse_options`].
pub fn parse_selector(bytes: &[u8]) -> Result<KeysetSelector, u32> {
    from_slice::<wire::Selector>(bytes)
        .map(KeysetSelector::from)
        .map_err(|e| malformed(format!("a keyset selector: {e}")))
}

/// The options and the selector as a host writes them, read straight from
/// the frame by serde (`vitaminc_aead_frame::serde`). Each field type
/// validates as it reads, through `TryFrom`, so a parsed value is already
/// the guest's. The frame's serde never repeats a `TryFrom` error's text,
/// so a refusal names the key and says only that its value was not
/// accepted; each error here is still a fixed string, for the reader.
mod wire {
    use serde::{Deserialize, Deserializer};
    use stack_encrypt::Label;
    use uuid::Uuid;
    use zerokms_protocol::Name;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Options {
        pub(super) keyset: Selector,
        /// Absent is `None`. Present, it must be a label: a null is refused
        /// like any other non-string, as it always has been.
        #[serde(default, deserialize_with = "present")]
        pub(super) context: Option<ContextLabel>,
    }

    fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        d: D,
    ) -> Result<Option<T>, D::Error> {
        T::deserialize(d).map(Some)
    }

    /// Every variant is spelled; the payload of `default` and `any` is an
    /// empty object.
    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase", deny_unknown_fields)]
    pub(super) enum Selector {
        Default {},
        Any {},
        Name(KeysetName),
        Id(KeysetId),
    }

    impl From<Selector> for super::KeysetSelector {
        fn from(selector: Selector) -> Self {
            match selector {
                Selector::Default {} => Self::Default,
                Selector::Any {} => Self::Any,
                Selector::Name(KeysetName(name)) => Self::Name(name),
                Selector::Id(KeysetId(id)) => Self::Id(id),
            }
        }
    }

    /// A keyset name, checked against ZeroKMS's naming rules here at the
    /// boundary, not at resolution.
    #[derive(Deserialize)]
    #[serde(try_from = "&str")]
    pub(super) struct KeysetName(Name);

    impl TryFrom<&str> for KeysetName {
        type Error = &'static str;

        fn try_from(name: &str) -> Result<Self, Self::Error> {
            Name::try_from(name)
                .map(KeysetName)
                .map_err(|_| "a keyset name that breaks ZeroKMS's naming rules")
        }
    }

    /// A keyset id: exactly 16 bytes, a UUID's raw form.
    #[derive(Deserialize)]
    #[serde(try_from = "&[u8]")]
    pub(super) struct KeysetId(Uuid);

    impl TryFrom<&[u8]> for KeysetId {
        type Error = &'static str;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            Uuid::from_slice(bytes)
                .map(KeysetId)
                .map_err(|_| "a keyset id that is not 16 bytes")
        }
    }

    /// The context a host expects a record's context field to hold: a
    /// string that parses as a plain label.
    #[derive(Deserialize)]
    #[serde(try_from = "&str")]
    pub(super) struct ContextLabel(pub(super) Label);

    impl TryFrom<&str> for ContextLabel {
        type Error = &'static str;

        fn try_from(text: &str) -> Result<Self, Self::Error> {
            Label::parse(text)
                .map(ContextLabel)
                .map_err(|_| "a context that is not a plain label")
        }
    }
}

impl KeysetSelector {
    /// The keyset this selector names, as the cipher resolves it: the
    /// default without a round trip, a name or id through the cipher's
    /// cache (a first use is one `load-keyset` call). `Any` is not a keyset
    /// and is [`STATUS_ENCODING`] here; opening exports resolve it through
    /// [`scope_for`] instead.
    pub async fn resolve<'c, K>(
        &self,
        cipher: &'c StackCipher<K>,
    ) -> Result<KeysetCipher<'c, K>, u32>
    where
        K: IndexKeySource,
    {
        let by: IdentifiedBy = match self {
            KeysetSelector::Default => return Ok(cipher.default_keyset()),
            KeysetSelector::Any => return Err(malformed(r#"{"any"} is not a keyset"#)),
            KeysetSelector::Name(name) => IdentifiedBy::Name(name.clone()),
            KeysetSelector::Id(id) => IdentifiedBy::Uuid(*id),
        };
        cipher.keyset(by).await.map_err(|e| fail_error(&e))
    }
}

/// The [`Scope`] a decrypt-side selector names: the client for `{"any"}`,
/// which opens a leaf sealed under any of its keysets, or one keyset's
/// cipher, which opens only its own and refuses the rest before any key is
/// retrieved.
pub async fn scope_for<'c, K>(
    cipher: &'c StackCipher<K>,
    selector: &KeysetSelector,
) -> Result<Scope<'c, K>, u32>
where
    K: IndexKeySource,
{
    match selector {
        KeysetSelector::Any => Ok(Scope::Client(cipher)),
        other => other.resolve(cipher).await.map(Scope::Keyset),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_frame::{empty, frame, obj, V};

    fn options(selector: V) -> V {
        obj(vec![("keyset", selector)])
    }

    fn selector(v: V) -> Result<KeysetSelector, u32> {
        parse_selector(&frame(&v))
    }

    fn opts(v: V, side: Side) -> Result<Options, u32> {
        parse_options(&frame(&v), side)
    }

    #[test]
    fn every_selector_variant_is_spelled() {
        let id = Uuid::from_u128(7);
        assert_eq!(
            selector(obj(vec![("default", empty())])),
            Ok(KeysetSelector::Default)
        );
        assert_eq!(
            selector(obj(vec![("any", empty())])),
            Ok(KeysetSelector::Any)
        );
        assert_eq!(
            selector(obj(vec![("name", V::Str("acme".into()))])),
            Ok(KeysetSelector::Name(
                Name::try_from("acme").ok().expect("valid name")
            ))
        );
        assert_eq!(
            selector(obj(vec![("id", V::Bytes(id.as_bytes().to_vec()))])),
            Ok(KeysetSelector::Id(id))
        );
    }

    #[test]
    fn a_selector_is_exactly_one_known_tag_with_the_right_payload() {
        for (label, bad) in [
            ("an empty object", empty()),
            ("a string", V::Str("default".into())),
            ("null", V::Null),
            ("an unknown tag", obj(vec![("primary", empty())])),
            (
                "two tags",
                obj(vec![("default", empty()), ("any", empty())]),
            ),
            (
                "default with a payload",
                obj(vec![("default", V::Bool(true))]),
            ),
            (
                "default with fields",
                obj(vec![("default", obj(vec![("x", empty())]))]),
            ),
            (
                "a name that is not a string",
                obj(vec![("name", V::U64(1))]),
            ),
            ("an empty name", obj(vec![("name", V::Str("".into()))])),
            (
                "a name past ZeroKMS's 64-byte limit",
                obj(vec![("name", V::Str("x".repeat(65)))]),
            ),
            (
                "an id that is not 16 bytes",
                obj(vec![("id", V::Bytes(vec![1, 2, 3]))]),
            ),
            (
                "a 16-byte id sent as text",
                obj(vec![("id", V::Str("0123456789abcdef".into()))]),
            ),
            (
                "a name sent as bytes",
                obj(vec![("name", V::Bytes(b"acme".to_vec()))]),
            ),
            (
                "a selector sent as an array",
                V::Arr(vec![obj(vec![("name", V::Str("acme".into()))])]),
            ),
            (
                "an id as text",
                obj(vec![(
                    "id",
                    V::Str("00000000-0000-0000-0000-000000000007".into()),
                )]),
            ),
        ] {
            assert_eq!(
                selector(bad).err(),
                Some(STATUS_ENCODING),
                "{label} is not a selector and must be refused"
            );
        }
    }

    /// Options sent as an array are refused: the frame reads them only from
    /// an object, never by position.
    #[test]
    fn options_sent_as_an_array_are_refused() {
        let positional = V::Arr(vec![obj(vec![("name", V::Str("acme".into()))])]);
        assert_eq!(opts(positional, Side::Open), Err(STATUS_ENCODING));
    }

    #[test]
    fn options_are_one_keyset_key() {
        assert_eq!(
            opts(options(obj(vec![("default", empty())])), Side::Mint),
            Ok(Options {
                keyset: KeysetSelector::Default,
                context: None,
            })
        );
        for (label, bad) in [
            ("no keyset", empty()),
            ("not an object", V::Null),
            (
                "an unknown key beside it",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("mode", V::Bool(true)),
                ]),
            ),
            (
                "keyset twice",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("keyset", obj(vec![("default", empty())])),
                ]),
            ),
        ] {
            assert_eq!(
                opts(bad, Side::Open).err(),
                Some(STATUS_ENCODING),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn an_expected_context_is_an_opening_option_only() {
        let with = |context: V| {
            obj(vec![
                ("keyset", obj(vec![("default", empty())])),
                ("context", context),
            ])
        };
        assert_eq!(
            opts(with(V::Str("tenants/acme".into())), Side::Open),
            Ok(Options {
                keyset: KeysetSelector::Default,
                context: Some(Label::parse("tenants/acme").expect("a label")),
            })
        );
        for (label, bad, side) in [
            (
                "on the sealing side",
                with(V::Str("tenants/acme".into())),
                Side::Mint,
            ),
            ("not a string", with(V::U64(7)), Side::Open),
            (
                "not a plain label",
                with(V::Str("tenants/(acme)".into())),
                Side::Open,
            ),
            ("empty", with(V::Str("".into())), Side::Open),
            (
                "given twice",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("context", V::Str("a".into())),
                    ("context", V::Str("a".into())),
                ]),
                Side::Open,
            ),
        ] {
            assert_eq!(
                opts(bad, side).err(),
                Some(STATUS_ENCODING),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn any_is_an_opening_selector_only() {
        let any = || options(obj(vec![("any", empty())]));
        assert_eq!(
            opts(any(), Side::Open),
            Ok(Options {
                keyset: KeysetSelector::Any,
                context: None,
            })
        );
        assert_eq!(opts(any(), Side::Mint).err(), Some(STATUS_ENCODING));
    }
}
