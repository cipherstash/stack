//! The per-call options object, and the keyset selector it carries.
//!
//! Every export that touches a keyset takes one more codec-encoded
//! argument: an [`FfiValue::Object`] with exactly one key, `keyset`, whose
//! value is a tagged object naming the keyset the call binds to:
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
//! This object is a cross-language contract: every binding builds it, so
//! it is objects, strings, bytes and nothing else, and this module is its
//! one home. The Go bindings plan points here.

use stack_encrypt::dynamic::Scope;
use stack_encrypt::{KeysetCipher, StackCipher};
use stack_kms::{IdentifiedBy, IndexKeySource};
use uuid::Uuid;
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::Controlled;
use zerokms_protocol::Name;

use crate::status::{status_for_error, STATUS_ENCODING};

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
}

/// Parse a decoded options object for `side`. Anything outside the shape in
/// the [module docs](self) is [`STATUS_ENCODING`].
pub fn parse_options(value: FfiValue, side: Side) -> Result<Options, u32> {
    let FfiValue::Object(entries) = value else {
        return Err(STATUS_ENCODING);
    };
    let mut keyset: Option<KeysetSelector> = None;
    for (key, value) in entries {
        match key.as_str() {
            "keyset" if keyset.is_none() => keyset = Some(parse_selector(value)?),
            _ => return Err(STATUS_ENCODING),
        }
    }
    let keyset = keyset.ok_or(STATUS_ENCODING)?;
    if side == Side::Mint && keyset == KeysetSelector::Any {
        return Err(STATUS_ENCODING);
    }
    Ok(Options { keyset })
}

/// Parse a keyset selector: a tagged object with exactly one key. Spelled
/// out here rather than in [`parse_options`] so `se_keyset`, which takes a
/// bare selector, shares the one definition.
pub fn parse_selector(value: FfiValue) -> Result<KeysetSelector, u32> {
    let FfiValue::Object(mut entries) = value else {
        return Err(STATUS_ENCODING);
    };
    if entries.len() != 1 {
        return Err(STATUS_ENCODING);
    }
    let (tag, value) = entries.pop().ok_or(STATUS_ENCODING)?;
    Ok(match (tag.as_str(), value) {
        ("default", FfiValue::Object(fields)) if fields.is_empty() => KeysetSelector::Default,
        ("any", FfiValue::Object(fields)) if fields.is_empty() => KeysetSelector::Any,
        ("name", FfiValue::String(name)) => {
            // Valid UTF-8 by `Utf8String`'s construction invariant; checked
            // rather than assumed because this is boundary code. A keyset
            // name is not secret, so the payload moves out of its
            // `Protected` rather than being copied and wiped. ZeroKMS's
            // naming rules apply here, at the boundary, not at resolution.
            let name =
                String::from_utf8(name.into_inner().risky_unwrap()).map_err(|_| STATUS_ENCODING)?;
            KeysetSelector::Name(Name::try_from(name.as_str()).map_err(|_| STATUS_ENCODING)?)
        }
        ("id", FfiValue::Bytes(bytes)) => {
            KeysetSelector::Id(Uuid::from_slice(bytes.risky_ref()).map_err(|_| STATUS_ENCODING)?)
        }
        _ => return Err(STATUS_ENCODING),
    })
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
            KeysetSelector::Any => return Err(STATUS_ENCODING),
            KeysetSelector::Name(name) => IdentifiedBy::Name(name.clone()),
            KeysetSelector::Id(id) => IdentifiedBy::Uuid(*id),
        };
        cipher.keyset(by).await.map_err(|e| status_for_error(&e))
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
    use vitaminc_protected::Protected;

    fn obj(entries: Vec<(&str, FfiValue)>) -> FfiValue {
        FfiValue::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    fn options(selector: FfiValue) -> FfiValue {
        obj(vec![("keyset", selector)])
    }

    fn empty() -> FfiValue {
        FfiValue::Object(Vec::new())
    }

    #[test]
    fn every_selector_variant_is_spelled() {
        let id = Uuid::from_u128(7);
        assert_eq!(
            parse_selector(obj(vec![("default", empty())])),
            Ok(KeysetSelector::Default)
        );
        assert_eq!(
            parse_selector(obj(vec![("any", empty())])),
            Ok(KeysetSelector::Any)
        );
        assert_eq!(
            parse_selector(obj(vec![("name", FfiValue::String("acme".into()))])),
            Ok(KeysetSelector::Name(
                Name::try_from("acme").ok().expect("valid name")
            ))
        );
        assert_eq!(
            parse_selector(obj(vec![(
                "id",
                FfiValue::Bytes(Protected::new(id.as_bytes().to_vec()))
            )])),
            Ok(KeysetSelector::Id(id))
        );
    }

    #[test]
    fn a_selector_is_exactly_one_known_tag_with_the_right_payload() {
        for (label, bad) in [
            ("an empty object", empty()),
            ("a string", FfiValue::String("default".into())),
            ("null", FfiValue::Null),
            ("an unknown tag", obj(vec![("primary", empty())])),
            (
                "two tags",
                obj(vec![("default", empty()), ("any", empty())]),
            ),
            (
                "default with a payload",
                obj(vec![("default", FfiValue::Bool(true))]),
            ),
            (
                "default with fields",
                obj(vec![("default", obj(vec![("x", empty())]))]),
            ),
            (
                "a name that is not a string",
                obj(vec![("name", FfiValue::UInt64(1))]),
            ),
            (
                "an empty name",
                obj(vec![("name", FfiValue::String("".into()))]),
            ),
            (
                "a name past ZeroKMS's 64-byte limit",
                obj(vec![(
                    "name",
                    FfiValue::String("x".repeat(65).as_str().into()),
                )]),
            ),
            (
                "an id that is not 16 bytes",
                obj(vec![("id", FfiValue::Bytes(Protected::new(vec![1, 2, 3])))]),
            ),
            (
                "an id as text",
                obj(vec![(
                    "id",
                    FfiValue::String("00000000-0000-0000-0000-000000000007".into()),
                )]),
            ),
        ] {
            assert_eq!(
                parse_selector(bad).err(),
                Some(STATUS_ENCODING),
                "{label} is not a selector and must be refused"
            );
        }
    }

    #[test]
    fn options_are_one_keyset_key() {
        assert_eq!(
            parse_options(options(obj(vec![("default", empty())])), Side::Mint),
            Ok(Options {
                keyset: KeysetSelector::Default
            })
        );
        for (label, bad) in [
            ("no keyset", empty()),
            ("not an object", FfiValue::Null),
            (
                "an unknown key beside it",
                obj(vec![
                    ("keyset", obj(vec![("default", empty())])),
                    ("mode", FfiValue::Bool(true)),
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
                parse_options(bad, Side::Open).err(),
                Some(STATUS_ENCODING),
                "{label} must be refused"
            );
        }
    }

    #[test]
    fn any_is_an_opening_selector_only() {
        let any = || options(obj(vec![("any", empty())]));
        assert_eq!(
            parse_options(any(), Side::Open),
            Ok(Options {
                keyset: KeysetSelector::Any
            })
        );
        assert_eq!(
            parse_options(any(), Side::Mint).err(),
            Some(STATUS_ENCODING)
        );
    }
}
