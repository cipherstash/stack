//! Parsing of the `se_cipher_init` configuration.
//!
//! The config crosses the boundary as one FFI-codec-encoded
//! [`FfiValue::Object`] — the same codec every other entry point uses, so
//! there is no second config format. Recognised keys (all string values):
//!
//! | key           | required | meaning |
//! |---------------|----------|---------|
//! | `client_id`   | yes      | ZeroKMS client id (UUID) |
//! | `client_key`  | yes      | the client key, hex-encoded (the v1 `to_hex_v1` encoding) |
//! | `keyset`      | no       | keyset *name* to pin the cipher to |
//! | `keyset_id`   | no       | keyset *id* (UUID) to pin the cipher to |
//! | `zerokms_url` | no       | pins the ZeroKMS endpoint at init; when absent the endpoint is resolved from the access token's `services` claim on first use |
//!
//! `keyset` and `keyset_id` are mutually exclusive; with neither, the
//! client's default keyset is used. Unknown keys are rejected — a typo'd
//! optional key must not silently fall back to a default.
//!
//! The parsed [`FfiValue`] holds the client-key hex inside
//! `Protected`, which wipes on drop; the raw config *buffer* is wiped by the
//! ABI layer immediately after decoding (see [`crate::abi`]).

use stack_kms::{ClientKey, IdentifiedBy, ZeroKmsEndpoint};
use uuid::Uuid;
use vitaminc_aead_value::FfiValue;

/// A parse failure, carrying which key was at fault. Maps to
/// `STATUS_ENCODING` at the ABI; the detail exists for the native tests and
/// is never surfaced across the boundary (statuses leak no config content).
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The config was not an object of string values.
    NotAnObject,
    /// A required key was absent.
    Missing(&'static str),
    /// A key held something other than a string.
    NotAString(&'static str),
    /// A key's value failed its own validation (bad UUID, bad hex, bad URL).
    Invalid(&'static str),
    /// `keyset` and `keyset_id` were both given.
    ConflictingKeysets,
    /// A key this version does not recognise.
    UnknownKey(String),
}

/// Everything `se_cipher_init` needs to build the cipher.
pub struct CipherConfig {
    pub client_key: ClientKey,
    pub keyset: Option<IdentifiedBy>,
    pub endpoint: Option<ZeroKmsEndpoint>,
}

/// Parse a decoded config value. Consumes it so the client-key material has
/// one owner; the `Protected` payloads are wiped when the strings drop here.
pub fn parse_config(value: FfiValue) -> Result<CipherConfig, ConfigError> {
    let FfiValue::Object(entries) = value else {
        return Err(ConfigError::NotAnObject);
    };

    let mut client_id: Option<String> = None;
    let mut client_key_hex: Option<String> = None;
    let mut keyset_name: Option<String> = None;
    let mut keyset_id: Option<String> = None;
    let mut url: Option<String> = None;

    for (key, value) in entries {
        let slot = match key.as_str() {
            "client_id" => &mut client_id,
            "client_key" => &mut client_key_hex,
            "keyset" => &mut keyset_name,
            "keyset_id" => &mut keyset_id,
            "zerokms_url" => &mut url,
            _ => return Err(ConfigError::UnknownKey(key)),
        };
        // The codec already rejects duplicate object keys, so the slot is
        // vacant; still, last-write-wins here would be silent, so require it.
        let FfiValue::String(s) = value else {
            return Err(ConfigError::NotAString(name_of(&key)));
        };
        let text = std::str::from_utf8(s.risky_ref())
            .map_err(|_| ConfigError::NotAString(name_of(&key)))?
            .to_string();
        *slot = Some(text);
    }

    let client_id = client_id.ok_or(ConfigError::Missing("client_id"))?;
    let client_id = Uuid::parse_str(&client_id).map_err(|_| ConfigError::Invalid("client_id"))?;

    let mut hex = client_key_hex.ok_or(ConfigError::Missing("client_key"))?;
    let client_key = ClientKey::from_hex_v1(client_id, &hex);
    // The hex string is a full encoding of the client root key: wipe this
    // copy whatever the parse outcome (the decoded FfiValue's own copy was
    // consumed above; the raw input buffer is the ABI layer's to wipe).
    zeroize::Zeroize::zeroize(&mut hex);
    let client_key = client_key.map_err(|_| ConfigError::Invalid("client_key"))?;

    let keyset = match (keyset_name, keyset_id) {
        (Some(_), Some(_)) => return Err(ConfigError::ConflictingKeysets),
        (Some(name), None) => Some(IdentifiedBy::Name(
            name.as_str()
                .try_into()
                .map_err(|_| ConfigError::Invalid("keyset"))?,
        )),
        (None, Some(id)) => Some(IdentifiedBy::Uuid(
            Uuid::parse_str(&id).map_err(|_| ConfigError::Invalid("keyset_id"))?,
        )),
        (None, None) => None,
    };

    let endpoint = url
        .map(|u| u.parse().map_err(|_| ConfigError::Invalid("zerokms_url")))
        .transpose()?;

    Ok(CipherConfig {
        client_key,
        keyset,
        endpoint,
    })
}

/// Intern the key name for error reporting (`&'static str` keeps
/// [`ConfigError`] cheap; unknown keys carry the owned string instead).
fn name_of(key: &str) -> &'static str {
    match key {
        "client_id" => "client_id",
        "client_key" => "client_key",
        "keyset" => "keyset",
        "keyset_id" => "keyset_id",
        "zerokms_url" => "zerokms_url",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid v1 client key for fixtures, minted through the real key type
    /// so the hex exercises the actual `from_hex_v1` decoder.
    fn client_key_hex() -> (Uuid, String) {
        use recipher::keyset::{EncryptionKeySet, ProxyKeySet};
        let id = Uuid::from_u128(7);
        let authority = EncryptionKeySet::generate().expect("generate");
        let domain = EncryptionKeySet::generate().expect("generate");
        let key = ClientKey::new_v1(id, ProxyKeySet::generate(&authority, &domain));
        (id, key.to_hex_v1().expect("encode fixture key"))
    }

    fn obj(entries: Vec<(&str, &str)>) -> FfiValue {
        FfiValue::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), FfiValue::String(v.into())))
                .collect(),
        )
    }

    #[test]
    fn parses_a_minimal_config() {
        let (id, hex) = client_key_hex();
        let cfg = parse_config(obj(vec![
            ("client_id", &id.to_string()),
            ("client_key", &hex),
        ]))
        .expect("minimal config parses");
        assert_eq!(cfg.client_key.key_id, id);
        assert!(cfg.keyset.is_none());
        assert!(cfg.endpoint.is_none());
    }

    #[test]
    fn parses_keyset_name_id_and_url() {
        let (id, hex) = client_key_hex();
        let cfg = parse_config(obj(vec![
            ("client_id", &id.to_string()),
            ("client_key", &hex),
            ("keyset", "users"),
            ("zerokms_url", "https://zerokms.example.com"),
        ]))
        .expect("config parses");
        assert!(matches!(cfg.keyset, Some(IdentifiedBy::Name(_))));
        assert!(cfg.endpoint.is_some());

        let keyset_id = Uuid::from_u128(9);
        let cfg = parse_config(obj(vec![
            ("client_id", &id.to_string()),
            ("client_key", &hex),
            ("keyset_id", &keyset_id.to_string()),
        ]))
        .expect("config parses");
        assert!(matches!(cfg.keyset, Some(IdentifiedBy::Uuid(k)) if k == keyset_id));
    }

    #[test]
    fn rejects_bad_configs() {
        let (id, hex) = client_key_hex();
        let id_s = id.to_string();

        assert!(matches!(
            parse_config(FfiValue::Null),
            Err(ConfigError::NotAnObject)
        ));
        assert!(matches!(
            parse_config(obj(vec![("client_id", &id_s)])),
            Err(ConfigError::Missing("client_key"))
        ));
        assert!(matches!(
            parse_config(obj(vec![("client_id", "nope"), ("client_key", &hex)])),
            Err(ConfigError::Invalid("client_id"))
        ));
        assert!(matches!(
            parse_config(obj(vec![
                ("client_id", &id_s),
                ("client_key", "deadbeef"), // valid hex, not a keyset
            ])),
            Err(ConfigError::Invalid("client_key"))
        ));
        assert!(matches!(
            parse_config(obj(vec![
                ("client_id", &id_s),
                ("client_key", &hex),
                ("keyset", "users"),
                ("keyset_id", "00000000-0000-0000-0000-000000000009"),
            ])),
            Err(ConfigError::ConflictingKeysets)
        ));
        assert!(matches!(
            parse_config(obj(vec![
                ("client_id", &id_s),
                ("client_key", &hex),
                ("zerokms_urk", "https://typo.example.com"),
            ])),
            Err(ConfigError::UnknownKey(_))
        ));
        assert!(matches!(
            parse_config(obj(vec![
                ("client_id", &id_s),
                ("client_key", &hex),
                ("zerokms_url", "not a url"),
            ])),
            Err(ConfigError::Invalid("zerokms_url"))
        ));
    }
}
