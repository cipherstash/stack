//! Parsing of the `se_cipher_init` configuration.
//!
//! The config crosses the boundary as one FFI-codec-encoded
//! [`FfiValue::Object`] — the same codec every other entry point uses, so
//! there is no second config format. Recognised keys (all string values):
//!
//! | key           | required | meaning |
//! |---------------|----------|---------|
//! | `client_id`   | yes      | ZeroKMS client id (UUID) |
//! | `client_key`  | yes      | the v1 client key material, hex-encoded (upper or lower case — the `to_hex_v1` / `CS_CLIENT_KEY` form) or standard padded base64 (the form `secretkey.json` serialises) |
//! | `zerokms_url` | no       | pins the ZeroKMS endpoint at init; when absent the endpoint is resolved from the access token's `services` claim on first use |
//! | `keyset_cache_size` | no | how many keysets beyond the default the cipher keeps loaded (a positive decimal integer; the crate default, 1024, when absent). See `StackCipherBuilder::keyset_cache_size` |
//!
//! There is no config key for a keyset. `{"default"}` means the default a
//! ZeroKMS administrator set for this client, and a client does not get to
//! redefine it — the same reason `StackCipherBuilder::keyset` was removed.
//! Every other keyset is selected per call (see [`crate::options`]). Unknown
//! keys are rejected — a typo'd optional key must not silently fall back to a
//! default — so a host still sending `keyset` is told so rather than quietly
//! encrypting somewhere else.
//!
//! The parsed [`FfiValue`] holds the client-key hex inside
//! `Protected`, which wipes on drop; the raw config *buffer* is wiped by the
//! ABI layer immediately after decoding (see [`crate::abi`]).

use std::num::NonZeroUsize;

use stack_kms::{ClientKey, ZeroKmsEndpoint};
use uuid::Uuid;
use vitaminc_aead_value::FfiValue;
use zeroize::Zeroizing;

/// A parse failure, carrying which key was at fault. Maps to
/// `STATUS_ENCODING` at the ABI, and [`describe`](Self::describe) is the
/// message the host reads through `se_last_error`: the name of the key at
/// fault crosses the boundary, its value never does.
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
    /// A key appeared twice. The codec rejects duplicate object keys before
    /// this parser runs, but `parse_config` is `pub` and takes any
    /// [`FfiValue`] — last-write-wins on, say, `client_key` must never be
    /// silent.
    Duplicate(&'static str),
    /// A key this version does not recognise.
    UnknownKey(String),
}

impl ConfigError {
    /// Says what was wrong with the config, for the host to read.
    ///
    /// The message names the key at fault but never its value, because the
    /// config holds the client key. An unrecognised key is not named
    /// either: if a value is pasted where a key should be, the unrecognised
    /// key *is* that value.
    pub fn describe(&self) -> String {
        match self {
            Self::NotAnObject => "the config is not an object of string values".to_owned(),
            Self::Missing(key) => format!("the config has no {key}"),
            Self::NotAString(key) => format!("the config's {key} is not a string"),
            Self::Invalid(key) => format!("the config's {key} is not valid"),
            Self::Duplicate(key) => format!("the config gives {key} twice"),
            Self::UnknownKey(_) => "the config has a key this version does not know".to_owned(),
        }
    }
}

/// Everything `se_cipher_init` needs to build the cipher.
pub struct CipherConfig {
    pub client_key: ClientKey,
    pub endpoint: Option<ZeroKmsEndpoint>,
    pub keyset_cache_size: Option<NonZeroUsize>,
}

/// Parse a decoded config value. Consumes it so the client-key material has
/// one owner; the `Protected` payloads are wiped when the strings drop here.
pub fn parse_config(value: FfiValue) -> Result<CipherConfig, ConfigError> {
    let FfiValue::Object(entries) = value else {
        return Err(ConfigError::NotAnObject);
    };

    // Every slot is a `Zeroizing<String>`, not just the key one: the
    // client-key slot *must* wipe on every exit path (any of the `?`s below
    // can fire while it holds a full encoding of the client root key), and
    // making one slot special invites the next edit to add an early return
    // above the wipe. Uniform is cheaper than remembering.
    let mut client_id: Option<Zeroizing<String>> = None;
    let mut client_key_encoded: Option<Zeroizing<String>> = None;
    let mut url: Option<Zeroizing<String>> = None;
    let mut cache_size: Option<Zeroizing<String>> = None;

    for (key, value) in entries {
        let slot = match key.as_str() {
            "client_id" => &mut client_id,
            "client_key" => &mut client_key_encoded,
            "zerokms_url" => &mut url,
            "keyset_cache_size" => &mut cache_size,
            _ => return Err(ConfigError::UnknownKey(key)),
        };
        // The codec already rejects duplicate object keys, so on the ABI
        // path the slot is always vacant — but this function accepts any
        // `FfiValue`, so enforce it rather than assume it.
        if slot.is_some() {
            return Err(ConfigError::Duplicate(name_of(&key)));
        }
        let FfiValue::String(s) = value else {
            return Err(ConfigError::NotAString(name_of(&key)));
        };
        let text = Zeroizing::new(
            std::str::from_utf8(s.risky_ref())
                .map_err(|_| ConfigError::NotAString(name_of(&key)))?
                .to_string(),
        );
        *slot = Some(text);
    }

    let client_id = client_id.ok_or(ConfigError::Missing("client_id"))?;
    let client_id = Uuid::parse_str(&client_id).map_err(|_| ConfigError::Invalid("client_id"))?;

    // Lenient by design: `from_encoded_v1` takes hex in either case *or* the
    // base64 `secretkey.json` holds, matching every native loader. The
    // `Zeroizing` slot wipes the encoded copy however this returns — the
    // decoded `FfiValue`'s own copy was consumed above, and the raw input
    // buffer is the ABI layer's to wipe.
    let client_key_encoded = client_key_encoded.ok_or(ConfigError::Missing("client_key"))?;
    let client_key = ClientKey::from_encoded_v1(client_id, &client_key_encoded)
        .map_err(|_| ConfigError::Invalid("client_key"))?;

    let endpoint = url
        .map(|u| u.parse().map_err(|_| ConfigError::Invalid("zerokms_url")))
        .transpose()?;

    let keyset_cache_size = cache_size
        .map(|n| {
            n.parse::<NonZeroUsize>()
                .map_err(|_| ConfigError::Invalid("keyset_cache_size"))
        })
        .transpose()?;

    Ok(CipherConfig {
        client_key,
        endpoint,
        keyset_cache_size,
    })
}

/// Intern the key name for error reporting (`&'static str` keeps
/// [`ConfigError`] cheap; unknown keys carry the owned string instead).
fn name_of(key: &str) -> &'static str {
    match key {
        "client_id" => "client_id",
        "client_key" => "client_key",
        "zerokms_url" => "zerokms_url",
        "keyset_cache_size" => "keyset_cache_size",
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
        assert!(cfg.endpoint.is_none());
        assert!(cfg.keyset_cache_size.is_none());
    }

    #[test]
    fn parses_the_keyset_cache_size() {
        let (id, hex) = client_key_hex();
        let id_s = id.to_string();
        let cfg = parse_config(obj(vec![
            ("client_id", &id_s),
            ("client_key", &hex),
            ("keyset_cache_size", "16"),
        ]))
        .expect("config parses");
        assert_eq!(cfg.keyset_cache_size, NonZeroUsize::new(16));

        for bad in ["0", "-1", "sixteen", ""] {
            assert!(
                matches!(
                    parse_config(obj(vec![
                        ("client_id", &id_s),
                        ("client_key", &hex),
                        ("keyset_cache_size", bad),
                    ])),
                    Err(ConfigError::Invalid("keyset_cache_size"))
                ),
                "{bad:?} must be refused"
            );
        }
    }

    /// A keyset is not a config key: the default is the server's and a
    /// client does not redefine it, so a host that still sends one is told,
    /// rather than silently encrypting under the client's default instead of
    /// the keyset it named.
    #[test]
    fn a_keyset_key_is_rejected_like_any_other_unknown_key() {
        let (id, hex) = client_key_hex();
        for key in ["keyset", "keyset_id"] {
            assert!(matches!(
                parse_config(obj(vec![
                    ("client_id", &id.to_string()),
                    ("client_key", &hex),
                    (key, "users"),
                ])),
                Err(ConfigError::UnknownKey(_))
            ));
        }
    }

    #[test]
    fn parses_the_zerokms_url() {
        let (id, hex) = client_key_hex();
        let cfg = parse_config(obj(vec![
            ("client_id", &id.to_string()),
            ("client_key", &hex),
            ("zerokms_url", "https://zerokms.example.com"),
        ]))
        .expect("config parses");
        assert!(cfg.endpoint.is_some());
    }

    /// The config table promises hex in either case *or* base64 — the form
    /// `secretkey.json` actually serialises. A user pasting the value out of
    /// their profile must not be told their key is invalid.
    #[test]
    fn accepts_the_encodings_every_native_loader_accepts() {
        use base64ct::Encoding;

        let (id, hex) = client_key_hex();
        let id_s = id.to_string();
        let bytes = base16ct::lower::decode_vec(&hex).expect("fixture hex");
        let base64 = base64ct::Base64::encode_string(&bytes);

        for (label, encoded) in [
            ("lowercase hex", hex.clone()),
            ("uppercase hex", hex.to_uppercase()),
            ("base64", base64),
        ] {
            let cfg = parse_config(obj(vec![("client_id", &id_s), ("client_key", &encoded)]))
                .unwrap_or_else(|e| panic!("{label} must parse, got {e:?}"));
            assert_eq!(cfg.client_key.key_id, id, "{label}");
            assert_eq!(
                cfg.client_key.to_hex_v1().expect("re-encode"),
                hex,
                "{label} must recover the same keyset"
            );
        }
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
                ("zerokms_urk", "https://typo.example.com"),
            ])),
            Err(ConfigError::UnknownKey(_))
        ));
        // The codec refuses duplicate keys on the ABI path, but this
        // function is `pub` over any `FfiValue`: a repeated `client_key`
        // must be an error, never a silent last-write-wins on root key
        // material.
        assert!(matches!(
            parse_config(obj(vec![
                ("client_id", &id_s),
                ("client_key", &hex),
                ("client_key", &hex),
            ])),
            Err(ConfigError::Duplicate("client_key"))
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
