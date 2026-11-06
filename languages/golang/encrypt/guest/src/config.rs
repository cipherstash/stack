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
//! A key vendor backend (ADR-0009, CIP-5311) is configured with the keys
//! below. They are all absent for a ZeroKMS-only client, which is then
//! unchanged.
//!
//! | key               | when | meaning |
//! |-------------------|------|---------|
//! | `key_vendor`      | with any key below | the backend: `aws-kms`, `vault-transit`, `gcp-kms`, `azure-key-vault` or `static` (`KeyVendor::name`) |
//! | `keyset_records`  | with `key_vendor`, required | an array of one or more keyset record texts (`stack-keyset:…`), all of that backend |
//! | `aws_region`      | `aws-kms`, required | the AWS region |
//! | `aws_endpoint`    | `aws-kms` | overrides the regional AWS KMS endpoint |
//! | `vault_address`   | `vault-transit`, required | the Vault address |
//! | `vault_namespace` | `vault-transit` | the Vault namespace |
//! | `vault_mount`     | `vault-transit` | the Transit mount (default `transit`) |
//! | `gcp_endpoint`    | `gcp-kms` | overrides the Cloud KMS endpoint |
//! | `static_key_ref`  | `static`, required | the static key's reference, as the records name it |
//! | `static_key`      | `static`, required | the static key: 32 bytes (a bytes value, not a string) |
//! | `default_keyset`  | no ZeroKMS only | the default keyset, `{"id": 16 bytes}` or `{"name": …}`; else the only record |
//! | `root_key_ttl_ms` | any | how long a derived data key keyset's root key stays unwrapped, in milliseconds (`0` keeps none; default 5 minutes) |
//!
//! With a key vendor backend and none of `client_id`, `client_key` and
//! `zerokms_url`, the client has no ZeroKMS: the default keyset is the
//! vendor's, and a request for any other keyset is `STATUS_NO_ZEROKMS`.
//!
//! A vendor key for another backend than `key_vendor`, or with no
//! `key_vendor`, is refused, as an unknown key is. The vendor's credentials
//! are never in the config: the guest asks the host for them per request
//! (`vendor_credential_get`, see [`crate::vendor`]).
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
use std::time::Duration;

use stack_kms::{ClientKey, KeyVendor, ZeroKmsEndpoint};
use stack_kms_vendor::KeyBytes;
use uuid::Uuid;
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::Controlled;
use zeroize::Zeroizing;

use crate::vendor::{DefaultKeyset, VendorConfig, VendorSettings};

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
    /// A key held a value of the wrong type (`keyset_records` is an array
    /// of strings, `static_key` bytes).
    WrongType(&'static str),
    /// A key vendor backend key that does not apply to the configured
    /// `key_vendor`, or that was given with no `key_vendor`.
    NotForVendor(&'static str),
    /// A key that applies only to a client with a key vendor backend and no
    /// ZeroKMS (`default_keyset`).
    OnlyWithoutZeroKms(&'static str),
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
            Self::WrongType(key) => format!("the config's {key} has the wrong type"),
            Self::NotForVendor(key) => {
                format!("the config's {key} does not apply to its key_vendor")
            }
            Self::OnlyWithoutZeroKms(key) => {
                format!("the config's {key} applies only to a client with no ZeroKMS")
            }
        }
    }
}

/// Everything `se_cipher_init` needs to build the cipher.
pub struct CipherConfig {
    /// The ZeroKMS client key. `None` for a client with a key vendor
    /// backend and no ZeroKMS: the config then has no `client_id`,
    /// `client_key` or `zerokms_url`.
    pub client_key: Option<ClientKey>,
    pub endpoint: Option<ZeroKmsEndpoint>,
    pub keyset_cache_size: Option<NonZeroUsize>,
    /// The key vendor backend, when one is configured.
    pub vendor: Option<VendorConfig>,
}

/// The key vendor backend keys of the config, in the order the table above
/// gives them.
const VENDOR_KEYS: [&str; 12] = [
    "key_vendor",
    "keyset_records",
    "aws_region",
    "aws_endpoint",
    "vault_address",
    "vault_namespace",
    "vault_mount",
    "gcp_endpoint",
    "static_key_ref",
    "static_key",
    "default_keyset",
    "root_key_ttl_ms",
];

/// Take the key vendor backend keys out of `entries` and parse them. The
/// other keys stay for the caller. `None` when no vendor key is present.
///
/// Both builds of the guest call this: the real one beside the ZeroKMS keys,
/// the deterministic test build beside its seed.
pub fn take_vendor_config(
    entries: &mut Vec<(String, FfiValue)>,
) -> Result<Option<VendorConfig>, ConfigError> {
    let mut slots: Vec<(&'static str, FfiValue)> = Vec::new();
    let mut rest = Vec::with_capacity(entries.len());
    for (key, value) in entries.drain(..) {
        match VENDOR_KEYS.iter().find(|k| **k == key) {
            Some(name) => {
                if slots.iter().any(|(k, _)| k == name) {
                    return Err(ConfigError::Duplicate(name));
                }
                slots.push((name, value));
            }
            None => rest.push((key, value)),
        }
    }
    *entries = rest;
    if slots.is_empty() {
        return Ok(None);
    }
    let mut slots = VendorSlots(slots);

    let vendor = slots
        .string("key_vendor")?
        .ok_or(ConfigError::Missing("key_vendor"))?;
    let vendor = KeyVendor::from_name(vendor.as_str()).ok_or(ConfigError::Invalid("key_vendor"))?;
    let records = slots.records()?;
    let settings = match vendor {
        KeyVendor::Aws => VendorSettings::Aws {
            region: slots.required("aws_region")?,
            endpoint: slots.string("aws_endpoint")?.map(|s| s.to_string()),
        },
        KeyVendor::Vault => VendorSettings::Vault {
            address: slots.required("vault_address")?,
            namespace: slots.string("vault_namespace")?.map(|s| s.to_string()),
            mount: slots.string("vault_mount")?.map(|s| s.to_string()),
        },
        KeyVendor::Gcp => VendorSettings::Gcp {
            endpoint: slots.string("gcp_endpoint")?.map(|s| s.to_string()),
        },
        KeyVendor::Azure => VendorSettings::Azure,
        KeyVendor::Static => VendorSettings::Static {
            key_ref: slots.required("static_key_ref")?,
            key: slots.static_key()?,
        },
        // `KeyVendor` is `#[non_exhaustive]`: a vendor this guest has no
        // client for is not one it can configure.
        _ => return Err(ConfigError::Invalid("key_vendor")),
    };
    let default_keyset = slots.default_keyset()?;
    let root_key_ttl = slots
        .string("root_key_ttl_ms")?
        .map(|ms| {
            ms.parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|_| ConfigError::Invalid("root_key_ttl_ms"))
        })
        .transpose()?;
    // Whatever is left was given for another backend.
    if let Some((key, _)) = slots.0.first() {
        return Err(ConfigError::NotForVendor(key));
    }
    Ok(Some(VendorConfig {
        settings,
        records,
        default_keyset,
        root_key_ttl,
    }))
}

/// The vendor keys of one config, taken one at a time.
struct VendorSlots(Vec<(&'static str, FfiValue)>);

impl VendorSlots {
    fn take(&mut self, key: &'static str) -> Option<FfiValue> {
        let at = self.0.iter().position(|(k, _)| *k == key)?;
        Some(self.0.swap_remove(at).1)
    }

    fn string(&mut self, key: &'static str) -> Result<Option<Zeroizing<String>>, ConfigError> {
        self.take(key)
            .map(|value| {
                let FfiValue::String(s) = value else {
                    return Err(ConfigError::NotAString(key));
                };
                std::str::from_utf8(s.risky_ref())
                    .map(|text| Zeroizing::new(text.to_owned()))
                    .map_err(|_| ConfigError::NotAString(key))
            })
            .transpose()
    }

    fn required(&mut self, key: &'static str) -> Result<String, ConfigError> {
        let text = self.string(key)?.ok_or(ConfigError::Missing(key))?;
        if text.is_empty() {
            return Err(ConfigError::Invalid(key));
        }
        Ok(text.to_string())
    }

    fn records(&mut self) -> Result<Vec<String>, ConfigError> {
        const KEY: &str = "keyset_records";
        let FfiValue::Array(items) = self.take(KEY).ok_or(ConfigError::Missing(KEY))? else {
            return Err(ConfigError::WrongType(KEY));
        };
        if items.is_empty() {
            return Err(ConfigError::Invalid(KEY));
        }
        items
            .into_iter()
            .map(|item| match item {
                FfiValue::String(s) => std::str::from_utf8(s.risky_ref())
                    .map(str::to_owned)
                    .map_err(|_| ConfigError::WrongType(KEY)),
                _ => Err(ConfigError::WrongType(KEY)),
            })
            .collect()
    }

    /// `default_keyset`: a selector object, `{"id": 16 bytes}` or
    /// `{"name": string}`.
    fn default_keyset(&mut self) -> Result<Option<DefaultKeyset>, ConfigError> {
        const KEY: &str = "default_keyset";
        let Some(value) = self.take(KEY) else {
            return Ok(None);
        };
        let FfiValue::Object(mut entries) = value else {
            return Err(ConfigError::WrongType(KEY));
        };
        let (Some((tag, value)), None) = (entries.pop(), entries.pop()) else {
            return Err(ConfigError::Invalid(KEY));
        };
        match (tag.as_str(), value) {
            ("id", FfiValue::Bytes(bytes)) => Uuid::from_slice(bytes.risky_ref())
                .map(|id| Some(DefaultKeyset::Id(id)))
                .map_err(|_| ConfigError::Invalid(KEY)),
            ("name", FfiValue::String(name)) => std::str::from_utf8(name.risky_ref())
                .ok()
                .filter(|name| !name.is_empty())
                .map(|name| Some(DefaultKeyset::Name(name.to_owned())))
                .ok_or(ConfigError::Invalid(KEY)),
            _ => Err(ConfigError::Invalid(KEY)),
        }
    }

    fn static_key(&mut self) -> Result<KeyBytes, ConfigError> {
        const KEY: &str = "static_key";
        let FfiValue::Bytes(bytes) = self.take(KEY).ok_or(ConfigError::Missing(KEY))? else {
            return Err(ConfigError::WrongType(KEY));
        };
        let mut key: [u8; 32] = bytes
            .risky_ref()
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::Invalid(KEY))?;
        // `bytes` is `Protected` and wipes on drop; `KeyBytes` wipes its own
        // copy, and the stack copy is wiped here.
        let protected = KeyBytes::new(key);
        zeroize::Zeroize::zeroize(&mut key);
        Ok(protected)
    }
}

/// Parse a decoded config value. Consumes it so the client-key material has
/// one owner; the `Protected` payloads are wiped when the strings drop here.
pub fn parse_config(value: FfiValue) -> Result<CipherConfig, ConfigError> {
    let FfiValue::Object(mut entries) = value else {
        return Err(ConfigError::NotAnObject);
    };
    let vendor = take_vendor_config(&mut entries)?;

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

    // A key vendor backend is an alternative to ZeroKMS: with one, and no
    // ZeroKMS key at all, the client has no ZeroKMS. Any ZeroKMS key given
    // makes the others required, as before.
    let vendor_only =
        vendor.is_some() && client_id.is_none() && client_key_encoded.is_none() && url.is_none();
    let client_key = if vendor_only {
        None
    } else {
        let client_id = client_id.ok_or(ConfigError::Missing("client_id"))?;
        let client_id =
            Uuid::parse_str(&client_id).map_err(|_| ConfigError::Invalid("client_id"))?;

        // Lenient by design: `from_encoded_v1` takes hex in either case *or*
        // the base64 `secretkey.json` holds, matching every native loader.
        // The `Zeroizing` slot wipes the encoded copy however this returns —
        // the decoded `FfiValue`'s own copy was consumed above, and the raw
        // input buffer is the ABI layer's to wipe.
        let client_key_encoded = client_key_encoded.ok_or(ConfigError::Missing("client_key"))?;
        Some(
            ClientKey::from_encoded_v1(client_id, &client_key_encoded)
                .map_err(|_| ConfigError::Invalid("client_key"))?,
        )
    };
    // The default keyset of a client with ZeroKMS is the one a ZeroKMS
    // administrator set; only a vendor-only client names its own.
    if !vendor_only && vendor.as_ref().is_some_and(|v| v.default_keyset.is_some()) {
        return Err(ConfigError::OnlyWithoutZeroKms("default_keyset"));
    }

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
        vendor,
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
        assert_eq!(cfg.client_key.as_ref().expect("zerokms").key_id, id);
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
            assert_eq!(
                cfg.client_key.as_ref().expect("zerokms").key_id,
                id,
                "{label}"
            );
            assert_eq!(
                cfg.client_key
                    .as_ref()
                    .expect("zerokms")
                    .to_hex_v1()
                    .expect("re-encode"),
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

    fn vendor_config(entries: Vec<(&str, FfiValue)>) -> Result<Option<VendorConfig>, ConfigError> {
        let mut entries: Vec<(String, FfiValue)> = entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        take_vendor_config(&mut entries)
    }

    fn records() -> FfiValue {
        FfiValue::Array(vec![FfiValue::String("stack-keyset:AQ".into())])
    }

    fn s(text: &str) -> FfiValue {
        FfiValue::String(text.into())
    }

    #[test]
    fn no_vendor_key_is_no_vendor_and_leaves_the_other_keys() {
        let mut entries = vec![("client_id".to_string(), s("x"))];
        assert!(take_vendor_config(&mut entries).unwrap().is_none());
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parses_each_vendor() {
        let aws = vendor_config(vec![
            ("key_vendor", s("aws-kms")),
            ("keyset_records", records()),
            ("aws_region", s("us-east-1")),
            ("aws_endpoint", s("http://localhost:4566")),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(
            aws.settings,
            VendorSettings::Aws { ref region, endpoint: Some(_) } if region == "us-east-1"
        ));
        assert_eq!(aws.records, vec!["stack-keyset:AQ".to_owned()]);

        let vault = vendor_config(vec![
            ("key_vendor", s("vault-transit")),
            ("keyset_records", records()),
            ("vault_address", s("https://vault.example.com")),
            ("vault_mount", s("kms")),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(
            vault.settings,
            VendorSettings::Vault {
                namespace: None,
                mount: Some(_),
                ..
            }
        ));

        let gcp = vendor_config(vec![
            ("key_vendor", s("gcp-kms")),
            ("keyset_records", records()),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(
            gcp.settings,
            VendorSettings::Gcp { endpoint: None }
        ));
        let azure = vendor_config(vec![
            ("key_vendor", s("azure-key-vault")),
            ("keyset_records", records()),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(azure.settings, VendorSettings::Azure));

        let static_key = vendor_config(vec![
            ("key_vendor", s("static")),
            ("keyset_records", records()),
            ("static_key_ref", s("local")),
            (
                "static_key",
                FfiValue::Bytes(vitaminc_protected::Protected::new(vec![7u8; 32])),
            ),
        ])
        .unwrap()
        .unwrap();
        assert!(matches!(static_key.settings, VendorSettings::Static { .. }));
        // The static key never prints.
        assert!(!format!("{static_key:?}").contains('7'));
    }

    #[test]
    fn refuses_bad_vendor_configs() {
        let cases: Vec<(Vec<(&str, FfiValue)>, ConfigError)> = vec![
            (
                vec![("keyset_records", records())],
                ConfigError::Missing("key_vendor"),
            ),
            (
                vec![("key_vendor", s("zerokms")), ("keyset_records", records())],
                ConfigError::Invalid("key_vendor"),
            ),
            (
                vec![("key_vendor", s("azure-key-vault"))],
                ConfigError::Missing("keyset_records"),
            ),
            (
                vec![
                    ("key_vendor", s("azure-key-vault")),
                    ("keyset_records", FfiValue::Array(vec![])),
                ],
                ConfigError::Invalid("keyset_records"),
            ),
            (
                vec![
                    ("key_vendor", s("azure-key-vault")),
                    ("keyset_records", s("stack-keyset:AQ")),
                ],
                ConfigError::WrongType("keyset_records"),
            ),
            (
                vec![("key_vendor", s("aws-kms")), ("keyset_records", records())],
                ConfigError::Missing("aws_region"),
            ),
            (
                vec![
                    ("key_vendor", s("aws-kms")),
                    ("keyset_records", records()),
                    ("aws_region", s("us-east-1")),
                    ("vault_address", s("https://vault.example.com")),
                ],
                ConfigError::NotForVendor("vault_address"),
            ),
            (
                vec![
                    ("key_vendor", s("static")),
                    ("keyset_records", records()),
                    ("static_key_ref", s("local")),
                    ("static_key", s("not bytes")),
                ],
                ConfigError::WrongType("static_key"),
            ),
            (
                vec![
                    ("key_vendor", s("static")),
                    ("keyset_records", records()),
                    ("static_key_ref", s("local")),
                    (
                        "static_key",
                        FfiValue::Bytes(vitaminc_protected::Protected::new(vec![7u8; 31])),
                    ),
                ],
                ConfigError::Invalid("static_key"),
            ),
            (
                vec![("key_vendor", s("gcp-kms")), ("key_vendor", s("gcp-kms"))],
                ConfigError::Duplicate("key_vendor"),
            ),
        ];
        for (entries, expected) in cases {
            let error = vendor_config(entries).unwrap_err();
            assert_eq!(error, expected);
            assert!(!error.describe().is_empty());
        }
    }

    #[test]
    fn a_full_config_carries_its_vendor() {
        let (id, hex) = client_key_hex();
        let mut entries = match obj(vec![("client_id", &id.to_string()), ("client_key", &hex)]) {
            FfiValue::Object(entries) => entries,
            _ => unreachable!(),
        };
        entries.push(("key_vendor".into(), s("gcp-kms")));
        entries.push(("keyset_records".into(), records()));
        let cfg = parse_config(FfiValue::Object(entries)).expect("config parses");
        assert!(matches!(
            cfg.vendor.map(|v| v.settings),
            Some(VendorSettings::Gcp { .. })
        ));
    }

    #[test]
    fn a_vendor_and_no_zerokms_key_is_a_vendor_only_client() {
        let cfg = parse_config(FfiValue::Object(vec![
            ("key_vendor".into(), s("gcp-kms")),
            ("keyset_records".into(), records()),
            (
                "default_keyset".into(),
                FfiValue::Object(vec![("name".into(), s("payments"))]),
            ),
            ("root_key_ttl_ms".into(), s("60000")),
        ]))
        .expect("config parses");
        assert!(cfg.client_key.is_none());
        let vendor = cfg.vendor.expect("vendor");
        assert_eq!(
            vendor.default_keyset,
            Some(DefaultKeyset::Name("payments".into()))
        );
        assert_eq!(vendor.root_key_ttl, Some(Duration::from_secs(60)));

        // One ZeroKMS key makes the others required.
        assert_eq!(
            parse_config(FfiValue::Object(vec![
                ("key_vendor".into(), s("gcp-kms")),
                ("keyset_records".into(), records()),
                ("zerokms_url".into(), s("https://zerokms.example.com")),
            ]))
            .err(),
            Some(ConfigError::Missing("client_id"))
        );
        // No vendor and no ZeroKMS key is still a missing client id.
        assert_eq!(
            parse_config(FfiValue::Object(vec![])).err(),
            Some(ConfigError::Missing("client_id"))
        );
    }

    #[test]
    fn a_default_keyset_needs_a_client_with_no_zerokms() {
        let (id, hex) = client_key_hex();
        let mut entries = match obj(vec![("client_id", &id.to_string()), ("client_key", &hex)]) {
            FfiValue::Object(entries) => entries,
            _ => unreachable!(),
        };
        entries.push(("key_vendor".into(), s("gcp-kms")));
        entries.push(("keyset_records".into(), records()));
        entries.push((
            "default_keyset".into(),
            FfiValue::Object(vec![(
                "id".into(),
                FfiValue::Bytes(vitaminc_protected::Protected::new(vec![1; 16])),
            )]),
        ));
        assert_eq!(
            parse_config(FfiValue::Object(entries)).err(),
            Some(ConfigError::OnlyWithoutZeroKms("default_keyset"))
        );

        for bad in [
            s("payments"),
            FfiValue::Object(vec![]),
            FfiValue::Object(vec![("name".into(), s(""))]),
            FfiValue::Object(vec![(
                "id".into(),
                FfiValue::Bytes(vitaminc_protected::Protected::new(vec![1; 15])),
            )]),
            FfiValue::Object(vec![("name".into(), s("a")), ("id".into(), s("b"))]),
        ] {
            assert!(vendor_config(vec![
                ("key_vendor", s("gcp-kms")),
                ("keyset_records", records()),
                ("default_keyset", bad),
            ])
            .is_err());
        }
        assert_eq!(
            vendor_config(vec![
                ("key_vendor", s("gcp-kms")),
                ("keyset_records", records()),
                ("root_key_ttl_ms", s("-1")),
            ])
            .unwrap_err(),
            ConfigError::Invalid("root_key_ttl_ms")
        );
    }
}
