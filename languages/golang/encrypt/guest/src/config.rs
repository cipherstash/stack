//! Parsing of the `se_cipher_init` configuration.
//!
//! The config crosses the boundary as one frame object, read by serde
//! (`vitaminc_aead_frame::serde`), the same format as every other control
//! message. Recognised keys (all string values):
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
//!
//! A vendor key for another backend than `key_vendor`, or with no
//! `key_vendor`, is refused. The vendor's credentials are never in the
//! config: the guest asks the host for them, through the step loop, before
//! each vendor request (see [`crate::vendor`]).
//!
//! There is no config key for a keyset. `{"default"}` means the default a
//! ZeroKMS administrator set for this client, and a client does not get to
//! redefine it — the same reason `StackCipherBuilder::keyset` was removed.
//! Every other keyset is selected per call (see [`crate::options`]). Unknown
//! keys are rejected — a typo'd optional key must not silently fall back to a
//! default — so a host still sending `keyset` is told so rather than quietly
//! encrypting somewhere else. A key given twice is refused by the frame.
//!
//! Every string is borrowed from the config buffer, so the only copy of the
//! client key this parser makes is the [`ClientKey`] it builds. The ABI
//! layer wipes the buffer as soon as [`parse_config`] returns (see
//! [`crate::abi`]).
//!
//! A refusal is [`STATUS_ENCODING`](crate::status::STATUS_ENCODING), with a
//! message that names the key at fault and never a value, because the
//! config holds the client key. An unrecognised key is not named either:
//! if a value is pasted where a key should be, the unrecognised key *is*
//! that value.

use std::num::NonZeroUsize;

use serde::{Deserialize, Deserializer};
use stack_encrypt::dynamic::frame::serde::from_slice;
use stack_guest_abi::last_error::malformed;
use stack_kms::{ClientKey, KeyVendor, ZeroKmsEndpoint};
use stack_kms_vendor::KeyBytes;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::vendor::{VendorConfig, VendorSettings};

/// The [`VendorWire`] of a wire struct that declares the key vendor
/// backend keys inline (the config's, the deterministic build's seed
/// object). A macro because the two structs are distinct types.
macro_rules! vendor_wire {
    ($wire:expr) => {
        $crate::config::VendorWire {
            key_vendor: $wire.key_vendor,
            keyset_records: $wire.keyset_records,
            aws_region: $wire.aws_region,
            aws_endpoint: $wire.aws_endpoint,
            vault_address: $wire.vault_address,
            vault_namespace: $wire.vault_namespace,
            vault_mount: $wire.vault_mount,
            gcp_endpoint: $wire.gcp_endpoint,
            static_key_ref: $wire.static_key_ref,
            static_key: $wire.static_key,
        }
    };
}
// The deterministic build reads the same keys beside its seed.
#[cfg(feature = "deterministic-kms")]
pub(crate) use vendor_wire;

/// Everything `se_cipher_init` needs to build the cipher.
pub struct CipherConfig {
    pub client_key: ClientKey,
    pub endpoint: Option<ZeroKmsEndpoint>,
    pub keyset_cache_size: Option<NonZeroUsize>,
    /// The key vendor backend, when one is configured.
    pub vendor: Option<VendorConfig>,
}

/// Parse the config frame a host sent. See the [module docs](self).
pub fn parse_config(bytes: &[u8]) -> Result<CipherConfig, u32> {
    read(bytes).map_err(malformed)
}

/// [`parse_config`], with the refusal's message.
fn read(bytes: &[u8]) -> Result<CipherConfig, String> {
    let wire: Wire<'_> = from_slice(bytes).map_err(|e| format!("the config: {e}"))?;
    let vendor = vendor_wire!(wire)
        .config()
        .map_err(|e| format!("the config: {e}"))?;
    // `from_encoded_v1` is lenient by design: hex in either case *or* the
    // base64 `secretkey.json` holds, matching every native loader.
    let client_key = ClientKey::from_encoded_v1(wire.client_id.0, wire.client_key)
        .map_err(|_| "the config: client_key: a client key that is not valid".to_owned())?;
    Ok(CipherConfig {
        client_key,
        endpoint: wire.zerokms_url.map(|url| url.0),
        keyset_cache_size: wire.keyset_cache_size.map(|size| size.0),
        vendor,
    })
}

/// The config as a host writes it. Each field validates as it reads,
/// through `TryFrom`. The frame's serde never repeats a `TryFrom` error's
/// text (it could carry the value), so a refusal names the key and says
/// only that its value was not accepted; each error here is still a fixed
/// string, for the reader.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire<'a> {
    client_id: ClientId,
    client_key: &'a str,
    #[serde(default, deserialize_with = "present")]
    zerokms_url: Option<Url>,
    #[serde(default, deserialize_with = "present")]
    keyset_cache_size: Option<CacheSize>,
    // The key vendor backend keys, read into a `VendorWire`. Not a
    // flattened field: serde does not deny unknown keys through a flatten.
    #[serde(default, borrow, deserialize_with = "present")]
    key_vendor: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    keyset_records: Option<Vec<&'a str>>,
    #[serde(default, borrow, deserialize_with = "present")]
    aws_region: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    aws_endpoint: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    vault_address: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    vault_namespace: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    vault_mount: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    gcp_endpoint: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    static_key_ref: Option<&'a str>,
    #[serde(default, borrow, deserialize_with = "present")]
    static_key: Option<&'a [u8]>,
}

/// Absent is `None`. Present, a value must be a string: a null is refused.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// A client id: a UUID, as text.
#[derive(Deserialize)]
#[serde(try_from = "&str")]
struct ClientId(Uuid);

impl TryFrom<&str> for ClientId {
    type Error = &'static str;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        Uuid::parse_str(text)
            .map(ClientId)
            .map_err(|_| "a client id that is not a UUID")
    }
}

/// The ZeroKMS endpoint to pin.
#[derive(Deserialize)]
#[serde(try_from = "&str")]
struct Url(ZeroKmsEndpoint);

impl TryFrom<&str> for Url {
    type Error = &'static str;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        text.parse().map(Url).map_err(|_| "a URL that is not valid")
    }
}

/// A positive integer, as a decimal string.
#[derive(Deserialize)]
#[serde(try_from = "&str")]
struct CacheSize(NonZeroUsize);

impl TryFrom<&str> for CacheSize {
    type Error = &'static str;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        text.parse()
            .map(CacheSize)
            .map_err(|_| "a size that is not a positive decimal integer")
    }
}

/// The key vendor backend keys of a config, as a host writes them. Read
/// beside the ZeroKMS keys here, and beside the seed in the deterministic
/// build ([`crate::deterministic`]).
#[derive(Default)]
pub struct VendorWire<'a> {
    pub(crate) key_vendor: Option<&'a str>,
    pub(crate) keyset_records: Option<Vec<&'a str>>,
    pub(crate) aws_region: Option<&'a str>,
    pub(crate) aws_endpoint: Option<&'a str>,
    pub(crate) vault_address: Option<&'a str>,
    pub(crate) vault_namespace: Option<&'a str>,
    pub(crate) vault_mount: Option<&'a str>,
    pub(crate) gcp_endpoint: Option<&'a str>,
    pub(crate) static_key_ref: Option<&'a str>,
    pub(crate) static_key: Option<&'a [u8]>,
}

impl VendorWire<'_> {
    /// The key vendor backend these keys configure, or `None` when none is
    /// given. A refusal names the key at fault and never its value.
    pub fn config(self) -> Result<Option<VendorConfig>, String> {
        let given: Vec<&'static str> = [
            ("key_vendor", self.key_vendor.is_some()),
            ("keyset_records", self.keyset_records.is_some()),
            ("aws_region", self.aws_region.is_some()),
            ("aws_endpoint", self.aws_endpoint.is_some()),
            ("vault_address", self.vault_address.is_some()),
            ("vault_namespace", self.vault_namespace.is_some()),
            ("vault_mount", self.vault_mount.is_some()),
            ("gcp_endpoint", self.gcp_endpoint.is_some()),
            ("static_key_ref", self.static_key_ref.is_some()),
            ("static_key", self.static_key.is_some()),
        ]
        .into_iter()
        .filter_map(|(key, present)| present.then_some(key))
        .collect();
        if given.is_empty() {
            return Ok(None);
        }
        let missing = |key: &str| format!("missing field `{key}`");
        let invalid = |key: &str| format!("{key}: a value its type does not accept");
        let name = self.key_vendor.ok_or_else(|| missing("key_vendor"))?;
        let vendor = KeyVendor::ALL
            .into_iter()
            .find(|v| v.name() == name)
            .ok_or_else(|| invalid("key_vendor"))?;
        let records = self
            .keyset_records
            .ok_or_else(|| missing("keyset_records"))?;
        if records.is_empty() {
            return Err(invalid("keyset_records"));
        }
        let required = |key: &'static str, value: Option<&str>| {
            let value = value.ok_or_else(|| missing(key))?;
            if value.is_empty() {
                return Err(invalid(key));
            }
            Ok(value.to_owned())
        };
        let (settings, used): (VendorSettings, &[&str]) = match vendor {
            KeyVendor::Aws => (
                VendorSettings::Aws {
                    region: required("aws_region", self.aws_region)?,
                    endpoint: self.aws_endpoint.map(str::to_owned),
                },
                &["aws_region", "aws_endpoint"],
            ),
            KeyVendor::Vault => (
                VendorSettings::Vault {
                    address: required("vault_address", self.vault_address)?,
                    namespace: self.vault_namespace.map(str::to_owned),
                    mount: self.vault_mount.map(str::to_owned),
                },
                &["vault_address", "vault_namespace", "vault_mount"],
            ),
            KeyVendor::Gcp => (
                VendorSettings::Gcp {
                    endpoint: self.gcp_endpoint.map(str::to_owned),
                },
                &["gcp_endpoint"],
            ),
            KeyVendor::Azure => (VendorSettings::Azure, &[]),
            KeyVendor::Static => {
                let key = self.static_key.ok_or_else(|| missing("static_key"))?;
                let mut bytes: [u8; 32] = key.try_into().map_err(|_| invalid("static_key"))?;
                // `KeyBytes` wipes its own copy; the stack copy is wiped
                // here. The config buffer is the ABI layer's to wipe.
                let key = KeyBytes::new(bytes);
                bytes.zeroize();
                (
                    VendorSettings::Static {
                        key_ref: required("static_key_ref", self.static_key_ref)?,
                        key,
                    },
                    &["static_key_ref", "static_key"],
                )
            }
            // `KeyVendor` is `#[non_exhaustive]`: a vendor this guest has no
            // client for is not one it can configure.
            _ => return Err(invalid("key_vendor")),
        };
        // Whatever else was given is for another backend.
        if let Some(key) = given
            .iter()
            .find(|key| !["key_vendor", "keyset_records"].contains(key) && !used.contains(key))
        {
            return Err(format!(
                "{key}: a key that does not apply to its key_vendor"
            ));
        }
        Ok(Some(VendorConfig {
            settings,
            records: records.into_iter().map(str::to_owned).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_frame::{frame, obj, s, V};

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

    fn config(entries: Vec<(&'static str, V)>) -> Result<CipherConfig, String> {
        read(&frame(&obj(entries)))
    }

    /// The config's refusal, checked to name neither the client key nor any
    /// value or unknown key the test sent.
    fn refused(v: &V, secrets: &[&str]) -> String {
        let message = read(&frame(v)).err().expect("refused");
        for secret in secrets {
            assert!(!message.contains(secret), "{message:?} echoes {secret:?}");
        }
        message
    }

    #[test]
    fn parses_a_minimal_config() {
        let (id, hex) = client_key_hex();
        let cfg = config(vec![
            ("client_id", s(&id.to_string())),
            ("client_key", s(&hex)),
        ])
        .expect("minimal config parses");
        assert_eq!(cfg.client_key.key_id, id);
        assert!(cfg.endpoint.is_none());
        assert!(cfg.keyset_cache_size.is_none());
    }

    #[test]
    fn parses_the_keyset_cache_size() {
        let (id, hex) = client_key_hex();
        let with = |size: V| {
            obj(vec![
                ("client_id", s(&id.to_string())),
                ("client_key", s(&hex)),
                ("keyset_cache_size", size),
            ])
        };
        let cfg = read(&frame(&with(s("16")))).expect("config parses");
        assert_eq!(cfg.keyset_cache_size, NonZeroUsize::new(16));

        for bad in ["0", "-1", "sixteen", ""] {
            assert_eq!(
                refused(&with(s(bad)), &[&hex]),
                "the config: keyset_cache_size: a value its type does not accept",
                "{bad:?} must be refused"
            );
        }
        // A decimal string, not an integer, and not null.
        for bad in [V::U32(16), V::Null] {
            assert!(refused(&with(bad), &[&hex]).starts_with("the config: keyset_cache_size: "));
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
            let message = refused(
                &obj(vec![
                    ("client_id", s(&id.to_string())),
                    ("client_key", s(&hex)),
                    (key, s("users")),
                ]),
                // "keyset" alone is inside the expected `keyset_cache_size`.
                &[&hex, "users", "keyset_id"],
            );
            assert!(message.contains("an unknown key"), "{message}");
        }
    }

    #[test]
    fn parses_the_zerokms_url() {
        let (id, hex) = client_key_hex();
        let cfg = config(vec![
            ("client_id", s(&id.to_string())),
            ("client_key", s(&hex)),
            ("zerokms_url", s("https://zerokms.example.com")),
        ])
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
        let bytes = base16ct::lower::decode_vec(&hex).expect("fixture hex");
        let base64 = base64ct::Base64::encode_string(&bytes);

        for (label, encoded) in [
            ("lowercase hex", hex.clone()),
            ("uppercase hex", hex.to_uppercase()),
            ("base64", base64),
        ] {
            let cfg = config(vec![
                ("client_id", s(&id.to_string())),
                ("client_key", s(&encoded)),
            ])
            .unwrap_or_else(|e| panic!("{label} must parse, got {e}"));
            assert_eq!(cfg.client_key.key_id, id, "{label}");
            assert_eq!(
                cfg.client_key.to_hex_v1().expect("re-encode"),
                hex,
                "{label} must recover the same keyset"
            );
        }
    }

    /// Every refusal names the key at fault and never a value: not the
    /// client key, not a bad id or URL, not an unknown key.
    #[test]
    fn rejects_bad_configs_without_echoing_a_value() {
        let (id, hex) = client_key_hex();
        let id_s = id.to_string();
        let secrets = [
            hex.as_str(),
            "nope",
            "zerokms_urk",
            "typo.example",
            "deadbeef",
        ];
        let cases = [
            (V::Null, "the config: expected "),
            (
                V::Arr(vec![s(&id_s), s(&hex)]),
                "the config: expected struct Wire, found an array",
            ),
            (
                obj(vec![
                    ("client_id", s(&id_s)),
                    ("client_key", V::Bytes(hex.clone().into_bytes())),
                ]),
                "the config: client_key: expected a borrowed string, found bytes",
            ),
            (
                obj(vec![("client_id", s(&id_s))]),
                "the config: missing field `client_key`",
            ),
            (
                obj(vec![("client_id", s("nope")), ("client_key", s(&hex))]),
                "the config: client_id: a value its type does not accept",
            ),
            (
                obj(vec![("client_id", s(&id_s)), ("client_key", V::U64(1))]),
                "the config: client_key: ",
            ),
            (
                // Valid hex, not a keyset.
                obj(vec![("client_id", s(&id_s)), ("client_key", s("deadbeef"))]),
                "the config: client_key: a client key that is not valid",
            ),
            (
                obj(vec![
                    ("client_id", s(&id_s)),
                    ("client_key", s(&hex)),
                    ("zerokms_urk", s("https://typo.example.com")),
                ]),
                "the config: an unknown key, ",
            ),
            (
                obj(vec![
                    ("client_id", s(&id_s)),
                    ("client_key", s(&hex)),
                    ("zerokms_url", s("not a url")),
                ]),
                "the config: zerokms_url: a value its type does not accept",
            ),
            (
                obj(vec![
                    ("client_id", s(&id_s)),
                    ("client_key", s(&hex)),
                    ("zerokms_url", V::Null),
                ]),
                "the config: zerokms_url: ",
            ),
        ];
        for (config, expected) in &cases {
            let message = refused(config, &secrets);
            assert!(
                message.starts_with(expected),
                "{message:?} is not {expected:?}"
            );
        }
    }

    /// A repeated `client_key` is never a silent last-write-wins on root key
    /// material: the frame refuses it.
    #[test]
    fn a_repeated_key_is_refused() {
        let (id, hex) = client_key_hex();
        let message = refused(
            &obj(vec![
                ("client_id", s(&id.to_string())),
                ("client_key", s(&hex)),
                ("client_key", s(&hex)),
            ]),
            &[&hex],
        );
        assert!(message.starts_with("the config: "), "{message}");
    }

    fn with_vendor(extra: Vec<(&'static str, V)>) -> Result<CipherConfig, String> {
        let (id, hex) = client_key_hex();
        let mut entries = vec![("client_id", s(&id.to_string())), ("client_key", s(&hex))];
        entries.extend(extra);
        config(entries)
    }

    fn records() -> V {
        V::Arr(vec![s("stack-keyset:AQ")])
    }

    #[test]
    fn no_vendor_key_is_no_vendor() {
        let cfg = with_vendor(vec![]).expect("config parses");
        assert!(cfg.vendor.is_none());
    }

    #[test]
    fn parses_each_vendor() {
        let aws = with_vendor(vec![
            ("key_vendor", s("aws-kms")),
            ("keyset_records", records()),
            ("aws_region", s("us-east-1")),
            ("aws_endpoint", s("http://localhost:4566")),
        ])
        .unwrap()
        .vendor
        .unwrap();
        assert!(matches!(
            aws.settings,
            VendorSettings::Aws { ref region, endpoint: Some(_) } if region == "us-east-1"
        ));
        assert_eq!(aws.records, vec!["stack-keyset:AQ".to_owned()]);

        let vault = with_vendor(vec![
            ("key_vendor", s("vault-transit")),
            ("keyset_records", records()),
            ("vault_address", s("https://vault.example.com")),
            ("vault_mount", s("kms")),
        ])
        .unwrap()
        .vendor
        .unwrap();
        assert!(matches!(
            vault.settings,
            VendorSettings::Vault {
                namespace: None,
                mount: Some(_),
                ..
            }
        ));

        for (name, expected) in [
            ("gcp-kms", KeyVendor::Gcp),
            ("azure-key-vault", KeyVendor::Azure),
        ] {
            let vendor = with_vendor(vec![("key_vendor", s(name)), ("keyset_records", records())])
                .unwrap()
                .vendor
                .unwrap();
            assert_eq!(vendor.settings.vendor(), expected);
        }

        let static_key = with_vendor(vec![
            ("key_vendor", s("static")),
            ("keyset_records", records()),
            ("static_key_ref", s("local")),
            ("static_key", V::Bytes(vec![7u8; 32])),
        ])
        .unwrap()
        .vendor
        .unwrap();
        assert_eq!(static_key.settings.vendor(), KeyVendor::Static);
        // The static key never prints.
        assert!(!format!("{static_key:?}").contains('7'));
    }

    /// Every refusal names the key at fault, never a value.
    #[test]
    fn refuses_bad_vendor_configs() {
        let cases: Vec<(Vec<(&'static str, V)>, &str)> = vec![
            (
                vec![("keyset_records", records())],
                "the config: missing field `key_vendor`",
            ),
            (
                vec![("key_vendor", s("zerokms")), ("keyset_records", records())],
                "the config: key_vendor: a value its type does not accept",
            ),
            (
                vec![("key_vendor", s("azure-key-vault"))],
                "the config: missing field `keyset_records`",
            ),
            (
                vec![
                    ("key_vendor", s("azure-key-vault")),
                    ("keyset_records", V::Arr(vec![])),
                ],
                "the config: keyset_records: a value its type does not accept",
            ),
            (
                vec![
                    ("key_vendor", s("azure-key-vault")),
                    ("keyset_records", s("stack-keyset:AQ")),
                ],
                "the config: keyset_records: ",
            ),
            (
                vec![("key_vendor", s("aws-kms")), ("keyset_records", records())],
                "the config: missing field `aws_region`",
            ),
            (
                vec![
                    ("key_vendor", s("aws-kms")),
                    ("keyset_records", records()),
                    ("aws_region", s("")),
                ],
                "the config: aws_region: a value its type does not accept",
            ),
            (
                vec![
                    ("key_vendor", s("aws-kms")),
                    ("keyset_records", records()),
                    ("aws_region", s("us-east-1")),
                    ("vault_address", s("https://vault.example.com")),
                ],
                "the config: vault_address: a key that does not apply to its key_vendor",
            ),
            (
                vec![
                    ("key_vendor", s("static")),
                    ("keyset_records", records()),
                    ("static_key_ref", s("local")),
                    ("static_key", s("not bytes")),
                ],
                "the config: static_key: ",
            ),
            (
                vec![
                    ("key_vendor", s("static")),
                    ("keyset_records", records()),
                    ("static_key_ref", s("local")),
                    ("static_key", V::Bytes(vec![7u8; 31])),
                ],
                "the config: static_key: a value its type does not accept",
            ),
        ];
        let (_, hex) = client_key_hex();
        for (entries, expected) in cases {
            let message = with_vendor(entries).err().expect("refused");
            assert!(
                message.starts_with(expected),
                "{message:?} is not {expected:?}"
            );
            for secret in [hex.as_str(), "us-east-1", "vault.example.com", "not bytes"] {
                assert!(!message.contains(secret), "{message:?} echoes {secret:?}");
            }
        }
    }
}
