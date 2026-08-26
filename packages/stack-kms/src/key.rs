pub(crate) use recipher::{
    cipher::ProxyCipher,
    key::{Iv, Key},
    keyset::ProxyKeySet as KeySet,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::ops::Deref;
use uuid::Uuid;
use vitaminc::protected::{OpaqueDebug, TimingSafeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use zerokms_protocol::{DecryptionPolicy, ViturKeyMaterial};

use crate::errors::{InvalidKeyMaterialError, LoadKeysetError};

/// NOTE: Debug is safe to implement because [KeySet] is opaque.
#[derive(Debug, Deserialize, Clone, Zeroize, ZeroizeOnDrop, Serialize)]
pub struct ClientKey {
    #[zeroize(skip)]
    #[serde(rename = "client_id")]
    pub key_id: Uuid,

    #[serde(rename = "client_key")]
    pub keyset: V1KeySet,
}

impl ClientKey {
    pub fn new_v1(key_id: Uuid, keyset: KeySet) -> Self {
        Self {
            key_id,
            keyset: V1KeySet(keyset),
        }
    }

    pub fn to_hex_v1(&self) -> serde_cbor::Result<String> {
        self.keyset.to_hex()
    }

    pub fn from_bytes(key_id: Uuid, bytes: &[u8]) -> serde_cbor::Result<Self> {
        Ok(Self {
            key_id,
            keyset: KeySet::from_bytes(bytes).map(V1KeySet)?,
        })
    }

    pub fn from_hex_v1(key_id: Uuid, hex: &str) -> serde_cbor::Result<Self> {
        Ok(Self {
            key_id,
            keyset: V1KeySet::from_hex(hex)?,
        })
    }
}

// FIXME: This shouldn't be Clone but it is needed right now for the JSONB indexer.
// `key` is secret DEK material, so equality is constant-time: the `TimingSafeEq`
// derive provides `ts_eq` *and* `PartialEq`/`Eq` implemented on top of it, so
// `==` is safe here — never add a variable-time `derive(PartialEq)`.
#[derive(TimingSafeEq, Zeroize, ZeroizeOnDrop, Clone)]
#[cfg_attr(test, derive(Default))]
pub struct DataKey {
    pub iv: Iv,
    pub key: Key,
}
opaque_debug::implement!(DataKey);

impl DataKey {
    /// Create a DataKey for a specific [`ClientKey`] given a specific initialisation vector
    /// (IV) and key material obtained from ZeroKMS.
    ///
    /// Returns [`InvalidKeyMaterialError`] when the material is not the exact
    /// length the keyset accepts (recipher validates up front) — the material
    /// is network-supplied, so a truncated or corrupt response must not panic.
    pub fn from_key_material(
        key: &ClientKey,
        iv: Iv,
        key_material: &ViturKeyMaterial,
    ) -> Result<Self, InvalidKeyMaterialError> {
        let cipher = ProxyCipher::new(key.keyset.keyset());
        // `rect` is reencrypted key material — the derived data key is a hash of
        // it — so wipe the returned copy on drop; recipher wipes its own
        // intermediate block buffer. (The Sha256 block buffer keeps the final
        // <=64-byte block; sha2 0.10 doesn't implement Zeroize and changing the
        // hash would alter the derived key, so that residue is accepted.)
        let rect = Zeroizing::new(cipher.reencrypt::<16>(&iv, key_material)?);

        let mut hasher = Sha256::new();
        hasher.update(rect.as_slice());

        Ok(DataKey {
            iv,
            key: hasher.finalize().into(),
        })
    }

    pub fn key(&self) -> &Key {
        &self.key
    }
}

// FIXME: Making this Cloneable for now so that we can use the same key many times for the JSONB indexer.
// We should modify the indexer so each value has a separate key.
// No `PartialEq`/`Eq` on the wrapper: the `tag` is public but `key` is secret.
// If key equality is ever needed, compare `a.key == b.key` (constant-time via
// `DataKey`'s `TimingSafeEq`-derived `PartialEq`) or `a.key.ts_eq(&b.key)`.
#[derive(Clone)]
#[cfg_attr(test, derive(Default))]
pub struct DataKeyWithTag {
    pub key: DataKey,
    pub tag: Vec<u8>,
    pub decryption_policy: Option<DecryptionPolicy>,
}
opaque_debug::implement!(DataKeyWithTag);

impl DataKeyWithTag {
    /// Create a DataKey for a specific [`ClientKey`] given a specific IV, key material and tag
    /// obtained from ZeroKMS. See [`DataKey::from_key_material`] for the
    /// key-material validation this inherits.
    pub fn from_key_material(
        key: &ClientKey,
        iv: Iv,
        key_material: &ViturKeyMaterial,
        tag: Vec<u8>,
        decryption_policy: Option<DecryptionPolicy>,
    ) -> Result<Self, InvalidKeyMaterialError> {
        Ok(Self {
            key: DataKey::from_key_material(key, iv, key_material)?,
            tag,
            decryption_policy,
        })
    }
}

impl Deref for DataKeyWithTag {
    type Target = DataKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

/// Key used specifically for generating index terms (Searchable Encrypted
/// Metadata) with PRFs and similar constructions.
///
/// Derived from the *keyset root* key material returned by ZeroKMS's
/// `load-keyset` operation: unlike data keys, the same keyset always yields the
/// same index key, so terms generated at write time match terms generated at
/// query time.
#[derive(Zeroize, ZeroizeOnDrop, OpaqueDebug)]
pub struct IndexKey(Key);

impl IndexKey {
    /// Derive the index key for a specific [`ClientKey`] from the partial
    /// keyset-root key material obtained from ZeroKMS.
    ///
    /// Returns [`LoadKeysetError::InvalidKeyMaterial`] when the material is
    /// not the exact length the keyset accepts (33 16-byte blocks; recipher
    /// owns the fact and validates up front) — the material is
    /// network-supplied, so a truncated or corrupt response must not panic.
    pub fn from_key_material(
        key: &ClientKey,
        key_material: &ViturKeyMaterial,
    ) -> Result<Self, LoadKeysetError> {
        // We use all zeros for the IV for the keyset index key.
        // This key is not used for encryption but for indexing using PRFs and
        // similar constructions. Even then, because all other data keys are
        // generated using random IVs, the likelihood of collision is negligible.
        let iv = Iv::default();
        let cipher = ProxyCipher::new(key.keyset.keyset());
        // `rect` is reencrypted key material — the derived index key is a hash
        // of it — so wipe the returned copy on drop; recipher wipes its own
        // intermediate block buffer (matches `DataKey::from_key_material`).
        let rect = Zeroizing::new(
            cipher
                .reencrypt::<16>(&iv, key_material)
                .map_err(InvalidKeyMaterialError::from)?,
        );

        let mut hasher = blake3::Hasher::new();
        // Bind the `OutputReader` so it can be wiped: it holds the final
        // chaining value from which the whole XOF stream — the index key —
        // is recomputable, and blake3's `zeroize` feature implements
        // `Zeroize` for it but not wipe-on-drop.
        let mut reader = hasher
            // Fixed info string
            .update(b"ZEROKMS-INDEXKEY")
            .update(rect.as_slice())
            .finalize_xof();

        let key: Key = {
            let mut key = Key::default();
            reader.fill(&mut key);
            key
        };

        reader.zeroize();
        hasher.zeroize();

        Ok(Self(key))
    }

    pub fn key(&self) -> &Key {
        &self.0
    }
}

/// Test-support only: mint an [`IndexKey`] from raw bytes, bypassing the
/// keyset-root derivation. Kept off the public API so production callers can
/// only obtain an index key through
/// [`from_key_material`](IndexKey::from_key_material) (or a
/// [`IndexKeySource`](crate::IndexKeySource)) — an index key that never went
/// through `load_keyset` would silently generate index terms that match
/// nothing written by other services.
#[cfg(feature = "test-support")]
impl From<Key> for IndexKey {
    fn from(key: Key) -> Self {
        Self(key)
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct V1KeySet(pub(crate) KeySet);

impl V1KeySet {
    pub fn from_bytes(bytes: &[u8]) -> serde_cbor::Result<Self> {
        KeySet::from_bytes(bytes).map(Self)
    }

    pub(crate) fn to_hex(&self) -> serde_cbor::Result<String> {
        self.0.to_bytes().map(|mut bytes| {
            let hex = base16ct::lower::encode_string(&bytes);
            bytes.zeroize();
            hex
        })
    }

    pub(crate) fn from_hex(hex: &str) -> serde_cbor::Result<Self> {
        let mut bytes = base16ct::lower::decode_vec(hex).map_err(|e| {
            <serde_cbor::Error as serde::de::Error>::custom(format!("invalid hex: {e}"))
        })?;
        let result = Self::from_bytes(&bytes);
        bytes.zeroize();
        result
    }

    pub(crate) fn keyset(&self) -> &KeySet {
        &self.0
    }
}

impl Serialize for V1KeySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = self.0.to_bytes().map_err(serde::ser::Error::custom)?;
        // Zeroize the intermediate plaintext keyset buffer, matching `to_hex`,
        // `from_hex` and `deserialize`. Serdect encoding is constant-time.
        let result = serdect::slice::serialize_hex_lower_or_bin(&bytes, serializer);
        bytes.zeroize();
        result
    }
}

impl<'de> Deserialize<'de> for V1KeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // CBOR encoded keyset is 168 bytes. `Zeroizing` wipes the buffer on
        // every exit path — including the `?` early returns below, where a
        // malformed or truncated input would otherwise leave whatever was
        // decoded so far on the stack.
        let mut buffer = Zeroizing::new([0u8; 168]);
        // Discards the returned `&[u8]`: it just borrows `buffer`, which we
        // read through the `Zeroizing` guard below so it still gets wiped.
        let _ = serdect::array::deserialize_hex_or_bin(&mut *buffer, deserializer)?;
        let keyset = KeySet::from_bytes(&*buffer).map_err(serde::de::Error::custom)?;

        Ok(Self(keyset))
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientKey, DataKey};
    use recipher::keyset::{EncryptionKeySet, ProxyKeySet};

    fn random_keyset() -> ProxyKeySet {
        let ek_a = EncryptionKeySet::generate().unwrap();
        let ek_b = EncryptionKeySet::generate().unwrap();
        ProxyKeySet::generate(&ek_a, &ek_b)
    }

    mod from_hex_v1 {
        use super::*;

        #[test]
        fn round_trips_through_to_hex_v1() {
            let id = uuid::Uuid::new_v4();
            let hex = ClientKey::new_v1(id, random_keyset()).to_hex_v1().unwrap();

            let restored = ClientKey::from_hex_v1(id, &hex).unwrap();

            assert_eq!(restored.key_id, id);
            assert_eq!(restored.to_hex_v1().unwrap(), hex, "hex must round-trip");
        }

        #[test]
        fn rejects_non_hex_with_the_custom_message() {
            let err = ClientKey::from_hex_v1(uuid::Uuid::nil(), "not hex!!").unwrap_err();

            assert!(
                err.to_string().contains("invalid hex"),
                "expected the custom invalid-hex message, got: {err}"
            );
        }

        #[test]
        fn rejects_hex_that_is_not_a_keyset() {
            let err = ClientKey::from_hex_v1(uuid::Uuid::nil(), "deadbeef").unwrap_err();

            assert!(
                !err.to_string().contains("invalid hex"),
                "valid hex of the wrong shape must fail at keyset decoding, got: {err}"
            );
        }
    }

    mod v1_keyset_deserialize {
        use super::super::V1KeySet;

        #[test]
        fn rejects_a_truncated_keyset() {
            // Valid hex, but shorter than the 168-byte CBOR keyset — exercises
            // the early-return after the buffer was partially written.
            let short = serde_json::to_string(&"00".repeat(20)).unwrap();
            let err = serde_json::from_str::<V1KeySet>(&short).unwrap_err();
            assert!(!err.to_string().is_empty());
        }

        #[test]
        fn rejects_non_hex_input() {
            let err = serde_json::from_str::<V1KeySet>("\"zz\"").unwrap_err();
            assert!(!err.to_string().is_empty());
        }
    }

    mod index_key {
        use super::*;
        use crate::errors::LoadKeysetError;
        use crate::key::IndexKey;
        use zerokms_protocol::testing::index_key_kat;

        fn kat_client_key() -> ClientKey {
            ClientKey::from_hex_v1(uuid::Uuid::nil(), index_key_kat::KEYSET_HEX).unwrap()
        }

        fn kat_material() -> zerokms_protocol::ViturKeyMaterial {
            index_key_kat::key_material().into()
        }

        /// Known-answer test pinning the index-key derivation to the shared
        /// fixture in `zerokms_protocol::testing::index_key_kat`.
        ///
        /// cipherstash-client (`zerokms::vitur_client::key`) runs the same KAT
        /// against the same fixture: the `ZEROKMS-INDEXKEY` zero-IV blake3-XOF
        /// derivation is duplicated across the two crates and must stay
        /// bit-identical, or records indexed via one stack become silently
        /// unfindable when queried via the other. If this test breaks, the
        /// derivation changed — do NOT update the fixture without changing
        /// cipherstash-client in lockstep.
        #[test]
        fn from_key_material_matches_the_known_answer() {
            let index_key =
                IndexKey::from_key_material(&kat_client_key(), &kat_material()).unwrap();

            assert_eq!(
                base16ct::lower::encode_string(index_key.key()),
                index_key_kat::EXPECTED_INDEX_KEY_HEX,
            );
        }

        #[test]
        fn from_key_material_is_deterministic() {
            let a = IndexKey::from_key_material(&kat_client_key(), &kat_material()).unwrap();
            let b = IndexKey::from_key_material(&kat_client_key(), &kat_material()).unwrap();
            assert_eq!(a.key(), b.key());
        }

        #[test]
        fn from_key_material_rejects_invalid_lengths_instead_of_panicking() {
            use recipher::errors::RecipherError;

            let ck = kat_client_key();
            let expected_len = index_key_kat::key_material().len();
            // Truncated, empty, non-block-multiple and over-long payloads: all
            // network-supplied shapes that previously panicked inside recipher.
            for len in [0usize, 1, 16, 527, 529, expected_len * 2] {
                let material: zerokms_protocol::ViturKeyMaterial = vec![0u8; len].into();
                match IndexKey::from_key_material(&ck, &material) {
                    Err(LoadKeysetError::InvalidKeyMaterial(e)) => {
                        assert!(
                            matches!(
                                e.0,
                                RecipherError::InvalidInputLength { expected, received }
                                    if expected == expected_len && received == len
                            ),
                            "unexpected inner error: {e:?}"
                        );
                    }
                    other => panic!(
                        "length {len} must be rejected as InvalidKeyMaterial, got: {other:?}"
                    ),
                }
            }
        }
    }

    #[test]
    fn test_opaque_debug_datakey() {
        let key = DataKey {
            iv: [0; 16],
            key: [0; 32],
        };
        assert_eq!(format!("{key:?}"), "DataKey { ... }");
    }

    #[test]
    fn test_v1_keyset_serde() {
        let ek_a = EncryptionKeySet::generate().unwrap();
        let ek_b = EncryptionKeySet::generate().unwrap();
        let keyset = ProxyKeySet::generate(&ek_a, &ek_b);
        let v1_keyset = super::V1KeySet(keyset);

        let serialized = serde_json::to_string(&v1_keyset).unwrap();
        let deserialized: super::V1KeySet = serde_json::from_str(&serialized).unwrap();

        // The current key implementation doesn't implement PartialEq because it can't do it safely.
        assert_eq!(
            v1_keyset.0.to_bytes().unwrap(),
            deserialized.0.to_bytes().unwrap()
        );
    }

    #[test]
    fn test_client_key_toml() {
        let ek_a = EncryptionKeySet::generate().unwrap();
        let ek_b = EncryptionKeySet::generate().unwrap();
        let keyset = ProxyKeySet::generate(&ek_a, &ek_b);
        let key_id = uuid::Uuid::new_v4();
        let client_key = ClientKey::new_v1(key_id, keyset);

        let toml = toml::to_string(&client_key).unwrap();

        let mut table = toml::Table::new();
        table.insert(
            String::from("client_id"),
            toml::Value::String(key_id.to_string()),
        );
        table.insert(
            String::from("client_key"),
            toml::Value::String(client_key.to_hex_v1().unwrap()),
        );

        assert_eq!(toml, table.to_string());
    }
}
