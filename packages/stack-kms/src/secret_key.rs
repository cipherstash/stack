use base64ct::Encoding;
use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use stack_profile::{ProfileData, ProfileError, ProfileStore};
use uuid::Uuid;
use vitaminc::protected::OpaqueDebug;
use zeroize::{Zeroize, ZeroizeOnDrop};
use zerokms_protocol::ViturKeyMaterial;

use crate::key::ClientKey;
use crate::key_provider::{KeyProvider, KeyProviderError};

/// Decode client key material accepting either hex (preferred) or standard padded base64.
///
/// `secretkey.json` serialises key material as base64 (via `ViturKeyMaterial`'s serde),
/// while `CS_CLIENT_KEY` has historically been hex. Tolerating either at parse time
/// means users can copy-paste between the two without re-encoding.
///
/// Tries hex first via `base16ct::mixed::decode_vec` (constant-time). Falls back to
/// `base64ct::Base64::decode_vec` (also constant-time) only if the hex parse fails —
/// which it does for any string containing `+`, `/`, `=`, or other non-hex chars.
pub(crate) fn decode_client_key_material(s: &str) -> Result<Vec<u8>, String> {
    if let Ok(bytes) = base16ct::mixed::decode_vec(s) {
        return Ok(bytes);
    }
    base64ct::Base64::decode_vec(s)
        .map_err(|e| format!("invalid encoding (expected hex or base64): {e}"))
}

/// A device-scoped client key, stored in `secretkey.json` within the profile directory.
///
/// The key material is zeroized on drop and hidden from debug output.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use stack_kms::{SecretKey, KeyProvider};
/// use zerokms_protocol::ViturKeyMaterial;
/// use uuid::Uuid;
///
/// let key_material: ViturKeyMaterial = vec![/* key bytes */].into();
/// let secret_key = SecretKey::new(
///     Uuid::new_v4(),
///     key_material,
/// );
///
/// // SecretKey implements KeyProvider
/// let client_key = secret_key.client_key().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop, OpaqueDebug)]
pub struct SecretKey {
    /// The client ID returned by ZeroKMS when creating a device keyset.
    #[zeroize(skip)]
    client_id: Uuid,
    /// The client key material for this device.
    client_key: ViturKeyMaterial,
}

impl SecretKey {
    /// Create a new [`SecretKey`] from the given client ID and key material.
    pub fn new(client_id: Uuid, client_key: ViturKeyMaterial) -> Self {
        Self {
            client_id,
            client_key,
        }
    }

    /// Create a [`SecretKey`] from string representations of the client ID and encoded
    /// key material.
    ///
    /// Accepts the key material as either **hex** (the historical `CS_CLIENT_KEY` format)
    /// **or** standard padded **base64** (the format used by `secretkey.json` on disk).
    /// Hex is tried first; base64 is a fallback for any input that doesn't parse as hex.
    ///
    /// Named `from_hex` for historical reasons — the function is now lenient. The name
    /// is preserved to avoid breaking callers.
    ///
    /// # Errors
    ///
    /// Returns [`KeyProviderError::InvalidKey`] if:
    /// - `client_id` is not a valid UUID
    /// - `client_key_encoded` is neither valid hex nor valid base64
    pub fn from_hex(
        client_id: String,
        mut client_key_encoded: String,
    ) -> Result<Self, KeyProviderError> {
        // Decode and zeroize the encoded key material *first*, so no later
        // fallible step (e.g. the UUID parse below) can early-return and leave
        // the secret sitting un-zeroized in the owned `String`.
        let result = decode_client_key_material(&client_key_encoded);
        client_key_encoded.zeroize();

        let mut bytes =
            result.map_err(|e| KeyProviderError::InvalidKey(format!("invalid client_key: {e}")))?;

        let uuid = match Uuid::parse_str(&client_id) {
            Ok(uuid) => uuid,
            Err(e) => {
                // The decoded key material is now the live copy of the secret —
                // zeroize it before returning rather than dropping the plain `Vec`.
                bytes.zeroize();
                return Err(KeyProviderError::InvalidKey(format!(
                    "invalid client_id: {e}"
                )));
            }
        };

        Ok(Self::new(uuid, ViturKeyMaterial::from(bytes)))
    }

    /// Load a [`SecretKey`] from the `CS_CLIENT_ID` and `CS_CLIENT_KEY` environment variables.
    ///
    /// `CS_CLIENT_KEY` accepts either hex (the historical format) or the base64 value
    /// that appears in `secretkey.json` — see [`SecretKey::from_hex`].
    ///
    /// Returns `Ok(None)` if neither or only one variable is set, allowing callers to
    /// fall back to another source. Returns `Err` if both variables are present but
    /// the values are invalid (bad UUID or bad encoding).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_kms::SecretKey;
    ///
    /// let key = SecretKey::from_env().expect("invalid key material in env");
    /// // key is Option<SecretKey> — None means "not configured via env"
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_env() -> Result<Option<Self>, KeyProviderError> {
        use crate::vars::{CS_CLIENT_ID, CS_CLIENT_KEY};

        match (std::env::var(CS_CLIENT_ID), std::env::var(CS_CLIENT_KEY)) {
            (Ok(id), Ok(key)) => {
                tracing::debug!("both {CS_CLIENT_ID} and {CS_CLIENT_KEY} set, loading secret key");
                Self::from_hex(id, key).map(Some)
            }
            (Ok(_), Err(_)) => {
                tracing::debug!("{CS_CLIENT_ID} set but {CS_CLIENT_KEY} missing, skipping");
                Ok(None)
            }
            (Err(_), Ok(_)) => {
                tracing::debug!("{CS_CLIENT_KEY} set but {CS_CLIENT_ID} missing, skipping");
                Ok(None)
            }
            (Err(_), Err(_)) => {
                tracing::debug!("neither {CS_CLIENT_ID} nor {CS_CLIENT_KEY} set");
                Ok(None)
            }
        }
    }
}

/// Implement [ProfileData] for [SecretKey] to enable loading/saving from the profile directory.
#[cfg(not(target_arch = "wasm32"))]
impl ProfileData for SecretKey {
    const FILENAME: &'static str = "secretkey.json";
    const MODE: Option<u32> = Some(0o600);
}

/// Implement [KeyProvider] for [SecretKey] to allow it to be used directly as a key source when initializing with a [super::StackKmsBuilder].
impl KeyProvider for SecretKey {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        ClientKey::from_bytes(self.client_id, &self.client_key)
            .map_err(|e| KeyProviderError::InvalidKey(e.to_string()))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl KeyProvider for ProfileStore {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        let ws_store = self.current_workspace_store().map_err(|e| match e {
            ProfileError::NoCurrentWorkspace => KeyProviderError::NotConfigured(e.to_string()),
            _ => KeyProviderError::LoadError(e.to_string()),
        })?;
        let secret_key: SecretKey = ws_store.load_profile().map_err(|e| match e {
            ProfileError::NotFound { .. } => KeyProviderError::NotConfigured(e.to_string()),
            _ => KeyProviderError::LoadError(e.to_string()),
        })?;
        secret_key.client_key().await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use recipher::keyset::{EncryptionKeySet, ProxyKeySet};
    use tempfile::TempDir;

    /// Build a random `SecretKey` and return it alongside the `client_id` and raw keyset bytes.
    fn random_secret_key() -> (SecretKey, Uuid, Vec<u8>) {
        let client_id = Uuid::new_v4();
        let ek_a = EncryptionKeySet::generate().unwrap();
        let ek_b = EncryptionKeySet::generate().unwrap();
        let keyset = ProxyKeySet::generate(&ek_a, &ek_b);
        let bytes = keyset.to_bytes().unwrap();

        let secret_key = SecretKey::new(client_id, ViturKeyMaterial::from(bytes.clone()));

        (secret_key, client_id, bytes)
    }

    mod secret_key_provider {
        use super::*;

        #[tokio::test]
        async fn returns_client_key_with_matching_id() {
            let (secret_key, client_id, _) = random_secret_key();

            let result = secret_key.client_key().await.unwrap();

            assert_eq!(
                result.key_id, client_id,
                "client_key should preserve the client_id"
            );
        }

        #[tokio::test]
        async fn returns_client_key_with_correct_key_material() {
            let (secret_key, _, bytes) = random_secret_key();

            let result = secret_key.client_key().await.unwrap();

            let expected_hex = base16ct::lower::encode_string(&bytes);
            let actual_hex = result.to_hex_v1().unwrap();
            assert_eq!(
                actual_hex, expected_hex,
                "client_key should preserve the key material"
            );
        }

        #[tokio::test]
        async fn returns_invalid_key_for_bad_material() {
            let secret_key =
                SecretKey::new(Uuid::new_v4(), ViturKeyMaterial::from(vec![0xDE, 0xAD]));

            let err = secret_key.client_key().await.unwrap_err();

            assert!(
                matches!(err, KeyProviderError::InvalidKey(_)),
                "expected InvalidKey for garbage bytes, got: {err:?}"
            );
        }
    }

    mod from_hex {
        use super::*;

        #[tokio::test]
        async fn round_trips_through_key_provider() {
            let (original, client_id, bytes) = random_secret_key();
            let hex = base16ct::lower::encode_string(&bytes);

            let from_hex = SecretKey::from_hex(client_id.to_string(), hex).unwrap();

            let original_key = original.client_key().await.unwrap();
            let from_hex_key = from_hex.client_key().await.unwrap();

            assert_eq!(
                original_key.key_id, from_hex_key.key_id,
                "from_hex should produce the same client_id"
            );
            assert_eq!(
                original_key.to_hex_v1().unwrap(),
                from_hex_key.to_hex_v1().unwrap(),
                "from_hex should produce the same key material"
            );
        }

        #[test]
        fn returns_invalid_key_for_bad_uuid() {
            let err = SecretKey::from_hex("not-a-uuid".into(), "deadbeef".into()).unwrap_err();

            assert!(
                matches!(err, KeyProviderError::InvalidKey(_)),
                "expected InvalidKey for bad UUID, got: {err:?}"
            );
        }

        #[test]
        fn returns_invalid_key_for_bad_encoding() {
            let uuid = Uuid::new_v4();
            // `!!` is rejected by both hex and base64 decoders
            let err =
                SecretKey::from_hex(uuid.to_string(), "not-valid-anything!!".into()).unwrap_err();

            assert!(
                matches!(err, KeyProviderError::InvalidKey(_)),
                "expected InvalidKey for bad encoding, got: {err:?}"
            );
        }

        #[tokio::test]
        async fn accepts_base64_encoded_key_material() {
            use base64ct::Encoding;
            let (_, client_id, bytes) = random_secret_key();
            let b64 = base64ct::Base64::encode_string(&bytes);

            let from_b64 = SecretKey::from_hex(client_id.to_string(), b64).unwrap();
            let key = from_b64.client_key().await.unwrap();

            let expected_hex = base16ct::lower::encode_string(&bytes);
            assert_eq!(
                key.to_hex_v1().unwrap(),
                expected_hex,
                "base64-encoded key material should round-trip to the same bytes as hex"
            );
        }
    }

    mod from_env {
        use super::*;
        use crate::test_env::ScopedEnv;
        use crate::vars::{CS_CLIENT_ID, CS_CLIENT_KEY};

        #[test]
        fn both_set_and_valid_returns_some() {
            let (_, id, bytes) = random_secret_key();
            let id = id.to_string();
            let hex = base16ct::lower::encode_string(&bytes);
            let _env = ScopedEnv::new(&[(CS_CLIENT_ID, Some(&id)), (CS_CLIENT_KEY, Some(&hex))]);

            let key = SecretKey::from_env().unwrap().expect("both variables set");

            assert_eq!(key.client_id.to_string(), id);
            assert_eq!(&*key.client_key, bytes.as_slice());
        }

        #[test]
        fn only_id_set_returns_none() {
            let id = Uuid::new_v4().to_string();
            let _env = ScopedEnv::new(&[(CS_CLIENT_ID, Some(&id)), (CS_CLIENT_KEY, None)]);

            assert!(SecretKey::from_env().unwrap().is_none());
        }

        #[test]
        fn only_key_set_returns_none() {
            let _env = ScopedEnv::new(&[(CS_CLIENT_ID, None), (CS_CLIENT_KEY, Some("deadbeef"))]);

            assert!(SecretKey::from_env().unwrap().is_none());
        }

        #[test]
        fn neither_set_returns_none() {
            let _env = ScopedEnv::new(&[(CS_CLIENT_ID, None), (CS_CLIENT_KEY, None)]);

            assert!(SecretKey::from_env().unwrap().is_none());
        }

        #[test]
        fn both_set_but_invalid_returns_err() {
            let _env = ScopedEnv::new(&[
                (CS_CLIENT_ID, Some("not-a-uuid")),
                (CS_CLIENT_KEY, Some("deadbeef")),
            ]);

            let err = SecretKey::from_env().unwrap_err();

            assert!(
                matches!(err, KeyProviderError::InvalidKey(_)),
                "expected InvalidKey, got: {err:?}"
            );
        }
    }

    mod profile_store_provider {
        use super::*;

        const TEST_WORKSPACE_ID: &str = "ZVATKW3VHMFG27DY";

        #[tokio::test]
        async fn loads_secret_key_from_disk() {
            let dir = TempDir::new().unwrap();
            let store = ProfileStore::new(dir.path());
            store.init_workspace(TEST_WORKSPACE_ID).unwrap();

            let (secret_key, client_id, bytes) = random_secret_key();
            let ws_store = store.current_workspace_store().unwrap();
            ws_store.save_profile(&secret_key).unwrap();

            let result = store.client_key().await.unwrap();

            assert_eq!(
                result.key_id, client_id,
                "should load and convert the stored SecretKey"
            );

            let expected_hex = base16ct::lower::encode_string(&bytes);
            let actual_hex = result.to_hex_v1().unwrap();
            assert_eq!(
                actual_hex, expected_hex,
                "should preserve the key material after round-tripping through disk"
            );
        }

        #[tokio::test]
        async fn returns_not_configured_when_no_workspace_set() {
            let dir = TempDir::new().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store.client_key().await.unwrap_err();

            assert!(
                matches!(err, KeyProviderError::NotConfigured(_)),
                "expected NotConfigured when no workspace is set, got: {err:?}"
            );
        }

        #[tokio::test]
        async fn returns_not_configured_when_file_missing() {
            let dir = TempDir::new().unwrap();
            let store = ProfileStore::new(dir.path());
            store.init_workspace(TEST_WORKSPACE_ID).unwrap();

            let err = store.client_key().await.unwrap_err();

            assert!(
                matches!(err, KeyProviderError::NotConfigured(_)),
                "expected NotConfigured for missing file, got: {err:?}"
            );

            let msg = err.to_string();
            assert!(
                msg.contains("Profile not found"),
                "error should explain the profile is missing, got: {msg}"
            );
        }

        #[tokio::test]
        async fn returns_load_error_for_invalid_json() {
            let dir = TempDir::new().unwrap();
            let store = ProfileStore::new(dir.path());
            store.init_workspace(TEST_WORKSPACE_ID).unwrap();

            // Write invalid JSON to the workspace-scoped file path
            let ws_dir = dir.path().join("workspaces").join(TEST_WORKSPACE_ID);
            std::fs::create_dir_all(&ws_dir).unwrap();
            std::fs::write(ws_dir.join(SecretKey::FILENAME), "not json").unwrap();

            let err = store.client_key().await.unwrap_err();

            assert!(
                matches!(err, KeyProviderError::LoadError(_)),
                "expected LoadError for corrupt file, got: {err:?}"
            );

            let msg = err.to_string();
            assert!(
                msg.contains("JSON error"),
                "error should mention the JSON parse failure, got: {msg}"
            );
        }
    }
}
