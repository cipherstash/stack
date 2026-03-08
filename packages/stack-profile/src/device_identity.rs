use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ProfileData, ProfileError, ProfileStore};

/// Persistent identity for a CLI installation.
///
/// Each device gets a unique `device_instance_id` (UUIDv4) and a human-readable
/// `device_name` (defaults to the hostname). The identity is stored in
/// `~/.cipherstash/device.json` and reused across sessions so the server can
/// track device lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// A UUIDv4 that uniquely identifies this CLI installation.
    pub device_instance_id: Uuid,
    /// A human-readable name for this device (defaults to the hostname).
    pub device_name: String,
}

impl ProfileData for DeviceIdentity {
    const FILENAME: &'static str = "device.json";
    const MODE: Option<u32> = Some(0o600);
}

impl DeviceIdentity {
    /// Load an existing device identity from the given store, or create a new
    /// one if none exists.
    ///
    /// When creating, generates a UUIDv4 and uses the system hostname as the
    /// default device name. The file is written with mode 0600 on Unix.
    pub fn load_or_create(store: &ProfileStore) -> Result<Self, ProfileError> {
        match store.load_profile::<Self>() {
            Ok(identity) => Ok(identity),
            Err(ProfileError::NotFound { .. }) => {
                let identity = Self {
                    device_instance_id: Uuid::new_v4(),
                    device_name: gethostname::gethostname().to_string_lossy().into_owned(),
                };
                store.save_profile(&identity)?;
                Ok(identity)
            }
            Err(e) => Err(e),
        }
    }

    /// Load a device identity from the given store.
    ///
    /// Returns [`ProfileError::NotFound`] if the file does not exist.
    pub fn load(store: &ProfileStore) -> Result<Self, ProfileError> {
        store.load_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_generates_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        let identity = DeviceIdentity::load_or_create(&store).unwrap();
        assert!(!identity.device_instance_id.is_nil());
        assert!(!identity.device_name.is_empty());
    }

    #[test]
    fn load_or_create_reuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        let first = DeviceIdentity::load_or_create(&store).unwrap();
        let second = DeviceIdentity::load_or_create(&store).unwrap();
        assert_eq!(first.device_instance_id, second.device_instance_id);
        assert_eq!(first.device_name, second.device_name);
    }

    #[test]
    fn load_returns_not_found_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());
        let err = DeviceIdentity::load(&store).unwrap_err();
        assert!(matches!(err, ProfileError::NotFound { .. }));
    }

    #[test]
    fn round_trip_serialization() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        let original = DeviceIdentity {
            device_instance_id: Uuid::new_v4(),
            device_name: "test-host".to_string(),
        };
        store.save("device.json", &original).unwrap();

        let loaded = DeviceIdentity::load(&store).unwrap();
        assert_eq!(original.device_instance_id, loaded.device_instance_id);
        assert_eq!(original.device_name, loaded.device_name);
    }
}
