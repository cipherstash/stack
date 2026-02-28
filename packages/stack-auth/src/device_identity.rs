use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config_dir;
use crate::token_store::TokenStoreError;

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

impl DeviceIdentity {
    /// Returns the default device identity location: `~/.cipherstash/device.json`.
    pub fn default_location() -> Result<PathBuf, TokenStoreError> {
        Ok(config_dir()?.join("device.json"))
    }

    /// Load an existing device identity from the given path, or create a new one
    /// if none exists.
    ///
    /// When creating, generates a UUIDv4 and uses the system hostname as the
    /// default device name.
    pub fn load_or_create(path: &Path) -> Result<Self, TokenStoreError> {
        match Self::load(path) {
            Ok(identity) => Ok(identity),
            Err(TokenStoreError::NotFound) => {
                let identity = Self {
                    device_instance_id: Uuid::new_v4(),
                    device_name: gethostname::gethostname().to_string_lossy().into_owned(),
                };
                identity.save(path)?;
                Ok(identity)
            }
            Err(e) => Err(e),
        }
    }

    /// Load a device identity from the given path.
    ///
    /// Returns [`TokenStoreError::NotFound`] if the file does not exist.
    pub fn load(path: &Path) -> Result<Self, TokenStoreError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let identity: Self = serde_json::from_str(&contents)?;
                Ok(identity)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(TokenStoreError::NotFound),
            Err(e) => Err(TokenStoreError::Io(e)),
        }
    }

    /// Save this identity to the given path, creating parent directories as needed.
    fn save(&self, path: &Path) -> Result<(), TokenStoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_generates_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.json");

        let identity = DeviceIdentity::load_or_create(&path).unwrap();
        assert!(!identity.device_instance_id.is_nil());
        assert!(!identity.device_name.is_empty());
    }

    #[test]
    fn load_or_create_reuses_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.json");

        let first = DeviceIdentity::load_or_create(&path).unwrap();
        let second = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(first.device_instance_id, second.device_instance_id);
        assert_eq!(first.device_name, second.device_name);
    }

    #[test]
    fn load_returns_not_found_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let err = DeviceIdentity::load(&path).unwrap_err();
        assert!(matches!(err, TokenStoreError::NotFound));
    }

    #[test]
    fn round_trip_serialization() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.json");

        let original = DeviceIdentity {
            device_instance_id: Uuid::new_v4(),
            device_name: "test-host".to_string(),
        };
        original.save(&path).unwrap();

        let loaded = DeviceIdentity::load(&path).unwrap();
        assert_eq!(original.device_instance_id, loaded.device_instance_id);
        assert_eq!(original.device_name, loaded.device_name);
    }
}
