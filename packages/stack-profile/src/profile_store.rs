use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{ProfileData, ProfileError};

const CS_CONFIG_PATH_ENV: &str = "CS_CONFIG_PATH";
const DEFAULT_DIR_NAME: &str = ".cipherstash";

/// A directory-scoped JSON file store for profile data.
///
/// `ProfileStore` represents a profile directory (typically `~/.cipherstash/`).
/// Individual files are addressed by name when calling [`save`](Self::save),
/// [`load`](Self::load), and other operations.
///
/// # Example
///
/// ```no_run
/// use stack_profile::ProfileStore;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyConfig {
///     name: String,
/// }
///
/// # fn main() -> Result<(), stack_profile::ProfileError> {
/// let store = ProfileStore::resolve(None)?;
/// store.save("my-config.json", &MyConfig { name: "example".into() })?;
/// let config: MyConfig = store.load("my-config.json")?;
/// # Ok(())
/// # }
/// ```
pub struct ProfileStore {
    dir: PathBuf,
}

impl ProfileStore {
    /// Create a profile store rooted at the given directory.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Resolve the profile directory.
    ///
    /// Resolution order:
    /// 1. `explicit` path, if provided
    /// 2. `CS_CONFIG_PATH` environment variable, if set
    /// 3. `~/.cipherstash` (the default)
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self, ProfileError> {
        if let Some(path) = explicit {
            return Ok(Self::new(path));
        }
        if let Ok(path) = std::env::var(CS_CONFIG_PATH_ENV) {
            if !path.trim().is_empty() {
                return Ok(Self::new(path));
            }
        }
        let home = dirs::home_dir().ok_or(ProfileError::HomeDirNotFound)?;
        Ok(Self::new(home.join(DEFAULT_DIR_NAME)))
    }

    /// Return the directory path.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Save a value as pretty-printed JSON to a file in the store directory.
    ///
    /// Creates the directory and any parents if they don't exist.
    pub fn save<T: Serialize>(&self, filename: &str, value: &T) -> Result<(), ProfileError> {
        self.write(filename, value, None)
    }

    /// Save a value as pretty-printed JSON with restricted Unix file permissions.
    ///
    /// On non-Unix platforms the mode is ignored and this behaves like [`save`](Self::save).
    pub fn save_with_mode<T: Serialize>(
        &self,
        filename: &str,
        value: &T,
        _mode: u32,
    ) -> Result<(), ProfileError> {
        #[cfg(unix)]
        return self.write(filename, value, Some(_mode));
        #[cfg(not(unix))]
        self.write(filename, value, None)
    }

    /// Validate that a filename is a plain, non-empty filename (no path separators or `..`).
    fn validate_filename(filename: &str) -> Result<(), ProfileError> {
        let path = Path::new(filename);
        if filename.is_empty()
            || path.is_absolute()
            || filename.contains(std::path::MAIN_SEPARATOR)
            || filename.contains('/')
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ProfileError::InvalidFilename(filename.to_string()));
        }
        Ok(())
    }

    fn write<T: Serialize>(
        &self,
        filename: &str,
        value: &T,
        _mode: Option<u32>,
    ) -> Result<(), ProfileError> {
        Self::validate_filename(filename)?;
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(filename);
        let json = serde_json::to_string_pretty(value)?;

        #[cfg(unix)]
        if let Some(mode) = _mode {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(mode)
                .open(&path)?;
            file.write_all(json.as_bytes())?;

            // Ensure permissions are set even if the file already existed,
            // since OpenOptions::mode() only applies on creation.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;

            return Ok(());
        }

        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Load a value from a JSON file in the store directory.
    ///
    /// Returns [`ProfileError::NotFound`] if the file does not exist.
    pub fn load<T: DeserializeOwned>(&self, filename: &str) -> Result<T, ProfileError> {
        Self::validate_filename(filename)?;
        let path = self.dir.join(filename);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let value: T = serde_json::from_str(&contents)?;
                Ok(value)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ProfileError::NotFound { path })
            }
            Err(e) => Err(ProfileError::Io(e)),
        }
    }

    /// Remove a file from the store directory.
    ///
    /// Does nothing if the file does not already exist.
    pub fn clear(&self, filename: &str) -> Result<(), ProfileError> {
        Self::validate_filename(filename)?;
        let path = self.dir.join(filename);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProfileError::Io(e)),
        }
    }

    /// Check whether a file exists in the store directory.
    pub fn exists(&self, filename: &str) -> bool {
        Self::validate_filename(filename).is_ok() && self.dir.join(filename).exists()
    }

    /// Save a [`ProfileData`] value using its declared filename and mode.
    pub fn save_profile<T: ProfileData>(&self, value: &T) -> Result<(), ProfileError> {
        self.write(T::FILENAME, value, T::MODE)
    }

    /// Load a [`ProfileData`] value from its declared filename.
    pub fn load_profile<T: ProfileData>(&self) -> Result<T, ProfileError> {
        self.load(T::FILENAME)
    }

    /// Remove the file for a [`ProfileData`] type.
    pub fn clear_profile<T: ProfileData>(&self) -> Result<(), ProfileError> {
        self.clear(T::FILENAME)
    }

    /// Check whether the file for a [`ProfileData`] type exists.
    pub fn exists_profile<T: ProfileData>(&self) -> bool {
        self.exists(T::FILENAME)
    }
}

/// Returns a profile store at `~/.cipherstash`.
///
/// # Panics
///
/// Panics if the home directory cannot be determined.
impl Default for ProfileStore {
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        let home = dirs::home_dir().expect("could not determine home directory");
        Self::new(home.join(DEFAULT_DIR_NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestData {
        name: String,
        value: u32,
    }

    #[test]
    fn round_trip_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        let data = TestData {
            name: "hello".into(),
            value: 42,
        };
        store.save("data.json", &data).unwrap();

        let loaded: TestData = store.load("data.json").unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn load_returns_not_found_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        let err = store.load::<TestData>("missing.json").unwrap_err();
        assert!(matches!(err, ProfileError::NotFound { .. }));
    }

    #[test]
    fn clear_removes_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        store
            .save(
                "data.json",
                &TestData {
                    name: "x".into(),
                    value: 1,
                },
            )
            .unwrap();
        assert!(store.exists("data.json"));

        store.clear("data.json").unwrap();
        assert!(!store.exists("data.json"));
    }

    #[test]
    fn clear_succeeds_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());
        store.clear("missing.json").unwrap();
    }

    #[test]
    fn save_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path().join("nested").join("dir"));

        store
            .save(
                "data.json",
                &TestData {
                    name: "nested".into(),
                    value: 99,
                },
            )
            .unwrap();

        let loaded: TestData = store.load("data.json").unwrap();
        assert_eq!(loaded.name, "nested");
    }

    #[test]
    fn exists_returns_false_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());
        assert!(!store.exists("missing.json"));
    }

    #[test]
    fn default_is_home_dot_cipherstash() {
        let store = ProfileStore::default();
        let home = dirs::home_dir().unwrap();
        assert_eq!(store.dir(), home.join(".cipherstash"));
    }

    #[test]
    fn resolve_explicit_overrides_all() {
        let store = ProfileStore::resolve(Some("/tmp/custom".into())).unwrap();
        assert_eq!(store.dir(), std::path::Path::new("/tmp/custom"));
    }

    mod filename_validation {
        use super::*;

        #[test]
        fn rejects_empty_string() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store
                .save(
                    "",
                    &TestData {
                        name: "x".into(),
                        value: 1,
                    },
                )
                .unwrap_err();
            assert!(matches!(err, ProfileError::InvalidFilename(_)));
        }

        #[test]
        fn rejects_absolute_path() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store
                .save(
                    "/etc/passwd",
                    &TestData {
                        name: "x".into(),
                        value: 1,
                    },
                )
                .unwrap_err();
            assert!(matches!(err, ProfileError::InvalidFilename(_)));
        }

        #[test]
        fn rejects_parent_traversal() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store
                .save(
                    "../escape.json",
                    &TestData {
                        name: "x".into(),
                        value: 1,
                    },
                )
                .unwrap_err();
            assert!(matches!(err, ProfileError::InvalidFilename(_)));
        }

        #[test]
        fn rejects_path_with_separator() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store
                .save(
                    "sub/file.json",
                    &TestData {
                        name: "x".into(),
                        value: 1,
                    },
                )
                .unwrap_err();
            assert!(matches!(err, ProfileError::InvalidFilename(_)));
        }

        #[test]
        fn rejects_on_load() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store.load::<TestData>("../escape.json").unwrap_err();
            assert!(matches!(err, ProfileError::InvalidFilename(_)));
        }

        #[test]
        fn rejects_on_clear() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let err = store.clear("../escape.json").unwrap_err();
            assert!(matches!(err, ProfileError::InvalidFilename(_)));
        }

        #[test]
        fn exists_returns_false_for_invalid_filename() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            assert!(!store.exists("../escape.json"));
        }

        #[test]
        fn accepts_plain_filename() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            store
                .save(
                    "valid.json",
                    &TestData {
                        name: "ok".into(),
                        value: 1,
                    },
                )
                .unwrap();
            let loaded: TestData = store.load("valid.json").unwrap();
            assert_eq!(loaded.name, "ok");
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_with_mode_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        store
            .save_with_mode(
                "secret.json",
                &TestData {
                    name: "secret".into(),
                    value: 1,
                },
                0o600,
            )
            .unwrap();

        let meta = std::fs::metadata(dir.path().join("secret.json")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_with_mode_tightens_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());
        let path = dir.path().join("secret.json");

        // Create file with broad permissions first
        store
            .save(
                "secret.json",
                &TestData {
                    name: "v1".into(),
                    value: 1,
                },
            )
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Overwrite with restricted mode
        store
            .save_with_mode(
                "secret.json",
                &TestData {
                    name: "v2".into(),
                    value: 2,
                },
                0o600,
            )
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "permissions should be tightened on existing file"
        );
    }
}
