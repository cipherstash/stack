use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{ProfileData, ProfileError};

const CS_CONFIG_PATH_ENV: &str = "CS_CONFIG_PATH";
const DEFAULT_DIR_NAME: &str = ".cipherstash";
const WORKSPACES_DIR: &str = "workspaces";
const CURRENT_WORKSPACE_FILE: &str = "current_workspace";

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
#[derive(Debug)]
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

    /// Validate that a workspace ID is a 16-character base32 string (A-Z, 2-7).
    ///
    /// This prevents path traversal without depending on `cts_common::WorkspaceId`.
    fn validate_workspace_id(id: &str) -> Result<(), ProfileError> {
        let valid = id.len() == 16
            && id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b));
        if valid {
            Ok(())
        } else {
            Err(ProfileError::InvalidWorkspaceId(id.to_string()))
        }
    }

    // ---- Workspace management ----

    /// Set the current workspace.
    ///
    /// Writes the workspace ID to the `current_workspace` file in the profile
    /// directory. The workspace must already have a directory under `workspaces/`
    /// (created during login). Use [`init_workspace`](Self::init_workspace) to
    /// create a new workspace directory.
    ///
    /// Returns [`ProfileError::WorkspaceNotFound`] if the workspace directory
    /// does not exist.
    pub fn set_current_workspace(&self, workspace_id: &str) -> Result<(), ProfileError> {
        Self::validate_workspace_id(workspace_id)?;
        let ws_dir = self.dir.join(WORKSPACES_DIR).join(workspace_id);
        if !ws_dir.is_dir() {
            return Err(ProfileError::WorkspaceNotFound(workspace_id.to_string()));
        }
        std::fs::create_dir_all(&self.dir)?;
        let path = self.dir.join(CURRENT_WORKSPACE_FILE);
        std::fs::write(&path, workspace_id)?;
        Ok(())
    }

    /// Create a workspace directory and set it as the current workspace.
    ///
    /// Unlike [`set_current_workspace`](Self::set_current_workspace), this
    /// creates the workspace directory if it does not exist. Used during login
    /// to initialize a new workspace.
    pub fn init_workspace(&self, workspace_id: &str) -> Result<(), ProfileError> {
        Self::validate_workspace_id(workspace_id)?;
        // create_dir_all creates self.dir and workspaces/ as ancestors.
        let ws_dir = self.dir.join(WORKSPACES_DIR).join(workspace_id);
        std::fs::create_dir_all(&ws_dir)?;
        let path = self.dir.join(CURRENT_WORKSPACE_FILE);
        std::fs::write(&path, workspace_id)?;
        Ok(())
    }

    /// Return the current workspace ID.
    ///
    /// Returns [`ProfileError::NoCurrentWorkspace`] if no workspace has been set.
    pub fn current_workspace(&self) -> Result<String, ProfileError> {
        let path = self.dir.join(CURRENT_WORKSPACE_FILE);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let id = contents.trim().to_string();
                Self::validate_workspace_id(&id)?;
                Ok(id)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ProfileError::NoCurrentWorkspace)
            }
            Err(e) => Err(ProfileError::Io(e)),
        }
    }

    /// Remove the current workspace selection.
    pub fn clear_current_workspace(&self) -> Result<(), ProfileError> {
        let path = self.dir.join(CURRENT_WORKSPACE_FILE);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ProfileError::Io(e)),
        }
    }

    /// List workspace IDs that have profile data on disk.
    ///
    /// Returns a sorted list of workspace IDs that have subdirectories in
    /// the `workspaces/` directory.
    pub fn list_workspaces(&self) -> Result<Vec<String>, ProfileError> {
        let ws_dir = self.dir.join(WORKSPACES_DIR);
        match std::fs::read_dir(&ws_dir) {
            Ok(entries) => {
                let mut ids = Vec::new();
                for entry in entries {
                    let entry = entry?;
                    if entry.file_type()?.is_dir() {
                        if let Some(name) = entry.file_name().to_str() {
                            if Self::validate_workspace_id(name).is_ok() {
                                ids.push(name.to_string());
                            }
                        }
                    }
                }
                ids.sort();
                Ok(ids)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(ProfileError::Io(e)),
        }
    }

    /// Return a [`ProfileStore`] scoped to a specific workspace directory.
    ///
    /// The returned store is rooted at `workspaces/<workspace_id>/` within this
    /// store's directory. All `save`/`load`/`save_profile`/`load_profile` calls
    /// on the returned store operate inside that workspace directory.
    pub fn workspace_store(&self, workspace_id: &str) -> Result<ProfileStore, ProfileError> {
        Self::validate_workspace_id(workspace_id)?;
        Ok(ProfileStore::new(
            self.dir.join(WORKSPACES_DIR).join(workspace_id),
        ))
    }

    /// Return a [`ProfileStore`] scoped to the current workspace.
    ///
    /// Shortcut for `store.workspace_store(&store.current_workspace()?)`.
    /// Returns [`ProfileError::NoCurrentWorkspace`] if no workspace has been set.
    pub fn current_workspace_store(&self) -> Result<ProfileStore, ProfileError> {
        let id = self.current_workspace()?;
        self.workspace_store(&id)
    }

    /// Move legacy flat-file profiles into a workspace directory.
    ///
    /// Moves `auth.json` and `secretkey.json` from the profile root into
    /// `workspaces/<workspace_id>/` and sets `workspace_id` as the current
    /// workspace. Files that already exist in the target are not overwritten.
    /// Missing source files are silently skipped.
    pub fn migrate_to_workspace(&self, workspace_id: &str) -> Result<(), ProfileError> {
        Self::validate_workspace_id(workspace_id)?;
        let ws_dir = self.dir.join(WORKSPACES_DIR).join(workspace_id);
        std::fs::create_dir_all(&ws_dir)?;

        for filename in &["auth.json", "secretkey.json"] {
            let src = self.dir.join(filename);
            let dst = ws_dir.join(filename);
            if src.exists() && !dst.exists() {
                std::fs::rename(&src, &dst)?;
            }
        }

        self.set_current_workspace(workspace_id)?;
        Ok(())
    }

    // ---- Internal write helpers ----

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
        Self::write_to_path(&path, &json, _mode)
    }

    /// Write JSON content to an absolute path, optionally setting Unix file permissions.
    fn write_to_path(path: &Path, json: &str, _mode: Option<u32>) -> Result<(), ProfileError> {
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
                .open(path)?;
            file.write_all(json.as_bytes())?;

            // Ensure permissions are set even if the file already existed,
            // since OpenOptions::mode() only applies on creation.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

            return Ok(());
        }

        std::fs::write(path, json)?;
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

    mod workspace {
        use super::*;
        use crate::ProfileData;

        const WS_A: &str = "AAAAAAAAAAAAAAAA";
        const WS_B: &str = "BBBBBBBBBBBBBBBB";

        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct WsData {
            name: String,
        }

        impl ProfileData for WsData {
            const FILENAME: &'static str = "ws-data.json";
        }

        mod given_no_workspace_set {
            use super::*;

            #[test]
            fn current_workspace_returns_no_current_workspace() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let err = store.current_workspace().unwrap_err();
                assert!(
                    matches!(err, ProfileError::NoCurrentWorkspace),
                    "expected NoCurrentWorkspace, got: {err:?}"
                );
            }

            #[test]
            fn current_workspace_store_returns_no_current_workspace() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let err = store.current_workspace_store().unwrap_err();
                assert!(
                    matches!(err, ProfileError::NoCurrentWorkspace),
                    "expected NoCurrentWorkspace, got: {err:?}"
                );
            }

            #[test]
            fn clear_current_workspace_succeeds() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());
                store.clear_current_workspace().unwrap();
            }

            #[test]
            fn set_current_workspace_returns_workspace_not_found() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let err = store.set_current_workspace(WS_A).unwrap_err();
                assert!(
                    matches!(err, ProfileError::WorkspaceNotFound(_)),
                    "expected WorkspaceNotFound, got: {err:?}"
                );
            }

            #[test]
            fn init_workspace_creates_dir_and_sets_current() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                store.init_workspace(WS_A).unwrap();
                assert_eq!(
                    store.current_workspace().unwrap(),
                    WS_A,
                    "init_workspace should set the current workspace"
                );
                assert!(
                    dir.path().join("workspaces").join(WS_A).is_dir(),
                    "init_workspace should create the workspace directory"
                );
            }
        }

        mod given_workspace_set {
            use super::*;

            fn scenario() -> (tempfile::TempDir, ProfileStore) {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());
                store.init_workspace(WS_A).unwrap();
                (dir, store)
            }

            #[test]
            fn returns_workspace_id() {
                let (_dir, store) = scenario();
                assert_eq!(
                    store.current_workspace().unwrap(),
                    WS_A,
                    "should return the workspace that was set"
                );
            }

            #[test]
            fn current_workspace_store_returns_scoped_store() {
                let (dir, store) = scenario();
                let ws_store = store.current_workspace_store().unwrap();
                assert_eq!(
                    ws_store.dir(),
                    dir.path().join("workspaces").join(WS_A),
                    "workspace store should be rooted in workspaces/<id>"
                );
            }

            #[test]
            fn clear_removes_selection() {
                let (_dir, store) = scenario();
                store.clear_current_workspace().unwrap();

                let err = store.current_workspace().unwrap_err();
                assert!(
                    matches!(err, ProfileError::NoCurrentWorkspace),
                    "expected NoCurrentWorkspace after clear, got: {err:?}"
                );
            }

            #[test]
            fn save_and_load_round_trips_through_workspace_store() {
                let (dir, store) = scenario();
                let ws_store = store.current_workspace_store().unwrap();

                let data = WsData {
                    name: "hello".into(),
                };
                ws_store.save_profile(&data).unwrap();

                let loaded: WsData = ws_store.load_profile().unwrap();
                assert_eq!(loaded, data, "workspace store should round-trip data");

                assert!(
                    dir.path()
                        .join("workspaces")
                        .join(WS_A)
                        .join("ws-data.json")
                        .exists(),
                    "file should be in the workspace directory"
                );
                assert!(
                    !store.exists_profile::<WsData>(),
                    "root store should not see workspace-scoped file"
                );
            }
        }

        mod given_multiple_workspaces {
            use super::*;

            fn scenario() -> (tempfile::TempDir, ProfileStore) {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                store
                    .workspace_store(WS_A)
                    .unwrap()
                    .save_profile(&WsData {
                        name: "alpha".into(),
                    })
                    .unwrap();
                store
                    .workspace_store(WS_B)
                    .unwrap()
                    .save_profile(&WsData {
                        name: "bravo".into(),
                    })
                    .unwrap();

                (dir, store)
            }

            #[test]
            fn switching_changes_current_workspace_store_data() {
                let (_dir, store) = scenario();

                store.set_current_workspace(WS_A).unwrap();
                let loaded: WsData = store
                    .current_workspace_store()
                    .unwrap()
                    .load_profile()
                    .unwrap();
                assert_eq!(
                    loaded.name, "alpha",
                    "should load workspace A data after switching to A"
                );

                store.set_current_workspace(WS_B).unwrap();
                let loaded: WsData = store
                    .current_workspace_store()
                    .unwrap()
                    .load_profile()
                    .unwrap();
                assert_eq!(
                    loaded.name, "bravo",
                    "should load workspace B data after switching to B"
                );
            }

            #[test]
            fn list_workspaces_returns_sorted_ids() {
                let (_dir, store) = scenario();

                let workspaces = store.list_workspaces().unwrap();
                assert_eq!(
                    workspaces,
                    vec![WS_A, WS_B],
                    "should list both workspaces in sorted order"
                );
            }
        }

        mod list_workspaces {
            use super::*;

            #[test]
            fn returns_empty_when_no_workspaces_dir() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());
                assert_eq!(
                    store.list_workspaces().unwrap(),
                    Vec::<String>::new(),
                    "should return empty list when workspaces/ does not exist"
                );
            }

            #[test]
            fn ignores_files_and_invalid_dirs() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let ws_dir = dir.path().join("workspaces");
                std::fs::create_dir_all(&ws_dir).unwrap();
                std::fs::create_dir(ws_dir.join(WS_A)).unwrap();
                std::fs::write(ws_dir.join("not-a-dir.txt"), "").unwrap();
                std::fs::create_dir(ws_dir.join("invalid-name")).unwrap();

                let workspaces = store.list_workspaces().unwrap();
                assert_eq!(
                    workspaces,
                    vec![WS_A],
                    "should only include valid workspace directories"
                );
            }
        }

        mod workspace_store {
            use super::*;

            #[test]
            fn returns_scoped_store() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let ws_store = store.workspace_store(WS_A).unwrap();
                assert_eq!(
                    ws_store.dir(),
                    dir.path().join("workspaces").join(WS_A),
                    "workspace store should be rooted in workspaces/<id>"
                );
            }

            #[test]
            fn rejects_invalid_id() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let err = store.workspace_store("../escape").unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidWorkspaceId(_)),
                    "expected InvalidWorkspaceId for path traversal, got: {err:?}"
                );
            }
        }

        mod validate_workspace_id {
            use super::*;

            #[test]
            fn accepts_valid_base32() {
                ProfileStore::validate_workspace_id("ABCDEFGH234567AB").unwrap();
                ProfileStore::validate_workspace_id(WS_A).unwrap();
            }

            #[test]
            fn rejects_lowercase() {
                let err = ProfileStore::validate_workspace_id("abcdefgh234567ab").unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidWorkspaceId(_)),
                    "expected InvalidWorkspaceId for lowercase, got: {err:?}"
                );
            }

            #[test]
            fn rejects_wrong_length() {
                let err = ProfileStore::validate_workspace_id("SHORT").unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidWorkspaceId(_)),
                    "expected InvalidWorkspaceId for short string, got: {err:?}"
                );
            }

            #[test]
            fn rejects_empty() {
                let err = ProfileStore::validate_workspace_id("").unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidWorkspaceId(_)),
                    "expected InvalidWorkspaceId for empty string, got: {err:?}"
                );
            }

            #[test]
            fn rejects_path_traversal() {
                let err = ProfileStore::validate_workspace_id("../escape.json..").unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidWorkspaceId(_)),
                    "expected InvalidWorkspaceId for path traversal, got: {err:?}"
                );
            }

            #[test]
            fn rejects_non_base32_digits() {
                let err = ProfileStore::validate_workspace_id("0000000000000000").unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidWorkspaceId(_)),
                    "expected InvalidWorkspaceId for digits outside base32 alphabet, got: {err:?}"
                );
            }
        }

        mod migrate_to_workspace {
            use super::*;

            mod given_legacy_flat_files {
                use super::*;

                fn scenario() -> (tempfile::TempDir, ProfileStore) {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ProfileStore::new(dir.path());
                    std::fs::create_dir_all(dir.path()).unwrap();
                    std::fs::write(dir.path().join("auth.json"), r#"{"token":"old"}"#).unwrap();
                    std::fs::write(dir.path().join("secretkey.json"), r#"{"key":"old"}"#).unwrap();
                    (dir, store)
                }

                #[test]
                fn moves_files_to_workspace_dir() {
                    let (dir, store) = scenario();
                    store.migrate_to_workspace(WS_A).unwrap();

                    assert!(
                        !dir.path().join("auth.json").exists(),
                        "legacy auth.json should be removed from root"
                    );
                    assert!(
                        !dir.path().join("secretkey.json").exists(),
                        "legacy secretkey.json should be removed from root"
                    );

                    let ws_dir = dir.path().join("workspaces").join(WS_A);
                    assert!(
                        ws_dir.join("auth.json").exists(),
                        "auth.json should be in workspace dir"
                    );
                    assert!(
                        ws_dir.join("secretkey.json").exists(),
                        "secretkey.json should be in workspace dir"
                    );
                }

                #[test]
                fn sets_current_workspace() {
                    let (_dir, store) = scenario();
                    store.migrate_to_workspace(WS_A).unwrap();
                    assert_eq!(
                        store.current_workspace().unwrap(),
                        WS_A,
                        "current workspace should be set after migration"
                    );
                }
            }

            mod given_existing_files_in_target {
                use super::*;

                #[test]
                fn does_not_overwrite() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ProfileStore::new(dir.path());

                    std::fs::create_dir_all(dir.path()).unwrap();
                    std::fs::write(dir.path().join("auth.json"), r#"{"token":"legacy"}"#).unwrap();

                    let ws_dir = dir.path().join("workspaces").join(WS_A);
                    std::fs::create_dir_all(&ws_dir).unwrap();
                    std::fs::write(ws_dir.join("auth.json"), r#"{"token":"existing"}"#).unwrap();

                    store.migrate_to_workspace(WS_A).unwrap();

                    let contents = std::fs::read_to_string(ws_dir.join("auth.json")).unwrap();
                    assert!(
                        contents.contains("existing"),
                        "workspace file should be unchanged, got: {contents}"
                    );
                    assert!(
                        dir.path().join("auth.json").exists(),
                        "legacy file should remain when target exists"
                    );
                }
            }

            mod given_no_legacy_files {
                use super::*;

                #[test]
                fn sets_current_workspace() {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ProfileStore::new(dir.path());

                    store.migrate_to_workspace(WS_A).unwrap();
                    assert_eq!(
                        store.current_workspace().unwrap(),
                        WS_A,
                        "should set current workspace even without legacy files"
                    );
                }
            }
        }
    }
}
