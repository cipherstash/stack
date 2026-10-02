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
#[derive(Debug, Clone)]
pub struct ProfileStore {
    dir: PathBuf,
}

/// RAII guard for an advisory file lock acquired via
/// [`ProfileStore::lock_exclusive`]. Releases on drop.
///
/// The guard owns the lock file handle; dropping it calls `unlock` and
/// closes the descriptor. The lock file itself is left on disk — it's reused
/// across acquisitions and carries no useful content.
#[must_use = "the lock is released as soon as this guard is dropped"]
#[derive(Debug)]
pub struct FileLockGuard {
    file: std::fs::File,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // Best-effort — the kernel releases on close regardless, so a failure
        // here only matters for diagnostics. Don't log: this runs during
        // teardown and the file may already be invalid (e.g. on process exit).
        let _ = self.file.unlock();
    }
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

    /// Atomically write JSON content to an absolute path, optionally setting
    /// Unix file permissions.
    ///
    /// Sequence:
    ///   1. Open a uniquely-named sibling tmp file in the same directory.
    ///   2. Write the bytes and `sync_all` (fsync the data + metadata).
    ///   3. Apply the requested mode with `set_permissions` (overrides
    ///      umask).
    ///   4. Rename the tmp file over the target. `std::fs::rename` uses
    ///      `MOVEFILE_REPLACE_EXISTING` on Windows and the POSIX `rename`
    ///      on Unix, so the replacement is atomic on both platforms.
    ///   5. On Unix, fsync the parent directory so the rename is durable
    ///      across power loss. Windows doesn't expose directory fsync, so
    ///      this step is Unix-only — Windows callers get atomicity but
    ///      slightly weaker crash-durability guarantees.
    ///
    /// Two concurrent writers cannot produce torn reads, and a crash
    /// mid-write leaves either the prior file intact or no destination
    /// file at all. The tmp file name embeds the process ID + a UUID so
    /// concurrent writers (across processes or threads) don't collide on
    /// the staging path.
    ///
    /// On Windows the rename can transiently fail with
    /// `ERROR_SHARING_VIOLATION` when an external (non-Rust) process holds
    /// the target open without `FILE_SHARE_DELETE`. Rust's own
    /// `File::open` sets that share flag, so contention between two Rust
    /// processes won't trip this — but to defend against third-party
    /// readers we retry the rename a handful of times with brief backoff
    /// before giving up.
    fn write_to_path(path: &Path, json: &str, _mode: Option<u32>) -> Result<(), ProfileError> {
        use std::io::Write;

        let parent = path.parent().ok_or_else(|| {
            ProfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "target path has no parent directory",
            ))
        })?;
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            ProfileError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "target path has no file name",
            ))
        })?;
        // The process id keeps two processes' staging files apart; the UUID
        // keeps two threads' apart. On wasm32-wasip1 `std::process::id()`
        // aborts the module ("unsupported"), and a wasm instance is the only
        // process there is, so the UUID alone carries the uniqueness.
        #[cfg(not(target_arch = "wasm32"))]
        let pid = std::process::id();
        #[cfg(target_arch = "wasm32")]
        let pid = 0u32;
        let tmp_path = parent.join(format!(
            ".{file_name}.tmp.{pid}.{}",
            uuid::Uuid::new_v4().simple()
        ));

        let result = (|| -> Result<(), ProfileError> {
            let mut file = {
                let mut opts = std::fs::OpenOptions::new();
                let _ = opts.write(true).create_new(true);
                #[cfg(unix)]
                if let Some(mode) = _mode {
                    use std::os::unix::fs::OpenOptionsExt;
                    let _ = opts.mode(mode);
                }
                opts.open(&tmp_path)?
            };
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
            drop(file);

            // `OpenOptions::mode()` is masked by the process umask, so an
            // explicit `set_permissions` is required to guarantee the exact
            // mode the caller asked for.
            #[cfg(unix)]
            if let Some(mode) = _mode {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))?;
            }

            Self::rename_with_retry(&tmp_path, path)?;

            // Durability: fsync the parent directory so the rename itself
            // survives a power loss, not just the file contents written
            // above. Unix-only because Windows has no directory fsync
            // primitive (and its filesystem metadata journaling makes
            // this less necessary in practice).
            #[cfg(unix)]
            {
                let dir = std::fs::File::open(parent)?;
                dir.sync_all()?;
            }

            Ok(())
        })();

        // On failure, the rename never happened (or was rolled back), so
        // clean up the staging file. Best-effort — if cleanup itself
        // fails there's nothing useful we can do beyond the original
        // error.
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        result
    }

    /// Rename `from` to `to`, retrying briefly on Windows
    /// `ERROR_SHARING_VIOLATION` (a transient failure when an external
    /// process holds the target open without `FILE_SHARE_DELETE`). On
    /// Unix the first attempt always succeeds or fails for a permanent
    /// reason, so the retry loop is a no-op there.
    fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
        // 5 attempts * 20ms = up to 100ms — long enough to ride out a
        // typical short-lived external read, short enough not to feel
        // hung if the contention is real.
        const MAX_ATTEMPTS: u32 = 5;
        const BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

        for attempt in 1..=MAX_ATTEMPTS {
            match std::fs::rename(from, to) {
                Ok(()) => return Ok(()),
                Err(e) if attempt < MAX_ATTEMPTS && Self::is_transient_rename_error(&e) => {
                    std::thread::sleep(BACKOFF);
                }
                Err(e) => return Err(e),
            }
        }
        // Unreachable — the loop either returns or breaks via the last
        // attempt's `Err` arm above.
        unreachable!()
    }

    /// True if the error is a sharing/access conflict that's worth
    /// retrying. On Unix `rename` doesn't produce these (the equivalent
    /// would be `EBUSY` on overlay/network filesystems, but it's rare and
    /// usually non-transient), so this is effectively a Windows guard.
    #[cfg(windows)]
    fn is_transient_rename_error(e: &std::io::Error) -> bool {
        // ERROR_SHARING_VIOLATION = 32, ERROR_ACCESS_DENIED = 5. Both can
        // appear transiently when MoveFileEx hits a target that's open.
        matches!(e.raw_os_error(), Some(32) | Some(5))
    }

    #[cfg(not(windows))]
    fn is_transient_rename_error(_e: &std::io::Error) -> bool {
        false
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

    /// Acquire an exclusive advisory lock that serialises critical sections
    /// against other processes sharing this profile directory.
    ///
    /// The lock is held on a sibling file (`.<filename>.lock`) so it survives
    /// atomic rewrites of the target. This is **blocking** — call it from a
    /// `spawn_blocking` task when invoked from async code. Released when the
    /// returned [`FileLockGuard`] is dropped.
    ///
    /// Intended use is around the read-modify-write window for files like
    /// `auth.json` where a non-atomic critical section across processes
    /// causes silent state corruption (in the auth case: refresh-token
    /// rotation replay).
    pub fn lock_exclusive(&self, filename: &str) -> Result<FileLockGuard, ProfileError> {
        let lock_path = self.lock_path(filename)?;
        std::fs::create_dir_all(&self.dir)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        file.lock()?;
        Ok(FileLockGuard { file })
    }

    /// The path of the lock file [`lock_exclusive`](Self::lock_exclusive)
    /// takes for `filename`: a sibling `.<filename>.lock` in this store's
    /// directory. Nothing is created or locked.
    ///
    /// This is for a host that must hold the lock on the crate's behalf.
    /// WASI preview 1 has no file locking, so the Go binding's credential
    /// guest cannot take it; the Go side takes the same lock on the path
    /// this names, and never composes a profile path itself.
    pub fn lock_path(&self, filename: &str) -> Result<PathBuf, ProfileError> {
        Self::validate_filename(filename)?;
        Ok(self.dir.join(format!(".{filename}.lock")))
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

    mod lock_path {
        use super::*;

        #[test]
        fn names_the_file_lock_exclusive_takes() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let path = store.lock_path("auth.json").unwrap();
            assert_eq!(path, dir.path().join(".auth.json.lock"));
            assert!(!path.exists(), "naming the lock file must not create it");

            let _guard = store.lock_exclusive("auth.json").unwrap();
            assert!(
                path.exists(),
                "lock_exclusive locks the file lock_path names"
            );
        }

        #[test]
        fn rejects_an_invalid_filename() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            for bad in ["", "../auth.json", "/etc/auth.json"] {
                let err = store.lock_path(bad).unwrap_err();
                assert!(
                    matches!(err, ProfileError::InvalidFilename(_)),
                    "{bad:?}: {err}"
                );
            }
        }
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

    /// Concurrent writers must never expose torn content to a reader. Each
    /// write goes through a sibling tmp file + rename, so an interleaved
    /// reader sees either the prior complete file or a complete new file —
    /// never a half-written one.
    #[test]
    fn concurrent_writes_never_expose_torn_content() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Big {
            // Large payload so any non-atomic write would leave an
            // observably-incomplete file mid-flight.
            payload: String,
            writer: usize,
        }

        fn make_value(writer: usize, payload_size: usize) -> Big {
            Big {
                // Encode the writer ID into the payload so any torn
                // mix-and-match between writers would show up as an
                // unparseable / inconsistent file.
                payload: char::from_digit(writer as u32, 16)
                    .unwrap()
                    .to_string()
                    .repeat(payload_size),
                writer,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(ProfileStore::new(dir.path()));
        let writers = 8;
        let iterations = 50;
        // 64 KiB per write — well above any sane page/buffer size.
        let payload_size = 64 * 1024;

        // Pre-seed so the reader always has a file to observe, even before
        // any concurrent writer completes its first save.
        store
            .save("contended.json", &make_value(0, payload_size))
            .unwrap();

        let done = Arc::new(AtomicBool::new(false));

        let mut handles = Vec::with_capacity(writers);
        for writer in 0..writers {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for _ in 0..iterations {
                    store
                        .save("contended.json", &make_value(writer, payload_size))
                        .unwrap();
                }
            }));
        }

        // Race reads against the writers. Every successful read must yield a
        // well-formed JSON whose payload matches the declared writer — proving
        // we never observed a partial overwrite.
        let reader_store = Arc::clone(&store);
        let reader_done = Arc::clone(&done);
        let reader = thread::spawn(move || {
            let mut reads = 0;
            while !reader_done.load(Ordering::Relaxed) {
                match reader_store.load::<Big>("contended.json") {
                    Ok(value) => {
                        let expected_char = char::from_digit(value.writer as u32, 16)
                            .unwrap()
                            .to_string();
                        assert_eq!(
                            value.payload.len(),
                            payload_size,
                            "torn write — payload truncated"
                        );
                        assert!(
                            value
                                .payload
                                .chars()
                                .all(|c| c.to_string() == expected_char),
                            "torn write — writer {} payload contained foreign content",
                            value.writer
                        );
                        reads += 1;
                    }
                    Err(e) => panic!("reader saw IO/parse error: {e}"),
                }
            }
            reads
        });

        for h in handles {
            h.join().unwrap();
        }
        done.store(true, Ordering::Relaxed);
        let reads = reader.join().unwrap();
        assert!(reads > 0, "reader never observed any successful load");

        // Final state should be a clean, complete JSON from one of the writers.
        let final_value: Big = store.load("contended.json").unwrap();
        assert_eq!(final_value.payload.len(), payload_size);

        // No staging files should be left behind after all writers finished.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                s.starts_with(".contended.json.tmp.")
            })
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp staging files leaked: {leftovers:?}"
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
