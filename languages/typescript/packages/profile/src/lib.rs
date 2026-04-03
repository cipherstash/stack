use napi::bindgen_prelude::*;
use napi_derive::napi;

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn error_code(err: &stack_profile::ProfileError) -> &'static str {
    match err {
        stack_profile::ProfileError::Io(_) => "IO_ERROR",
        stack_profile::ProfileError::Json(_) => "JSON_ERROR",
        stack_profile::ProfileError::HomeDirNotFound => "HOME_DIR_NOT_FOUND",
        stack_profile::ProfileError::NotFound { .. } => "NOT_FOUND",
        stack_profile::ProfileError::InvalidFilename(_) => "INVALID_FILENAME",
        stack_profile::ProfileError::NoCurrentWorkspace => "NO_CURRENT_WORKSPACE",
        stack_profile::ProfileError::InvalidWorkspaceId(_) => "INVALID_WORKSPACE_ID",
        _ => "UNKNOWN_ERROR",
    }
}

fn to_napi_error(err: stack_profile::ProfileError) -> napi::Error {
    let code = error_code(&err);
    napi::Error::new(Status::GenericFailure, format!("{code}: {err}"))
}

// ---------------------------------------------------------------------------
// ProfileStore
// ---------------------------------------------------------------------------

#[napi]
pub struct ProfileStore {
    inner: stack_profile::ProfileStore,
}

#[napi]
impl ProfileStore {
    /// Create a profile store at the default location (`~/.cipherstash`),
    /// or the path specified by the `CS_CONFIG_PATH` environment variable.
    #[napi(factory)]
    pub fn resolve() -> Result<Self> {
        let inner = stack_profile::ProfileStore::resolve(None).map_err(to_napi_error)?;
        Ok(Self { inner })
    }

    /// Create a profile store rooted at the given directory.
    #[napi(factory)]
    pub fn with_dir(dir: String) -> Self {
        Self {
            inner: stack_profile::ProfileStore::new(dir),
        }
    }

    /// The directory path of this profile store.
    #[napi(getter)]
    pub fn dir(&self) -> String {
        self.inner.dir().to_string_lossy().into_owned()
    }

    /// Set the current workspace.
    #[napi]
    pub fn set_current_workspace(&self, workspace_id: String) -> Result<()> {
        self.inner
            .set_current_workspace(&workspace_id)
            .map_err(to_napi_error)
    }

    /// Return the current workspace ID.
    ///
    /// Throws if no workspace has been set.
    #[napi]
    pub fn current_workspace(&self) -> Result<String> {
        self.inner.current_workspace().map_err(to_napi_error)
    }

    /// Remove the current workspace selection.
    #[napi]
    pub fn clear_current_workspace(&self) -> Result<()> {
        self.inner.clear_current_workspace().map_err(to_napi_error)
    }

    /// List workspace IDs that have profile data on disk.
    #[napi]
    pub fn list_workspaces(&self) -> Result<Vec<String>> {
        self.inner.list_workspaces().map_err(to_napi_error)
    }

    /// Return a profile store scoped to a specific workspace directory.
    #[napi]
    pub fn workspace_store(&self, workspace_id: String) -> Result<ProfileStore> {
        let inner = self
            .inner
            .workspace_store(&workspace_id)
            .map_err(to_napi_error)?;
        Ok(ProfileStore { inner })
    }

    /// Return a profile store scoped to the current workspace.
    ///
    /// Throws if no workspace has been set.
    #[napi]
    pub fn current_workspace_store(&self) -> Result<ProfileStore> {
        let inner = self
            .inner
            .current_workspace_store()
            .map_err(to_napi_error)?;
        Ok(ProfileStore { inner })
    }
}
