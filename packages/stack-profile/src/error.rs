use std::path::PathBuf;

/// Errors that can occur when reading or writing profile files.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    /// An I/O error occurred while reading or writing a profile file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A profile file contained invalid JSON.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// The user's home directory could not be determined.
    #[error("Could not determine home directory")]
    HomeDirNotFound,
    /// The requested profile file was not found.
    #[error("Profile not found: {path}")]
    NotFound {
        /// The path that was looked up.
        path: PathBuf,
    },
    /// The filename is invalid (contains path separators, `..`, or is absolute).
    #[error("Invalid profile filename: {0}")]
    InvalidFilename(String),
    /// No current workspace is set but a workspace-scoped operation was attempted.
    #[error("No current workspace set. Run `stash login` or `stash workspaces switch` first.")]
    NoCurrentWorkspace,
    /// The workspace ID is invalid (not a 16-character base32 string).
    #[error("Invalid workspace ID: {0}")]
    InvalidWorkspaceId(String),
    /// The workspace has no local profile data (not logged in).
    #[error("Workspace not found: {0}. Log in to this workspace first.")]
    WorkspaceNotFound(String),
}
