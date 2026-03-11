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
}
