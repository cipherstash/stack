use std::path::PathBuf;

use crate::diagnostic::{describe_json_error, payload, ErrorPayload};

/// Errors that can occur when reading or writing profile files.
///
/// Every variant has a miette code in [`ERROR_CODES`](crate::ERROR_CODES).
/// [`Io`](Self::Io) and [`Json`](Self::Json) wrap another library's error
/// and keep its message out of their own (see [`ErrorPayload`] for the
/// rule): the wrapped error is their [`source`](std::error::Error::source).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum ProfileError {
    /// An I/O error occurred while reading or writing a profile file. The
    /// message names the kind of failure; the I/O error itself is the source.
    #[error("I/O error: {}", .0.kind())]
    #[diagnostic(code(stack_profile::io))]
    Io(#[from] std::io::Error),
    /// A profile file contained invalid JSON. The message gives where and
    /// what kind of error it was, never the parser's own text: that can
    /// quote the file, and a profile file can hold a token.
    #[error("JSON error: {}", describe_json_error(.0))]
    #[diagnostic(
        code(stack_profile::json),
        help("The profile file is damaged. Log in again with `stash auth login` to rewrite it.")
    )]
    Json(#[from] serde_json::Error),
    /// The user's home directory could not be determined.
    #[error("Could not determine home directory")]
    #[diagnostic(
        code(stack_profile::home_dir_not_found),
        help("Set `HOME` (or `USERPROFILE` on Windows), or open the store at an explicit directory with `ProfileStore::new`.")
    )]
    HomeDirNotFound,
    /// The requested profile file was not found.
    #[error("Profile not found: {path}")]
    #[diagnostic(
        code(stack_profile::not_found),
        help("Log in with `stash auth login` to create the profile.")
    )]
    NotFound {
        /// The path that was looked up.
        path: PathBuf,
    },
    /// The filename is invalid (contains path separators, `..`, or is absolute).
    #[error("Invalid profile filename: {0}")]
    #[diagnostic(
        code(stack_profile::invalid_filename),
        help("A profile filename is a bare name such as `auth.json`: no directory, no `..`.")
    )]
    InvalidFilename(String),
    /// No current workspace is set but a workspace-scoped operation was attempted.
    #[error("No current workspace set. Run `stash login` or `stash workspaces switch` first.")]
    #[diagnostic(code(stack_profile::no_current_workspace))]
    NoCurrentWorkspace,
    /// The workspace ID is invalid (not a 16-character base32 string).
    #[error("Invalid workspace ID: {0}")]
    #[diagnostic(
        code(stack_profile::invalid_workspace_id),
        help("A workspace ID is 16 base32 characters, such as `ZVATKW3VHMFG27DY`.")
    )]
    InvalidWorkspaceId(String),
    /// The workspace has no local profile data (not logged in).
    #[error("Workspace not found: {0}. Log in to this workspace first.")]
    #[diagnostic(code(stack_profile::workspace_not_found))]
    WorkspaceNotFound(String),
}

impl ErrorPayload for ProfileError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Io(error) => payload([("io_kind", format!("{:?}", error.kind()).into())]),
            Self::Json(error) => payload([
                ("line", error.line().into()),
                ("column", error.column().into()),
            ]),
            Self::NotFound { path } => payload([("path", path.display().to_string().into())]),
            Self::InvalidFilename(filename) => payload([("filename", filename.as_str().into())]),
            Self::InvalidWorkspaceId(workspace) | Self::WorkspaceNotFound(workspace) => {
                payload([("workspace_id", workspace.as_str().into())])
            }
            Self::HomeDirNotFound | Self::NoCurrentWorkspace => serde_json::Map::new(),
        }
    }
}

/// Every miette code [`ProfileError`] can carry. A test builds every variant
/// and checks its code is here, so renaming a code means editing this list
/// on purpose.
pub const ERROR_CODES: &[&str] = &[
    "stack_profile::io",
    "stack_profile::json",
    "stack_profile::home_dir_not_found",
    "stack_profile::not_found",
    "stack_profile::invalid_filename",
    "stack_profile::no_current_workspace",
    "stack_profile::invalid_workspace_id",
    "stack_profile::workspace_not_found",
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use miette::Diagnostic;

    use super::*;
    use crate::diagnostic::is_code_of;

    /// One of every variant, so the code test covers them all.
    fn every_variant() -> Vec<ProfileError> {
        vec![
            ProfileError::Io(std::io::Error::other("disk")),
            serde_json::from_str::<u8>("\"secret\"")
                .map_err(ProfileError::Json)
                .unwrap_err(),
            ProfileError::HomeDirNotFound,
            ProfileError::NotFound {
                path: "auth.json".into(),
            },
            ProfileError::InvalidFilename("../x".into()),
            ProfileError::NoCurrentWorkspace,
            ProfileError::InvalidWorkspaceId("short".into()),
            ProfileError::WorkspaceNotFound("AAAAAAAAAAAAAAAA".into()),
        ]
    }

    #[test]
    fn every_variant_has_a_listed_code() {
        let mut seen = BTreeSet::new();
        for error in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            assert!(is_code_of("stack_profile", &code), "{code}");
            assert!(ERROR_CODES.contains(&code.as_str()), "{code} is unlisted");
            seen.insert(code);
        }
        let listed: BTreeSet<String> = ERROR_CODES.iter().map(|c| c.to_string()).collect();
        assert_eq!(seen, listed, "every listed code is produced by a variant");
    }

    /// serde_json quotes the value it refused; a profile file can hold a
    /// token, so neither the message nor the payload may carry that text.
    #[test]
    fn a_json_error_does_not_quote_the_file() {
        let error = serde_json::from_str::<u8>("\"marker-token\"")
            .map_err(ProfileError::Json)
            .unwrap_err();
        assert!(
            std::error::Error::source(&error)
                .is_some_and(|source| source.to_string().contains("marker-token")),
            "the parser's own message is still the source",
        );
        let shown = format!("{error} {:?}", error.payload());
        assert!(!shown.contains("marker-token"), "{shown}");
        assert!(shown.contains("line 1"), "{shown}");
    }

    #[test]
    fn an_io_error_names_its_kind_not_its_message() {
        let error = ProfileError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "marker-text",
        ));
        let shown = format!("{error} {:?}", error.payload());
        assert!(!shown.contains("marker-text"), "{shown}");
        assert_eq!(error.payload()["io_kind"], "PermissionDenied");
    }
}
