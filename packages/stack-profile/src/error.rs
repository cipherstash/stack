use std::path::PathBuf;

use crate::diagnostic::{describe_json_error, payload, ErrorPayload};

/// Errors that can occur when reading or writing profile files.
///
/// Every variant has a miette code, `stack_profile::` and a `snake_case`
/// name.
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
    #[error("No current workspace set")]
    #[diagnostic(
        code(stack_profile::no_current_workspace),
        help("Log in with `stash auth login`, or set the current workspace on the profile store.")
    )]
    NoCurrentWorkspace,
    /// The workspace ID is invalid (not a 16-character base32 string).
    #[error("Invalid workspace ID: {0}")]
    #[diagnostic(
        code(stack_profile::invalid_workspace_id),
        help("A workspace ID is 16 base32 characters, such as `ZVATKW3VHMFG27DY`.")
    )]
    InvalidWorkspaceId(String),
    /// The workspace has no local profile data (not logged in).
    #[error("Workspace not found: {0}")]
    #[diagnostic(
        code(stack_profile::workspace_not_found),
        help("Log in to this workspace with `stash auth login`.")
    )]
    WorkspaceNotFound(String),
}

impl ErrorPayload for ProfileError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Io(error) => payload([("io_kind", io_kind(error.kind()).into())]),
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

/// An I/O error kind as the payload spells it: the kinds a profile store
/// can meet, written out rather than taken from `Debug`, which is no format.
/// `ErrorKind` is non-exhaustive, so any other kind is `Other`.
fn io_kind(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind as K;
    match kind {
        K::NotFound => "NotFound",
        K::PermissionDenied => "PermissionDenied",
        K::AlreadyExists => "AlreadyExists",
        K::WouldBlock => "WouldBlock",
        K::NotADirectory => "NotADirectory",
        K::IsADirectory => "IsADirectory",
        K::DirectoryNotEmpty => "DirectoryNotEmpty",
        K::ReadOnlyFilesystem => "ReadOnlyFilesystem",
        K::StorageFull => "StorageFull",
        K::QuotaExceeded => "QuotaExceeded",
        K::FileTooLarge => "FileTooLarge",
        K::ResourceBusy => "ResourceBusy",
        K::InvalidInput => "InvalidInput",
        K::InvalidData => "InvalidData",
        K::InvalidFilename => "InvalidFilename",
        K::TimedOut => "TimedOut",
        K::WriteZero => "WriteZero",
        K::Interrupted => "Interrupted",
        K::Unsupported => "Unsupported",
        K::UnexpectedEof => "UnexpectedEof",
        K::OutOfMemory => "OutOfMemory",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use miette::Diagnostic;

    use super::*;
    use crate::diagnostic::is_code_of;

    /// One row per variant of an enum, written `pattern => value`. The
    /// patterns are the arms of a match with no wildcard, so a variant with
    /// no row fails to compile, and each value must match its own pattern.
    macro_rules! variants {
        ($($pattern:pat => $value:expr),+ $(,)?) => {{
            let rows = vec![$({
                let value = $value;
                assert!(matches!(value, $pattern), "{value:?} is not {}", stringify!($pattern));
                value
            }),+];
            for row in &rows {
                match row {
                    $($pattern => {})+
                }
            }
            rows
        }};
    }

    /// One of every variant, so the code test covers them all.
    fn every_variant() -> Vec<ProfileError> {
        variants![
            ProfileError::Io(_) => ProfileError::Io(std::io::Error::other("disk")),
            ProfileError::Json(_) => serde_json::from_str::<u8>("\"secret\"")
                .map_err(ProfileError::Json)
                .unwrap_err(),
            ProfileError::HomeDirNotFound => ProfileError::HomeDirNotFound,
            ProfileError::NotFound { .. } => ProfileError::NotFound {
                path: "auth.json".into(),
            },
            ProfileError::InvalidFilename(_) => ProfileError::InvalidFilename("../x".into()),
            ProfileError::NoCurrentWorkspace => ProfileError::NoCurrentWorkspace,
            ProfileError::InvalidWorkspaceId(_) => ProfileError::InvalidWorkspaceId("short".into()),
            ProfileError::WorkspaceNotFound(_) => {
                ProfileError::WorkspaceNotFound("AAAAAAAAAAAAAAAA".into())
            }
        ]
    }

    /// Every variant has a code, in this crate's namespace and `snake_case`.
    #[test]
    fn every_variant_has_a_code_of_this_crate() {
        for error in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            assert!(is_code_of("stack_profile", &code), "{code}");
        }
    }

    /// No two variants share a code: callers branch on it.
    #[test]
    fn no_two_variants_share_a_code_by_mistake() {
        let errors = every_variant();
        let shared =
            crate::diagnostic::shared_codes(errors.iter().map(|error| error as &dyn Diagnostic));
        let codes: Vec<&str> = shared.keys().map(String::as_str).collect();
        assert_eq!(codes, [] as [&str; 0], "{shared:#?}");
    }

    /// The workspace errors name the one CLI command there is for this,
    /// `stash auth login`, and no command the CLI does not have.
    #[test]
    fn the_workspace_errors_name_stash_auth_login() {
        for error in [
            ProfileError::NoCurrentWorkspace,
            ProfileError::WorkspaceNotFound("AAAAAAAAAAAAAAAA".into()),
        ] {
            let help = error
                .help()
                .map(|help| help.to_string())
                .unwrap_or_default();
            assert!(help.contains("`stash auth login`"), "{error:?}: {help}");
            let shown = format!("{error} {help}");
            assert!(!shown.contains("`stash login`"), "{shown}");
            assert!(!shown.contains("workspaces switch"), "{shown}");
        }
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

    /// The table spells each kind as std names it, and a kind it does not
    /// list is `Other` rather than a spelling nobody wrote down.
    #[test]
    fn an_io_kind_is_spelled_as_std_names_it() {
        use std::io::ErrorKind as K;
        for kind in [
            K::NotFound,
            K::PermissionDenied,
            K::StorageFull,
            K::UnexpectedEof,
        ] {
            assert_eq!(io_kind(kind), format!("{kind:?}"));
        }
        assert_eq!(io_kind(K::BrokenPipe), "Other");
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
