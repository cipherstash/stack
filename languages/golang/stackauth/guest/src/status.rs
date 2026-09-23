//! The mapping from [`stack_profile::ProfileError`] onto the status table.
//!
//! The numbers are [`stack_guest_abi::status`]'s — one table for every
//! guest, decoded once by the Go host — re-exported here so this crate's
//! modules and tests name them as the crypto guest names its own. What
//! this guest decides is *which* number a profile failure is: the seven
//! `stack-profile` conditions a Go caller can act on each have one, and
//! the two it cannot act on are internal.

use stack_profile::ProfileError;

pub use stack_guest_abi::status::{
    STATUS_ENCODING, STATUS_INTERNAL, STATUS_PROFILE_INVALID_FILENAME,
    STATUS_PROFILE_INVALID_WORKSPACE_ID, STATUS_PROFILE_IO, STATUS_PROFILE_JSON,
    STATUS_PROFILE_NOT_FOUND, STATUS_PROFILE_NO_CURRENT_WORKSPACE,
    STATUS_PROFILE_WORKSPACE_NOT_FOUND, STATUS_STATE,
};

/// A profile error as a status code.
///
/// `HomeDirNotFound` is [`STATUS_INTERNAL`]: this guest is given its
/// directory and never resolves one, so reaching that variant would be a
/// bug here, not a condition for the host. `ProfileError` is
/// `#[non_exhaustive]`, so the catch-all is required, and it goes the same
/// way: a variant added upstream is reported as ours until someone reads
/// it and gives it a number.
pub fn status_for_profile(error: &ProfileError) -> u32 {
    match error {
        ProfileError::Io(_) => STATUS_PROFILE_IO,
        ProfileError::Json(_) => STATUS_PROFILE_JSON,
        ProfileError::NotFound { .. } => STATUS_PROFILE_NOT_FOUND,
        ProfileError::InvalidFilename(_) => STATUS_PROFILE_INVALID_FILENAME,
        ProfileError::NoCurrentWorkspace => STATUS_PROFILE_NO_CURRENT_WORKSPACE,
        ProfileError::InvalidWorkspaceId(_) => STATUS_PROFILE_INVALID_WORKSPACE_ID,
        ProfileError::WorkspaceNotFound(_) => STATUS_PROFILE_WORKSPACE_NOT_FOUND,
        ProfileError::HomeDirNotFound => STATUS_INTERNAL,
        _ => STATUS_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_actionable_profile_error_has_its_own_code() {
        let cases: Vec<(ProfileError, u32)> = vec![
            (
                ProfileError::Io(std::io::Error::other("disk")),
                STATUS_PROFILE_IO,
            ),
            (
                serde_json::from_str::<u8>("nope")
                    .map_err(ProfileError::Json)
                    .unwrap_err(),
                STATUS_PROFILE_JSON,
            ),
            (
                ProfileError::NotFound { path: "x".into() },
                STATUS_PROFILE_NOT_FOUND,
            ),
            (
                ProfileError::InvalidFilename("../x".into()),
                STATUS_PROFILE_INVALID_FILENAME,
            ),
            (
                ProfileError::NoCurrentWorkspace,
                STATUS_PROFILE_NO_CURRENT_WORKSPACE,
            ),
            (
                ProfileError::InvalidWorkspaceId("short".into()),
                STATUS_PROFILE_INVALID_WORKSPACE_ID,
            ),
            (
                ProfileError::WorkspaceNotFound("AAAAAAAAAAAAAAAA".into()),
                STATUS_PROFILE_WORKSPACE_NOT_FOUND,
            ),
            (ProfileError::HomeDirNotFound, STATUS_INTERNAL),
        ];
        let mut seen = std::collections::HashSet::new();
        for (error, expected) in cases {
            assert_eq!(status_for_profile(&error), expected, "{error}");
            if expected != STATUS_INTERNAL {
                assert!(seen.insert(expected), "code {expected} is shared");
            }
        }
    }
}
