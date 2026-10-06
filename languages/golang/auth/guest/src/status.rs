//! Map profile and auth errors onto the shared guest status table, and
//! record each as the last error ([`fail_auth`], [`fail_profile`]) so
//! `se_last_error` has the full error behind the number.
//!
//! The numbers are [`stack_guest_abi::status`]'s — one table for every
//! guest, decoded once by the Go host — re-exported here so this crate's
//! modules and tests name them as the crypto guest names its own. What
//! this guest decides is *which* number a profile failure is: the seven
//! `stack-profile` conditions a Go caller can act on each have one, and
//! the two it cannot act on are internal.

use stack_auth::{AuthError, ErrorPayload};
use stack_guest_abi::last_error;
use stack_profile::ProfileError;

pub use stack_guest_abi::status::{
    STATUS_AUTH_CONFIG, STATUS_AUTH_INVALID_CLIENT, STATUS_AUTH_INVALID_GRANT,
    STATUS_AUTH_NOT_AUTHENTICATED, STATUS_AUTH_OTHER, STATUS_AUTH_REFRESH_REQUIRED,
    STATUS_AUTH_TRANSPORT, STATUS_AUTH_USAGE_LIMIT, STATUS_ENCODING, STATUS_INTERNAL,
    STATUS_PROFILE_INVALID_FILENAME, STATUS_PROFILE_INVALID_WORKSPACE_ID, STATUS_PROFILE_IO,
    STATUS_PROFILE_JSON, STATUS_PROFILE_NOT_FOUND, STATUS_PROFILE_NO_CURRENT_WORKSPACE,
    STATUS_PROFILE_WORKSPACE_NOT_FOUND, STATUS_STATE,
};

/// Record an auth error as the last error and return its status: what
/// every export's `map_err` calls, so the status a host acts on and the
/// error it can ask for come from the one site.
pub fn fail_auth(error: &AuthError) -> u32 {
    last_error::record(error, error.payload());
    status_for_auth(error)
}

/// [`fail_auth`] for a profile error.
pub fn fail_profile(error: &ProfileError) -> u32 {
    last_error::record(error, error.payload());
    status_for_profile(error)
}

/// Preserve the auth decisions callers can act on without exposing token
/// bytes or parsing a server message across the ABI.
///
/// Matched on the variants, not on `error_code()`'s strings: a renamed code
/// cannot silently fall through to [`STATUS_AUTH_OTHER`] here. `AuthError`
/// is `#[non_exhaustive]`, so a variant added upstream still lands on the
/// catch-all until someone reads it and gives it a number; every variant
/// there is today is named.
pub fn status_for_auth(error: &AuthError) -> u32 {
    match error {
        AuthError::Store(store_error) => status_for_profile(&store_error.0),
        AuthError::InvalidGrant(_) => STATUS_AUTH_INVALID_GRANT,
        AuthError::InvalidClient(_) => STATUS_AUTH_INVALID_CLIENT,
        AuthError::UsageLimitExceeded(_) => STATUS_AUTH_USAGE_LIMIT,
        AuthError::NotAuthenticated(_) | AuthError::TokenExpired(_) => {
            STATUS_AUTH_NOT_AUTHENTICATED
        }
        AuthError::Request(_) | AuthError::Server(_) => STATUS_AUTH_TRANSPORT,
        AuthError::InvalidUrl(_)
        | AuthError::Region(_)
        | AuthError::InvalidCrn(_)
        | AuthError::WorkspaceMismatch(_)
        | AuthError::InvalidWorkspaceId(_)
        | AuthError::MissingWorkspaceCrn(_)
        | AuthError::InvalidAccessKey(_)
        | AuthError::InvalidToken(_) => STATUS_AUTH_CONFIG,
        AuthError::AccessDenied(_)
        | AuthError::OrgNotProvisioned(_)
        | AuthError::AlreadyConsumed(_)
        | AuthError::Internal(_)
        | AuthError::Custom(_) => STATUS_AUTH_OTHER,
        _ => STATUS_AUTH_OTHER,
    }
}

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

    /// The match on variants gives every error the status the match on
    /// `error_code()` strings it replaced gave, so the switch changed no
    /// number. The string table is kept here, frozen, as the reference.
    #[test]
    fn the_variant_match_gives_every_code_its_old_status() {
        fn by_code(code: &str) -> u32 {
            match code {
                "INVALID_GRANT" => STATUS_AUTH_INVALID_GRANT,
                "INVALID_CLIENT" => STATUS_AUTH_INVALID_CLIENT,
                "USAGE_LIMIT_EXCEEDED" => STATUS_AUTH_USAGE_LIMIT,
                "NOT_AUTHENTICATED" | "EXPIRED_TOKEN" => STATUS_AUTH_NOT_AUTHENTICATED,
                "REQUEST_ERROR" | "SERVER_ERROR" => STATUS_AUTH_TRANSPORT,
                "INVALID_URL"
                | "INVALID_REGION"
                | "INVALID_CRN"
                | "WORKSPACE_MISMATCH"
                | "INVALID_WORKSPACE_ID"
                | "MISSING_WORKSPACE_CRN"
                | "INVALID_ACCESS_KEY"
                | "INVALID_TOKEN" => STATUS_AUTH_CONFIG,
                _ => STATUS_AUTH_OTHER,
            }
        }
        let workspace = |id: &str| id.parse::<cts_common::WorkspaceId>().unwrap();
        let errors: Vec<AuthError> = vec![
            stack_auth::RequestError(Box::new(std::io::Error::other("refused"))).into(),
            stack_auth::AccessDenied.into(),
            stack_auth::InvalidGrant.into(),
            stack_auth::InvalidClient.into(),
            "not a url".parse::<url::Url>().unwrap_err().into(),
            "nowhere".parse::<cts_common::Region>().unwrap_err().into(),
            "not a crn".parse::<cts_common::Crn>().unwrap_err().into(),
            stack_auth::WorkspaceMismatch {
                expected_workspace: workspace("ZVATKW3VHMFG27DY"),
                token_workspace: workspace("AAAAAAAAAAAAAAAA"),
            }
            .into(),
            "short"
                .parse::<cts_common::WorkspaceId>()
                .unwrap_err()
                .into(),
            stack_auth::MissingWorkspaceCrn.into(),
            stack_auth::NotAuthenticated.into(),
            stack_auth::TokenExpired.into(),
            "".parse::<stack_auth::AccessKey>().unwrap_err().into(),
            stack_auth::InvalidToken("malformed".into()).into(),
            stack_auth::UsageLimitExceeded("over".into()).into(),
            stack_auth::OrgNotProvisioned("unknown".into()).into(),
            stack_auth::ServerError("boom".into()).into(),
            stack_auth::AlreadyConsumed.into(),
            stack_auth::InternalError("poisoned".into()).into(),
            stack_auth::CustomError("custom".into()).into(),
        ];
        let mut codes = std::collections::BTreeSet::new();
        for error in &errors {
            assert_eq!(
                status_for_auth(error),
                by_code(error.error_code()),
                "{error:?}"
            );
            codes.insert(error.error_code());
        }
        // Every frozen code but the store's, which defers to the profile
        // status and has its own test below.
        assert_eq!(codes.len(), AuthError::ERROR_CODES.len() - 1);
    }

    #[test]
    fn auth_store_errors_keep_their_profile_status() {
        let missing = AuthError::from(ProfileError::NotFound {
            path: "auth.json".into(),
        });
        assert_eq!(status_for_auth(&missing), STATUS_PROFILE_NOT_FOUND);
        let io = AuthError::from(ProfileError::Io(std::io::Error::other("disk full")));
        assert_eq!(status_for_auth(&io), STATUS_PROFILE_IO);
    }
}
