//! Finds the workspace for a strategy whose caller did not name one.

use cts_common::Crn;
use stack_profile::{ProfileError, ProfileStore};

use crate::{AuthError, Token};

/// Returns the workspace CRN configured for this process.
///
/// `CS_WORKSPACE_CRN` is used if it is set. Otherwise the CRN is the region
/// and workspace of the session that `stash auth login` saved for the CLI's
/// current workspace. On wasm32 there is no profile directory, so the
/// variable is the only source.
pub(super) fn detect_crn() -> Result<Crn, AuthError> {
    let env_crn = std::env::var("CS_WORKSPACE_CRN").ok();
    #[cfg(not(target_arch = "wasm32"))]
    let store = || ProfileStore::resolve(None).ok();
    #[cfg(target_arch = "wasm32")]
    let store = || None;
    crn_from(env_crn.as_deref(), store)
}

/// Does the work of [`detect_crn`] on a variable that is already read.
///
/// `store` is called only when the variable is not set, so a process
/// configured by the variable never reads the profile directory.
fn crn_from(
    env_crn: Option<&str>,
    store: impl FnOnce() -> Option<ProfileStore>,
) -> Result<Crn, AuthError> {
    if let Some(crn) = env_crn {
        return crn.parse::<Crn>().map_err(AuthError::from);
    }
    let store = store().ok_or(AuthError::NotAuthenticated(crate::error::NotAuthenticated))?;
    profile_workspace_crn(&store)
}

/// Returns the workspace CRN of the session that `stash auth login` saved
/// for the CLI's current workspace in `store`: the region the session
/// records and the workspace its token names.
///
/// This is where [`OidcFederationStrategy::with_detected_workspace`](super::OidcFederationStrategy::with_detected_workspace)
/// looks when `CS_WORKSPACE_CRN` is not set. Use it when the profile
/// directory is not the one `CS_CONFIG_PATH` or the home directory names,
/// or when the process has no environment to read.
///
/// `store` is the profile root, the directory that holds
/// `current_workspace`, not a workspace's own directory.
///
/// # Errors
///
/// Only a profile with nothing saved means "not logged in". A profile that
/// cannot be read is reported as itself.
///
/// - [`AuthError::NotAuthenticated`] if there is no current workspace, the
///   current workspace has no saved session, or the session records no
///   region.
/// - [`AuthError::Store`] if `current_workspace` or the session's
///   `auth.json` cannot be read or parsed, or `current_workspace` does not
///   hold a valid workspace id.
/// - [`AuthError::InvalidToken`] if the session's token is not a JWT with a
///   `workspace` claim.
/// - [`AuthError::Region`] if the session records a region this crate does
///   not know.
///
/// # Example
///
/// ```
/// use stack_auth::{profile_workspace_crn, AuthError};
/// use stack_profile::ProfileStore;
///
/// let dir = tempfile::tempdir().unwrap();
/// let result = profile_workspace_crn(&ProfileStore::new(dir.path()));
/// // An empty profile has no login.
/// assert!(matches!(result, Err(AuthError::NotAuthenticated(_))));
/// ```
pub fn profile_workspace_crn(store: &ProfileStore) -> Result<Crn, AuthError> {
    let not_authenticated = || AuthError::NotAuthenticated(crate::error::NotAuthenticated);
    // Only a missing `current_workspace` file means "not logged in". A file
    // that cannot be read, or that names an invalid workspace, is reported
    // as itself, as `ProfileKeyProvider` reports it.
    let session = match store.current_workspace_store() {
        Ok(session) => session,
        Err(ProfileError::NoCurrentWorkspace) => return Err(not_authenticated()),
        Err(e) => return Err(e.into()),
    };
    // Likewise only a missing `auth.json`. An existence check first would
    // read an unreadable file as a missing one.
    let token = match session.load_profile::<Token>() {
        Ok(token) => token,
        Err(ProfileError::NotFound { .. }) => return Err(not_authenticated()),
        Err(e) => return Err(e.into()),
    };
    token.workspace_crn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{claims_with_workspace, jwt_token};

    const SESSION_WORKSPACE: &str = "ZVATKW3VHMFG27DY";
    const SESSION_CRN: &str = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";
    const OTHER_CRN: &str = "crn:us-east-1.aws:AAAAAAAAAAAAAAAA";

    /// A profile whose current workspace has a saved session.
    fn profile_with_session(dir: &std::path::Path) -> ProfileStore {
        let store = ProfileStore::new(dir);
        store.init_workspace(SESSION_WORKSPACE).unwrap();
        let mut token = jwt_token(claims_with_workspace(SESSION_WORKSPACE));
        token.region = Some("ap-southeast-2.aws".to_string());
        store
            .current_workspace_store()
            .unwrap()
            .save_profile(&token)
            .unwrap();
        store
    }

    /// A profile source for a case that must not read the profile.
    fn unreachable_store() -> Option<ProfileStore> {
        panic!("the profile directory must not be resolved")
    }

    mod crn_from {
        use super::*;

        mod given_cs_workspace_crn {
            use super::*;

            #[test]
            fn returns_it_without_resolving_the_profile() {
                let crn = crn_from(Some(OTHER_CRN), unreachable_store).unwrap();

                assert_eq!(crn.to_string(), OTHER_CRN, "the variable's CRN is returned");
            }

            #[test]
            fn that_is_not_a_crn_is_invalid_crn_not_the_profiles() {
                let result = crn_from(Some("not-a-crn"), unreachable_store);

                assert!(
                    matches!(result, Err(AuthError::InvalidCrn(_))),
                    "expected InvalidCrn, got: {result:?}"
                );
            }
        }

        mod given_no_cs_workspace_crn {
            use super::*;

            #[test]
            fn returns_the_crn_of_the_current_workspaces_session() {
                let dir = tempfile::tempdir().unwrap();
                let store = profile_with_session(dir.path());

                let crn = crn_from(None, || Some(store)).unwrap();

                assert_eq!(
                    crn.to_string(),
                    SESSION_CRN,
                    "the session's region and workspace make the CRN"
                );
            }

            #[test]
            fn a_current_workspace_without_a_session_is_not_authenticated() {
                let dir = tempfile::tempdir().unwrap();
                let store = profile_with_session(dir.path());
                // The CLI user switches to another workspace with no session.
                store.init_workspace("AAAAAAAAAAAAAAAA").unwrap();

                let result = crn_from(None, || Some(store));

                assert!(
                    matches!(result, Err(AuthError::NotAuthenticated(_))),
                    "another workspace's session must not be used, got: {result:?}"
                );
            }

            #[test]
            fn a_profile_with_no_current_workspace_is_not_authenticated() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let result = crn_from(None, || Some(store));

                assert!(
                    matches!(result, Err(AuthError::NotAuthenticated(_))),
                    "expected NotAuthenticated, got: {result:?}"
                );
            }

            #[test]
            fn a_current_workspace_file_naming_an_invalid_id_is_a_store_error() {
                let dir = tempfile::tempdir().unwrap();
                std::fs::write(dir.path().join("current_workspace"), "not-a-workspace").unwrap();
                let store = ProfileStore::new(dir.path());

                let result = crn_from(None, || Some(store));

                assert!(
                    matches!(
                        result,
                        Err(AuthError::Store(crate::error::StoreError(
                            ProfileError::InvalidWorkspaceId(_)
                        )))
                    ),
                    "a broken profile must not read as not logged in, got: {result:?}"
                );
            }

            #[test]
            fn no_profile_is_not_authenticated() {
                let result = crn_from(None, || None);

                assert!(
                    matches!(result, Err(AuthError::NotAuthenticated(_))),
                    "expected NotAuthenticated, got: {result:?}"
                );
            }

            #[test]
            fn a_session_recording_an_unknown_region_is_a_region_error() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());
                store.init_workspace(SESSION_WORKSPACE).unwrap();
                let mut token = jwt_token(claims_with_workspace(SESSION_WORKSPACE));
                token.region = Some("nowhere".to_string());
                store
                    .current_workspace_store()
                    .unwrap()
                    .save_profile(&token)
                    .unwrap();

                let result = crn_from(None, || Some(store));

                assert!(
                    matches!(result, Err(AuthError::Region(_))),
                    "a broken session must not read as a server error, got: {result:?}"
                );
            }

            /// An `auth.json` that cannot be reached is a store error. Only a
            /// missing one means "not logged in".
            #[cfg(unix)]
            #[test]
            fn an_unreadable_session_is_a_store_error() {
                use std::os::unix::fs::PermissionsExt;

                let dir = tempfile::tempdir().unwrap();
                let store = profile_with_session(dir.path());
                let ws = dir.path().join("workspaces").join(SESSION_WORKSPACE);
                std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o000)).unwrap();
                let unreadable = std::fs::metadata(ws.join("auth.json")).is_err();

                let result = crn_from(None, || Some(store));

                std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o755)).unwrap();
                if !unreadable {
                    // Run as root: permissions do not stop the read.
                    return;
                }
                assert!(
                    matches!(
                        result,
                        Err(AuthError::Store(crate::error::StoreError(
                            ProfileError::Io(_)
                        )))
                    ),
                    "an unreadable session must not read as not logged in, got: {result:?}"
                );
            }
        }
    }

    // These tests set process environment variables. `temp_env` runs them
    // one at a time and restores the variables afterwards, because plain
    // `cargo test` runs every test in one process. `CS_CONFIG_PATH` always
    // names a temporary directory, so the developer's own profile is never
    // read.
    mod detect_crn {
        use super::*;

        fn detect_with(
            workspace_crn: Option<&str>,
            profile: &std::path::Path,
        ) -> Result<Crn, AuthError> {
            temp_env::with_vars(
                [
                    ("CS_WORKSPACE_CRN", workspace_crn),
                    ("CS_CONFIG_PATH", profile.to_str()),
                ],
                detect_crn,
            )
        }

        #[test]
        fn reads_cs_workspace_crn() {
            let dir = tempfile::tempdir().unwrap();

            let result = detect_with(Some(OTHER_CRN), dir.path()).unwrap();

            assert_eq!(
                result.to_string(),
                OTHER_CRN,
                "the variable's CRN is returned"
            );
        }

        #[test]
        fn falls_back_to_the_profile_cs_config_path_names() {
            let dir = tempfile::tempdir().unwrap();
            profile_with_session(dir.path());

            let result = detect_with(None, dir.path()).unwrap();

            assert_eq!(
                result.to_string(),
                SESSION_CRN,
                "the profile session's CRN is returned"
            );
        }

        #[test]
        fn with_neither_is_not_authenticated() {
            let dir = tempfile::tempdir().unwrap();

            let result = detect_with(None, dir.path());

            assert!(
                matches!(result, Err(AuthError::NotAuthenticated(_))),
                "nothing configured must be an error, got: {result:?}"
            );
        }
    }
}
