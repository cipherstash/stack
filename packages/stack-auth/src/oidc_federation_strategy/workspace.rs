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
    let not_authenticated = || AuthError::NotAuthenticated(crate::error::NotAuthenticated);
    let store = store().ok_or_else(not_authenticated)?;
    // Only a missing `current_workspace` file means "not logged in". A file
    // that cannot be read, or that names an invalid workspace, is reported
    // as itself, as `ProfileKeyProvider` reports it.
    let session = match store.current_workspace_store() {
        Ok(session) => session,
        Err(ProfileError::NoCurrentWorkspace) => return Err(not_authenticated()),
        Err(e) => return Err(e.into()),
    };
    if !session.exists_profile::<Token>() {
        return Err(not_authenticated());
    }
    session.load_profile::<Token>()?.workspace_crn()
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
