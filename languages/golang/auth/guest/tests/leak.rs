//! The leak test for the credential guest: no error it records carries a
//! secret.
//!
//! Every error path a native test can reach is driven with marker values
//! where a caller's secrets would be — an access token in `auth.json`, an
//! access key in a strategy config, a client key in `secretkey.json` —
//! through the same functions the wasm exports run, inside the real export
//! lifecycle. Each failure's encoded error, read back through
//! `se_last_error`'s packing, is decoded and searched at every depth: no
//! marker may appear. Each scenario also pins the code it reaches, so one
//! that stops reaching it fails by name. The rule it enforces is
//! written on `ErrorPayload` in `stack-profile`.
//!
//! The profile exports (`ops`) run natively, so they are driven directly.
//! The strategy exports (`auth`) exist only on wasm32, since they reach the
//! host's imports, so their refusals are recorded here through the same
//! `status::fail_auth` they call, from errors built the way they build them
//! (a parsed access key, a parsed CRN, a token with no region). The token
//! exchanges themselves need the host's HTTP import; their errors are
//! stack-auth's, which the crypto guest's leak test also encodes.

use std::path::Path;

use stack_auth::AuthError;
use stack_auth_guest::ops;
use stack_auth_guest::status::fail_auth;
use stack_guest_abi::call;
use vitaminc_aead_value::{transport as codec, FfiValue};

const ACCESS_TOKEN: &str = "leak-marker-access-token";
const ACCESS_KEY: &str = "leak-marker-access-key";
const CLIENT_KEY: &str = "leak-marker-client-key";

const MARKERS: &[&str] = &[ACCESS_TOKEN, ACCESS_KEY, CLIENT_KEY];

/// Run one failing step through the real export lifecycle
/// ([`call::run`]), read its error the way the host does, through
/// `se_last_error`'s packing ([`call::take_last_error`]), and check it has
/// the codes this scenario is there to reach: its own code, then its
/// causes'. Each scenario pins its own, so one that stops reaching the code
/// that could leak its marker fails by name.
fn failure<T: std::fmt::Debug>(
    what: &str,
    expect: &[&str],
    step: impl FnOnce() -> Result<T, u32>,
) -> FfiValue {
    let _ = call::run(step).expect_err(what);
    let bytes = call::take_last_error().unwrap_or_else(|| panic!("{what}: no error recorded"));
    let error = codec::decode_value(&mut codec::Reader::new(&bytes)).expect("an error decodes");
    assert_eq!(codes(&error), expect, "{what}: the codes it reaches");
    error
}

/// An error's code, then its causes' codes, in order.
fn codes(value: &FfiValue) -> Vec<String> {
    let mut out: Vec<String> = text(get(value, "code")).into_iter().collect();
    if let Some(FfiValue::Array(causes)) = get(value, "causes") {
        out.extend(causes.iter().filter_map(|cause| text(get(cause, "code"))));
    }
    out
}

fn check(text: &[u8], at: &str, found: &mut Vec<String>) {
    for marker in MARKERS {
        if text
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            found.push(format!("{at}: {marker}"));
        }
    }
}

fn leaks(value: &FfiValue, path: &str, found: &mut Vec<String>) {
    match value {
        FfiValue::String(text) => check(text.risky_ref(), path, found),
        FfiValue::Bytes(bytes) => {
            use vitaminc_protected::Controlled;
            check(bytes.risky_ref(), path, found);
        }
        FfiValue::Array(items) => {
            for (at, item) in items.iter().enumerate() {
                leaks(item, &format!("{path}[{at}]"), found);
            }
        }
        FfiValue::Object(entries) => {
            for (key, item) in entries {
                check(key.as_bytes(), &format!("{path} key"), found);
                leaks(item, &format!("{path}.{key}"), found);
            }
        }
        _ => {}
    }
}

fn get<'a>(value: &'a FfiValue, key: &str) -> Option<&'a FfiValue> {
    match value {
        FfiValue::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn text(value: Option<&FfiValue>) -> Option<String> {
    match value? {
        FfiValue::String(s) => String::from_utf8(s.risky_ref().to_vec()).ok(),
        _ => None,
    }
}

fn dir(path: &Path) -> Vec<u8> {
    path.to_str().expect("utf8 temp dir").as_bytes().to_vec()
}

fn scenarios() -> Vec<(&'static str, FfiValue)> {
    let root = tempfile::tempdir().expect("temp dir");
    let store = dir(root.path());
    let workspace = root.path().join("workspaces").join("AAAAAAAAAAAAAAAA");
    std::fs::create_dir_all(&workspace).expect("workspace dir");

    vec![
        // -- the profile store ---------------------------------------------
        (
            "an empty store directory",
            failure("empty dir", &["stack_guest_abi::malformed_input"], || {
                ops::current_workspace(b"")
            }),
        ),
        (
            "no current workspace",
            failure(
                "no current",
                &["stack_profile::no_current_workspace"],
                || ops::current_workspace(&store),
            ),
        ),
        (
            "a workspace id that is not one",
            failure("bad id", &["stack_profile::invalid_workspace_id"], || {
                ops::set_current_workspace(&store, b"short")
            }),
        ),
        (
            "a workspace with no directory",
            failure(
                "no workspace",
                &["stack_profile::workspace_not_found"],
                || ops::set_current_workspace(&store, b"BBBBBBBBBBBBBBBB"),
            ),
        ),
        (
            "a filename that names a path",
            failure("bad filename", &["stack_profile::invalid_filename"], || {
                ops::lock_path(&store, b"../auth.json")
            }),
        ),
        (
            "a profile file that is not there",
            failure("missing", &["stack_profile::not_found"], || {
                ops::token(&dir(&workspace))
            }),
        ),
        (
            "an auth.json whose expiry is the token",
            failure("json", &["stack_profile::json"], || {
                std::fs::write(
                    workspace.join("auth.json"),
                    format!(
                        r#"{{"access_token":"x","token_type":"Bearer","expires_at":"{ACCESS_TOKEN}"}}"#
                    ),
                )
                .expect("write auth.json");
                ops::token(&dir(&workspace))
            }),
        ),
        (
            "a secretkey.json whose client id is the key",
            failure("secret key json", &["stack_profile::json"], || {
                std::fs::write(
                    workspace.join("secretkey.json"),
                    // A JSON string where an object belongs: serde_json's
                    // message would quote it. (As an object key it would
                    // not: serde says only "invalid type: map".)
                    format!(r#""{CLIENT_KEY}""#),
                )
                .expect("write secretkey.json");
                ops::secret_key(&dir(&workspace))
            }),
        ),
        (
            "a profile file that is a directory",
            failure("io", &["stack_profile::io"], || {
                std::fs::create_dir_all(workspace.join("device.json")).expect("dir");
                ops::device_identity(&dir(&workspace))
            }),
        ),
        // -- strategies, as `auth` records their refusals -----------------
        (
            "an access key that is not one",
            failure("access key", &["stack_auth::invalid_access_key"], || {
                ACCESS_KEY
                    .parse::<stack_auth::AccessKey>()
                    .map_err(|e| fail_auth(&AuthError::from(e)))
            }),
        ),
        (
            "a CRN that is not one",
            failure("crn", &["stack_auth::invalid_crn"], || {
                "not a crn"
                    .parse::<cts_common::Crn>()
                    .map_err(|e| fail_auth(&AuthError::from(e)))
            }),
        ),
        // Coverage only: no marker can reach this error. The token parses,
        // and the refusal is `NotAuthenticated`, which this test builds and
        // which has no field that could hold the token.
        (
            "a device token with no region",
            failure(
                "not authenticated",
                &["stack_auth::not_authenticated"],
                || {
                    let session = root.path().join("session");
                    std::fs::create_dir_all(&session).expect("dir");
                    std::fs::write(
                    session.join("auth.json"),
                    format!(
                        r#"{{"access_token":"{ACCESS_TOKEN}","token_type":"Bearer","expires_at":99999999999}}"#
                    ),
                )
                .expect("write auth.json");
                    let token: stack_auth::Token = stack_profile::ProfileStore::new(&session)
                        .load_profile()
                        .expect("a token that parses");
                    if token.region().is_none() {
                        return Err(fail_auth(&stack_auth::NotAuthenticated.into()));
                    }
                    Ok(())
                },
            ),
        ),
    ]
}

#[test]
fn no_encoded_error_carries_a_marker() {
    let mut found = Vec::new();
    for (what, error) in scenarios() {
        leaks(&error, what, &mut found);
    }
    assert!(
        found.is_empty(),
        "markers in encoded errors:\n{}",
        found.join("\n")
    );
}

/// A profile JSON error gives its kind and position, and its payload names
/// where in the file, so a caller can say which line to fix.
#[test]
fn a_profile_json_error_points_at_the_line() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(root.path().join("auth.json"), "{\n  \"access_token\": 7\n}").expect("write");
    let error = failure("json", &["stack_profile::json"], || {
        ops::token(&dir(root.path()))
    });
    assert_eq!(
        text(get(&error, "code")).as_deref(),
        Some("stack_profile::json")
    );
    let fields = get(&error, "fields").expect("fields");
    assert!(matches!(get(fields, "line"), Some(FfiValue::UInt64(2))));
    assert!(
        text(get(&error, "help")).is_some(),
        "the help says how to fix it"
    );
}
