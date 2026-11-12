//! The Python SDK's engine-side logic, with no pyo3 in it, so that it can be
//! linked and tested without a Python interpreter.
//!
//! It holds the engine commit the build recorded (`build.rs`), the engine's
//! check of a model's plan ([`plan`]), the credential lookup
//! ([`credentials`]), the one engine client a process shares ([`client`]),
//! the value rules ([`values`]), `encrypt` itself ([`encrypt`]),
//! `decrypt` ([`decrypt`]) and `query` ([`query`]). Each
//! reports an engine error as a [`refusal::Refusal`]. The Python SDK spec
//! (#1341, "Layout") says what else belongs here.

pub mod client;
pub mod credentials;
pub mod decrypt;
pub mod encrypt;
pub mod plan;
pub mod query;
pub mod refusal;
pub mod values;

// The resolver file below holds the EQL types only under this feature.
#[cfg(not(feature = "eql"))]
compile_error!(
    "stackencrypt-core needs its `eql` feature: every build of the SDK holds the EQL types"
);

// The deterministic key source takes every key from a fixed seed. A wheel
// built with it would export `_use_deterministic_keys`, which switches every
// key in the process to that seed. Only the test build uses it, and that
// build is the dev profile. A release build with the feature is refused here,
// so a release wheel cannot carry it.
#[cfg(all(feature = "deterministic-kms", not(debug_assertions)))]
compile_error!(
    "the `deterministic-kms` feature is for test builds only: a release build must not carry it"
);

// The EQL resolver: the Go guest's own file, compiled here too, so the two
// SDKs run one resolver and cannot drift apart. It switches on this crate's
// `eql` feature. Its tests run here as well as in the guest. `HOLDS_EQL` is
// the guest's alone, so dead code is allowed.
//
// This crate must have every crate the file uses. Today that is
// stack-encrypt and eql-bindings, plus serde_json for its tests. A Go change
// that adds one fails this crate's build in tests-python.yml. Then add it
// to Cargo.toml here too.
#[allow(dead_code)]
#[path = "../../../../golang/encrypt/guest/src/targets.rs"]
mod targets;

/// The commit of the `stack-encrypt` engine this build was taken from: a
/// full 40-character lower-case hex SHA, with `-dirty` appended when any
/// `packages/stack-*` crate had uncommitted changes at build time.
pub fn engine_commit() -> &'static str {
    env!("STACKENCRYPT_ENGINE_COMMIT")
}

#[cfg(test)]
#[path = "../engine_commit_rules.rs"]
mod engine_commit_rules;

#[cfg(test)]
mod tests {
    use super::engine_commit;
    use super::engine_commit_rules::{from_override, is_valid};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    /// The override rules: an empty value reads git, a value is lower-cased,
    /// and only a full hex SHA, with `-dirty` or not, is a commit.
    #[test]
    fn the_override_is_lower_cased_and_checked() {
        assert_eq!(from_override(""), None);
        assert_eq!(
            from_override(&SHA.to_ascii_uppercase()).as_deref(),
            Some(SHA)
        );
        assert!(is_valid(SHA));
        assert!(is_valid(&format!("{SHA}-dirty")));
        assert!(!is_valid(&SHA[..39]));
        assert!(!is_valid(&format!("{SHA}0")));
        assert!(!is_valid(&SHA.replace('a', "g")));
        assert!(!is_valid(&SHA.to_ascii_uppercase()));
        assert!(!is_valid(&format!("{SHA}-clean")));
    }
    use std::process::Command;

    #[test]
    fn engine_commit_is_a_full_hex_sha() {
        let commit = engine_commit();
        let sha = commit.strip_suffix("-dirty").unwrap_or(commit);
        assert_eq!(sha.len(), 40, "{commit:?}");
        assert!(
            sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{commit:?}"
        );
    }

    /// `git` in this crate's directory, or `None` when it fails.
    fn git(args: &[&str]) -> Option<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// The commit is this checkout's, with `-dirty` exactly when a file
    /// under a `packages/stack-*` crate has changed outside its `fuzz/`, or
    /// the root `Cargo.toml` or this workspace's `Cargo.lock` has changed.
    /// The status is read for wider paths and filtered here, so the test
    /// does not repeat build.rs's pathspec.
    #[test]
    fn engine_commit_is_this_checkouts_commit() {
        // A commit given in STACKENCRYPT_ENGINE_COMMIT is trusted as given.
        if env!("STACKENCRYPT_ENGINE_COMMIT_SOURCE") != "git" {
            return;
        }
        let Some(head) = git(&["rev-parse", "HEAD"]) else {
            return;
        };
        let status = git(&[
            "status",
            "--porcelain",
            "--",
            "../../../../packages",
            "../../../../Cargo.toml",
            "../../Cargo.lock",
        ])
        .expect("git status runs in a checkout");
        // A porcelain line is a two-letter status, a space and the path from
        // the repository root. A rename shows "old -> new".
        let dirty = status.lines().any(|line| {
            line.get(3..).is_some_and(|paths| {
                paths.split(" -> ").any(|path| {
                    let path = path.trim_matches('"');
                    path == "Cargo.toml"
                        || path == "languages/python/Cargo.lock"
                        || path
                            .strip_prefix("packages/")
                            .and_then(|rest| rest.split_once('/'))
                            .is_some_and(|(krate, rest)| {
                                krate.starts_with("stack-") && !rest.starts_with("fuzz/")
                            })
                })
            })
        });
        let expected = format!("{}{}", head.trim(), if dirty { "-dirty" } else { "" });
        assert_eq!(engine_commit(), expected, "git status:\n{status}");
    }
}
