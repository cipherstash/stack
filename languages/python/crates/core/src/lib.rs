//! The Python SDK's engine-side logic, with no pyo3 in it, so that it can be
//! linked and tested without a Python interpreter.
//!
//! Today it holds one fact: the engine commit the build recorded (`build.rs`).
//! The Python SDK spec (#1341, "Layout") says what else belongs here.

/// The commit of the `stack-encrypt` engine this build was taken from: a
/// full 40-character lower-case hex SHA, with `-dirty` appended when any
/// `packages/stack-*` crate had uncommitted changes at build time.
pub fn engine_commit() -> &'static str {
    env!("STACKENCRYPT_ENGINE_COMMIT")
}

#[cfg(test)]
mod tests {
    use super::engine_commit;

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
}
