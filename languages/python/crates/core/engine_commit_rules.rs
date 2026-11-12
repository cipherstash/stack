//! The rules for the engine commit that `build.rs` records. `build.rs`
//! includes this file with `mod`, and the crate's tests include it with
//! `#[path]`, so the rules are tested without running a build.

/// The commit given in `STACKENCRYPT_ENGINE_COMMIT`, in lower case, or
/// `None` when the value is empty: an empty value means "read git".
pub fn from_override(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

/// Whether `commit` is a full 40-character lower-case hex SHA, with
/// `-dirty` after it or not.
pub fn is_valid(commit: &str) -> bool {
    let sha = commit.strip_suffix("-dirty").unwrap_or(commit);
    sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
