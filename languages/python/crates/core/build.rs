//! Records the engine commit the extension is built from.
//!
//! The engine is `stack-encrypt`, taken by path from this repository, so the
//! commit of this checkout is the engine's commit. The wheel exposes it as
//! `stackencrypt.__engine__` so a bug report names it (spec, user story 42).
//! When `packages/stack-encrypt` carries uncommitted changes the value ends
//! in `-dirty`, because the commit alone would then name code the wheel was
//! not built from.
//!
//! `STACKENCRYPT_ENGINE_COMMIT` in the environment wins over git, for a build
//! from a source tree that is not a checkout. With neither, the build fails:
//! an "unknown" engine in a wheel is a report nobody can act on.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const ENV_OVERRIDE: &str = "STACKENCRYPT_ENGINE_COMMIT";
/// The engine's source, relative to this crate.
const ENGINE_DIR: &str = "../../../../packages/stack-encrypt";

fn main() {
    println!("cargo:rerun-if-env-changed={ENV_OVERRIDE}");
    let commit = match env::var(ENV_OVERRIDE) {
        Ok(value) if !value.is_empty() => value.to_ascii_lowercase(),
        _ => commit_from_git(),
    };
    let sha = commit.strip_suffix("-dirty").unwrap_or(&commit);
    assert!(
        sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "the engine commit must be a full 40-character hex SHA (optionally `-dirty`), got {commit:?}"
    );
    println!("cargo:rustc-env={ENV_OVERRIDE}={commit}");
}

fn commit_from_git() -> String {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let git = |args: &[&str]| -> Option<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&manifest_dir)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    };
    // Rerun when HEAD moves or the engine tree changes. A path that does not
    // exist is "always stale" to cargo, so only existing files are named: a
    // branch ref moves into `packed-refs` after `git pack-refs`, which is why
    // that file is watched beside the loose ref. The index changes on every
    // commit and stage, and the engine directory on every edit, which is what
    // keeps the `-dirty` suffix current. `--git-path` resolves correctly in a
    // worktree, where `.git` is a file and the real directory lives elsewhere.
    let mut watch: Vec<String> = ["HEAD", "packed-refs", "index"]
        .iter()
        .filter_map(|name| git(&["rev-parse", "--git-path", name]))
        .collect();
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        watch.extend(git(&["rev-parse", "--git-path", &reference]));
    }
    for path in watch {
        let resolved = manifest_dir.join(&path);
        if Path::new(&resolved).exists() {
            println!("cargo:rerun-if-changed={}", resolved.display());
        }
    }
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join(ENGINE_DIR).display()
    );

    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| {
        panic!(
            "no engine commit: this is not a git checkout and {ENV_OVERRIDE} is not set. \
             Build from a checkout of cipherstash/stack, or set {ENV_OVERRIDE} to the \
             commit the engine (packages/stack-encrypt) is taken from."
        )
    });
    let dirty = git(&["status", "--porcelain", "--", ENGINE_DIR]).is_some_and(|s| !s.is_empty());
    if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    }
}
