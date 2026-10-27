//! Records the engine commit the extension is built from.
//!
//! The engine is `stack-encrypt`, taken by path from this repository, so the
//! commit of this checkout is the engine's commit. The wheel exposes it as
//! `stackencrypt.__engine__` so a bug report names it (spec, user story 42).
//! When any `packages/stack-*` crate carries uncommitted changes the value
//! ends in `-dirty`, because the commit alone would then name code the wheel
//! was not built from. The scope is every stack-* crate, not only
//! `stack-encrypt`: it depends by path on `stack-kms` and
//! `stack-encrypt-derive`, and a wider scope can only add a `-dirty` that is
//! true. Edits outside `packages/stack-*` (this workspace, the Python
//! package) are not engine edits and do not mark the engine dirty; the wheel
//! version and the checkout commit describe those.
//!
//! `STACKENCRYPT_ENGINE_COMMIT` in the environment wins over git, for a build
//! from a source tree that is not a checkout. It is trusted as given: with no
//! checkout there is nothing to check it against. With neither, the build
//! fails: an "unknown" engine in a wheel is a report nobody can act on.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const ENV_OVERRIDE: &str = "STACKENCRYPT_ENGINE_COMMIT";
/// The directory of the stack-* crates, relative to this crate. Every
/// `stack-*` entry in it is engine source for the `-dirty` check.
const PACKAGES_DIR: &str = "../../../../packages";
const ENGINE_PREFIX: &str = "stack-";

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
    for dir in engine_dirs(&manifest_dir) {
        println!("cargo:rerun-if-changed={}", dir.display());
    }

    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| {
        panic!(
            "no engine commit: this is not a git checkout and {ENV_OVERRIDE} is not set. \
             Build from a checkout of cipherstash/stack, or set {ENV_OVERRIDE} to the \
             commit the engine (packages/stack-encrypt) is taken from."
        )
    });
    // Each crate's `fuzz/` is a detached workspace the engine build never
    // compiles, and its tracked seed corpus grows on every fuzz run, so a
    // corpus file must not mark the engine dirty.
    let dirs = engine_dirs(&manifest_dir);
    let mut paths: Vec<String> = dirs
        .iter()
        .map(|d| d.to_str().expect("utf-8 path").to_string())
        .collect();
    paths.extend(
        dirs.iter()
            .map(|d| format!(":(exclude){}/fuzz", d.display())),
    );
    let mut status = vec!["status", "--porcelain", "--"];
    status.extend(paths.iter().map(String::as_str));
    let dirty = git(&status).is_some_and(|s| !s.is_empty());
    if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    }
}

/// Every `packages/stack-*` directory, as engine source.
fn engine_dirs(manifest_dir: &Path) -> Vec<PathBuf> {
    let packages = manifest_dir.join(PACKAGES_DIR);
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&packages)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", packages.display()))
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(ENGINE_PREFIX)
        })
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    assert!(
        !dirs.is_empty(),
        "no {ENGINE_PREFIX}* crate under {}",
        packages.display()
    );
    dirs
}
