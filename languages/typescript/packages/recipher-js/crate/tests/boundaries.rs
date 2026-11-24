//! What the crate must not reach.
//!
//! - It names no `Label` and no `IntoLabel`. The engine is to replace both
//!   (the label becomes a field path), and a crate that never named them
//!   needs no change when it does.
//! - It does not link `eql-bindings`. The EQL types are an extension to the
//!   core; a build of the core holds none of them.
//! - A build with its default features has no test cipher: neither the
//!   crate's `testing` feature nor the engine's `test-support`, whose key
//!   source derives every key from a public seed. `build:native` makes the
//!   release addon with the default features, and every CI build turns
//!   `testing` on, so this is the check that the release build cannot reach
//!   the test keys.

use std::path::{Path, PathBuf};
use std::process::Command;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Whether `source` holds `word` as a whole identifier.
fn names(source: &str, word: &str) -> bool {
    source.match_indices(word).any(|(at, _)| {
        let before = source[..at].chars().next_back();
        let after = source[at + word.len()..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

#[test]
fn the_crate_names_no_label() {
    let mut files = Vec::new();
    rust_files(&crate_dir().join("src"), &mut files);
    assert!(!files.is_empty(), "no source files found");
    for file in files {
        let source = std::fs::read_to_string(&file).unwrap();
        for word in ["Label", "IntoLabel"] {
            assert!(!names(&source, word), "{} names `{word}`", file.display());
        }
    }
}

#[test]
fn the_word_check_matches_whole_identifiers_only() {
    assert!(names("use stack_encrypt::Label;", "Label"));
    assert!(names("fn f(x: IntoLabel)", "IntoLabel"));
    assert!(!names("LabelError", "Label"));
    assert!(!names("MyLabel", "Label"));
}

/// `cargo tree --locked` for the crate with its default features, from the
/// committed lock: no build is needed.
fn tree(edges: &str, format: Option<&str>) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut args = vec![
        "tree",
        "--locked",
        "--package",
        "recipher-js",
        "--edges",
        edges,
        "--prefix",
        "none",
    ];
    if let Some(format) = format {
        args.extend(["--format", format]);
    }
    let output = Command::new(cargo)
        .args(&args)
        .current_dir(crate_dir())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn the_crate_does_not_link_eql_bindings() {
    let tree = tree("normal,build", None);
    assert!(
        tree.lines().any(|line| line.starts_with("stack-encrypt ")),
        "the tree does not list the engine, so this check reads nothing:\n{tree}"
    );
    assert!(
        !tree.lines().any(|line| line.starts_with("eql-bindings ")),
        "the crate links eql-bindings:\n{tree}"
    );
}

#[test]
fn a_default_build_has_no_test_cipher() {
    // Each line is a package and the features it is built with, as cargo
    // resolves them for a normal build of the crate.
    let tree = tree("normal", Some("{p} [{f}]"));
    let features_of = |package: &str| -> Vec<String> {
        tree.lines()
            .filter(|line| line.starts_with(&format!("{package} ")))
            .flat_map(|line| {
                let inner = line
                    .rsplit_once('[')
                    .map_or("", |(_, rest)| rest.trim_end_matches(']'));
                inner
                    .split(',')
                    .filter(|feature| !feature.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let engine = features_of("stack-encrypt");
    assert!(
        engine.iter().any(|feature| feature == "dynamic"),
        "the engine's features were not read, so this check reads nothing:\n{tree}"
    );
    assert!(
        !engine.iter().any(|feature| feature == "test-support"),
        "a default build turns on the engine's test-support: {engine:?}"
    );
    assert!(
        !features_of("recipher-js")
            .iter()
            .any(|feature| feature == "testing"),
        "the crate's default features include `testing`"
    );
}
