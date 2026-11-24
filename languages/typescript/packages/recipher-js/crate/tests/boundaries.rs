//! Checks of what the crate must not depend on.
//!
//! - The crate does not link `eql-bindings`. The EQL (Encrypt Query
//!   Language) types are an extension to the core. A build of the core
//!   contains none of them.
//! - A build with the default features has no test cipher. That build turns
//!   on neither the crate's `testing` feature nor the engine's
//!   `test-support` feature. The `test-support` key source derives every
//!   key from a public seed. `build:native` makes the release addon with
//!   the default features, and every CI build turns `testing` on. So this
//!   test is what checks that the release build cannot reach the test keys.

use std::path::PathBuf;
use std::process::Command;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Runs `cargo tree --locked` for the crate with its default features.
/// The command reads the committed lock file, so no build is needed.
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
