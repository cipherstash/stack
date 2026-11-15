//! Every Rust code block in the `eql-bindings` README is run.
//!
//! `src/lib.rs` includes the README as documentation, so `cargo test` runs
//! each Rust block as a doctest of this crate. rustdoc skips a block marked
//! `ignore`, and only compiles one marked `no_run`. It reports both as
//! passing. So no Rust block may carry a marker.
//!
//! rustdoc also reads a block as Rust when its info string holds only
//! rustdoc's own words, such as `ignore` or `should_panic`, or is empty. So
//! this test does not try to tell which blocks rustdoc compiles. It allows
//! two kinds of block, and refuses every other:
//!
//! - `rust`, alone: rustdoc compiles it and runs it;
//! - one of [`OTHER_LANGUAGES`]: a word rustdoc does not know, so the
//!   block is not a doctest.

const README: &str = include_str!("../../../crates/eql-bindings/README.md");

/// The languages a block may name that are not Rust. rustdoc knows none of
/// these words, so it does not compile a block that names one.
const OTHER_LANGUAGES: [&str; 6] = ["bash", "json", "sh", "sql", "text", "toml"];

/// The info string of each fenced code block, with the line it opens on.
fn code_blocks(markdown: &str) -> Vec<(usize, &str)> {
    let mut blocks = Vec::new();
    let mut open = false;
    for (index, line) in markdown.lines().enumerate() {
        let Some(info) = line.strip_prefix("```") else {
            continue;
        };
        if !open {
            blocks.push((index + 1, info.trim()));
        }
        open = !open;
    }
    assert!(!open, "the last code block is not closed");
    blocks
}

/// Whether a block with this info string is allowed: a Rust block that is
/// run, or a block in another language.
fn allowed(info: &str) -> bool {
    info == "rust" || OTHER_LANGUAGES.contains(&info)
}

#[test]
fn every_rust_block_in_the_readme_is_run() {
    let blocks = code_blocks(README);
    assert!(
        blocks.iter().any(|(_, info)| *info == "rust"),
        "the README has no Rust code block"
    );
    for (line, info) in blocks {
        assert!(
            allowed(info),
            "README line {line}: a code block marked `{info}`. Mark a Rust example `rust` \
             alone, so that it is run. Mark any other block with its language, one of \
             {OTHER_LANGUAGES:?}"
        );
    }
}

#[test]
fn the_scan_reads_each_blocks_info_string() {
    let blocks = code_blocks("```rust,ignore\nlet x = 1;\n```\n\n```sh\nls\n```\n\n```\nx\n```\n");
    assert_eq!(blocks, [(1, "rust,ignore"), (5, "sh"), (9, "")]);
}

#[test]
fn a_block_rustdoc_would_skip_is_refused() {
    for info in ["rust", "sh", "bash", "text"] {
        assert!(allowed(info), "`{info}` is allowed");
    }
    // Every one of these is Rust to rustdoc, and none is run as written:
    // skipped, compiled only, expected to fail, or run with no language
    // named.
    for info in [
        "",
        "ignore",
        "no_run",
        "rust,ignore",
        "rust,no_run",
        "rust ignore",
        "should_panic",
        "compile_fail",
        "rust,should_panic",
        "edition2021",
        "sh,ignore",
    ] {
        assert!(!allowed(info), "`{info}` is refused");
    }
}
