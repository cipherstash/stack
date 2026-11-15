//! Every Rust code block in the `eql-bindings` README is run.
//!
//! `src/lib.rs` includes the README as documentation, so `cargo test` runs
//! each Rust block as a doctest of this crate. rustdoc skips a block marked
//! `ignore`, and only compiles one marked `no_run`. It reports both as
//! passing. So no Rust block may carry a marker.

const README: &str = include_str!("../../../crates/eql-bindings/README.md");

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

#[test]
fn every_rust_block_in_the_readme_is_run() {
    // rustdoc reads a block with no language as Rust too.
    let rust: Vec<_> = code_blocks(README)
        .into_iter()
        .filter(|(_, info)| info.is_empty() || info.starts_with("rust"))
        .collect();
    assert!(!rust.is_empty(), "the README has no Rust code block");
    for (line, info) in rust {
        assert_eq!(
            info, "rust",
            "README line {line}: mark the block `rust` alone, so that it is run"
        );
    }
}

#[test]
fn the_scan_finds_a_marked_block() {
    let blocks = code_blocks("```rust,ignore\nlet x = 1;\n```\n\n```sh\nls\n```\n\n```\nx\n```\n");
    assert_eq!(blocks, [(1, "rust,ignore"), (5, "sh"), (9, "")]);
}
