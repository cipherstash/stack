//! The rustdoc of `stack-encrypt` and `stack-encrypt-derive` names no
//! design record or plan.
//!
//! A doc comment is what a user reads on docs.rs and in an editor. The
//! records under `docs/adr` and the plans under `docs/plans` are for the
//! people who maintain the crates and are not published with them, so a
//! doc comment states the rule itself. A maintainer's pointer to a record
//! belongs in a plain `//` comment.

use std::fs;
use std::path::{Path, PathBuf};

/// The repository's `packages` directory, which holds both crates.
fn packages() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits in `packages`")
}

/// The `src` directories of both crates.
fn sources() -> [PathBuf; 2] {
    ["stack-encrypt/src", "stack-encrypt-derive/src"].map(|dir| packages().join(dir))
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Whether `line` is a `///` or `//!` doc comment. A `////` line is a plain
/// comment.
fn is_doc_comment(line: &str) -> bool {
    let line = line.trim_start();
    (line.starts_with("///") && !line.starts_with("////")) || line.starts_with("//!")
}

/// What `line` names that a doc comment must not: a record number such as
/// `ADR-0004` or `ADR 0010`, or a path into `docs/adr` or `docs/plans`.
fn names_a_record(line: &str) -> Option<&'static str> {
    if line.contains("docs/adr") {
        return Some("docs/adr");
    }
    if line.contains("docs/plans") {
        return Some("docs/plans");
    }
    let bytes = line.as_bytes();
    line.match_indices("ADR")
        .any(|(at, _)| {
            let next = |offset: usize| bytes.get(at + 3 + offset).copied();
            match next(0) {
                Some(b'-' | b' ') => next(1).is_some_and(|b| b.is_ascii_digit()),
                Some(b) => b.is_ascii_digit(),
                None => false,
            }
        })
        .then_some("an ADR number")
}

#[test]
fn no_doc_comment_names_a_design_record_or_plan() {
    let mut files = Vec::new();
    for dir in sources() {
        rust_files(&dir, &mut files);
    }
    files.sort();
    assert!(
        !files.is_empty(),
        "no source files found under {:?}",
        sources()
    );

    let mut offences = Vec::new();
    for file in &files {
        let text =
            fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (number, line) in text.lines().enumerate() {
            if !is_doc_comment(line) {
                continue;
            }
            if let Some(what) = names_a_record(line) {
                let shown = file.strip_prefix(packages()).unwrap_or(file);
                offences.push(format!(
                    "packages/{}:{}: names {what}: {}",
                    shown.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        offences.is_empty(),
        "rustdoc must not name a design record or plan: users cannot follow it.\n\
         State the rule in the doc comment instead, and put any pointer for\n\
         maintainers in a plain `//` comment.\n\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_matcher_finds_what_it_should_and_nothing_else() {
    for line in [
        "/// The context is threaded (ADR-0004).",
        "//! See ADR 0010.",
        "    /// ADR0009 decision 5.",
        "/// Design: `docs/plans/x.md`.",
        "/// See `packages/stack-encrypt/docs/adr`.",
    ] {
        assert!(is_doc_comment(line), "{line}");
        assert!(names_a_record(line).is_some(), "{line}");
    }
    for line in ["/// ADRs are for maintainers.", "/// An ADR- prefix alone."] {
        assert!(names_a_record(line).is_none(), "{line}");
    }
    for line in ["// ADR-0004.", "//// ADR-0004.", "let x = 1; // ADR-0004"] {
        assert!(!is_doc_comment(line), "{line}");
    }
}
