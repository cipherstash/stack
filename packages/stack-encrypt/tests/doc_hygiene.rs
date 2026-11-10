//! The rustdoc of `stack-encrypt` and `stack-encrypt-derive` names no
//! design record or plan.
//!
//! A doc comment is what a user reads on docs.rs and in an editor. The
//! design records and plans are for the people who maintain the crates and
//! are not published with them, so a doc comment states the rule itself. A
//! maintainer's pointer to a record belongs in a plain `//` comment.
//!
//! The scan covers every `///` and `//!` line under both crates' `src`,
//! and every file a `doc = include_str!(..)` attribute there pulls into the
//! rustdoc.

use std::collections::BTreeSet;
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

/// The file a `#[doc = include_str!("..")]` or `#![doc = ..]` line pulls
/// into the rustdoc, as the path written in it.
fn included_doc(line: &str) -> Option<&str> {
    let line = line.trim_start();
    if !(line.starts_with("#[doc") || line.starts_with("#![doc")) {
        return None;
    }
    let rest = &line[line.find("include_str!(\"")? + "include_str!(\"".len()..];
    Some(&rest[..rest.find('"')?])
}

/// What `line` names that a doc comment must not: a record number such as
/// `ADR-0004`, `ADR 0010` or `adr0009`, an `ADR` that ends the line (its
/// number is on the next), or a path into `docs/adr` or `docs/plans`.
fn names_a_record(line: &str) -> Option<&'static str> {
    let line = line.to_lowercase();
    if line.contains("docs/adr") {
        return Some("docs/adr");
    }
    if line.contains("docs/plans") {
        return Some("docs/plans");
    }
    let names_a_number = line.match_indices("adr").any(|(at, _)| {
        let before = line[..at].chars().next_back();
        if before.is_some_and(char::is_alphanumeric) {
            return false;
        }
        let after = &line[at + 3..];
        let after = after
            .strip_prefix(['-', ' ', '\u{2013}', '\u{2014}'])
            .unwrap_or(after);
        after.trim_end().is_empty() || after.starts_with(|c: char| c.is_ascii_digit())
    });
    names_a_number.then_some("an ADR number")
}

/// One place a rustdoc line comes from, for the failure message.
fn shown(file: &Path, number: usize) -> String {
    let file = file.strip_prefix(packages()).unwrap_or(file);
    format!("packages/{}:{}", file.display(), number + 1)
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
    let mut included = BTreeSet::new();
    for file in &files {
        let text =
            fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (number, line) in text.lines().enumerate() {
            if let Some(path) = included_doc(line) {
                let dir = file.parent().expect("a source file has a directory");
                let mut resolved = dir.to_path_buf();
                for part in Path::new(path).components() {
                    match part {
                        std::path::Component::ParentDir => {
                            resolved.pop();
                        }
                        part => resolved.push(part),
                    }
                }
                included.insert(resolved);
            }
            if !is_doc_comment(line) {
                continue;
            }
            if let Some(what) = names_a_record(line) {
                offences.push(format!(
                    "{}: names {what}: {}",
                    shown(file, number),
                    line.trim()
                ));
            }
        }
    }
    for file in &included {
        let text =
            fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (number, line) in text.lines().enumerate() {
            if let Some(what) = names_a_record(line) {
                offences.push(format!(
                    "{}: names {what}: {}",
                    shown(file, number),
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
        "/// as adr-0004 says.",
        "/// as ADR\u{2013}0004 says.",
        "//! but not which one when several share a selector (ADR",
        "/// recorded in ADR-",
        "/// Design: `docs/plans/x.md`.",
        "/// See `packages/stack-encrypt/docs/adr`.",
    ] {
        assert!(is_doc_comment(line), "{line}");
        assert!(names_a_record(line).is_some(), "{line}");
    }
    for line in [
        "/// ADRs are for maintainers.",
        "/// An ADR- prefix alone.",
        "/// A quadrant 4 and a QUADR 4.",
        "/// The `madr` field.",
    ] {
        assert!(names_a_record(line).is_none(), "{line}");
    }
    for line in ["// ADR-0004.", "//// ADR-0004.", "let x = 1; // ADR-0004"] {
        assert!(!is_doc_comment(line), "{line}");
    }
    assert_eq!(
        included_doc(r#"#![doc = include_str!("../docs/attributes.md")]"#),
        Some("../docs/attributes.md")
    );
    assert_eq!(
        included_doc(r#"#[doc = include_str!("../docs/attributes.md")]"#),
        Some("../docs/attributes.md")
    );
    assert_eq!(included_doc(r#"let s = include_str!("x.md");"#), None);
}

#[test]
fn the_scan_reads_the_derive_crates_attribute_docs() {
    let lib = fs::read_to_string(packages().join("stack-encrypt-derive/src/lib.rs"))
        .expect("read the derive crate's lib.rs");
    assert!(
        lib.lines().any(|line| included_doc(line).is_some()),
        "the derive crate no longer includes a doc file; if that is intended, \
         this test and the include scan above can go"
    );
}
