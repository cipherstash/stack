//! A doc example shows the production path.
//!
//! Developers and coding agents copy examples as they are. An example that
//! builds its cipher with `FakeDataKeySource` in plain view is copied with
//! the fake: the keys are then held in memory, are lost when the process
//! ends, and no key request reaches ZeroKMS.
//!
//! So an example shows the builder as a program writes it, and hides the
//! line that passes the fake:
//!
//! ```text
//! /// let cipher = StackCipher::builder()
//! /// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//! ///     .init()
//! ///     .await?;
//! ```
//!
//! The example still runs as a doctest, and a copy of it uses ZeroKMS.
//!
//! This test reads every `.rs` file under `src/`. It fails when a line of a
//! doc example names `FakeDataKeySource` and is not hidden with `#`. The
//! examples that show the fake on purpose are listed in [`ALLOWED`], each
//! with the reason.
//!
//! It reads `///` and `//!` comments only. An example written in a
//! `#[doc = "..."]` attribute is not checked.

use std::fs;
use std::path::{Path, PathBuf};

/// The name an example must not show.
const FAKE: &str = "FakeDataKeySource";

/// Files whose examples show the fake on purpose: the path, the number of
/// lines that name it, and why. A count that changes fails the test, so a
/// new use in one of these files is a decision, not an accident.
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        "src/lib.rs",
        2,
        "the section \"Testing without ZeroKMS\" shows how to test with the fake",
    ),
    (
        "src/cipher.rs",
        2,
        "the `StackCipher` example of `.kms(..)` passes a key source, and says it is the one for tests",
    ),
    (
        "src/testing.rs",
        2,
        "the examples of the `testing` module are tests",
    ),
];

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read a source directory") {
        let path = entry.expect("read a directory entry").path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The numbers of the lines in `source` that show [`FAKE`] in a doc
/// example: inside a code block of a `///` or `//!` comment, and not hidden
/// with `#`.
fn visible_uses(source: &str) -> Vec<usize> {
    let mut in_example = false;
    let mut uses = Vec::new();
    for (index, line) in source.lines().enumerate() {
        let line = line.trim_start();
        let Some(doc) = line
            .strip_prefix("///")
            .or_else(|| line.strip_prefix("//!"))
        else {
            // The comment ended, and any code block ended with it.
            in_example = false;
            continue;
        };
        let doc = doc.trim_start();
        if doc.starts_with("```") {
            in_example = !in_example;
            continue;
        }
        let hidden = doc == "#" || doc.starts_with("# ");
        if in_example && !hidden && doc.contains(FAKE) {
            uses.push(index + 1);
        }
    }
    uses
}

#[test]
fn only_a_hidden_line_of_an_example_names_the_fake() {
    let hidden = "/// ```\n/// let cipher = StackCipher::builder()\n/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())\n///     .init()\n/// ```\n";
    assert_eq!(visible_uses(hidden), Vec::<usize>::new());

    let shown = "//! ```\n//! use stack_encrypt::kms::FakeDataKeySource;\n//! ```\n";
    assert_eq!(visible_uses(shown), vec![2]);

    // Prose may name the fake: only a code block is copied and run.
    let prose = "/// `FakeDataKeySource` is the key source for tests.\n";
    assert_eq!(visible_uses(prose), Vec::<usize>::new());

    // Code is not a doc example, and a code block ends with its comment.
    let code =
        "/// ```\n/// let a = 1;\nlet source = FakeDataKeySource::new();\n/// FakeDataKeySource\n";
    assert_eq!(visible_uses(code), Vec::<usize>::new());
}

#[test]
fn no_doc_example_shows_the_fake_key_source() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    assert!(!files.is_empty(), "no source file was read");

    let mut problems = Vec::new();
    for file in &files {
        let name = file
            .strip_prefix(root)
            .expect("a file under the crate")
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(file).expect("read a source file");
        let uses = visible_uses(&source);
        let allowed = ALLOWED
            .iter()
            .find(|(path, _, _)| *path == name)
            .map_or(0, |(_, count, _)| *count);
        if uses.len() != allowed {
            problems.push(format!(
                "{name}: {} lines of doc examples name `{FAKE}`, at lines {uses:?}, and {allowed} are allowed",
                uses.len()
            ));
        }
    }
    for (path, _, reason) in ALLOWED {
        assert!(
            root.join(path).is_file(),
            "{path} is allowed ({reason}) but is not a file"
        );
    }
    assert!(
        problems.is_empty(),
        "A doc example must not show `{FAKE}`: a developer who copies the example copies the fake.\n\
         Hide the line with `#`, as the other examples do, or add the file to `ALLOWED` with a reason.\n{}",
        problems.join("\n")
    );
}
