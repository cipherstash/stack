//! Guard: no workspace-keyed SteVec selector is written into this crate.
//!
//! A SteVec selector is a keyed MAC over (workspace keyset, prefix, JSON path),
//! so a selector copied out of a fixture is a fact about one CipherStash
//! workspace. Pinned in source, it breaks the whole suite the next time CI's
//! `CS_WORKSPACE_CRN` changes, which happened twice (issue #1200). Tests read
//! selectors from the loaded fixture instead (`fixtures::ste_vec_selector`).
//!
//! The scan reads every `.rs` file under `src/` and `tests/`, and nothing
//! else: SQL and JSON only reach this crate's source inside Rust strings, and
//! the generated `fixtures/*.sql` files hold real selectors and are not
//! scanned. It flags any standalone run of exactly 32 hex characters (a
//! 16-byte selector), in any case, that looks random, wherever it sits on the
//! line: a bare `"…"` literal, inside a SQL string (`payload -> '…'::text`, the
//! shape the removed pins were used in), or inside escaped JSON
//! (`{\"s\":\"…\"}`). "Standalone" means no ASCII letter, digit or `_`
//! directly before or after, so a longer hash or identifier never matches
//! part-way. Two exceptions still count as a boundary, so `"\n…"`, `'\x…'`
//! (Postgres bytea) and `0x…` (a Rust `u128`) are caught: a `0x` prefix, and a
//! backslash followed by any ASCII letter, or by a hex character that the run
//! swallows (`\0`, `\b`, `\f`, but also `\5`). After a `0x` run, a Rust
//! integer suffix (`0x…u128`, `0x…_u128`, any integer type) counts as a right
//! boundary, so a suffixed literal is caught too. That rule is lexical, not a
//! string-escape parser: an escaped backslash (`\\n`), a raw string (`r"\b…"`)
//! and a path separator count the same. Telling them apart would only stop
//! some runs being flagged, and the guard errs toward flagging. A match must
//! also look random: at least [`MIN_DISTINCT_DIGITS`] distinct hex digits,
//! counted case-insensitively. A real selector is MAC output, uniformly random,
//! and has fewer than 8 distinct digits in 32 with probability about 4e-8.
//! Forged selectors in literal-payload tests are written low-entropy
//! (`"00000000000000000000000000000001"`, `"ffff…"`, `"deadbeef…"`), so they read
//! as fake and pass. Needs no database.
//!
//! Not caught: a selector split into pieces, such as a `[u8; 16]` array of
//! `0x..` bytes, two `u64` halves, or a run broken across lines. The scan sees
//! one line at a time and only a contiguous 32-hex run.

use std::path::{Path, PathBuf};

/// Selector hex length: 16 bytes.
const SELECTOR_HEX_LEN: usize = 32;

/// A literal with at least this many distinct hex digits is treated as real.
const MIN_DISTINCT_DIGITS: usize = 8;

/// Whether `content` (a string literal's body) looks like a real selector.
fn looks_like_real_selector(content: &str) -> bool {
    if content.len() != SELECTOR_HEX_LEN || !content.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mut seen = [false; 256];
    for b in content.bytes() {
        seen[b.to_ascii_lowercase() as usize] = true;
    }
    seen.iter().filter(|s| **s).count() >= MIN_DISTINCT_DIGITS
}

/// A byte that continues an identifier or number: an ASCII letter, digit or `_`.
/// The one word-boundary rule both sides of a run are judged by.
fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// What stands directly left of a hex run that has a left boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeftBoundary {
    /// Nothing, a non-word byte, or a backslash then an ASCII letter (`\n`,
    /// `\x`, whether or not the backslash is itself escaped or in a raw string).
    Plain,
    /// A standalone `0x` / `0X` prefix: the run is a Rust integer literal, which
    /// may carry a type suffix on its right.
    HexPrefix,
}

/// The left boundary of the hex run starting at `start`, if it has one. A
/// backslash then a hex character is handled by the caller, which strips that
/// character from the run (`after_escape`).
fn left_boundary(bytes: &[u8], start: usize) -> Option<LeftBoundary> {
    let Some(prev) = start.checked_sub(1).map(|i| bytes[i]) else {
        return Some(LeftBoundary::Plain);
    };
    if !is_word(prev) {
        return Some(LeftBoundary::Plain);
    }
    let before = start.checked_sub(2).map(|i| bytes[i]);
    match (before, prev) {
        // `\n`, `\t`, `\r`, `\x` (and `\\x`, the same inside a Rust string).
        (Some(b'\\'), p) if p.is_ascii_alphabetic() => Some(LeftBoundary::Plain),
        // `0x` / `0X`, itself standalone.
        (Some(b'0'), b'x' | b'X') if start < 3 || !is_word(bytes[start - 3]) => {
            Some(LeftBoundary::HexPrefix)
        }
        _ => None,
    }
}

/// Whether `rest`, the bytes after a `0x`-prefixed run, starts with a Rust
/// integer suffix (`u128`, `_u128`, …) that is itself standalone, as in
/// `0x<hex>u128`.
fn int_suffix_follows(rest: &[u8]) -> bool {
    const SUFFIXES: [&str; 12] = [
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
    ];
    let rest = rest.strip_prefix(b"_").unwrap_or(rest);
    SUFFIXES.iter().any(|suffix| {
        rest.strip_prefix(suffix.as_bytes())
            .is_some_and(|after| after.first().is_none_or(|b| !is_word(*b)))
    })
}

/// Every standalone 32-hex run on `line` that looks like a real selector.
fn selector_literals(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let boundary = match left_boundary(bytes, i) {
            Some(boundary) if bytes[i].is_ascii_hexdigit() => boundary,
            _ => {
                i += 1;
                continue;
            }
        };
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let suffixed = boundary == LeftBoundary::HexPrefix && int_suffix_follows(&bytes[i..]);
        if i < bytes.len() && is_word(bytes[i]) && !suffixed {
            continue;
        }
        let run = &line[start..i];
        // An escape whose letter is itself a hex digit (`\0`, `\b`, `\f`) is
        // swallowed into the run; the selector is the rest of it.
        let after_escape =
            start > 0 && bytes[start - 1] == b'\\' && run.len() == SELECTOR_HEX_LEN + 1;
        if looks_like_real_selector(run) {
            found.push(run);
        } else if after_escape && looks_like_real_selector(&run[1..]) {
            found.push(&run[1..]);
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The guard itself: no `.rs` file under `src/` or `tests/` holds a
/// random-looking standalone 32-hex run.
#[test]
fn no_workspace_keyed_selector_literals() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests"] {
        rust_files(&root.join(dir), &mut files);
    }
    files.sort();
    assert!(
        files.len() > 10,
        "the scan found only {} .rs files under {}; is it reading the right crate?",
        files.len(),
        root.display(),
    );

    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (n, line) in text.lines().enumerate() {
            for literal in selector_literals(line) {
                let rel = file.strip_prefix(root).unwrap_or(file);
                hits.push(format!("  {}:{}: \"{literal}\"", rel.display(), n + 1));
            }
        }
    }

    assert!(
        hits.is_empty(),
        "selector-shaped hex literals found (32 hex chars, any case, >= {MIN_DISTINCT_DIGITS} \
         distinct digits):\n{}\n\
         A SteVec selector is keyed by the CipherStash workspace, so a pinned one breaks \
         when CI's workspace changes. Read it from the loaded fixture \
         (`fixtures::v3_doc_integer::field_op_selector`, \
         `fixtures::v3_ste_vec::hello_op_selector`). If the value is forged for a \
         literal-payload test, make it visibly fake, e.g. all zeros ending in 1.",
        hits.join("\n"),
    );
}

#[cfg(test)]
mod classifier {
    use super::*;

    /// A random-looking 32-hex string built at runtime, so this file carries no
    /// literal the guard would flag.
    fn random_looking() -> String {
        let digits = b"0123456789abcdef";
        (0..SELECTOR_HEX_LEN)
            .map(|i| digits[(i * 7 + 3) % 16] as char)
            .collect()
    }

    #[test]
    fn flags_a_random_looking_selector() {
        assert!(looks_like_real_selector(&random_looking()));
        let line = format!(r#"    {{"s":"{}","c":"ct"}}"#, random_looking());
        assert_eq!(selector_literals(&line), vec![random_looking().as_str()]);
    }

    #[test]
    fn flags_a_selector_inside_sql_or_escaped_json() {
        let r = random_looking();
        let sql = format!("    \"SELECT 1 WHERE (payload -> '{r}'::text) IS NOT NULL\"");
        assert_eq!(selector_literals(&sql), vec![r.as_str()]);
        let escaped = format!(r#"    "{{\"s\":\"{r}\"}}""#);
        assert_eq!(selector_literals(&escaped), vec![r.as_str()]);
    }

    /// A run with a word character on either side is part of something longer.
    #[test]
    fn ignores_a_run_inside_a_longer_word() {
        let r = random_looking();
        for line in [
            format!("x{r}"),
            format!("{r}0"),
            format!("{r}_"),
            format!("0{r}"),
        ] {
            assert!(selector_literals(&line).is_empty(), "{line}");
        }
    }

    /// A Rust or SQL string escape (`\n`, `\t`, `\r`) ends in a letter, but the
    /// run after it is still standalone in the string's value. So is a
    /// run after `\x` (Postgres bytea), after an escape whose letter is itself
    /// hex (`\0`, `\b`, `\f`), and after a `0x` prefix (a Rust integer).
    #[test]
    fn flags_a_selector_right_after_a_string_escape() {
        let r = random_looking();
        for escape in [r"\n", r"\t", r"\r", r"\x", r"\\x", r"\0", r"\b", r"\f"] {
            let line = format!(r#"    "line{escape}{r}""#);
            assert_eq!(selector_literals(&line), vec![r.as_str()], "{line}");
        }
        let bytea = format!(r"    WHERE s = '\x{r}'::bytea");
        assert_eq!(selector_literals(&bytea), vec![r.as_str()], "{bytea}");
        for prefix in ["0x", "0X"] {
            let int = format!("    const S: u128 = {prefix}{r};");
            assert_eq!(selector_literals(&int), vec![r.as_str()], "{int}");
        }
        // A Rust integer suffix after a `0x` run does not hide it.
        for suffix in ["u128", "_u128", "i128"] {
            let int = format!("    const S: u128 = 0x{r}{suffix};");
            assert_eq!(selector_literals(&int), vec![r.as_str()], "{int}");
        }
        // A `0x` inside a longer word is not a prefix.
        assert!(selector_literals(&format!("a0x{r}")).is_empty());
        // A suffix-shaped tail is only a suffix after `0x`, and only standalone.
        assert!(selector_literals(&format!("{r}u128")).is_empty());
        assert!(selector_literals(&format!("0x{r}u128x")).is_empty());
    }

    /// Uppercase and mixed-case hex selectors are flagged too.
    #[test]
    fn flags_uppercase_and_mixed_case_selectors() {
        let upper = random_looking().to_uppercase();
        assert!(looks_like_real_selector(&upper));
        let line = format!(r#"    {{"s":"{upper}"}}"#);
        assert_eq!(selector_literals(&line), vec![upper.as_str()]);
        let mixed: String = random_looking()
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(looks_like_real_selector(&mixed));
        assert_eq!(
            selector_literals(&format!("'{mixed}'")),
            vec![mixed.as_str()]
        );
    }

    /// Distinct digits are counted case-insensitively: `a` and `A` are one.
    #[test]
    fn counts_distinct_digits_case_insensitively() {
        // Six distinct letters; counted case-sensitively, the mix would be 12.
        let aa = "abcdef".repeat(6)[..32].to_string();
        let aa_mixed: String = aa
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(!looks_like_real_selector(&aa_mixed), "{aa_mixed}");
    }

    /// Pins the randomness threshold at 8 distinct digits. Written as
    /// literal numbers, not `MIN_DISTINCT_DIGITS`, so moving the constant
    /// fails here.
    #[test]
    fn threshold_is_eight_distinct_digits() {
        let with_distinct = |n: usize| -> String {
            let digits = &b"0123456789abcdef"[..n];
            (0..SELECTOR_HEX_LEN)
                .map(|i| digits[i % n] as char)
                .collect()
        };
        for (n, flagged) in [(7, false), (8, true), (12, true)] {
            let s = with_distinct(n);
            assert_eq!(looks_like_real_selector(&s), flagged, "{n} distinct: {s}");
            let expected: Vec<&str> = if flagged { vec![s.as_str()] } else { vec![] };
            assert_eq!(
                selector_literals(&format!("\"{s}\"")),
                expected,
                "{n} distinct"
            );
        }
    }

    #[test]
    fn passes_visibly_forged_values() {
        for forged in [
            "0".repeat(31) + "1",
            "f".repeat(32),
            "deadbeef".repeat(4),
            "ab".repeat(16),
        ] {
            assert!(!looks_like_real_selector(&forged), "{forged}");
        }
    }

    /// Only exactly 32 hex characters is selector-shaped.
    #[test]
    fn ignores_other_lengths() {
        let r = random_looking();
        assert!(!looks_like_real_selector(&r[..31]));
        assert!(!looks_like_real_selector(&format!("{r}0")));
        assert!(!looks_like_real_selector("placeholder"));
    }
}
