//! STRUCTURAL GATES over the committed scalar SQL surface.
//!
//! Byte-for-byte parity between the generator and the committed
//! `src/v3/scalars/<token>/` files is enforced by `mise run codegen:parity`
//! (regenerate in place + `git diff --exit-code`), mirroring how
//! `mise run types:check` gates the committed Rust bindings. These in-process
//! tests are the belt-and-suspenders that run in a plain `cargo test` (no git,
//! no build): they assert the committed token dirs match `eql_domains::CATALOG`
//! and that every generated file carries its owner-marker, plus the
//! determinism promise (identical `CATALOG` => byte-identical SQL).
//!
//! The plaintext fixture lists are not generated; they live in the catalog
//! (`eql_domains::INT4_VALUES` / `INT2_VALUES`) and are pinned by `eql-domains`'s
//! own `values_tests`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use eql_codegen::repo_root;

/// SQL generated-file marker — the first line every generated `.sql` carries.
/// Kept in lockstep with `eql_codegen`'s crate-private `AUTO_GENERATED_MARKER`
/// (asserted there by `consts::tests::sql_marker_is_grep_compatible_single_line`).
const AUTO_GENERATED_MARKER: &str = "-- AUTOMATICALLY GENERATED FILE.";

/// A temp dir removed on drop, so parity runs don't leak `/tmp` trees.
struct TempDir(PathBuf);
impl TempDir {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn tempdir(tag: &str) -> TempDir {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("eql-parity-{tag}-{nanos}"));
    fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

/// The committed scalar token dirs under `src/v3/scalars/` (every entry that is
/// a directory; the depth-1 hand-written `functions.sql` is a file and skipped).
fn committed_scalar_tokens(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root.join("src/v3/scalars"))
        .expect("src/v3/scalars dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_str().unwrap().to_string())
        .collect()
}

#[test]
fn committed_scalar_dirs_match_catalog_tokens() {
    let root = repo_root();
    let dirs = committed_scalar_tokens(&root);
    // `families_with_scalar_domains()`, not `scalar_families()`: the mixed `json`
    // family is non-scalar (it carries SteVec domains) but its bare scalar storage
    // domain IS generated into `src/v3/scalars/json/`, so its token must appear.
    let catalog: BTreeSet<String> = eql_domains::families_with_scalar_domains()
        .map(|s| s.name.to_string())
        .collect();
    assert_eq!(
        dirs, catalog,
        "committed src/v3/scalars/<token>/ dirs must equal the scalar-bearing catalog token \
         set: a new catalog type needs its regenerated SQL committed (run `mise run build` and \
         commit src/v3/scalars), and a stale dir with no catalog row must be removed"
    );
}

/// Every generated `.sql` under a committed token dir must start with the
/// owner-marker. The writer only ever overwrites/prunes marker-bearing files,
/// so a generated file missing its marker would silently escape regeneration and
/// orphan-pruning. Hand-written `*_extensions.sql` (and the depth-1
/// `functions.sql`, which is not under a token dir) carry no marker and are
/// deliberately excluded.
#[test]
fn every_generated_sql_file_starts_with_marker() {
    let root = repo_root();
    let mut checked = 0;
    for token in committed_scalar_tokens(&root) {
        let dir = root.join("src/v3/scalars").join(&token);
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if path.extension().and_then(|e| e.to_str()) != Some("sql")
                || name.ends_with("_extensions.sql")
            {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let first = text.lines().next().unwrap_or_default();
            assert_eq!(
                first,
                AUTO_GENERATED_MARKER,
                "{}: generated SQL must start with the owner-marker so the writer \
                 recognises it for overwrite/prune (found {first:?})",
                path.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 11,
        "expected >=11 generated SQL files across all tokens, checked {checked}"
    );
}

/// Every `.sql` file in the real `src/v3` tree is in the install order — the
/// completeness invariant, checked against an independent walk rather than a
/// hardcoded count.
///
/// This is the gate that a two-block build could not express. When the surface
/// was ordered as "hand-written files (globbed, minus the AUTO-GENERATED marker)"
/// plus "generated files (from a codegen manifest of `render_type` output)", a
/// cross-family generated file — marker-bearing, but rendered outside
/// `render_type` — matched neither predicate and would be silently dropped from
/// the installer. Set equality, not a count: a new cross-family generated file is
/// required here the moment it lands on disk.
///
/// Runs against the real tree, not a tempdir: `surface_order` validates that
/// every `-- REQUIRE:` target is a node, and a generate-only tempdir has no
/// `schema.sql` or `sem/**` for the generated files to point at.
#[test]
fn install_order_contains_every_v3_sql_file() {
    let root = repo_root();

    // Independent of walk_v3_surface: if the walker under-collects, this diverges.
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![root.join("src/v3")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".sql") && !name.ends_with("_test.sql") {
                on_disk.insert(
                    path.strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }

    let files = eql_codegen::ordering::walk_v3_surface(&root).expect("walk src/v3");
    let order = eql_codegen::ordering::surface_order(&files).expect(
        "src/v3 surface must linearize: every REQUIRE target a node under src/v3, no cycles",
    );

    // Check for duplicates BEFORE collapsing into a set, which would absorb them.
    // `tasks/build.sh` concatenates the order line by line with no `uniq`, so a
    // repeated path emits that file's DDL twice into the installer. Kahn's
    // algorithm cannot produce one today; this pins that it stays that way.
    let ordered: BTreeSet<String> = order.iter().cloned().collect();
    assert_eq!(
        order.len(),
        ordered.len(),
        "the install order contains a duplicate path — build.sh would emit its DDL twice"
    );

    assert_eq!(
        ordered, on_disk,
        "the install order must contain exactly the src/v3 SQL files on disk — a file \
         present on disk but absent from the order is silently missing from \
         release/cipherstash-encrypt.sql"
    );
    assert!(
        on_disk.contains("src/v3/schema.sql"),
        "sanity: the walk found no schema.sql, so it is not seeing the real tree"
    );
}

#[test]
fn generate_all_skips_non_scalar_families() {
    let tmp = tempdir("skip-non-scalar");
    eql_codegen::generate::generate_all(tmp.path()).unwrap();
    assert!(
        !tmp.path().join("src/v3/scalars/jsonb").exists(),
        "SteVec family must not emit a src/v3/scalars/jsonb SQL dir"
    );
}

/// Run the generator twice into separate temp dirs and assert every emitted file
/// is byte-identical between the runs. Guards the documented determinism promise
/// (identical `CATALOG` => byte-identical SQL) against a future `HashMap`/`HashSet`
/// iteration leaking into a renderer.
#[test]
fn generate_all_is_deterministic_across_runs() {
    let a = tempdir("determinism-a");
    let b = tempdir("determinism-b");
    eql_codegen::generate::generate_all(a.path()).expect("generate_all a");
    eql_codegen::generate::generate_all(b.path()).expect("generate_all b");

    let collect = |root: &Path| -> Vec<(String, String)> {
        let base = root.join("src/v3/scalars");
        let mut files: Vec<(String, String)> = Vec::new();
        let mut stack = vec![base.clone()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|x| x.to_str()) == Some("sql") {
                    let rel = path
                        .strip_prefix(&base)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string();
                    files.push((rel, fs::read_to_string(&path).unwrap()));
                }
            }
        }
        files.sort();
        files
    };

    let fa = collect(a.path());
    let fb = collect(b.path());
    assert_eq!(
        fa.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        fb.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        "two generator runs emitted different file sets"
    );
    for ((na, ca), (_nb, cb)) in fa.iter().zip(fb.iter()) {
        assert_eq!(ca, cb, "{na}: two generator runs produced different bytes");
    }
}
