//! THE RUST-BINDINGS PARITY GATE. Mirrors `tests/parity.rs` for the committed
//! Rust payload bindings: runs `eql_codegen::bindings::generate_bindings` into a
//! temp dir and asserts every emitted file is byte-for-byte equal to the
//! committed `crates/eql-bindings/src/v3/<same>` tree, and that two runs produce
//! identical bytes. Without this, committed-source freshness rested only on the
//! CI-only `types:check` regen-diff, so a dev running `cargo test` alone would
//! miss a stale or hand-edited `bigint.rs`/`inventory.rs`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use eql_codegen::repo_root;
use eql_codegen::writer::{is_generated, GeneratedKind};

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
    p.push(format!("eql-bindings-parity-{tag}-{nanos}"));
    fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

/// Relative path (from repo root / generator out-root) of the v3 bindings dir.
const V3_BINDINGS_DIR: &str = "crates/eql-bindings/src/v3";

/// Generate the bindings into `out`, then assert each written file is
/// byte-for-byte identical to the committed copy under `repo_root()`.
#[test]
fn rust_bindings_match_committed_files() {
    let root = repo_root();
    let out = tempdir("committed");
    let written = eql_codegen::bindings::generate_bindings(out.path()).expect("generate bindings");

    for path in &written {
        let rel = path
            .strip_prefix(out.path())
            .expect("written path is under out-root");
        let generated = fs::read_to_string(path).unwrap();
        let committed_path = root.join(rel);
        let committed = fs::read_to_string(&committed_path).unwrap_or_else(|e| {
            panic!(
                "committed binding {} is missing or unreadable ({e}); run \
                 `mise run types:generate` and commit",
                committed_path.display()
            )
        });
        assert_eq!(
            generated,
            committed,
            "{}: committed Rust binding is stale or hand-edited — run \
             `mise run types:generate` and commit the result",
            rel.display()
        );
    }
}

/// The committed marker-bearing (`// @generated`) `.rs` file SET under
/// `crates/eql-bindings/src/v3` must equal the set the generator emits. The
/// per-file parity test above only iterates the freshly-generated `written`
/// set, so an ORPHANED committed generated file — a `<family>.rs` left behind
/// after a catalog family rename/removal — is never visited and passes `cargo
/// test`, caught only by the CI-only `types:check` regen-diff. This mirrors the
/// SQL parity script's file-set equality check (`tasks/codegen-parity.sh`).
///
/// Only `// @generated` files participate: hand-written `mod.rs` /
/// `domain_type.rs` / `terms.rs` carry no marker (`is_generated` is false), so
/// they are correctly excluded — the filter keys on the marker, not the `.rs`
/// extension.
#[test]
fn committed_binding_set_has_no_orphans() {
    let root = repo_root();
    let out = tempdir("orphan-check");
    let written = eql_codegen::bindings::generate_bindings(out.path()).expect("generate bindings");

    let generated: BTreeSet<String> = written
        .iter()
        .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
        .collect();

    let dir = root.join(V3_BINDINGS_DIR);
    let committed: BTreeSet<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
        .filter(|p| is_generated(p, GeneratedKind::Rust).expect("read committed binding"))
        .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
        .collect();

    assert_eq!(
        committed, generated,
        "committed `// @generated` binding set differs from the generated set \
         (< committed, > generated): an orphaned committed binding (left after a \
         catalog family rename/removal) or a missing one — run \
         `mise run types:generate` and commit the result"
    );
}

/// Run the generator twice into separate temp dirs and assert every emitted file
/// is byte-identical between the runs. Guards the determinism promise (identical
/// `CATALOG` => byte-identical bindings) against a future `HashMap`/`HashSet`
/// iteration order leaking into a renderer.
#[test]
fn generate_bindings_is_deterministic_across_runs() {
    let a = tempdir("determinism-a");
    let b = tempdir("determinism-b");
    eql_codegen::bindings::generate_bindings(a.path()).expect("generate bindings a");
    eql_codegen::bindings::generate_bindings(b.path()).expect("generate bindings b");

    let collect = |root: &Path| -> Vec<(String, String)> {
        let base = root.join(V3_BINDINGS_DIR);
        let mut files: Vec<(String, String)> = fs::read_dir(&base)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
            .map(|p| {
                let name = p.file_name().unwrap().to_str().unwrap().to_string();
                (name, fs::read_to_string(&p).unwrap())
            })
            .collect();
        files.sort();
        files
    };

    let fa = collect(a.path());
    let fb = collect(b.path());
    assert_eq!(
        fa.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        fb.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        "two generator runs emitted different binding file sets"
    );
    for ((na, ca), (_nb, cb)) in fa.iter().zip(fb.iter()) {
        assert_eq!(ca, cb, "{na}: two generator runs produced different bytes");
    }
}
