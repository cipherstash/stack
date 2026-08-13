//! Smoke test for the `eql-codegen` binary's subcommand dispatch (`main.rs`).
//! No `assert_cmd` in this repo, so we drive the compiled binary directly via
//! the `CARGO_BIN_EXE_eql-codegen` path Cargo injects for integration tests.

use std::path::PathBuf;
use std::process::Command;

/// Path to the compiled `eql-codegen` binary, injected by Cargo.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_eql-codegen")
}

/// A throwaway directory under the system temp root, removed on drop. Lets the
/// smoke test redirect `bindings` output via `EQL_CODEGEN_OUT_ROOT` instead of
/// writing into the committed source tree.
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tempdir() -> TempDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!("eql-codegen-cli-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

/// `bindings` exits 0 and reports the written-file count. Run against a throwaway
/// `EQL_CODEGEN_OUT_ROOT` tree so the smoke test proves the subcommand honours
/// the output-root override (test isolation) and never touches the committed
/// `crates/eql-bindings/src/v3/*.rs`. The count is one file per scalar family
/// plus the jsonb family's generated `jsonb_storage.rs`, `payload.rs`,
/// `query_payload.rs`, and `inventory.rs`.
#[test]
fn bindings_subcommand_succeeds_and_reports_count() {
    let out_root = tempdir();
    let out = Command::new(bin())
        .arg("bindings")
        .env("EQL_CODEGEN_OUT_ROOT", out_root.0.as_os_str())
        .output()
        .expect("run eql-codegen bindings");
    assert!(
        out.status.success(),
        "bindings should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = eql_domains::scalar_families().count() + 4;
    assert!(
        stdout.contains(&format!("bindings: ok ({expected} files)")),
        "expected 'bindings: ok ({expected} files)' in stdout, got:\n{stdout}"
    );
    // The override must have routed output into the temp tree, leaving the
    // committed bindings tree untouched.
    let generated = out_root.0.join("crates/eql-bindings/src/v3/inventory.rs");
    assert!(
        generated.is_file(),
        "expected generated inventory.rs under the override root at {}",
        generated.display()
    );
}

/// `list-schemas` exits 0 and prints the owned schemas, public first, one per
/// line. This is the Rust side of the schema-split parity gate
/// (`mise run test:schemas:parity`), so the exact stdout is pinned here.
#[test]
fn list_schemas_subcommand_prints_owned_schemas() {
    let out = Command::new(bin())
        .arg("list-schemas")
        .output()
        .expect("run eql-codegen list-schemas");
    assert!(
        out.status.success(),
        "list-schemas should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "eql_v3\neql_v3_internal\n",
        "list-schemas must print the public schema first, then the internal schema"
    );
}

/// `order` exits 0 and prints the real surface's install order, one repo-relative
/// path per line, dependency first. `tasks/build.sh` redirects this straight into
/// `src/deps-ordered-v3.txt` and concatenates the files in this order, so the
/// stdout contract is pinned here: nothing but paths (no banner, no progress).
#[test]
fn order_subcommand_prints_the_install_order() {
    let out = Command::new(bin())
        .arg("order")
        .output()
        .expect("run eql-codegen order");
    assert!(
        out.status.success(),
        "order should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.first(),
        Some(&"src/v3/schema.sql"),
        "schema.sql creates the schemas everything else requires, so it must come first"
    );
    assert!(
        lines
            .iter()
            .all(|l| l.starts_with("src/v3/") && l.ends_with(".sql")),
        "stdout must be paths only — build.sh feeds it to `strip_require_lines` unfiltered"
    );
}

/// A `-- REQUIRE:` naming a file that does not exist fails the build loudly
/// instead of emitting a short order. The two-block scheme this replaced could
/// omit a file and still exit 0 — a green build with the file missing from
/// `release/cipherstash-encrypt.sql`.
#[test]
fn order_subcommand_fails_on_a_dangling_require() {
    let root = tempdir();
    let v3 = root.0.join("src/v3");
    std::fs::create_dir_all(&v3).unwrap();
    std::fs::write(v3.join("schema.sql"), "CREATE SCHEMA eql_v3;\n").unwrap();
    std::fs::write(
        v3.join("broken.sql"),
        "-- REQUIRE: src/v3/typo.sql\nSELECT 1;\n",
    )
    .unwrap();

    let out = Command::new(bin())
        .arg("order")
        .env("EQL_CODEGEN_OUT_ROOT", root.0.as_os_str())
        .output()
        .expect("run eql-codegen order");
    assert!(
        !out.status.success(),
        "a dangling REQUIRE must fail the build, not emit a partial order"
    );
    assert!(
        out.stdout.is_empty(),
        "a failed order must print no partial order to stdout"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("src/v3/typo.sql") && stderr.contains("src/v3/broken.sql"),
        "the error must name both the dangling target and the file requiring it, got:\n{stderr}"
    );
}

/// An unrecognised argument prints usage and exits 2 (the `ExitCode::from(2)`
/// fall-through in `main.rs`).
#[test]
fn unknown_arg_exits_two() {
    let out = Command::new(bin())
        .arg("frobnicate")
        .output()
        .expect("run eql-codegen frobnicate");
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown arg must exit 2; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
