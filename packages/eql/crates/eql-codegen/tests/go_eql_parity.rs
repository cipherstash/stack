//! The Go `encrypt/eql` parity gate, the twin of `bindings_parity.rs`: the
//! committed `languages/golang/encrypt/eql/eql_gen.go` must be byte for byte
//! what the catalog renders. Without this, a catalog change would leave the
//! Go types behind until `mise run types:check` in CI, and a hand edit would
//! survive `cargo test`.

use std::fs;

use eql_codegen::go_eql::{render_go_eql, GO_EQL_PATH};
use eql_codegen::repo_root;

#[test]
fn go_eql_matches_the_committed_file() {
    let path = repo_root().join(GO_EQL_PATH);
    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "committed Go package {} is missing or unreadable ({e}); run `mise run types:generate` and commit",
            path.display()
        )
    });
    assert_eq!(
        render_go_eql(),
        committed,
        "{}: the committed Go package is stale or hand-edited — run `mise run types:generate` and commit the result",
        path.display()
    );
}
