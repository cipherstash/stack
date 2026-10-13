//! Scalar encrypted-domain SQL generator. Renders the `eql-domains` catalog to
//! the committed SQL surface under `src/v3/scalars/<token>/`, drift-gated
//! byte-for-byte by `mise run codegen:parity` (regenerate in place +
//! `git diff --exit-code`, mirroring `types:check` for the Rust bindings). The
//! plaintext fixture lists the SQLx matrix consumes live in the catalog itself
//! (`eql_domains::INT4_VALUES` / `INT2_VALUES`), not in a generated file.

use std::path::PathBuf;

pub mod bindings;
pub mod consts;
pub mod context;
pub mod dump;
pub mod generate;
pub mod go_eql;
pub mod operator_surface;
pub mod ordering;
pub mod render;
pub mod targets;
pub mod writer;

/// The repository root, derived from this crate's manifest dir (the generator
/// writes the real `src/v3/scalars/` tree relative to it). `CARGO_MANIFEST_DIR`
/// is `crates/eql-codegen`, so the repo root is two parents up. Shared by the
/// binary, the in-crate tests, and the `tests/parity.rs` gate.
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// The schemas the SQL surface owns, public first: `[SCHEMA, INTERNAL_SCHEMA]`.
///
/// These are placeholder source (`{{prefix}}`, `{{prefix}}_internal`), like the
/// SQL they are compared with; render them with [`render::render_str`] for one
/// EQL version's real names, as `list-schemas` does.
///
/// Public accessor over the crate-private `consts::SCHEMA` / `INTERNAL_SCHEMA`
/// so the binary (`list-schemas`) and the `test:schemas:parity` gate can read
/// the Rust side of the schema split without exposing the consts. This is the
/// Rust counterpart of the SQL `eql_v3_internal.owned_schemas()` function in
/// `src/v3/schema.sql`; the parity gate compares the two so they cannot drift.
pub fn owned_schemas() -> [&'static str; 2] {
    [consts::SCHEMA, consts::INTERNAL_SCHEMA]
}
