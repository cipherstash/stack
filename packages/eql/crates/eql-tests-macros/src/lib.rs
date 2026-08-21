//! Proc-macros that expand one declarative scalar-type list into the per-type
//! SQLx-matrix wiring that used to be hand-maintained across four locations.
//!
//! The list lives once in the `scalar_types!` `macro_rules!` in
//! `tests/sqlx/src/scalar_types.rs`:
//!
//! ```ignore
//! eql_tests::scalar_types! {
//!     integer => i32,
//!     smallint => i16,
//! }
//! ```
//!
//! The harness pieces live in three separate compilation contexts — the
//! `eql-tests` lib, the `encrypted_domain` integration-test binary, and the
//! `generate_all_fixtures` integration-test binary — so no single invocation
//! can emit them all. `scalar_types!` forwards the same list to whichever
//! proc-macro below fits the call site; each parses the list and emits only the
//! items belonging there. The list is the single source of truth; the four
//! emitters are pure functions of it.
//!
//! Each entry is `token => rust_type`: `token` is the Postgres type token
//! (`integer`, also the fixture/domain suffix), `rust_type` is the Rust plaintext
//! type (`i32`). The catalog value const is the upper-cased token plus
//! `_VALUES` (`integer` -> `eql_domains::INTEGER_VALUES`).
//!
//! Each emitter is split into a thin `#[proc_macro]` shim and a pure `*_tokens`
//! core so the core is unit-testable without a consumer crate.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Ident, Token, Type};

/// One `token => rust_type` entry. The type's *shape* (temporal vs integer,
/// equality-only vs ordered) is **not** declared here — it is read from the
/// `eql-domains::CATALOG` row for `token` via [`is_temporal_token`] /
/// [`is_eq_only_token`]. The catalog is the single source of truth; this list
/// only maps a token to the Rust plaintext type the harness compiles against.
struct ScalarEntry {
    /// Postgres type token (`integer`); also the fixture/domain suffix and the
    /// matrix `suite` ident. Must name a row in `eql-domains::CATALOG`.
    token: Ident,
    /// Rust plaintext type (`i32`).
    rust_type: Type,
}

impl Parse for ScalarEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let token: Ident = input.parse()?;
        input.parse::<Token![=>]>()?;
        let rust_type: Type = input.parse()?;
        Ok(ScalarEntry { token, rust_type })
    }
}

/// The `eql-domains::CATALOG` row for `token`, or a hard panic at macro-expansion
/// time if the token is unknown — a dispatch-list entry must name a catalog type.
/// Now used only by the structural predicates (`is_eq_only_token`,
/// `is_storage_only_token`, `has_search_token`); the kind-predicates read the
/// native scalar kind from `fixtures_for_token` (it is no longer a `DomainFamily`
/// field).
fn spec_for_token(token: &str) -> &'static eql_domains::DomainFamily {
    eql_domains::CATALOG
        .iter()
        .find(|s| s.name == token)
        .unwrap_or_else(|| panic!("scalar token `{token}` not in eql-domains::CATALOG"))
}

/// The `eql-domains::FIXTURES` record for `token`, or a hard panic at
/// macro-expansion time if the token is unknown. The kind-predicates read the
/// native scalar kind from the fixture layer (it is no longer a `DomainFamily`
/// field); the structural predicates (`is_eq_only`, `is_storage_only`,
/// `has_search`) keep reading `spec_for_token`.
fn fixtures_for_token(token: &str) -> &'static eql_domains::TypeFixtures {
    eql_domains::FIXTURES
        .iter()
        .find(|f| f.family.name == token)
        .unwrap_or_else(|| panic!("scalar token `{token}` not in eql-domains::FIXTURES"))
}

/// True when `token`'s catalog kind is temporal (chrono-backed). Replaces the
/// `[temporal]` marker: temporal scalars hand off their `impl ScalarType` to
/// `temporal_values!` (so `emit_scalar_type_impls` skips them) and stamp the
/// `temporal` fixture variant.
fn is_temporal_token(token: &str) -> bool {
    fixtures_for_token(token).kind.is_temporal()
}

/// True when `token`'s catalog kind is a fixed-width integer (`smallint`/`integer`/
/// `bigint`). The integer kinds are the only ones whose `impl ScalarType` is
/// macro-generated (inherent `MIN`/`MAX` pivots + a `const` `<TOKEN>_VALUES`
/// slice) and whose fixture module stamps the `int` discriminator. Every
/// non-integer kind (`date`, `text`) is hand-written in `scalar_domains.rs` and
/// skipped by `scalar_type_impls_tokens`.
fn is_int_token(token: &str) -> bool {
    fixtures_for_token(token).kind.is_int()
}

/// True when `token`'s catalog kind is `text` — an unbounded, owned-`String`
/// scalar. Like a temporal scalar it is hand-written (no `const`-friendly
/// inherent pivots), so `emit_scalar_type_impls` skips it; but it stamps the
/// `text` fixture discriminator (which additionally adds the `Match` index, so
/// generated payloads carry `bf`) and draws its values from the harness accessor
/// (`text_values()`). Replaces the `[text]` marker.
fn is_text_token(token: &str) -> bool {
    fixtures_for_token(token).kind.is_text()
}

/// True when `token`'s catalog row is the `numeric` kind (owned
/// `rust_decimal::Decimal`). Like `text` it is ordered but non-integer and
/// non-chrono, so it stamps the `numeric` fixture discriminator and draws its
/// values from the harness accessor (`numeric_values()`).
fn is_numeric_token(token: &str) -> bool {
    matches!(
        fixtures_for_token(token).kind,
        eql_domains::ScalarKind::Numeric
    )
}

/// True when `token`'s catalog row is an IEEE-754 float kind (`F32`/`F64`).
/// Like `numeric` it is ordered but non-integer and non-chrono, so it stamps the
/// `float` fixture discriminator and draws its values from the harness accessor
/// (`real_values()` / `double_values()`).
fn is_float_token(token: &str) -> bool {
    matches!(
        fixtures_for_token(token).kind,
        eql_domains::ScalarKind::F32 | eql_domains::ScalarKind::F64
    )
}

/// True when `token`'s catalog row declares no ordered domain — equality-only.
/// Replaces the `[eq_only]` marker. Consumed by [`matrix_suite_for_entry`] to
/// keep an eq-only type out of the ordered matrix (which exercises ordering
/// operators it does not support).
fn is_eq_only_token(token: &str) -> bool {
    spec_for_token(token).is_eq_only()
}

/// True when `token`'s catalog row is **storage-only / encryption-only** — a
/// single term-less domain, no `_eq`/`_ord` (currently only `bool`). Consumed by
/// [`matrix_suite_for_entry`] to route the token to the `caps = [storage]` arm
/// (which runs only the storage-domain subset: blockers, payload-check,
/// path-ops, native-absent — no comparison or index arms). Checked **before**
/// [`is_eq_only_token`], which is also true for a storage-only type (it has no
/// `_ord` domain) but would wrongly select the `caps = [eq]` arm. Stamps the
/// `bool` fixture discriminator (storage-only fixtures carry no index term).
fn is_storage_only_token(token: &str) -> bool {
    spec_for_token(token).is_storage_only()
}

/// True when `token`'s catalog row declares a combined `_search` domain
/// (currently only `text`). Consumed by [`matrix_suite_for_entry`] to route the
/// token to the `caps = [eq, ord, search]` arm, which additionally runs the
/// `_search` domain (equality + ordering + bloom match) through the matrix.
fn has_search_token(token: &str) -> bool {
    spec_for_token(token)
        .domains
        .iter()
        .any(|d| d.name == "search")
}

/// The comma-separated list (optional trailing comma).
struct ScalarList {
    entries: Vec<ScalarEntry>,
}

impl Parse for ScalarList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let punctuated = Punctuated::<ScalarEntry, Token![,]>::parse_terminated(input)?;
        Ok(ScalarList {
            entries: punctuated.into_iter().collect(),
        })
    }
}

/// `integer` -> `INTEGER_VALUES`, the catalog value const in `eql_domains`.
fn values_const_ident(token: &Ident) -> Ident {
    format_ident!("{}_VALUES", token.to_string().to_uppercase())
}

// ---------------------------------------------------------------------------
// Core token generators (pure, unit-testable).
// ---------------------------------------------------------------------------

/// Emit one `impl ScalarType for <rust_type>` per entry. See
/// [`emit_scalar_type_impls`].
fn scalar_type_impls_tokens(list: &ScalarList) -> TokenStream2 {
    // Only integer scalars get a macro-generated impl (inherent `MIN`/`MAX`
    // pivots + a `const` `<TOKEN>_VALUES` slice). Every non-integer kind is
    // hand-written in `scalar_domains.rs`: temporal scalars (`date`) hand off to
    // `temporal_values!`, and `text` is an owned `String` with explicit pivots —
    // both would fail to typecheck through the integer materialiser.
    let impls = list
        .entries
        .iter()
        .filter(|e| is_int_token(&e.token.to_string()))
        .map(|e| {
            let token_str = e.token.to_string();
            let rust_type = &e.rust_type;
            let values = values_const_ident(&e.token);
            quote! {
                impl ScalarType for #rust_type {
                    const PG_TYPE: &'static str = #token_str;

                    /// The catalog `eql_domains::*_VALUES` list — the same values
                    /// the fixture generator encrypts, so the oracle can't drift
                    /// from the fixture.
                    fn fixture_values() -> &'static [#rust_type] {
                        ::eql_domains::#values
                    }

                    /// Integers draw the full `any::<Self>()` range — the e2e
                    /// suite's value over the fixture suite is fresh, arbitrary
                    /// plaintexts, not a re-encryption of the fixed fixture set.
                    fn arbitrary_value() -> ::proptest::strategy::BoxedStrategy<#rust_type> {
                        use ::proptest::strategy::Strategy;
                        ::proptest::prelude::any::<#rust_type>().boxed()
                    }
                }

                impl OrderedScalar for #rust_type {
                    // Boundary pivots derive from `fixture_values()` (the integer
                    // fixture lists include `Min`/`Max` = the inherent bounds);
                    // `mid_pivot` inherits `Self::default()` = `0`. Nothing to
                    // override.
                }

                impl SignedScalar for #rust_type {
                    /// Integers are signed about `0`; the fixtures straddle it
                    /// (negatives below, positives above).
                    fn origin() -> #rust_type {
                        0
                    }
                }
            }
        });
    quote! { #(#impls)* }
}

/// Emit one `pub mod eql_v3_<token> { ... }` per entry. See
/// [`emit_scalar_fixture_modules`].
fn scalar_fixture_modules_tokens(list: &ScalarList) -> TokenStream2 {
    let mods = list.entries.iter().map(|e| {
        let token_str = e.token.to_string();
        let rust_type = &e.rust_type;
        let mod_ident = format_ident!("eql_v3_{}", e.token);
        let fixture_name = format!("eql_v3_{}", token_str);
        if is_int_token(&token_str) {
            let values = values_const_ident(&e.token);
            quote! {
                #[doc = concat!("`eql_v3_", #token_str, "` scalar fixture — generated by `scalar_types!`.")]
                pub mod #mod_ident {
                    use ::eql_domains::#values as VALUES;
                    // `scalar_fixture!` is `#[macro_export]`ed by `eql-tests`;
                    // these modules expand into that lib, so `crate::` resolves it.
                    crate::scalar_fixture!(int, #fixture_name, #rust_type, VALUES);
                }
            }
        } else {
            // Hand-written non-integer scalars (`date`, `text`) have no
            // `eql_domains::<TOKEN>_VALUES` const usable by the integer
            // materialiser (chrono is not `const`-friendly; text is owned
            // `String`). The values come from the harness accessor
            // (`<token>_values()`), and the fixture stamps the kind-specific
            // discriminator so the integer-only signed-extreme asserts are
            // replaced by a pivot-presence assert. The `text` discriminator
            // additionally adds the `Match` index, so generated payloads carry
            // `bf`. The accessor name mirrors the token (`date` -> `date_values`,
            // `text` -> `text_values`).
            let values_fn = format_ident!("{}_values", e.token);
            let discriminator = if is_temporal_token(&token_str) {
                format_ident!("temporal")
            } else if is_text_token(&token_str) {
                format_ident!("text")
            } else if is_numeric_token(&token_str) {
                format_ident!("numeric")
            } else if is_float_token(&token_str) {
                format_ident!("float")
            } else if is_storage_only_token(&token_str) {
                // Storage-only (encryption-only) scalars (`bool`): the fixture
                // carries no index term (no `hm`/`ob`/`bf`), just the encrypted
                // value, and asserts the storage-domain shape only.
                format_ident!("storage")
            } else {
                panic!(
                    "scalar token `{token_str}` is neither integer, temporal, text, \
                     numeric, float, nor storage-only — no fixture discriminator is wired for its kind"
                )
            };
            quote! {
                #[doc = concat!("`eql_v3_", #token_str, "` hand-written scalar fixture — generated by `scalar_types!`.")]
                pub mod #mod_ident {
                    use crate::scalar_domains::#values_fn as values;
                    crate::scalar_fixture!(#discriminator, #fixture_name, #rust_type, values());
                }
            }
        }
    });
    quote! { #(#mods)* }
}

/// Emit the `generate_for_token` dispatch fn. See [`emit_fixture_dispatch`].
fn fixture_dispatch_tokens(list: &ScalarList) -> TokenStream2 {
    let arms = list.entries.iter().map(|e| {
        let token_str = e.token.to_string();
        let mod_ident = format_ident!("eql_v3_{}", e.token);
        // Every scalar fixture is generated from its fixed curated catalog
        // values via `run()`.
        quote! {
            #token_str => ::eql_tests::fixtures::#mod_ident::spec().run().await,
        }
    });
    quote! {
        /// Map a catalog token to its fixture generator and run it. A token in
        /// the catalog but absent from the harness list hits the catch-all and
        /// fails loudly, so a new scalar type can't silently skip generation.
        async fn generate_for_token(token: &str) -> anyhow::Result<()> {
            match token {
                #(#arms)*
                other => anyhow::bail!(
                    "no fixture generator wired for catalog token '{other}'. \
                     Add it to the scalar_types! list (tests/sqlx/src/scalar_types.rs). \
                     See the encrypted-domain spec §3."
                ),
            }
        }
    }
}

/// Build the matrix suite for one entry. Both shapes route through the unified
/// `scalar_matrix!` wrapper, selected by a `caps` capability marker derived from
/// the catalog (`eq_only` = [`is_eq_only_token`]): an ordered type emits
/// `caps = [eq, ord]` (`=`/`<>`/`<`/`>`/`min`/`max`); an equality-only type (no
/// `_ord` domain) emits `caps = [eq]`, whose empty `ord_domains` make the
/// ordering arms emit zero tests rather than exercising operators the type does
/// not support. `eq_only` is passed in so this stays a pure function of its
/// inputs and both arms are unit-testable without an eq-only row in the live
/// catalog.
fn matrix_suite_for_entry(
    token: &Ident,
    rust_type: &Type,
    storage_only: bool,
    eq_only: bool,
    has_search: bool,
) -> TokenStream2 {
    let token_str = token.to_string();
    let eql_type = format!("eql_v3_{}", token_str);
    // `storage_only` is checked FIRST: a storage-only type is also `eq_only`
    // (no `_ord` domain), so the eq-only arm would otherwise wrongly select
    // `caps = [eq]` and emit equality tests against a domain that has no `_eq`.
    let caps = if storage_only {
        quote! { caps = [storage] }
    } else if eq_only {
        quote! { caps = [eq] }
    } else if has_search {
        // A token declaring a combined `_search` domain (text) additionally runs
        // that domain through the matrix (equality + ordering + bloom match).
        quote! { caps = [eq, ord, search] }
    } else {
        quote! { caps = [eq, ord] }
    };
    quote! {
        #[doc = concat!("`eql_v3_", #token_str, "` matrix suite — generated by `scalar_types!`.")]
        pub mod #token {
            ::eql_tests::scalar_matrix! {
                suite = #token,
                scalar = #rust_type,
                eql_type = #eql_type,
                #caps
            }
        }
    }
}

/// Emit one `pub mod <token> { scalar_matrix! { ... } }` per entry.
/// See [`emit_scalar_matrix_suites`] and [`matrix_suite_for_entry`].
fn scalar_matrix_suites_tokens(list: &ScalarList) -> TokenStream2 {
    let mods = list.entries.iter().map(|e| {
        matrix_suite_for_entry(
            &e.token,
            &e.rust_type,
            is_storage_only_token(&e.token.to_string()),
            is_eq_only_token(&e.token.to_string()),
            has_search_token(&e.token.to_string()),
        )
    });
    quote! { #(#mods)* }
}

// ---------------------------------------------------------------------------
// Proc-macro shims.
// ---------------------------------------------------------------------------

/// Emit one `impl ScalarType for <rust_type>` per entry.
///
/// Invoked via `scalar_types!` in `tests/sqlx/src/scalar_domains.rs`, so the
/// impls land in the `eql-tests` lib next to the trait. `PG_TYPE` is the token
/// string; `FIXTURE_VALUES` is the catalog const `eql_domains::<TOKEN>_VALUES`.
#[proc_macro]
pub fn emit_scalar_type_impls(input: TokenStream) -> TokenStream {
    let list = syn::parse_macro_input!(input as ScalarList);
    scalar_type_impls_tokens(&list).into()
}

/// Emit one `pub mod eql_v3_<token> { ... }` per entry.
///
/// Invoked via `scalar_types!` in `tests/sqlx/src/fixtures/mod.rs`, so the
/// modules land at `crate::fixtures::eql_v3_<token>` — the path the matrix and
/// fixture dispatch reference. Each body is a `use` of the catalog value const
/// plus a `scalar_fixture!` invocation.
#[proc_macro]
pub fn emit_scalar_fixture_modules(input: TokenStream) -> TokenStream {
    let list = syn::parse_macro_input!(input as ScalarList);
    scalar_fixture_modules_tokens(&list).into()
}

/// Emit the `generate_for_token` dispatch fn.
///
/// Invoked via `scalar_types!` in `tests/generate_all_fixtures.rs`. Emits an
/// `async fn generate_for_token(token: &str)` with one match arm per entry plus
/// a loud catch-all, so a catalog token missing from the harness list fails the
/// generator loudly. (The matrix-inventory cross-check enforces the same at
/// test time.)
#[proc_macro]
pub fn emit_fixture_dispatch(input: TokenStream) -> TokenStream {
    let list = syn::parse_macro_input!(input as ScalarList);
    fixture_dispatch_tokens(&list).into()
}

/// Emit one `pub mod <token> { scalar_matrix! { ... } }` per entry.
///
/// Invoked via `scalar_types!` in
/// `tests/sqlx/tests/encrypted_domain/scalars/mod.rs`, so the matrix suites land
/// in the `encrypted_domain` integration-test binary where `#[sqlx::test]`
/// suites belong. Separate from the lib-side macros because that binary is a
/// different crate target. The emitted test names (`scalars::<token>::matrix_*`)
/// match the old per-type files, so the `matrix_tests.txt` snapshot still holds.
#[proc_macro]
pub fn emit_scalar_matrix_suites(input: TokenStream) -> TokenStream {
    let list = syn::parse_macro_input!(input as ScalarList);
    scalar_matrix_suites_tokens(&list).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScalarList {
        syn::parse_str::<ScalarList>("integer => i32, bigint => i64,").unwrap()
    }

    /// Normalize to the `to_string()` form so whitespace differences don't make
    /// assertions brittle.
    fn norm(ts: &TokenStream2) -> String {
        ts.to_string()
    }

    #[test]
    fn values_const_name_is_uppercased_with_suffix() {
        let token: Ident = syn::parse_str("bigint").unwrap();
        assert_eq!(values_const_ident(&token).to_string(), "BIGINT_VALUES");
    }

    #[test]
    fn scalar_type_impls_emit_pg_type_and_fixture_values() {
        let out = norm(&scalar_type_impls_tokens(&sample()));
        // One impl per entry, with the right PG_TYPE string and catalog const.
        assert!(out.contains("impl ScalarType for i32"));
        assert!(out.contains("impl ScalarType for i64"));
        assert!(out.contains(r#"const PG_TYPE : & 'static str = "integer""#));
        assert!(out.contains(r#"const PG_TYPE : & 'static str = "bigint""#));
        assert!(out.contains(":: eql_domains :: INTEGER_VALUES"));
        assert!(out.contains(":: eql_domains :: BIGINT_VALUES"));
        // const→fn: fixture values is a method now.
        assert!(out.contains("fn fixture_values"));
        // Pivots are now derived trait defaults — the emitter writes an empty
        // `impl OrderedScalar` and no longer spells out the boundary bodies.
        assert!(out.contains("impl OrderedScalar for i32 { }"));
        assert!(out.contains("impl OrderedScalar for i64 { }"));
        assert!(!out.contains("fn min_pivot"));
        assert!(!out.contains("fn max_pivot"));
        // `SignedScalar::origin` is still emitted.
        assert!(out.contains("fn origin () -> i32 { 0 }"));
    }

    #[test]
    fn fixture_modules_emit_named_mods_with_scalar_fixture() {
        let out = norm(&scalar_fixture_modules_tokens(&sample()));
        assert!(out.contains("pub mod eql_v3_integer"));
        assert!(out.contains("pub mod eql_v3_bigint"));
        assert!(out.contains("crate :: scalar_fixture !"));
        assert!(out.contains(r#""eql_v3_integer""#));
        assert!(out.contains(":: eql_domains :: INTEGER_VALUES as VALUES"));
        // Integer entries stamp the `int` kind discriminator.
        assert!(out.contains("int ,"));
    }

    #[test]
    fn temporal_entry_skips_impl_and_stamps_temporal_fixture() {
        // No marker: `date`'s temporal shape is read from eql-domains::CATALOG.
        let list =
            syn::parse_str::<ScalarList>("integer => i32, date => chrono::NaiveDate").unwrap();
        // Impl emitter skips the temporal entry (handed to `temporal_values!`).
        let impls = norm(&scalar_type_impls_tokens(&list));
        assert!(impls.contains("impl ScalarType for i32"));
        assert!(!impls.contains("NaiveDate"));
        // Fixture-module emitter stamps the temporal kind + harness accessor.
        let mods = norm(&scalar_fixture_modules_tokens(&list));
        assert!(mods.contains("pub mod eql_v3_date"));
        assert!(mods.contains("temporal ,"));
        assert!(mods.contains("date_values"));
        // Matrix + dispatch emitters include the temporal entry like any other.
        let suites = norm(&scalar_matrix_suites_tokens(&list));
        assert!(suites.contains("pub mod date"));
        assert!(suites.contains("scalar = chrono :: NaiveDate"));
        let dispatch = norm(&fixture_dispatch_tokens(&list));
        assert!(dispatch.contains(r#""date" =>"#));
    }

    #[test]
    fn entry_parses_without_markers() {
        let list = syn::parse_str::<ScalarList>("integer => i32, date => chrono::NaiveDate")
            .expect("bare token => rust_type must parse");
        assert_eq!(list.entries.len(), 2);
    }

    #[test]
    fn temporal_is_read_from_catalog_not_a_marker() {
        assert!(!is_temporal_token("integer"));
        assert!(is_temporal_token("date"));
    }

    #[test]
    fn eq_only_is_read_from_catalog_not_a_marker() {
        assert!(!is_eq_only_token("integer"));
        assert!(!is_eq_only_token("date"));
    }

    #[test]
    fn kind_classification_is_read_from_catalog_not_a_marker() {
        // Integer vs temporal vs text is read from the catalog kind, never from
        // a `[marker]` on the dispatch entry.
        assert!(is_int_token("integer"));
        assert!(!is_int_token("date"));
        assert!(!is_int_token("text"));
        assert!(is_text_token("text"));
        assert!(!is_text_token("integer"));
        assert!(!is_text_token("date"));
    }

    #[test]
    fn has_search_is_read_from_catalog() {
        // The `_search` capability is read from the catalog row's declared
        // domains, never from a `[marker]` on the dispatch entry. Only `text`
        // declares a combined `_search` domain today; ordered/eq-only scalars
        // do not, so they must route to the non-search arm.
        assert!(has_search_token("text"));
        assert!(!has_search_token("integer"));
        assert!(!has_search_token("date"));
    }

    #[test]
    fn text_entry_skips_impl_and_stamps_text_fixture() {
        // No marker: `text`'s shape is read from eql-domains::CATALOG.
        let list = syn::parse_str::<ScalarList>("integer => i32, text => String").unwrap();
        // Impl emitter skips the text entry (hand-written in scalar_domains.rs).
        let impls = norm(&scalar_type_impls_tokens(&list));
        assert!(impls.contains("impl ScalarType for i32"));
        assert!(
            !impls.contains("impl ScalarType for String"),
            "text must skip the generated impl (hand-written instead)"
        );
        // Fixture-module emitter stamps the text kind + harness accessor. The
        // `text` discriminator drives the Match index (payloads carry `bf`).
        let mods = norm(&scalar_fixture_modules_tokens(&list));
        assert!(mods.contains("pub mod eql_v3_text"));
        assert!(mods.contains("text ,"), "got: {mods}");
        assert!(mods.contains("text_values"), "got: {mods}");
        // Matrix + dispatch emitters include the text entry like any other.
        let suites = norm(&scalar_matrix_suites_tokens(&list));
        assert!(suites.contains("pub mod text"));
        assert!(suites.contains("scalar = String"));
        let dispatch = norm(&fixture_dispatch_tokens(&list));
        assert!(dispatch.contains(r#""text" =>"#));
    }

    #[test]
    fn float_entry_skips_impl_and_stamps_float_fixture() {
        // `real`/`double` are ordered, non-integer, non-chrono: the impl emitter
        // skips them (hand-written in scalar_domains.rs), and the fixture module
        // stamps the `float` discriminator drawing from `real_values()`.
        let list = syn::parse_str::<ScalarList>("integer => i32, real => F4").unwrap();
        let impls = norm(&scalar_type_impls_tokens(&list));
        assert!(impls.contains("impl ScalarType for i32"));
        assert!(
            !impls.contains("impl ScalarType for F4"),
            "float must skip the generated impl (hand-written instead)"
        );
        let mods = norm(&scalar_fixture_modules_tokens(&list));
        assert!(mods.contains("pub mod eql_v3_real"));
        assert!(mods.contains("float ,"), "got: {mods}");
        assert!(mods.contains("real_values"), "got: {mods}");
        let suites = norm(&scalar_matrix_suites_tokens(&list));
        assert!(suites.contains("pub mod real"));
        assert!(suites.contains("caps = [eq , ord]"));
    }

    #[test]
    fn float_classification_is_read_from_catalog() {
        assert!(is_float_token("real"));
        assert!(is_float_token("double"));
        assert!(!is_float_token("integer"));
        assert!(!is_float_token("numeric"));
    }

    #[test]
    fn ordered_entry_emits_scalar_matrix_with_eq_ord_caps() {
        let token: Ident = syn::parse_str("integer").unwrap();
        let rust_type: Type = syn::parse_str("i32").unwrap();
        let out = norm(&matrix_suite_for_entry(
            &token, &rust_type, false, false, false,
        ));
        assert!(out.contains(":: eql_tests :: scalar_matrix !"));
        assert!(out.contains("caps = [eq , ord]"));
        assert!(out.contains("suite = integer"));
    }

    #[test]
    fn eq_only_entry_emits_scalar_matrix_with_eq_caps_only() {
        // No eq-only row exists in the live catalog yet, so pass the shape
        // directly: an eq-only token routes to the `caps = [eq]` arm (empty
        // ord_domains), never the ordered `caps = [eq, ord]` arm.
        let token: Ident = syn::parse_str("timestamp").unwrap();
        let rust_type: Type = syn::parse_str("chrono::DateTime<chrono::Utc>").unwrap();
        let out = norm(&matrix_suite_for_entry(
            &token, &rust_type, false, true, false,
        ));
        assert!(out.contains(":: eql_tests :: scalar_matrix !"));
        assert!(out.contains("caps = [eq]"));
        assert!(!out.contains("caps = [eq , ord]"));
        assert!(!out.contains("compile_error"));
    }

    #[test]
    fn search_entry_emits_scalar_matrix_with_eq_ord_search_caps() {
        // A token declaring a `_search` domain (text) routes to the
        // `caps = [eq, ord, search]` arm, which runs the combined `_search`
        // domain through the matrix in addition to the ordered shape.
        let token: Ident = syn::parse_str("text").unwrap();
        let rust_type: Type = syn::parse_str("String").unwrap();
        let out = norm(&matrix_suite_for_entry(
            &token, &rust_type, false, false, true,
        ));
        assert!(out.contains(":: eql_tests :: scalar_matrix !"));
        assert!(out.contains("caps = [eq , ord , search]"));
        assert!(out.contains("suite = text"));
    }

    #[test]
    fn storage_only_is_read_from_catalog() {
        // The storage-only (encryption-only) shape is read from the catalog row,
        // never a marker. Only `bool` is storage-only today; comparison-capable
        // types are not. Note bool is ALSO eq-only (no `_ord`), so the router
        // must check storage-only first.
        assert!(is_storage_only_token("boolean"));
        assert!(is_eq_only_token("boolean"));
        assert!(!is_storage_only_token("integer"));
        assert!(!is_storage_only_token("text"));
        assert!(!is_storage_only_token("timestamp"));
    }

    #[test]
    fn storage_only_entry_emits_scalar_matrix_with_storage_caps_only() {
        // A storage-only token routes to the `caps = [storage]` arm even though
        // it is also eq-only — storage-only is checked first, so it never selects
        // the `caps = [eq]` arm (which would emit equality tests for a domain
        // that has no `_eq`).
        let token: Ident = syn::parse_str("boolean").unwrap();
        let rust_type: Type = syn::parse_str("bool").unwrap();
        // (storage_only = true, eq_only = true) — true catalog state for bool.
        let out = norm(&matrix_suite_for_entry(
            &token, &rust_type, true, true, false,
        ));
        assert!(out.contains(":: eql_tests :: scalar_matrix !"));
        assert!(out.contains("caps = [storage]"));
        assert!(!out.contains("caps = [eq]"));
        assert!(!out.contains("caps = [eq , ord]"));
        assert!(out.contains("suite = boolean"));
    }

    #[test]
    fn bool_entry_skips_impl_and_stamps_storage_fixture() {
        // `bool` is storage-only: the impl emitter skips it (hand-written in
        // scalar_domains.rs), and the fixture module stamps the `storage`
        // discriminator drawing from the `boolean_values()` accessor.
        let list = syn::parse_str::<ScalarList>("integer => i32, boolean => bool").unwrap();
        let impls = norm(&scalar_type_impls_tokens(&list));
        assert!(impls.contains("impl ScalarType for i32"));
        assert!(
            !impls.contains("impl ScalarType for bool"),
            "bool must skip the generated impl (hand-written instead)"
        );
        let mods = norm(&scalar_fixture_modules_tokens(&list));
        assert!(mods.contains("pub mod eql_v3_boolean"));
        assert!(mods.contains("storage ,"), "got: {mods}");
        assert!(mods.contains("boolean_values"), "got: {mods}");
        let suites = norm(&scalar_matrix_suites_tokens(&list));
        assert!(suites.contains("pub mod boolean"));
        assert!(suites.contains("caps = [storage]"));
        let dispatch = norm(&fixture_dispatch_tokens(&list));
        assert!(dispatch.contains(r#""boolean" =>"#));
        // Every scalar fixture is generated from its fixed curated catalog
        // values via `run()`.
        assert!(
            dispatch.contains(
                r#""boolean" => :: eql_tests :: fixtures :: eql_v3_boolean :: spec () . run () . await"#
            ),
            "bool must dispatch to run(), got: {dispatch}"
        );
        assert!(
            dispatch.contains(
                r#""integer" => :: eql_tests :: fixtures :: eql_v3_integer :: spec () . run () . await"#
            ),
            "integer must dispatch to run(), got: {dispatch}"
        );
    }

    #[test]
    #[should_panic(expected = "not in eql-domains::FIXTURES")]
    fn unknown_token_fails_loudly() {
        // `is_temporal_token` reads the native scalar kind from the fixture
        // layer, so an unknown token now fails loudly via the `FIXTURES` lookup
        // (the structural predicates still fail via `CATALOG` / `spec_for_token`).
        is_temporal_token("nonesuch");
    }

    #[test]
    fn fixture_dispatch_emits_one_arm_per_token_and_a_catch_all() {
        let out = norm(&fixture_dispatch_tokens(&sample()));
        assert!(out.contains("async fn generate_for_token"));
        assert!(out.contains(r#""integer" =>"#));
        assert!(out.contains(r#""bigint" =>"#));
        assert!(out.contains(":: eql_tests :: fixtures :: eql_v3_integer :: spec"));
        // Loud catch-all preserved.
        assert!(out.contains("other =>"));
        assert!(out.contains("no fixture generator wired"));
    }

    #[test]
    fn matrix_suites_emit_mods_with_unchanged_suite_and_eql_type() {
        let out = norm(&scalar_matrix_suites_tokens(&sample()));
        assert!(out.contains("pub mod integer"));
        assert!(out.contains("pub mod bigint"));
        assert!(out.contains(":: eql_tests :: scalar_matrix !"));
        // suite/scalar/eql_type must match the old per-type files so test names
        // (and the snapshot) are unchanged.
        assert!(out.contains("suite = integer"));
        assert!(out.contains("scalar = i32"));
        assert!(out.contains(r#"eql_type = "eql_v3_integer""#));
        assert!(out.contains("suite = bigint"));
        assert!(out.contains("scalar = i64"));
        assert!(out.contains(r#"eql_type = "eql_v3_bigint""#));
    }

    #[test]
    fn matrix_suites_emit_unified_macro_with_caps() {
        // Both base types are ordered, so the emitter routes them through the
        // unified wrapper with the ordered capability marker and never names
        // either of the now-deleted parallel wrappers.
        let list =
            syn::parse_str::<ScalarList>("integer => i32, date => chrono::NaiveDate").unwrap();
        let out = norm(&scalar_matrix_suites_tokens(&list));
        assert!(out.contains(":: eql_tests :: scalar_matrix !"));
        assert!(out.contains("caps = [eq , ord]"));
        assert!(!out.contains("ordered_numeric_matrix"));
        assert!(!out.contains("eq_only_scalar_matrix"));
    }
}
