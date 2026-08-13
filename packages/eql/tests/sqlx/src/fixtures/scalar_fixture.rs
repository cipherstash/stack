//! `scalar_fixture!` — collapse a scalar fixture wrapper to one invocation.
//!
//! Every `eql_v3_<T>` scalar fixture file (`eql_v3_smallint`, `eql_v3_integer`, …) is
//! the same three items differing only in the fixture name, the Rust plaintext
//! type, and the generated value list: the `spec()` builder, the `fixture-gen`
//! generator test, and a small property-test module. This macro stamps all
//! three out, so a new scalar fixture is one `use` of the value const plus one
//! `scalar_fixture!(…)`.
//!
//! The per-file `//!` module docs still belong in each fixture file — they
//! describe *that* type's value choices and are not boilerplate.

/// Stamp out the `spec()` builder, the `fixture-gen` generator test, and the
/// property-test module for a scalar fixture.
///
/// The leading **kind** discriminator (`int` / `temporal` / `text` / `numeric` / `float`
/// / `storage`) selects which property asserts are stamped and which index set
/// the fixture declares — the rest of the expansion is identical:
///
/// - `storage` — storage-only / encryption-only (`bool`): NO index, so the
///   payload is `{v,i,c}` with no term key. Asserts both values are present and
///   no index is declared (the type is not `OrderedScalar`, so there are no
///   comparison pivots to check).
///
/// - `int` — signed-extreme asserts (`<$ty>::MIN`/`MAX`, `contains(&0)`,
///   `any(|v| v < 0)`). These typecheck only for integer plaintexts. Indexes
///   `Unique` + `Ore` + `Ope`.
/// - `temporal` — a pivot-presence assert (`min_pivot`/`max_pivot`/zero from the
///   `ScalarType` impl all appear in the values). `<$ty>::MIN` / `< 0` don't
///   exist for a `chrono::NaiveDate`, so the integer asserts can't be reused.
///   Indexes `Unique` + `Ore` + `Ope`.
/// - `text` — pivot-presence asserts (same as `temporal`; text has no signed
///   extremes), plus a `Match` index so generated payloads carry `bf` for
///   the `text_match` containment surface. Indexes `Unique` + `Ore` + `Match`
///   + `Ope`.
///
/// - `$name` — the fixture name (`"eql_v3_smallint"`), drives every derived path.
/// - `$ty` — the Rust plaintext type (`i16` / `chrono::NaiveDate` / `String`).
/// - `$values` — the value source: the catalog const (`eql_domains::SMALLINT_VALUES`)
///   for integers, or the harness accessor (`date_values()` / `text_values()`).
///
/// `Unique` drives `=` / `<>` (HMAC); `Ore` drives `<` `<=` `>` `>=` (ORE block
/// terms); `Ope` drives the CLLW-OPE `op` term for the `_ord_ope` domains
/// (cipherstash-client 0.38.1+); `Match` drives `@>` / `<@` (bloom
/// filter). The generated payload is always `jsonb`.
#[macro_export]
macro_rules! scalar_fixture {
    // Integer scalars: signed-extreme property asserts.
    (int, $name:literal, $ty:ty, $values:expr $(,)?) => {
        $crate::scalar_fixture!(@common $name, $ty, $values, [Unique, Ore, Ope]);

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn spec_is_complete() {
                assert!(spec().check_complete().is_ok());
            }

            #[test]
            fn spec_includes_signed_extremes() {
                // MIN / MAX exercise ORE block-encoding sign-bit edges that a
                // smaller list would not cover.
                let spec = spec();
                let values = spec.values();
                assert!(
                    values.contains(&<$ty>::MIN),
                    "spec must include {}::MIN",
                    stringify!($ty)
                );
                assert!(
                    values.contains(&<$ty>::MAX),
                    "spec must include {}::MAX",
                    stringify!($ty)
                );
                assert!(values.contains(&0), "spec must include 0");
            }

            #[test]
            fn spec_includes_negative_values() {
                assert!(spec().values().iter().any(|&v| v < 0));
            }
        }
    };

    // Temporal scalars: pivot-presence property assert (no signed extremes).
    (temporal, $name:literal, $ty:ty, $values:expr $(,)?) => {
        $crate::scalar_fixture!(@common $name, $ty, $values, [Unique, Ore, Ope]);

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::scalar_domains::OrderedScalar;

            #[test]
            fn spec_is_complete() {
                assert!(spec().check_complete().is_ok());
            }

            #[test]
            fn spec_includes_pivots() {
                // The three matrix pivots (min/mid/max) must be present in the
                // fixture — `fetch_fixture_payload` fetches each at test time.
                let spec = spec();
                let values = spec.values();
                let min = <$ty as OrderedScalar>::min_pivot();
                let mid = <$ty as OrderedScalar>::mid_pivot();
                let max = <$ty as OrderedScalar>::max_pivot();
                assert!(values.contains(&min), "spec must include min_pivot {min:?}");
                assert!(values.contains(&mid), "spec must include mid_pivot {mid:?}");
                assert!(values.contains(&max), "spec must include max_pivot {max:?}");
            }
        }
    };

    // Text scalars: pivot-presence asserts (like temporal) + the `Match` index
    // so generated payloads carry `bf` for the `text_match` containment surface.
    (text, $name:literal, $ty:ty, $values:expr $(,)?) => {
        $crate::scalar_fixture!(@common $name, $ty, $values, [Unique, Ore, Match, Ope]);

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::scalar_domains::OrderedScalar;

            #[test]
            fn spec_is_complete() {
                assert!(spec().check_complete().is_ok());
            }

            #[test]
            fn spec_includes_pivots() {
                // text has no signed extremes; assert the OrderedScalar pivots
                // (min/mid/max) are present, like the temporal arm.
                let spec = spec();
                let values = spec.values();
                let min = <$ty as OrderedScalar>::min_pivot();
                let mid = <$ty as OrderedScalar>::mid_pivot();
                let max = <$ty as OrderedScalar>::max_pivot();
                assert!(values.contains(&min), "spec must include min_pivot {min:?}");
                assert!(values.contains(&mid), "spec must include mid_pivot {mid:?}");
                assert!(values.contains(&max), "spec must include max_pivot {max:?}");
            }
        }
    };

    // Numeric scalars (`rust_decimal::Decimal`): ordered, non-chrono. Same
    // shape as `temporal` — `[Unique, Ore, Ope]` indexes, pivot-presence asserts
    // via `OrderedScalar` — but materialised from owned `Decimal` values (no
    // `Match` index, no chrono).
    (numeric, $name:literal, $ty:ty, $values:expr $(,)?) => {
        $crate::scalar_fixture!(@common $name, $ty, $values, [Unique, Ore, Ope]);

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::scalar_domains::OrderedScalar;

            #[test]
            fn spec_is_complete() {
                assert!(spec().check_complete().is_ok());
            }

            #[test]
            fn spec_includes_pivots() {
                let spec = spec();
                let values = spec.values();
                let min = <$ty as OrderedScalar>::min_pivot();
                let mid = <$ty as OrderedScalar>::mid_pivot();
                let max = <$ty as OrderedScalar>::max_pivot();
                assert!(values.contains(&min), "spec must include min_pivot {min:?}");
                assert!(values.contains(&mid), "spec must include mid_pivot {mid:?}");
                assert!(values.contains(&max), "spec must include max_pivot {max:?}");
            }
        }
    };

    // Float scalars (`F4`/`F8`): ordered, non-chrono. Same shape as `numeric` —
    // `[Unique, Ore, Ope]` indexes, pivot-presence asserts via `OrderedScalar` —
    // materialised from the harness float newtypes (no `Match`, no chrono).
    (float, $name:literal, $ty:ty, $values:expr $(,)?) => {
        $crate::scalar_fixture!(@common $name, $ty, $values, [Unique, Ore, Ope]);

        #[cfg(test)]
        mod tests {
            use super::*;
            use $crate::scalar_domains::OrderedScalar;

            #[test]
            fn spec_is_complete() {
                assert!(spec().check_complete().is_ok());
            }

            #[test]
            fn spec_includes_pivots() {
                let spec = spec();
                let values = spec.values();
                let min = <$ty as OrderedScalar>::min_pivot();
                let mid = <$ty as OrderedScalar>::mid_pivot();
                let max = <$ty as OrderedScalar>::max_pivot();
                assert!(values.contains(&min), "spec must include min_pivot {min:?}");
                assert!(values.contains(&mid), "spec must include mid_pivot {mid:?}");
                assert!(values.contains(&max), "spec must include max_pivot {max:?}");
            }
        }
    };

    // Storage-only (encryption-only) scalars (`bool`): the value is encrypted
    // with NO search index, so the payload is `{v,i,c}` with no term key. The
    // fixture declares zero indexes (`.storage_only()`), and the property test
    // asserts only that both values are present and no index is declared — there
    // are no comparison pivots (the type is not `OrderedScalar`).
    (storage, $name:literal, $ty:ty, $values:expr $(,)?) => {
        /// The complete storage-only fixture definition. No `IndexKind` — the
        /// encrypted payload carries only `{v,i,c}` (no `hm`/`ob`/`bf`).
        pub fn spec() -> $crate::fixtures::FixtureSpec<'static, $ty> {
            $crate::fixtures::FixtureSpec::new($name)
                .storage_only()
                .with_column_type("jsonb")
                .with_values($values)
        }

        /// The generator. Gated by `fixture-gen` so `cargo test` never compiles
        /// it; `#[ignore]` is a second guard. Run via `mise run fixture:generate`.
        #[cfg(feature = "fixture-gen")]
        #[tokio::test]
        #[ignore = "generator — run via `mise run fixture:generate`"]
        async fn generate() -> anyhow::Result<()> {
            spec().run().await
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn spec_is_complete() {
                assert!(spec().check_complete().is_ok());
            }

            #[test]
            fn spec_declares_no_index() {
                // Storage-only / encryption-only: the payload carries no search
                // term, so the fixture must declare zero indexes.
                assert!(spec().indexes().is_empty());
            }

            #[test]
            fn spec_includes_both_boolean_values() {
                // Low-cardinality but still both values, so the storage matrix
                // can prove the domain accepts a real ciphertext for each.
                let spec = spec();
                let values = spec.values();
                assert!(values.contains(&false), "spec must include false");
                assert!(values.contains(&true), "spec must include true");
            }
        }
    };

    // Shared expansion: the `spec()` builder + the gated generator test. The
    // trailing `[Unique, Ore, ...]` token list parametrizes the index set.
    (@common $name:literal, $ty:ty, $values:expr, [$($ix:ident),+ $(,)?]) => {
        /// The complete fixture definition. `IndexKind::Unique` drives `=` /
        /// `<>` (HMAC); `IndexKind::Ore` drives `<` `<=` `>` `>=` (ORE block
        /// terms); `IndexKind::Ope` drives the CLLW-OPE `op` term (`_ord_ope`
        /// domains); `IndexKind::Match` (when present) drives `@>` / `<@` (bloom).
        pub fn spec() -> $crate::fixtures::FixtureSpec<'static, $ty> {
            $crate::fixtures::FixtureSpec::new($name)
                $(.with_index($crate::fixtures::IndexKind::$ix))+
                .with_column_type("jsonb")
                .with_values($values)
        }

        /// The generator. Gated by `fixture-gen` so `cargo test` never compiles
        /// it; `#[ignore]` is a second guard. Run via
        /// `mise run fixture:generate`. Generates the fixed curated catalog
        /// values via `run()`.
        #[cfg(feature = "fixture-gen")]
        #[tokio::test]
        #[ignore = "generator — run via `mise run fixture:generate`"]
        async fn generate() -> anyhow::Result<()> {
            spec().run().await
        }
    };
}
