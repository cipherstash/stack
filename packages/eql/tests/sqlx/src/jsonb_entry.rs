//! SteVec **entry** view type for the behaviour matrix. A `JsonbEntryInteger`
//! reuses the `i32` plaintext oracle (`expected_forward`, pivots,
//! `fixture_values`) but reaches its comparable value by extracting the entry
//! at `v3_doc_integer::SELECTOR` and casting to `public.eql_v3_json_entry`, so the
//! matrix's correctness/ordering/null/order-by/count/index generators run
//! against jsonb-entry comparisons instead of whole-column scalar casts.
//!
//! It is deliberately NOT a `eql_domains::CATALOG` scalar (it has no generated
//! domain family and must stay out of the scalar matrix inventory). The entry
//! suite invokes it through the reduced `jsonb_entry_matrix!` macro.

use crate::fixtures::v3_doc_integer;
use crate::scalar_domains::{OrderedScalar, ScalarType, Variant};

/// Newtype over `i32`. `Display`/`Ord`/`Default` delegate to the inner value so
/// the inherited `expected_forward` oracle is identical to integer's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct JsonbEntryInteger(pub i32);

impl std::fmt::Display for JsonbEntryInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl sqlx::Type<sqlx::Postgres> for JsonbEntryInteger {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <i32 as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for JsonbEntryInteger {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        Ok(JsonbEntryInteger(
            <i32 as sqlx::Decode<sqlx::Postgres>>::decode(value)?,
        ))
    }
}

/// Fixture values: integer's list, wrapped. Materialised once into a `LazyLock`
/// because the trait returns `&'static [Self]` and `i32`'s const slice cannot
/// be reinterpreted as `&[JsonbEntryInteger]` without an allocation.
static VALUES: std::sync::LazyLock<Vec<JsonbEntryInteger>> = std::sync::LazyLock::new(|| {
    eql_domains::INTEGER_VALUES
        .iter()
        .copied()
        .map(JsonbEntryInteger)
        .collect()
});

impl ScalarType for JsonbEntryInteger {
    /// Drives `fixture_table_name()`'s default; overridden below, but kept
    /// honest (the entry is an integer-shaped document).
    const PG_TYPE: &'static str = "integer";

    fn fixture_values() -> &'static [Self] {
        &VALUES
    }

    /// The scalar-shaped document fixture, not `fixtures.eql_v3_integer`.
    fn fixture_table_name() -> String {
        "fixtures.v3_doc_integer".to_string()
    }

    /// Single entry domain, variant-independent.
    fn sql_domain(_variant: Variant) -> String {
        "public.eql_v3_json_entry".to_string()
    }

    /// Extract the entry at the pinned selector. `->` already yields
    /// `public.eql_v3_json_entry`; the call sites' `::public.eql_v3_json_entry` cast is
    /// a no-op. The selector literal is explicitly typed as text so Postgres
    /// resolves the `public.eql_v3_json_search -> text` operator instead of native jsonb path
    /// lookup. Parenthesised by the call sites (`({col})::{d}`).
    fn column_expr() -> String {
        format!("payload -> '{}'::text", v3_doc_integer::SELECTOR)
    }

    fn to_sql_literal(value: &Self) -> String {
        value.0.to_string()
    }

    /// Valid `public.eql_v3_json_entry` literal for tests that only need a non-NULL
    /// operand shape (NULL propagation). Must satisfy the domain CHECK: string
    /// `s`, string `c`, no `hm`, and an optional string `op`.
    fn placeholder_payload() -> &'static str {
        r#"{"s":"placeholder","c":"sample","op":"00"}"#
    }

    /// A SteVec entry orders by its structural CLLW-OPE term (`op`), whatever
    /// the variant. Deliberately ignores the catalog default rather than relying
    /// on it: `PG_TYPE` is `"integer"`, so the derived extractor answers for
    /// `integer`'s `_ord`, which coincides with `ord_term` only for as long as
    /// that domain stays OPE-backed. The entry's term is structural.
    fn ord_extractor_expr(_variant: Variant, value_expr: &str) -> String {
        format!("eql_v3.ord_term({value_expr})")
    }

    // Not an e2e/property-oracle type (the entry suite runs the jsonb_entry
    // matrix, not the value oracle), but `arbitrary_value` is a required
    // `ScalarType` method — sample the wrapped integer fixtures.
    fn arbitrary_value() -> proptest::strategy::BoxedStrategy<Self> {
        use proptest::strategy::Strategy;
        proptest::sample::select(Self::fixture_values().to_vec()).boxed()
    }
}

impl OrderedScalar for JsonbEntryInteger {
    // All three pivots inherit the `OrderedScalar` defaults: the boundaries
    // derive from `fixture_values()` (wrapped `INTEGER_VALUES`) and `mid_pivot`
    // inherits `JsonbEntryInteger::default()` = `JsonbEntryInteger(0)`. This is exactly
    // the integer delegation that used to be spelled out here.
}

// `JsonbEntryInteger` is deliberately NOT `SignedScalar` — the entry suite does
// not run the signed-only sign-boundary test. `expected_forward` is the
// inherited default from `ScalarType` (it works for any `Ord` type), so the
// oracle is automatically integer-identical.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegates_oracle_to_integer() {
        // Same forward result set as i32 for a representative op/pivot.
        let got = <JsonbEntryInteger as ScalarType>::expected_forward(">", JsonbEntryInteger(0));
        let want: Vec<JsonbEntryInteger> = <i32 as ScalarType>::expected_forward(">", 0)
            .into_iter()
            .map(JsonbEntryInteger)
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn extracts_entry_at_selector() {
        assert_eq!(
            <JsonbEntryInteger as ScalarType>::column_expr(),
            format!("payload -> '{}'::text", v3_doc_integer::SELECTOR),
        );
        assert_eq!(
            <JsonbEntryInteger as ScalarType>::sql_domain(Variant::Ord),
            "public.eql_v3_json_entry",
        );
        assert_eq!(
            <JsonbEntryInteger as ScalarType>::ord_extractor_expr(Variant::Ord, "value"),
            "eql_v3.ord_term(value)",
        );
    }

    /// Pins the `ord_extractor_expr` OVERRIDE as load-bearing.
    ///
    /// Under `Variant::Ord` the override is indistinguishable from the
    /// catalog-derived default: `PG_TYPE` is `"integer"`, whose `_ord` is
    /// `Term::Ope`, which yields `ord_term` — the same string. Asserting only
    /// that case would pass with the override deleted.
    ///
    /// `Variant::OrdOre` is where they diverge. The default would consult the
    /// catalog, find `Term::Ore`, and emit `ord_term_ore` — wrong for an entry,
    /// whose ordering term is structurally `op` regardless of variant. So this
    /// fails the moment the override stops ignoring the variant.
    #[test]
    fn ord_extractor_override_ignores_the_variant() {
        for variant in [Variant::Ord, Variant::OrdOre] {
            assert_eq!(
                <JsonbEntryInteger as ScalarType>::ord_extractor_expr(variant, "value"),
                "eql_v3.ord_term(value)",
                "a SteVec entry always orders by its structural `op` term, but \
                 {variant:?} resolved to a different extractor — the override in \
                 `impl ScalarType for JsonbEntryInteger` was bypassed or removed",
            );
        }
    }

    #[test]
    fn fixture_values_wrap_integer_values_in_order() {
        let got: Vec<i32> = <JsonbEntryInteger as ScalarType>::fixture_values()
            .iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(got, eql_domains::INTEGER_VALUES.to_vec());
    }

    #[test]
    fn pivots_delegate_to_integer() {
        assert_eq!(
            <JsonbEntryInteger as OrderedScalar>::min_pivot().0,
            i32::MIN
        );
        assert_eq!(
            <JsonbEntryInteger as OrderedScalar>::max_pivot().0,
            i32::MAX
        );
        assert_eq!(<JsonbEntryInteger as OrderedScalar>::mid_pivot().0, 0);
    }

    /// The placeholder must satisfy the `public.eql_v3_json_entry` CHECK shape:
    /// string `s`, string `c`, no `hm`, and an optional string `op`. SQL-level
    /// validity is asserted in the integration `jsonb_entry` suite.
    #[test]
    fn placeholder_is_a_valid_entry_shape() {
        let v: serde_json::Value =
            serde_json::from_str(<JsonbEntryInteger as ScalarType>::placeholder_payload()).unwrap();
        assert!(v.get("s").and_then(|x| x.as_str()).is_some());
        assert!(v.get("c").and_then(|x| x.as_str()).is_some());
        assert!(v.get("hm").is_none(), "hm is retired");
        assert!(v.get("op").and_then(|x| x.as_str()).is_some());
    }
}
