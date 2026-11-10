//! The EQL types this build holds: the `TargetResolver`
//! (`stack_encrypt::dynamic::TargetResolver`) the record operations run
//! target fields through. The two names below are cfg-dependent, so they
//! are code spans, not links: a doc build of either feature set resolves.
//!
//! Two builds of this crate, one resolver each (ADR-0007, amended
//! 2026-10-06). With the `eql` feature, [`Resolver`] is `eql-bindings`'
//! own resolver (`eql_bindings::encryption::EqlTargets`): `se_targets`
//! lists every EQL type the catalog has, and a plan field naming a
//! producible one (`TextEq`) is run through that type's own plan, in the
//! same ZeroKMS request as the rest of the record. Without it,
//! [`Resolver`] is the engine's `NoTargets`
//! (`stack_encrypt::dynamic::NoTargets`): `se_targets` lists nothing, and
//! a plan that names a target is refused when it is parsed — at
//! `se_plan_check`, before any value crosses.
//!
//! The Go module embeds both: `encrypt` the build without EQL types,
//! `encrypt/eql` the build with them, registered on import, so a program
//! that names an EQL type links the build that has it.

/// The resolver this build installs.
#[cfg(feature = "eql")]
pub type Resolver = eql_bindings::encryption::EqlTargets;
/// The resolver this build installs.
#[cfg(not(feature = "eql"))]
pub type Resolver = stack_encrypt::dynamic::NoTargets;

/// This build's resolver, for the record operations.
pub fn resolver() -> Resolver {
    Resolver::default()
}

/// Whether this build holds the EQL types.
pub const HOLDS_EQL: bool = cfg!(feature = "eql");

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "eql")]
    use stack_encrypt::dynamic::{TargetError, TargetResolver as _};

    #[cfg(not(feature = "eql"))]
    #[test]
    fn the_build_without_eql_holds_no_target() {
        use stack_encrypt::dynamic::TargetResolver as _;
        assert!(resolver().targets().is_empty());
        assert!(matches!(
            resolver().resolve("TextEq"),
            Err(stack_encrypt::dynamic::TargetError::NoTargets { .. })
        ));
    }

    #[cfg(feature = "eql")]
    #[test]
    fn the_eql_build_lists_the_catalog_and_resolves_text_eq() {
        let targets = resolver().targets();
        assert!(!targets.is_empty(), "the catalog has types");
        let text_eq = targets.iter().find(|t| t.name == "TextEq").expect("TextEq");
        assert!(text_eq.producible);
        assert_eq!(
            text_eq.plaintext,
            Some(stack_encrypt::dynamic::ValueKind::String)
        );
        assert_eq!(text_eq.indexes, ["eq"]);
        assert_eq!(text_eq.query.as_deref(), Some("TextEqQuery"));
        assert_eq!(resolver().resolve("TextEq").unwrap().name, "TextEq");
        let producible: Vec<&str> = targets
            .iter()
            .filter(|t| t.producible)
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(
            producible,
            [
                "Integer",
                "IntegerEq",
                "IntegerOrdOre",
                "IntegerOrd",
                "IntegerOrdOpe",
                "Smallint",
                "SmallintEq",
                "SmallintOrdOre",
                "SmallintOrd",
                "SmallintOrdOpe",
                "Bigint",
                "BigintEq",
                "BigintOrdOre",
                "BigintOrd",
                "BigintOrdOpe",
                "Date",
                "DateEq",
                "DateOrdOre",
                "DateOrd",
                "DateOrdOpe",
                "Timestamp",
                "TimestampEq",
                "TimestampOrdOre",
                "TimestampOrd",
                "TimestampOrdOpe",
                "Numeric",
                "NumericEq",
                "NumericOrdOre",
                "NumericOrd",
                "NumericOrdOpe",
                "Text",
                "TextEq",
                "TextMatch",
                "TextOrdOre",
                "TextOrd",
                "TextOrdOpe",
                "TextSearchOre",
                "TextSearch",
                "Boolean",
                "Real",
                "RealEq",
                "RealOrdOre",
                "RealOrd",
                "RealOrdOpe",
                "Double",
                "DoubleEq",
                "DoubleOrdOre",
                "DoubleOrd",
                "DoubleOrdOpe",
                "JsonSearch"
            ],
            "the engine's producible types, in catalog order"
        );
        assert!(matches!(
            resolver().resolve("Json"),
            Err(TargetError::Unproducible { .. })
        ));
        assert!(matches!(
            resolver().resolve("Nope"),
            Err(TargetError::Unknown { .. })
        ));
    }
}
