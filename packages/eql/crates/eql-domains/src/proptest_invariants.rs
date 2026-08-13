//! Catalog suite: property-based invariants over the scalar/term catalog.
//!
//! Pure Rust — no database, no encryption, no creds. These run in the lean
//! `cargo test -p eql-domains` path (fork CI). They assert the *catalog* is
//! internally consistent for any generated input; the DB-backed oracle suites
//! (fixture/e2e) live in `tests/sqlx`.

use crate::{ScalarKind, Term};
use proptest::prelude::*;

/// Strategy over the four index terms.
fn any_term() -> impl Strategy<Value = Term> {
    prop_oneof![
        Just(Term::Hm),
        Just(Term::Ore),
        Just(Term::Bloom),
        Just(Term::Ope)
    ]
}

/// Strategy over the eleven scalar kinds.
fn any_kind() -> impl Strategy<Value = ScalarKind> {
    prop_oneof![
        Just(ScalarKind::I16),
        Just(ScalarKind::I32),
        Just(ScalarKind::I64),
        Just(ScalarKind::Numeric),
        Just(ScalarKind::Text),
        Just(ScalarKind::Jsonb),
        Just(ScalarKind::Bool),
        Just(ScalarKind::Date),
        Just(ScalarKind::Timestamp),
        Just(ScalarKind::F32),
        Just(ScalarKind::F64),
    ]
}

proptest! {
    /// The ordering terms (`Ore`, `Ope`) support a strict superset of `Hm`
    /// (equality): every operator Hm provides, each ordering term also provides.
    #[test]
    fn ordering_term_operators_superset_of_hm(_ in any::<()>()) {
        for term in [Term::Ore, Term::Ope] {
            for op in Term::Hm.operators() {
                prop_assert!(
                    term.operators().contains(op),
                    "{term:?} must support every Hm operator; missing {op}"
                );
            }
        }
    }

    /// `operators_for_terms` is order-preserving-deduped: no duplicate operator
    /// appears, and every input term's operators are present in the union.
    #[test]
    fn operators_for_terms_is_deduped_union(terms in prop::collection::vec(any_term(), 0..6)) {
        let union = Term::operators_for_terms(&terms);

        // No duplicates.
        let mut seen = std::collections::HashSet::new();
        for op in &union {
            prop_assert!(seen.insert(*op), "duplicate operator {op} in union");
        }

        // Completeness: every term's operators are in the union.
        for t in &terms {
            for op in t.operators() {
                prop_assert!(union.contains(op), "union missing {op} from {t:?}");
            }
        }
    }

    /// For any domain term set and any operator the union supports, there is a
    /// resolving extractor; for an unsupported operator there is none.
    #[test]
    fn extractor_resolves_iff_operator_supported(
        terms in prop::collection::vec(any_term(), 1..4)
    ) {
        let union = Term::operators_for_terms(&terms);
        for op in ["=", "<>", "<", "<=", ">", ">=", "@>", "<@", "->", "??"] {
            let resolves = Term::extractor_for_operator(&terms, op).is_some();
            let supported = union.contains(&op);
            prop_assert_eq!(
                resolves, supported,
                "operator {} resolves={} but supported={}", op, resolves, supported
            );
        }
    }

    /// Every integer kind's representable range is non-empty and ordered.
    #[test]
    fn bounded_int_ranges_are_ordered(kind in any_kind()) {
        if let Some(b) = kind.as_bounded_int() {
            prop_assert!(b.min_value() < b.max_value(), "{kind:?} range must be non-empty");
            prop_assert!(kind.is_int());
        } else {
            prop_assert!(!kind.is_int());
        }
    }
}

/// Non-proptest catalog invariants that range over the whole `CATALOG` (a fixed
/// set, so an exhaustive loop is the right tool, not a generator).
#[test]
fn every_catalog_domain_payload_keys_match_its_terms() {
    for spec in crate::scalar_families() {
        for dom in spec.domains {
            // Exact set equality: the payload keys are precisely each term's
            // json_key (deduped) — no missing keys and no extras.
            let actual: std::collections::HashSet<&str> =
                Term::term_json_keys(dom.terms).into_iter().collect();
            let expected: std::collections::HashSet<&str> =
                dom.terms.iter().map(|t| t.json_key()).collect();
            assert_eq!(
                actual,
                expected,
                "domain {} payload-key set mismatch",
                spec.domain_name(dom)
            );
        }
    }
}

#[test]
fn eq_only_specs_have_no_ordering_operators() {
    for spec in crate::scalar_families() {
        if spec.is_eq_only() {
            for dom in spec.domains {
                let ops = Term::operators_for_terms(dom.terms);
                assert!(
                    !ops.iter().any(|o| matches!(*o, "<" | "<=" | ">" | ">=")),
                    "eq-only spec {} exposes an ordering operator on {}",
                    spec.name,
                    spec.domain_name(dom)
                );
            }
        }
    }
}
