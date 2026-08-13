//! Inherent impls for [`Term`] — the per-term SQL contract (`json_key`,
//! `extractor`, `ctor`, `role`, `operators`, `requires`) plus the cross-term
//! helpers that resolve a domain's `&[Term]` to its operators, keys, requires,
//! role, and extractor. Definition lives in `lib.rs`.

use crate::{Role, Term};

impl Term {
    /// JSON payload key carrying this term (`"hm"` / `"ob"` / `"bf"` / `"op"`).
    pub const fn json_key(self) -> &'static str {
        match self {
            Term::Hm => "hm",
            Term::Ore => "ob",
            Term::Bloom => "bf",
            Term::Ope => "op",
        }
    }

    /// The generated extractor function name (`"eq_term"` / `"ord_term"` /
    /// `"match_term"` / `"ord_term_ore"`).
    ///
    /// The extractor name tracks the *domain* it serves, not the cipher: `Ope`
    /// backs the default `_ord` domain, so it takes the unqualified
    /// `"ord_term"`, and block-ORE — the by-name escape hatch behind
    /// `_ord_ore` — takes the qualified `"ord_term_ore"`, mirroring the domain
    /// suffix exactly (`_ord` → `ord_term`, `_ord_ore` → `ord_term_ore`).
    ///
    /// The two names must stay DISTINCT: `dedupe_terms_by(Term::extractor)`
    /// collapses terms sharing an extractor name, so giving `Ore` and `Ope` a
    /// shared name would silently drop one extractor from a mixed
    /// `[Ore, Ope]` domain. No such domain exists today; the distinctness is
    /// what keeps that true by construction rather than by luck.
    pub const fn extractor(self) -> &'static str {
        match self {
            Term::Hm => "eq_term",
            Term::Ore => "ord_term_ore",
            Term::Bloom => "match_term",
            Term::Ope => "ord_term",
        }
    }

    /// Constructor name for the index-term type (unqualified).
    pub const fn ctor(self) -> &'static str {
        match self {
            Term::Hm => "hmac_256",
            Term::Ore => "ore_block_256",
            Term::Bloom => "bloom_filter",
            Term::Ope => "ope_cllw",
        }
    }

    /// The shared binding newtype carrying this term's payload field on the
    /// wire (`Hmac256` for `hm`, `OreBlock256` for `ob`, `BloomFilter` for
    /// `bf`). Part of the structural wire contract, beside [`Term::json_key`]/
    /// [`Term::ctor`] — a new term names its newtype HERE, so the bindings
    /// emitter (which matches on `Term`) stays exhaustive at compile time
    /// instead of panicking at codegen runtime on an unmapped key.
    pub const fn binding_newtype(self) -> &'static str {
        match self {
            Term::Hm => "Hmac256",
            Term::Ore => "OreBlock256",
            Term::Bloom => "BloomFilter",
            Term::Ope => "OpeCllw",
        }
    }

    /// Generated-file [`Role`] contributed by this single term. A domain's role
    /// is the richest of its terms' roles — see [`Term::role_for_terms`].
    pub const fn role(self) -> Role {
        match self {
            Term::Hm => Role::Eq,
            Term::Ore => Role::Ord,
            Term::Bloom => Role::Match,
            Term::Ope => Role::Ord,
        }
    }

    /// SQL operators this term supports, in catalog order.
    pub const fn operators(self) -> &'static [&'static str] {
        match self {
            Term::Hm => &["=", "<>"],
            Term::Ore => &["=", "<>", "<", "<=", ">", ">="],
            Term::Bloom => &["@@"],
            Term::Ope => &["=", "<>", "<", "<=", ">", ">="],
        }
    }

    /// SQL `-- REQUIRE:` edges this term pulls in, in catalog order.
    pub const fn requires(self) -> &'static [&'static str] {
        match self {
            Term::Hm => &["src/v3/sem/hmac_256/functions.sql"],
            Term::Ore => &[
                "src/v3/sem/ore_block_256/functions.sql",
                "src/v3/sem/ore_block_256/operators.sql",
            ],
            Term::Bloom => &["src/v3/sem/bloom_filter/functions.sql"],
            // No operators.sql edge: eql_v3_internal.ope_cllw is a domain over bytea,
            // so it inherits the native bytea comparison operators and btree
            // opclass — the extractor is the whole SEM surface (like Hm).
            Term::Ope => &["src/v3/sem/ope_cllw/functions.sql"],
        }
    }

    /// True when this term provides ordering operators (`<` `<=` `>` `>=`).
    /// A per-term *capability*, distinct from [`Role`] (the whole-domain file
    /// role derived from the first term). New ordering terms opt in here, so
    /// `is_ord_capable` never hardcodes a single ordering term.
    pub const fn provides_ordering(self) -> bool {
        matches!(self, Term::Ore | Term::Ope)
    }

    /// JSON key whose payload must be a NON-EMPTY array for this term to be
    /// well-formed, or `None` if the term imposes no such structural rule. The
    /// ORE term (`ob`) is an array of block terms; an empty array (`ob: []`) is
    /// only ever produced by encrypting the empty string into an ordered column,
    /// and the domain CHECK rejects it at the boundary rather than ordering it
    /// (issue #262). A new array-backed term opts in here, so the domain CHECK
    /// never hardcodes a single key.
    pub const fn nonempty_array_key(self) -> Option<&'static str> {
        match self {
            Term::Ore => Some(self.json_key()),
            // `op` is a single hex string, not an array.
            Term::Hm | Term::Bloom | Term::Ope => None,
        }
    }
}

impl Term {
    /// Stable dedupe — first occurrence wins.
    fn dedupe_preserving_order<'a>(items: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        let mut out: Vec<&'a str> = Vec::new();
        for item in items {
            if !out.contains(&item) {
                out.push(item);
            }
        }
        out
    }

    /// Distinct terms keyed by `key`, first occurrence wins, order preserved.
    /// The `Term`-returning sibling of [`Self::dedupe_preserving_order`] (which
    /// returns the `&str` keys): [`Term::payload_terms`] keys on
    /// [`Term::json_key`], [`Term::extractor_terms`] on [`Term::extractor`].
    fn dedupe_terms_by(terms: &[Term], key: fn(Term) -> &'static str) -> Vec<Term> {
        let mut seen: Vec<&str> = Vec::new();
        let mut out: Vec<Term> = Vec::new();
        for &t in terms {
            let k = key(t);
            if !seen.contains(&k) {
                seen.push(k);
                out.push(t);
            }
        }
        out
    }

    /// Supported operators for the union of a domain's terms (catalog order,
    /// deduped).
    pub fn operators_for_terms(terms: &[Term]) -> Vec<&'static str> {
        Self::dedupe_preserving_order(terms.iter().flat_map(|t| t.operators().iter().copied()))
    }

    /// JSON payload keys required by these terms (deduped, in order).
    pub fn term_json_keys(terms: &[Term]) -> Vec<&'static str> {
        Self::dedupe_preserving_order(terms.iter().map(|t| t.json_key()))
    }

    /// The distinct terms contributing a payload field, in wire order: one per
    /// [`Term::json_key`], deduped first-occurrence-wins. Symmetric to
    /// [`Term::term_json_keys`] but returns the `Term`s, so the bindings emitter
    /// reads both the field key ([`Term::json_key`]) and its newtype
    /// ([`Term::binding_newtype`]) while matching on the enum.
    pub fn payload_terms(terms: &[Term]) -> Vec<Term> {
        Self::dedupe_terms_by(terms, Term::json_key)
    }

    /// JSON keys whose payload must be a non-empty array across these terms
    /// (deduped, in order). Symmetric to [`Term::term_json_keys`]; drives the
    /// domain CHECK's non-empty-array clauses. See [`Term::nonempty_array_key`].
    pub fn nonempty_array_keys(terms: &[Term]) -> Vec<&'static str> {
        Self::dedupe_preserving_order(terms.iter().filter_map(|t| t.nonempty_array_key()))
    }

    /// Distinct extractor-bearing terms, first occurrence per extractor wins.
    /// Two terms sharing an extractor collapse to the first, since the generated
    /// `eq_term`/`ord_term`/`ord_term_ore`/`match_term` function is emitted once
    /// per extractor.
    pub fn extractor_terms(terms: &[Term]) -> Vec<Term> {
        Self::dedupe_terms_by(terms, Term::extractor)
    }

    /// SQL `-- REQUIRE:` edges needed by these terms (deduped, in order).
    pub fn term_requires(terms: &[Term]) -> Vec<&'static str> {
        Self::dedupe_preserving_order(terms.iter().flat_map(|t| t.requires().iter().copied()))
    }

    /// The extractor that supports `op` for a domain carrying `terms`, or
    /// `None`. First supporting term wins.
    pub fn extractor_for_operator(terms: &[Term], op: &str) -> Option<&'static str> {
        terms
            .iter()
            .find(|t| t.operators().contains(&op))
            .map(|t| t.extractor())
    }

    /// Generated-file [`Role`] for a domain with these terms. No terms =>
    /// [`Role::Storage`]; otherwise the **richest** role across the terms by
    /// [`Role::rank`] precedence (`Ord > Eq > Match > Storage`). For the current
    /// single-term catalog this equals the lone term's role, so generated SQL is
    /// unchanged; the precedence only disambiguates a future mixed-term domain
    /// (e.g. `[Hm, Ore]` => `Ord`), keeping this consistent with
    /// [`Term::operators_for_terms`], which unions across all terms rather than
    /// reading only the first.
    pub fn role_for_terms(terms: &[Term]) -> Role {
        terms
            .iter()
            .map(|t| t.role())
            .max_by_key(|r| r.rank())
            .unwrap_or(Role::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_newtype_maps_each_term() {
        assert_eq!(Term::Hm.binding_newtype(), "Hmac256");
        assert_eq!(Term::Ore.binding_newtype(), "OreBlock256");
        assert_eq!(Term::Bloom.binding_newtype(), "BloomFilter");
        assert_eq!(Term::Ope.binding_newtype(), "OpeCllw");
    }

    #[test]
    fn payload_terms_is_one_field_per_json_key_in_order() {
        let keys: Vec<&str> = Term::payload_terms(&[Term::Hm, Term::Ore])
            .iter()
            .map(|t| t.json_key())
            .collect();
        assert_eq!(keys, ["hm", "ob"]);
        let keys: Vec<&str> = Term::payload_terms(&[Term::Hm, Term::Hm])
            .iter()
            .map(|t| t.json_key())
            .collect();
        assert_eq!(keys, ["hm"]);
        assert!(Term::payload_terms(&[]).is_empty());
    }
}
