//! `dump_catalog` — serialize the `eql_domains::CATALOG` surface (each type's
//! domains and their supported SQL operators) for downstream verification
//! tooling. The reusable producer behind `eql-codegen -- dump-catalog`.
//!
//! Stage 1 consumes the `(type, domain)` shape; later stages consume the
//! per-domain `supported_ops`. Blocked-operator tagging is added in Stage 4.

use eql_domains::Term;
use serde::Serialize;

/// The catalog surface: every scalar type and its domains, plus the non-scalar
/// SteVec (`json`) family.
#[derive(Serialize)]
pub struct CatalogDump {
    pub types: Vec<TypeEntry>,
    /// The whole `json` family inventory — the SteVec domains
    /// (`public.eql_v3_json_search` / `public.eql_v3_json_entry` /
    /// `eql_v3.query_json`) **and** the bare `public.eql_v3_json` storage
    /// domain, which is scalar-shaped but belongs to this mixed family. Their
    /// SQL is hand-written under `src/v3/json/`; the catalog owns only their
    /// inventory (scalar-only consumers ignore this field).
    ///
    /// The storage domain is carried here rather than in `types` because
    /// `types` is the scalar-*matrix* surface: the catalog-coverage task
    /// requires a `scalars::<token>::matrix_*` suite for every (type, domain)
    /// it lists, and the json family has no such matrix. Listing it in neither
    /// is what dropped `public.eql_v3_json` from the docs manifest entirely.
    pub stevec: Vec<SteVecEntry>,
}

#[derive(Serialize)]
pub struct TypeEntry {
    /// Catalog token, e.g. `integer`.
    pub token: &'static str,
    /// True when the type has no `_ord` domain (storage + `_eq` only).
    pub is_eq_only: bool,
    pub domains: Vec<DomainEntry>,
}

#[derive(Serialize)]
pub struct DomainEntry {
    /// Test-name segment: the base domain (`name == ""`) is `storage`;
    /// otherwise the bare domain name (`eq`, `ord`, …).
    pub segment: String,
    /// The `suffix` wire field (`""`, `_eq`, `_ord`, `_ord_ore`, `_match`),
    /// reconstructed by re-prefixing the bare domain name with `_` so the
    /// emitted JSON stays byte-stable after the catalog dropped the leading
    /// underscore from its stored domain names.
    pub suffix: String,
    /// The installed pg_type typname: the version-prefixed unqualified SQL
    /// name (`eql_v3_integer_eq`), resolved under `public`.
    pub typname: String,
    /// SQL operators the domain's terms support, in catalog order. Empty for
    /// the storage domain (no terms).
    pub supported_ops: Vec<&'static str>,
    /// The index terms this domain carries, with their extractor + SEM ctor.
    pub terms: Vec<TermInfo>,
}

/// A domain's index term: payload key + generated extractor + SEM constructor
/// (from `eql_domains::Term`) — links a domain to its extractor functions.
#[derive(Serialize)]
pub struct TermInfo {
    /// Payload key: `hm` / `ob` / `bf` / `op`.
    pub key: &'static str,
    /// Generated extractor function (unqualified): `eq_term` / `ord_term` /
    /// `match_term` / `ord_term_ore`.
    pub extractor: &'static str,
    /// SEM index-term constructor (unqualified): `hmac_256` / `ore_block_256` /
    /// `bloom_filter` / `ope_cllw`.
    pub ctor: &'static str,
}

/// One `json`-family domain: catalog inventory only — its SQL surface
/// (CHECK, operators) is hand-written and not derivable from the catalog.
#[derive(Serialize)]
pub struct SteVecEntry {
    /// The bare domain name: `json` / `json_search` / `json_entry` / `query_json`.
    pub full_name: String,
    /// The installed pg_type typname: the version-prefixed name for the
    /// public-schema column domains (`eql_v3_json_search` /
    /// `eql_v3_json_entry`); the containment needle stays `query_json` (it lives in the
    /// already-versioned `eql_v3` schema).
    pub typname: String,
    /// The catalog domain name: `json` / `entry` / `query`.
    pub name: &'static str,
    /// Index terms for this SteVec domain. Non-empty only for `json_entry`
    /// (the sv element type); the `json` container and `query_json` domains
    /// carry no term extractors — see `stevec_terms`.
    pub terms: Vec<TermInfo>,
    /// True for the family's one scalar-shaped member, the storage-only
    /// `public.eql_v3_json`. Consumers that describe SteVec capabilities
    /// (containment, path navigation) must not apply them to this domain: it
    /// stores and decrypts, nothing more.
    pub scalar: bool,
}

fn term_infos(terms: &[Term]) -> Vec<TermInfo> {
    terms
        .iter()
        .map(|t| TermInfo {
            key: t.json_key(),
            extractor: t.extractor(),
            ctor: t.ctor(),
        })
        .collect()
}

/// Index terms for one `json` (SteVec) domain, hardcoded for now.
///
/// The catalog does not model per-SteVec-entry terms — `JSON_DOMAINS` declare
/// `terms: &[]` and the `shape_and_terms_are_consistent` invariant fails CI if a
/// non-`Scalar` domain ever gains one — so `term_infos(d.terms)` is provably
/// empty here. Until the catalog carries them, source the real hand-written
/// extractors from `src/v3/json/{functions,operators}.sql`.
///
/// The sole entry term is `op`, read by `eql_v3.ord_term` for ordered
/// comparisons. Entry equality is blocked, and `hm` is retired from the SteVec
/// wire. The `json_search` document and `query_json` domains carry no term
/// extractors (their surface is containment `@>`/`<@` and path navigation), so
/// they return no terms. Keyed on the catalog domain name (`json`/`entry`/`query`).
fn stevec_terms(name: &str) -> Vec<TermInfo> {
    if name != "entry" {
        return Vec::new();
    }
    vec![TermInfo {
        key: "op",
        extractor: "ord_term",
        ctor: "ope_cllw",
    }]
}

/// Build the catalog surface description from `eql_domains::CATALOG`.
pub fn dump_catalog() -> CatalogDump {
    let types = eql_domains::scalar_families()
        .map(|spec| {
            let domains = spec
                .domains
                .iter()
                .map(|d| DomainEntry {
                    segment: if d.name.is_empty() {
                        "storage".to_string()
                    } else {
                        d.name.to_string()
                    },
                    typname: d.sql_typname(spec.name),
                    suffix: if d.name.is_empty() {
                        String::new()
                    } else {
                        format!("_{}", d.name)
                    },
                    supported_ops: Term::operators_for_terms(d.terms),
                    terms: term_infos(d.terms),
                })
                .collect();
            TypeEntry {
                token: spec.name,
                is_eq_only: spec.is_eq_only(),
                domains,
            }
        })
        .collect();

    // The hand-written SteVec (jsonb) family — catalog inventory only. Kept out
    // of `types` so scalar-only consumers (the fixture-coverage task) are
    // unaffected; the docs manifest reads both `types` and `stevec`.
    // The whole json family, scalar member included. This used to filter out
    // the bare `public.eql_v3_json` storage domain on the assumption it would
    // surface via `types` — but `types` iterates `scalar_families()`, which
    // excludes the mixed json family wholesale, so the domain appeared in
    // neither list and was missing from the docs manifest even though the SQL
    // materializer (`families_with_scalar_domains()`) creates it.
    let stevec = eql_domains::JSON
        .domains
        .iter()
        .map(|d| SteVecEntry {
            full_name: d.full_name(eql_domains::JSON.name),
            typname: d.sql_typname(eql_domains::JSON.name),
            name: d.name,
            // Catalog terms are empty for SteVec; hardcode per-domain — only
            // `json_entry` carries extractors (see stevec_terms).
            terms: stevec_terms(d.name),
            scalar: d.is_scalar(),
        })
        .collect();

    CatalogDump { types, stevec }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_exposes_all_ordered_domains_with_operators() {
        let dump = dump_catalog();
        let integer = dump
            .types
            .iter()
            .find(|t| t.token == "integer")
            .expect("integer present in catalog");
        assert!(!integer.is_eq_only, "integer is an ordered type");

        let segments: Vec<&str> = integer.domains.iter().map(|d| d.segment.as_str()).collect();
        assert_eq!(segments, ["storage", "eq", "ord_ore", "ord", "ord_ope"]);

        let storage = integer
            .domains
            .iter()
            .find(|d| d.segment == "storage")
            .unwrap();
        assert!(storage.supported_ops.is_empty(), "storage has no operators");

        let eq = integer.domains.iter().find(|d| d.segment == "eq").unwrap();
        assert_eq!(eq.supported_ops, ["=", "<>"]);

        let ord = integer.domains.iter().find(|d| d.segment == "ord").unwrap();
        assert_eq!(ord.supported_ops, ["=", "<>", "<", "<=", ">", ">="]);

        // Every ordered domain advertises the same operator set regardless of
        // which SEM backs it — only the term/extractor differ.
        let ord_ope = integer
            .domains
            .iter()
            .find(|d| d.segment == "ord_ope")
            .unwrap();
        assert_eq!(ord_ope.supported_ops, ["=", "<>", "<", "<=", ">", ">="]);
    }

    #[test]
    fn ordered_domain_exposes_its_extractor_and_ctor() {
        let dump = dump_catalog();
        let integer = dump.types.iter().find(|t| t.token == "integer").unwrap();

        // `_ord` is the OPE-backed default, reached by the unqualified extractor.
        let ord = integer.domains.iter().find(|d| d.segment == "ord").unwrap();
        assert_eq!(ord.terms.len(), 1);
        assert_eq!(ord.terms[0].key, "op");
        assert_eq!(ord.terms[0].extractor, "ord_term");
        assert_eq!(ord.terms[0].ctor, "ope_cllw");

        // `_ord_ore` keeps the block-ORE term, behind the qualified extractor.
        let ord_ore = integer
            .domains
            .iter()
            .find(|d| d.segment == "ord_ore")
            .unwrap();
        assert_eq!(ord_ore.terms.len(), 1);
        assert_eq!(ord_ore.terms[0].key, "ob");
        assert_eq!(ord_ore.terms[0].extractor, "ord_term_ore");
        assert_eq!(ord_ore.terms[0].ctor, "ore_block_256");
    }

    #[test]
    fn stevec_json_family_is_dumped() {
        let dump = dump_catalog();
        let names: Vec<&str> = dump.stevec.iter().map(|e| e.full_name.as_str()).collect();
        assert_eq!(names, ["json_search", "json_entry", "query_json", "json"]);

        // The bare storage domain is the family's one scalar member. It is
        // carried here — not in `types` — and flagged so consumers do not
        // describe it with the SteVec query surface.
        let scalars: Vec<&str> = dump
            .stevec
            .iter()
            .filter(|e| e.scalar)
            .map(|e| e.full_name.as_str())
            .collect();
        assert_eq!(scalars, ["json"]);

        let by_name = |n: &str| {
            dump.stevec
                .iter()
                .find(|e| e.full_name == n)
                .unwrap_or_else(|| panic!("{n} present"))
        };

        // The sole SteVec term extractor lives on `json_entry` (the sv element
        // type): `ord_term` reads `op`. Entry equality is blocked and `hm` is
        // not part of the v3 SteVec wire.
        let entry_extractors: Vec<&str> = by_name("json_entry")
            .terms
            .iter()
            .map(|t| t.extractor)
            .collect();
        assert_eq!(entry_extractors, ["ord_term"]);

        // The `json_search` document and `query_json` needle carry no term
        // extractors — their surface is containment (@>, <@) and path nav.
        assert!(by_name("json_search").terms.is_empty());
        assert!(by_name("query_json").terms.is_empty());
    }

    /// Pins the hand-re-derived `suffix` wire field — the one channel with no
    /// other automated reader — so its underscore-prefixed values stay
    /// byte-stable after the catalog dropped the leading underscore from its
    /// stored (now bare) domain names.
    #[test]
    fn integer_suffix_field_is_underscore_prefixed() {
        let dump = dump_catalog();
        let integer = dump
            .types
            .iter()
            .find(|t| t.token == "integer")
            .expect("integer present in catalog");

        let suffixes: Vec<&str> = integer.domains.iter().map(|d| d.suffix.as_str()).collect();
        assert_eq!(suffixes, ["", "_eq", "_ord_ore", "_ord", "_ord_ope"]);
    }

    #[test]
    fn timestamp_is_ordered() {
        // timestamp was promoted to the ordered shape once
        // `compare_ore_block_256_term` generalized to N blocks (see #284 / the
        // `EQ_ONLY_DOMAINS` note in `eql-domains`). It now mirrors integer's
        // four-domain ordered surface.
        let dump = dump_catalog();
        let ts = dump
            .types
            .iter()
            .find(|t| t.token == "timestamp")
            .expect("timestamp present in catalog");
        assert!(!ts.is_eq_only, "timestamp is an ordered type");

        let segments: Vec<&str> = ts.domains.iter().map(|d| d.segment.as_str()).collect();
        assert_eq!(segments, ["storage", "eq", "ord_ore", "ord", "ord_ope"]);

        let ord = ts.domains.iter().find(|d| d.segment == "ord").unwrap();
        assert_eq!(ord.supported_ops, ["=", "<>", "<", "<=", ">", ">="]);
    }

    #[test]
    fn dump_catalog_excludes_non_scalar_json() {
        // `dump_catalog` (and, via the same `scalar_families()` filter, the CLI
        // `list-types` / `dump-catalog` output the scalar-matrix tooling consumes)
        // must NOT surface the mixed `json` family in `types`: its SteVec domains
        // have no `scalars::json::*` matrix, even though its domain names
        // (`public.eql_v3_json_entry` / `eql_v3.query_json`) follow the
        // family+suffix string convention — the SteVec payload shape is still not
        // flat, and the family is non-scalar. (Its bare storage domain IS
        // generated, but storage-only types carry no operator matrix, so `json`
        // stays out of `types`.) This pins the exclusion directly at the codegen
        // surface rather than relying only on the transitive `scalar_families()`
        // guard in `eql-domains`.
        let dump = dump_catalog();
        assert!(
            !dump.types.iter().any(|t| t.token == "json"),
            "dump_catalog must exclude the non-scalar json family, got tokens: {:?}",
            dump.types.iter().map(|t| t.token).collect::<Vec<_>>()
        );
        // Sanity: the scalar families are still present (the filter isn't empty).
        assert!(dump.types.iter().any(|t| t.token == "integer"));
    }
}
