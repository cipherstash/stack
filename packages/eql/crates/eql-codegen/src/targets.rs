//! The target-dispatch emitter: renders `eql_domains::CATALOG` to the
//! committed `crates/eql-bindings/src/v3/targets.rs` — the table of EQL
//! types a Stack Encrypt data plan may name as a field target, and the
//! by-name dispatch that runs a named type's own Rust plan. Generated beside
//! `inventory.rs` by the same mechanism ([`crate::bindings`]), and gated to
//! the `stack-encrypt` feature by the hand-written `v3/mod.rs`.
//!
//! The table is the stack-encrypt view of the catalog: for every stored
//! domain, the type's name in every language (`TextEq`), its family and
//! suffix, the plaintext kind it accepts, the indexes it carries, its query
//! twin, and whether the engine can produce it today — with the reason when
//! not. The dispatch has an arm for exactly the producible types, which are
//! exactly the domains carrying the `stack-encrypt` derives
//! ([`bindings::ENCRYPTION_DOMAINS`](crate::bindings::ENCRYPTION_DOMAINS)):
//! an arm runs `<T as EncryptFrom<S>>::encryption()`, which only exists with
//! the derive, and [`target_gap`] is tested to agree with
//! [`encryption_gap`](crate::bindings::encryption_gap) on every domain.
//!
//! The reasons a type is not producible are the plan's
//! (`docs/plans/2026-10-04-plan-builder.md`, "EQL types"): every family but
//! text has no specified plaintext encoding; match and OPE terms are derived
//! but no EQL type is built from them; EQL's ORE term is block ORE where the
//! engine derives CLLW ORE; and the JSON index is a new engine operation.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use eql_domains::{Domain, DomainFamily, Shape, Term};

use crate::bindings::{encryption_gap, format_rs, stored_payload_domains};

/// The `IndexSpec::key()` a catalog term rides under in a plan — the
/// `"eq"` / `"match"` / `"ore"` / `"ope"` strings of stack-encrypt's data
/// grammar — so a Go generator can match a target's indexes against the
/// indexes a plan field may ask for by the same names. Exhaustive on
/// purpose: a new catalog term must say which engine index it is.
pub fn index_key(term: Term) -> &'static str {
    match term {
        Term::Hm => "eq",
        Term::Bloom => "match",
        Term::Ore => "ore",
        Term::Ope => "ope",
    }
}

/// The index a SteVec document carries: the engine's JSON index, which has
/// no catalog `Term` because its terms live per `sv` leaf, not as flat
/// payload keys.
const JSON_INDEX_KEY: &str = "json";

/// The plaintext a family's domains are produced from, as a vitaminc
/// `ValueKind` name (what a plan field's `"type"` key spells) and the Rust
/// type the generated dispatch names. `None` while the family's plaintext
/// encoding for the stack-encrypt producer profile is unspecified, which is
/// every family but text today.
pub fn plaintext(family: &DomainFamily) -> Option<(&'static str, &'static str)> {
    plaintext_of(family.name)
}

/// [`plaintext`], by family name: what a rendered row carries.
fn plaintext_of(family: &str) -> Option<(&'static str, &'static str)> {
    (family == "text").then_some(("string", "String"))
}

/// Why the engine cannot produce a stored domain's EQL type today, or
/// `None` when it can. `None` exactly when the domain carries the
/// `stack-encrypt` derives ([`encryption_gap`]), because the dispatch runs
/// the derived plan; the reasons are the plan's, keyed on catalog facts so
/// a domain added tomorrow gets an answer.
pub fn target_gap(family: &DomainFamily, domain: &Domain) -> Option<&'static str> {
    encryption_gap(family, domain)?;
    Some(if matches!(domain.shape, Shape::SteVec) {
        "the JSON index is a new operation in the engine"
    } else if family.name != "text" {
        "how this family encodes a plaintext for the stack-encrypt producer profile is not \
         specified; only the text family's encoding is"
    } else if domain.terms.contains(&Term::Ore) {
        "EQL stores a block ORE term and the engine derives a CLLW ORE term; the two are \
         different algorithms"
    } else if domain
        .terms
        .iter()
        .any(|t| matches!(t, Term::Bloom | Term::Ope))
    {
        "the engine derives match and OPE terms, but no EQL type is built from them yet"
    } else if domain.terms.is_empty() {
        "the storage-only text domain follows once TextEq is proven end to end in PostgreSQL"
    } else {
        "an equality-only text domain derives the same way TextEq does; it is not listed in \
         ENCRYPTION_DOMAINS yet"
    })
}

/// One row of the generated table, computed from the catalog: what both
/// the Rust `TARGETS` table and the Go `encrypt/eql` package
/// ([`crate::go_eql`]) are rendered from, so the two cannot disagree.
pub(crate) struct Row {
    pub(crate) name: String,
    pub(crate) family: &'static str,
    pub(crate) suffix: String,
    pub(crate) plaintext: Option<&'static str>,
    pub(crate) sql_domain: String,
    pub(crate) indexes: Vec<&'static str>,
    /// The query twin's struct identifier and SQL domain, if the type
    /// answers a query.
    pub(crate) query: Option<(String, String)>,
    pub(crate) reason: Option<&'static str>,
}

/// Every row, in catalog order: one per stored domain.
pub(crate) fn rows() -> Vec<Row> {
    stored_payload_domains().map(|(f, d)| row(f, d)).collect()
}

/// The PascalCase of a bare domain name — `TextOrdOre` is family `text`,
/// suffix `OrdOre`; the storage domain's suffix is empty. The same mangler
/// as the struct identifier, run over the bare name alone: a scalar-shaped
/// `Domain` under an empty family name is `_<name>`, and `struct_ident`
/// drops the empty segment.
fn suffix(domain: &Domain) -> String {
    Domain {
        name: domain.name,
        terms: &[],
        shape: Shape::Scalar,
    }
    .struct_ident("")
}

fn row(family: &'static DomainFamily, domain: &'static Domain) -> Row {
    let is_stevec = matches!(domain.shape, Shape::SteVec);
    let indexes = if is_stevec {
        vec![JSON_INDEX_KEY]
    } else {
        Term::payload_terms(domain.terms)
            .into_iter()
            .map(index_key)
            .collect()
    };
    let query = if is_stevec {
        // The containment needle is the document's query form. Its struct
        // is the hand-written `SteVecQuery`; its domain is the family's
        // `query` domain (`eql_v3.query_json`), read from the catalog so
        // the name is spelled once.
        family
            .domains
            .iter()
            .find(|d| matches!(d.shape, Shape::SteVec) && d.name == "query")
            .map(|needle| {
                (
                    needle.rust_struct_name(family.name),
                    format!("eql_v3.{}", needle.full_name(family.name)),
                )
            })
    } else if domain.terms.is_empty() {
        None
    } else {
        Some((
            format!("{}Query", domain.struct_ident(family.name)),
            format!("eql_v3.{}", domain.query_name(family.name)),
        ))
    };
    Row {
        name: domain.rust_struct_name(family.name),
        family: family.name,
        suffix: suffix(domain),
        plaintext: plaintext(family).map(|(kind, _)| kind),
        sql_domain: format!("public.{}", domain.sql_typname(family.name)),
        indexes,
        query,
        reason: target_gap(family, domain),
    }
}

fn option_str(value: Option<&str>) -> TokenStream {
    match value {
        Some(s) => quote!(Some(#s)),
        None => quote!(None),
    }
}

/// Render the generated `crates/eql-bindings/src/v3/targets.rs`.
pub fn render_targets_rs() -> String {
    render_targets_from(&rows())
}

/// Render the target table and dispatch from the given rows: the catalog's
/// in [`render_targets_rs`], a synthetic set in tests (a producible type
/// with no query twin is not in the catalog today).
fn render_targets_from(rows: &[Row]) -> String {
    let entries: TokenStream = rows
        .iter()
        .map(|r| {
            let name = &r.name;
            let family = r.family;
            let suffix = &r.suffix;
            let plaintext = option_str(r.plaintext);
            let sql_domain = &r.sql_domain;
            let indexes = &r.indexes;
            let query = option_str(r.query.as_ref().map(|(n, _)| n.as_str()));
            let query_sql_domain = option_str(r.query.as_ref().map(|(_, d)| d.as_str()));
            let producible = r.reason.is_none();
            let reason = option_str(r.reason);
            quote! {
                Target {
                    name: #name,
                    family: #family,
                    suffix: #suffix,
                    plaintext: #plaintext,
                    sql_domain: #sql_domain,
                    indexes: &[#(#indexes),*],
                    query: #query,
                    query_sql_domain: #query_sql_domain,
                    producible: #producible,
                    reason: #reason,
                },
            }
        })
        .collect();

    // One arm per producible type. The plaintext Rust type is the family's;
    // a producible family always has one, since a derive names it.
    let producible: Vec<&Row> = rows.iter().filter(|r| r.reason.is_none()).collect();
    let arm = |r: &Row, strukt: &str| {
        let name = &r.name;
        let module = format_ident!("{}", r.family);
        let ty = format_ident!("{strukt}");
        let (_, rust) =
            plaintext_of(r.family).expect("a producible family has a specified plaintext");
        let source = format_ident!("{rust}");
        (name.clone(), quote!(super::#module::#ty), quote!(#source))
    };
    let encrypt_arms: TokenStream = producible
        .iter()
        .map(|r| {
            let (name, ty, source) = arm(r, &r.name);
            quote! { #name => run_target::<#ty, #source, K>(#name, keyset, column, plaintext), }
        })
        .collect();
    let decrypt_arms: TokenStream = producible
        .iter()
        .map(|r| {
            let (name, ty, source) = arm(r, &r.name);
            quote! { #name => open_target::<#ty, #source, K>(#name, opener, column, stored), }
        })
        .collect();
    // A producible type with no query twin (a storage-only domain) gets no
    // query arm: the fall-through refuses it as answering no query.
    let query_arms: TokenStream = producible
        .iter()
        .filter_map(|r| {
            let (query, _) = r.query.as_ref()?;
            let (name, ty, source) = arm(r, query);
            Some(quote! { #name => run_target::<#ty, #source, K>(#name, keyset, column, plaintext), })
        })
        .collect();
    let helpers = if producible.is_empty() {
        quote!()
    } else {
        quote!(open_target, run_target,)
    };

    let mod_doc = " The EQL types a Stack Encrypt data plan may name as a field target — \
                   every stored v3 domain type in eql-domains::CATALOG order, as data a \
                   guest serializes (`TARGETS`), with the by-name dispatch that runs a \
                   producible type's own Rust plan. Generated from the catalog; the \
                   descriptor type, the errors and the public entry points stay \
                   hand-written in `crate::encryption::targets`, which documents the \
                   wire format.";

    let file = quote! {
        #![doc = #mod_doc]

        use vitaminc_aead_value::FfiValue;

        use crate::encryption::targets::{#helpers refuse, refuse_query, Opener, Target, TargetError};
        use crate::Identifier;
        use stack_encrypt::{KeysetCipher, NonEmpty, Pending};

        /// Every EQL type a plan may name as a target, in
        /// `eql-domains::CATALOG` order: one per stored domain (every flat
        /// scalar domain plus the SteVec document). Query twins are not
        /// targets; each row names its own under `query`.
        pub const TARGETS: &[Target] = &[
            #entries
        ];

        /// Run the named type's own encryption plan for one field, or refuse
        /// the name: the type is not producible (`TargetError::Unproducible`)
        /// or does not exist (`TargetError::Unknown`).
        pub(crate) fn encrypt_named<'a, K: 'static>(
            name: &str,
            keyset: &'a KeysetCipher<'_, K>,
            column: NonEmpty<Identifier>,
            plaintext: FfiValue,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            match name {
                #encrypt_arms
                _ => Err(refuse(name)),
            }
        }

        /// Open a stored value of the named type back to its plaintext, or
        /// refuse the name as `encrypt_named` does.
        pub(crate) fn decrypt_named<'a, K: 'static>(
            name: &str,
            opener: Opener<'a, K>,
            column: NonEmpty<Identifier>,
            stored: &[u8],
        ) -> Result<Pending<'a, FfiValue, K>, TargetError> {
            match name {
                #decrypt_arms
                _ => Err(refuse(name)),
            }
        }

        /// Run the named type's query twin for one plaintext, or refuse the
        /// name: as `encrypt_named` does, or as answering no query
        /// (`TargetError::NoQuery`) for a producible type with no twin.
        pub(crate) fn query_named<'a, K: 'static>(
            name: &str,
            keyset: &'a KeysetCipher<'_, K>,
            column: NonEmpty<Identifier>,
            plaintext: FfiValue,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            match name {
                #query_arms
                _ => Err(refuse_query(name)),
            }
        }
    };

    format_rs(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::ENCRYPTION_DOMAINS;

    /// The dispatch runs a derived plan, so a type is producible exactly
    /// when its domain carries the derive. The two answers come from two
    /// functions; this is what holds them together.
    #[test]
    fn a_target_is_producible_exactly_when_its_domain_has_a_derive() {
        let mut producible = Vec::new();
        for (family, domain) in stored_payload_domains() {
            let full = domain.full_name(family.name);
            assert_eq!(
                target_gap(family, domain).is_none(),
                encryption_gap(family, domain).is_none(),
                "{full}: producible and derived must agree"
            );
            if target_gap(family, domain).is_none() {
                producible.push((family.name, domain.name));
                assert!(
                    plaintext(family).is_some(),
                    "{full}: a producible family names its plaintext"
                );
            }
        }
        assert_eq!(
            producible,
            ENCRYPTION_DOMAINS.to_vec(),
            "the producible set is the derived set"
        );
    }

    /// Every reason is the plan's reason for that domain, selected by the
    /// catalog fact that applies: a wrong branch order would hand the ORE
    /// reason to `text_search` or the encoding reason to a text domain.
    #[test]
    fn every_unproducible_target_has_the_plan_reason_for_its_domain() {
        for (family, domain) in stored_payload_domains() {
            let full = domain.full_name(family.name);
            let Some(reason) = target_gap(family, domain) else {
                continue;
            };
            let expected = if matches!(domain.shape, Shape::SteVec) {
                "JSON index"
            } else if family.name != "text" {
                "encodes a plaintext"
            } else if domain.terms.contains(&Term::Ore) {
                "block ORE"
            } else if domain
                .terms
                .iter()
                .any(|t| matches!(t, Term::Bloom | Term::Ope))
            {
                "match and OPE terms"
            } else {
                assert!(
                    domain.terms.is_empty(),
                    "{full}: an hm-only text domain other than eq is not in the catalog"
                );
                "storage-only text domain"
            };
            assert!(reason.contains(expected), "{full}: {reason}");
        }
        // Spelled out for the four plan rows, so the table reads without
        // the derivation above.
        let text = eql_domains::TEXT;
        let by_name = |name: &str| text.domain_by_name(name).expect("text domain");
        assert!(target_gap(&text, by_name("ord_ore"))
            .unwrap()
            .contains("CLLW"));
        assert!(target_gap(&text, by_name("search_ore"))
            .unwrap()
            .contains("CLLW"));
        assert!(target_gap(&text, by_name("match"))
            .unwrap()
            .contains("no EQL type"));
        assert!(target_gap(&text, by_name("ord"))
            .unwrap()
            .contains("no EQL type"));
        assert!(target_gap(&text, by_name("ord_ope"))
            .unwrap()
            .contains("no EQL type"));
        assert!(target_gap(&text, by_name("search"))
            .unwrap()
            .contains("no EQL type"));
        assert!(
            target_gap(&text, by_name("eq")).is_none(),
            "TextEq is producible"
        );
    }

    #[test]
    fn index_keys_are_the_engine_index_spec_keys() {
        // The `IndexSpec::key()` strings of stack-encrypt's data grammar;
        // a plan field spells an index by exactly these.
        assert_eq!(index_key(Term::Hm), "eq");
        assert_eq!(index_key(Term::Bloom), "match");
        assert_eq!(index_key(Term::Ore), "ore");
        assert_eq!(index_key(Term::Ope), "ope");
    }

    #[test]
    fn suffix_is_the_pascal_case_of_the_bare_domain_name() {
        let text = eql_domains::TEXT;
        let by_name = |name: &str| text.domain_by_name(name).expect("text domain");
        assert_eq!(suffix(by_name("")), "");
        assert_eq!(suffix(by_name("eq")), "Eq");
        assert_eq!(suffix(by_name("ord_ore")), "OrdOre");
        assert_eq!(suffix(by_name("search_ore")), "SearchOre");
    }

    #[test]
    fn rendered_table_names_every_stored_domain_and_dispatches_the_producible_ones() {
        let rendered = render_targets_rs();
        assert!(rendered.starts_with(crate::consts::RUST_GENERATED_MARKER));
        // rustfmt wraps a long arm over several lines; compare on one
        // whitespace-collapsed line so the assertions below do not depend on
        // where it broke.
        let out: String = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
        // One row per stored domain, in catalog order, named as the struct.
        let mut last = 0;
        for (family, domain) in stored_payload_domains() {
            let needle = format!("name: \"{}\",", domain.rust_struct_name(family.name));
            let at = out[last..]
                .find(&needle)
                .unwrap_or_else(|| panic!("{needle} missing or out of order"));
            last += at + needle.len();
        }
        // The SteVec document carries the JSON index and the containment
        // needle as its query form; the scalar storage domain carries none.
        assert!(out.contains("name: \"SteVecDocument\""));
        assert!(out.contains("indexes: &[\"json\"]"));
        assert!(out.contains("query: Some(\"SteVecQuery\")"));
        assert!(out.contains("query_sql_domain: Some(\"eql_v3.query_json\")"));
        assert!(out.contains("sql_domain: \"public.eql_v3_text_eq\""));
        assert!(out.contains("query_sql_domain: Some(\"eql_v3.query_text_eq\")"));
        // Exactly the producible types have dispatch arms, in all three
        // dispatches, and the query dispatch names the query twin.
        for (family, domain) in ENCRYPTION_DOMAINS.iter().map(|(f, d)| {
            let family = eql_domains::CATALOG
                .iter()
                .find(|x| x.name == *f)
                .expect("family");
            (family, family.domain_by_name(d).expect("domain"))
        }) {
            let name = domain.rust_struct_name(family.name);
            let module = family.name;
            let arm = |helper: &str, ty: &str| {
                format!(
                    "\"{name}\" => {{ {helper}::<super::{module}::{ty}, String, K>(\"{name}\", "
                )
            };
            let flat_arm = |helper: &str, ty: &str| {
                format!("\"{name}\" => {helper}::<super::{module}::{ty}, String, K>(\"{name}\", ")
            };
            let count = |helper: &str, ty: &str| {
                out.matches(&arm(helper, ty)).count() + out.matches(&flat_arm(helper, ty)).count()
            };
            assert_eq!(count("run_target", &name), 1, "{name}: one encrypt arm");
            assert_eq!(count("open_target", &name), 1, "{name}: one decrypt arm");
            assert_eq!(
                count("run_target", &format!("{name}Query")),
                1,
                "{name}: one query arm"
            );
        }
        // No unproducible type has an arm: the only `=>` arms are the
        // producible ones and the three fall-throughs.
        let arms = out.matches("\" => ").count();
        assert_eq!(arms, ENCRYPTION_DOMAINS.len() * 3, "arms: {out}");
        assert_eq!(out.matches("_ => Err(refuse(name))").count(), 2);
        assert_eq!(out.matches("_ => Err(refuse_query(name))").count(), 1);
    }

    /// A producible type with no query twin — a storage-only domain, once
    /// its derive lands — renders encrypt and decrypt arms and no query arm,
    /// rather than aborting the generator: the query dispatch's fall-through
    /// refuses it as answering no query. Not in the catalog today, so the
    /// row is flipped by hand.
    #[test]
    fn a_producible_type_without_a_query_twin_gets_no_query_arm() {
        let mut rows = rows();
        let text = rows
            .iter_mut()
            .find(|r| r.name == "Text")
            .expect("the storage-only text domain");
        assert!(text.query.is_none() && text.reason.is_some());
        text.reason = None;
        let out: String = render_targets_from(&rows)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let arms_for = |helper: &str| {
            out.matches(&format!(
                "\"Text\" => {{ {helper}::<super::text::Text, String, K>(\"Text\","
            ))
            .count()
                + out
                    .matches(&format!(
                        "\"Text\" => {helper}::<super::text::Text, String, K>(\"Text\","
                    ))
                    .count()
        };
        assert_eq!(arms_for("run_target"), 1, "one encrypt arm: {out}");
        assert_eq!(arms_for("open_target"), 1, "one decrypt arm: {out}");
        assert!(
            !out.contains("TextQuery"),
            "no query arm for a type with no twin: {out}"
        );
        assert_eq!(
            out.matches("\" => ").count(),
            (ENCRYPTION_DOMAINS.len() + 1) * 3 - 1,
            "every producible type has three arms but the twinless one, which has two"
        );
    }
}
