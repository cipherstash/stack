//! The target-dispatch emitter: renders `eql_domains::CATALOG` to the
//! committed `crates/eql-bindings/src/v4/targets.rs` — the table of EQL
//! types a Stack Encrypt data plan may name as a field target, and the
//! by-name dispatch that runs a named type's own Rust plan. Generated beside
//! the v4 family modules by the same mechanism ([`crate::bindings`]), and
//! under the `targets` feature, inside `v4`.
//! Stack Encrypt produces EQL v4 only (ADR-0002), so every target is an
//! `eql_v4_*` domain.
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
//! The same rows give the operators each producible type answers in Stack
//! Encrypt's typed query chain ([`answers_for_indexes`]), rendered to
//! `v4/answers.rs` ([`render_answers_rs`]) under the `stack-encrypt` feature
//! alone: it implements `op::Answers` for each, with the type's query twin as
//! the query term, and lists them in `ANSWERS` so the encryption tests can
//! hold them to the operators the engine's data path answers for the same
//! type. A producible type whose twin carries an order index, or more than
//! one index, answers nothing there yet ([`typed_gap`]): the chain sends one
//! index's term as the twin, and those twins need an order term, or several
//! terms at once.
//!
//! The reasons a type is not producible: eql-bindings names no Rust
//! plaintext type for the family, and the JSON index is a new engine
//! operation. Each reason string names the issue that tracks it.
//!
//! The query dispatch takes the index that answers the query's operator. A
//! twin whose terms are optional in EQL v4 (`TextSearchQuery`) is built
//! through the projection for that index, so it carries that term alone.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use eql_domains::{Domain, DomainFamily, Shape, Term};

use crate::bindings::{
    encryption_gap, format_rs, plaintext_of, query_projection_ident, stored_payload_domains,
};
use crate::context::v4_optional_query_terms;
use crate::render::EqlVersion;

/// The version every target is produced into.
const TARGET_VERSION: EqlVersion = EqlVersion::V4;

/// The `IndexSpec::key()` a catalog term rides under in a plan — the
/// `"eq"` / `"match"` / `"ore_block"` / `"ope"` strings of stack-encrypt's
/// data grammar — so a Go generator can match a target's indexes against the
/// indexes a plan field may ask for by the same names. Exhaustive on
/// purpose: a new catalog term must say which engine index it is.
///
/// EQL's `ob` term is block ORE, the engine's `ore_block` index (ore-rs's
/// 6-bit schemes), not its `ore` index, which is CLLW ORE and has no EQL
/// domain.
pub fn index_key(term: Term) -> &'static str {
    match term {
        Term::Hm => "eq",
        Term::Bloom => "match",
        Term::Ore => "ore_block",
        Term::Ope => "ope",
    }
}

/// The index a SteVec document carries: the engine's JSON index, which has
/// no catalog `Term` because its terms live per `sv` leaf, not as flat
/// payload keys.
const JSON_INDEX_KEY: &str = "json";

/// An operator a producible EQL type answers in Stack Encrypt's typed query
/// chain: what the generated file implements `op::Answers` for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// `op::Eq`, through the equality index.
    Eq,
    /// `op::Matches`, through the match index under EQL's configuration.
    Matches,
}

impl Answer {
    /// The operator's wire name, `stack_encrypt::dynamic::OpSpec::name`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Answer::Eq => "eq",
            Answer::Matches => "matches",
        }
    }

    /// The catalog term the operator's index derives: the one term the
    /// query twin carries, under its JSON key.
    pub(crate) fn term(self) -> Term {
        match self {
            Answer::Eq => Term::Hm,
            Answer::Matches => Term::Bloom,
        }
    }
}

/// Why the typed query chain has no answer yet for a type carrying these
/// indexes, by [`index_key`] name, or `None` when it answers: a query twin
/// is assembled from the one term its type's index derived, so a twin that
/// needs an order term (`"ore"`, `"ore_block"` or `"ope"`), or more than one term, is not
/// built by it. The reason is the generator's, for its tests and docs; the
/// generated file simply leaves the type out.
pub(crate) fn typed_gap(indexes: &[&str]) -> Option<&'static str> {
    if indexes
        .iter()
        .any(|key| matches!(*key, "ore" | "ore_block" | "ope"))
    {
        Some("its twin carries an order term, which the typed query chain does not derive yet")
    } else if indexes.len() > 1 {
        Some("its twin carries more than one term, which the typed query chain does not assemble yet")
    } else {
        None
    }
}

/// The operators a producible type with a query twin answers, given the
/// indexes it carries by [`index_key`] name, the same input the engine's
/// table reads: `Eq` for the `"eq"` index and `Matches` for the `"match"`
/// index, as `OpSpec::answered_by` answers a field that names the type
/// (`TargetDescriptor::operators`). Empty for a type the chain has no
/// answer for yet ([`typed_gap`]). The encryption tests compare the two,
/// type by type, and hold the gap to exactly those types.
///
/// # Panics
///
/// On an index key the generator does not know: a new catalog term must say
/// what the typed query chain does with it.
pub(crate) fn answers_for_indexes(name: &str, indexes: &[&str]) -> Vec<Answer> {
    if typed_gap(indexes).is_some() {
        return Vec::new();
    }
    indexes
        .iter()
        .map(|key| match *key {
            "eq" => Answer::Eq,
            "match" => Answer::Matches,
            other => panic!(
                "{name}: the typed query chain has no rule for the {other} index; extend \
                 eql-codegen's answers_for_indexes and typed_gap"
            ),
        })
        .collect()
}

/// The plaintext a family's domains are produced from: see
/// [`bindings::plaintext_of`](crate::bindings::plaintext_of).
pub fn plaintext(family: &DomainFamily) -> Option<(&'static str, &'static str)> {
    plaintext_of(family.name)
}

/// Why the engine cannot produce a stored domain's EQL type today, or
/// `None` when it can: exactly when the v4 domain carries the
/// `stack-encrypt` derives, because the dispatch runs the derived plan, so
/// the one source of reasons is [`encryption_gap`].
pub fn target_gap(family: &DomainFamily, domain: &Domain) -> Option<&'static str> {
    encryption_gap(TARGET_VERSION, family, domain)
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
    /// For a query twin whose terms are optional in EQL v4, the projection
    /// that builds it for each index, by the index's key: the query dispatch
    /// runs the one for the index that answers the query's operator.
    /// Empty for every other twin, whose plan derives all its terms.
    pub(crate) projections: Vec<(&'static str, String)>,
    pub(crate) reason: Option<&'static str>,
    /// The operators the type answers in the typed query chain: none
    /// unless it is producible and has a query twin ([`answers_for_indexes`]).
    pub(crate) answers: Vec<Answer>,
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
        // `query` domain (`eql_v4.query_json`), read from the catalog so
        // the name is spelled once. v4 has no compiled SteVec types yet, so
        // these rows are never producible.
        family
            .domains
            .iter()
            .find(|d| matches!(d.shape, Shape::SteVec) && d.name == "query")
            .map(|needle| {
                (
                    needle.rust_struct_name(family.name),
                    format!(
                        "{}.{}",
                        TARGET_VERSION.prefix(),
                        needle.full_name(family.name)
                    ),
                )
            })
    } else if domain.terms.is_empty() {
        None
    } else {
        Some((
            format!("{}Query", domain.struct_ident(family.name)),
            format!(
                "{}.{}",
                TARGET_VERSION.prefix(),
                domain.query_name(family.name)
            ),
        ))
    };
    let name = domain.rust_struct_name(family.name);
    let reason = target_gap(family, domain);
    let answers = if reason.is_none() && query.is_some() {
        answers_for_indexes(&name, &indexes)
    } else {
        Vec::new()
    };
    Row {
        name,
        family: family.name,
        suffix: suffix(domain),
        plaintext: plaintext(family).map(|(kind, _)| kind),
        sql_domain: format!(
            "public.{}_{}",
            TARGET_VERSION.prefix(),
            domain.full_name(family.name)
        ),
        indexes,
        query,
        projections: if !is_stevec && v4_optional_query_terms(domain) {
            Term::payload_terms(domain.terms)
                .into_iter()
                .map(|term| {
                    (
                        index_key(term),
                        query_projection_ident(family, domain, term),
                    )
                })
                .collect()
        } else {
            Vec::new()
        },
        reason,
        answers,
    }
}

/// The typed query chain's impls for one type that answers an operator:
/// its query twin's assembly from the one term it carries, `QueryTerm` on
/// the twin when an exact operator returns it as is, and one `op::Answers`
/// per operator, through Stack Encrypt's index for it, sent as the twin.
fn answer_impls(r: &Row) -> TokenStream {
    let module = format_ident!("{}", r.family);
    let ty = format_ident!("{}", r.name);
    let (twin_name, twin_domain) = r
        .query
        .as_ref()
        .expect("a type that answers an operator has a query twin");
    let twin = format_ident!("{twin_name}");
    let (_, rust) = plaintext_of(r.family).expect("a producible family has a specified plaintext");
    let source: syn::Path = syn::parse_str(rust).expect("a family's Rust plaintext is a type path");
    // `answers_for_indexes` admits one index, so every operator's term is
    // the same.
    let term = r.answers[0].term();
    let field = format_ident!("{}", term.json_key());
    let newtype = format_ident!("{}", term.binding_newtype());
    let assemble_doc = format!(
        " `{twin_name}` from the column it queries and its `{}` term, at version 4.",
        term.json_key()
    );
    let labelled_doc = format!(
        " `{}` is sealed under the column a two-segment label names, so its plan is \
         queried under the plan's label.",
        r.name
    );
    let mut out = quote! {
        #[doc = #labelled_doc]
        impl op::LabelledTarget for super::#module::#ty {}
        #[doc = #assemble_doc]
        impl QueryTwin<#newtype> for super::#module::#twin {
            type Plaintext = #source;
            fn assemble(i: Identifier, #field: #newtype) -> Self {
                Self { v: SchemaVersion::default(), i, #field }
            }
        }
    };
    for answer in &r.answers {
        let name = &r.name;
        let (op, via, doc) = match answer {
            Answer::Eq => {
                let term_doc =
                    format!(" `{twin_name}` is exact: the query term of `{name}`'s `op::Eq`.");
                out.extend(quote! {
                    #[doc = #term_doc]
                    impl op::QueryTerm for super::#module::#twin {}
                });
                (
                    quote!(op::Eq),
                    quote!(TwinIndex<Equality, super::#module::#twin>),
                    format!(
                        " `{name}` answers `op::Eq` through its equality index. The query \
                         term is `{twin_name}`, bound as `{twin_domain}`."
                    ),
                )
            }
            Answer::Matches => (
                quote!(op::Matches),
                quote!(TwinIndex<Match<EqlMatch>, super::#module::#twin>),
                format!(
                    " `{name}` answers `op::Matches` through its match index, under \
                     `EqlMatch`. The query term is a `MatchTwin<{twin_name}>`: the twin, \
                     bound as `{twin_domain}`, and the tokens that verify a row."
                ),
            ),
        };
        out.extend(quote! {
            #[doc = #doc]
            impl op::Answers<#op, #source> for super::#module::#ty {
                type Via = #via;
            }
        });
    }
    out
}

fn option_str(value: Option<&str>) -> TokenStream {
    match value {
        Some(s) => quote!(Some(#s)),
        None => quote!(None),
    }
}

/// Render the generated `crates/eql-bindings/src/v4/targets.rs`.
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
        // Named by its last segment: the file imports every plaintext path.
        let source = format_ident!("{}", rust.rsplit("::").next().unwrap_or(rust));
        (name.clone(), quote!(super::#module::#ty), quote!(#source))
    };
    // A type whose terms a null has (none, or equality's alone) seals,
    // opens and queries an `Option` of its plaintext: a value exactly as the
    // plaintext does, and a null as a null with a null's terms (#1298).
    // Whether a field may hold one is its plan's.
    let stored_source = |r: &Row, source: TokenStream| {
        if r.indexes.iter().all(|index| *index == "eq") {
            quote!(Option<#source>)
        } else {
            source
        }
    };
    let encrypt_arms: TokenStream = producible
        .iter()
        .map(|r| {
            let (name, ty, source) = arm(r, &r.name);
            let source = stored_source(r, source);
            quote! { #name => run_target::<#ty, #source, K>(#name, keyset, column, plaintext), }
        })
        .collect();
    let decrypt_arms: TokenStream = producible
        .iter()
        .map(|r| {
            let (name, ty, source) = arm(r, &r.name);
            let source = stored_source(r, source);
            quote! { #name => open_target::<#ty, #source, K>(#name, opener, column, stored), }
        })
        .collect();
    // A producible type with no query twin (a storage-only domain) gets no
    // query arm: the fall-through refuses it as answering no query.
    //
    // A twin whose terms are optional is built through the projection of
    // the index that answers the query's operator, and carries that term
    // alone; any other index is one the type does not carry, which
    // `encryption::targets::query` refuses before dispatching here.
    let query_arms: TokenStream = producible
        .iter()
        .filter_map(|r| {
            let (query, _) = r.query.as_ref()?;
            let (name, ty, source) = arm(r, query);
            let source = stored_source(r, source);
            if r.projections.is_empty() {
                return Some(
                    quote! { #name => run_target::<#ty, #source, K>(#name, keyset, column, plaintext), },
                );
            }
            let by_index: TokenStream = r
                .projections
                .iter()
                .map(|(key, projection)| {
                    let (_, projection, _) = arm(r, projection);
                    quote! {
                        #key => run_projected::<#projection, #ty, #source, K>(#name, keyset, column, plaintext),
                    }
                })
                .collect();
            Some(quote! {
                #name => match index.key() {
                    #by_index
                    _ => Err(no_index(#name, index)),
                },
            })
        })
        .collect();
    let projected = producible.iter().any(|r| !r.projections.is_empty());
    let index_param = if projected {
        quote!(index)
    } else {
        quote!(_index)
    };
    // One `use` per plaintext a producible type names by path (`String` is
    // in the prelude), so the arms stay short enough to read.
    let mut imports: Vec<&str> = producible
        .iter()
        .filter_map(|r| plaintext_of(r.family).map(|(_, rust)| rust))
        .filter(|rust| rust.contains("::"))
        .collect();
    imports.sort_unstable();
    imports.dedup();
    let imports: TokenStream = imports
        .iter()
        .map(|rust| {
            let path: syn::Path = syn::parse_str(rust).expect("plaintext is a type path");
            quote!(use #path;)
        })
        .collect();
    let helpers = match (producible.is_empty(), projected) {
        (true, _) => quote!(),
        (false, false) => quote!(open_target, run_target,),
        (false, true) => quote!(no_index, open_target, run_projected, run_target,),
    };

    let mod_doc = " The EQL types a Stack Encrypt data plan may name as a field target — \
                   every stored EQL v4 domain type in eql-domains::CATALOG order, as data a \
                   guest serializes (`TARGETS`), with the by-name dispatch that runs a \
                   producible type's own Rust plan. Generated from the catalog; the \
                   descriptor type, the errors and the public entry points stay \
                   hand-written in `crate::encryption::targets`, which documents the \
                   wire format.";

    let file = quote! {
        #![doc = #mod_doc]

        use stack_encrypt::dynamic::ValueFrame;
        use stack_encrypt::target::IndexSpec;

        #imports
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
            plaintext: ValueFrame,
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
        ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
            match name {
                #decrypt_arms
                _ => Err(refuse(name)),
            }
        }

        /// Run the named type's query twin for one plaintext, or refuse the
        /// name: as `encrypt_named` does, or as answering no query
        /// (`TargetError::NoQuery`) for a producible type with no twin.
        /// `index` answers the query's operator; a twin whose terms are
        /// optional carries that index's term alone.
        pub(crate) fn query_named<'a, K: 'static>(
            name: &str,
            #index_param: &IndexSpec,
            keyset: &'a KeysetCipher<'_, K>,
            column: NonEmpty<Identifier>,
            plaintext: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            match name {
                #query_arms
                _ => Err(refuse_query(name)),
            }
        }
    };

    format_rs(file)
}

/// Render the generated `crates/eql-bindings/src/v4/answers.rs`.
pub fn render_answers_rs() -> String {
    render_answers_from(&rows())
}

/// Render the typed query chain's impls from the given rows. A file of its
/// own, beside `targets.rs` rather than in it: it needs only the
/// `stack-encrypt` feature, so a Rust program queries a v4 type without
/// Stack Encrypt's `dynamic` layer, which `targets.rs` (the `targets`
/// feature) is built on.
fn render_answers_from(rows: &[Row]) -> String {
    // The typed query chain: per type that answers an operator, its twin's
    // assembly from the one term it carries, and one `op::Answers` impl per
    // operator, through Stack Encrypt's index for it, sent as the twin.
    let answering: Vec<&Row> = rows.iter().filter(|r| !r.answers.is_empty()).collect();
    let answer_impls: TokenStream = answering.iter().map(|r| answer_impls(r)).collect();
    let answer_entries: TokenStream = answering
        .iter()
        .map(|r| {
            let name = &r.name;
            let ops = r.answers.iter().map(|answer| answer.name());
            quote!((#name, &[#(#ops),*]),)
        })
        .collect();
    let answers_any = |wanted: Answer| answering.iter().any(|r| r.answers.contains(&wanted));
    let mut answer_imports = TokenStream::new();
    if !answering.is_empty() {
        let mut newtypes: Vec<&str> = answering
            .iter()
            .flat_map(|r| {
                r.answers
                    .iter()
                    .map(|answer| answer.term().binding_newtype())
            })
            .collect();
        newtypes.sort_unstable();
        newtypes.dedup();
        let newtypes = newtypes.iter().map(|n| format_ident!("{n}"));
        answer_imports.extend(quote! {
            use crate::encryption::query::{QueryTwin, TwinIndex};
            use crate::Identifier;
            use crate::v4::terms::{#(#newtypes),*};
            use crate::v4::SchemaVersion;
            use stack_encrypt::op;
        });
    }
    if answers_any(Answer::Eq) {
        answer_imports.extend(quote!(
            use stack_encrypt::Equality;
        ));
    }
    if answers_any(Answer::Matches) {
        answer_imports.extend(quote! {
            use crate::encryption::EqlMatch;
            use stack_encrypt::Match;
        });
    }

    let mod_doc = " How Stack Encrypt's typed query chain queries a producible EQL v4 \
                   type: per type that answers an operator, its `op::Answers` impls, \
                   its `op::LabelledTarget` impl and its query twin's assembly \
                   (`crate::encryption::query`). Generated from the catalog, by the \
                   rule the data path answers a field that names the type with.";

    let file = quote! {
        #![doc = #mod_doc]

        #answer_imports

        /// The operators each EQL type answers in Stack Encrypt's typed
        /// query chain (`op::Answers`), by the wire names
        /// `stack_encrypt::dynamic::OpSpec` gives them, in catalog order:
        /// one row per type that answers any. Generated from the rule the
        /// impls below are, so the encryption tests can hold the impls to
        /// the operators the data path answers for each type. Not part of
        /// the supported API.
        #[doc(hidden)]
        pub const ANSWERS: &[(&str, &[&str])] = &[
            #answer_entries
        ];

        #answer_impls
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
                encryption_gap(TARGET_VERSION, family, domain).is_none(),
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

    /// A target's reason is its v4 domain's derive reason: one source, so
    /// the table and the derives cannot disagree about why.
    #[test]
    fn every_unproducible_target_has_its_derive_reason() {
        for (family, domain) in stored_payload_domains() {
            assert_eq!(
                target_gap(family, domain),
                encryption_gap(TARGET_VERSION, family, domain),
                "{}",
                domain.full_name(family.name)
            );
        }
        // Spelled out, so the table reads without the derivation.
        let gap = |family: &eql_domains::DomainFamily, name: &str| {
            target_gap(family, family.domain_by_name(name).expect("domain"))
        };
        let text = eql_domains::TEXT;
        for producible in [
            "",
            "eq",
            "match",
            "ord",
            "ord_ope",
            "ord_ore",
            "search",
            "search_ore",
        ] {
            assert!(gap(&text, producible).is_none(), "text {producible:?}");
        }
        assert!(gap(&text, "match").is_none(), "TextMatch is producible");
        let family = |name: &str| {
            eql_domains::CATALOG
                .iter()
                .find(|f| f.name == name)
                .expect("family")
        };
        for family_name in [
            "integer",
            "smallint",
            "bigint",
            "real",
            "double",
            "date",
            "timestamp",
            "numeric",
        ] {
            let family = family(family_name);
            assert!(gap(family, "").is_none(), "{family_name}");
            for producible in ["eq", "ord", "ord_ope", "ord_ore"] {
                assert!(
                    gap(family, producible).is_none(),
                    "{family_name} {producible}"
                );
            }
        }
        assert!(gap(family("json"), "").unwrap().contains("tree of leaves"));
    }

    #[test]
    fn index_keys_are_the_engine_index_spec_keys() {
        // The `IndexSpec::key()` strings of stack-encrypt's data grammar;
        // a plan field spells an index by exactly these.
        assert_eq!(index_key(Term::Hm), "eq");
        assert_eq!(index_key(Term::Bloom), "match");
        assert_eq!(index_key(Term::Ore), "ore_block");
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
        assert!(out.contains("query_sql_domain: Some(\"eql_v4.query_json\")"));
        assert!(out.contains("sql_domain: \"public.eql_v4_text_eq\""));
        assert!(out.contains("query_sql_domain: Some(\"eql_v4.query_text_eq\")"));
        assert!(!out.contains("eql_v3"), "every target is an eql_v4 domain");
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
            let (_, plaintext) = plaintext_of(family.name).expect("a derived family's plaintext");
            let plaintext = plaintext.rsplit("::").next().unwrap();
            // A type whose terms a null has (none, or equality's alone)
            // stores, opens and queries an `Option` of its plaintext.
            let source = if crate::bindings::nullable_terms(domain) {
                format!("Option<{plaintext}>")
            } else {
                plaintext.to_owned()
            };
            let arm = |helper: &str, ty: &str| {
                format!(
                    "\"{name}\" => {{ {helper}::<super::{module}::{ty}, {source}, K>(\"{name}\", "
                )
            };
            let flat_arm = |helper: &str, ty: &str| {
                format!("\"{name}\" => {helper}::<super::{module}::{ty}, {source}, K>(\"{name}\", ")
            };
            // rustfmt breaks long arms at different points, so compare with
            // all whitespace gone.
            let tight: String = out.split_whitespace().collect();
            let count = |helper: &str, ty: &str| {
                let strip = |p: String| p.split_whitespace().collect::<String>();
                tight.matches(&strip(arm(helper, ty))).count()
                    + tight.matches(&strip(flat_arm(helper, ty))).count()
            };
            assert_eq!(count("run_target", &name), 1, "{name}: one encrypt arm");
            assert_eq!(count("open_target", &name), 1, "{name}: one decrypt arm");
            let projected = v4_optional_query_terms(domain);
            assert_eq!(
                count("run_target", &format!("{name}Query")),
                usize::from(!domain.terms.is_empty() && !projected),
                "{name}: a query arm exactly when it has a query twin"
            );
            if projected {
                // One arm per index, each through the projection for it.
                for term in Term::payload_terms(domain.terms) {
                    let projection = query_projection_ident(family, domain, term);
                    let needle = format!(
                        "\"{}\"=>run_projected::<super::{module}::{projection},super::{module}::{name}Query,{plaintext},K>(\"{name}\",",
                        index_key(term)
                    );
                    // rustfmt leaves a trailing comma in a broken turbofish.
                    let unbroken = tight.replace(",>", ">");
                    assert_eq!(unbroken.matches(&needle).count(), 1, "{needle}");
                }
            }
        }
        // No unproducible type has an arm: the only `=>` arms are the
        // producible ones, one per index of a projected twin, and the
        // fall-throughs.
        let (with_twin, by_index) = ENCRYPTION_DOMAINS
            .iter()
            .map(|(f, d)| {
                let family = eql_domains::CATALOG.iter().find(|x| x.name == *f).unwrap();
                family.domain_by_name(d).unwrap()
            })
            .filter(|domain| !domain.terms.is_empty())
            .fold((0, 0), |(twins, by_index), domain| {
                let indexes = if v4_optional_query_terms(domain) {
                    Term::payload_terms(domain.terms).len()
                } else {
                    0
                };
                (twins + 1, by_index + indexes)
            });
        assert!(by_index > 0, "TextSearch's query is projected");
        let arms = out.matches("\" => ").count();
        assert_eq!(
            arms,
            ENCRYPTION_DOMAINS.len() * 2 + with_twin + by_index,
            "arms: {out}"
        );
        assert_eq!(out.matches("_ => Err(refuse(name))").count(), 2);
        assert_eq!(out.matches("_ => Err(refuse_query(name))").count(), 1);
        assert_eq!(
            out.matches("_ => Err(no_index(\"TextSearch\", index))")
                .count(),
            1
        );
    }

    /// A type answers operators in the typed query chain exactly when the
    /// engine produces it and it has a query twin, and then by the engine's
    /// rule over its indexes: `Eq` for the equality index, `Matches` for
    /// the match index. Spelled out per type, so the table reads without
    /// the rule.
    #[test]
    fn a_producible_type_with_a_twin_answers_what_its_indexes_answer() {
        for row in rows() {
            let answers: Vec<&str> = row.answers.iter().map(|a| a.name()).collect();
            if row.reason.is_some() || row.query.is_none() {
                assert!(answers.is_empty(), "{}: answers nothing", row.name);
                continue;
            }
            if let Some(gap) = typed_gap(&row.indexes) {
                assert!(answers.is_empty(), "{}: {gap}", row.name);
                continue;
            }
            let expected: Vec<&str> = row
                .indexes
                .iter()
                .map(|key| match *key {
                    "eq" => "eq",
                    "match" => "matches",
                    other => panic!("{}: no answer for the {other} index", row.name),
                })
                .collect();
            assert_eq!(answers, expected, "{}", row.name);
        }
        let answered: Vec<(String, Vec<&str>)> = rows()
            .into_iter()
            .filter(|r| !r.answers.is_empty())
            .map(|r| (r.name, r.answers.iter().map(|a| a.name()).collect()))
            .collect();
        let spelled = |name: &str, ops: &[&'static str]| (name.to_owned(), ops.to_vec());
        assert_eq!(
            answered,
            vec![
                spelled("IntegerEq", &["eq"]),
                spelled("SmallintEq", &["eq"]),
                spelled("BigintEq", &["eq"]),
                spelled("DateEq", &["eq"]),
                spelled("TimestampEq", &["eq"]),
                spelled("NumericEq", &["eq"]),
                spelled("TextEq", &["eq"]),
                spelled("TextMatch", &["matches"]),
                spelled("RealEq", &["eq"]),
                spelled("DoubleEq", &["eq"]),
            ]
        );
    }

    /// The rule over indexes: `eq` answers `Eq` and `match` answers
    /// `Matches`; each operator's twin term is its index's.
    #[test]
    fn answers_for_indexes_maps_each_index_to_its_operator() {
        assert_eq!(answers_for_indexes("T", &[]), Vec::<Answer>::new());
        assert_eq!(answers_for_indexes("T", &["eq"]), vec![Answer::Eq]);
        assert_eq!(answers_for_indexes("T", &["match"]), vec![Answer::Matches]);
        assert_eq!(index_key(Answer::Eq.term()), "eq");
        assert_eq!(index_key(Answer::Matches.term()), "match");
        assert_eq!(Answer::Eq.name(), "eq");
        assert_eq!(Answer::Matches.name(), "matches");
    }

    /// A producible type whose twin carries an order index, or more than
    /// one index, has no typed answer yet: the generator leaves it out of
    /// the typed query chain and says why.
    #[test]
    fn an_order_index_or_several_indexes_answer_nothing_yet() {
        for (name, indexes) in [
            ("IntegerOrd", &["ope"][..]),
            ("IntegerOrdOre", &["ore"]),
            ("TextOrd", &["eq", "ope"]),
            ("TextSearch", &["eq", "ope", "match"]),
        ] {
            let gap = typed_gap(indexes).unwrap_or_else(|| panic!("{name} has a typed gap"));
            assert!(gap.contains("order term"), "{name}: {gap}");
            assert_eq!(
                answers_for_indexes(name, indexes),
                Vec::<Answer>::new(),
                "{name}"
            );
        }
        let gap = typed_gap(&["eq", "match"]).expect("several terms are a gap");
        assert!(gap.contains("more than one term"), "{gap}");
        assert_eq!(
            answers_for_indexes("T", &["eq", "match"]),
            Vec::<Answer>::new()
        );
        assert_eq!(typed_gap(&[]), None);
        assert_eq!(typed_gap(&["eq"]), None);
        assert_eq!(typed_gap(&["match"]), None);
    }

    #[test]
    #[should_panic(expected = "no rule for the json index")]
    fn an_unknown_index_stops_the_generator() {
        answers_for_indexes("SteVecDocument", &["json"]);
    }

    /// The rendered file implements `op::Answers` once per answered
    /// operator, through the index the operator names, sent as the type's
    /// twin; marks an exact twin a `QueryTerm`; and lists every answering
    /// type in `ANSWERS`.
    #[test]
    fn rendered_answers_are_one_impl_per_operator_and_one_table_row_per_type() {
        let tight: String = render_answers_rs().split_whitespace().collect();
        let mut answered = 0;
        for row in rows() {
            let module = row.family;
            let name = &row.name;
            let Some((twin, _)) = &row.query else {
                continue;
            };
            let answers_impl = |op: &str| format!("implop::Answers<op::{op},");
            let for_type = format!("forsuper::{module}::{name}{{typeVia=TwinIndex<");
            let impls = tight.matches(&for_type).count();
            assert_eq!(impls, row.answers.len(), "{name}: one impl per operator");
            if row.answers.is_empty() {
                assert!(!tight.contains(&format!("(\"{name}\",&[")), "{name}");
                continue;
            }
            answered += 1;
            let ops: Vec<String> = row
                .answers
                .iter()
                .map(|a| format!("\"{}\"", a.name()))
                .collect();
            assert!(
                tight.contains(&format!("(\"{name}\",&[{}]),", ops.join(","))),
                "{name}: its ANSWERS row"
            );
            for answer in &row.answers {
                let (op, via) = match answer {
                    Answer::Eq => (
                        "Eq",
                        format!("TwinIndex<Equality,super::{module}::{twin}>;"),
                    ),
                    Answer::Matches => (
                        "Matches",
                        format!("TwinIndex<Match<EqlMatch>,super::{module}::{twin}>;"),
                    ),
                };
                assert!(tight.contains(&answers_impl(op)), "{name}: op::{op}");
                assert!(tight.contains(&via), "{name}: {via}");
            }
            let exact = row.answers.contains(&Answer::Eq);
            assert_eq!(
                tight.contains(&format!("implop::QueryTermforsuper::{module}::{twin}{{}}")),
                exact,
                "{name}: QueryTerm exactly on an exact twin"
            );
            assert_eq!(
                tight
                    .matches(&format!("forsuper::{module}::{twin}{{typePlaintext="))
                    .count(),
                1,
                "{name}: one assembly"
            );
            assert_eq!(
                tight
                    .matches(&format!(
                        "implop::LabelledTargetforsuper::{module}::{name}{{}}"
                    ))
                    .count(),
                1,
                "{name}: labelled"
            );
        }
        assert_eq!(answered, 10);
        assert_eq!(tight.matches("implop::Answers<").count(), 10);
        assert_eq!(tight.matches("implop::LabelledTarget").count(), 10);
    }

    /// A producible type with no query twin — the storage-only `Text` —
    /// renders encrypt and decrypt arms over an `Option` of its plaintext,
    /// so it stores a null (#1298), and no query arm: the query dispatch's
    /// fall-through refuses it as answering no query.
    #[test]
    fn a_producible_type_without_a_query_twin_gets_no_query_arm() {
        let rows = rows();
        let text = rows
            .iter()
            .find(|r| r.name == "Text")
            .expect("the storage-only text domain");
        assert!(text.query.is_none() && text.reason.is_none());
        let out: String = render_targets_from(&rows)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let arms_for = |helper: &str| {
            out.matches(&format!(
                "\"Text\" => {{ {helper}::<super::text::Text, Option<String>, K>(\"Text\","
            ))
            .count()
                + out
                    .matches(&format!(
                        "\"Text\" => {helper}::<super::text::Text, Option<String>, K>(\"Text\","
                    ))
                    .count()
        };
        assert_eq!(arms_for("run_target"), 1, "one encrypt arm: {out}");
        assert_eq!(arms_for("open_target"), 1, "one decrypt arm: {out}");
        assert!(
            !out.contains("TextQuery"),
            "no query arm for a type with no twin: {out}"
        );
    }
}
