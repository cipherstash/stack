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
//! an arm runs `<T as EncryptTarget<S>>::encryption()`, which only exists with
//! the derive, and [`target_gap`] is tested to agree with
//! [`encryption_gap`](crate::bindings::encryption_gap) on every domain.
//!
//! The same rows give the operators each producible type answers in Stack
//! Encrypt's typed query ([`answers_for_indexes`]), rendered to
//! `v4/answers.rs` ([`render_answers_rs`]) under the `stack-encrypt` feature
//! alone: it implements `op::Answers` for each, with the type's query twin as
//! the query term, and lists them in `ANSWERS` so the encryption tests can
//! hold them to the operators the engine's data path answers for the same
//! type: every producible type with a twin answers there what it answers
//! through a data plan. A twin that requires several terms (`TextOrdQuery`'s
//! `hm` and `op`) is assembled from all of them whatever the operator, and a
//! twin whose terms are optional (`TextSearchQuery`) from the answering
//! index's term alone, as the data path builds each.
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
    encryption_gap, format_rs, plaintext_of, query_projection_ident, query_term_newtype,
    stored_payload_domains,
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
    IndexKey::of_term(term).as_str()
}

/// An engine index a catalog term rides under, named by its
/// `IndexSpec::key()` ([`as_str`](Self::as_str)). Each rule the typed query
/// generator applies to an index matches on it exhaustively, so a new index
/// is a compile error in every rule rather than a missing arm. A row's
/// indexes stay strings, as the table spells them; [`parse`](Self::parse)
/// reads one back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexKey {
    /// `eq`: the equality index, EQL's `hm`.
    Eq,
    /// `match`: the match index, EQL's `bf`.
    Match,
    /// `ore_block`: block ORE, EQL's `ob`.
    OreBlock,
    /// `ope`: OPE, EQL's `op`.
    Ope,
}

impl IndexKey {
    /// Every index, in the order `answers.rs` imports them.
    const ALL: [IndexKey; 4] = [
        IndexKey::Eq,
        IndexKey::Match,
        IndexKey::Ope,
        IndexKey::OreBlock,
    ];

    /// The index a catalog term rides under.
    fn of_term(term: Term) -> Self {
        match term {
            Term::Hm => IndexKey::Eq,
            Term::Bloom => IndexKey::Match,
            Term::Ore => IndexKey::OreBlock,
            Term::Ope => IndexKey::Ope,
        }
    }

    /// The catalog term the index derives: the inverse of
    /// [`of_term`](Self::of_term).
    fn term(self) -> Term {
        match self {
            IndexKey::Eq => Term::Hm,
            IndexKey::Match => Term::Bloom,
            IndexKey::OreBlock => Term::Ore,
            IndexKey::Ope => Term::Ope,
        }
    }

    /// The key `IndexSpec::key()` spells.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            IndexKey::Eq => "eq",
            IndexKey::Match => "match",
            IndexKey::OreBlock => "ore_block",
            IndexKey::Ope => "ope",
        }
    }

    /// The index a row's key names.
    ///
    /// # Panics
    ///
    /// On a key no catalog term rides under, such as a document's `json`:
    /// a typed query has no rule for it.
    fn parse(type_name: &str, key: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|index| index.as_str() == key)
            .unwrap_or_else(|| {
                panic!(
                    "{type_name}: a typed query has no rule for the {key} index; extend \
                     eql-codegen's IndexKey"
                )
            })
    }

    /// Stack Encrypt's index type, as `answers.rs` names it.
    fn index_type(self) -> TokenStream {
        match self {
            IndexKey::Eq => quote!(Equality),
            IndexKey::Match => quote!(Match<EqlMatch>),
            IndexKey::Ope => quote!(Ope),
            IndexKey::OreBlock => quote!(OreBlock),
        }
    }

    /// The name `answers.rs` imports Stack Encrypt's index type by.
    fn index_import(self) -> &'static str {
        match self {
            IndexKey::Eq => "Equality",
            IndexKey::Match => "Match",
            IndexKey::Ope => "Ope",
            IndexKey::OreBlock => "OreBlock",
        }
    }

    /// The type a query twin stores the index's term in, over the type's
    /// plaintext `source`. An `hm` or a `bf` is an EQL newtype
    /// ([`query_term_newtype`]). A `bf` is a `QueryBloomFilter`. An `op` or
    /// an `ob` is Stack Encrypt's own term.
    fn twin_term_type(self, source: &syn::Path) -> TokenStream {
        match self.term_import() {
            TermImport::Newtype(name) => {
                let newtype = format_ident!("{name}");
                quote!(#newtype)
            }
            TermImport::OrderTerm(name) => {
                let term = format_ident!("{name}");
                quote!(#term<#source>)
            }
        }
    }

    /// The name `answers.rs` imports the twin's term type by, and where
    /// from. An `hm` or a `bf` is the newtype a query contains
    /// ([`query_term_newtype`]): `Hmac256`, or `QueryBloomFilter`.
    fn term_import(self) -> TermImport {
        match self {
            IndexKey::Eq | IndexKey::Match => {
                TermImport::Newtype(query_term_newtype(TARGET_VERSION, self.term()))
            }
            IndexKey::Ope => TermImport::OrderTerm("OpeTerm"),
            IndexKey::OreBlock => TermImport::OrderTerm("OreBlockTerm"),
        }
    }

    /// How the index is named in the generated docs.
    fn doc(self) -> &'static str {
        match self {
            IndexKey::Eq => "equality",
            IndexKey::Match => "match",
            IndexKey::Ope => "OPE",
            IndexKey::OreBlock => "block ORE",
        }
    }
}

/// Where `answers.rs` imports a twin's term type from.
enum TermImport {
    /// An EQL newtype, from `crate::v4::terms`.
    Newtype(&'static str),
    /// Stack Encrypt's order term, from `stack_encrypt::sem`.
    OrderTerm(&'static str),
}

/// An operator a producible EQL type answers in a Stack Encrypt typed
/// query: what the generated file implements `op::Answers` for. Declared in
/// the order `stack_encrypt::dynamic::Op::ALL` lists them, which is the
/// order the data path lists a type's operators in, so sorting a type's
/// answers gives the data path's list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Answer {
    /// `op::Eq`, through the equality index.
    Eq,
    /// `op::Lt`, through the type's order index.
    Lt,
    /// `op::Lte`, through the type's order index.
    Lte,
    /// `op::Gt`, through the type's order index.
    Gt,
    /// `op::Gte`, through the type's order index.
    Gte,
    /// `op::Matches`, through the match index under EQL's configuration.
    Matches,
}

impl Answer {
    /// The operator's wire name, `stack_encrypt::dynamic::Op::name`.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Answer::Eq => "eq",
            Answer::Lt => "lt",
            Answer::Lte => "lte",
            Answer::Gt => "gt",
            Answer::Gte => "gte",
            Answer::Matches => "matches",
        }
    }

    /// The operator's type in `stack_encrypt::op`.
    pub(crate) fn operator(self) -> &'static str {
        match self {
            Answer::Eq => "Eq",
            Answer::Lt => "Lt",
            Answer::Lte => "Lte",
            Answer::Gt => "Gt",
            Answer::Gte => "Gte",
            Answer::Matches => "Matches",
        }
    }

    /// Whether the server's answer is the answer, so the twin itself is the
    /// query term: every operator but `Matches`, whose query is a
    /// `MatchTwin` that verifies rows.
    pub(crate) fn is_exact(self) -> bool {
        self != Answer::Matches
    }

    /// The operators `index` answers: the engine's declarations
    /// (`Equality::OPERATORS`, `Ope::OPERATORS`, …) less `between`, which
    /// the data path answers for no EQL type.
    fn of_index(index: IndexKey) -> &'static [Answer] {
        match index {
            IndexKey::Eq => &[Answer::Eq],
            IndexKey::Match => &[Answer::Matches],
            IndexKey::Ope | IndexKey::OreBlock => {
                &[Answer::Lt, Answer::Lte, Answer::Gt, Answer::Gte]
            }
        }
    }

    /// The index among `indexes` that answers this operator.
    fn index(self, indexes: &[IndexKey]) -> IndexKey {
        indexes
            .iter()
            .copied()
            .find(|index| Answer::of_index(*index).contains(&self))
            .expect("an answer comes from one of the type's indexes")
    }
}

/// The operators a producible type with a query twin answers, given the
/// indexes it carries, the same input the engine's
/// table reads: `Eq` for the `"eq"` index, `Matches` for the `"match"`
/// index and the orderings (`Lt`, `Lte`, `Gt`, `Gte`) for the `"ope"` or
/// `"ore_block"` index, as `Op::answered_by` answers a field that names the
/// type (`TargetDescriptor::operators`), in its order. No `Between`: the
/// data path answers no `between` on an EQL type. The encryption tests
/// compare the two, type by type.
///
/// `optional_terms` says whether the twin's terms are optional in EQL v4,
/// so its query carries the answering index's term alone; otherwise the
/// twin carries every index's term whatever the operator.
///
/// # Panics
///
/// On a twin that carries a match term beside another term that it
/// requires: its `matches` query would carry them all, and a typed query
/// has no rule to assemble a verifying query from several terms.
pub(crate) fn answers_for_indexes(
    name: &str,
    indexes: &[IndexKey],
    optional_terms: bool,
) -> Vec<Answer> {
    if indexes.len() > 1 && indexes.contains(&IndexKey::Match) && !optional_terms {
        panic!(
            "{name}: its twin requires a match term beside another term; a typed query \
             assembles a match twin from the match term alone"
        );
    }
    let mut answers: Vec<Answer> = indexes
        .iter()
        .flat_map(|index| Answer::of_index(*index).iter().copied())
        .collect();
    answers.sort_unstable();
    answers
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
    /// The operators the type answers in a typed query: none
    /// unless it is producible and has a query twin ([`answers_for_indexes`]).
    pub(crate) answers: Vec<Answer>,
    /// A document family's stored type (`eql_domains::DOCUMENT_FAMILIES`):
    /// its plan is the JSON index's under the field's options, so the
    /// generated dispatch has no arm for it and
    /// `encryption::targets` runs it by hand.
    pub(crate) document: bool,
}

/// The catalog domains that are targets, in catalog order: every stored
/// scalar domain. The `json` family's SteVec document is not one: its SQL is
/// EQL v3 only, and in v4 its domain name, `json_search`, is the JSON tree
/// family's stored type, a document family's row.
fn target_domains() -> impl Iterator<Item = (&'static DomainFamily, &'static Domain)> {
    stored_payload_domains().filter(|(_, d)| d.is_scalar())
}

/// Every row, in catalog order: one per [target domain](target_domains),
/// then one per document family's stored domain.
pub(crate) fn rows() -> Vec<Row> {
    target_domains()
        .map(|(f, d)| row(f, d))
        .chain(eql_domains::DOCUMENT_FAMILIES.iter().map(document_row))
        .collect()
}

/// A document family's row: its stored type, produced from the family's
/// plaintext kind, carrying its index, with its containment needle as the
/// query twin. Producible: `encryption::targets` runs it by hand.
fn document_row(family: &'static eql_domains::DocumentFamily) -> Row {
    use eql_domains::DocumentRole;
    let stored = family
        .domain(DocumentRole::Stored)
        .expect("a document family has a stored domain");
    Row {
        name: stored.name.to_owned(),
        family: family.name,
        suffix: String::new(),
        plaintext: Some(family.plaintext),
        sql_domain: stored.sql_domain.to_owned(),
        indexes: vec![family.index],
        query: family
            .domain(DocumentRole::Query)
            .map(|query| (query.name.to_owned(), query.sql_domain.to_owned())),
        projections: Vec::new(),
        reason: None,
        answers: Vec::new(),
        document: true,
    }
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
    let keys: Vec<IndexKey> = Term::payload_terms(domain.terms)
        .into_iter()
        .map(IndexKey::of_term)
        .collect();
    let indexes: Vec<&'static str> = keys.iter().map(|key| key.as_str()).collect();
    let query = if domain.terms.is_empty() {
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
    let optional_terms = v4_optional_query_terms(domain);
    let answers = if reason.is_none() && query.is_some() {
        answers_for_indexes(&name, &keys, optional_terms)
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
        projections: if optional_terms {
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
        document: false,
    }
}

/// A typed query's impls for one type that answers an operator: its query
/// twin's assembly from the terms it carries (every index's, or for a twin
/// whose terms are optional, one assembly per index from that index's term
/// alone), `QueryTerm` on the twin when an exact operator returns it as is,
/// and one `op::Answers` per operator, through Stack Encrypt's index for it,
/// sent as the twin.
fn answer_impls(r: &Row) -> TokenStream {
    let module = format_ident!("{}", r.family);
    let ty = format_ident!("{}", r.name);
    let name = &r.name;
    let (twin_name, twin_domain) = r
        .query
        .as_ref()
        .expect("a type that answers an operator has a query twin");
    let twin = format_ident!("{twin_name}");
    let (_, rust) = plaintext_of(r.family).expect("a producible family has a specified plaintext");
    let source: syn::Path = syn::parse_str(rust).expect("a family's Rust plaintext is a type path");
    let keys: Vec<IndexKey> = r
        .indexes
        .iter()
        .map(|key| IndexKey::parse(name, key))
        .collect();
    let field = |key: IndexKey| format_ident!("{}", key.term().json_key());
    let optional_terms = !r.projections.is_empty();
    let labelled_doc = format!(
        " `{name}` is sealed under the column a two-segment label names, so a field of this \
         type is queried under its field reference's label."
    );
    let mut out = quote! {
        #[doc = #labelled_doc]
        impl op::LabelledTarget for super::#module::#ty {}
    };
    if optional_terms {
        // One assembly per index, each setting that index's term alone.
        for &key in &keys {
            let set = field(key);
            let term = key.twin_term_type(&source);
            let unset = keys.iter().filter(|k| **k != key).map(|k| field(*k));
            let doc = format!(
                " `{twin_name}` from the column it queries and its `{set}` term alone, at \
                 version 4: the query through its {} index.",
                key.doc()
            );
            out.extend(quote! {
                #[doc = #doc]
                impl QueryTwin<#term> for super::#module::#twin {
                    type Plaintext = #source;
                    fn assemble(i: Identifier, #set: #term) -> Self {
                        Self { v: SchemaVersion::default(), i, #set: Some(#set), #(#unset: None),* }
                    }
                }
            });
        }
    } else {
        let fields: Vec<_> = keys.iter().map(|key| field(*key)).collect();
        let terms: Vec<_> = keys.iter().map(|key| key.twin_term_type(&source)).collect();
        let named: Vec<String> = fields.iter().map(|f| format!("`{f}`")).collect();
        let doc = format!(
            " `{twin_name}` from the column it queries and its {} {}, at version 4.",
            named.join(" and "),
            if named.len() == 1 { "term" } else { "terms" }
        );
        let (pattern, input) = match (fields.as_slice(), terms.as_slice()) {
            ([one], [term]) => (quote!(#one), quote!(#term)),
            _ => (quote!((#(#fields),*)), quote!((#(#terms),*))),
        };
        out.extend(quote! {
            #[doc = #doc]
            impl QueryTwin<#input> for super::#module::#twin {
                type Plaintext = #source;
                fn assemble(i: Identifier, #pattern: #input) -> Self {
                    Self { v: SchemaVersion::default(), i, #(#fields),* }
                }
            }
        });
    }
    let exact: Vec<String> = r
        .answers
        .iter()
        .filter(|answer| answer.is_exact())
        .map(|answer| format!("`op::{}`", answer.operator()))
        .collect();
    if !exact.is_empty() {
        let term_doc = format!(
            " `{twin_name}` is exact: the query term of `{name}`'s {}.",
            exact.join(", ")
        );
        out.extend(quote! {
            #[doc = #term_doc]
            impl op::QueryTerm for super::#module::#twin {}
        });
    }
    // A twin that requires every term derives them all, whichever index
    // answers; one whose terms are optional derives the answering index's.
    let derived = (!optional_terms && keys.len() > 1).then(|| {
        let all = keys.iter().map(|key| key.index_type());
        quote!(, (#(#all),*))
    });
    let carries = if derived.is_some() {
        ", which carries the terms of all its indexes"
    } else if optional_terms {
        ", which carries that index's term alone"
    } else {
        ""
    };
    for answer in &r.answers {
        let key = answer.index(&keys);
        let index = key.index_type();
        let op = format_ident!("{}", answer.operator());
        let (via, doc) = match answer {
            Answer::Matches => (
                quote!(TwinIndex<#index, super::#module::#twin>),
                format!(
                    " `{name}` answers `op::Matches` through its match index, under \
                     `EqlMatch`. The query term is a `MatchTwin<{twin_name}>`: the twin, \
                     bound as `{twin_domain}`{carries}, and the tokens that verify a row."
                ),
            ),
            exact => (
                quote!(TwinIndex<#index, super::#module::#twin #derived>),
                format!(
                    " `{name}` answers `op::{}` through its {} index. The query term is \
                     `{twin_name}`, bound as `{twin_domain}`{carries}.",
                    exact.operator(),
                    key.doc()
                ),
            ),
        };
        out.extend(quote! {
            #[doc = #doc]
            impl op::Answers<op::#op, #source> for super::#module::#ty {
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
    // A document family's type is run by hand, under the field's options.
    let producible: Vec<&Row> = rows
        .iter()
        .filter(|r| r.reason.is_none() && !r.document)
        .collect();
    let mut document_families: Vec<&str> = rows
        .iter()
        .filter(|r| r.document)
        .map(|r| r.family)
        .collect();
    document_families.dedup();
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
        if r.indexes
            .iter()
            .all(|index| *index == IndexKey::Eq.as_str())
        {
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
            quote! { #name => run_target::<#ty, #source, K>(#name, keyset, context, plaintext), }
        })
        .collect();
    let decrypt_arms: TokenStream = producible
        .iter()
        .map(|r| {
            let (name, ty, source) = arm(r, &r.name);
            let source = stored_source(r, source);
            quote! { #name => open_target::<#ty, #source, K>(#name, opener, context, stored), }
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
                    quote! { #name => run_target::<#ty, #source, K>(#name, keyset, context, plaintext), },
                );
            }
            let by_index: TokenStream = r
                .projections
                .iter()
                .map(|(key, projection)| {
                    let (_, projection, _) = arm(r, projection);
                    quote! {
                        #key => run_projected::<#projection, #ty, #source, K>(#name, keyset, context, plaintext),
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
        use stack_encrypt::target::{CallerContext, IndexSpec};

        #imports
        use crate::encryption::targets::{#helpers refuse, refuse_query, Opener, Target, TargetError};
        use stack_encrypt::{KeysetCipher, Pending};

        /// Every EQL type a plan may name as a target, in
        /// `eql-domains::CATALOG` order: one per stored scalar domain, then
        /// one per document family's stored type
        /// (`eql-domains::DOCUMENT_FAMILIES`). Query twins are not targets;
        /// each row names its own under `query`.
        pub const TARGETS: &[Target] = &[
            #entries
        ];

        /// The families whose stored type stores a document
        /// (`eql-domains::DOCUMENT_FAMILIES`): the dispatch below has no
        /// arm for them, and `crate::encryption::targets` runs their types
        /// under the field's options.
        pub(crate) const DOCUMENT_FAMILIES: &[&str] = &[#(#document_families),*];

        /// Run the named type's own encryption plan for one field, or refuse
        /// the name: the type is not producible (`TargetError::Unproducible`)
        /// or does not exist (`TargetError::Unknown`). `context` is the
        /// field's context: its column, then the scopes and the bindings.
        pub(crate) fn encrypt_named<'a, K: 'static>(
            name: &str,
            keyset: &'a KeysetCipher<'_, K>,
            context: CallerContext,
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
            context: CallerContext,
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
            context: CallerContext,
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

/// Render a typed query's impls from the given rows. A file of its
/// own, beside `targets.rs` rather than in it: it needs only the
/// `stack-encrypt` feature, so a Rust program queries a v4 type without
/// Stack Encrypt's `dynamic` layer, which `targets.rs` (the `targets`
/// feature) is built on.
fn render_answers_from(rows: &[Row]) -> String {
    // A typed query: per type that answers an operator, its twin's
    // assembly from the terms it carries, and one `op::Answers` impl per
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
    // Every index an answering type carries is named in its impls: as the
    // index an operator answers through, in the indexes a twin's terms are
    // derived by, and as the type of the term the twin stores.
    let carries = |key: IndexKey| answering.iter().any(|r| r.indexes.contains(&key.as_str()));
    let mut answer_imports = TokenStream::new();
    if !answering.is_empty() {
        let carried: Vec<IndexKey> = IndexKey::ALL
            .into_iter()
            .filter(|key| carries(*key))
            .collect();
        let indexes: Vec<_> = carried
            .iter()
            .map(|key| format_ident!("{}", key.index_import()))
            .collect();
        let (mut newtypes, mut order_terms) = (Vec::new(), Vec::new());
        for key in &carried {
            match key.term_import() {
                TermImport::Newtype(name) => newtypes.push(format_ident!("{name}")),
                TermImport::OrderTerm(name) => order_terms.push(format_ident!("{name}")),
            }
        }
        answer_imports.extend(quote! {
            use crate::encryption::query::{QueryTwin, TwinIndex};
            use crate::Identifier;
            use crate::v4::terms::{#(#newtypes),*};
            use crate::v4::SchemaVersion;
            use stack_encrypt::op;
            use stack_encrypt::{#(#indexes),*};
        });
        if !order_terms.is_empty() {
            answer_imports.extend(quote!(use stack_encrypt::sem::{#(#order_terms),*};));
        }
        if carries(IndexKey::Match) {
            answer_imports.extend(quote!(
                use crate::encryption::EqlMatch;
            ));
        }
    }

    let mod_doc =
        " How a Stack Encrypt typed query, from a field reference, queries a producible EQL v4 \
                   type: per type that answers an operator, its `op::Answers` impls, \
                   its `op::LabelledTarget` impl and its query twin's assembly \
                   (`crate::encryption::query`). Generated from the catalog, by the \
                   rule the data path answers a field that names the type with.";

    let file = quote! {
        #![doc = #mod_doc]

        #answer_imports

        /// The operators each EQL type answers in Stack Encrypt's typed
        /// query (`op::Answers`), by the wire names
        /// `stack_encrypt::dynamic::Op` gives them, in catalog order:
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
        // The `json` family's storage domain is produced from a document
        // sealed as one leaf.
        assert!(gap(family("json"), "").is_none());
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
        // One row per target domain, in catalog order, named as the struct.
        let mut last = 0;
        for (family, domain) in target_domains() {
            let needle = format!("name: \"{}\",", domain.rust_struct_name(family.name));
            let at = out[last..]
                .find(&needle)
                .unwrap_or_else(|| panic!("{needle} missing or out of order"));
            last += at + needle.len();
        }
        // The SteVec document is EQL v3 only, so it is no target: the
        // v4 `json_search` domain is the JSON tree family's stored type,
        // `JsonSearch`, which carries the JSON index and the containment
        // needle as its query form.
        assert!(!out.contains("SteVec"));
        assert!(out.contains("indexes: &[\"json\"]"));
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

    /// A type answers operators in a typed query exactly when the
    /// engine produces it and it has a query twin, and then by the engine's
    /// rule over its indexes: `Eq` for the equality index, the orderings for
    /// an order index, `Matches` for the match index, in the data path's
    /// order. Spelled out per type, so the table reads without the rule.
    #[test]
    fn a_producible_type_with_a_twin_answers_what_its_indexes_answer() {
        const ORDERINGS: &[&str] = &["lt", "lte", "gt", "gte"];
        for row in rows() {
            let answers: Vec<&str> = row.answers.iter().map(|a| a.name()).collect();
            // A document's operators are the JSON index's, answered
            // through a data plan.
            if row.reason.is_some() || row.query.is_none() || row.document {
                assert!(answers.is_empty(), "{}: answers nothing", row.name);
                continue;
            }
            let mut expected: Vec<&str> = Vec::new();
            if row.indexes.contains(&IndexKey::Eq.as_str()) {
                expected.push("eq");
            }
            if row
                .indexes
                .iter()
                .any(|key| [IndexKey::Ope.as_str(), IndexKey::OreBlock.as_str()].contains(key))
            {
                expected.extend(ORDERINGS);
            }
            if row.indexes.contains(&IndexKey::Match.as_str()) {
                expected.push("matches");
            }
            assert_eq!(answers, expected, "{}", row.name);
        }
        let answered: Vec<(String, Vec<&str>)> = rows()
            .into_iter()
            .filter(|r| !r.answers.is_empty())
            .map(|r| (r.name, r.answers.iter().map(|a| a.name()).collect()))
            .collect();
        let spelled = |name: &str, ops: &[&'static str]| (name.to_owned(), ops.to_vec());
        const ORDERED_TEXT: &[&str] = &["eq", "lt", "lte", "gt", "gte"];
        const SEARCH: &[&str] = &["eq", "lt", "lte", "gt", "gte", "matches"];
        let mut expected = Vec::new();
        for family in [
            "Integer",
            "Smallint",
            "Bigint",
            "Date",
            "Timestamp",
            "Numeric",
            "Text",
            "Real",
            "Double",
        ] {
            expected.push(spelled(&format!("{family}Eq"), &["eq"]));
            if family == "Text" {
                expected.push(spelled("TextMatch", &["matches"]));
            }
            let ordered = if family == "Text" {
                ORDERED_TEXT
            } else {
                ORDERINGS
            };
            for suffix in ["OrdOre", "Ord", "OrdOpe"] {
                expected.push(spelled(&format!("{family}{suffix}"), ordered));
            }
            if family == "Text" {
                expected.push(spelled("TextSearchOre", SEARCH));
                expected.push(spelled("TextSearch", SEARCH));
            }
        }
        assert_eq!(answered, expected);
    }

    /// The rule over indexes: `eq` answers `Eq`, `match` answers `Matches`,
    /// and an order index (`ope` or `ore_block`) the four orderings, in the
    /// order `Op::ALL` lists them, whatever the order of the indexes.
    #[test]
    fn answers_for_indexes_maps_each_index_to_its_operators() {
        use Answer::*;
        use IndexKey as Key;
        assert_eq!(answers_for_indexes("T", &[], false), Vec::<Answer>::new());
        assert_eq!(answers_for_indexes("T", &[Key::Eq], false), vec![Eq]);
        assert_eq!(
            answers_for_indexes("T", &[Key::Match], false),
            vec![Matches]
        );
        assert_eq!(
            answers_for_indexes("T", &[Key::Ope], false),
            vec![Lt, Lte, Gt, Gte]
        );
        assert_eq!(
            answers_for_indexes("T", &[Key::OreBlock], false),
            vec![Lt, Lte, Gt, Gte]
        );
        assert_eq!(
            answers_for_indexes("T", &[Key::Ope, Key::Eq], false),
            vec![Eq, Lt, Lte, Gt, Gte]
        );
        assert_eq!(
            answers_for_indexes("T", &[Key::Match, Key::OreBlock, Key::Eq], true),
            vec![Eq, Lt, Lte, Gt, Gte, Matches]
        );
        let names: Vec<&str> = [Eq, Lt, Lte, Gt, Gte, Matches]
            .iter()
            .map(|a| a.name())
            .collect();
        assert_eq!(names, ["eq", "lt", "lte", "gt", "gte", "matches"]);
        let operators: Vec<&str> = [Eq, Lt, Lte, Gt, Gte, Matches]
            .iter()
            .map(|a| a.operator())
            .collect();
        assert_eq!(operators, ["Eq", "Lt", "Lte", "Gt", "Gte", "Matches"]);
        assert!(!Matches.is_exact(), "a match query verifies its rows");
        assert!([Eq, Lt, Lte, Gt, Gte].iter().all(|a| a.is_exact()));
        for (key, answer) in [
            (Key::Eq, Eq),
            (Key::Ope, Lt),
            (Key::OreBlock, Gte),
            (Key::Match, Matches),
        ] {
            assert_eq!(answer.index(&[Key::Match, key]), key, "{answer:?}");
        }
    }

    /// Every index round-trips through its catalog term and its key, and
    /// `ALL` lists each once.
    #[test]
    fn every_index_key_round_trips() {
        for key in IndexKey::ALL {
            assert_eq!(IndexKey::of_term(key.term()), key, "{key:?}: its term");
            assert_eq!(index_key(key.term()), key.as_str(), "{key:?}: its key");
            assert_eq!(IndexKey::parse("T", key.as_str()), key, "{key:?}: parsed");
        }
        for term in [Term::Hm, Term::Bloom, Term::Ore, Term::Ope] {
            assert!(
                IndexKey::ALL.contains(&IndexKey::of_term(term)),
                "{term:?}: its index is listed"
            );
        }
    }

    #[test]
    #[should_panic(expected = "no rule for the json index")]
    fn an_unknown_index_stops_the_generator() {
        IndexKey::parse("SteVecDocument", "json");
    }

    /// A twin that requires a match term beside another stops the
    /// generator: its `matches` query would have to carry every term, and a
    /// typed query assembles a match twin from the match term alone.
    #[test]
    #[should_panic(expected = "requires a match term beside another term")]
    fn a_twin_requiring_a_match_term_and_another_stops_the_generator() {
        answers_for_indexes("TextEqMatch", &[IndexKey::Eq, IndexKey::Match], false);
    }

    /// The rendered file implements `op::Answers` once per answered
    /// operator, through the index the operator names, sent as the type's
    /// twin; derives every index's term for a twin that requires them all;
    /// assembles a twin once, or once per index when its terms are
    /// optional; marks an exact twin a `QueryTerm`; and lists every
    /// answering type in `ANSWERS`.
    #[test]
    fn rendered_answers_are_one_impl_per_operator_and_one_table_row_per_type() {
        let tight: String = render_answers_rs().split_whitespace().collect();
        let mut answered = 0;
        let mut impls_total = 0;
        for row in rows() {
            let module = row.family;
            let name = &row.name;
            let Some((twin, _)) = &row.query else {
                continue;
            };
            let for_type = format!("forsuper::{module}::{name}{{typeVia=TwinIndex<");
            let impls = tight.matches(&for_type).count();
            assert_eq!(impls, row.answers.len(), "{name}: one impl per operator");
            impls_total += impls;
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
                // rustfmt may wrap a long row, with a trailing comma.
                tight.contains(&format!("(\"{name}\",&[{}])", ops.join(",")))
                    || tight.contains(&format!("(\"{name}\",&[{}],)", ops.join(","))),
                "{name}: its ANSWERS row"
            );
            let optional = !row.projections.is_empty();
            let keys: Vec<IndexKey> = row
                .indexes
                .iter()
                .map(|key| IndexKey::parse(name, key))
                .collect();
            let derived = if !optional && keys.len() > 1 {
                let all: Vec<String> = keys
                    .iter()
                    .map(|key| key.index_type().to_string().replace(' ', ""))
                    .collect();
                format!(",({})", all.join(","))
            } else {
                String::new()
            };
            for answer in &row.answers {
                let op = answer.operator();
                let index = answer
                    .index(&keys)
                    .index_type()
                    .to_string()
                    .replace(' ', "");
                let derived = if answer.is_exact() {
                    derived.as_str()
                } else {
                    ""
                };
                let via = format!(
                    "implop::Answers<op::{op},{}>forsuper::{module}::{name}{{typeVia=\
                     TwinIndex<{index},super::{module}::{twin}{derived}>;",
                    plaintext_of(row.family).unwrap().1.replace(' ', "")
                );
                assert!(tight.contains(&via), "{name}: {via}");
            }
            let exact = row.answers.iter().any(|a| a.is_exact());
            assert_eq!(
                tight.contains(&format!("implop::QueryTermforsuper::{module}::{twin}{{}}")),
                exact,
                "{name}: QueryTerm exactly on an exact twin"
            );
            let assemblies = if optional { row.indexes.len() } else { 1 };
            assert_eq!(
                tight
                    .matches(&format!("forsuper::{module}::{twin}{{typePlaintext="))
                    .count(),
                assemblies,
                "{name}: one assembly, or one per index of optional terms"
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
        assert_eq!(answered, 39, "every producible type with a twin answers");
        assert_eq!(tight.matches("implop::Answers<").count(), impls_total);
        assert_eq!(tight.matches("implop::LabelledTarget").count(), 39);
        assert!(
            tight.contains(
                "implQueryTwin<(Hmac256,OpeTerm<String>)>forsuper::text::TextOrdQuery{\
                 typePlaintext=String;fnassemble(i:Identifier,(hm,op):(Hmac256,OpeTerm<String>))"
            ),
            "TextOrdQuery is assembled from both its terms"
        );
        assert!(
            tight.contains(
                "fnassemble(i:Identifier,ob:OreBlockTerm<String>)->Self{Self{v:SchemaVersion::default(),i,ob:Some(ob),hm:None,bf:None,}}"
            ),
            "TextSearchOreQuery is assembled from its `ob` alone for an ordering"
        );
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
