//! The query terms of the JSON index, and how the operators reach it.
//!
//! A containment query sends the [`JsonSelectorSet`] of the document it
//! asks about: the selector pairs `{s, vs}` of every node, grouped by the
//! array element they sit in. A stored document carries its own, built the
//! same way, as `q`, which the server reads, and native `jsonb @>` over the
//! two sets is exact containment: each element of the query's document has
//! to fit inside one stored element, which is PostgreSQL's own rule for
//! arrays.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::derive::{JsonTerms, Selectors, TermNode};
use super::path::JsonPath;
use super::plain::PlainJson;
use super::{base64, JsonDocument, JsonExtracted, JsonNode, JsonOptions, JsonSubtree, Tag};
use crate::op::{
    Answers, AtPath, Between, ContainedBy, Contains, DefaultIndex, Eq, Gt, Gte, Input,
    LabelledTarget, Lt, Lte, One, Pair, Pathed, QueryTerm, QueryToken, Supports,
};
use crate::sem::{RangeQuery, TermError};
use crate::target::{DeclaredContext, Index, Json, Owned, Pending};
use crate::{Error, KeysetCipher, Label, NonEmpty};
use vitaminc_protected::{Choice, Controlled, OpaqueDebug, Protected, TimingSafeEq};

/// One node's selector pair: its path selector `s` and its value selector
/// `vs`. Ordered, so a set can be sorted into one spelling.
#[derive(Clone, Copy, TimingSafeEq, PartialOrd, Ord)]
struct Pair16 {
    s: Tag,
    vs: Tag,
}

/// The selector pairs `{s, vs}` of a document's nodes, grouped by array
/// element: the pairs of the nodes outside any array element, and one
/// nested set per array element that is a container. A stored document
/// carries its own as `q`, which the server reads (`json_tree_query`), and
/// a containment query sends the set of the document it asks about.
///
/// It holds no plaintext: a selector is a keyed hash of a path, and a value
/// selector of a path and a value, which is what the database stores. It
/// prints opaquely all the same, since the pairs are derived from the
/// document's keys and values.
///
/// Equality is as sets, which is how `jsonb @>` reads one: two sets are
/// equal when they hold the same pairs in the same groups, whatever order
/// their lists are in. A stored `q` is shuffled, so two seals of one
/// document carry equal sets in different orders. The comparison is
/// constant-time in the pairs ([`TimingSafeEq`]); the sort that puts both
/// sides in one spelling first depends on the order of the pairs, which
/// the database holds.
#[derive(Clone, Default, OpaqueDebug)]
pub struct JsonSelectorSet {
    sv: Vec<Pair16>,
    el: Vec<JsonSelectorSet>,
}

impl TimingSafeEq for JsonSelectorSet {
    fn ts_eq(&self, other: &Self) -> Choice {
        let (a, b) = (self.canonical(), other.canonical());
        let mut equal = Choice::from(u8::from(
            a.sv.len() == b.sv.len() && a.el.len() == b.el.len(),
        ));
        for (x, y) in a.sv.iter().zip(&b.sv) {
            equal &= x.ts_eq(y);
        }
        for (x, y) in a.el.iter().zip(&b.el) {
            equal &= x.ts_eq(y);
        }
        equal
    }
}

impl PartialEq for JsonSelectorSet {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ts_eq(other))
    }
}
impl std::cmp::Eq for JsonSelectorSet {}

impl JsonSelectorSet {
    /// This set with every list sorted, recursively: one spelling per set
    /// of pairs and groups.
    fn canonical(&self) -> Self {
        let mut sv = self.sv.clone();
        sv.sort_unstable();
        let mut el: Vec<Self> = self.el.iter().map(Self::canonical).collect();
        el.sort_unstable_by(Self::cmp_canonical);
        Self { sv, el }
    }

    /// The order of two sets already in [`canonical`](Self::canonical)
    /// form: by their pairs, then by their groups in turn. A sort key, not a
    /// comparison of secrets.
    fn cmp_canonical(a: &Self, b: &Self) -> std::cmp::Ordering {
        a.sv.cmp(&b.sv).then_with(|| {
            a.el.iter()
                .zip(&b.el)
                .map(|(x, y)| Self::cmp_canonical(x, y))
                .find(|o| o.is_ne())
                .unwrap_or_else(|| a.el.len().cmp(&b.el.len()))
        })
    }

    /// Put the pairs of every group, and the groups of every element list,
    /// in a uniformly random order ([`shuffle`](super::shuffle::shuffle)).
    /// The server reads `q` as sets (`jsonb @>` over `sv` and `el`), so the
    /// order changes no answer, and the stored order says nothing of the
    /// document's.
    pub(crate) fn shuffle(&mut self, rng: &mut vitaminc::random::SafeRand) {
        super::shuffle::shuffle(&mut self.sv, rng);
        super::shuffle::shuffle(&mut self.el, rng);
        for group in &mut self.el {
            group.shuffle(rng);
        }
    }

    /// `jsonb @>` over two sets: every pair of `other` is some pair of this
    /// set, and every element group of `other` fits inside some element
    /// group of it, recursively. What the server computes natively over
    /// the two sets; here so a caller can decide containment over documents
    /// it holds, with no database.
    pub fn contains(&self, other: &JsonSelectorSet) -> bool {
        other.sv.iter().all(|pair| self.sv.contains(pair))
            && other
                .el
                .iter()
                .all(|group| self.el.iter().any(|mine| mine.contains(group)))
    }
}

/// The query term of [`Contains`], [`ContainedBy`] and `AtPath<Eq>`: the
/// [`JsonSelectorSet`] of the document the query asks about, and, for a
/// document whose root is a scalar, the alternative set that matches a
/// stored root array holding it. Serializes to the `query_json`
/// operand: `{"sv": [{"s": "…", "vs": "…"}, …], "el": [{"sv": …, "el": …},
/// …], "alt": {…}}`.
///
/// The set is sent in a random order of its own, drawn when the terms were
/// derived, as a stored
/// `q`'s order is drawn when its document is sealed: every pair list and
/// element-group list shuffled, recursively. `jsonb @>` is set containment
/// over arrays, so the order changes no answer, and a query shows no more
/// of the order of its keys than a stored row does. Two derivations of one
/// value therefore serialize differently and compare equal (equality is as
/// sets).
#[derive(Clone, OpaqueDebug, PartialEq, Eq)]
pub struct JsonQuery {
    selectors: JsonSelectorSet,
    alt: Option<JsonSelectorSet>,
}

impl JsonQuery {
    /// The query of an accessor: the selector set of the document that
    /// holds the value at the path, with no `alt`. The alternative matches
    /// a root array that holds a root scalar, which is containment; at a
    /// path, `("$", 1)` asks for the scalar `1`, not for an array holding
    /// it.
    pub(crate) fn at_path(terms: JsonTerms) -> Self {
        Self {
            selectors: terms.into_query_selectors(),
            alt: None,
        }
    }

    pub(crate) fn of_terms(terms: JsonTerms) -> Self {
        let alt = terms.alt().map(|(s, vs)| JsonSelectorSet {
            sv: vec![Pair16 { s, vs }],
            el: Vec::new(),
        });
        Self {
            selectors: terms.into_query_selectors(),
            alt,
        }
    }

    /// The query's selector set: what `<@` compares a stored document's
    /// against.
    pub fn selector_set(&self) -> &JsonSelectorSet {
        &self.selectors
    }

    /// Whether a stored document's selector set contains this query's, as
    /// the server decides `@>`: containment of the query's set, or of its
    /// alternative for a root scalar against a root array.
    pub fn matches(&self, stored: &JsonSelectorSet) -> bool {
        stored.contains(&self.selectors)
            || self.alt.as_ref().is_some_and(|alt| stored.contains(alt))
    }
}

/// The selector set of the nodes that sit directly in `parent` (`None` is
/// the top level), with the container elements in it nested as groups.
/// What a query sends, and what a document writes to `q` when it is sealed.
pub(crate) fn group_of(nodes: &[TermNode], parent: Option<usize>) -> JsonSelectorSet {
    let belongs = |index: usize, node: &TermNode| {
        if node.container_element {
            Some(index)
        } else {
            node.element
        }
    };
    JsonSelectorSet {
        sv: nodes
            .iter()
            .enumerate()
            .filter(|(i, n)| belongs(*i, n) == parent)
            .map(|(_, n)| Pair16 { s: n.s, vs: n.vs })
            .collect(),
        el: nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.container_element && n.element == parent)
            .map(|(i, _)| group_of(nodes, Some(i)))
            .collect(),
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PairWire {
    s: String,
    vs: String,
}

/// One group, as a query or a stored document's `q` spells it.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct GroupWire {
    sv: Vec<PairWire>,
    el: Vec<GroupWire>,
}

#[derive(Serialize, Deserialize)]
struct QueryWire {
    #[serde(flatten)]
    group: GroupWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alt: Option<GroupWire>,
}

impl From<&JsonSelectorSet> for GroupWire {
    fn from(group: &JsonSelectorSet) -> Self {
        Self {
            sv: group
                .sv
                .iter()
                .map(|p| PairWire {
                    s: base64(&p.s),
                    vs: base64(&p.vs),
                })
                .collect(),
            el: group.el.iter().map(GroupWire::from).collect(),
        }
    }
}

/// A selector set serializes as a stored `q` and a query do: `{"sv":
/// [{"s", "vs"}, …], "el": [group, …]}`.
impl Serialize for JsonSelectorSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        GroupWire::from(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonSelectorSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        JsonSelectorSet::try_from(GroupWire::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<GroupWire> for JsonSelectorSet {
    type Error = super::WireError;
    fn try_from(w: GroupWire) -> Result<Self, Self::Error> {
        let tag = |text: &str| {
            Tag::try_from(super::unbase64(text)?).map_err(|_| super::WireError("not 16 bytes"))
        };
        Ok(Self {
            sv: w
                .sv
                .iter()
                .map(|p| {
                    Ok(Pair16 {
                        s: tag(&p.s)?,
                        vs: tag(&p.vs)?,
                    })
                })
                .collect::<Result<_, super::WireError>>()?,
            el: w
                .el
                .into_iter()
                .map(JsonSelectorSet::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl Serialize for JsonQuery {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        QueryWire {
            group: GroupWire::from(&self.selectors),
            alt: self.alt.as_ref().map(GroupWire::from),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonQuery {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = QueryWire::deserialize(d)?;
        Ok(Self {
            selectors: JsonSelectorSet::try_from(wire.group).map_err(serde::de::Error::custom)?,
            alt: wire
                .alt
                .map(JsonSelectorSet::try_from)
                .transpose()
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// The query term of `AtPath<Lt | Lte | Gt | Gte>`: the selector of the
/// path and the leaf ordering term of the value, which the SQL compares
/// against the stored leaf's: `col -> $1 >= $2`. Serializes to the
/// `query_json_leaf` operand, `{"s": "…", "op": "…"}`. `Between`
/// sends two as one [`RangeQuery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonLeafQuery {
    s: Tag,
    op: Vec<u8>,
}

impl JsonLeafQuery {
    pub(crate) fn of_leaf(terms: &JsonTerms) -> Self {
        // `check` admitted only a number or a string, both of which carry a
        // term; an empty term here would be a leaf that cannot be.
        let leaf = terms.leaf();
        Self {
            s: leaf.map(|n| n.s).unwrap_or_default(),
            op: leaf.and_then(|n| n.op.clone()).unwrap_or_default(),
        }
    }

    /// The path's selector, for `->`.
    pub fn selector(&self) -> JsonSelector {
        JsonSelector(self.s)
    }

    /// The leaf's ordering term, as the `op` of a stored leaf is.
    pub fn ordering_term(&self) -> &[u8] {
        &self.op
    }
}

#[derive(Serialize, Deserialize)]
struct LeafWire {
    s: String,
    op: String,
}

impl Serialize for JsonLeafQuery {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        LeafWire {
            s: base64(&self.s),
            op: base64(&self.op),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonLeafQuery {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = LeafWire::deserialize(d)?;
        let s = super::unbase64(&wire.s)
            .ok()
            .and_then(|b| Tag::try_from(b).ok())
            .ok_or_else(|| serde::de::Error::custom("not a selector"))?;
        let op = super::unbase64(&wire.op).map_err(serde::de::Error::custom)?;
        Ok(Self { s, op })
    }
}

/// A path selector: what `->` and the path functions take. Prints and
/// serializes as the base64 the stored entry carries in `s`.
///
/// It is also what opens the entry `->` returns ([`open`](Self::open)):
/// the selector the client derived for the path is the one the entry must
/// carry, so a database that answers with another path's entry is refused.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsonSelector(pub(crate) Tag);

impl JsonSelector {
    /// The sixteen bytes.
    pub fn as_bytes(&self) -> &Tag {
        &self.0
    }

    /// The entry `col -> selector` returned, ready to open: the only way to
    /// open one. Opening it ([`DecryptInto<Value>`](crate::DecryptInto))
    /// first checks that the entry carries this selector, and refuses any
    /// other with [`Error::JsonWrongEntry`] before a key is retrieved: an
    /// entry's ciphertext is bound to the selector it carries, so a
    /// database that answers `$.salary` with the row's `$.bonus`, or with
    /// the sealed root (the whole document, whose selector is the root's),
    /// returns an entry that would open, and is not the one asked for.
    ///
    /// What the check covers is the path, read as a selector reads it: a
    /// position reads as the wildcard, so any element at the path passes,
    /// as `->` returns the first one. It does not cover the row: the same
    /// path's entry from another row of the column, returned with that
    /// row's header, opens (ADR 0010).
    pub fn open(&self, node: JsonNode) -> JsonExtracted {
        JsonExtracted::keyed(node, self.0)
    }
}

impl fmt::Display for JsonSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64(&self.0))
    }
}

impl fmt::Debug for JsonSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JsonSelector({})", base64(&self.0))
    }
}

impl Serialize for JsonSelector {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64(&self.0))
    }
}

/// One token a subtree read sends: the token of the node at a concrete
/// path (no wildcard), the path, and whether it is a probe, the element at
/// the bound of a wildcard level, which the read sends to learn whether an
/// array there is longer than the bound and never answers with.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Read {
    pub(crate) token: Tag,
    pub(crate) path: JsonPath,
    pub(crate) probe: bool,
}

/// The key of a subtree read: one token per concrete path the read's path
/// names, in document order, with a probe for each array a wildcard
/// expands, the bound the wildcards were expanded to, and the path it was
/// derived from, which
/// [`open`](Self::open) attaches to the rows the read returns. What
/// `json_tree_subtree(doc, tokens, budget)` takes is
/// [`tokens`](Self::tokens). Serializes as `{"t": ["…", …]}`; the paths
/// are not part of the wire.
///
/// Every token derives from its node's path alone, so a path with no
/// wildcard sends exactly one token and nothing that covers a node above
/// it. A wildcard (`$.items[*].price`) names no one node: the key holds a
/// token for each position below the bound (`$.items[0].price` …
/// `$.items[N − 1].price`) and a probe for the element at the bound
/// (`$.items[N]`, the element itself). A row where a probe names a node
/// opens to [`Error::JsonWildcardTruncated`](crate::Error::JsonWildcardTruncated),
/// never to part of the answer.
///
/// The key also holds what derives selectors under the column it was
/// derived for (the keyset's index-key PRF, shared with the keyset handle,
/// and the column's context), so that opening the rows can check each
/// one's selector against the path it must sit at. Neither is printed or
/// serialized.
#[derive(Clone, PartialEq, Eq)]
pub struct JsonSubtreeKey {
    pub(crate) reads: Vec<Read>,
    pub(crate) bound: u32,
    pub(crate) path: JsonPath,
    pub(crate) selectors: Selectors,
}

impl JsonSubtreeKey {
    /// The bound a wildcard expands to when the caller names none: 64
    /// elements per wildcard level, in the spirit of the walk's default
    /// budget.
    pub const DEFAULT_BOUND: u32 = 64;

    /// The tokens, as the base64 `json_tree_subtree` takes in its `tokens`
    /// array, in the key's order, the probes among them.
    pub fn tokens(&self) -> Vec<String> {
        self.reads.iter().map(|read| base64(&read.token)).collect()
    }

    /// The tokens' bytes, in the key's order. A token is a capability over
    /// the structure of its node's subtree in every row of the column, for
    /// as long as the column lives: send it to the server for a query, and
    /// nowhere else.
    pub fn token_bytes(&self) -> Vec<Tag> {
        self.reads.iter().map(|read| read.token).collect()
    }

    /// Which of [`tokens`](Self::tokens) are probes, by their places in it:
    /// one per element a wildcard level sits below, last at its level.
    /// Empty for a path with no wildcard.
    pub fn probes(&self) -> Vec<usize> {
        self.reads
            .iter()
            .enumerate()
            .filter(|(_, read)| read.probe)
            .map(|(i, _)| i)
            .collect()
    }

    /// The bound each wildcard level was expanded to.
    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// The path the key was derived from.
    pub fn path(&self) -> &JsonPath {
        &self.path
    }

    /// The rows the read this key keyed returned, ready to open: the only
    /// way to build a [`JsonSubtree`], so the rows always carry the key a
    /// sealed-root fallback is evaluated under.
    ///
    /// Opening the rows checks each one against the key, and refuses the
    /// rows with [`Error::JsonWrongEntry`] if one does not fit: a node a
    /// token names, at depth `0`, must carry the self tag of one of the
    /// key's tokens (each matched once, in order) and that token's path's
    /// selector and last step (its key, its position, or the root); every
    /// row beneath it must carry the selector of its parent's path extended
    /// by its own label, sit one level below its parent, follow the row
    /// before it in the document with no entry between, and carry the self
    /// tag of the token its label derives under its parent's. The self tags
    /// are not authenticated: matching them catches a corrupted row or a
    /// server that walked wrongly, and the selector, the position and the
    /// label are what bind a row to its place. The rows must also be of
    /// distinct entries of one document: an entry returned twice, or rows
    /// carrying two headers, are refused the same way.
    ///
    /// Not covered, by design: which row of the column the entries come
    /// from (ADR 0010), and which element a node at the path's selector
    /// sits under, since every element of an array shares its selector: a
    /// read of `$.items[1].price` can be answered with `$.items[0].price`
    /// of the same row. Nor whether the database left whole nodes out: a
    /// read answered with no rows opens as no node, and a wildcard read
    /// with some elements' rows left out, its probe's included, opens to
    /// the rest.
    pub fn open(&self, rows: Vec<JsonNode>) -> JsonSubtree {
        JsonSubtree::keyed(rows, self.clone())
    }
}

/// The tokens are capabilities: the key prints as its shape, not its bytes.
impl fmt::Debug for JsonSubtreeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonSubtreeKey")
            .field("tokens", &self.reads.len())
            .field("probes", &self.reads.iter().filter(|r| r.probe).count())
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
}

impl Serialize for JsonSubtreeKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire {
            t: Vec<String>,
        }
        Wire { t: self.tokens() }.serialize(s)
    }
}

/// The terms of an accessor's input: the path it was asked at, and the
/// index's terms of the document that holds the value there. What
/// [`Input<Pathed<A>>`](Input) derives, and what the JSON index's
/// [`Supports`] impls build an accessor's query from.
#[derive(Clone, Debug)]
pub struct AtPathTerms<T> {
    path: JsonPath,
    terms: T,
}

impl<T> AtPathTerms<T> {
    /// The path the query was asked at.
    pub fn path(&self) -> &JsonPath {
        &self.path
    }

    /// The terms of the document holding the value, or of both documents
    /// for a pair of bounds.
    pub fn terms(&self) -> &T {
        &self.terms
    }
}

impl QueryTerm for JsonQuery {}
impl QueryTerm for JsonLeafQuery {}

// =============================================================================
// Inputs: a path and a value, or a path and a pair of bounds
// =============================================================================

fn parse_path(text: &str) -> Result<JsonPath, Error> {
    JsonPath::parse(text).map_err(|e| Error::Term(TermError::JsonPath(e)))
}

/// A path and a value: the input of `AtPath<Eq>` and the single-bound
/// orderings. The index is declared over the document, so the plaintext
/// is a [`Value`], and the term is derived over the document that holds
/// the value at the path.
impl<P, V> Input<Pathed<One>> for (P, V)
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Plaintext = Value;
    type Terms<T: 'static> = AtPathTerms<T>;

    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, AtPathTerms<I::Term>, K>
    where
        I: Index<Value>,
        K: 'static,
    {
        let (path, value) = self;
        let path = match parse_path(path.as_ref()) {
            Ok(path) => path,
            Err(error) => return Pending::failed(keyset, error),
        };
        let holding = path.holding(value.into());
        keyset
            .run(
                index.operation::<K, Owned>().under(NonEmpty::from(label)),
                holding,
                extend,
            )
            .map(move |terms| AtPathTerms { path, terms })
    }
}

/// A path and a pair of bounds: the input of `AtPath<Between>`. Both
/// documents' terms derive under the one label, settled together.
impl<P, V> Input<Pathed<Pair>> for (P, (V, V))
where
    P: AsRef<str> + 'static,
    V: Into<Value> + 'static,
{
    type Plaintext = Value;
    type Terms<T: 'static> = AtPathTerms<(T, T)>;

    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, AtPathTerms<(I::Term, I::Term)>, K>
    where
        I: Index<Value>,
        K: 'static,
    {
        let (path, (lo, hi)) = self;
        let path = match parse_path(path.as_ref()) {
            Ok(path) => path,
            Err(error) => return Pending::failed(keyset, error),
        };
        let lo = keyset.run(
            index
                .operation::<K, Owned>()
                .under(NonEmpty::from(label.clone())),
            path.holding(lo.into()),
            extend.clone(),
        );
        let hi = keyset.run(
            index.operation::<K, Owned>().under(NonEmpty::from(label)),
            path.holding(hi.into()),
            extend,
        );
        lo.zip(hi).map(move |terms| AtPathTerms { path, terms })
    }
}

// =============================================================================
// What the index answers
// =============================================================================

/// A document is sealed under the caller's context ([`json_document`]
/// takes a [`CallerContext`](crate::target::CallerContext)), which is the
/// label a plan names, so its terms and a query's derive under the same
/// context and a plan typed with it answers the operators below.
///
/// [`json_document`]: crate::target::json_document
impl LabelledTarget for JsonDocument {}

/// Containment, both ways: the query's selector set, which the SQL compares
/// against the stored set in the direction the operator says.
macro_rules! containment {
    ($($op:ident),+ $(,)?) => {$(
        impl Supports<$op, Value> for Json {
            type Query = JsonQuery;
            type Verifier = ();
            fn check(&self, _: &Value) -> Result<(), Error> {
                Ok(())
            }
            fn verifier(&self, _: &Value) {}
            fn query((): (), terms: JsonTerms, _: QueryToken) -> JsonQuery {
                JsonQuery::of_terms(terms)
            }
        }
        impl Answers<$op, Value> for JsonDocument {
            type Via = Json;
        }
        impl DefaultIndex<Value> for $op {
            type Via = Json;
        }
    )+};
}
containment!(Contains, ContainedBy);

/// Equality at a path: the selector set of the document that holds the
/// value at the path, with no `alt`. For a scalar, containment of that set is
/// equality of the value at the path. For an object or an array it would be
/// containment (`{"x": 1}` matching `{"x": 1, "y": 2}`), so a container is
/// refused with [`TermError::JsonValueNotScalar`] when the query is
/// awaited. A position in the path reads as the wildcard, since selectors
/// do not tell positions apart.
impl<P, V> Supports<AtPath<Eq>, (P, V)> for Json
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Query = JsonQuery;
    type Verifier = ();
    fn check(&self, (path, value): &(P, V)) -> Result<(), Error> {
        let _ = parse_path(path.as_ref())?;
        scalar(&copy_of(value))
    }
    fn verifier(&self, _: &(P, V)) {}
    fn query((): (), terms: AtPathTerms<JsonTerms>, _: QueryToken) -> JsonQuery {
        JsonQuery::at_path(terms.terms)
    }
}
impl<P, V> Answers<AtPath<Eq>, (P, V)> for JsonDocument
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Via = Json;
}
impl<P, V> DefaultIndex<(P, V)> for AtPath<Eq>
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Via = Json;
}

/// The copy of the caller's plaintext a check reads: wiped when it drops.
fn copy_of<V: Into<Value> + Clone>(value: &V) -> Protected<PlainJson> {
    PlainJson::protect(value.clone().into())
}

/// Whether `value` is a scalar, which equality at a path compares.
fn scalar(value: &Protected<PlainJson>) -> Result<(), Error> {
    let value = value.risky_ref().value();
    match value {
        Value::Object(_) | Value::Array(_) => Err(TermError::JsonValueNotScalar.into()),
        _ => Ok(()),
    }
}

/// Whether `value` is a leaf the index orders: a number or a string.
fn ordered(value: &Protected<PlainJson>) -> Result<(), Error> {
    let value = value.risky_ref().value();
    match value {
        Value::Number(_) | Value::String(_) => Ok(()),
        _ => Err(TermError::JsonLeafNotOrdered.into()),
    }
}

/// Whether the index orders the leaves at `path`: some path in its
/// `ordered` option covers it. A path that names a position is refused
/// first: the comparison extracts by selector, which reads the position as
/// the wildcard, so it would compare an unspecified element at the path
/// rather than the one named.
fn orders(index: &Json, path: &JsonPath) -> Result<(), Error> {
    if path.names_a_position() {
        Err(TermError::JsonOrderingAtPosition.into())
    } else if index.options.orders(path) {
        Ok(())
    } else {
        Err(TermError::JsonPathNotOrdered.into())
    }
}

/// The orderings at a path: the path's selector and the value's leaf
/// ordering term. Refused, when the query is awaited, for a value that is
/// neither a number nor a string, and for a path the index does not order
/// ([`JsonOptions::ordered`]): no stored leaf there carries a term, so the
/// comparison would match no row.
macro_rules! orderings {
    ($($op:ident),+ $(,)?) => {$(
        impl<P, V> Supports<AtPath<$op>, (P, V)> for Json
        where
            P: AsRef<str> + 'static,
            V: Into<Value> + Clone + 'static,
        {
            type Query = JsonLeafQuery;
            type Verifier = ();
            fn check(&self, (path, value): &(P, V)) -> Result<(), Error> {
                let path = parse_path(path.as_ref())?;
                orders(self, &path)?;
                ordered(&copy_of(value))
            }
            fn verifier(&self, _: &(P, V)) {}
            fn query((): (), terms: AtPathTerms<JsonTerms>, _: QueryToken) -> JsonLeafQuery {
                JsonLeafQuery::of_leaf(&terms.terms)
            }
        }
        impl<P, V> Answers<AtPath<$op>, (P, V)> for JsonDocument
        where
            P: AsRef<str> + 'static,
            V: Into<Value> + Clone + 'static,
        {
            type Via = Json;
        }
        impl<P, V> DefaultIndex<(P, V)> for AtPath<$op>
        where
            P: AsRef<str> + 'static,
            V: Into<Value> + Clone + 'static,
        {
            type Via = Json;
        }
    )+};
}
orderings!(Lt, Lte, Gt, Gte);

impl<P, V> Supports<AtPath<Between>, (P, (V, V))> for Json
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Query = RangeQuery<JsonLeafQuery>;
    type Verifier = ();
    fn check(&self, (path, (lo, hi)): &(P, (V, V))) -> Result<(), Error> {
        let path = parse_path(path.as_ref())?;
        orders(self, &path)?;
        ordered(&copy_of(lo))?;
        ordered(&copy_of(hi))
    }
    fn verifier(&self, _: &(P, (V, V))) {}
    fn query(
        (): (),
        terms: AtPathTerms<(JsonTerms, JsonTerms)>,
        _: QueryToken,
    ) -> RangeQuery<JsonLeafQuery> {
        let (lo, hi) = &terms.terms;
        RangeQuery::new(JsonLeafQuery::of_leaf(lo), JsonLeafQuery::of_leaf(hi))
    }
}
impl<P, V> Answers<AtPath<Between>, (P, (V, V))> for JsonDocument
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Via = Json;
}
impl<P, V> DefaultIndex<(P, (V, V))> for AtPath<Between>
where
    P: AsRef<str> + 'static,
    V: Into<Value> + Clone + 'static,
{
    type Via = Json;
}

/// The options a query derives under must be the stored document's; a
/// plan that declares the index carries them, and a query through it takes
/// them from there.
impl Json {
    /// The index's options: its layout, and the paths it orders.
    pub fn options(&self) -> &JsonOptions {
        &self.options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(n: u8) -> Pair16 {
        Pair16 {
            s: [n; 16],
            vs: [n + 100; 16],
        }
    }

    /// Selector sets compare as the sets `jsonb @>` reads: the order of
    /// their lists does not count, their contents and their grouping do.
    #[test]
    fn selector_sets_are_equal_as_sets() {
        let group = |sv: Vec<Pair16>, el: Vec<JsonSelectorSet>| JsonSelectorSet { sv, el };
        let a = group(
            vec![pair(1), pair(2)],
            vec![
                group(vec![pair(3), pair(4)], vec![]),
                group(vec![pair(5)], vec![]),
            ],
        );
        let shuffled = group(
            vec![pair(2), pair(1)],
            vec![
                group(vec![pair(5)], vec![]),
                group(vec![pair(4), pair(3)], vec![]),
            ],
        );
        assert_eq!(a, shuffled, "the same pairs in the same groups");
        let regrouped = group(
            vec![pair(1), pair(2)],
            vec![
                group(vec![pair(3)], vec![]),
                group(vec![pair(4), pair(5)], vec![]),
            ],
        );
        assert_ne!(a, regrouped, "the grouping counts");
        let fewer = group(vec![pair(1)], a.el.clone());
        assert_ne!(a, fewer, "a pair fewer");
        let more_groups = group(a.sv.clone(), {
            let mut el = a.el.clone();
            el.push(JsonSelectorSet::default());
            el
        });
        assert_ne!(a, more_groups, "a group more");
        let nested = group(
            vec![],
            vec![group(vec![], vec![group(vec![pair(1)], vec![])])],
        );
        assert_ne!(
            nested,
            group(vec![], vec![group(vec![pair(1)], vec![])]),
            "depth counts"
        );
    }
    use serde_json::json;

    #[test]
    fn a_query_serializes_as_the_query_operand() {
        let pair = |b: u8| Pair16 {
            s: [b; 16],
            vs: [b + 1; 16],
        };
        let query = JsonQuery {
            selectors: JsonSelectorSet {
                sv: vec![pair(1)],
                el: vec![JsonSelectorSet {
                    sv: vec![pair(3)],
                    el: vec![],
                }],
            },
            alt: None,
        };
        let json = serde_json::to_value(&query).unwrap();
        assert_eq!(
            json,
            json!({
                "sv": [{"s": "AQEBAQEBAQEBAQEBAQEBAQ==", "vs": "AgICAgICAgICAgICAgICAg=="}],
                "el": [{"sv": [{"s": "AwMDAwMDAwMDAwMDAwMDAw==", "vs": "BAQEBAQEBAQEBAQEBAQEBA=="}], "el": []}],
            })
        );
        let back: JsonQuery = serde_json::from_value(json).unwrap();
        assert_eq!(back, query);
    }

    #[test]
    fn a_selector_prints_as_its_base64_and_a_subtree_key_hides_its_token() {
        let selector = JsonSelector([0xab; 16]);
        assert_eq!(selector.to_string(), "q6urq6urq6urq6urq6urqw==");
        assert_eq!(
            format!("{selector:?}"),
            format!("JsonSelector({})", "q6urq6urq6urq6urq6urqw==")
        );
        let key = JsonSubtreeKey {
            reads: vec![
                Read {
                    token: [0xcd; 16],
                    path: JsonPath::parse("$.a[0]").unwrap(),
                    probe: false,
                },
                Read {
                    token: [0xab; 16],
                    path: JsonPath::parse("$.a[1]").unwrap(),
                    probe: true,
                },
            ],
            bound: 1,
            path: JsonPath::parse("$.a[*]").unwrap(),
            selectors: Selectors::for_tests(),
        };
        assert_eq!(
            key.tokens(),
            ["zc3Nzc3Nzc3Nzc3Nzc3NzQ==", "q6urq6urq6urq6urq6urqw=="],
            "every token, in order, the probe among them"
        );
        assert_eq!(key.token_bytes(), [[0xcd; 16], [0xab; 16]]);
        assert_eq!(key.probes(), [1], "the probe is marked by its place");
        assert_eq!(key.bound(), 1);
        assert_eq!(
            serde_json::to_value(&key).unwrap(),
            serde_json::json!({"t": ["zc3Nzc3Nzc3Nzc3Nzc3NzQ==", "q6urq6urq6urq6urq6urqw=="]}),
            "the wire carries the tokens and nothing of the paths"
        );
        assert_eq!(
            format!("{key:?}"),
            "JsonSubtreeKey { tokens: 2, probes: 1, bound: 1, .. }",
            "a token is a capability: it never prints"
        );
    }

    #[test]
    fn accessor_terms_carry_the_path_they_were_asked_at() {
        let terms = AtPathTerms {
            path: JsonPath::parse("$.a[*]").unwrap(),
            terms: 7u8,
        };
        assert_eq!(terms.path(), &JsonPath::parse("$.a[*]").unwrap());
        assert_eq!(terms.terms(), &7);
    }

    #[test]
    fn the_index_reports_its_options() {
        let open = JsonOptions {
            sealed_root: false,
            ..JsonOptions::new()
        };
        assert_eq!(Json::new(open.clone()).options(), &open);
        assert_eq!(Json::default().options(), &JsonOptions::default());
    }

    #[test]
    fn a_selector_set_round_trips_through_its_wire_form() {
        let set = JsonSelectorSet {
            sv: vec![Pair16 {
                s: [1; 16],
                vs: [2; 16],
            }],
            el: vec![JsonSelectorSet {
                sv: vec![Pair16 {
                    s: [3; 16],
                    vs: [4; 16],
                }],
                el: Vec::new(),
            }],
        };
        let wire = serde_json::to_value(&set).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "sv": [{"s": "AQEBAQEBAQEBAQEBAQEBAQ==", "vs": "AgICAgICAgICAgICAgICAg=="}],
                "el": [{"sv": [{"s": "AwMDAwMDAwMDAwMDAwMDAw==", "vs": "BAQEBAQEBAQEBAQEBAQEBA=="}], "el": []}],
            })
        );
        let back: JsonSelectorSet = serde_json::from_value(wire).unwrap();
        assert_eq!(back, set);
        assert!(
            serde_json::from_value::<JsonSelectorSet>(serde_json::json!({"sv": [], "el": []}))
                .unwrap()
                .el
                .is_empty()
        );
        assert!(
            serde_json::from_value::<JsonSelectorSet>(
                serde_json::json!({"sv": [{"s": "zz", "vs": "00"}], "el": []})
            )
            .is_err(),
            "a pair that is not two tags is refused"
        );
    }

    #[test]
    fn group_containment_is_jsonbs_rule() {
        let pair = |b: u8| Pair16 {
            s: [b; 16],
            vs: [b; 16],
        };
        let element = |pairs: &[u8]| JsonSelectorSet {
            sv: pairs.iter().map(|&b| pair(b)).collect(),
            el: vec![],
        };
        let stored = JsonSelectorSet {
            sv: vec![pair(0)],
            el: vec![element(&[1, 5]), element(&[7, 2])],
        };
        // The issue's example: 1 and 2 sit in different elements.
        assert!(!stored.contains(&JsonSelectorSet {
            sv: vec![],
            el: vec![element(&[1, 2])],
        }));
        assert!(stored.contains(&JsonSelectorSet {
            sv: vec![],
            el: vec![element(&[1, 5])],
        }));
        assert!(stored.contains(&JsonSelectorSet {
            sv: vec![pair(0)],
            el: vec![element(&[1]), element(&[2])],
        }));
        assert!(!stored.contains(&JsonSelectorSet {
            sv: vec![pair(9)],
            el: vec![],
        }));
    }
}
