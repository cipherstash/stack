//! The query terms of the JSON index, and how the operators reach it.
//!
//! A containment needle is the **element-nested projection** of the
//! needle's terms: the selector pairs `{s, vs}` of every node, grouped by
//! the array element they sit in. A stored document carries its own
//! projection, built the same way, as `q`, which the server reads, and
//! native `jsonb @>` over the two projections is exact containment: each needle element has to fit inside
//! one stored element, which is PostgreSQL's own rule for arrays. The
//! design's "The preferred form" records why no re-check is needed.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::derive::{JsonTerms, TermNode};
use super::path::JsonPath;
use super::{base64, JsonDocument, JsonNode, JsonOptions, JsonSubtree, Tag};
use crate::op::{
    Answers, AtPath, Between, ContainedBy, Contains, DefaultIndex, Eq, Gt, Gte, Input,
    LabelledTarget, Lt, Lte, One, Pair, Pathed, QueryTerm, QueryToken, Supports,
};
use crate::sem::{RangeQuery, TermError};
use crate::target::{DeclaredContext, Index, Json, Owned, Pending};
use crate::{Error, KeysetCipher, Label, NonEmpty};

/// One selector pair of a projection.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pair16 {
    s: Tag,
    vs: Tag,
}

/// The element-nested projection of a document: the selector pairs that
/// sit outside any array element, and one nested projection per array
/// element that is a container. What a stored document carries as `q`,
/// which the server reads (`json_tree_query`), and what a containment
/// needle is.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct JsonProjection {
    sv: Vec<Pair16>,
    el: Vec<JsonProjection>,
}

impl JsonProjection {
    /// `jsonb @>` over two projections: every needle pair is some pair of
    /// this projection, and every needle element fits inside some element
    /// of it, recursively. What the server computes natively over the two
    /// projections; here so a caller can decide containment over documents
    /// it holds, with no database.
    pub fn contains(&self, needle: &JsonProjection) -> bool {
        needle.sv.iter().all(|pair| self.sv.contains(pair))
            && needle
                .el
                .iter()
                .all(|group| self.el.iter().any(|mine| mine.contains(group)))
    }
}

/// The query term of [`Contains`], [`ContainedBy`] and `AtPath<Eq>`: the
/// element-nested projection of the needle's selectors, and, for a needle
/// whose root is a scalar, the alternative projection that matches a
/// stored root array holding it. Serializes to the `query_json_tree`
/// operand: `{"sv": [{"s": "…", "vs": "…"}, …], "el": [{"sv": …, "el": …},
/// …], "alt": {…}}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonQuery {
    group: JsonProjection,
    alt: Option<JsonProjection>,
}

impl JsonQuery {
    /// The needle of an accessor: the projection of the document that holds
    /// the value at the path, with no `alt`. The alternative matches a root
    /// array that holds a root scalar, which is containment; at a path,
    /// `("$", 1)` asks for the scalar `1`, not for an array holding it.
    pub(crate) fn at_path(terms: &JsonTerms) -> Self {
        Self {
            group: group_of(terms.nodes(), None),
            alt: None,
        }
    }

    pub(crate) fn of_terms(terms: &JsonTerms) -> Self {
        let alt = terms.alt().map(|(s, vs)| JsonProjection {
            sv: vec![Pair16 { s, vs }],
            el: Vec::new(),
        });
        Self {
            group: group_of(terms.nodes(), None),
            alt,
        }
    }

    /// The needle's projection: what `<@` compares a stored document's
    /// projection against.
    pub fn projection(&self) -> &JsonProjection {
        &self.group
    }

    /// Whether a stored document's projection contains this needle, as the
    /// server decides `@>`: containment of the needle's projection, or of
    /// its alternative for a root scalar against a root array.
    pub fn matches(&self, stored: &JsonProjection) -> bool {
        stored.contains(&self.group) || self.alt.as_ref().is_some_and(|alt| stored.contains(alt))
    }
}

/// The group of the nodes that sit directly in `parent` (`None` is the top
/// level), with the container elements in it nested as groups. What a
/// needle is, and what a document writes to `q` when it is sealed.
pub(crate) fn group_of(nodes: &[TermNode], parent: Option<usize>) -> JsonProjection {
    let belongs = |index: usize, node: &TermNode| {
        if node.container_element {
            Some(index)
        } else {
            node.element
        }
    };
    JsonProjection {
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

/// One group, as a needle or a stored document's `q` spells it.
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

impl From<&JsonProjection> for GroupWire {
    fn from(group: &JsonProjection) -> Self {
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

/// A projection serializes as a stored `q` and a needle do: `{"sv": [{"s",
/// "vs"}, …], "el": [group, …]}`.
impl Serialize for JsonProjection {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        GroupWire::from(self).serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonProjection {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        JsonProjection::try_from(GroupWire::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<GroupWire> for JsonProjection {
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
                .map(JsonProjection::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl Serialize for JsonQuery {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        QueryWire {
            group: GroupWire::from(&self.group),
            alt: self.alt.as_ref().map(GroupWire::from),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for JsonQuery {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = QueryWire::deserialize(d)?;
        Ok(Self {
            group: JsonProjection::try_from(wire.group).map_err(serde::de::Error::custom)?,
            alt: wire
                .alt
                .map(JsonProjection::try_from)
                .transpose()
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// The query term of `AtPath<Lt | Lte | Gt | Gte>`: the selector of the
/// path and the leaf ordering term of the value, which the SQL compares
/// against the stored leaf's: `col -> $1 >= $2`. Serializes to the
/// `query_json_tree_leaf` operand, `{"s": "…", "op": "…"}`. `Between`
/// sends two as one [`RangeQuery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonLeafQuery {
    s: Tag,
    op: Vec<u8>,
}

impl JsonLeafQuery {
    fn of_leaf(terms: &JsonTerms) -> Self {
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
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsonSelector(pub(crate) Tag);

impl JsonSelector {
    /// The sixteen bytes.
    pub fn as_bytes(&self) -> &Tag {
        &self.0
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

/// One gate of a subtree walk: what the entry at one depth below the
/// walk's token must be for the walk to descend through it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// The selector of the path down to that depth: a key step, or a
    /// wildcard, whose selector every element carries.
    Selector(Tag),
    /// An array position: the one ordinal probed at that depth, and the
    /// selector of an element there (the wildcard's), which the entry at
    /// that ordinal must carry. The ordinal alone would admit an object
    /// member that ranks there in a row whose node at the path is an
    /// object.
    Slot(u32, Tag),
}

impl Gate {
    /// The gate as `json_tree_subtree_at` takes it: the selector's base64, or
    /// `#n:` and the element selector's base64 for a position.
    fn text(&self) -> String {
        match self {
            Gate::Selector(s) => base64(s),
            Gate::Slot(n, s) => format!("#{n}:{}", base64(s)),
        }
    }
}

/// The key of a subtree walk: the token of the deepest node on the path
/// the client can derive, one gate per step below it, and the path it was
/// derived from, which [`open`](Self::open) attaches to the rows the walk
/// returns. Serializes as `{"t": "…", "g": ["…", "#0:…", …]}`, `g` omitted
/// when empty; the path is not part of the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct JsonSubtreeKey {
    pub(crate) token: Tag,
    pub(crate) gates: Vec<Gate>,
    pub(crate) path: JsonPath,
}

impl JsonSubtreeKey {
    /// The token, as the base64 the walk takes.
    pub fn token(&self) -> String {
        base64(&self.token)
    }

    /// The token's bytes. A token is a capability over the structure of
    /// one subtree in every row of the column, for as long as the column
    /// lives: send it to the server for a query, and nowhere else.
    pub fn token_bytes(&self) -> &Tag {
        &self.token
    }

    /// The gates the walk descends through below the token, one per step,
    /// as `json_tree_subtree_at` takes them: a selector's base64, or
    /// `#n:<selector>` for an array position, the selector being the array
    /// elements' own. Empty when the token names the walked node itself,
    /// which `json_tree_subtree` takes.
    pub fn gates(&self) -> Vec<String> {
        self.gates.iter().map(Gate::text).collect()
    }

    /// The path the key was derived from.
    pub fn path(&self) -> &JsonPath {
        &self.path
    }

    /// The rows the walk this key keyed returned, ready to open: the only
    /// way to build a [`JsonSubtree`], so the rows always carry the path
    /// a sealed-root fallback is opened at. With no gates the rows came
    /// from `json_tree_subtree(doc, token)` and are the descendants of the
    /// path's node; with gates they came from `json_tree_subtree_at(doc,
    /// token, gates)` and are the nodes the path reaches, with theirs. The
    /// key knows which, so the fallback opens to what the walked rows
    /// open to either way.
    pub fn open(&self, rows: Vec<JsonNode>) -> JsonSubtree {
        JsonSubtree::keyed(rows, self.path.clone(), self.gates.is_empty())
    }
}

/// The token is a capability: it prints as the key's shape, not its bytes.
impl fmt::Debug for JsonSubtreeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonSubtreeKey")
            .field("gates", &self.gates.len())
            .finish_non_exhaustive()
    }
}

impl Serialize for JsonSubtreeKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire {
            t: String,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            g: Vec<String>,
        }
        Wire {
            t: base64(&self.token),
            g: self.gates(),
        }
        .serialize(s)
    }
}

/// The terms of an accessor's input: the path it was asked at, and the
/// index's terms of the needle that holds the value there. What
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

    /// The terms of the needle, or of both needles for a pair of bounds.
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
/// is a [`Value`], and the term is derived over the needle that holds the
/// value at the path.
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
        let needle = path.needle(value.into());
        keyset
            .run(
                index.operation::<K, Owned>().under(NonEmpty::from(label)),
                needle,
                extend,
            )
            .map(move |terms| AtPathTerms { path, terms })
    }
}

/// A path and a pair of bounds: the input of `AtPath<Between>`. Both
/// needles derive under the one label, settled together.
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
            path.needle(lo.into()),
            extend.clone(),
        );
        let hi = keyset.run(
            index.operation::<K, Owned>().under(NonEmpty::from(label)),
            path.needle(hi.into()),
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

/// Containment, both ways: the needle's projection, which the SQL compares
/// against the stored projection in the direction the operator says.
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
                JsonQuery::of_terms(&terms)
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

/// Equality at a path: the needle that holds the value at the path,
/// projected, with no `alt`. For a scalar, containment of that needle is
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
        scalar(&value.clone().into())
    }
    fn verifier(&self, _: &(P, V)) {}
    fn query((): (), terms: AtPathTerms<JsonTerms>, _: QueryToken) -> JsonQuery {
        JsonQuery::at_path(&terms.terms)
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

/// Whether `value` is a scalar, which equality at a path compares.
fn scalar(value: &Value) -> Result<(), Error> {
    match value {
        Value::Object(_) | Value::Array(_) => Err(TermError::JsonValueNotScalar.into()),
        _ => Ok(()),
    }
}

/// Whether `value` is a leaf the index orders: a number or a string.
fn ordered(value: &Value) -> Result<(), Error> {
    match value {
        Value::Number(_) | Value::String(_) => Ok(()),
        _ => Err(TermError::JsonLeafNotOrdered.into()),
    }
}

/// Whether the index orders the leaves at `path`: some path in its
/// `ordered` option covers it. A path that names a position is refused
/// first: the comparison extracts by selector, which reads the position as
/// the wildcard, so it would compare the first element at the path rather
/// than the one named.
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
                ordered(&value.clone().into())
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
        ordered(&lo.clone().into())?;
        ordered(&hi.clone().into())
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
    use serde_json::json;

    #[test]
    fn a_query_serializes_as_the_needle_operand() {
        let pair = |b: u8| Pair16 {
            s: [b; 16],
            vs: [b + 1; 16],
        };
        let query = JsonQuery {
            group: JsonProjection {
                sv: vec![pair(1)],
                el: vec![JsonProjection {
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
            token: [0xcd; 16],
            gates: vec![Gate::Selector([0xab; 16]), Gate::Slot(3, [0xab; 16])],
            path: JsonPath::parse("$.a.b[3]").unwrap(),
        };
        assert_eq!(key.token(), "zc3Nzc3Nzc3Nzc3Nzc3NzQ==");
        assert_eq!(key.token_bytes(), &[0xcd; 16]);
        assert_eq!(
            key.gates(),
            ["q6urq6urq6urq6urq6urqw==", "#3:q6urq6urq6urq6urq6urqw=="]
        );
        assert_eq!(
            serde_json::to_value(&key).unwrap(),
            serde_json::json!({"t": "zc3Nzc3Nzc3Nzc3Nzc3NzQ==", "g": ["q6urq6urq6urq6urq6urqw==", "#3:q6urq6urq6urq6urq6urqw=="]})
        );
        assert_eq!(
            format!("{key:?}"),
            "JsonSubtreeKey { gates: 2, .. }",
            "a token is a capability: it never prints"
        );
        let bare = JsonSubtreeKey {
            token: [0xcd; 16],
            gates: Vec::new(),
            path: JsonPath::parse("$.a").unwrap(),
        };
        assert_eq!(
            serde_json::to_value(&bare).unwrap(),
            serde_json::json!({"t": "zc3Nzc3Nzc3Nzc3Nzc3NzQ=="})
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
    fn a_projection_round_trips_through_its_wire_form() {
        let projection = JsonProjection {
            sv: vec![Pair16 {
                s: [1; 16],
                vs: [2; 16],
            }],
            el: vec![JsonProjection {
                sv: vec![Pair16 {
                    s: [3; 16],
                    vs: [4; 16],
                }],
                el: Vec::new(),
            }],
        };
        let wire = serde_json::to_value(&projection).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({
                "sv": [{"s": "AQEBAQEBAQEBAQEBAQEBAQ==", "vs": "AgICAgICAgICAgICAgICAg=="}],
                "el": [{"sv": [{"s": "AwMDAwMDAwMDAwMDAwMDAw==", "vs": "BAQEBAQEBAQEBAQEBAQEBA=="}], "el": []}],
            })
        );
        let back: JsonProjection = serde_json::from_value(wire).unwrap();
        assert_eq!(back, projection);
        assert!(
            serde_json::from_value::<JsonProjection>(serde_json::json!({"sv": [], "el": []}))
                .unwrap()
                .el
                .is_empty()
        );
        assert!(
            serde_json::from_value::<JsonProjection>(
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
        let element = |pairs: &[u8]| JsonProjection {
            sv: pairs.iter().map(|&b| pair(b)).collect(),
            el: vec![],
        };
        let stored = JsonProjection {
            sv: vec![pair(0)],
            el: vec![element(&[1, 5]), element(&[7, 2])],
        };
        // The issue's example: 1 and 2 sit in different elements.
        assert!(!stored.contains(&JsonProjection {
            sv: vec![],
            el: vec![element(&[1, 2])],
        }));
        assert!(stored.contains(&JsonProjection {
            sv: vec![],
            el: vec![element(&[1, 5])],
        }));
        assert!(stored.contains(&JsonProjection {
            sv: vec![pair(0)],
            el: vec![element(&[1]), element(&[2])],
        }));
        assert!(!stored.contains(&JsonProjection {
            sv: vec![pair(9)],
            el: vec![],
        }));
    }
}
