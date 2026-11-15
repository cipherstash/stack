//! The `json_tree` family: an encrypted JSON document stored as one entry
//! per node, with node-local ciphertexts, a token chain and exact
//! containment. HAND-WRITTEN, like the v3 SteVec structs and for the same
//! reason: the bodies are not derivable from the catalog. The SQL is
//! `src/v3/json_tree/`, confined to EQL v4; the family is not in the
//! catalog yet, so it is not in [`super::all`] nor in the target table.
//!
//! Stack Encrypt's [`Json`](stack_encrypt::target::Json) index produces the
//! document ([`stack_encrypt::json::JsonDocument`], whose wire form is the
//! `h` and `sv` here) and the query operands; these types are the SQL
//! contract around them, with the `v` and `i` envelope, and the
//! [`EncryptTarget`] / [`DecryptSource`] impls that let a Rust program name
//! [`JsonTreeDocument`] as a target:
//! `document.encrypt_into_with_context(&keyset, column)` under an
//! [`Identifier`]. As a field of a derived record, its field reference has the
//! JSON queries (`contains`, `at`, `elements`, `predicate`, `children`),
//! which return the query types here
//! ([`JsonQueries`](stack_encrypt::json::JsonQueries)), under the options
//! the field's `#[stash(json(..))]` names
//! ([`JsonTarget`](stack_encrypt::json::JsonTarget)). A document with
//! no record is queried through a data plan that names the type
//! (`JsonSearch`) under the same column, and its operand converts into the
//! operand types here (see [`crate::encryption`]). The
//! design is `docs/plans/2026-10-17-json-tree-index.md` at
//! the repository root.

use schemars::{schema_for, JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_encrypt::json::{
    JsonDocument, JsonElementsQuery, JsonLeafQuery, JsonNode, JsonOptions, JsonPath, JsonPlaintext,
    JsonPredicateQuery, JsonQueries, JsonQuery, JsonSelector, JsonSubtree, JsonSubtreeKey,
    JsonTarget,
};
use stack_encrypt::target::{
    json_document, AeadContext, Borrowed, DecryptSource, EncryptTarget, ExpectedContext, Index,
    IndexSpec, Json, RequiredContext, StoredContext,
};
use stack_encrypt::{DecryptField, Decryptable, Decryption, Encryption, Error, NonEmpty};
use ts_rs::TS;
use zeroize::Zeroize;

use crate::encoding::{Base64Text, Base85Text};
use crate::v4::{DomainType, SchemaVersion};
use crate::Identifier;

/// A path selector `s` (and the value selector `vs` of a projection pair):
/// sixteen bytes in [`Base64Text`]. Column-wide: the same path has the
/// same selector in every row, which is what `->` and containment match on.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeSelector(pub Base64Text);

/// A node's ciphertext `c`, in [`Base85Text`], which no SQL function
/// decodes. The AES-GCM envelope of the node's label, kind, child count and
/// scalar value under the document's data key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeCiphertext(pub Base85Text);

/// An eight-byte chain tag in [`Base64Text`]: an entry's self tag `x`, the
/// first eight bytes of `H("x" ‖ iv ‖ t)` for the entry's own token `t`, or
/// its parent tag `p`, the first eight bytes of
/// `H("p" ‖ iv ‖ t(parent) ‖ LE32(o))`. Salted by the document's `iv`, so
/// unlinkable across rows at rest. `eql_v4.json_tree_subtree` derives the
/// same text with `encode(substr(…, 1, 8), 'base64')` to find the node a
/// token names (`x`) and its children (`p`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeTag(pub Base64Text);

/// A leaf ordering term `op`, in [`Base64Text`]: the CLLW OPE term of a
/// number or string leaf at a path the index orders. `eql_v4.ord_term`
/// decodes it to the bytea-backed `eql_v4_internal.ope_cllw` domain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeOrderingTerm(pub Base64Text);

/// The document's key header `h`, in [`Base64Text`]: what retrieving the
/// document's data key needs, and the root's layout
/// ([`stack_encrypt::json::JsonHeader`]'s bytes). Stored once per document,
/// and grafted onto every entry an extractor returns. The SQL decodes it to
/// read the `iv` the parent tags are salted by and the sealed-root flag.
/// Not the v3 SteVec [`KeyHeader`](crate::v3::terms::KeyHeader), which is
/// base85 and which SQL never parses.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeKeyHeader(pub Base64Text);

/// `public.eql_v4_json_search`: a JSON tree document, `{v, i, h, sv:
/// [entry], q: group}`. Strict. `h` is the document's key header, stored
/// once (every entry is sealed under the document's one data key); `sv`
/// holds one entry per node, the root first and the rest in a random order
/// drawn when the document was sealed; `q` is
/// the document's containment projection, one `{s, vs}` pair per node
/// nested by array element, which the client writes beside the entries
/// and which is the only place the value selectors live: the server's
/// `eql_v4.json_tree_query` reads it, and the engine takes it as the
/// projection when it reads a document back.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeDocument {
    pub v: SchemaVersion,
    pub i: Identifier,
    pub h: JsonTreeKeyHeader,
    pub sv: Vec<JsonTreeEntry>,
    pub q: JsonTreeQueryGroup,
}

/// `public.eql_v4_json_entry`: one node. `s` is the path selector,
/// `c` the node's own ciphertext, `x` the self tag by which a read finds
/// the node its token names; `p` the parent tag below the chain's heads,
/// which a read probes by ordinal; `op` the leaf ordering term.
/// `h`, `j`, `d`, `v` and `i` are what the extractors graft onto an entry
/// they return, so that it can be opened.
///
/// An entry a query returned is the database's word and does not open on
/// its own: open the entry `->` returned through the selector that asked
/// for it ([`JsonTreeExtracted::from_selector`]), and a read's rows through
/// the key that keyed it ([`JsonTreeSubtree::from_key`]). Each checks that
/// the rows are the ones it asked for.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeEntry {
    pub s: JsonTreeSelector,
    pub c: JsonTreeCiphertext,
    pub x: JsonTreeTag,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub p: Option<JsonTreeTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub op: Option<JsonTreeOrderingTerm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub h: Option<JsonTreeKeyHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub j: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub d: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub v: Option<SchemaVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub i: Option<Identifier>,
}

/// One selector pair of a containment needle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeQueryPair {
    pub s: JsonTreeSelector,
    pub vs: JsonTreeSelector,
}

/// One group of a containment needle: the pairs that sit directly in it,
/// and one nested group per array element that is a container.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeQueryGroup {
    pub sv: Vec<JsonTreeQueryPair>,
    pub el: Vec<JsonTreeQueryGroup>,
}

/// `eql_v4.query_json`: a containment needle, the element-nested
/// projection of the needle document's selectors, with the alternative
/// projection a root scalar carries. Strict. What
/// [`stack_encrypt::json::JsonQuery`] serializes to; [`TryFrom`] converts
/// one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeQuery {
    pub sv: Vec<JsonTreeQueryPair>,
    pub el: Vec<JsonTreeQueryGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub alt: Option<JsonTreeQueryGroup>,
}

/// `eql_v4.query_json_leaf`: an ordering operand at a path, the path's
/// selector and the leaf ordering term. What
/// [`stack_encrypt::json::JsonLeafQuery`] serializes to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeLeafQuery {
    pub s: JsonTreeSelector,
    pub op: JsonTreeOrderingTerm,
}

/// A read token, in [`Base64Text`]: sixteen bytes a client derives from a
/// concrete path alone, which `eql_v4.json_tree_subtree` and its indexed
/// form take to find the node at that path in every row.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS, JsonSchema)]
pub struct JsonTreeToken(pub Base64Text);

/// One member of an element-scoped predicate: the tokens of a read of one
/// field's path through the array's wildcard, one per element below the
/// bound in element order and then the probe, and the field's bounds,
/// each an ordering operand. `gt` or `gte` is the lower bound, `lt` or
/// `lte` the upper; equality is `gte` and `lte` at one value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeElementsMember {
    pub t: Vec<JsonTreeToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gt: Option<JsonTreeLeafQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gte: Option<JsonTreeLeafQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub lt: Option<JsonTreeLeafQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub lte: Option<JsonTreeLeafQuery>,
}

/// `eql_v4.query_json_elements`: an element-scoped predicate, `{"m":
/// [member, …]}`, true of a row where some one element of the array
/// satisfies every member (`eql_v4.json_tree_element_match`). What Stack
/// Encrypt's `element_match` operator derives. The domain's CHECK also
/// holds what this type does not: at least one member, each with at least
/// one bound and at most one of each side, all its bounds at one selector,
/// and every member's tokens as many as every other's.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeElementsQuery {
    pub m: Vec<JsonTreeElementsMember>,
}

/// The bounds of an ordering at one path: one or two ordering operands at
/// the path's selector, `gt` or `gte` the lower and `lt` or `lte` the upper.
/// The `cmp` leaf of a [`JsonTreePredicateQuery`]. The domain's CHECK also
/// holds what this type does not: at least one bound, at most one of each
/// side, and every bound at one selector.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeBounds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gt: Option<JsonTreeLeafQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gte: Option<JsonTreeLeafQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub lt: Option<JsonTreeLeafQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub lte: Option<JsonTreeLeafQuery>,
}

/// `eql_v4.query_json_predicate`: a compiled predicate, a boolean tree
/// whose leaves are the family's other query operands, which
/// `eql_v4.json_tree_match` and `col @@ $1` evaluate. What Stack Encrypt's
/// `match` operator compiles a jsonpath predicate into. Each node is an
/// object of one key naming its kind: `{"and": [node, …]}`, `{"or": […]}`,
/// `{"not": node}`, `{"contains": needle}`, `{"exists": selector}`,
/// `{"cmp": bounds}` and `{"elements": predicate}`. The domain's CHECK also
/// holds what this type does not: at least one child under `and` and `or`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum JsonTreePredicateQuery {
    /// True when every child is; false when one is false; else NULL.
    And(Vec<JsonTreePredicateQuery>),
    /// True when one child is; false when every child is false; else NULL.
    Or(Vec<JsonTreePredicateQuery>),
    /// The child's negation, NULL of NULL.
    Not(Box<JsonTreePredicateQuery>),
    /// The document contains the needle, `col @> needle`.
    Contains(JsonTreeQuery),
    /// The document has a node at the path, `json_tree_path_exists`.
    Exists(JsonTreeSelector),
    /// The first entry at the bounds' selector against each bound,
    /// `(col -> s) > gt AND (col -> s) < lt`.
    Cmp(JsonTreeBounds),
    /// One element of an array satisfies every member,
    /// `json_tree_element_match`.
    Elements(JsonTreeElementsQuery),
}

/// The entry `col -> selector` returned, with the selector that asked for
/// it: opens to the scalar the entry holds, or to the whole document for a
/// sealed root asked for at `$`. The only constructor,
/// [`from_selector`](Self::from_selector), takes the selector, and opening
/// refuses an entry that does not carry it
/// ([`Error::JsonWrongEntry`](stack_encrypt::Error::JsonWrongEntry)), as
/// [`JsonSelector::open`] does: a database that answers one path with
/// another path's entry, or with the sealed root, returns an entry that
/// would otherwise open.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonTreeExtracted {
    entry: JsonTreeEntry,
    selector: JsonSelector,
}

impl JsonTreeExtracted {
    /// The entry `col -> selector` returned for `selector`, as the server
    /// sent it.
    pub fn from_selector(selector: &JsonSelector, entry: JsonTreeEntry) -> Self {
        Self {
            entry,
            selector: *selector,
        }
    }

    /// The entry.
    pub fn entry(&self) -> &JsonTreeEntry {
        &self.entry
    }

    /// The selector the read asked for.
    pub fn selector(&self) -> &JsonSelector {
        &self.selector
    }
}

/// The rows a subtree read returned,
/// `eql_v4.json_tree_subtree(doc, key.tokens(), budget)`, collected with the
/// key that keyed the read. Every read returns each node a token names at
/// depth `0` with everything beneath it, so the rows open to the value at
/// the path, `{}`, `[]` and scalars included; to `None` as an
/// `Option<Value>` when the row has no node there; or to a list, one value
/// per concrete path a wildcard reaches. A wildcard read of an array longer
/// than the key's bound fails with
/// [`Error::JsonWildcardTruncated`](stack_encrypt::Error::JsonWildcardTruncated)
/// rather than open to part of the answer.
///
/// Past its budget a read returns the sealed root alone, at depth `0`;
/// those rows open to the whole document, and the key's concrete paths and
/// probes are evaluated over it to the same answers. The only constructor,
/// [`from_key`](Self::from_key), takes the key, which checks every row
/// against its path when the rows are opened, so rows cannot be opened
/// without it.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonTreeSubtree {
    rows: Vec<JsonTreeEntry>,
    key: JsonSubtreeKey,
}

impl JsonTreeSubtree {
    /// The rows the read `key` keyed returned, as the server sent them.
    pub fn from_key(key: &JsonSubtreeKey, rows: Vec<JsonTreeEntry>) -> Self {
        Self {
            rows,
            key: key.clone(),
        }
    }

    /// The rows.
    pub fn rows(&self) -> &[JsonTreeEntry] {
        &self.rows
    }

    /// The path the read was keyed from.
    pub fn path(&self) -> &JsonPath {
        self.key.path()
    }
}

macro_rules! json_tree_domain_type {
    ($ty:ident, $sql:literal) => {
        impl DomainType for $ty {
            fn sql_domain_static() -> &'static str {
                $sql
            }
            fn sql_domain(&self) -> &'static str {
                Self::sql_domain_static()
            }
            // `term_json_keys` keeps the trait default (`None`): the terms
            // live per entry, not as flat payload keys.
            fn parse_value(&self, value: &serde_json::Value) -> Result<(), serde_json::Error> {
                <$ty as Deserialize>::deserialize(value).map(|_| ())
            }
            fn schema(&self) -> Schema {
                schema_for!($ty)
            }
            fn schema_id_base_static() -> &'static str {
                super::SCHEMA_ID_BASE
            }
            fn schema_id(&self) -> String {
                format!("{}{}.json", super::SCHEMA_ID_BASE, self.domain())
            }
        }
    };
}

json_tree_domain_type!(JsonTreeDocument, "public.eql_v4_json_search");
json_tree_domain_type!(JsonTreeEntry, "public.eql_v4_json_entry");
json_tree_domain_type!(JsonTreeQuery, "eql_v4.query_json");
json_tree_domain_type!(JsonTreeLeafQuery, "eql_v4.query_json_leaf");
json_tree_domain_type!(JsonTreeElementsQuery, "eql_v4.query_json_elements");
json_tree_domain_type!(JsonTreePredicateQuery, "eql_v4.query_json_predicate");

// =============================================================================
// Conversions to and from the engine's types, through their one wire form
// =============================================================================

fn codec(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(Box::new(error))
}

/// Re-read one serializable value as another type sharing its wire form.
fn transcode<T: Serialize, U: serde::de::DeserializeOwned>(value: &T) -> Result<U, Error> {
    serde_json::from_value(serde_json::to_value(value).map_err(codec)?).map_err(codec)
}

impl JsonTreeDocument {
    /// The envelope around an engine document: `v = 4`, the column, and
    /// the document's header and entries.
    fn envelope(i: Identifier, document: &JsonDocument) -> Result<Self, Error> {
        let mut value = serde_json::to_value(document).map_err(codec)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| Error::Other("a JSON document serializes to an object".into()))?;
        let _ = object.insert("v".into(), serde_json::json!(4));
        let _ = object.insert("i".into(), serde_json::to_value(i).map_err(codec)?);
        serde_json::from_value(value).map_err(codec)
    }

    /// The engine's document: the header, entries and projection without
    /// the envelope.
    fn document(&self) -> Result<JsonDocument, Error> {
        serde_json::from_value(serde_json::json!({ "h": self.h, "sv": self.sv, "q": self.q }))
            .map_err(codec)
    }
}

impl TryFrom<JsonQuery> for JsonTreeQuery {
    type Error = Error;
    fn try_from(query: JsonQuery) -> Result<Self, Error> {
        transcode(&query)
    }
}

impl TryFrom<&JsonQuery> for JsonTreeQuery {
    type Error = Error;
    fn try_from(query: &JsonQuery) -> Result<Self, Error> {
        transcode(query)
    }
}

impl TryFrom<&JsonLeafQuery> for JsonTreeLeafQuery {
    type Error = Error;
    fn try_from(query: &JsonLeafQuery) -> Result<Self, Error> {
        transcode(query)
    }
}

impl JsonTreeEntry {
    /// The entry as an extracted node the engine opens: it must carry the
    /// grafted `h` and `j`, which every extractor adds.
    fn node(&self) -> Result<JsonNode, Error> {
        if self.h.is_none() || self.j.is_none() {
            return Err(Error::Other(
                "a JSON tree entry opens only as an extractor returned it, with `h` and `j`".into(),
            ));
        }
        transcode(self)
    }
}

// =============================================================================
// Stack Encrypt targets
// =============================================================================

/// The `json_tree` layout under the JSON index's options: what seals a
/// document into a [`JsonTreeDocument`] under options other than the
/// defaults, such as the paths that carry an ordering term
/// ([`JsonOptions::ordered`]). A Rust program runs it as
/// `keyset.run(JsonTree::new(options).encryption(), &value, column)`. Its
/// index is the engine's [`Json`] under the same options, which a query
/// derives through. [`JsonTreeDocument`]'s own [`EncryptTarget`] is this
/// layout under the defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JsonTree {
    options: JsonOptions,
}

impl JsonTree {
    /// The layout under `options`.
    pub fn new(options: JsonOptions) -> Self {
        Self { options }
    }

    /// The index the layout seals under, with its options.
    pub fn index(&self) -> Json {
        Json::new(self.options.clone())
    }

    /// The index the layout declares, as data: the JSON index under its
    /// options.
    pub fn specs(&self) -> Vec<IndexSpec> {
        vec![Index::<Value>::spec(&self.index())]
    }

    /// Seal a document as the JSON index lays it out under these options,
    /// under the column it is stored in. The [`Identifier`] is the context
    /// the data key is requested under and every selector derives under.
    /// It is written to `i`.
    pub fn encryption<'s, K: 'static>(
        &self,
    ) -> Encryption<'s, Value, JsonTreeDocument, K, NonEmpty<Identifier>> {
        self.sealing().accepting()
    }

    /// Seal a document under these options, and write its column to `i`.
    ///
    /// On its own, the document stores the column the caller passes, and
    /// seals under it. As a field of a record, it stores the field's own
    /// column, and seals under the scopes and bindings of the record too.
    pub(crate) fn sealing<'s, K: 'static>(
        &self,
    ) -> Encryption<'s, Value, JsonTreeDocument, K, StoredContext<Identifier>> {
        json_document::<K, Borrowed>(self.options.clone())
            .storing(|document, column: Identifier| (column, document))
            .try_map(|(column, document)| JsonTreeDocument::envelope(column, &document))
    }
}

impl JsonTreeDocument {
    /// Open the document, once its stored column has passed the caller's
    /// check. The check runs before any key is requested.
    ///
    /// On its own, the document opens under the stored column. As a field
    /// of a record, it opens under the scopes and bindings of the record
    /// too.
    fn open<K: 'static>(
        self,
        context: ExpectedContext<Identifier>,
    ) -> Decryption<JsonPlaintext, K> {
        let context = match context.decryption_context(self.i.clone()) {
            Ok(context) => context,
            Err(error) => return Decryption::failed(error),
        };
        match self.document() {
            Ok(document) => DecryptSource::decryption(document, AeadContext::from(context).into()),
            Err(error) => Decryption::failed(error),
        }
    }
}

/// A [`JsonPlaintext`] seals into a document as a `serde_json::Value` does,
/// under the default options ([`JsonTree::default`]), with the column as
/// its context.
///
/// The code below is executed by `cargo test -p eql-encryption-tests --test
/// json_example`. It is not one of this crate's doctests, for the reason
/// the [encryption example](crate::encryption#example) gives: the test key
/// source and the runtime it needs stay in the encryption test crate.
#[doc = concat!("```rust,ignore\n", include_str!("../encryption/json_example.rs"), "\n```")]
///
/// It can be a field of a derived `struct = ..` record. The field's column
/// is then the record's scope and the field's name. A scope or a binding
/// that the record lists is not stored in the document: the reader supplies
/// it again.
impl EncryptTarget<JsonPlaintext> for JsonTreeDocument {
    type ContextInput = StoredContext<Identifier>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, JsonPlaintext, Self, K, Self::ContextInput>
    where
        JsonPlaintext: 's,
    {
        JsonTree::default().sealing().project(JsonPlaintext::value)
    }
    fn indexes() -> Vec<IndexSpec> {
        JsonTree::default().specs()
    }
}

/// A document field sealed under the options its record's
/// `#[stash(json(..))]` names, which order the paths its queries compare.
impl JsonTarget<JsonPlaintext> for JsonTreeDocument {
    fn json_encryption<'s, K: 'static>(
        options: JsonOptions,
    ) -> Encryption<'s, JsonPlaintext, Self, K, Self::ContextInput>
    where
        JsonPlaintext: 's,
    {
        JsonTree::new(options)
            .sealing()
            .project(JsonPlaintext::value)
    }
}

/// A document field's reference queries return the EQL query types a
/// parameter binds as: `JsonTreeQuery` for `@>` and `<@`
/// (`eql_v4.query_json`), `JsonTreeLeafQuery` for an ordering at a path
/// (`eql_v4.query_json_leaf`), `JsonTreeElementsQuery` for
/// `eql_v4.json_tree_element_match`, `JsonTreePredicateQuery` for `@@`, the
/// selector `->` takes, and the token the child functions take.
impl JsonQueries for JsonTreeDocument {
    type Query = JsonTreeQuery;
    type LeafQuery = JsonTreeLeafQuery;
    type ElementsQuery = JsonTreeElementsQuery;
    type PredicateQuery = JsonTreePredicateQuery;
    type Selector = JsonTreeSelector;
    type Token = JsonTreeToken;
    fn query(query: JsonQuery) -> Result<JsonTreeQuery, Error> {
        JsonTreeQuery::try_from(query)
    }
    fn leaf_query(query: JsonLeafQuery) -> Result<JsonTreeLeafQuery, Error> {
        JsonTreeLeafQuery::try_from(&query)
    }
    fn elements_query(query: JsonElementsQuery) -> Result<JsonTreeElementsQuery, Error> {
        transcode(&query)
    }
    fn predicate_query(query: JsonPredicateQuery) -> Result<JsonTreePredicateQuery, Error> {
        transcode(&query)
    }
    fn selector(selector: JsonSelector) -> Result<JsonTreeSelector, Error> {
        transcode(&selector)
    }
    fn token(key: JsonSubtreeKey) -> Result<JsonTreeToken, Error> {
        match key.tokens().as_slice() {
            [token] => transcode(token),
            _ => Err(Error::Other(
                "a path with no wildcard names one node".into(),
            )),
        }
    }
}

/// Decrypts to the plaintext document, under the stored column.
///
/// - `decrypt_from_with_context(document, &keyset, column)` checks that the
///   stored column is `column`. The check runs before any key is
///   requested.
/// - `decrypt_from(document, &keyset)` opens the document under the column
///   it stores, without that check.
impl DecryptSource<JsonPlaintext> for JsonTreeDocument {
    type ContextInput = ExpectedContext<Identifier>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<JsonPlaintext, K> {
        self.open(context)
    }
}

impl Decryptable for JsonTreeDocument {
    const DECRYPTABLE: bool = true;
}
impl<P: Zeroize, Ctx> DecryptField<P, Ctx> for JsonTreeDocument
where
    Self: DecryptSource<P>,
    Ctx: Into<<Self as DecryptSource<P>>::ContextInput>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(<Self as DecryptSource<P>>::decryption(self, context.into()))
    }
}

/// An extracted entry opens to a [`JsonPlaintext`], which is wiped when it
/// is dropped: the scalar the entry holds, or the whole document for a
/// sealed root asked for at `$`. A container node holds no value of its
/// own. Its subtree opens through [`JsonTreeSubtree`].
///
/// The context is required. It is the context the document was sealed
/// under:
///
/// - For a document stored on its own, pass its column:
///   `JsonPlaintext::decrypt_from_with_context(extracted, &keyset, column)`.
/// - For a document that is a field of a record with scopes or bindings,
///   pass the field's column, then those scopes and bindings.
///
/// An entry that does not carry the selector asked for is refused before
/// any key is requested.
impl DecryptSource<JsonPlaintext> for JsonTreeExtracted {
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<JsonPlaintext, K> {
        match self.entry.node() {
            Ok(node) => DecryptSource::decryption(self.selector.open(node), context),
            Err(error) => Decryption::failed(error),
        }
    }
}

/// The rows of a read open to the value at its path, as a
/// [`JsonPlaintext`], which is wiped when it is dropped. No node at the
/// path is an error: open as an `Option<JsonPlaintext>` to read that as
/// `None`.
///
/// The context is required. It is the context the document was sealed
/// under, as for [`JsonTreeExtracted`].
impl DecryptSource<JsonPlaintext> for JsonTreeSubtree {
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<JsonPlaintext, K> {
        self.read(context)
    }
}

/// The rows of a read open to the value at its path, or to `None` where
/// the row has no node there.
impl DecryptSource<Option<JsonPlaintext>> for JsonTreeSubtree {
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(
        self,
        context: Self::ContextInput,
    ) -> Decryption<Option<JsonPlaintext>, K> {
        self.read(context)
    }
}

/// The rows of a read open to a list: one value per concrete path the key
/// named that the row has, in document order.
impl DecryptSource<Vec<JsonPlaintext>> for JsonTreeSubtree {
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(
        self,
        context: Self::ContextInput,
    ) -> Decryption<Vec<JsonPlaintext>, K> {
        self.read(context)
    }
}

impl JsonTreeSubtree {
    /// Open the rows as the engine's subtree opens them, once every row is
    /// shown to carry the header and the slot an extractor adds.
    fn read<P, K>(self, context: RequiredContext<AeadContext>) -> Decryption<P, K>
    where
        P: Zeroize + 'static,
        K: 'static,
        JsonSubtree: DecryptSource<P, ContextInput = RequiredContext<AeadContext>>,
    {
        match self.subtree() {
            Ok(subtree) => DecryptSource::decryption(subtree, context),
            Err(error) => Decryption::failed(error),
        }
    }

    fn subtree(&self) -> Result<JsonSubtree, Error> {
        Ok(self.key.open(
            self.rows
                .iter()
                .map(JsonTreeEntry::node)
                .collect::<Result<_, _>>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sixteen bytes of `byte` as a selector's wire text.
    fn b64(byte: u8) -> String {
        Base64Text::encode([byte; 16]).as_str().to_owned()
    }

    /// Eight bytes of `byte` as a self or parent tag's wire text.
    fn b64_8(byte: u8) -> String {
        Base64Text::encode([byte; 8]).as_str().to_owned()
    }

    /// A ciphertext's wire text.
    fn b85(byte: u8) -> String {
        Base85Text::encode([byte; 28]).as_str().to_owned()
    }

    #[test]
    fn the_domains_are_the_v4_json_tree_family() {
        assert_eq!(
            JsonTreeDocument::sql_domain_static(),
            "public.eql_v4_json_search"
        );
        assert_eq!(
            JsonTreeEntry::sql_domain_static(),
            "public.eql_v4_json_entry"
        );
        assert_eq!(JsonTreeQuery::sql_domain_static(), "eql_v4.query_json");
        assert_eq!(
            JsonTreeLeafQuery::sql_domain_static(),
            "eql_v4.query_json_leaf"
        );
        assert_eq!(
            JsonTreeElementsQuery::sql_domain_static(),
            "eql_v4.query_json_elements"
        );
        assert_eq!(
            JsonTreePredicateQuery::sql_domain_static(),
            "eql_v4.query_json_predicate"
        );
    }

    #[test]
    fn a_predicate_query_is_a_tree_of_one_key_nodes() {
        let leaf = serde_json::json!({"s": b64(0xaa), "op": "AQI="});
        let needle = serde_json::json!({"sv": [{"s": b64(1), "vs": b64(2)}], "el": []});
        let elements = serde_json::json!({"m": [{"t": [b64(1)], "gt": leaf}]});
        let query = serde_json::json!({"and": [
            {"exists": b64(0xaa)},
            {"not": {"cmp": {"gte": leaf, "lt": leaf}}},
            {"or": [{"contains": needle}, {"elements": elements}]},
        ]});
        let parsed: JsonTreePredicateQuery = serde_json::from_value(query.clone()).unwrap();
        let JsonTreePredicateQuery::And(children) = &parsed else {
            panic!("the root is an and: {parsed:?}")
        };
        assert!(
            matches!(children[0], JsonTreePredicateQuery::Exists(_)),
            "{children:?}"
        );
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            query,
            "a tree reads and writes as itself"
        );
        for wrong in [
            serde_json::json!({"exists": b64(1), "not": {"exists": b64(1)}}),
            serde_json::json!({"xor": []}),
            serde_json::json!({"cmp": {"eq": leaf}}),
            serde_json::json!({"exists": 1}),
            serde_json::json!([]),
        ] {
            assert!(
                serde_json::from_value::<JsonTreePredicateQuery>(wrong.clone()).is_err(),
                "{wrong} should not deserialize"
            );
        }
    }

    #[test]
    fn an_elements_query_is_members_of_tokens_and_bounds() {
        let leaf = serde_json::json!({"s": b64(0xaa), "op": "AQI="});
        let query = serde_json::json!({"m": [
            {"t": [b64(1), b64(2)], "gte": leaf, "lte": leaf},
            {"t": [b64(3), b64(4)], "gt": leaf},
        ]});
        let parsed: JsonTreeElementsQuery = serde_json::from_value(query.clone()).unwrap();
        assert_eq!(parsed.m.len(), 2, "one member per field");
        assert!(parsed.m[1].lt.is_none(), "an absent bound is none");
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            query,
            "absent bounds are left out"
        );
        for wrong in [
            serde_json::json!({"m": [{"t": [b64(1)], "eq": leaf}]}),
            serde_json::json!({"m": [{"gt": leaf}]}),
            serde_json::json!({"m": [], "x": 1}),
            serde_json::json!({"m": [{"t": ["not base64"], "gt": leaf}]}),
        ] {
            assert!(
                serde_json::from_value::<JsonTreeElementsQuery>(wrong.clone()).is_err(),
                "{wrong} should not deserialize"
            );
        }
    }

    #[test]
    fn a_query_needs_sv_and_el_and_takes_an_alt() {
        let query: JsonTreeQuery = serde_json::from_value(serde_json::json!({
            "sv": [{"s": b64(0xaa), "vs": b64(0xbb)}],
            "el": [{"sv": [], "el": []}],
            "alt": {"sv": [{"s": b64(0xcc), "vs": b64(0xdd)}], "el": []},
        }))
        .unwrap();
        assert_eq!(query.el.len(), 1);
        assert!(query.alt.is_some());
        assert!(serde_json::from_value::<JsonTreeQuery>(serde_json::json!({"sv": []})).is_err());
        assert!(serde_json::from_value::<JsonTreeQuery>(serde_json::json!({
            "sv": [], "el": [], "grp": []
        }))
        .is_err());
    }

    #[test]
    fn a_document_carries_its_projection() {
        let document = serde_json::json!({
            "v": 4, "i": {"t": "users", "c": "profile"}, "h": "AA==",
            "sv": [{"s": b64(0xaa), "c": b85(0), "x": b64_8(0xcc)}],
            "q": {"sv": [{"s": b64(0xaa), "vs": b64(0xbb)}], "el": []},
        });
        let stored: JsonTreeDocument = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(stored.q.sv.len(), 1);
        assert_eq!(serde_json::to_value(&stored).unwrap(), document);
        let mut without = document.clone();
        let _ = without.as_object_mut().unwrap().remove("q");
        assert!(
            serde_json::from_value::<JsonTreeDocument>(without).is_err(),
            "a document without `q` is not a stored document"
        );
    }

    #[test]
    fn an_entry_with_a_field_in_the_wrong_encoding_is_refused() {
        for entry in [
            serde_json::json!({"s": "aa", "c": b85(0), "x": b64_8(0)}),
            serde_json::json!({"s": b64(0), "c": "z", "x": b64_8(0)}),
            serde_json::json!({"s": b64(0), "c": b85(0), "x": "not base64"}),
            serde_json::json!({"s": b64(0), "c": b85(0), "x": b64_8(0), "p": "not base64"}),
            serde_json::json!({"s": b64(0), "c": b85(0)}),
        ] {
            assert!(
                serde_json::from_value::<JsonTreeEntry>(entry.clone()).is_err(),
                "{entry} should not deserialize"
            );
        }
    }

    #[test]
    fn an_entry_without_the_grafted_fields_does_not_open() {
        let entry: JsonTreeEntry = serde_json::from_value(serde_json::json!({
            "s": b64(0), "c": b85(0), "x": b64_8(0)
        }))
        .unwrap();
        assert!(entry.node().is_err());
    }
}
