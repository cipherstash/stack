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
//! [`EncryptFrom`] / [`DecryptInto`] impls that let a Rust program name
//! [`JsonTreeDocument`] as a target: `encrypt_as::<JsonTreeDocument>` under
//! an [`Identifier`]. A query derives through the engine's own document
//! target under the same context as a label, `Plan::value::<Value>()
//! .context("users/profile").encrypt_into::<JsonDocument>()`, and converts
//! into the operand types here; the identifier and the two-segment label
//! are one context, so the selectors agree (see [`crate::encryption`]). The
//! design is `docs/plans/2026-10-17-json-tree-index.md` at
//! the repository root.

use schemars::{schema_for, JsonSchema, Schema};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stack_encrypt::json::{
    JsonDocument, JsonLeafQuery, JsonNode, JsonOptions, JsonPath, JsonQuery, JsonSubtree,
    JsonSubtreeKey,
};
use stack_encrypt::target::{AeadContext, ExpectedContext, IndexSpec, Json, Layout};
use stack_encrypt::{
    DecryptField, DecryptInto, Decryptable, Decryption, EncryptFrom, Encryption, Error, NonEmpty,
};
use ts_rs::TS;

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

/// An eight-byte parent tag `p`, in [`Base64Text`]: the first eight bytes
/// of the parent-tag hash, per document, salted by the document's `iv`, so
/// unlinkable across rows at rest. `eql_v4.json_tree_subtree_at` derives
/// the same text with `encode(substr(…, 1, 8), 'base64')` to find a child.
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

/// `public.eql_v4_json_tree`: a JSON tree document, `{v, i, h, sv:
/// [entry], q: group}`. Strict. `h` is the document's key header, stored
/// once (every entry is sealed under the document's one data key); `sv`
/// holds one entry per node in depth-first order, the root first; `q` is
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

/// `public.eql_v4_json_tree_entry`: one node. `s` is the path selector,
/// `c` the node's own ciphertext; `p` the parent tag below the chain's
/// heads, which the walk probes by ordinal; `op` the leaf ordering term.
/// `h`, `j`, `d`, `v` and `i` are what the extractors graft onto an entry
/// they return, so it opens on its own.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeEntry {
    pub s: JsonTreeSelector,
    pub c: JsonTreeCiphertext,
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

/// `eql_v4.query_json_tree`: a containment needle, the element-nested
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

/// `eql_v4.query_json_tree_leaf`: an ordering operand at a path, the path's
/// selector and the leaf ordering term. What
/// [`stack_encrypt::json::JsonLeafQuery`] serializes to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JsonTreeLeafQuery {
    pub s: JsonTreeSelector,
    pub op: JsonTreeOrderingTerm,
}

/// The rows a subtree walk returned (`eql_v4.json_tree_subtree` or
/// `json_tree_subtree_at`), collected with the key that keyed the walk:
/// opens to the value under the walked path, or to the list of complete
/// subtrees the rows hold.
///
/// Past its budget a walk returns the sealed root alone, at depth `0`;
/// those rows open to the whole document, and the key's path selects the
/// same value(s) the walked rows open to. The key also says which walk the
/// rows came from (no gates: `json_tree_subtree`, the rows below the path's
/// node; gates: `json_tree_subtree_at`, the nodes the path reaches), so the
/// only constructor, [`from_key`](Self::from_key), takes it, and rows
/// cannot be opened without it.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonTreeSubtree {
    rows: Vec<JsonTreeEntry>,
    key: JsonSubtreeKey,
}

impl JsonTreeSubtree {
    /// The rows the walk `key` keyed returned, as the server sent them.
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

    /// The path the walk was keyed from.
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

json_tree_domain_type!(JsonTreeDocument, "public.eql_v4_json_tree");
json_tree_domain_type!(JsonTreeEntry, "public.eql_v4_json_tree_entry");
json_tree_domain_type!(JsonTreeQuery, "eql_v4.query_json_tree");
json_tree_domain_type!(JsonTreeLeafQuery, "eql_v4.query_json_tree_leaf");

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
/// value into a [`JsonTreeDocument`] under options other than the
/// defaults, such as the paths that carry an ordering term
/// ([`JsonOptions::ordered`]). A [`Layout`], so a Rust program runs it as
/// `keyset.run(JsonTree::new(options).encryption(), &value, column)`, and
/// its index is the engine's [`Json`] under the same options, which a
/// query derives through. [`JsonTreeDocument`]'s own [`EncryptFrom`] is
/// this layout under the defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JsonTree {
    index: Json,
}

impl JsonTree {
    /// The layout under `options`.
    pub fn new(options: JsonOptions) -> Self {
        Self {
            index: Json::new(options),
        }
    }

    /// The index the layout seals under, with its options.
    pub fn index(&self) -> &Json {
        &self.index
    }
}

/// A document seals as the JSON index lays it out under the layout's
/// options, under the column it is stored in: the [`Identifier`] is the
/// context the data key is minted under and every selector derives
/// under, and is written to `i`.
impl Layout<Value> for JsonTree {
    type Target = JsonTreeDocument;
    type Index = Json;
    fn encryption<'s, K: 'static>(
        &self,
    ) -> Encryption<'s, Value, JsonTreeDocument, K, NonEmpty<Identifier>> {
        Layout::<Value>::encryption::<K>(&self.index)
            .accepting::<NonEmpty<Identifier>>()
            .map_with_context(|document, i: NonEmpty<Identifier>| (i, document))
            .try_map(|(i, document)| JsonTreeDocument::envelope(i.into_inner(), &document))
    }
    fn index(&self) -> &Json {
        &self.index
    }
}

/// A document seals as the JSON index lays it out under the default
/// options ([`JsonTree::default`]): no path ordered, the root sealed.
impl EncryptFrom<Value> for JsonTreeDocument {
    type Context = NonEmpty<Identifier>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Value, Self, K, Self::Context> {
        JsonTree::default().encryption()
    }
    fn indexes() -> Vec<IndexSpec> {
        JsonTree::default().specs()
    }
}

/// Opens to the plaintext document, under the stored identifier, which an
/// [`ExpectedContext`] may require to be the column the caller expects.
impl DecryptInto<Value> for JsonTreeDocument {
    type Context = ExpectedContext<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        let column = match context.validate(self.i.clone()) {
            Ok(column) => column,
            Err(error) => return Decryption::failed(error),
        };
        match self.document() {
            Ok(document) => document.decryption(AeadContext::from(column)),
            Err(error) => Decryption::failed(error),
        }
    }
}

impl Decryptable for JsonTreeDocument {
    const DECRYPTABLE: bool = true;
}
impl<P, Ctx> DecryptField<P, Ctx> for JsonTreeDocument
where
    Self: DecryptInto<P>,
    Ctx: Into<<Self as DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// An extracted entry opens to the scalar it holds, or to the whole
/// document for a sealed root, under the column it was extracted from. A
/// container node holds no value of its own; its subtree opens through
/// [`JsonTreeSubtree`].
impl DecryptInto<Value> for JsonTreeEntry {
    type Context = NonEmpty<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        match self.node() {
            Ok(node) => node.decryption(AeadContext::from(context)),
            Err(error) => Decryption::failed(error),
        }
    }
}

/// The rows of `json_tree_subtree(doc, token)` open to the value under the
/// walked node.
impl DecryptInto<Value> for JsonTreeSubtree {
    type Context = NonEmpty<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        match self.subtree() {
            Ok(subtree) => subtree.decryption(AeadContext::from(context)),
            Err(error) => Decryption::failed(error),
        }
    }
}

/// The rows of a walk open to the complete subtrees they hold, in order:
/// one per node the gates of `json_tree_subtree_at` reached.
impl DecryptInto<Vec<Value>> for JsonTreeSubtree {
    type Context = NonEmpty<Identifier>;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<Value>, K> {
        match self.subtree() {
            Ok(subtree) => subtree.decryption(AeadContext::from(context)),
            Err(error) => Decryption::failed(error),
        }
    }
}

impl JsonTreeSubtree {
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

    /// A ciphertext's wire text.
    fn b85(byte: u8) -> String {
        Base85Text::encode([byte; 28]).as_str().to_owned()
    }

    #[test]
    fn the_domains_are_the_v4_json_tree_family() {
        assert_eq!(
            JsonTreeDocument::sql_domain_static(),
            "public.eql_v4_json_tree"
        );
        assert_eq!(
            JsonTreeEntry::sql_domain_static(),
            "public.eql_v4_json_tree_entry"
        );
        assert_eq!(JsonTreeQuery::sql_domain_static(), "eql_v4.query_json_tree");
        assert_eq!(
            JsonTreeLeafQuery::sql_domain_static(),
            "eql_v4.query_json_tree_leaf"
        );
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
            "sv": [{"s": b64(0xaa), "c": b85(0)}],
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
            serde_json::json!({"s": "aa", "c": b85(0)}),
            serde_json::json!({"s": b64(0), "c": "z"}),
            serde_json::json!({"s": b64(0), "c": b85(0), "p": "not base64"}),
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
            "s": b64(0), "c": b85(0)
        }))
        .unwrap();
        assert!(entry.node().is_err());
    }
}
