//! The derivations: flattening a document into its terms, sealing the
//! entries under one data key, and opening them again.
//!
//! One walk ([`walk`]) serves both the index's term operation and the
//! sealing operation, so a query derives exactly the selectors a stored
//! document carries. The walk is depth-first, pre-order, siblings in key
//! order for an object and in position order for an array. Sealing runs the
//! other way, from the leaves up, so that each node's AAD can bind the AEAD
//! tags of its children ([`cascade`](super::cascade)); the AAD also binds the
//! slot the entry is stored at.
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vitaminc::random::SafeRand;
use vitaminc_aead::{Cipher, Context, IntoAad, IntoContext, LocalCipherText};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{BlockVisitor, IntoPrfContext, PrfValue};
use vitaminc_protected::{AsProtectedRef, Controlled, Protected};
use zeroize::Zeroizing;

use super::cascade::{self, ChildrenDigest};
use super::path::{key_step_len, push_key, JsonPath, Segment, ARRAY_STEP};
use super::plain::{
    insert_member, protected_array, protected_object, push_element, read_protected, take_protected,
    PlainJson,
};
use super::query::{group_of, JsonSelector, JsonSelectorSet, JsonSubtreeKey, Read};
use super::shuffle;
use super::{JsonDocument, JsonEntry, JsonExtracted, JsonHeader, JsonOptions, JsonSubtree, Tag};
use crate::keyset::KeysetState;
use crate::sem::TermError;
use crate::target::{AeadContext, CallerContext, Decryption, Pending, Request};
use crate::{DecryptInto, Descriptor, Error, KeysetCipher, NonEmpty, StackCipher};

/// PAE domain of the path selector `s`.
const SELECTOR_DOMAIN: &[u8] = b"stack-encrypt/json/selector/v1";
/// PAE domain of the value selector `vs`.
const VALUE_DOMAIN: &[u8] = b"stack-encrypt/json/value/v1";
/// PAE domain of a chain head's token: the root's, or a top-level field's
/// under the sealed root.
const TOKEN_DOMAIN: &[u8] = b"stack-encrypt/json/token/v1";
/// PAE domain of an entry's AAD ([`entry_aad`]).
const ENTRY_AAD_DOMAIN: &[u8] = b"stack-encrypt/json/entry/v1";

/// Deeper than this is refused rather than sealed: the walk recurses, and a
/// document built in memory can nest deeper than any parser admits.
///
/// The bound is what reading the document back needs, not what the walk
/// could manage. A sealed root's plaintext is the document as JSON, which
/// `serde_json` parses with a nesting limit of 128 containers, so a
/// document whose innermost value sits 128 levels down, or whose innermost
/// container is the 128th (an empty `[]` or `{}` at depth 127), seals and
/// then never opens. Refusing both here moves that failure from the read,
/// where the value is lost, to the write, where the caller still holds it.
/// The bound is the same under either root option, so the option never
/// changes which documents the index accepts.
pub(crate) const MAX_DEPTH: usize = 127;

/// The largest number the index gives an array element's position, a
/// node's ordinal or a node's child count: PostgreSQL's `integer`, which is
/// what the SQL walk's ordinals are and what `json_tree_child_count`
/// returns.
///
/// A document with a wider array or object is refused when it is sealed,
/// and a path naming a position past this is refused when its subtree key
/// is derived. No stored document has a node there, so the refusal loses no
/// answer: a position reaches the server only inside a token, so without
/// the refusal the read would find nothing, where the caller asked for
/// something no document can hold. A wildcard's bound is not held to this:
/// the token cap ([`MAX_READ_TOKENS`]) is far lower and refuses first.
const MAX_ORDINAL: u32 = i32::MAX.unsigned_abs();

/// `n` as an ordinal, or [`TermError::JsonTooWide`] past [`MAX_ORDINAL`].
fn fit_ordinal(n: impl TryInto<u32>) -> Result<u32, TermError> {
    n.try_into()
        .ok()
        .filter(|n| *n <= MAX_ORDINAL)
        .ok_or(TermError::JsonTooWide)
}

/// The byte that leads a sealed root's plaintext: the whole document, not a
/// node.
const SEALED_ROOT: u8 = 0xff;

/// A node's kind: what its value selector says it is, and what its
/// ciphertext's first byte records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Null,
    Bool,
    Number,
    String,
    Object,
    Array,
}

impl Kind {
    fn of(value: &Value) -> Self {
        match value {
            Value::Null => Kind::Null,
            Value::Bool(_) => Kind::Bool,
            Value::Number(_) => Kind::Number,
            Value::String(_) => Kind::String,
            Value::Object(_) => Kind::Object,
            Value::Array(_) => Kind::Array,
        }
    }

    pub(crate) fn is_container(self) -> bool {
        matches!(self, Kind::Object | Kind::Array)
    }

    fn byte(self) -> u8 {
        match self {
            Kind::Null => 0,
            Kind::Bool => 1,
            Kind::Number => 2,
            Kind::String => 3,
            Kind::Object => 4,
            Kind::Array => 5,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Kind::Null,
            1 => Kind::Bool,
            2 => Kind::Number,
            3 => Kind::String,
            4 => Kind::Object,
            5 => Kind::Array,
            _ => return None,
        })
    }

    /// The tag the value selector binds: a container contributes its tag
    /// alone, so every object has one value selector at a path and every
    /// array another.
    fn tag(self) -> &'static [u8] {
        match self {
            Kind::Null => b"NULL",
            Kind::Bool => b"BOOL",
            Kind::Number => b"NUM",
            Kind::String => b"STR",
            Kind::Object => b"MAP0{}",
            Kind::Array => b"ARRY[]",
        }
    }
}

/// An opened node's label under its parent. A key is plaintext, so it is
/// held in a `Protected` until it is moved into the value the caller asked
/// for.
#[derive(Clone, Debug)]
pub(crate) enum Label {
    Root,
    Key(Protected<String>),
    Index(u64),
}

/// A node's label as the walk reads it from the caller's value, borrowed:
/// the walk encodes it straight into the node's plaintext and keeps no
/// copy.
#[derive(Clone, Copy)]
enum LabelRef<'a> {
    Root,
    Key(&'a str),
    Index(u64),
}

/// One node's one-way terms: what a query is built from, and what sealing
/// adds the ciphertext and chain fields to.
#[derive(Clone, Debug)]
pub(crate) struct TermNode {
    /// The node's positional path.
    pub(crate) positional: JsonPath,
    pub(crate) s: Tag,
    pub(crate) vs: Tag,
    /// The node's token, derivable from its path alone: every node has
    /// one, the root and the chain's heads included.
    pub(crate) token: Tag,
    /// The leaf ordering term, on a number or string.
    pub(crate) op: Option<Vec<u8>>,
    pub(crate) parent: Option<usize>,
    /// The node's ordinal under its parent, when it chains from its parent
    /// (everything below the chain's heads): its index for an array
    /// element; for an object member, its place in a random permutation of
    /// the object's members, drawn for the document ([`member_ordinals`]).
    pub(crate) ordinal: Option<u32>,
    /// The nearest enclosing array element that is a container.
    pub(crate) element: Option<usize>,
    /// Whether this node is an array element that is a container.
    pub(crate) container_element: bool,
}

/// The one-way terms of a document: one term node per node, in the
/// walk's order, with the root first. The term of the
/// [`Json`](struct@crate::target::Json) index, and what every query term is built
/// from. It holds no scalar value and no key, but it does hold the
/// document's shape: each node's positional path, whose key names are
/// plaintext, and each node's chain token, which is a capability over its
/// subtree in every row. `Debug` prints neither, only how many nodes there
/// are, and the terms should not be logged or sent anywhere but into a
/// query.
#[derive(Clone)]
pub struct JsonTerms {
    nodes: Vec<TermNode>,
    /// For a document whose root is a scalar: the selector pair the same
    /// scalar has as an element of a root array, so a containment query
    /// can match a stored `["a"]` as `jsonb @>` does.
    alt: Option<(Tag, Tag)>,
    /// The selector set a containment query built from these terms sends,
    /// its pair lists and element groups in a random order drawn when the
    /// terms were derived for a query ([`terms_pending`]). `None` for the
    /// terms a document is sealed from, which no query is built from.
    query_selectors: Option<JsonSelectorSet>,
}

/// The key names and the tokens are what the terms must not leak, so the
/// output is the node count alone.
impl std::fmt::Debug for JsonTerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonTerms")
            .field("nodes", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl JsonTerms {
    /// The path selector of the node at `path`, which names the node
    /// positionally, or `None` when the document has no node there.
    pub fn selector(&self, path: &JsonPath) -> Option<JsonSelector> {
        self.nodes
            .iter()
            .find(|n| &n.positional == path)
            .map(|n| JsonSelector(n.s))
    }

    /// How many nodes the document has.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the document has no nodes. It never has: a document has a
    /// root.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn nodes(&self) -> &[TermNode] {
        &self.nodes
    }

    pub(crate) fn alt(&self) -> Option<(Tag, Tag)> {
        self.alt
    }

    /// The selector set a containment query sends: the one drawn when the
    /// terms were derived for a query, or, for terms no query was derived
    /// for, the nodes' set in the walk's order.
    pub(crate) fn into_query_selectors(self) -> JsonSelectorSet {
        self.query_selectors
            .unwrap_or_else(|| group_of(&self.nodes, None))
    }

    /// The last node of the walk: in a document built from one path, the
    /// leaf the path names.
    pub(crate) fn leaf(&self) -> Option<&TermNode> {
        self.nodes.last()
    }
}

// =============================================================================
// Primitives
// =============================================================================

fn truncate(block: &[u8]) -> Tag {
    let mut tag = [0; 16];
    tag.copy_from_slice(&block[..16]);
    tag
}

/// The first sixteen bytes of the PRF of `input` under `domain` and the
/// column's context.
fn prf16(
    prf: &HmacSha256Prf,
    domain: &[u8],
    context: &Context<'_>,
    input: &[u8],
) -> Result<Tag, TermError> {
    prf16_of(prf, domain, context, input)
}

/// [`prf16`] over any PRF input: a `Protected<Vec<u8>>` derives exactly
/// what its bytes do, so input built from decrypted plaintext stays
/// wrapped up to the PRF.
fn prf16_of(
    prf: &HmacSha256Prf,
    domain: &[u8],
    context: &Context<'_>,
    input: impl PrfValue,
) -> Result<Tag, TermError> {
    let block: [u8; 32] = input
        .prf_visit_with_context(
            prf,
            Context::pae(&[domain, context.as_bytes()]),
            BlockVisitor,
        )
        .into_result()
        .map_err(TermError::from_prf)?;
    Ok(truncate(&block))
}

/// What derives path selectors under one column after the keyset handle
/// that derived a subtree key is gone: the keyset's loaded state (its
/// index-key PRF), shared, and the column's PRF context. A
/// [`JsonSubtreeKey`] holds one, so that opening a walk's rows can derive
/// the selector each row must carry from its parent's path and its own
/// decrypted label. Never printed; compared by keyset and context.
#[derive(Clone)]
pub(crate) struct Selectors {
    keyset: Arc<KeysetState>,
    context: Context<'static>,
}

impl Selectors {
    pub(crate) fn new(keyset: Arc<KeysetState>, context: Context<'static>) -> Self {
        Self { keyset, context }
    }

    /// The selector of the path whose selector bytes are `bytes`.
    fn of(&self, bytes: Protected<Vec<u8>>) -> Result<Tag, Error> {
        prf16_of(&self.keyset.prf, SELECTOR_DOMAIN, &self.context, bytes).map_err(Error::from)
    }
}

#[cfg(test)]
impl Selectors {
    /// Selectors under a fixed test keyset (index key `[7; 32]`, as the
    /// unit tests' `prf()`) and the column `users/profile`.
    pub(crate) fn for_tests() -> Self {
        use vitaminc_prf::PrfKeyInit;
        Self::new(
            Arc::new(KeysetState {
                id: Uuid::from_u128(1),
                name: None,
                prf: HmacSha256Prf::new(Protected::new([7; 32])),
            }),
            Context::from_encoded(b"users/profile").into_owned(),
        )
    }
}

impl PartialEq for Selectors {
    fn eq(&self, other: &Self) -> bool {
        self.keyset.id == other.keyset.id && self.context == other.context
    }
}
impl Eq for Selectors {}

/// The first sixteen bytes of SHA-256 over the concatenation of `parts`.
/// Plain SHA-256 by design: the design's "Why plain SHA-256 is enough here"
/// records why length extension does not apply.
fn h16(parts: &[&[u8]]) -> Tag {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    truncate(&hasher.finalize())
}

/// `H16("t" ‖ t(parent) ‖ s(member))`: the token of the object member whose
/// selector is `selector`, under the object whose token is `parent`.
/// Column-wide like every token (no document salt), and free of the
/// member's ordinal, which is random per document: so the client derives a
/// member's token from the path alone, whatever else the object holds in a
/// row, and the server derives a hit's from its parent's and the hit's
/// stored `s` as it walks. No token is ever stored.
///
/// Object keys are unique, so the selector alone tells a member from its
/// siblings. It also keeps a member apart from an array element: an
/// element's selector is the wildcard path's and a member's names its key,
/// and an element's input is four bytes longer ([`element_token`]), so the
/// two never share a token.
pub(super) fn member_token(parent: &Tag, selector: &Tag) -> Tag {
    h16(&[b"t", parent, selector])
}

/// `H16("t" ‖ t(array) ‖ s(element) ‖ LE32(index))`: the token of the
/// element at `index` of the array whose token is `array`, `selector` being
/// the selector every element of that array shares. An element's ordinal is
/// its index, so this is derivable from the path alone too.
pub(super) fn element_token(array: &Tag, selector: &Tag, index: u32) -> Tag {
    h16(&[b"t", array, selector, &index.to_le_bytes()])
}

/// The first eight bytes of `H("x" ‖ iv ‖ t(node))`: the self tag every
/// entry carries, by which the server finds the node a token names. Salted
/// by the document like the parent tag, so it is unrelated bytes in every
/// row until a query supplies the token. Eight bytes, as the parent tag
/// ([`SelfTag`](super::SelfTag)).
pub(super) fn self_tag(iv: &[u8], token: &Tag) -> super::SelfTag {
    let full = h16(&[b"x", iv, token]);
    let mut tag = super::SelfTag::default();
    tag.copy_from_slice(&full[..8]);
    tag
}

/// The token the server derives for `entry`, found at `ordinal` under the
/// node whose token is `parent`: the member rule's if the entry's self tag
/// is that token's, else the element rule's if it is that one's, else none.
/// Nothing stored says whether a node is a member or an element (its kind
/// is inside `c`), so the self tag is what chooses. An entry that matches
/// neither is still a child, and is returned, but the walk does not descend
/// into it.
pub(super) fn hit_token(
    iv: &[u8],
    parent: &Tag,
    entry: &super::JsonEntry,
    ordinal: u32,
) -> Option<Tag> {
    let member = member_token(parent, &entry.s);
    if self_tag(iv, &member) == entry.x {
        return Some(member);
    }
    let element = element_token(parent, &entry.s, ordinal);
    (self_tag(iv, &element) == entry.x).then_some(element)
}

/// The first eight bytes of `H("p" ‖ iv ‖ t(parent) ‖ LE32(ordinal))`:
/// position-keyed, so siblings are unlinkable at rest, and salted by the
/// document, so the same position in two rows is too. Eight bytes, since a
/// parent tag only has to be distinct within its document
/// ([`ParentTag`](super::ParentTag)).
pub(super) fn parent_tag(iv: &[u8], parent: &Tag, ordinal: u32) -> super::ParentTag {
    let full = h16(&[b"p", iv, parent, &ordinal.to_le_bytes()]);
    let mut tag = super::ParentTag::default();
    tag.copy_from_slice(&full[..8]);
    tag
}

/// [`Context::pae`] into a buffer that is sized before it is written and
/// wiped when it drops: for framing that holds a key name or a scalar.
fn pae_wiped(pieces: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let len = 8 + pieces.iter().map(|piece| 8 + piece.len()).sum::<usize>();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        out.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        out.extend_from_slice(piece);
    }
    out
}

/// A number's canonical bytes for its value selector: an integral value,
/// whichever JSON spelling it had, is its `i128`; anything else is its
/// `f64`. So `2` and `2.0` are one value, as `jsonb` compares them, and
/// `-0.0` is `0`.
fn canonical_number(number: &Number) -> Zeroizing<Vec<u8>> {
    fn int(i: i128) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(17));
        out.push(b'i');
        out.extend_from_slice(&i.to_le_bytes());
        out
    }
    if let Some(i) = number.as_i64() {
        return int(i128::from(i));
    }
    if let Some(u) = number.as_u64() {
        return int(i128::from(u));
    }
    let f = number.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e38 {
        return int(f as i128);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(9));
    out.push(b'f');
    out.extend_from_slice(&f.to_le_bytes());
    out
}

/// A scalar's canonical bytes; a container contributes nothing beyond its
/// kind's tag.
fn canonical(value: &Value) -> Zeroizing<Vec<u8>> {
    match value {
        Value::Null | Value::Object(_) | Value::Array(_) => Zeroizing::new(Vec::new()),
        Value::Bool(b) => Zeroizing::new(vec![u8::from(*b)]),
        Value::Number(n) => canonical_number(n),
        Value::String(s) => Zeroizing::new(s.as_bytes().to_vec()),
    }
}

/// The value selector: the PRF of the kind's tag, the path selector and
/// the canonical value, PAE-framed.
fn value_selector(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    s: &Tag,
    value: &Value,
) -> Result<Tag, TermError> {
    let framed = pae_wiped(&[Kind::of(value).tag(), s, &canonical(value)]);
    prf16(prf, VALUE_DOMAIN, context, &framed)
}

/// The leaf ordering term: the OPE term of a number as an `f64` or of a
/// string, under the column's context, as the scalar `Ope` index derives
/// it. Nothing for any other kind. An integer wider than 53 bits orders by
/// the `f64` it rounds to. The walk asks for it only at a path the
/// options order.
fn leaf_op(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    value: &Value,
) -> Result<Option<Vec<u8>>, TermError> {
    Ok(match value {
        Value::Number(n) => Some(
            crate::sem::ope(prf, n.as_f64().unwrap_or(0.0), context.clone())?
                .into_inner()
                .as_ref()
                .to_vec(),
        ),
        Value::String(s) => Some(
            crate::sem::ope(prf, s.clone(), context.clone())?
                .into_inner()
                .as_ref()
                .to_vec(),
        ),
        _ => None,
    })
}

// =============================================================================
// The walk
// =============================================================================

struct Walked {
    terms: JsonTerms,
    /// Each node's plaintext as its ciphertext encodes it, in the walk's
    /// order, built under `Protected` from the caller's value and handed to
    /// the cipher as it is.
    plain: Vec<Protected<Vec<u8>>>,
}

struct Walker<'p> {
    prf: &'p HmacSha256Prf,
    context: &'p Context<'p>,
    options: &'p JsonOptions,
    /// Draws each object's member ordinals ([`member_ordinals`]).
    rng: &'p mut SafeRand,
    nodes: Vec<TermNode>,
    plain: Vec<Protected<Vec<u8>>>,
}

/// Flatten `value` into its terms and its nodes' plaintexts, each object's
/// member ordinals drawn from `rng`.
fn walk(
    value: &Value,
    options: &JsonOptions,
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    rng: &mut SafeRand,
) -> Result<Walked, TermError> {
    options.check()?;
    let mut walker = Walker {
        prf,
        context,
        options,
        rng,
        nodes: Vec::new(),
        plain: Vec::new(),
    };
    let _ = walker.visit(
        value,
        &JsonPath::root(),
        &JsonPath::root(),
        LabelRef::Root,
        None,
        None,
        None,
        0,
    )?;
    let alt = if Kind::of(value).is_container() {
        None
    } else {
        let wild = JsonPath::root().then(Segment::Wildcard);
        let s = prf16(prf, SELECTOR_DOMAIN, context, &wild.selector_bytes())?;
        let vs = value_selector(prf, context, &s, value)?;
        Some((s, vs))
    };
    Ok(Walked {
        terms: JsonTerms {
            nodes: walker.nodes,
            alt,
            query_selectors: None,
        },
        plain: walker.plain,
    })
}

impl Walker<'_> {
    /// Visit `value`, the node at `positional`. `chain` is its parent's
    /// token and its ordinal under it when it chains from its parent, and
    /// `None` for the root and, under the sealed root, for the chain's
    /// heads, whose tokens are PRFs of their paths.
    #[allow(clippy::too_many_arguments)]
    fn visit(
        &mut self,
        value: &Value,
        positional: &JsonPath,
        wild: &JsonPath,
        label: LabelRef<'_>,
        parent: Option<usize>,
        chain: Option<(Tag, u32)>,
        element: Option<usize>,
        depth: usize,
    ) -> Result<usize, TermError> {
        let kind = Kind::of(value);
        // A container at MAX_DEPTH, empty or not, would be the 128th nested
        // container, which serde_json refuses to read back; only a scalar
        // may sit that deep.
        if depth > MAX_DEPTH || (depth == MAX_DEPTH && kind.is_container()) {
            return Err(TermError::JsonTooDeep);
        }
        let s = prf16(
            self.prf,
            SELECTOR_DOMAIN,
            self.context,
            &wild.selector_bytes(),
        )?;
        let vs = value_selector(self.prf, self.context, &s, value)?;
        let token = match (chain, label) {
            (Some((parent, _)), LabelRef::Key(_)) => member_token(&parent, &s),
            (Some((parent, o)), LabelRef::Index(_)) => element_token(&parent, &s, o),
            _ => prf16(
                self.prf,
                TOKEN_DOMAIN,
                self.context,
                &positional.token_bytes().unwrap_or_default(),
            )?,
        };
        let ordinal = chain.map(|(_, o)| o);
        // Under the sealed root nothing chains from the root: its members
        // are the chain's heads.
        let chains = depth > 0 || !self.options.sealed_root;
        let op = if self.options.orders(positional) {
            leaf_op(self.prf, self.context, value)?
        } else {
            None
        };
        let container_element = matches!(label, LabelRef::Index(_)) && kind.is_container();
        let children = match value {
            Value::Object(map) => map.len(),
            Value::Array(items) => items.len(),
            _ => 0,
        };
        let children = fit_ordinal(children)?;
        let index = self.nodes.len();
        self.nodes.push(TermNode {
            positional: positional.clone(),
            s,
            vs,
            token,
            op,
            parent,
            ordinal,
            element,
            container_element,
        });
        self.plain.push(encode_node(kind, children, label, value));
        let child_element = if container_element {
            Some(index)
        } else {
            element
        };
        match value {
            Value::Object(map) => {
                let ordinals: Option<BTreeMap<&String, u32>> =
                    chains.then(|| member_ordinals(map, self.rng)).transpose()?;
                for (key, child) in map {
                    let chain = ordinals
                        .as_ref()
                        .and_then(|o| o.get(key).copied())
                        .map(|o| (token, o));
                    let _ = self.visit(
                        child,
                        &positional.then(Segment::Key(key.clone())),
                        &wild.then(Segment::Key(key.clone())),
                        LabelRef::Key(key),
                        Some(index),
                        chain,
                        child_element,
                        depth + 1,
                    )?;
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    let i = u64::try_from(i).map_err(|_| TermError::JsonTooWide)?;
                    let chain = chains
                        .then(|| fit_ordinal(i))
                        .transpose()?
                        .map(|o| (token, o));
                    let _ = self.visit(
                        child,
                        &positional.then(Segment::Index(i)),
                        &wild.then(Segment::Wildcard),
                        LabelRef::Index(i),
                        Some(index),
                        chain,
                        child_element,
                        depth + 1,
                    )?;
                }
            }
            _ => {}
        }
        Ok(index)
    }
}

/// The ordinal of each of an object's members: a uniformly random
/// permutation of `0..n` drawn from `rng` ([`shuffle::ordinals`]), the
/// generator the document's stored order is drawn from. The ordinals below a
/// node are what the server probes to enumerate its children, so they are
/// public to whoever holds the node's token; random, they say nothing about
/// the members' keys, in this row or across rows. Nothing recomputes them: a
/// member's token does not depend on its ordinal ([`member_token`]), and the
/// parent tag that carries it is read back from the row.
fn member_ordinals<'m>(
    map: &'m Map<String, Value>,
    rng: &mut SafeRand,
) -> Result<BTreeMap<&'m String, u32>, TermError> {
    let ordinals = shuffle::ordinals(fit_ordinal(map.len())?, rng);
    Ok(map.keys().zip(ordinals).collect())
}

// =============================================================================
// Sealing
// =============================================================================

/// The one-way terms of `value` under `context`, as the index's operation
/// derives them for a query: no key is requested. The selector set a
/// containment query sends is drawn here, in a random order of its own
/// ([`shuffle`]), so a query shows no more of the order of its keys than a
/// stored `q` does; `jsonb @>` reads both as sets, so the order changes no
/// answer.
pub(crate) fn terms_pending<'a, K>(
    value: &Value,
    options: &JsonOptions,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<CallerContext>,
) -> Pending<'a, JsonTerms, K> {
    let context = context.into_prf_context().into_owned();
    let terms = cipher
        .cipher()
        .json_randomness()
        .generator()
        .and_then(|mut rng| {
            let walked = walk(value, options, cipher.prf(), &context, &mut rng)?;
            let mut selectors = group_of(&walked.terms.nodes, None);
            selectors.shuffle(&mut rng);
            Ok(JsonTerms {
                query_selectors: Some(selectors),
                ..walked.terms
            })
        });
    Pending::ready(cipher, terms)
}

/// Seal `value` into a [`JsonDocument`] under `context`: one data key for
/// the document, requested under the context's descriptor, and every entry
/// sealed under it with the AAD that binds the entry to the document, the
/// column and its ordinal.
pub(crate) fn seal_pending<'a, K: 'static>(
    value: Value,
    options: &JsonOptions,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<CallerContext>,
) -> Pending<'a, JsonDocument, K> {
    let piece = context.into_context();
    let descriptor = Descriptor::from_piece(&piece);
    if let Err(error) = descriptor.check() {
        return Pending::failed(cipher, error);
    }
    // The caller's document, owned here: wiped when this returns.
    let value = PlainJson::protect(value);
    let prf_context = piece.clone().into_prf_context().into_owned();
    let aad = piece.into_aad().into_owned();
    // One generator for the document: its members' ordinals, its stored
    // order and the order of its selector set.
    let mut rng = match cipher.cipher().json_randomness().generator() {
        Ok(rng) => rng,
        Err(error) => return Pending::failed(cipher, error),
    };
    let walked = match walk(
        value.risky_ref().value(),
        options,
        cipher.prf(),
        &prf_context,
        &mut rng,
    ) {
        Ok(walked) => walked,
        Err(error) => return Pending::failed(cipher, error.into()),
    };
    let whole = if options.sealed_root {
        match sealed_root_plaintext(value.risky_ref().value()) {
            Ok(bytes) => Some(bytes),
            Err(error) => return Pending::failed(cipher, Error::Other(Box::new(error))),
        }
    } else {
        None
    };
    let keyset_id = cipher.keyset_id();
    let sealed_root = options.sealed_root;
    Pending::request(
        cipher,
        vec![Request::generate_under(descriptor)],
        move |responses| {
            let key = responses.next_generated_key()?;
            seal(walked, whole, keyset_id, key, &aad, sealed_root, rng)
        },
    )
}

/// The AAD an entry is sealed and opened under, PAE-framed: the domain;
/// `keyset_id`, the keyset the document's data key was minted under;
/// `column`, the column's own AAD (its caller context); `key_tag`, the
/// ZeroKMS tag of that data key ([`JsonHeader::tag`]); `selector`, the
/// entry's path selector; `slot`, the slot the entry is stored at in `sv`;
/// and `children`, the digest of the entry's children's AEAD tags
/// ([`cascade::children_digest`]), which is what makes a node's ciphertext
/// commit to everything beneath it.
fn entry_aad(
    keyset_id: Uuid,
    column: &Context<'_>,
    key_tag: &[u8],
    selector: JsonSelector,
    slot: u64,
    children: &ChildrenDigest,
) -> Context<'static> {
    Context::pae(&[
        ENTRY_AAD_DOMAIN,
        keyset_id.as_bytes(),
        column.as_bytes(),
        key_tag,
        &selector.0,
        &slot.to_le_bytes(),
        children,
    ])
}

fn leaf_cipher(key: &stack_kms::DataKey) -> Result<Aes256Cipher, Error> {
    Aes256Cipher::new(&AesKey::from(*key.key())).map_err(|_| Error::Aead)
}

/// A node's plaintext: its kind, its child count, its label and, for a
/// scalar, its value. Built under `Protected` straight from the caller's
/// value, sized before it is written so it never reallocates and leaves a
/// copy behind, and handed to the cipher as it is.
fn encode_node(
    kind: Kind,
    children: u32,
    label: LabelRef<'_>,
    value: &Value,
) -> Protected<Vec<u8>> {
    // A number's text is a new allocation: it is made wrapped too.
    let number = match value {
        Value::Number(n) => Some(Protected::new(n.to_string())),
        _ => None,
    };
    let size = encoded_len(label, value, number.as_ref());
    Protected::generate(|| {
        let mut out = Vec::with_capacity(size);
        out.push(kind.byte());
        out.extend_from_slice(&children.to_le_bytes());
        match label {
            LabelRef::Root => out.push(0x00),
            LabelRef::Key(key) => {
                out.push(0x01);
                out.extend_from_slice(&(key.len() as u32).to_le_bytes());
                out.extend_from_slice(key.as_bytes());
            }
            LabelRef::Index(index) => {
                out.push(0x02);
                out.extend_from_slice(&index.to_le_bytes());
            }
        }
        match value {
            Value::String(text) => out.extend_from_slice(text.as_bytes()),
            Value::Bool(flag) => out.push(u8::from(*flag)),
            _ => {
                if let Some(text) = &number {
                    out.extend_from_slice(text.risky_ref().as_bytes());
                }
            }
        }
        out
    })
}

/// How many bytes [`encode_node`] writes: the kind, the child count, the
/// label and the scalar, `number` being a number's text.
fn encoded_len(label: LabelRef<'_>, value: &Value, number: Option<&Protected<String>>) -> usize {
    let label_len = match label {
        LabelRef::Root => 1,
        LabelRef::Key(key) => 1 + 4 + key.len(),
        LabelRef::Index(_) => 1 + 8,
    };
    let scalar_len = match value {
        Value::String(text) => text.len(),
        Value::Bool(_) => 1,
        _ => number.map_or(0, |text| text.risky_ref().len()),
    };
    1 + 4 + label_len + scalar_len
}

/// A sealed root's plaintext: [`SEALED_ROOT`], then the whole document as
/// JSON, built under `Protected`. The JSON is measured first, so the buffer
/// is allocated once at its final size and no reallocation leaves a copy of
/// the document behind.
fn sealed_root_plaintext(value: &Value) -> Result<Protected<Vec<u8>>, serde_json::Error> {
    struct Measure(usize);
    impl std::io::Write for Measure {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut measure = Measure(0);
    serde_json::to_writer(&mut measure, value)?;
    Protected::generate_ok(|| {
        let mut out = Vec::with_capacity(1 + measure.0);
        out.push(SEALED_ROOT);
        serde_json::to_writer(&mut out, value)?;
        Ok(out)
    })
}

/// Seal the walked nodes under `key`, from the leaves up, each at the slot
/// `rng` draws for it ([`shuffle::slots`]), and shuffle the projection with
/// the same generator.
fn seal(
    walked: Walked,
    mut whole: Option<Protected<Vec<u8>>>,
    keyset_id: Uuid,
    key: stack_kms::DataKeyWithTag,
    aad: &Context<'_>,
    sealed_root: bool,
    mut rng: SafeRand,
) -> Result<JsonDocument, Error> {
    if key.tag.len() > usize::from(u16::MAX) {
        return Err(Error::Other(
            "the data key's tag does not fit the JSON header".into(),
        ));
    }
    let cipher = leaf_cipher(&key.key)?;
    let iv = key.key.iv;
    let tag = key.tag;
    let Walked { terms, plain } = walked;
    let nodes = &terms.nodes;
    // The children a node's AAD commits to: the nodes that chain from it, by
    // ordinal. Under the sealed root its members chain from nothing, so the
    // root commits to no children and opens under the empty digest.
    let children = cascade::children_of(nodes.iter().map(|n| n.parent.zip(n.ordinal)));
    // Where each node is stored, by its index in the walk; the AAD binds it.
    let slots = shuffle::slots(nodes.len(), &mut rng);
    let mut sealed: Vec<Vec<u8>> = vec![Vec::new(); nodes.len()];
    // From the leaves up: the walk is pre-order, so every descendant of a
    // node has a larger index, and the reverse order seals a node's children
    // before the node.
    for (i, plain) in plain.into_iter().enumerate().rev() {
        debug_assert!(
            children[i].iter().all(|&child| child > i),
            "the walk is pre-order: a child is sealed before its parent"
        );
        // The root's plaintext is the whole document when the root is
        // sealed; the node encoding it replaces is wiped as it drops.
        let plaintext = if i == 0 {
            whole.take().unwrap_or(plain)
        } else {
            plain
        };
        let digest = cascade::children_digest(children[i].iter().map(|&c| sealed[c].as_slice()));
        let aad = entry_aad(
            keyset_id,
            aad,
            &tag,
            JsonSelector(nodes[i].s),
            slots[i] as u64,
            &digest,
        );
        let c = cipher.seal(plaintext, &aad).map_err(|_| Error::Aead)?;
        sealed[i] = c.as_ref().to_vec();
    }
    let mut entries: Vec<Option<JsonEntry>> =
        std::iter::repeat_with(|| None).take(nodes.len()).collect();
    for ((node, c), slot) in nodes.iter().zip(sealed).zip(&slots) {
        let p = node
            .parent
            .zip(node.ordinal)
            .map(|(parent, o)| parent_tag(&iv, &nodes[parent].token, o));
        entries[*slot] = Some(JsonEntry {
            s: node.s,
            c,
            x: self_tag(&iv, &node.token),
            p,
            op: node.op.clone(),
        });
    }
    // `slots` is a permutation, so every slot was filled once.
    let entries: Vec<JsonEntry> = entries.into_iter().flatten().collect();
    let mut selectors = group_of(nodes, None);
    selectors.shuffle(&mut rng);
    Ok(JsonDocument::new(
        JsonHeader::new(keyset_id, iv, tag, sealed_root),
        entries,
        selectors,
    ))
}

// =============================================================================
// Opening
// =============================================================================

/// An opened node. Every part that holds plaintext (a key, a scalar, a
/// sealed root's document) is under `Protected`; the kind and child count
/// are the node's framing.
struct Opened {
    label: Label,
    kind: Kind,
    scalar: Option<Protected<PlainJson>>,
    children: u32,
    /// The whole document, from a sealed root.
    whole: Option<Protected<PlainJson>>,
}

fn shape(expected: &'static str) -> Error {
    Error::OpenedType { expected }
}

/// Decode an opened entry's plaintext. The bytes stay in the cipher's
/// `Protected`: the framing (kind, child count, label tag, key length) is
/// read in place, and every part that carries plaintext is read out
/// through [`read_protected`], wrapped as it is made.
fn decode_node(plaintext: &Protected<Vec<u8>>) -> Result<Opened, Error> {
    let refused = || shape("a JSON index node");
    let bytes: &[u8] = plaintext.risky_ref();
    let (&first, rest) = bytes.split_first().ok_or_else(refused)?;
    if first == SEALED_ROOT {
        let mut kind = None;
        let whole = read_protected(plaintext, |bytes: &Vec<u8>| {
            let whole = PlainJson::parse(bytes.get(1..)?)?;
            kind = Some(Kind::of(whole.value()));
            Some(whole)
        })
        .ok_or_else(refused)?;
        return Ok(Opened {
            label: Label::Root,
            kind: kind.ok_or_else(refused)?,
            scalar: None,
            children: 0,
            whole: Some(whole),
        });
    }
    let kind = Kind::from_byte(first).ok_or_else(refused)?;
    if rest.len() < 5 {
        return Err(refused());
    }
    let (count, rest) = rest.split_at(4);
    let children = u32::from_le_bytes([count[0], count[1], count[2], count[3]]);
    let (&label_tag, rest) = rest.split_first().ok_or_else(refused)?;
    // Offsets into `bytes`, so the plaintext parts are read out of the
    // `Protected` itself.
    let at = bytes.len() - rest.len();
    let (label, scalar_at) = match label_tag {
        0x00 => (Label::Root, at),
        0x01 => {
            if rest.len() < 4 {
                return Err(refused());
            }
            let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let start = at + 4;
            let end = start.checked_add(len).filter(|end| *end <= bytes.len());
            let end = end.ok_or_else(refused)?;
            let key = read_protected(plaintext, |bytes: &Vec<u8>| {
                std::str::from_utf8(bytes.get(start..end)?)
                    .ok()
                    .map(str::to_owned)
            })
            .ok_or_else(refused)?;
            (Label::Key(key), end)
        }
        0x02 => {
            if rest.len() < 8 {
                return Err(refused());
            }
            let mut index = [0; 8];
            index.copy_from_slice(&rest[..8]);
            (Label::Index(u64::from_le_bytes(index)), at + 8)
        }
        _ => return Err(refused()),
    };
    let scalar = match kind {
        Kind::Object | Kind::Array => None,
        _ => Some(
            read_protected(plaintext, |bytes: &Vec<u8>| {
                let rest = bytes.get(scalar_at..)?;
                Some(PlainJson::from_value(match kind {
                    Kind::Null => Value::Null,
                    Kind::Bool => Value::Bool(rest.first().is_some_and(|&b| b != 0)),
                    Kind::Number => Value::Number(std::str::from_utf8(rest).ok()?.parse().ok()?),
                    _ => Value::String(std::str::from_utf8(rest).ok()?.to_owned()),
                }))
            })
            .ok_or_else(refused)?,
        ),
    };
    Ok(Opened {
        label,
        kind,
        scalar,
        children,
        whole: None,
    })
}

/// Open one entry stored at `slot`, under the digest of the children it
/// must have been sealed over. The plaintext the cipher returns stays in its
/// `Protected` and is wiped when decoding is done.
fn open_entry(
    cipher: &Aes256Cipher,
    header: &JsonHeader,
    column: &Context<'_>,
    entry: &JsonEntry,
    slot: u64,
    children: &ChildrenDigest,
) -> Result<Opened, Error> {
    let aad = entry_aad(
        header.keyset_id,
        column,
        &header.tag,
        JsonSelector(entry.s),
        slot,
        children,
    );
    let plaintext = cipher
        .open(LocalCipherText::from(entry.c.clone()), &aad)
        .map_err(|_| Error::Aead)?;
    decode_node(&plaintext)
}

/// Take a node's label out of it, so the rebuild can consume the node.
fn take_label(mut node: Opened) -> (Label, Opened) {
    (std::mem::replace(&mut node.label, Label::Root), node)
}

/// The value the caller asked for, out of the `Protected` that held it:
/// the one place an opened JSON plaintext is unwrapped.
fn hand_over(value: Protected<PlainJson>) -> Value {
    value.risky_unwrap().into_value()
}

/// What opening a document's entries under the caller's context needs
/// from ZeroKMS and from the context: the request that retrieves the
/// document's one data key (its `iv`, its tag and its keyset from the
/// header, and the context's descriptor, which ZeroKMS bound the key to),
/// and the column AAD every entry opens under ([`entry_aad`]), which is the
/// context's AAD. Refused with [`Error::DescriptorTooLong`] before any
/// request is made.
fn key_retrieval(
    header: &JsonHeader,
    context: vitaminc_aead::ContextPiece<'static>,
) -> Result<(Request, Context<'static>), Error> {
    let descriptor = Descriptor::from_piece(&context);
    descriptor.check()?;
    Ok((
        Request::retrieve_under(header.iv, header.tag.clone(), descriptor, header.keyset_id),
        context.into_aad().into_owned(),
    ))
}

/// Open the document: one key retrieval, then the sealed root alone, or,
/// with the root open, every entry placed by the chain and opened under the
/// cascade.
///
/// With the root open the client walks the chain itself, as the server does
/// for a read of `$`: it derives the root's token, finds each node's
/// children by their parent tags, and opens each node under the digest of
/// its children's tags ([`place`]). Deriving the root's token takes the
/// index key of the keyset the document was sealed under, which the pending
/// asks for beside the data key ([`Request::load_keyset`]): the cipher's
/// cached keyset, or one loaded from ZeroKMS and cached, as
/// [`StackCipher::keyset`] would load it. The sealed root needs no index
/// key.
fn open_document<'a, K>(
    doc: JsonDocument,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Value, K> {
    let piece = context.into_context();
    let prf_context = piece.clone().into_prf_context().into_owned();
    let (request, aad) = match key_retrieval(&doc.header, piece) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    // With the root open, the keyset the document names is loaded beside
    // its data key: from the cipher's cache, or from ZeroKMS on a miss.
    let open_root = !doc.header.sealed_root;
    let mut requests = vec![request];
    if open_root {
        requests.push(Request::load_keyset(doc.header.keyset_id));
    }
    Pending::request(cipher, requests, move |responses| {
        let key = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key)?;
        if open_root {
            let keyset = responses.next_keyset()?;
            open_whole_chain(doc, &aes, &aad, Selectors::new(keyset, prf_context))
        } else {
            open_sealed_root(&doc, &aes, &aad)
        }
    })
}

/// The whole document out of its sealed root, which is stored at slot `0`
/// and commits to no children.
fn open_sealed_root(
    doc: &JsonDocument,
    aes: &Aes256Cipher,
    aad: &Context<'_>,
) -> Result<Value, Error> {
    let root = doc
        .entries
        .first()
        .ok_or_else(|| shape("a document with a root entry"))?;
    open_entry(aes, &doc.header, aad, root, 0, &cascade::no_children())?
        .whole
        .map(hand_over)
        .ok_or_else(|| shape("a sealed root"))
}

/// The whole document with its root open: every entry placed by the chain
/// from the root's token, as one read of `$` that must reach every entry.
fn open_whole_chain(
    doc: JsonDocument,
    aes: &Aes256Cipher,
    aad: &Context<'_>,
    selectors: Selectors,
) -> Result<Value, Error> {
    let root = JsonPath::root();
    let token = prf16(
        &selectors.keyset.prf,
        TOKEN_DOMAIN,
        &selectors.context,
        &root.token_bytes().unwrap_or_default(),
    )?;
    // A document whose chain the root's token does not enter was sealed
    // under another column or keyset, or its tags were rewritten. Its first
    // entry is opened under the empty digest so that the cipher refuses it
    // as it refuses a sealed root of another column: a root with children
    // fails that open whichever the cause, and only a scalar or empty
    // root reaches the shape error below.
    if doc.find(&token).is_none() {
        let first = doc
            .entries
            .first()
            .ok_or_else(|| shape("a document with a root entry"))?;
        let _ = open_entry(aes, &doc.header, aad, first, 0, &cascade::no_children())?;
        return Err(shape("a document whose chain reaches its root"));
    }
    let JsonDocument {
        header, entries, ..
    } = doc;
    // The entries move into the rows: the document is opened, not kept.
    let rows = entries
        .into_iter()
        .enumerate()
        .map(|(slot, entry)| ReturnedRow {
            entry,
            slot: slot as u64,
            depth: None,
        })
        .collect();
    let reads = [Read {
        token,
        path: root,
        probe: false,
    }];
    let opening = Opening {
        header: &header,
        aad,
        aes,
    };
    // One read, of the root the chain was seen to enter: one value.
    place(rows, &reads, &selectors, 0, &opening)?
        .pop()
        .map(hand_over)
        .ok_or_else(|| shape("a document whose chain reaches its root"))
}

impl DecryptInto<Value> for JsonDocument {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        Decryption::from_open(move |cipher| open_document(self, cipher, context))
    }
}

/// The refusal of a row that is not the one a read asked for.
fn wrong(expected: &'static str) -> Error {
    Error::JsonWrongEntry { expected }
}

/// Open the entry `->` returned for a selector: the scalar it holds, or the
/// whole document for a sealed root asked for at `$`. An entry that does
/// not carry the selector asked for is refused with
/// [`Error::JsonWrongEntry`] before any key is retrieved: it is another
/// path's entry, or the sealed root (whose selector is the root's) in place
/// of a node, and it would open, since every entry is sealed under its own
/// selector.
///
/// The entry opens under the digest of no children, which is what a
/// scalar, an empty container and the sealed root are sealed under. A
/// container with children is sealed over its children's tags, which `->`
/// does not return, so it does not open alone, and nothing outside the
/// ciphertext says whether an entry is one. So an entry the cipher refuses
/// here is [`Error::JsonNotALeaf`], which names both causes, a container
/// with children (read it through [`JsonSubtree`]) and an altered entry,
/// and claims neither. An empty container opens and holds no value of its
/// own: [`Error::OpenedType`].
///
/// At a wildcard path (a path with an array step, whose elements all share
/// one selector, at any depth: every element under `$.a[*]`) the entry `->`
/// returns is the first the server finds carrying the selector in the
/// stored order, which is random per document: an unspecified element of
/// the row, the same one every time the row is read, but not element `0`.
/// The same holds for `->>` and for ordering by `eql_v4.ord_term(col ->
/// sel)`. Every element of a wildcard path is reached through all its
/// matches instead (`json_tree_path_query`, or a [`JsonSubtree`] read,
/// which opens them in document order by their labels).
impl DecryptInto<Value> for JsonExtracted {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        let (node, selector) = self.into_parts();
        if node.entry.s != selector {
            return Decryption::failed(wrong("the entry at the path asked for"));
        }
        Decryption::from_open(move |cipher| {
            let (request, aad) = match key_retrieval(&node.header, context.into_context()) {
                Ok(parts) => parts,
                Err(error) => return Pending::failed(cipher, error),
            };
            Pending::request(cipher, vec![request], move |responses| {
                let key = responses.next_retrieved_key()?;
                let aes = leaf_cipher(&key)?;
                let opened = open_entry(
                    &aes,
                    &node.header,
                    &aad,
                    &node.entry,
                    node.slot,
                    &cascade::no_children(),
                )
                .map_err(|error| match error {
                    Error::Aead => Error::JsonNotALeaf,
                    other => other,
                })?;
                opened
                    .whole
                    .or(opened.scalar)
                    .map(hand_over)
                    .ok_or_else(|| shape("a JSON scalar, or a sealed root"))
            })
        })
    }
}

/// Open the rows of a read into the values of the nodes its tokens named,
/// in the key's order, each still under its `Protected`. Shared by the
/// three openings below, so they agree on every row and on the fallback:
/// the sealed root a read fell back to opens whole, and the key's concrete
/// paths and probes are evaluated over it to the same values the walked
/// rows open to, the truncation included.
fn open_reads<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Vec<Protected<PlainJson>>, K> {
    if subtree.is_sealed_root() {
        open_fallback(subtree, cipher, context)
            .try_map(|(key, mut whole)| select_reads(&key, &mut whole))
    } else {
        open_subtree(subtree, cipher, context)
    }
}

/// The one value a read reached, or none; more than one (a wildcard that
/// reached several nodes) is [`Error::OpenedType`].
fn one_reached(
    mut values: Vec<Protected<PlainJson>>,
) -> Result<Option<Protected<PlainJson>>, Error> {
    match values.len() {
        0 | 1 => Ok(values.pop()),
        _ => Err(shape("one node at the walked path")),
    }
}

/// Open the rows of a read into a list: one value per concrete path the
/// key's tokens named that the row has, in the key's order, which is
/// document order. For a path with no wildcard that is the node at the path
/// or nothing; for a wildcard, every element it reaches below the bound.
/// A probe that named a node (an array longer than the bound) is
/// [`Error::JsonWildcardTruncated`], never a partial list. Every row is
/// checked against the key first ([`JsonSubtreeKey::open`]); a row that
/// does not fit is [`Error::JsonWrongEntry`].
impl DecryptInto<Vec<Value>> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<Value>, K> {
        Decryption::from_open(move |cipher| {
            open_reads(self, cipher, context)
                .map(|values| values.into_iter().map(hand_over).collect())
        })
    }
}

/// Open the rows of a read into the value at the path, or `None` where the
/// row has no node there: the four answers `jsonb #>` gives, an object, an
/// array and a scalar (`null` included) as `Some`, and SQL `NULL` as
/// `None`, the way `->` returns SQL `NULL` for a path the row lacks. More
/// than one node (a wildcard that reached several) is
/// [`Error::OpenedType`]; a probe that named a node is
/// [`Error::JsonWildcardTruncated`].
impl DecryptInto<Option<Value>> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Option<Value>, K> {
        Decryption::from_open(move |cipher| {
            open_reads(self, cipher, context)
                .try_map(|values| Ok(one_reached(values)?.map(hand_over)))
        })
    }
}

/// Open the rows of a read into the value at the path: an object, an array
/// or a scalar, empty containers included, as `jsonb` holds them there. No
/// node at the path is [`Error::OpenedType`]; open as `Option<Value>` to
/// read that as `None`. More than one node is [`Error::OpenedType`] too,
/// and opens through [`DecryptInto<Vec<Value>>`] instead; a probe that
/// named a node is [`Error::JsonWildcardTruncated`].
impl DecryptInto<Value> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        Decryption::from_open(move |cipher| {
            open_reads(self, cipher, context).try_map(|values| {
                one_reached(values)?
                    .map(hand_over)
                    .ok_or_else(|| shape("a node at the walked path"))
            })
        })
    }
}

/// One row of a read as the server returned it, not yet opened: the entry,
/// the slot its ciphertext is bound to, and the depth the server reported,
/// which is optional on the wire and checked against the place the chain
/// puts the row in.
struct ReturnedRow {
    entry: JsonEntry,
    slot: u64,
    depth: Option<u32>,
}

/// Open every row and place each node a token named, checking every row
/// against the key as it goes ([`place`]).
fn open_subtree<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Vec<Protected<PlainJson>>, K> {
    let (mut nodes, key) = subtree.into_parts();
    let Some(first) = nodes.first() else {
        return Pending::ready(cipher, Ok(Vec::new()));
    };
    let header = first.header.clone();
    // A read is of one row, so its rows carry one header. Rows of two
    // documents are not the answer to it. Checked first: two documents'
    // entries can share a slot.
    if nodes.iter().any(|n| n.header != header) {
        return Pending::failed(cipher, wrong("rows of one document"));
    }
    // A read returns each entry once. Two rows at one slot are the server
    // repeating an entry, which would let it line up one container as many
    // times as it likes: an honest database never returns one, so it is the
    // wrong entry, not a shape the target refuses.
    nodes.sort_by_key(|n| n.slot);
    if nodes.windows(2).any(|pair| pair[0].slot == pair[1].slot) {
        return Pending::failed(cipher, wrong("rows of distinct entries"));
    }
    let (request, aad) = match key_retrieval(&header, context.into_context()) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key_bytes = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key_bytes)?;
        let rows = nodes
            .into_iter()
            .map(|n| ReturnedRow {
                entry: n.entry,
                slot: n.slot,
                depth: n.depth,
            })
            .collect();
        let opening = Opening {
            header: &header,
            aad: &aad,
            aes: &aes,
        };
        place(rows, &key.reads, &key.selectors, key.bound, &opening)
    })
}

/// The cipher side of opening a document's rows: its header, the AAD its
/// entries open under, and the cipher of its data key.
struct Opening<'o> {
    header: &'o JsonHeader,
    aad: &'o Context<'o>,
    aes: &'o Aes256Cipher,
}

/// Where the selector a node must carry comes from: the concrete path of
/// the read that named it, for the node at the top of a read, or the
/// selector bytes of its parent, extended by its own label, beneath one.
enum ExpectedSelector<'p> {
    OfPath(&'p JsonPath),
    UnderParent(&'p Protected<Vec<u8>>),
}

/// Put the rows of a read back into the nodes its `reads` named, in the
/// reads' order, opening every node under the cascade
/// ([`cascade`](super::cascade)); and refuse the whole read with
/// [`Error::JsonWildcardTruncated`] at `bound` if a probe named a node.
///
/// The rows arrive in any order, and nothing here reads a row's slot `j` as
/// a position in the document: the chain's tags say where each row sits. The
/// node a read's token names is the row carrying that token's self tag, and
/// a node's children are the rows carrying its parent tags at the ordinals
/// `0, 1, 2, …`, each with the token the member or element rule derives for
/// it, as the server finds them. The tags are the database's word, so they
/// only say where to try each row. What decides is the cipher: every node
/// opens under the digest of the AEAD tags of the children the tags gave
/// it, so a node whose children were swapped, dropped, added or reordered,
/// or which was put under the wrong parent, does not open
/// ([`Error::Aead`]).
///
/// The checks the client still makes, each [`Error::JsonWrongEntry`]: no
/// two rows are one entry ([`open_subtree`], before any key is retrieved);
/// every row the server returned is one the reads reach; the depth the
/// server reported for a row is the one the chain gives it; a child's self
/// tag fits the member or the element rule, and the rule its decrypted
/// label names; the node at the top of a read carries its path's selector
/// and its decrypted label is the last step of that path; the sealed root
/// sits nowhere but at `$`; and a container has the number of children its
/// plaintext says. The node at the top of a read is checked by these alone,
/// since nothing above it is read. Beneath it the cascade already holds
/// every child to its place, and the selector and child-count checks there
/// back the AEAD rather than replace it.
///
/// Still allowed by design (ADR 0010): an entry from another row of the
/// column, returned with that row's header; a node at the same selector
/// under another element (`$.items[0].price` for `$.items[1].price`) at the
/// top of a read, which no bound field tells apart; and rows withheld whole.
fn place(
    rows: Vec<ReturnedRow>,
    reads: &[Read],
    selectors: &Selectors,
    bound: u32,
    opening: &Opening<'_>,
) -> Result<Vec<Protected<PlainJson>>, Error> {
    let mut walk = ChainWalk::new(rows, selectors, opening);
    let mut reached = Vec::new();
    let mut truncated = false;
    for read in reads {
        let Some(at) = walk.find(&read.token) else {
            continue;
        };
        let (value, _) = walk.node(at, &read.token, ExpectedSelector::OfPath(&read.path), 0)?;
        if read.probe {
            truncated = true;
        } else {
            reached.push(value);
        }
    }
    // A read returns the subtrees of the nodes its tokens name and nothing
    // else, so a row none of them reaches is not an answer to it.
    if walk.placed.contains(&false) {
        return Err(wrong("rows the walked paths reach"));
    }
    if truncated {
        return Err(Error::JsonWildcardTruncated { bound });
    }
    Ok(reached)
}

/// The client's walk of the chain over the rows of one read, as the server
/// walked it: the rows, which of them the walk has placed, and the server's
/// two lookups over them, by self tag and by parent tag.
struct ChainWalk<'k> {
    rows: Vec<ReturnedRow>,
    placed: Vec<bool>,
    by_self_tag: HashMap<super::SelfTag, usize>,
    by_parent_tag: HashMap<super::ParentTag, usize>,
    selectors: &'k Selectors,
    opening: &'k Opening<'k>,
}

impl<'k> ChainWalk<'k> {
    fn new(rows: Vec<ReturnedRow>, selectors: &'k Selectors, opening: &'k Opening<'k>) -> Self {
        // Where several rows carry one tag, which no sealing produces, the
        // last of them, as the server's index keeps it
        // (`eql_v4_internal.json_tree_index` builds it with
        // `jsonb_object_agg`), so the client tries the row the server found.
        let mut by_self_tag = HashMap::with_capacity(rows.len());
        let mut by_parent_tag = HashMap::with_capacity(rows.len());
        for (i, row) in rows.iter().enumerate() {
            let _ = by_self_tag.insert(row.entry.x, i);
            if let Some(p) = row.entry.p {
                let _ = by_parent_tag.insert(p, i);
            }
        }
        Self {
            placed: vec![false; rows.len()],
            rows,
            by_self_tag,
            by_parent_tag,
            selectors,
            opening,
        }
    }

    /// The row carrying the self tag of `token`.
    fn find(&self, token: &Tag) -> Option<usize> {
        self.by_self_tag
            .get(&self_tag(&self.opening.header.iv, token))
            .copied()
    }

    /// The children of the node whose token is `token`, as the server
    /// enumerates them: the rows at its parent tags for the ordinals from
    /// zero until the first miss, each with the token its self tag says it
    /// has. A child whose self tag fits neither rule is refused: the server
    /// would not descend into it, and no sealing writes one.
    fn children(&self, token: &Tag) -> Result<Vec<(usize, Tag)>, Error> {
        let iv = &self.opening.header.iv;
        let mut children = Vec::new();
        // A node has fewer children than there are rows, so the probe loop
        // is bounded whatever the tags say.
        for o in 0..u32::try_from(self.rows.len()).unwrap_or(u32::MAX) {
            let Some(&child) = self.by_parent_tag.get(&parent_tag(iv, token, o)) else {
                break;
            };
            let child_token = hit_token(iv, token, &self.rows[child].entry, o)
                .ok_or_else(|| wrong("a child the member or element rule names"))?;
            children.push((child, child_token));
        }
        Ok(children)
    }

    /// Place and open the row at `at`, the node whose token is `token`,
    /// `depth` levels below the node its read named, which must carry the
    /// selector `expected` says: its children found by the chain, then the
    /// node opened under the digest of their tags, then the checks, then
    /// the children in turn. Returns the node's value and its label, which
    /// its parent places it by.
    ///
    /// The recursion follows only nodes that opened, so it follows the tree
    /// that was sealed, which nests no deeper than [`MAX_DEPTH`].
    fn node(
        &mut self,
        at: usize,
        token: &Tag,
        expected: ExpectedSelector<'_>,
        depth: u32,
    ) -> Result<(Protected<PlainJson>, Label), Error> {
        let refused = || wrong("a node the walked path reaches");
        // No row is placed twice: below a node the chain follows only
        // children that open under its digest, which are the ones sealed
        // there, and a key's paths are disjoint, so no row is both a read's
        // node and beneath another's.
        self.placed[at] = true;
        if self.rows[at].depth.is_some_and(|got| got != depth) {
            return Err(wrong("a row at the depth the chain gives it"));
        }
        let children = self.children(token)?;
        let digest = cascade::children_digest(
            children
                .iter()
                .map(|&(child, _)| self.rows[child].entry.c.as_slice()),
        );
        let row = &self.rows[at];
        let Opening { header, aad, aes } = *self.opening;
        let opened = open_entry(aes, header, aad, &row.entry, row.slot, &digest)?;
        // The sealed root is the whole document, read only at `$`.
        if opened.whole.is_some()
            && !matches!(expected, ExpectedSelector::OfPath(path) if path.segments().is_empty())
        {
            return Err(wrong("a node of the walked subtree"));
        }
        if opened.children as usize != children.len() {
            return Err(wrong("a container with the children it was sealed over"));
        }
        let (label, opened) = take_label(opened);
        // The selector the chain gives this node: the read's path for the
        // node it named, its parent's path extended by its own label below.
        let bytes = match expected {
            ExpectedSelector::OfPath(path) => {
                if !names(path, &label) {
                    return Err(refused());
                }
                path.protected_selector_bytes()
            }
            ExpectedSelector::UnderParent(parent) => {
                child_selector_bytes(parent, &label).ok_or_else(refused)?
            }
        };
        if self.selectors.of(bytes.clone())? != row.entry.s {
            return Err(refused());
        }
        if let Some(whole) = opened.whole {
            return Ok((whole, label));
        }
        match opened.kind {
            Kind::Object => {
                let mut object = protected_object();
                for (child, child_token) in children {
                    let (value, child_label) =
                        self.child(child, token, &child_token, &bytes, depth)?;
                    let Label::Key(key) = child_label else {
                        return Err(shape("an object member"));
                    };
                    insert_member(&mut object, key, value);
                }
                Ok((object, label))
            }
            Kind::Array => {
                let mut array = protected_array(children.len());
                for (i, (child, child_token)) in children.into_iter().enumerate() {
                    let (value, child_label) =
                        self.child(child, token, &child_token, &bytes, depth)?;
                    if !matches!(child_label, Label::Index(at) if at == i as u64) {
                        return Err(shape("an array element in order"));
                    }
                    push_element(&mut array, value);
                }
                Ok((array, label))
            }
            _ => Ok((opened.scalar.ok_or_else(|| shape("a JSON scalar"))?, label)),
        }
    }

    /// Place and open a child, and check that the token its self tag chose
    /// (the member or the element rule) is the one its decrypted label
    /// derives under its parent's: a member's by its key, an element's by
    /// its index.
    fn child(
        &mut self,
        child: usize,
        parent_token: &Tag,
        child_token: &Tag,
        parent_bytes: &Protected<Vec<u8>>,
        depth: u32,
    ) -> Result<(Protected<PlainJson>, Label), Error> {
        let (value, label) = self.node(
            child,
            child_token,
            ExpectedSelector::UnderParent(parent_bytes),
            depth + 1,
        )?;
        let s = self.rows[child].entry.s;
        if labelled_token(parent_token, &s, &label).as_ref() != Some(child_token) {
            return Err(wrong("a child under the rule its label names"));
        }
        Ok((value, label))
    }
}

/// Whether a node with `label` is the one the concrete `path` names by its
/// last step: the key, the position, or the root for `$`.
fn names(path: &JsonPath, label: &Label) -> bool {
    match (path.segments().last(), label) {
        (None, Label::Root) => true,
        (Some(Segment::Key(want)), Label::Key(got)) => got.risky_ref() == want,
        (Some(Segment::Index(want)), Label::Index(got)) => got == want,
        _ => false,
    }
}

/// The selector bytes of the child labelled `label` of the node whose
/// selector bytes are `parent`: the parent's, then the child's step, a key
/// for a member and the array step for an element, as
/// [`JsonPath::selector_bytes`] writes them. A member's key is decrypted
/// plaintext, so the bytes are built inside a `Protected`, sized before
/// they are written. `None` for the root, which is no node's child.
fn child_selector_bytes(parent: &Protected<Vec<u8>>, label: &Label) -> Option<Protected<Vec<u8>>> {
    let parent_len = parent.risky_ref().len();
    let mut out = match label {
        Label::Root => return None,
        Label::Index(_) => Protected::new(Vec::with_capacity(parent_len + 1)),
        Label::Key(key) => Protected::new(Vec::with_capacity(
            parent_len + key_step_len(key.risky_ref().len()),
        )),
    };
    out.update_with_ref(parent.as_protected_ref(), |out, parent: &Vec<u8>| {
        out.extend_from_slice(parent);
    });
    match label {
        Label::Key(key) => out.update_with_ref(key.as_protected_ref(), |out, key: &String| {
            push_key(out, key);
        }),
        _ => out.update(|out| out.push(ARRAY_STEP)),
    }
    Some(out)
}

/// The token of the child labelled `label`, whose selector is `s`, under the
/// node whose token is `parent`: the member rule for a key, the element rule
/// for a position. `None` for the root, which is no node's child.
fn labelled_token(parent: &Tag, s: &Tag, label: &Label) -> Option<Tag> {
    match label {
        Label::Key(_) => Some(member_token(parent, s)),
        Label::Index(i) => u32::try_from(*i).ok().map(|i| element_token(parent, s, i)),
        Label::Root => None,
    }
}

/// The key's reads evaluated over the whole document a read fell back to,
/// to what the walked rows open to: each concrete path's node, moved out of
/// the document's `Protected` into one of its own (leaving `null` behind,
/// so its plaintext is never copied), in the key's order, and the same
/// [`Error::JsonWildcardTruncated`] when a probe's path names a node. The
/// key's paths are disjoint, so moving one node out never touches another.
/// What is left of the document is wiped when it drops.
fn select_reads(
    key: &JsonSubtreeKey,
    whole: &mut Protected<PlainJson>,
) -> Result<Vec<Protected<PlainJson>>, Error> {
    let truncated = {
        let doc = whole.risky_ref().value();
        key.reads
            .iter()
            .any(|read| read.probe && !read.path.select(doc).is_empty())
    };
    if truncated {
        return Err(Error::JsonWildcardTruncated { bound: key.bound });
    }
    Ok(key
        .reads
        .iter()
        .filter(|read| !read.probe)
        .filter_map(|read| {
            take_protected(whole, |doc: &mut PlainJson| {
                read.path
                    .select_mut(doc.value_mut())
                    .into_iter()
                    .next()
                    .map(|node| PlainJson::from_value(std::mem::take(node)))
            })
        })
        .collect())
}

/// Open the sealed root a read fell back to: the whole document, under its
/// `Protected`, with the key that keyed the read, whose reads the caller
/// evaluates over it.
fn open_fallback<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, (JsonSubtreeKey, Protected<PlainJson>), K> {
    let (nodes, key) = subtree.into_parts();
    let Some(root) = nodes.into_iter().next() else {
        return Pending::failed(cipher, shape("the sealed root"));
    };
    let (request, aad) = match key_retrieval(&root.header, context.into_context()) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let retrieved = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&retrieved)?;
        let opened = open_entry(
            &aes,
            &root.header,
            &aad,
            &root.entry,
            root.slot,
            &cascade::no_children(),
        )?;
        let whole = opened.whole.ok_or_else(|| shape("a sealed root"))?;
        Ok((key, whole))
    })
}

// =============================================================================
// Extraction keys, on the keyset cipher
// =============================================================================

/// The most tokens one subtree read sends. A wildcard expands to `N + 1`
/// tokens under each node it sits below, so wildcards nested `w` deep send
/// `N^w + … + N + 1`: two levels at the default bound send 4,161, three
/// would send 266,305. Past this a read is refused
/// ([`TermError::JsonWildcardTooWide`]) rather than built. 8,192 admits
/// every one-level wildcard up to 8,191 elements and two levels up to a
/// bound of 90, the default included, and no third level: the server looks
/// every token up in every row before it knows whether the budget is
/// blown, so a wider read costs its tokens even when the whole document
/// comes back instead, and the largest read measured sent 4,161.
pub(crate) const MAX_READ_TOKENS: u64 = 1 << 13;

/// How a path expands into the concrete paths a read sends tokens for.
struct Expansion<'p> {
    segments: &'p [Segment],
    /// The selector of each step's path, from the first step down: every
    /// element of an array shares one, so it is the same for every concrete
    /// path the read expands to.
    steps: &'p [Tag],
    bound: u32,
    reads: Vec<Read>,
}

impl Expansion<'_> {
    /// Expand the steps from `k` on below the node at the concrete path
    /// `at`, whose token is `token`, in document order: a key by the member
    /// rule, a position by the element rule, and a wildcard into the
    /// positions `0 … N − 1`, each expanded in turn, then the probe at `N`.
    /// The recursion is as deep as the path, which the caller bounds.
    fn descend(&mut self, at: JsonPath, token: Tag, k: usize) -> Result<(), TermError> {
        let Some(segment) = self.segments.get(k) else {
            self.reads.push(Read {
                token,
                path: at,
                probe: false,
            });
            return Ok(());
        };
        let s = self.steps[k];
        match segment {
            Segment::Key(key) => self.descend(
                at.then(Segment::Key(key.clone())),
                member_token(&token, &s),
                k + 1,
            ),
            Segment::Index(index) => {
                let i = fit_ordinal(*index)?;
                self.descend(
                    at.then(Segment::Index(*index)),
                    element_token(&token, &s, i),
                    k + 1,
                )
            }
            Segment::Wildcard => {
                for i in 0..self.bound {
                    self.descend(
                        at.then(Segment::Index(u64::from(i))),
                        element_token(&token, &s, i),
                        k + 1,
                    )?;
                }
                self.reads.push(Read {
                    token: element_token(&token, &s, self.bound),
                    path: at.then(Segment::Index(u64::from(self.bound))),
                    probe: true,
                });
                Ok(())
            }
        }
    }
}

/// How many tokens a read of a path with `wildcards` wildcard steps sends
/// at `bound`: `bound^w + … + bound + 1`, or `None` past
/// [`MAX_READ_TOKENS`].
fn read_tokens(wildcards: usize, bound: u32) -> Option<u64> {
    let mut count: u64 = 1;
    for _ in 0..wildcards {
        count = count
            .checked_mul(u64::from(bound))?
            .checked_add(1)
            .filter(|count| *count <= MAX_READ_TOKENS)?;
    }
    Some(count)
}

/// The key that reads `path`: one token per concrete path the path names,
/// each derived from the path alone, in document order, with a probe for
/// the element at `bound` of each array a wildcard expands.
///
/// Every node's token derives from its path: the root's and, under the
/// sealed root, each chain head's are PRFs of their paths; below them a
/// member's is one hash under its parent's with its selector, and an
/// element's one hash with its selector and its index. So a path with no
/// wildcard sends exactly one token, its node's. A wildcard names no one
/// node, and the client expands it to the positions `0 … bound − 1`, plus
/// the probe at `bound`: the element itself, not the path below it, since
/// an element past the bound need not have what the path names.
fn subtree_key_for(
    selectors: Selectors,
    options: &JsonOptions,
    path: &JsonPath,
    bound: u32,
) -> Result<JsonSubtreeKey, TermError> {
    // The bound is not checked against PostgreSQL's integer: a path with no
    // wildcard never uses it, and with one the token cap refuses any bound
    // of MAX_READ_TOKENS or more first, naming the bound in its help.
    let segments = path.segments();
    // No sealed document has a node deeper than this, and the expansion
    // recurses once per step.
    if segments.len() > MAX_DEPTH {
        return Err(TermError::JsonTooDeep);
    }
    for segment in segments {
        if let Segment::Index(index) = segment {
            let _ = fit_ordinal(*index)?;
        }
    }
    let wildcards = segments
        .iter()
        .filter(|segment| matches!(segment, Segment::Wildcard))
        .count();
    let count = read_tokens(wildcards, bound).ok_or(TermError::JsonWildcardTooWide)?;
    let prf = &selectors.keyset.prf;
    let context = &selectors.context;
    let mut steps = Vec::with_capacity(segments.len());
    let mut prefix = JsonPath::root();
    for segment in segments {
        prefix = prefix.then(segment.clone());
        steps.push(prf16(
            prf,
            SELECTOR_DOMAIN,
            context,
            &prefix.selector_bytes(),
        )?);
    }
    let mut expansion = Expansion {
        segments,
        steps: &steps,
        bound,
        reads: Vec::with_capacity(usize::try_from(count).unwrap_or_default()),
    };
    let head = |at: &JsonPath| {
        prf16(
            prf,
            TOKEN_DOMAIN,
            context,
            &at.token_bytes().unwrap_or_default(),
        )
    };
    match segments.first() {
        // Under the sealed root the chain starts at the heads, each a PRF
        // of its path; a wildcard head is each position's head in turn.
        Some(first) if options.sealed_root => {
            let heads: Vec<(Segment, bool)> = match first {
                Segment::Wildcard => (0..bound)
                    .map(|i| (Segment::Index(u64::from(i)), false))
                    .chain(std::iter::once((Segment::Index(u64::from(bound)), true)))
                    .collect(),
                step => vec![(step.clone(), false)],
            };
            for (step, probe) in heads {
                let at = JsonPath::root().then(step);
                let token = head(&at)?;
                if probe {
                    expansion.reads.push(Read {
                        token,
                        path: at,
                        probe,
                    });
                } else {
                    expansion.descend(at, token, 1)?;
                }
            }
        }
        // `$` itself, under either root, or any path from an open root:
        // the root's token, and every step below it by rule.
        _ => {
            let root = JsonPath::root();
            let token = head(&root)?;
            expansion.descend(root, token, 0)?;
        }
    }
    Ok(JsonSubtreeKey {
        reads: expansion.reads,
        bound,
        path: path.clone(),
        selectors,
    })
}

impl<K> KeysetCipher<'_, K> {
    /// The selector of `path`, under the field `descriptor`: what `->` and
    /// the path functions take. Every element of an array shares its
    /// parent's selector, so a position in `path` reads as the wildcard.
    /// Derived locally; the pending carries no request.
    pub fn json_selector<'c>(
        &self,
        path: &JsonPath,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, JsonSelector, K> {
        Pending::ready(self, self.json_selector_now(path, descriptor))
    }

    /// [`json_selector`](Self::json_selector), derived and returned now:
    /// for the engine's own callers, which derive locally and want a
    /// refusal as a plain error.
    pub(crate) fn json_selector_now<'c>(
        &self,
        path: &JsonPath,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Result<JsonSelector, Error> {
        let context = descriptor.into_prf_context().into_owned();
        prf16(
            self.prf(),
            SELECTOR_DOMAIN,
            &context,
            &path.selector_bytes(),
        )
        .map(JsonSelector)
        .map_err(Error::from)
    }

    /// The key that reads the node at `path`, under the field `descriptor`
    /// and the index's `options`, with wildcards expanded to
    /// [`JsonSubtreeKey::DEFAULT_BOUND`] elements: one token per concrete
    /// path, each derived from the path alone, which is what
    /// `json_tree_subtree(doc, key.tokens(), budget)` takes. See
    /// [`json_subtree_key_with_bound`](Self::json_subtree_key_with_bound).
    ///
    /// # Errors
    ///
    /// As [`json_subtree_key_with_bound`](Self::json_subtree_key_with_bound).
    pub fn json_subtree_key<'c>(
        &self,
        path: &JsonPath,
        options: &JsonOptions,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, JsonSubtreeKey, K> {
        self.json_subtree_key_with_bound(path, options, JsonSubtreeKey::DEFAULT_BOUND, descriptor)
    }

    /// The key that reads the node at `path`, under the field `descriptor`
    /// and the index's `options`, with each wildcard step expanded to the
    /// positions `0 … bound − 1`. A path with no wildcard sends exactly one
    /// token, its node's, and nothing that covers any node above it; `$`
    /// is a read too, of the root entry, which under the sealed root opens
    /// to the whole document. A path with a wildcard sends one token per
    /// concrete path and, for each array a wildcard expands, a probe for
    /// the element at `bound`; a row where a probe names a node has an
    /// array longer than `bound` there, and its rows open to
    /// [`Error::JsonWildcardTruncated`] rather than to part of the answer.
    /// Raise `bound`, or read the array itself, for longer arrays; lower it
    /// for a nested wildcard over many rows, which sends `bound² + bound +
    /// 1` tokens. Derived locally; the pending carries no request.
    ///
    /// # Errors
    ///
    /// [`TermError::JsonTooWide`] for a path naming an array position past
    /// 2³¹ − 1: no stored document has an element there.
    /// [`TermError::JsonTooDeep`] for a path deeper than any document the
    /// index seals. [`TermError::JsonWildcardTooWide`] for a path whose
    /// wildcards would expand past 8,192 tokens at `bound`; a path with no
    /// wildcard takes any `bound`, since it uses none.
    pub fn json_subtree_key_with_bound<'c>(
        &self,
        path: &JsonPath,
        options: &JsonOptions,
        bound: u32,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, JsonSubtreeKey, K> {
        Pending::ready(
            self,
            self.json_subtree_key_now(path, options, bound, descriptor),
        )
    }

    /// [`json_subtree_key_with_bound`](Self::json_subtree_key_with_bound),
    /// derived and returned now, for the engine's own callers.
    pub(crate) fn json_subtree_key_now<'c>(
        &self,
        path: &JsonPath,
        options: &JsonOptions,
        bound: u32,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Result<JsonSubtreeKey, Error> {
        let context = descriptor.into_prf_context().into_owned();
        let selectors = Selectors::new(Arc::clone(self.state()), context);
        subtree_key_for(selectors, options, path, bound).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vitaminc_prf::PrfKeyInit;

    fn prf() -> HmacSha256Prf {
        HmacSha256Prf::new(Protected::new([7; 32]))
    }

    fn open_root() -> JsonOptions {
        JsonOptions {
            sealed_root: false,
            ..JsonOptions::new()
        }
    }

    fn rng() -> SafeRand {
        SafeRand::from_controlled_seed(Protected::new([5; 32]))
    }

    fn terms(value: &Value, options: &JsonOptions) -> JsonTerms {
        walk(
            value,
            options,
            &prf(),
            &Context::from_encoded(b"users/profile"),
            &mut rng(),
        )
        .unwrap()
        .terms
    }

    /// The wiped framing is byte for byte the PAE vitaminc writes, so a
    /// value selector does not move.
    #[test]
    fn the_wiped_framing_is_vitamincs_pae() {
        for pieces in [
            vec![],
            vec![&b""[..]],
            vec![&b"a"[..], &b""[..], &b"key name"[..]],
            vec![&[7u8; 16][..], &b"x".repeat(300)[..]],
        ] {
            let wiped = pae_wiped(&pieces);
            assert_eq!(&wiped[..], Context::pae(&pieces).as_bytes());
            assert_eq!(wiped.len(), wiped.capacity(), "sized before it is written");
        }
    }

    #[test]
    fn numbers_canonicalise_by_value() {
        let n = |text: &str| -> Number { text.parse().unwrap() };
        assert_eq!(canonical_number(&n("2")), canonical_number(&n("2.0")));
        assert_eq!(canonical_number(&n("0")), canonical_number(&n("-0.0")));
        assert_ne!(canonical_number(&n("2")), canonical_number(&n("2.5")));
        assert_ne!(canonical_number(&n("1")), canonical_number(&n("-1")));
        assert_eq!(
            canonical_number(&n("18446744073709551615")),
            canonical_number(&n("18446744073709551615"))
        );
        // A value selector is stored, so where an integral float stops
        // reading as an integer is part of the stored form: below 1e38 it
        // is the `i128`, from 1e38 up the `f64`.
        assert_eq!(canonical_number(&n("9.9e37"))[0], b'i');
        assert_eq!(canonical_number(&n("1e38"))[0], b'f');
        assert_eq!(canonical_number(&n("-1e38"))[0], b'f');
    }

    #[test]
    fn the_terms_name_a_node_by_its_path() {
        let t = terms(&json!({"a": [1, {"b": 2}]}), &JsonOptions::default());
        // $, $.a, $.a[0], $.a[1], $.a[1].b
        assert_eq!(t.len(), 5);
        assert!(!t.is_empty());
        let at = |path: &str| t.selector(&JsonPath::parse(path).unwrap());
        assert_eq!(at("$.a[1].b"), Some(JsonSelector(t.nodes()[4].s)));
        assert_eq!(at("$.a"), Some(JsonSelector(t.nodes()[1].s)));
        assert_eq!(at("$.a[0]"), at("$.a[1]"), "every element shares one");
        assert_eq!(at("$.c"), None, "no node there");
        assert_eq!(at("$.a[2]"), None, "no third element");
    }

    #[test]
    fn the_terms_print_neither_key_names_nor_tokens() {
        let t = terms(
            &json!({"alice@example.com": {"ssn": "123"}}),
            &JsonOptions::default(),
        );
        let printed = format!("{t:?}");
        assert_eq!(printed, "JsonTerms { nodes: 3, .. }");
        assert!(!printed.contains("alice"));
    }

    #[test]
    fn every_element_of_an_array_shares_a_selector_and_values_do_not() {
        let t = terms(&json!({"a": [1, 2, 1]}), &JsonOptions::default());
        let nodes = t.nodes();
        assert_eq!(nodes.len(), 5);
        assert_eq!(nodes[2].s, nodes[3].s);
        assert_eq!(nodes[2].s, nodes[4].s);
        assert_eq!(nodes[2].vs, nodes[4].vs, "equal values at one path");
        assert_ne!(nodes[2].vs, nodes[3].vs);
    }

    #[test]
    fn every_node_has_a_token_and_only_what_chains_has_an_ordinal() {
        let sealed = terms(&json!({"a": {"b": 1}}), &JsonOptions::default());
        let open = terms(&json!({"a": {"b": 1}}), &open_root());
        let root = prf16(
            &prf(),
            TOKEN_DOMAIN,
            &Context::from_encoded(b"users/profile"),
            &[],
        )
        .unwrap();
        assert_eq!(
            sealed.nodes()[0].token,
            root,
            "the sealed root's token is the PRF of `$`"
        );
        assert_eq!(open.nodes()[0].token, root, "and so is the open root's");
        assert!(
            sealed.nodes()[1].ordinal.is_none(),
            "a head chains from nothing under the sealed root"
        );
        assert!(
            sealed.nodes()[2].ordinal.is_some(),
            "below a head, everything chains"
        );
        assert!(
            open.nodes()[1].ordinal.is_some(),
            "under an open root, a top-level field chains"
        );
        assert_eq!(
            open.nodes()[1].token,
            member_token(&root, &open.nodes()[1].s),
            "a top-level field under an open root is a member of the root"
        );
        // The chain below a head is the same rule either way, but the heads
        // differ: one is a PRF of the path, the other a hash under the
        // root's token.
        assert_ne!(
            sealed.nodes()[1].token,
            open.nodes()[1].token,
            "the heads differ"
        );
        assert_eq!(
            sealed.nodes()[2].token,
            member_token(&sealed.nodes()[1].token, &sealed.nodes()[2].s),
            "a member's token is one hash under its parent's"
        );
    }

    fn key_for(options: &JsonOptions, path: &str, bound: u32) -> Result<JsonSubtreeKey, TermError> {
        subtree_key_for(
            Selectors::for_tests(),
            options,
            &JsonPath::parse(path).unwrap(),
            bound,
        )
    }

    fn node<'t>(t: &'t JsonTerms, path: &str) -> &'t TermNode {
        t.nodes()
            .iter()
            .find(|n| n.positional == JsonPath::parse(path).unwrap())
            .unwrap_or_else(|| panic!("the document has {path}"))
    }

    mod given_a_path_with_no_wildcard {
        use super::*;

        #[test]
        fn the_key_sends_exactly_the_token_of_the_node_at_the_path() {
            let value = json!({"a": {"b": [1, {"c": 2}], "": {"$": [[3]]}}, "l": [[0], 1]});
            for options in [JsonOptions::default(), open_root()] {
                let t = terms(&value, &options);
                for path in [
                    "$",
                    "$.a",
                    "$.a.b",
                    "$.a.b[0]",
                    "$.a.b[1]",
                    "$.a.b[1].c",
                    "$.l",
                    "$.l[0]",
                    "$.l[0][0]",
                    "$.l[1]",
                    r#"$.a[""]"#,
                    r#"$.a[""]["$"][0][0]"#,
                ] {
                    let key = key_for(&options, path, 64).unwrap();
                    assert_eq!(
                        key.token_bytes(),
                        [node(&t, path).token],
                        "{path} under {options:?}: one token, the node's own"
                    );
                    assert!(
                        key.probes().is_empty(),
                        "{path}: no probe without a wildcard"
                    );
                }
            }
        }

        #[test]
        fn the_root_is_a_read_under_the_sealed_root_too() {
            let key = key_for(&JsonOptions::default(), "$", 64).unwrap();
            assert_eq!(key.reads.len(), 1, "one token");
            assert_eq!(key.reads[0].path, JsonPath::root(), "the root's");
        }

        #[test]
        fn a_position_past_postgres_integer_is_refused_not_sent() {
            for path in [
                "$.a.b[2147483648]",
                "$.a[2147483648]",
                "$[2147483648]",
                "$.a[4294967296]",
            ] {
                assert!(
                    matches!(
                        key_for(&JsonOptions::default(), path, 64),
                        Err(TermError::JsonTooWide)
                    ),
                    "{path}: no stored document has an element there"
                );
            }
            let last = key_for(&JsonOptions::default(), "$.a.b[2147483647]", 64).unwrap();
            assert_eq!(
                last.reads.len(),
                1,
                "the last position PostgreSQL's integer holds"
            );
            assert_eq!(fit_ordinal(i32::MAX.unsigned_abs()).unwrap(), 2_147_483_647);
            assert!(matches!(
                fit_ordinal(2_147_483_648_u64),
                Err(TermError::JsonTooWide)
            ));
        }

        #[test]
        fn a_path_deeper_than_any_document_is_refused() {
            let deepest = format!("${}", "[0]".repeat(MAX_DEPTH));
            assert!(
                key_for(&JsonOptions::default(), &deepest, 64).is_ok(),
                "the deepest path a sealed document has"
            );
            let deeper = format!("${}", "[0]".repeat(MAX_DEPTH + 1));
            assert!(
                matches!(
                    key_for(&JsonOptions::default(), &deeper, 64),
                    Err(TermError::JsonTooDeep)
                ),
                "one step deeper names no node of any document"
            );
        }
    }

    mod given_a_path_with_a_wildcard {
        use super::*;

        #[test]
        fn the_key_sends_each_position_below_the_bound_and_a_probe_at_it() {
            let t = terms(
                &json!({"a": [{"b": 1}, {"b": 2}, {"b": 3}]}),
                &JsonOptions::default(),
            );
            let key = key_for(&JsonOptions::default(), "$.a[*].b", 2).unwrap();
            let paths: Vec<String> = key.reads.iter().map(|r| r.path.to_string()).collect();
            assert_eq!(
                paths,
                ["$.a[0].b", "$.a[1].b", "$.a[2]"],
                "N + 1, in document order"
            );
            assert_eq!(key.probes(), [2], "the probe last, the element itself");
            assert_eq!(key.bound(), 2);
            for read in &key.reads {
                assert_eq!(
                    read.token,
                    node(&t, &read.path.to_string()).token,
                    "{}: the token the stored node carries",
                    read.path
                );
            }
        }

        #[test]
        fn nested_wildcards_multiply() {
            for bound in [0, 1, 3, 64] {
                let key = key_for(&JsonOptions::default(), "$.a[*].b[*]", bound).unwrap();
                let n = bound as usize;
                assert_eq!(key.reads.len(), n * n + n + 1, "N² + N + 1 at N = {bound}");
                assert_eq!(key.probes().len(), n + 1, "N inner probes and one outer");
                assert_eq!(
                    key.reads.last().map(|r| r.path.to_string()),
                    Some(format!("$.a[{bound}]")),
                    "the outer probe last"
                );
                let mut tokens: Vec<Tag> = key.token_bytes();
                tokens.sort_unstable();
                tokens.dedup();
                assert_eq!(tokens.len(), key.reads.len(), "every token distinct");
            }
        }

        #[test]
        fn a_wildcard_head_expands_under_the_sealed_root() {
            let t = terms(&json!([{"x": 1}, {"x": 2}]), &JsonOptions::default());
            let key = key_for(&JsonOptions::default(), "$[*].x", 2).unwrap();
            let paths: Vec<String> = key.reads.iter().map(|r| r.path.to_string()).collect();
            assert_eq!(paths, ["$[0].x", "$[1].x", "$[2]"]);
            assert_eq!(key.reads[0].token, node(&t, "$[0].x").token, "below a head");
            assert_eq!(
                key.reads[2].token,
                prf16(
                    &prf(),
                    TOKEN_DOMAIN,
                    &Context::from_encoded(b"users/profile"),
                    &JsonPath::parse("$[2]").unwrap().token_bytes().unwrap(),
                )
                .unwrap(),
                "the probe is the head at the bound"
            );
        }

        #[test]
        fn an_expansion_past_the_token_limit_is_refused() {
            assert_eq!(
                read_tokens(2, 64),
                Some(4_161),
                "two levels at the default bound"
            );
            assert_eq!(read_tokens(2, 90), Some(8_191), "two levels at 90");
            assert_eq!(read_tokens(2, 91), None, "two levels at 91 is past 8,192");
            assert_eq!(
                read_tokens(3, 64),
                None,
                "three levels at the default bound"
            );
            assert_eq!(
                read_tokens(0, u32::MAX),
                Some(1),
                "no wildcard is one token"
            );
            assert_eq!(read_tokens(1, 8_191), Some(8_192), "the limit itself");
            assert_eq!(read_tokens(1, 8_192), None, "one past the limit");
            assert!(
                matches!(
                    key_for(&JsonOptions::default(), "$.a[*].b[*].c[*]", 64),
                    Err(TermError::JsonWildcardTooWide)
                ),
                "refused before any token is derived"
            );
            assert!(
                matches!(
                    key_for(&JsonOptions::default(), "$.a[*]", 2_147_483_648),
                    Err(TermError::JsonWildcardTooWide)
                ),
                "a bound past PostgreSQL's integer is past the token cap first"
            );
            let unused = key_for(&JsonOptions::default(), "$.a.b", u32::MAX).unwrap();
            assert_eq!(
                unused.reads.len(),
                1,
                "a path with no wildcard uses no bound, so any bound is taken"
            );
        }
    }

    #[test]
    fn a_hit_takes_the_rule_its_self_tag_matches() {
        let iv = [3; 16];
        let parent = [5; 16];
        let s = [6; 16];
        let entry = |x: crate::json::SelfTag| JsonEntry {
            s,
            c: vec![],
            x,
            p: None,
            op: None,
        };
        let member = member_token(&parent, &s);
        let element = element_token(&parent, &s, 2);
        assert_eq!(
            hit_token(&iv, &parent, &entry(self_tag(&iv, &member)), 2),
            Some(member)
        );
        assert_eq!(
            hit_token(&iv, &parent, &entry(self_tag(&iv, &element)), 2),
            Some(element)
        );
        assert_eq!(
            hit_token(&iv, &parent, &entry(self_tag(&iv, &element)), 3),
            None,
            "the element rule takes the hit's own ordinal"
        );
        assert_eq!(
            hit_token(&iv, &parent, &entry([0; 8]), 2),
            None,
            "neither rule"
        );
        assert_ne!(
            member,
            element_token(&parent, &s, 0),
            "a member is never an element"
        );
        assert_ne!(
            self_tag(&iv, &member),
            self_tag(&[4; 16], &member),
            "salted by the iv"
        );
    }

    /// A member's token is the same in every row, whatever its siblings:
    /// the property the change exists for, and what makes a read of
    /// `$.a.b` send `$.a.b`'s token alone.
    mod given_random_documents {
        use super::*;
        use proptest::prelude::*;

        fn key_name() -> impl Strategy<Value = String> {
            prop_oneof![
                Just(String::new()),
                Just("0".to_owned()),
                Just("a.b".to_owned()),
                Just("[*]".to_owned()),
                Just("$".to_owned()),
                Just("\"\\".to_owned()),
                Just("é✓".to_owned()),
                "[a-d]{1,3}",
            ]
        }

        fn siblings() -> impl Strategy<Value = Vec<(String, i64)>> {
            prop::collection::vec((key_name(), any::<i64>()), 0..12)
        }

        proptest! {
            #[test]
            fn a_members_token_ignores_its_siblings(
                left in siblings(),
                right in siblings(),
                sealed in any::<bool>(),
            ) {
                let options = JsonOptions { sealed_root: sealed, ..JsonOptions::new() };
                let row = |siblings: &[(String, i64)], b: Value| {
                    let mut a: Map<String, Value> = siblings
                        .iter()
                        .filter(|(k, _)| k != "b" && k != "c")
                        .map(|(k, v)| (k.clone(), json!(v)))
                        .collect();
                    let _ = a.insert("b".into(), b);
                    terms(&json!({"a": a, "z": 1}), &options)
                };
                let one = row(&left, json!({"c": 1}));
                let two = row(&right, json!([true]));
                prop_assert_eq!(node(&one, "$.a.b").token, node(&two, "$.a.b").token);
                let key = key_for(&options, "$.a.b", 64).unwrap();
                prop_assert_eq!(key.token_bytes(), vec![node(&one, "$.a.b").token]);
                prop_assert_ne!(node(&one, "$.a.b").token, node(&one, "$.a.b.c").token);
                let c = key_for(&options, "$.a.c", 64).unwrap();
                prop_assert_ne!(c.token_bytes(), key.token_bytes(), "$.a.b and $.a.c differ");
            }

            #[test]
            fn element_tokens_differ_by_index_and_from_every_member(
                len in 1usize..20,
                keys in prop::collection::btree_set(key_name(), 0..8),
            ) {
                let options = JsonOptions::default();
                let array = terms(&json!({"a": vec![0; len]}), &options);
                let object: Map<String, Value> = keys.iter().map(|k| (k.clone(), json!(0))).collect();
                let object = terms(&json!({"a": object}), &options);
                let mut elements: Vec<Tag> = (0..len)
                    .map(|i| node(&array, &format!("$.a[{i}]")).token)
                    .collect();
                for member in object.nodes().iter().skip(2) {
                    prop_assert!(!elements.contains(&member.token), "a member is never an element");
                }
                elements.sort_unstable();
                elements.dedup();
                prop_assert_eq!(elements.len(), len, "every index its own token");
            }

            #[test]
            fn every_concrete_path_the_document_has_keys_its_own_token(
                value in arbitrary_json(),
                sealed in any::<bool>(),
            ) {
                let options = JsonOptions { sealed_root: sealed, ..JsonOptions::new() };
                let t = terms(&value, &options);
                for n in t.nodes() {
                    let key = subtree_key_for(Selectors::for_tests(), &options, &n.positional, 4).unwrap();
                    prop_assert_eq!(key.token_bytes(), vec![n.token], "{}", n.positional);
                }
            }
        }

        proptest! {
            /// A query sent in a shuffled order matches exactly the stored
            /// selector sets the query in the walk's order matched, stored
            /// in either order: `jsonb @>` is set containment over arrays.
            #[test]
            fn a_shuffled_query_matches_what_the_unshuffled_one_did(
                stored in arbitrary_json(),
                asked in arbitrary_json(),
                seed in any::<[u8; 32]>(),
            ) {
                let options = JsonOptions::default();
                let selectors = |value: &Value| group_of(terms(value, &options).nodes(), None);
                let mut rng = SafeRand::from_controlled_seed(Protected::new(seed));
                let walked = selectors(&asked);
                let mut shuffled = walked.clone();
                shuffled.shuffle(&mut rng);
                let mut stored_shuffled = selectors(&stored);
                stored_shuffled.shuffle(&mut rng);
                prop_assert_eq!(&shuffled, &walked, "one query, as sets");
                for target in [selectors(&stored), stored_shuffled] {
                    prop_assert_eq!(target.contains(&shuffled), target.contains(&walked));
                }
                prop_assert!(selectors(&asked).contains(&shuffled), "a query's set contains itself in any order");
            }
        }

        /// Small documents over the keys that stress the path encoding.
        pub(super) fn arbitrary_json() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::Bool),
                any::<i64>().prop_map(|n| json!(n)),
                Just(json!(2.0)),
                Just(json!(-0.0)),
                "[a-z]{0,4}".prop_map(Value::String),
            ];
            leaf.prop_recursive(4, 32, 5, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
                    prop::collection::btree_map(key_name(), inner, 0..5)
                        .prop_map(|m| Value::Object(m.into_iter().collect())),
                ]
            })
        }
    }

    #[test]
    fn a_root_scalar_carries_its_element_selectors_as_alt() {
        let scalar = terms(&json!("a"), &JsonOptions::default());
        let array = terms(&json!(["a"]), &JsonOptions::default());
        assert_eq!(
            scalar.alt(),
            Some((array.nodes()[1].s, array.nodes()[1].vs)),
            "the alt pair is the stored array element's"
        );
        assert!(terms(&json!({}), &JsonOptions::default()).alt().is_none());
    }

    #[test]
    fn container_elements_group_what_sits_inside_them() {
        let t = terms(&json!({"a": [{"x": 1}, 2, [3]]}), &JsonOptions::default());
        let nodes = t.nodes();
        // $, $.a, $.a[0], $.a[0].x, $.a[1], $.a[2], $.a[2][0]
        assert!(nodes[2].container_element);
        assert_eq!(nodes[3].element, Some(2));
        assert!(
            !nodes[4].container_element,
            "a scalar element groups nothing"
        );
        assert_eq!(nodes[4].element, None);
        assert!(nodes[5].container_element);
        assert_eq!(nodes[6].element, Some(5));
    }

    /// An object's members get a random permutation of `0..n` as their
    /// ordinals, drawn afresh for every object: the same object sealed
    /// twice gets two.
    #[test]
    fn member_ordinals_are_a_random_permutation_per_object() {
        let map: Map<String, Value> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|k| (k.to_string(), json!(1)))
            .collect();
        let mut rng = rng();
        let ordinals = member_ordinals(&map, &mut rng).unwrap();
        let mut seen: Vec<u32> = ordinals.values().copied().collect();
        seen.sort_unstable();
        assert_eq!(seen, [0, 1, 2, 3, 4, 5], "a permutation of 0..n");
        assert_eq!(ordinals.len(), map.len(), "every member has one");
        let again = member_ordinals(&map, &mut rng).unwrap();
        assert_ne!(
            ordinals, again,
            "the same object drawn twice (with overwhelming probability)"
        );
    }

    /// The plain bytes of a node's encoding, for the test to inspect.
    fn bytes(plain: &Protected<Vec<u8>>) -> Vec<u8> {
        plain.risky_ref().clone()
    }

    fn key_of(label: &Label) -> Option<String> {
        match label {
            Label::Key(key) => Some(key.risky_ref().clone()),
            _ => None,
        }
    }

    #[test]
    fn a_node_encodes_and_decodes() {
        for (label, value, kind) in [
            (LabelRef::Root, json!({}), Kind::Object),
            (LabelRef::Key("k"), json!("v"), Kind::String),
            (LabelRef::Index(3), json!(1.5), Kind::Number),
            (LabelRef::Index(0), json!(true), Kind::Bool),
            (LabelRef::Key("n"), Value::Null, Kind::Null),
            (LabelRef::Key("a"), json!([]), Kind::Array),
        ] {
            let opened = decode_node(&encode_node(kind, 2, label, &value)).unwrap();
            match (label, &opened.label) {
                (LabelRef::Root, Label::Root) => {}
                (LabelRef::Index(a), Label::Index(b)) => assert_eq!(a, *b),
                (LabelRef::Key(a), Label::Key(_)) => {
                    assert_eq!(key_of(&opened.label).as_deref(), Some(a))
                }
                _ => panic!("{kind:?}: the label changed kind"),
            }
            assert_eq!(opened.kind, kind);
            let scalar = opened.scalar.map(|s| s.risky_unwrap().into_value());
            assert_eq!(scalar, (!kind.is_container()).then_some(value));
            assert_eq!(opened.children, 2);
        }
        assert!(decode_node(&Protected::new(vec![])).is_err());
        assert!(decode_node(&Protected::new(vec![9, 0, 0, 0, 0, 0])).is_err());

        // The empty key is a key: its label is the tag and a zero length,
        // and nothing after it.
        let encoded = encode_node(Kind::Object, 0, LabelRef::Key(""), &json!({}));
        assert_eq!(encoded.risky_ref().len(), 1 + 4 + 1 + 4);
        assert_eq!(
            key_of(&decode_node(&encoded).unwrap().label).as_deref(),
            Some("")
        );
        // The encoding is allocated once at its size: nothing reallocated
        // and left a copy behind.
        for (label, value) in [
            (LabelRef::Key("key"), json!("a string value")),
            (LabelRef::Index(9), json!(-12.25)),
            (LabelRef::Root, json!(false)),
            (LabelRef::Key("z"), Value::Null),
            (LabelRef::Root, json!({"a": 1})),
        ] {
            let plain = encode_node(Kind::of(&value), 0, label, &value);
            let number = match &value {
                Value::Number(n) => Some(Protected::new(n.to_string())),
                _ => None,
            };
            assert_eq!(
                encoded_len(label, &value, number.as_ref()),
                plain.risky_ref().len(),
                "measured before it is written"
            );
            assert_eq!(plain.risky_ref().len(), plain.risky_ref().capacity());
        }
        // Every truncation of a labelled node is refused, not read past.
        let keyed = bytes(&encode_node(
            Kind::Array,
            1,
            LabelRef::Key("key"),
            &json!([]),
        ));
        let indexed = bytes(&encode_node(
            Kind::Object,
            1,
            LabelRef::Index(7),
            &json!({}),
        ));
        let encoded = bytes(&encoded);
        for whole in [&keyed, &indexed, &encoded] {
            for len in 0..whole.len() {
                assert!(
                    decode_node(&Protected::new(whole[..len].to_vec())).is_err(),
                    "{len} of {whole:?}"
                );
            }
        }
    }

    #[test]
    fn a_sealed_root_plaintext_is_the_document_allocated_once() {
        let value = json!({"a": [1, "two", {"three": null}], "b": "x".repeat(300)});
        let plain = sealed_root_plaintext(&value).unwrap();
        assert_eq!(plain.risky_ref()[0], SEALED_ROOT);
        assert_eq!(
            serde_json::from_slice::<Value>(&plain.risky_ref()[1..]).unwrap(),
            value
        );
        assert_eq!(plain.risky_ref().len(), plain.risky_ref().capacity());
        let opened = decode_node(&plain).unwrap();
        assert!(matches!(opened.label, Label::Root));
        assert_eq!(opened.kind, Kind::Object);
        assert_eq!(opened.whole.map(hand_over), Some(value));
    }

    #[test]
    fn a_key_tag_must_fit_the_header() {
        let value = json!({"a": 1});
        let context = Context::from_encoded(b"users/profile");
        let sealed = |tag_len: usize| {
            let walked = walk(
                &value,
                &JsonOptions::default(),
                &prf(),
                &context,
                &mut rng(),
            )
            .unwrap();
            let key = stack_kms::DataKeyWithTag {
                key: stack_kms::DataKey {
                    iv: [1; 16],
                    key: [2; 32],
                },
                tag: vec![3; tag_len],
                decryption_policy: None,
            };
            seal(
                walked,
                Some(sealed_root_plaintext(&value).unwrap()),
                Uuid::from_u128(1),
                key,
                &context,
                true,
                SafeRand::from_controlled_seed(Protected::new([0; 32])),
            )
        };
        let longest = usize::from(u16::MAX);
        let doc = sealed(longest).unwrap();
        assert_eq!(doc.header().tag().len(), longest);
        assert_eq!(
            &JsonHeader::from_bytes(&doc.header().to_bytes()).unwrap(),
            doc.header(),
            "the longest tag the field holds round-trips"
        );
        assert!(matches!(sealed(longest + 1), Err(Error::Other(_))));
    }

    mod given_a_walked_row {
        use super::*;

        fn path(text: &str) -> JsonPath {
            JsonPath::parse(text).unwrap()
        }

        fn key(text: &str) -> Label {
            Label::Key(Protected::new(text.to_owned()))
        }

        #[test]
        fn a_childs_selector_bytes_are_its_paths() {
            let parent = path("$.a[3]").protected_selector_bytes();
            for (label, child) in [(key("b"), "$.a[*].b"), (Label::Index(7), "$.a[*][*]")] {
                let bytes = child_selector_bytes(&parent, &label).expect("a child");
                assert_eq!(
                    bytes.risky_ref(),
                    &*path(child).selector_bytes(),
                    "{child}: the parent's bytes and the child's step"
                );
                assert_eq!(
                    bytes.risky_ref().len(),
                    bytes.risky_ref().capacity(),
                    "{child}: sized before it is written"
                );
            }
            assert!(
                child_selector_bytes(&parent, &Label::Root).is_none(),
                "the root is no node's child"
            );
        }

        #[test]
        fn the_last_step_of_a_path_names_the_label_it_reaches() {
            assert!(names(&path("$.a[2]"), &Label::Index(2)), "the position");
            assert!(!names(&path("$.a[2]"), &Label::Index(1)), "another one");
            assert!(!names(&path("$.a[2]"), &key("2")), "a member");
            assert!(names(&path("$.a.b"), &key("b")), "the member");
            assert!(!names(&path("$.a.b"), &key("c")), "another member");
            assert!(!names(&path("$.a.b"), &Label::Index(0)), "not an element");
            assert!(names(&path("$"), &Label::Root), "the root");
            assert!(!names(&path("$"), &key("a")), "only the root");
            assert!(!names(&path("$.a"), &Label::Root), "the root is no member");
        }

        #[test]
        fn a_childs_token_follows_its_label() {
            let (parent, s) = ([1; 16], [2; 16]);
            assert_eq!(
                labelled_token(&parent, &s, &key("k")),
                Some(member_token(&parent, &s))
            );
            assert_eq!(
                labelled_token(&parent, &s, &Label::Index(3)),
                Some(element_token(&parent, &s, 3))
            );
            assert_eq!(
                labelled_token(&parent, &s, &Label::Root),
                None,
                "the root is no child"
            );
            assert_eq!(
                labelled_token(&parent, &s, &Label::Index(u64::from(u32::MAX) + 1)),
                None,
                "no element sits past u32"
            );
        }

        #[test]
        fn selectors_are_the_ones_the_key_derives_and_compare_by_keyset_and_column() {
            let selectors = Selectors::for_tests();
            let at = |text: &str| {
                prf16(
                    &prf(),
                    SELECTOR_DOMAIN,
                    &Context::from_encoded(b"users/profile"),
                    &path(text).selector_bytes(),
                )
                .unwrap()
            };
            assert_eq!(
                selectors
                    .of(path("$.a.b").protected_selector_bytes())
                    .unwrap(),
                at("$.a.b"),
                "a protected input derives what its bytes do"
            );
            assert!(
                selectors == Selectors::for_tests(),
                "same keyset, same column"
            );
            let other_column = Selectors::new(
                Arc::clone(&selectors.keyset),
                Context::from_encoded(b"users/bio").into_owned(),
            );
            assert!(selectors != other_column, "another column");
            let other_keyset = Selectors::new(
                Arc::new(KeysetState {
                    id: Uuid::from_u128(2),
                    name: None,
                    prf: prf(),
                }),
                selectors.context.clone(),
            );
            assert!(selectors != other_keyset, "another keyset");
        }
    }

    /// Seal `value` with its root open, under a fixed key, after `forge`
    /// has had the walked nodes' plaintexts, and open it whole: what a
    /// sealer that wrote a node's plaintext wrongly would leave behind.
    fn seal_forged_and_open(
        value: &Value,
        forge: impl FnOnce(&mut Vec<Protected<Vec<u8>>>),
    ) -> Result<Value, Error> {
        let context = Context::from_encoded(b"users/profile");
        let mut walked = walk(value, &open_root(), &prf(), &context, &mut rng()).unwrap();
        forge(&mut walked.plain);
        let key = stack_kms::DataKeyWithTag {
            key: stack_kms::DataKey {
                iv: [1; 16],
                key: [2; 32],
            },
            tag: vec![3; 8],
            decryption_policy: None,
        };
        let aes = leaf_cipher(&key.key).unwrap();
        let doc = seal(
            walked,
            None,
            Uuid::from_u128(1),
            key,
            &context,
            false,
            SafeRand::from_controlled_seed(Protected::new([5; 32])),
        )
        .unwrap();
        open_whole_chain(doc, &aes, &context, Selectors::for_tests())
    }

    #[test]
    fn a_document_opens_whole_from_its_chain() {
        let value = json!({"a": [1, {"b": null}], "c": "d"});
        assert_eq!(seal_forged_and_open(&value, |_| {}).unwrap(), value);
    }

    /// A container whose plaintext claims more children than it was sealed
    /// over opens (its AAD covers the children the chain found) and is
    /// refused by its child count; no honest sealing writes one.
    #[test]
    fn a_container_claiming_another_child_count_is_refused() {
        let value = json!({"a": [1, 2]});
        let refused = seal_forged_and_open(&value, |plain| {
            // `$.a`, the second node walked: kind, then the child count.
            plain[1] = encode_node(Kind::Array, 3, LabelRef::Key("a"), &json!([]));
        });
        assert!(
            matches!(
                refused,
                Err(Error::JsonWrongEntry {
                    expected: "a container with the children it was sealed over"
                })
            ),
            "{refused:?}"
        );
    }

    /// The whole document opened under another column's PRF context finds
    /// no entry carrying the root's token, and the cipher refuses its first
    /// entry under the column's AAD.
    #[test]
    fn a_document_of_another_column_is_refused_by_the_cipher() {
        let value = json!({"a": 1});
        let context = Context::from_encoded(b"users/profile");
        let walked = walk(&value, &open_root(), &prf(), &context, &mut rng()).unwrap();
        let key = stack_kms::DataKeyWithTag {
            key: stack_kms::DataKey {
                iv: [1; 16],
                key: [2; 32],
            },
            tag: vec![3; 8],
            decryption_policy: None,
        };
        let aes = leaf_cipher(&key.key).unwrap();
        let doc = seal(
            walked,
            None,
            Uuid::from_u128(1),
            key,
            &context,
            false,
            SafeRand::from_controlled_seed(Protected::new([5; 32])),
        )
        .unwrap();
        let other = Context::from_encoded(b"users/bio");
        let selectors = Selectors::new(Arc::clone(&Selectors::for_tests().keyset), other.clone());
        assert!(matches!(
            open_whole_chain(doc, &aes, &other, selectors),
            Err(Error::Aead)
        ));
    }

    #[test]
    fn too_deep_a_document_is_refused() {
        // The innermost scalar of `n` nested arrays sits at depth `n`.
        let nested = |n: usize| {
            let mut value = json!(1);
            for _ in 0..n {
                value = json!([value]);
            }
            value
        };
        assert!(walk(
            &nested(MAX_DEPTH),
            &JsonOptions::default(),
            &prf(),
            &Context::empty(),
            &mut rng()
        )
        .is_ok());
        assert!(matches!(
            walk(
                &nested(MAX_DEPTH + 1),
                &JsonOptions::default(),
                &prf(),
                &Context::empty(),
                &mut rng()
            ),
            Err(TermError::JsonTooDeep)
        ));
    }
}
