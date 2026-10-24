//! The derivations: flattening a document into its terms, sealing the
//! entries under one data key, and opening them again.
//!
//! One walk ([`walk`]) serves both the index's term operation and the
//! sealing operation, so a query derives exactly the selectors a stored
//! document carries. The walk is depth-first, pre-order, siblings in key
//! order for an object and in position order for an array; every entry's
//! ordinal `j` is its place in that order, and the AAD of its ciphertext
//! binds it there.
use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vitaminc_aead::{Cipher, Context, IntoAad, IntoContext, LocalCipherText};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{BlockVisitor, IntoPrfContext, PrfValue};
use vitaminc_protected::{AsProtectedRef, Controlled, Protected};

use super::path::{key_step_len, push_key, JsonPath, Segment, ARRAY_STEP};
use super::plain::{
    insert_member, protected_array, protected_object, push_element, read_protected, take_protected,
    PlainJson,
};
use super::query::{Gate, JsonSelector, JsonSubtreeKey};
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
/// PAE domain of an entry's AAD.
const ENTRY_AAD_DOMAIN: &[u8] = b"stack-encrypt/json/entry/v1";
/// PAE domain of an object member's rank under its parent's token, which
/// orders the members' ordinals. Keyed, so a token does not let its holder
/// test key names.
const RANK_DOMAIN: &[u8] = b"stack-encrypt/json/rank/v1";

/// Deeper than this is refused rather than sealed: the walk recurses, and a
/// document built in memory can nest deeper than any parser admits.
///
/// The bound is what reading the document back needs, not what the walk
/// could manage. A sealed root's plaintext is the document as JSON, which
/// `serde_json` parses with a nesting limit of 128 containers, so a
/// document whose innermost value sits 128 levels down seals and then never
/// opens. Refusing it here moves that failure from the read, where the
/// value is lost, to the write, where the caller still holds it. The bound
/// is the same under either root option, so the option never changes which
/// documents the index accepts.
pub(crate) const MAX_DEPTH: usize = 127;

/// The largest number the index gives an array element's position, a
/// node's ordinal or a node's child count: PostgreSQL's `integer`, which is
/// what the SQL walk casts a position gate's ordinal to and what
/// `json_tree_child_count` returns.
///
/// A document with a wider array or object is refused when it is sealed,
/// and a path naming a position past this is refused when its subtree key
/// is derived. No stored document has a node there, so the refusal loses no
/// answer, and without it the position would reach the server as a gate
/// that PostgreSQL refuses to cast (error 22003) instead of finding nothing.
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
    /// The node's token: every node has one except the sealed root.
    pub(crate) token: Option<Tag>,
    /// The leaf ordering term, on a number or string.
    pub(crate) op: Option<Vec<u8>>,
    pub(crate) parent: Option<usize>,
    /// The node's ordinal under its parent, when the parent has a token.
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
    /// scalar has as an element of a root array, so a containment needle
    /// can match a stored `["a"]` as `jsonb @>` does.
    alt: Option<(Tag, Tag)>,
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

    pub(crate) fn nodes(&self) -> &[TermNode] {
        &self.nodes
    }

    pub(crate) fn alt(&self) -> Option<(Tag, Tag)> {
        self.alt
    }

    /// The last node of the walk: in a needle built from one path, the
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

/// `H("t" ‖ t(parent) ‖ s(child) ‖ LE32(ordinal))`: the token of the child
/// at `ordinal` under a node, whose selector is `selector`. Column-wide like
/// every token (no document salt), so the client derives an array
/// element's token from the path alone, and the server derives every hit's
/// from its parent's and the hit's stored `s` as it walks; no token is ever
/// stored.
///
/// The selector is what keeps an element apart from an object member. An
/// ordinal alone does not: a member's is its rank among its siblings, and
/// rows of one column need not agree on a node's kind, so without it the
/// token of `$.a[0]` would be the token of whichever member of an object
/// `$.a` ranks first, in every row whose `$.a` is an object. An element's
/// selector is the wildcard's and a member's names its key, so the two
/// never share a token.
pub(super) fn child_token(parent: &Tag, selector: &Tag, ordinal: u32) -> Tag {
    h16(&[b"t", parent, selector, &ordinal.to_le_bytes()])
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

/// `PRF(json/rank ‖ column, PAE(t(parent), key))`: what an object's members
/// are ranked by for their ordinals, so an ordinal does not rank key names.
/// Keyed with the index key (the design's decision 11). The chain below a
/// token is public to whoever holds it (the server derives each child's
/// token from its ordinal), so an unkeyed rank would let a token's holder
/// rank guessed key names and compare the order with the selector it finds
/// at each ordinal, in every row. Only the client ranks, when it seals.
fn rank(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    parent: &Tag,
    key: &str,
) -> Result<Tag, TermError> {
    let framed = Context::pae(&[parent, key.as_bytes()]);
    prf16(prf, RANK_DOMAIN, context, framed.as_bytes())
}

/// A number's canonical bytes for its value selector: an integral value,
/// whichever JSON spelling it had, is its `i128`; anything else is its
/// `f64`. So `2` and `2.0` are one value, as `jsonb` compares them, and
/// `-0.0` is `0`.
fn canonical_number(number: &Number) -> Vec<u8> {
    fn int(i: i128) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
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
    let mut out = Vec::with_capacity(9);
    out.push(b'f');
    out.extend_from_slice(&f.to_le_bytes());
    out
}

/// A scalar's canonical bytes; a container contributes nothing beyond its
/// kind's tag.
fn canonical(value: &Value) -> Vec<u8> {
    match value {
        Value::Null | Value::Object(_) | Value::Array(_) => Vec::new(),
        Value::Bool(b) => vec![u8::from(*b)],
        Value::Number(n) => canonical_number(n),
        Value::String(s) => s.as_bytes().to_vec(),
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
    let framed = Context::pae(&[Kind::of(value).tag(), s, &canonical(value)]);
    prf16(prf, VALUE_DOMAIN, context, framed.as_bytes())
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
    nodes: Vec<TermNode>,
    plain: Vec<Protected<Vec<u8>>>,
}

/// Flatten `value` into its terms and its nodes' plaintexts.
fn walk(
    value: &Value,
    options: &JsonOptions,
    prf: &HmacSha256Prf,
    context: &Context<'_>,
) -> Result<Walked, TermError> {
    options.check()?;
    let mut walker = Walker {
        prf,
        context,
        options,
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
        },
        plain: walker.plain,
    })
}

impl Walker<'_> {
    #[allow(clippy::too_many_arguments)]
    fn visit(
        &mut self,
        value: &Value,
        positional: &JsonPath,
        wild: &JsonPath,
        label: LabelRef<'_>,
        parent: Option<usize>,
        parent_token: Option<Tag>,
        ordinal: Option<u32>,
        element: Option<usize>,
        depth: usize,
    ) -> Result<usize, TermError> {
        if depth > MAX_DEPTH {
            return Err(TermError::JsonTooDeep);
        }
        let kind = Kind::of(value);
        let s = prf16(
            self.prf,
            SELECTOR_DOMAIN,
            self.context,
            &wild.selector_bytes(),
        )?;
        let vs = value_selector(self.prf, self.context, &s, value)?;
        let token = match (depth, self.options.sealed_root) {
            (0, true) => None,
            (0, false) | (1, true) => Some(prf16(
                self.prf,
                TOKEN_DOMAIN,
                self.context,
                &positional.token_bytes().unwrap_or_default(),
            )?),
            _ => parent_token
                .zip(ordinal)
                .map(|(p, o)| child_token(&p, &s, o)),
        };
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
                let ordinals: Option<BTreeMap<String, u32>> = token
                    .map(|t| shuffled_ordinals(self.prf, self.context, &t, map))
                    .transpose()?;
                for (key, child) in map {
                    let ordinal = ordinals.as_ref().and_then(|o| o.get(key).copied());
                    let _ = self.visit(
                        child,
                        &positional.then(Segment::Key(key.clone())),
                        &wild.then(Segment::Key(key.clone())),
                        LabelRef::Key(key),
                        Some(index),
                        token,
                        ordinal,
                        child_element,
                        depth + 1,
                    )?;
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    let i = u64::try_from(i).map_err(|_| TermError::JsonTooWide)?;
                    let ordinal = token.map(|_| fit_ordinal(i)).transpose()?;
                    let _ = self.visit(
                        child,
                        &positional.then(Segment::Index(i)),
                        &wild.then(Segment::Wildcard),
                        LabelRef::Index(i),
                        Some(index),
                        token,
                        ordinal,
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

/// An object's members' ordinals: their positions in the order of their
/// ranks under the parent's token, so the ordinals rank nothing a reader
/// without the token can see.
fn shuffled_ordinals(
    prf: &HmacSha256Prf,
    context: &Context<'_>,
    parent: &Tag,
    map: &Map<String, Value>,
) -> Result<BTreeMap<String, u32>, TermError> {
    let mut ranked: Vec<(Tag, &String)> = map
        .keys()
        .map(|k| Ok((rank(prf, context, parent, k)?, k)))
        .collect::<Result<_, TermError>>()?;
    ranked.sort();
    Ok(ranked
        .into_iter()
        .enumerate()
        .map(|(o, (_, key))| (key.clone(), o as u32))
        .collect())
}

// =============================================================================
// Sealing
// =============================================================================

/// The one-way terms of `value` under `context`, as the index's operation
/// derives them: no key is requested.
pub(crate) fn terms_pending<'a, K>(
    value: &Value,
    options: &JsonOptions,
    cipher: &'a KeysetCipher<'_, K>,
    context: NonEmpty<CallerContext>,
) -> Pending<'a, JsonTerms, K> {
    let context = context.into_prf_context().into_owned();
    let terms = walk(value, options, cipher.prf(), &context)
        .map(|w| w.terms)
        .map_err(Error::from);
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
    let prf_context = piece.clone().into_prf_context().into_owned();
    let aad = piece.into_aad().into_owned();
    let walked = match walk(&value, options, cipher.prf(), &prf_context) {
        Ok(walked) => walked,
        Err(error) => return Pending::failed(cipher, error.into()),
    };
    let whole = if options.sealed_root {
        match sealed_root_plaintext(&value) {
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
            seal(walked, whole, keyset_id, key, &aad, sealed_root)
        },
    )
}

/// An entry's AAD: the domain, the keyset, the column's AAD, the key tag,
/// the entry's selector and its ordinal.
fn entry_aad(keyset_id: Uuid, aad: &Context<'_>, tag: &[u8], s: &Tag, j: u64) -> Context<'static> {
    Context::pae(&[
        ENTRY_AAD_DOMAIN,
        keyset_id.as_bytes(),
        aad.as_bytes(),
        tag,
        s,
        &j.to_le_bytes(),
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

fn seal(
    walked: Walked,
    mut whole: Option<Protected<Vec<u8>>>,
    keyset_id: Uuid,
    key: stack_kms::DataKeyWithTag,
    aad: &Context<'_>,
    sealed_root: bool,
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
    let mut entries = Vec::with_capacity(nodes.len());
    for (j, (node, plain)) in nodes.iter().zip(plain).enumerate() {
        // The root's plaintext, the first, is the whole document when the
        // root is sealed (`whole` is taken there, and is `None` after); the
        // node encoding it replaces is wiped as it drops.
        let plaintext = whole.take().unwrap_or(plain);
        let c = cipher
            .seal(
                plaintext,
                &entry_aad(keyset_id, aad, &tag, &node.s, j as u64),
            )
            .map_err(|_| Error::Aead)?;
        let c = c.as_ref().to_vec();
        let parent_token = node.parent.and_then(|p| nodes[p].token);
        let p = parent_token
            .zip(node.ordinal)
            .map(|(parent, o)| parent_tag(&iv, &parent, o));
        entries.push(JsonEntry {
            s: node.s,
            c,
            p,
            op: node.op.clone(),
        });
    }
    let projection = super::query::group_of(nodes, None);
    Ok(JsonDocument::new(
        JsonHeader::new(keyset_id, iv, tag, sealed_root),
        entries,
        projection,
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

/// Open one entry. The plaintext the cipher returns stays in its
/// `Protected` and is wiped when decoding is done.
fn open_entry(
    cipher: &Aes256Cipher,
    header: &JsonHeader,
    aad: &Context<'_>,
    entry: &JsonEntry,
    j: u64,
) -> Result<Opened, Error> {
    let plaintext = cipher
        .open(
            LocalCipherText::from(entry.c.clone()),
            &entry_aad(header.keyset_id, aad, &header.tag, &entry.s, j),
        )
        .map_err(|_| Error::Aead)?;
    decode_node(&plaintext)
}

/// Take a node's label out of it, so the rebuild can consume the node.
fn take_label(mut node: Opened) -> (Label, Opened) {
    (std::mem::replace(&mut node.label, Label::Root), node)
}

/// Rebuild the value of `node`, taking its descendants from `rest`, the
/// pre-order sequence after it. Every child is taken with `next`, so each
/// step consumes an entry and the rebuild ends on any sequence. The value
/// is built under `Protected`: each member and element is moved in from
/// its own, so a rebuild that fails part-way wipes what it had.
///
/// `depth` is `node`'s depth below the rebuild's start. Each entry is
/// authentic, but which entries the server returned, and so how deep the
/// containers it lines up nest, is not: rows that repeat one container, or
/// list only the containers of a wide document, would otherwise recurse as
/// deep as there are rows. Nothing the index seals nests deeper than
/// [`MAX_DEPTH`], so deeper is refused as a shape mismatch.
fn rebuild(
    node: Opened,
    rest: &mut impl Iterator<Item = Opened>,
    depth: usize,
) -> Result<Protected<PlainJson>, Error> {
    if let Some(whole) = node.whole {
        return Ok(whole);
    }
    if depth > MAX_DEPTH {
        return Err(shape("a JSON document no deeper than the index seals"));
    }
    match node.kind {
        Kind::Object => {
            let mut object = protected_object();
            for _ in 0..node.children {
                let (label, member) = take_label(next_child(rest)?);
                let Label::Key(key) = label else {
                    return Err(shape("an object member"));
                };
                let value = rebuild(member, rest, depth + 1)?;
                insert_member(&mut object, key, value);
            }
            Ok(object)
        }
        Kind::Array => {
            let mut array = protected_array(node.children as usize);
            for i in 0..node.children {
                let element = next_child(rest)?;
                if !matches!(element.label, Label::Index(at) if at == u64::from(i)) {
                    return Err(shape("an array element in order"));
                }
                push_element(&mut array, rebuild(element, rest, depth + 1)?);
            }
            Ok(array)
        }
        _ => node.scalar.ok_or_else(|| shape("a JSON scalar")),
    }
}

fn next_child(rest: &mut impl Iterator<Item = Opened>) -> Result<Opened, Error> {
    rest.next().ok_or_else(|| shape("a complete JSON subtree"))
}

/// The value the caller asked for, out of the `Protected` that held it:
/// the one place an opened JSON plaintext is unwrapped.
fn hand_over(value: Protected<PlainJson>) -> Value {
    value.risky_unwrap().into_value()
}

/// The retrieve request for a document's one data key, and the AAD its
/// entries open under.
fn retrieval(
    header: &JsonHeader,
    context: AeadContext,
) -> Result<(Request, Context<'static>), Error> {
    let piece = context.into_context();
    let descriptor = Descriptor::from_piece(&piece);
    descriptor.check()?;
    Ok((
        Request::retrieve_under(header.iv, header.tag.clone(), descriptor, header.keyset_id),
        piece.into_aad().into_owned(),
    ))
}

/// Open the document: one key retrieval, then the sealed root alone, or
/// every entry rebuilt into the value.
fn open_document<'a, K>(
    doc: JsonDocument,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Value, K> {
    let (request, aad) = match retrieval(&doc.header, context) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key)?;
        if doc.header.sealed_root {
            let root = doc
                .entries
                .first()
                .ok_or_else(|| shape("a document with a root entry"))?;
            return open_entry(&aes, &doc.header, &aad, root, 0)?
                .whole
                .map(hand_over)
                .ok_or_else(|| shape("a sealed root"));
        }
        let opened = doc
            .entries
            .iter()
            .enumerate()
            .map(|(j, entry)| open_entry(&aes, &doc.header, &aad, entry, j as u64))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rest = opened.into_iter();
        let root = rest
            .next()
            .ok_or_else(|| shape("a document with a root entry"))?;
        let value = rebuild(root, &mut rest, 0)?;
        if rest.next().is_some() {
            return Err(shape("a document with no entries past its root"));
        }
        Ok(hand_over(value))
    })
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
/// selector. A container node holds no value of its own and is refused
/// with [`Error::OpenedType`]; its subtree opens through [`JsonSubtree`].
impl DecryptInto<Value> for JsonExtracted {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        let (node, selector) = self.into_parts();
        if node.entry.s != selector {
            return Decryption::failed(wrong("the entry at the path asked for"));
        }
        Decryption::from_open(move |cipher| {
            let (request, aad) = match retrieval(&node.header, context) {
                Ok(parts) => parts,
                Err(error) => return Pending::failed(cipher, error),
            };
            Pending::request(cipher, vec![request], move |responses| {
                let key = responses.next_retrieved_key()?;
                let aes = leaf_cipher(&key)?;
                let opened = open_entry(&aes, &node.header, &aad, &node.entry, node.j)?;
                opened
                    .whole
                    .or(opened.scalar)
                    .map(hand_over)
                    .ok_or_else(|| shape("a JSON scalar, or a sealed root"))
            })
        })
    }
}

/// Open the rows of a walk: each complete subtree the rows hold, as a
/// value, in order. What `json_tree_subtree_at` returns is one subtree per
/// node its gates reached, each rooted at depth `0`; what
/// `json_tree_subtree` returns is the children of one node, which
/// [`DecryptInto<Value>`] assembles into that node's value, or this opens
/// into its children's values. The sealed root a walk fell back to opens
/// whole, and the key's path selects over it to the same values the walked
/// rows open to: one per node the path reaches, for a key with gates
/// (`json_tree_subtree_at`); the children of the one node at the path, for
/// a key without (`json_tree_subtree`). An object's members come in an
/// order neither form fixes, and without their keys; open it as a
/// [`Value`] to keep them. Every row is checked against the key first
/// ([`JsonSubtreeKey::open`]); a row that does not fit is
/// [`Error::JsonWrongEntry`].
impl DecryptInto<Vec<Value>> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<Value>, K> {
        Decryption::from_open(move |cipher| {
            if self.is_sealed_root() {
                let below = self.below();
                return open_fallback(self, cipher, context).try_map(move |(path, mut whole)| {
                    // The selected nodes move out of the document's
                    // `Protected` into one of their own, leaving `null`
                    // behind, so their plaintext is never copied; what is
                    // left of the document is wiped when it drops at the
                    // end of this closure.
                    let selected = take_protected(&mut whole, |doc: &mut PlainJson| {
                        let mut found = path.select_mut(doc.value_mut());
                        let selected = if below {
                            match found.as_mut_slice() {
                                [node] => take_children(node),
                                _ => return None,
                            }
                        } else {
                            found.into_iter().map(std::mem::take).collect()
                        };
                        Some(PlainJson::from_value(Value::Array(selected)))
                    })
                    .ok_or_else(|| shape("one node at the walked path"))?;
                    Ok(match hand_over(selected) {
                        Value::Array(items) => items,
                        other => vec![other],
                    })
                });
            }
            open_subtree(self, cipher, context)
                .map(|forest| forest.into_iter().map(|(_, v)| hand_over(v)).collect())
        })
    }
}

/// Open the rows of a walk into the one value they hold. For
/// `json_tree_subtree(doc, token)`, the rows are the descendants of the
/// token's node and the value is that node's: an array when the rows are
/// elements, an object when they are members. For a gated
/// `json_tree_subtree_at`, the rows are the node the gates reached, at
/// depth `0`, and its descendants, and the value is that node's; more than
/// one reached node (a wildcard) is [`Error::OpenedType`], and opens
/// through [`DecryptInto<Vec<Value>>`] instead. No rows is no value
/// ([`Error::OpenedType`]): an empty container and a scalar both have no
/// descendants, and `->` on the node's selector returns the node itself.
/// The sealed root a walk fell back to opens whole, and the key's path
/// ([`JsonSubtreeKey::open`]) selects the one value under it; a path that
/// reaches no node, or more than one, is [`Error::OpenedType`]. Every row
/// is checked against the key first ([`JsonSubtreeKey::open`]); a row that
/// does not fit is [`Error::JsonWrongEntry`].
impl DecryptInto<Value> for JsonSubtree {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Value, K> {
        Decryption::from_open(move |cipher| {
            if self.is_sealed_root() {
                return open_fallback(self, cipher, context).try_map(|(path, mut whole)| {
                    // The one node at the path moves out of the document's
                    // `Protected` into one of its own, leaving `null`
                    // behind, so its plaintext is never copied; what is
                    // left of the document is wiped when it drops at the
                    // end of this closure.
                    let mut reached = 0;
                    let selected = take_protected(&mut whole, |doc: &mut PlainJson| {
                        let mut found = path.select_mut(doc.value_mut());
                        reached = found.len();
                        match found.as_mut_slice() {
                            [node] => Some(PlainJson::from_value(std::mem::take(&mut **node))),
                            _ => None,
                        }
                    });
                    match (selected, reached) {
                        (Some(value), _) => Ok(hand_over(value)),
                        (None, 0) => Err(shape("a node at the walked path")),
                        (None, _) => Err(shape("one node at the walked path")),
                    }
                });
            }
            let below = self.below();
            open_subtree(self, cipher, context).try_map(move |forest| {
                if !below {
                    let mut values: Vec<Protected<PlainJson>> =
                        forest.into_iter().map(|(_, v)| v).collect();
                    return match values.len() {
                        1 => Ok(hand_over(values.remove(0))),
                        _ => Err(shape("one node at the walked path")),
                    };
                }
                let mut members = None;
                let mut elements: Vec<(u64, Protected<PlainJson>)> = Vec::new();
                for (label, value) in forest {
                    match label {
                        Label::Key(key) => {
                            insert_member(members.get_or_insert_with(protected_object), key, value)
                        }
                        Label::Index(i) => elements.push((i, value)),
                        Label::Root => return Err(shape("a subtree below the root")),
                    }
                }
                match (members, elements.is_empty()) {
                    (Some(members), true) => Ok(hand_over(members)),
                    (None, false) => {
                        elements.sort_by_key(|(i, _)| *i);
                        let mut array = protected_array(elements.len());
                        for (_, element) in elements {
                            push_element(&mut array, element);
                        }
                        Ok(hand_over(array))
                    }
                    (None, true) => Err(shape("a node with children")),
                    (Some(_), false) => Err(shape("the children of one node")),
                }
            })
        })
    }
}

/// One row of a walk, opened: the node, and the selector, position and
/// depth the server returned it with. The depth is the server's report and
/// optional on the wire; the rows are placed by their positions and the
/// opened nodes' child counts, and a depth that disagrees with the place
/// a row is put in is refused.
struct Row {
    node: Opened,
    s: Tag,
    j: u64,
    d: Option<u32>,
}

/// Open every row and rebuild each complete subtree, labelled, each still
/// under its `Protected`, checking every row against the key as it goes
/// ([`place`]).
fn open_subtree<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, Vec<(Label, Protected<PlainJson>)>, K> {
    let (mut nodes, key) = subtree.into_parts();
    nodes.sort_by_key(|n| n.j);
    // A walk returns each entry once. Two rows at one ordinal are the
    // server repeating an entry, which would let it line up one container
    // as many times as it likes.
    if nodes.windows(2).any(|pair| pair[0].j == pair[1].j) {
        return Pending::failed(cipher, shape("rows of distinct entries"));
    }
    let Some(first) = nodes.first() else {
        return Pending::ready(cipher, Ok(Vec::new()));
    };
    let header = first.header.clone();
    if nodes.iter().any(|n| n.header != header) {
        return Pending::failed(cipher, shape("rows of one document"));
    }
    let (request, aad) = match retrieval(&header, context) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key_bytes = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key_bytes)?;
        let rows = nodes
            .iter()
            .map(|n| {
                Ok(Row {
                    node: open_entry(&aes, &header, &aad, &n.entry, n.j)?,
                    s: n.entry.s,
                    j: n.j,
                    d: n.depth,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        place(rows, &key)
    })
}

/// Put the opened rows of a walk back into the subtrees they hold, in
/// document order, refusing any row that is not where the key says the
/// walk's rows are ([`Error::JsonWrongEntry`]).
///
/// Each entry opened under its own selector `s` and position `j`, which its
/// ciphertext is bound to, so each is a genuine node of the row; what the
/// check adds is that it is the node the walk asked for. A subtree's rows
/// in a document are its root and then every node beneath it, at
/// consecutive positions, each node's children in order; so the rows are
/// placed one by one, each the next position after the one before, one
/// level below its parent, and carrying the selector of its parent's path
/// extended by its own label, which the key derives from the decrypted
/// label. With gates, each subtree's root is a node the path reaches: the
/// path's selector, at depth `0`, at the position the path names if its
/// last step is one. Without gates, the rows are the children of the
/// path's node and their subtrees, side by side: each child carries the
/// selector of the path extended by its label, at depth `1`, right after
/// the subtree before it.
fn place(
    rows: Vec<Row>,
    key: &JsonSubtreeKey,
) -> Result<Vec<(Label, Protected<PlainJson>)>, Error> {
    let below = key.gates.is_empty();
    let at = Protected::new(key.path.selector_bytes());
    let reached = key.selectors.of(at.clone())?;
    let mut rest = rows.into_iter();
    let mut forest = Vec::new();
    // Without gates, the position the next child of the path's node must
    // have: right after the subtree of the one before.
    let mut next: Option<u64> = None;
    while let Some(top) = rest.next() {
        let (bytes, depth) = if below {
            let bytes = child_selector_bytes(&at, &top.node.label)
                .ok_or_else(|| wrong("a child of the walked node"))?;
            if top.d.is_some_and(|d| d != 1)
                || next.is_some_and(|j| j != top.j)
                || key.selectors.of(bytes.clone())? != top.s
            {
                return Err(wrong("a child of the walked node"));
            }
            (bytes, 1)
        } else {
            if top.d.is_some_and(|d| d != 0)
                || top.s != reached
                || !reaches(&key.path, &top.node.label)
            {
                return Err(wrong("a node the walked path reaches"));
            }
            (at.clone(), 0)
        };
        let mut cursor = top
            .j
            .checked_add(1)
            .ok_or_else(|| wrong("a node of the walk"))?;
        let (label, node) = take_label(top.node);
        let value = rebuild_walked(node, &bytes, depth, &mut rest, &mut cursor, &key.selectors)?;
        next = Some(cursor);
        forest.push((label, value));
    }
    Ok(forest)
}

/// Whether a node with `label` is one `path` reaches by its last step,
/// beyond what the selector says: a position names the element at that
/// position, where the selector reads every position as the wildcard.
fn reaches(path: &JsonPath, label: &Label) -> bool {
    match path.segments().last() {
        Some(Segment::Index(n)) => matches!(label, Label::Index(at) if at == n),
        Some(Segment::Wildcard) => matches!(label, Label::Index(_)),
        Some(Segment::Key(_)) => matches!(label, Label::Key(_)),
        None => matches!(label, Label::Root),
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

/// [`rebuild`] for a walk's rows, checking each child as it is taken:
/// that it is at `cursor`, the position after the row before it; that it
/// is one level below `node`, which sits `d` levels below the walk's start;
/// and that it carries the selector of `node`'s path, whose selector bytes
/// are `bytes`, extended by its own label. A sealed root among the rows is
/// not a node of any walk.
///
/// The rows are consecutive entries of one sealed document, placed by its
/// authenticated child counts, so they nest no deeper than the document
/// does, which is never deeper than [`MAX_DEPTH`]; a document that does is
/// refused as a shape mismatch rather than recursed into.
fn rebuild_walked(
    node: Opened,
    bytes: &Protected<Vec<u8>>,
    d: u32,
    rest: &mut impl Iterator<Item = Row>,
    cursor: &mut u64,
    selectors: &Selectors,
) -> Result<Protected<PlainJson>, Error> {
    if node.whole.is_some() {
        return Err(wrong("a node of the walked subtree"));
    }
    if d as usize > MAX_DEPTH {
        return Err(shape("a JSON document no deeper than the index seals"));
    }
    let child = |rest: &mut dyn Iterator<Item = Row>, cursor: &mut u64| {
        let row = rest
            .next()
            .ok_or_else(|| shape("a complete JSON subtree"))?;
        let child_bytes = child_selector_bytes(bytes, &row.node.label)
            .ok_or_else(|| wrong("the next node of the walked subtree"))?;
        if row.j != *cursor
            || row.d.is_some_and(|got| Some(got) != d.checked_add(1))
            || selectors.of(child_bytes.clone())? != row.s
        {
            return Err(wrong("the next node of the walked subtree"));
        }
        *cursor = cursor
            .checked_add(1)
            .ok_or_else(|| wrong("the next node of the walked subtree"))?;
        Ok::<_, Error>((row.node, child_bytes))
    };
    match node.kind {
        Kind::Object => {
            let mut object = protected_object();
            for _ in 0..node.children {
                let (member, member_bytes) = child(rest, cursor)?;
                let (label, member) = take_label(member);
                let Label::Key(key) = label else {
                    return Err(shape("an object member"));
                };
                let value = rebuild_walked(member, &member_bytes, d + 1, rest, cursor, selectors)?;
                insert_member(&mut object, key, value);
            }
            Ok(object)
        }
        Kind::Array => {
            let mut array = protected_array(node.children as usize);
            for i in 0..node.children {
                let (element, element_bytes) = child(rest, cursor)?;
                if !matches!(element.label, Label::Index(at) if at == u64::from(i)) {
                    return Err(shape("an array element in order"));
                }
                push_element(
                    &mut array,
                    rebuild_walked(element, &element_bytes, d + 1, rest, cursor, selectors)?,
                );
            }
            Ok(array)
        }
        _ => node.scalar.ok_or_else(|| shape("a JSON scalar")),
    }
}

/// The values of a node's children, in the node's order, moved out of it:
/// an array's elements, an object's member values (each leaving `null`
/// under its key, which stays in the document to be wiped with it), and
/// none for a scalar. What a `json_tree_subtree` walk's rows open to as a
/// [`Vec`], taken out of the whole document when the walk fell back to the
/// sealed root.
fn take_children(node: &mut Value) -> Vec<Value> {
    match node {
        Value::Array(items) => std::mem::take(items),
        Value::Object(members) => members.values_mut().map(std::mem::take).collect(),
        _ => Vec::new(),
    }
}

/// Open the sealed root a walk fell back to: the whole document, under its
/// `Protected`, with the path the rows were keyed from, which the caller
/// selects over. The key that built the rows attached the path, so it is
/// always there.
fn open_fallback<'a, K>(
    subtree: JsonSubtree,
    cipher: &'a StackCipher<K>,
    context: AeadContext,
) -> Pending<'a, (JsonPath, Protected<PlainJson>), K> {
    let path = subtree.path().clone();
    let Some(root) = subtree.nodes().first().cloned() else {
        return Pending::failed(cipher, shape("the sealed root"));
    };
    let (request, aad) = match retrieval(&root.header, context) {
        Ok(parts) => parts,
        Err(error) => return Pending::failed(cipher, error),
    };
    Pending::request(cipher, vec![request], move |responses| {
        let key = responses.next_retrieved_key()?;
        let aes = leaf_cipher(&key)?;
        let opened = open_entry(&aes, &root.header, &aad, &root.entry, root.j)?;
        let whole = opened.whole.ok_or_else(|| shape("a sealed root"))?;
        Ok((path, whole))
    })
}

// =============================================================================
// Extraction keys, on the keyset cipher
// =============================================================================

/// The key that walks `path`: the token of the deepest node on it the
/// client can derive, and one gate per step below that.
///
/// A chain head's token is a PRF of its path. An array element's is one
/// hash under its parent's, by its position and the element selector, so
/// the client follows array steps as far as they run from the head. An
/// object member's ordinal is a rank among its siblings' keys, which the
/// client does not know, so from the first key step on the client cannot
/// derive tokens and the server walks instead, through gates: the step's
/// selector for a key or a wildcard (every element's selector is the
/// wildcard's, so a wildcard admits them all), and for an array step the
/// position with the element selector, so a member that happens to sit at
/// that ordinal under an object is not taken for an element.
fn subtree_key_for(
    selectors: Selectors,
    options: &JsonOptions,
    path: &JsonPath,
) -> Result<JsonSubtreeKey, TermError> {
    let prf = &selectors.keyset.prf;
    let context = &selectors.context;
    let segments = path.segments();
    let (head, rest) = if options.sealed_root {
        let Some((first, rest)) = segments.split_first() else {
            return Err(TermError::JsonSealedRoot);
        };
        let head = JsonPath::root().then(first.clone());
        (head, rest)
    } else {
        (JsonPath::root(), segments)
    };
    // A wildcard head names no one node.
    let head_bytes = head.token_bytes().ok_or(TermError::JsonSealedRoot)?;
    let mut token = prf16(prf, TOKEN_DOMAIN, context, &head_bytes)?;
    let mut prefix = head;
    let mut rest = rest.iter();
    let mut gates = Vec::new();
    for segment in rest.by_ref() {
        prefix = prefix.then(segment.clone());
        match segment {
            Segment::Index(index) => {
                let o = fit_ordinal(*index)?;
                let element = prf16(prf, SELECTOR_DOMAIN, context, &prefix.selector_bytes())?;
                token = child_token(&token, &element, o);
            }
            Segment::Key(_) | Segment::Wildcard => {
                gates.push(Gate::Selector(prf16(
                    prf,
                    SELECTOR_DOMAIN,
                    context,
                    &prefix.selector_bytes(),
                )?));
                break;
            }
        }
    }
    for segment in rest {
        prefix = prefix.then(segment.clone());
        gates.push(match segment {
            Segment::Index(index) => Gate::Slot(
                fit_ordinal(*index)?,
                prf16(prf, SELECTOR_DOMAIN, context, &prefix.selector_bytes())?,
            ),
            Segment::Key(_) | Segment::Wildcard => Gate::Selector(prf16(
                prf,
                SELECTOR_DOMAIN,
                context,
                &prefix.selector_bytes(),
            )?),
        });
    }
    Ok(JsonSubtreeKey {
        token,
        gates,
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
        let context = descriptor.into_prf_context().into_owned();
        let selector = prf16(
            self.prf(),
            SELECTOR_DOMAIN,
            &context,
            &path.selector_bytes(),
        )
        .map(JsonSelector)
        .map_err(Error::from);
        Pending::ready(self, selector)
    }

    /// The key that walks the subtree under `path`, under the field
    /// `descriptor` and the index's `options`: the token of the deepest
    /// node on the path the client can derive (a chain head, then array
    /// positions), and one gate per step below it, which the server walks
    /// through. What `json_tree_subtree` and `json_tree_subtree_at` take.
    ///
    /// # Errors
    ///
    /// [`TermError::JsonSealedRoot`] for the root, or for a path whose
    /// first step is a wildcard, under the sealed root: no token exists for
    /// the root, and the document opens whole instead.
    /// [`TermError::JsonTooWide`] for a path naming an array position past
    /// 2³¹ − 1, PostgreSQL's `integer`: no stored document has an element
    /// there.
    pub fn json_subtree_key<'c>(
        &self,
        path: &JsonPath,
        options: &JsonOptions,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, JsonSubtreeKey, K> {
        let context = descriptor.into_prf_context().into_owned();
        let selectors = Selectors::new(Arc::clone(self.state()), context);
        let key = subtree_key_for(selectors, options, path);
        Pending::ready(self, key.map_err(Error::from))
    }
}

#[cfg(test)]
mod tests {
    use super::super::base64;
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

    fn terms(value: &Value, options: &JsonOptions) -> JsonTerms {
        walk(
            value,
            options,
            &prf(),
            &Context::from_encoded(b"users/profile"),
        )
        .unwrap()
        .terms
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
        assert!(t.nodes()[1].token.is_some(), "the terms hold a token");
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
    fn the_sealed_root_has_no_token_and_its_fields_are_heads() {
        let sealed = terms(&json!({"a": {"b": 1}}), &JsonOptions::default());
        assert!(sealed.nodes()[0].token.is_none());
        assert!(sealed.nodes()[1].token.is_some());
        assert!(sealed.nodes()[1].ordinal.is_none(), "a head has no ordinal");
        assert!(sealed.nodes()[2].ordinal.is_some());
        let open = terms(&json!({"a": {"b": 1}}), &open_root());
        assert!(open.nodes()[0].token.is_some());
        assert!(open.nodes()[1].ordinal.is_some());
        // The chain below a head is the same hash chain either way, but
        // the heads differ: one is a PRF of the path, the other a hash
        // under the root's token.
        assert_ne!(sealed.nodes()[1].token, open.nodes()[1].token);
    }

    #[test]
    fn the_subtree_key_derives_what_it_can_and_gates_the_rest() {
        let value = json!({"a": {"b": [1, {"c": 2}]}, "l": [[0], 1]});
        let key = |options: &JsonOptions, path: &str| {
            subtree_key_for(
                Selectors::for_tests(),
                options,
                &JsonPath::parse(path).unwrap(),
            )
        };
        let at = |t: &JsonTerms, path: &str| {
            t.nodes()
                .iter()
                .find(|n| n.positional == JsonPath::parse(path).unwrap())
                .unwrap()
                .clone()
        };
        let options = JsonOptions::default();
        let t = terms(&value, &options);
        // A head's token, and the positions under it, derive exactly.
        for path in ["$.a", "$.l", "$.l[0]", "$.l[0][0]", "$.l[1]"] {
            let k = key(&options, path).unwrap();
            assert_eq!(Some(*k.token_bytes()), at(&t, path).token, "{path}");
            assert!(k.gates().is_empty(), "{path}");
        }
        // The server derives an object member's token the same way, from
        // its parent's, its selector and its ordinal.
        let a = at(&t, "$.a");
        let b = at(&t, "$.a.b");
        assert_eq!(
            b.token,
            Some(child_token(&a.token.unwrap(), &b.s, b.ordinal.unwrap()))
        );
        // The selector is bound: the same parent and ordinal under another
        // selector (an element where the row holds a member) is another
        // token.
        assert_ne!(
            b.token,
            Some(child_token(&a.token.unwrap(), &a.s, b.ordinal.unwrap()))
        );
        // Below a key step, gates: the step's selector, a position, the
        // wildcard's selector (every element's).
        let k = key(&options, "$.a.b[1].c").unwrap();
        assert_eq!(Some(*k.token_bytes()), a.token);
        assert_eq!(
            k.gates(),
            [
                base64(&b.s),
                format!("#1:{}", base64(&at(&t, "$.a.b[1]").s)),
                base64(&at(&t, "$.a.b[1].c").s)
            ]
        );
        let k = key(&options, "$.a.b[*].c").unwrap();
        assert_eq!(
            k.gates(),
            [
                base64(&b.s),
                base64(&at(&t, "$.a.b[0]").s),
                base64(&at(&t, "$.a.b[1].c").s)
            ]
        );
        // Under the sealed root the root has no token; under an open root
        // it has, and `$.a` is then one gate below it.
        assert!(matches!(
            key(&JsonOptions::default(), "$"),
            Err(TermError::JsonSealedRoot)
        ));
        let open = open_root();
        let root = key(&open, "$").unwrap();
        assert!(root.gates().is_empty());
        let a = key(&open, "$.a").unwrap();
        assert_eq!(a.token_bytes(), root.token_bytes());
        assert_eq!(a.gates().len(), 1);
    }

    #[test]
    fn a_position_past_postgres_integer_is_refused_not_sent() {
        let key = |path: &str| {
            subtree_key_for(
                Selectors::for_tests(),
                &JsonOptions::default(),
                &JsonPath::parse(path).unwrap(),
            )
        };
        // The last position PostgreSQL's integer holds reaches the server
        // as a gate it can cast, and finds nothing there.
        let last = key("$.a.b[2147483647]").unwrap();
        assert!(last.gates()[1].starts_with("#2147483647:"));
        // One past it fits u32 but not integer: refused here, as a gate and
        // as a position the client chains itself.
        for path in ["$.a.b[2147483648]", "$.a[2147483648]", "$.a[4294967296]"] {
            assert!(matches!(key(path), Err(TermError::JsonTooWide)), "{path}");
        }
        assert_eq!(fit_ordinal(i32::MAX.unsigned_abs()).unwrap(), 2_147_483_647);
        assert!(matches!(
            fit_ordinal(2_147_483_648_u64),
            Err(TermError::JsonTooWide)
        ));
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

    #[test]
    fn object_ordinals_are_a_permutation_that_does_not_rank_keys() {
        let map: Map<String, Value> = ["a", "b", "c", "d"]
            .iter()
            .map(|k| (k.to_string(), json!(1)))
            .collect();
        let context = Context::from_encoded(b"users/profile");
        let ordinals = shuffled_ordinals(&prf(), &context, &[1; 16], &map).unwrap();
        let mut seen: Vec<u32> = ordinals.values().copied().collect();
        seen.sort_unstable();
        assert_eq!(seen, [0, 1, 2, 3]);
        let other = shuffled_ordinals(&prf(), &context, &[2; 16], &map).unwrap();
        assert_ne!(
            ordinals, other,
            "a different token shuffles differently (with overwhelming probability)"
        );
    }

    /// A token's holder cannot rank guessed key names: an object member's
    /// rank is keyed with the index key, so the same parent token and key
    /// give unrelated bytes under another key.
    #[test]
    fn the_rank_is_keyed() {
        let context = Context::from_encoded(b"users/profile");
        let other = HmacSha256Prf::new(Protected::new([8; 32]));
        let parent = [5; 16];
        let rank_under = |prf: &HmacSha256Prf| rank(prf, &context, &parent, "a").unwrap();
        assert_eq!(rank_under(&prf()), rank_under(&prf()), "deterministic");
        assert_ne!(rank_under(&prf()), rank_under(&other), "keyed");
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
            let walked = walk(&value, &JsonOptions::default(), &prf(), &context).unwrap();
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
            let parent = Protected::new(path("$.a[3]").selector_bytes());
            for (label, child) in [(key("b"), "$.a[*].b"), (Label::Index(7), "$.a[*][*]")] {
                let bytes = child_selector_bytes(&parent, &label).expect("a child");
                assert_eq!(
                    bytes.risky_ref(),
                    &path(child).selector_bytes(),
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
            assert!(reaches(&path("$.a[2]"), &Label::Index(2)), "the position");
            assert!(!reaches(&path("$.a[2]"), &Label::Index(1)), "another one");
            assert!(!reaches(&path("$.a[2]"), &key("2")), "a member");
            assert!(reaches(&path("$.a[*]"), &Label::Index(9)), "any element");
            assert!(!reaches(&path("$.a[*]"), &key("x")), "not a member");
            assert!(reaches(&path("$.a.b"), &key("b")), "a member");
            assert!(!reaches(&path("$.a.b"), &Label::Index(0)), "not an element");
            assert!(reaches(&path("$"), &Label::Root), "the root");
            assert!(!reaches(&path("$"), &key("a")), "only the root");
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
                    .of(Protected::new(path("$.a.b").selector_bytes()))
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
            &Context::empty()
        )
        .is_ok());
        assert!(matches!(
            walk(
                &nested(MAX_DEPTH + 1),
                &JsonOptions::default(),
                &prf(),
                &Context::empty()
            ),
            Err(TermError::JsonTooDeep)
        ));
    }
}
