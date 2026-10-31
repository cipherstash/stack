//! The JSON index: a document stored as one searchable value, with
//! node-local ciphertexts, a token chain and exact containment.
//!
//! `docs/plans/2026-10-17-json-tree-index.md` is the design
//! this module implements, and the authority on why. In short, a document
//! is flattened into one entry per node. Each entry carries:
//!
//! - a **selector** `s`, a PRF of the node's path with every array position
//!   folded into the wildcard, so every element of an array shares one;
//! - the node's own **ciphertext** `c`, sealed under one ZeroKMS data key
//!   per document: the node's label, its kind and, for a scalar, its
//!   value, and for a container its child count. Nothing beneath a node is
//!   encrypted in that node's entry, so a document's ciphertext is linear
//!   in its size;
//! - the **self tag** `x`, the first eight bytes of `H("x" ‖ iv ‖ t)`,
//!   `t` being the node's own **token**, on every entry: how the server
//!   finds the node a client-derived token names. Every token derives from
//!   its node's path alone: the root's (and, under the sealed root, each
//!   top-level field's) is a PRF of its path, an object member's is
//!   `H16("t" ‖ t(parent) ‖ s(member))` and an array element's
//!   `H16("t" ‖ t(array) ‖ s(element) ‖ LE32(i))`, `i` its index. So the
//!   client sends exactly the tokens of the nodes it reads;
//! - the **parent tag** `p`, the first eight bytes of
//!   `H("p" ‖ iv ‖ t(parent) ‖ LE32(o))`, below the chain's heads, which
//!   lets the server enumerate the subtree under a node from its token and
//!   nothing else: the ordinals `o` under a node are dense from zero (an
//!   element's is its index, an object's members' a random permutation
//!   drawn when the document is sealed), so the server probes them in turn
//!   until the first miss.
//!   Nothing stored says whether a hit is a member or an element, so the
//!   server derives the member rule's token for it, keeps it if the hit's
//!   self tag is that token's, and otherwise tries the element rule's;
//! - a leaf ordering term `op` on the number and string leaves at the
//!   paths the index declares ordered ([`JsonOptions::ordered`]), the
//!   same OPE term the scalar [`Ope`](crate::target::Ope) index derives,
//!   keyed by the column. No path is ordered by default.
//!
//! Beside the entries the document stores its **selector set** `q` (the
//! design's containment projection, [`JsonSelectorSet`]): one `(s, vs)`
//! pair per node, `vs` being a PRF of the node's kind and, for a scalar,
//! its canonical value, bound to `s`, nested by array element so that
//! PostgreSQL's own `jsonb @>` over two sets is exact containment. The
//! value selectors live there and nowhere else.
//!
//! By default the root is **sealed** ([`JsonOptions::sealed_root`]): the root
//! entry's ciphertext is the whole document and the top-level fields are
//! the heads of the chain, chained from nothing, so the root's token finds
//! the root entry and nothing beneath it, and no query can hand the server
//! a token that unlocks the shape of every row in the column.
//!
//! # What the types are
//!
//! [`Json`](struct@crate::target::Json) is the index, an [`Index<Value>`](crate::target::Index)
//! whose term is a [`JsonTerms`]: the one-way terms of a document (its
//! selectors, tokens and grouping), which a query is built from. Sealing is
//! a separate operation, [`json_document`](crate::target::json_document),
//! whose output is the stored [`JsonDocument`]; `JsonDocument` is itself an
//! [`EncryptFrom<Value>`](crate::EncryptFrom) target, so a plan or a record
//! names it by type. The query terms are [`JsonQuery`] (containment and
//! `AtPath<Eq>`), [`JsonLeafQuery`] (ordering at a path), and the two
//! extraction keys a caller derives through the keyset cipher,
//! [`JsonSelector`] and [`JsonSubtreeKey`]. What the server returns for an
//! extraction is [`JsonNode`] rows, which open only through what the
//! client derived for the read: [`JsonSelector::open`] for the one entry
//! `->` returns ([`JsonExtracted`]), [`JsonSubtreeKey::open`] for the rows
//! of a walk ([`JsonSubtree`]). Each checks that the rows are the ones the
//! read asked for. Every entry's AAD binds its selector, the slot it is
//! stored at and the digest of its children's AEAD tags (the cascade), so
//! the rows beneath the node a read names open only as they were sealed;
//! the node itself is checked against the path the client derived, since
//! nothing above it is read. The entries are stored in a random order, root
//! first, and no check reads a slot as a position in the document.
//!
//! # Where this deviates from the design
//!
//! Two deliberate deviations, recorded here so the plan can be read against
//! the code:
//!
//! - **Nonces are random, not derived.** The design derives each entry's
//!   AES-GCM nonce from its selector and ordinal. This module seals every
//!   entry through the engine's one AEAD path (`vitaminc-encrypt`'s
//!   `Aes256Cipher`, a fresh random 96-bit nonce per seal, carried in the
//!   ciphertext), so there is one leaf cipher in the crate and no second
//!   AES-GCM call site. Uniqueness under one document key is probabilistic
//!   rather than structural: at `N` entries the collision probability is
//!   `N² / 2^97`, negligible for any document. The AAD still binds the
//!   entry to its slot, and its parent's AAD to its tag, so a moved or
//!   reordered entry fails to open as the design requires. The cost is
//!   twelve bytes per entry.
//! - **Tokens chain by selector, and nothing stores a token.** The design
//!   wraps each child's label-derived token under its parent's (`w`) and
//!   stores the ordinal (`o`) so the server can find and unmask it. Here a
//!   child's token is a hash of its parent's token and its own selector,
//!   with its index for an array element, so the client derives any node's
//!   token from the path and the server derives each child's as it walks,
//!   and both fields go. The ordinals under a node are dense from zero, so
//!   the walk needs no fan-out bound either: it probes until the first
//!   miss. A wildcard names no one node, so the client expands it into
//!   concrete paths up to a bound, with a probe past it
//!   ([`JsonSubtreeKey`]).
//!
//! # Byte encodings
//!
//! The document's wire form is JSON, as the EQL domain stores it. Every
//! field the SQL compares, derives or decodes is standard base64 with
//! padding, which is what PostgreSQL's `encode(x, 'base64')` writes and
//! `decode(x, 'base64')` reads: the selectors `s` and the pairs of `q`
//! (sixteen bytes, 24 characters), the self tag `x` and the parent tag `p`
//! (eight bytes, 12 characters each), the ordering term `op`, the tokens a
//! read takes, and the header `h`, which the SQL reads the `iv` and the
//! sealed-root flag from. The ciphertext `c`, which nothing in SQL
//! decodes, is RFC 1924 base85 (`base85-simd`): five characters per four
//! bytes against base64's eight per six, on the one field that is most of
//! a document. The alphabet has no `"` or `\`, so a JSON string carries it
//! unescaped. The header's bytes are a frozen layout, [`JsonHeader`]. The
//! derivations are versioned by their PAE domain labels, as every other
//! term kind's are ([`sem`](crate::sem)): a change to any of them is a new
//! version, never an edit in place.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vitaminc_protected::OpaqueDebug;

use crate::target::{DecryptField, DecryptInto, Decryptable, Decryption};

mod cascade;
mod derive;
mod path;
mod plain;
mod query;
mod shuffle;
mod text;

pub use derive::JsonTerms;
pub use path::{JsonPath, JsonPathError, Segment};
pub use query::{
    AtPathTerms, JsonLeafQuery, JsonQuery, JsonSelector, JsonSelectorSet, JsonSubtreeKey,
};
pub use text::{parse_text, to_text, JsonTextError};

/// Wipe a JSON value's plaintext in place: every string (object keys too)
/// is overwritten, every number set to zero and every boolean to `false`,
/// and the containers emptied. For a binding that holds a document it
/// parsed ([`parse_text`]) or opened, once it is done with it: a
/// `serde_json::Value` has no `Zeroize` of its own. Numbers and booleans
/// are overwritten best-effort, as [`Zeroize`](zeroize::Zeroize) on the
/// engine's own JSON plaintext does.
pub fn wipe_value(value: &mut serde_json::Value) {
    plain::wipe(value);
}

/// The deepest a document nests: the data plan refuses a path with more
/// steps, which names no node.
#[cfg(feature = "dynamic")]
pub(crate) use derive::MAX_DEPTH;
pub(crate) use derive::{seal_pending, terms_pending};
pub(crate) use plain::PlainJson;
pub(crate) use shuffle::Randomness;

/// A sixteen-byte tag: a selector or a token.
pub type Tag = [u8; 16];

/// An eight-byte parent tag: the first eight bytes of the parent-tag hash.
/// [`SelfTag`] has the same width for the same reason.
/// A parent tag is a lookup key for the server's walk and nothing else (an
/// entry's AAD binds its selector and ordinal, not its parent tag), so it
/// needs only to be distinct among the entries of one document; eight
/// bytes put a collision in a document of ten thousand nodes below one in
/// 10^11, and save eight bytes an entry over the full hash.
pub type ParentTag = [u8; 8];

/// An eight-byte self tag: the first eight bytes of `H("x" ‖ iv ‖ t)`, `t`
/// being the entry's own token. A lookup key for the server, by which it
/// finds the node a token names; like the parent tag, it is not bound by
/// the entry's AAD and needs only to be distinct among the entries of one
/// document.
pub type SelfTag = [u8; 8];

/// How a JSON index lays a document out, and which of its leaves it
/// orders. Part of the index's identity: a stored document and the query
/// probing it must agree on it, so it rides in the data plan beside the
/// index. The layout is recorded in every document's header; the ordered
/// paths are not, since a stored leaf shows whether it carries a term.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JsonOptions {
    /// Seal the root: the root entry's ciphertext is the whole document and
    /// the top-level fields are the heads of the token chain, so no token
    /// for the root exists and no query can hand the server one. On by
    /// default. Off, the chain starts at the root and a query may walk the
    /// whole document from the root's token.
    pub sealed_root: bool,
    /// The paths whose number and string leaves carry an ordering term
    /// `op`, and so answer `op::AtPath(op::Lt)` and the other orderings.
    /// None by default: an ordering term reveals the order of the leaf
    /// across every row that holds one, and costs about eighty bytes a
    /// leaf, so a path pays for it only when asked. A wildcard step covers
    /// every element of the array (`$.orders[*].total`). A position
    /// (`$.scores[2]`) is refused, here and in an ordering query
    /// ([`TermError::JsonOrderingAtPosition`](crate::sem::TermError::JsonOrderingAtPosition)):
    /// an ordering compares the leaf `->` extracts by the path's selector,
    /// which reads every position as the wildcard, so it reaches an
    /// unspecified element at the path (entries are stored in a random
    /// order) and never the one a position names. An ordering asked at a
    /// path no entry here covers is refused
    /// ([`TermError::JsonPathNotOrdered`](crate::sem::TermError::JsonPathNotOrdered)).
    pub ordered: BTreeSet<JsonPath>,
}

impl JsonOptions {
    /// The defaults: the root sealed, no leaf ordered.
    pub const fn new() -> Self {
        Self {
            sealed_root: true,
            ordered: BTreeSet::new(),
        }
    }

    /// These options with the leaves at `paths` ordered, each path parsed
    /// as [`JsonPath::parse`] does.
    ///
    /// # Errors
    ///
    /// [`TermError::JsonPath`](crate::sem::TermError::JsonPath) for a path
    /// that is not one, and
    /// [`TermError::JsonOrderingAtPosition`](crate::sem::TermError::JsonOrderingAtPosition)
    /// for a path that names an array position, which no ordering can
    /// reach (see [`ordered`](Self::ordered)).
    pub fn ordering<I>(mut self, paths: I) -> Result<Self, crate::sem::TermError>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        for path in paths {
            let path = JsonPath::parse(path.as_ref())?;
            if path.names_a_position() {
                return Err(crate::sem::TermError::JsonOrderingAtPosition);
            }
            let _ = self.ordered.insert(path);
        }
        Ok(self)
    }

    /// Refuse options whose ordered paths name a position, which the
    /// field admits but [`ordering`](Self::ordering) does not: sealing
    /// under them would put a term no ordering can reach on the leaf.
    pub(crate) fn check(&self) -> Result<(), crate::sem::TermError> {
        if self.ordered.iter().any(JsonPath::names_a_position) {
            Err(crate::sem::TermError::JsonOrderingAtPosition)
        } else {
            Ok(())
        }
    }

    /// Whether the leaf at `path` carries an ordering term: some ordered
    /// path [covers](JsonPath::covers) it.
    pub fn orders(&self, path: &JsonPath) -> bool {
        self.ordered.iter().any(|ordered| ordered.covers(path))
    }
}

impl Default for JsonOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// The document's key header, stored once in `h`: what retrieving the
/// document's data key needs, and which shape the root has.
///
/// # Frozen byte encoding
///
/// | offset | field | size | value |
/// |---|---|---|---|
/// | 0 | header version | 1 | [`FORMAT_VERSION`](Self::FORMAT_VERSION) (`0x01`) |
/// | 1 | flags | 1 | bit 0: the root is sealed |
/// | 2 | epoch | 4 | `u32` little-endian; reserved, always `0` |
/// | 6 | keyset id | 16 | the keyset the data key was minted under, raw UUID bytes |
/// | 22 | ZeroKMS `iv` | 16 | identifies the data key for retrieval; also the per-document salt of the chain tags |
/// | 38 | `tag_len` | 2 | `u16` little-endian |
/// | 40 | ZeroKMS key `tag` | `tag_len` | required to retrieve the key |
///
/// The SQL reads the `iv` at offset 22 to compute parent tags, and the
/// flags at offset 1 to know whether a walk may fall back to the sealed
/// root; it parses nothing else. The epoch is reserved for bounding a revealed token
/// in time (the design's "Epochs"); writing it now keeps that a new value
/// rather than a new layout.
///
/// `Debug` ([`OpaqueDebug`]) prints the keyset and the layout, which say
/// what a header is for, and masks the ZeroKMS `iv` and `tag`, which
/// retrieve the data key.
#[derive(Clone, PartialEq, Eq, OpaqueDebug)]
pub struct JsonHeader {
    #[non_sensitive]
    keyset_id: Uuid,
    iv: stack_kms::Iv,
    tag: Vec<u8>,
    #[non_sensitive]
    sealed_root: bool,
    #[non_sensitive]
    epoch: u32,
}

/// The [`JsonHeader`] bytes are not the frozen layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum JsonHeaderError {
    /// The leading version byte is not one this build parses.
    #[error("unknown JSON header version {0}")]
    #[diagnostic(code(stack_encrypt::json_header_version))]
    UnknownVersion(u8),
    /// The bytes end before the fixed fields, or before the tag promised.
    #[error("JSON header bytes are truncated")]
    #[diagnostic(code(stack_encrypt::json_header_truncated))]
    Truncated,
}

impl JsonHeader {
    /// The version byte of the frozen layout.
    pub const FORMAT_VERSION: u8 = 1;
    const FLAG_SEALED_ROOT: u8 = 0b1;
    const FIXED_LEN: usize = 1 + 1 + 4 + 16 + 16 + 2;

    /// The keyset the document's data key was minted under.
    pub fn keyset_id(&self) -> Uuid {
        self.keyset_id
    }

    /// The ZeroKMS IV of the document's data key: its identifier, and the
    /// per-document salt of every chain tag.
    pub fn iv(&self) -> &stack_kms::Iv {
        &self.iv
    }

    /// The ZeroKMS key tag.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Whether the root is sealed: see [`JsonOptions::sealed_root`].
    pub fn sealed_root(&self) -> bool {
        self.sealed_root
    }

    /// The frozen byte layout; see the type docs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED_LEN + self.tag.len());
        out.push(Self::FORMAT_VERSION);
        out.push(if self.sealed_root {
            Self::FLAG_SEALED_ROOT
        } else {
            0
        });
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(self.keyset_id.as_bytes());
        out.extend_from_slice(&self.iv);
        // `seal_pending` refuses a tag longer than the field, so the
        // saturation is unreachable; it is a bound, not a case.
        out.extend_from_slice(
            &u16::try_from(self.tag.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&self.tag);
        out
    }

    /// Parse the frozen byte layout. Structural only: nothing here is
    /// trusted until an entry opens under the key it names.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JsonHeaderError> {
        let (&version, rest) = bytes.split_first().ok_or(JsonHeaderError::Truncated)?;
        if version != Self::FORMAT_VERSION {
            return Err(JsonHeaderError::UnknownVersion(version));
        }
        if rest.len() < Self::FIXED_LEN - 1 {
            return Err(JsonHeaderError::Truncated);
        }
        let (flags, rest) = rest.split_at(1);
        let (epoch, rest) = rest.split_at(4);
        let (keyset, rest) = rest.split_at(16);
        let (iv, rest) = rest.split_at(16);
        let (tag_len, rest) = rest.split_at(2);
        let tag_len = usize::from(u16::from_le_bytes([tag_len[0], tag_len[1]]));
        if rest.len() < tag_len {
            return Err(JsonHeaderError::Truncated);
        }
        let mut iv_bytes: stack_kms::Iv = [0; 16];
        iv_bytes.copy_from_slice(iv);
        Ok(Self {
            keyset_id: Uuid::from_slice(keyset).map_err(|_| JsonHeaderError::Truncated)?,
            iv: iv_bytes,
            tag: rest[..tag_len].to_vec(),
            sealed_root: flags[0] & Self::FLAG_SEALED_ROOT != 0,
            epoch: u32::from_le_bytes([epoch[0], epoch[1], epoch[2], epoch[3]]),
        })
    }

    pub(crate) fn new(keyset_id: Uuid, iv: stack_kms::Iv, tag: Vec<u8>, sealed_root: bool) -> Self {
        Self {
            keyset_id,
            iv,
            tag,
            sealed_root,
            epoch: 0,
        }
    }
}

/// One entry of a stored document: one JSON node.
///
/// `s`, `c` and `x` are always present. `p` is present on a node that
/// chains from its parent (everything below the chain's heads); `op` on a
/// number or string leaf at a path the index orders
/// ([`JsonOptions::ordered`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonEntry {
    s: Tag,
    c: Vec<u8>,
    x: SelfTag,
    p: Option<ParentTag>,
    op: Option<Vec<u8>>,
}

impl JsonEntry {
    /// The path selector.
    pub fn selector(&self) -> &Tag {
        &self.s
    }
    /// The node's ciphertext, as sealed.
    pub fn ciphertext(&self) -> &[u8] {
        &self.c
    }
    /// The self tag, on every entry.
    pub fn self_tag(&self) -> &SelfTag {
        &self.x
    }
    /// The parent tag, when the node chains from its parent.
    pub fn parent_tag(&self) -> Option<&ParentTag> {
        self.p.as_ref()
    }
    /// The leaf ordering term, on a number or string leaf at an ordered
    /// path.
    pub fn ordering_term(&self) -> Option<&[u8]> {
        self.op.as_deref()
    }
}

/// A stored JSON document: its [`JsonHeader`] and its entries, one per
/// node, in a random order drawn for the document when it was sealed, with
/// the root first. What
/// [`json_document`](crate::target::json_document) produces and
/// [`DecryptInto<Value>`](crate::DecryptInto) opens.
///
/// Serializes to the wire form the EQL domain stores: `{"h": "…", "sv":
/// [{"s": "…", "c": "…", …}, …], "q": {"sv": [{"s", "vs"}, …], "el":
/// […]}}`, where `q` is the document's [selector set](Self::selector_set);
/// see the [module docs](self#byte-encodings).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "DocumentWire", into = "DocumentWire")]
pub struct JsonDocument {
    header: JsonHeader,
    entries: Vec<JsonEntry>,
    selectors: JsonSelectorSet,
}

impl JsonDocument {
    /// The document's header.
    pub fn header(&self) -> &JsonHeader {
        &self.header
    }

    /// The entries, in their stored order: the root first, the rest in a
    /// uniformly random order drawn when the document was sealed, which says
    /// nothing of the tree. A node's children are found by the chain
    /// ([`children`](Self::children)), not by position.
    pub fn entries(&self) -> &[JsonEntry] {
        &self.entries
    }

    /// The document's selector set: what a [`JsonQuery`] is matched
    /// against, stored as `q`. Computed from the plaintext when the
    /// document is sealed and read back as stored: like every search field
    /// it is unauthenticated (only `c` is), and a tampered `q` changes
    /// which rows a containment query returns and nothing else.
    pub fn selector_set(&self) -> &JsonSelectorSet {
        &self.selectors
    }

    /// The entry whose self tag is `token`'s, as the server finds the node
    /// a token names: its ordinal and the entry. `None` for a token that
    /// names no node of this document.
    ///
    /// Where several entries carry the tag, which no sealing produces, the
    /// last of them, as the server's index keeps it
    /// (`eql_v4_internal.json_tree_index` builds it with
    /// `jsonb_object_agg`, which keeps the last value of a repeated key).
    pub fn find(&self, token: &Tag) -> Option<(usize, &JsonEntry)> {
        let x = derive::self_tag(&self.header.iv, token);
        self.entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, e)| e.x == x)
    }

    /// The children of the node whose token is `token`, as the server
    /// enumerates them: the entries at the ordinals `0, 1, 2, …` under it,
    /// probed until the first miss, each with the token the server derives
    /// for it, by the member rule or the element rule, whichever the entry's
    /// self tag matches, and `None` when it matches neither. A token that
    /// names no node yields nothing.
    ///
    /// What `json_tree_children(doc, token)` returns; one level of the
    /// walk [`subtree`](Self::subtree) runs to the bottom.
    pub fn children(&self, token: &Tag) -> Vec<(usize, &JsonEntry, Option<Tag>)> {
        let iv = &self.header.iv;
        let mut out = Vec::new();
        if self.find(token).is_none() {
            return out;
        }
        // A node has at most as many children as the document has entries,
        // so the probe loop is bounded whatever the entries say.
        let most = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        for o in 0..most {
            let tag = derive::parent_tag(iv, token, o);
            // The last entry carrying the tag, as the server's index keeps
            // it ([`find`](Self::find)).
            let Some((j, entry)) = self
                .entries
                .iter()
                .enumerate()
                .rev()
                .find(|(_, e)| e.p.as_ref() == Some(&tag))
            else {
                break;
            };
            out.push((j, entry, derive::hit_token(iv, token, entry, o)));
        }
        out
    }

    /// The rows the server's read returns for `tokens` with no budget:
    /// for each token in order, the node it names at depth `0` and every
    /// entry beneath it with its depth below that node, each node followed
    /// by its children in ordinal order. (The SQL returns the rows of a
    /// token by slot instead, which the client does not rely on.)
    /// A token that names no node yields nothing. What
    /// `json_tree_subtree(doc, tokens, 0)` returns.
    ///
    /// A stored document is untrusted, and its tags need not form a tree:
    /// whoever holds a token can write a chain deeper than any document the
    /// index seals, or a cycle. Each token's walk stops descending below the
    /// deepest level a sealed document has, and stops once it has returned
    /// as many entries as the document holds, which a tree never exceeds,
    /// so it ends, and in bounded stack, on any document.
    pub fn subtree(&self, tokens: &[Tag]) -> Vec<(usize, &JsonEntry, u32)> {
        let mut out = Vec::new();
        for token in tokens {
            let Some((j, entry)) = self.find(token) else {
                continue;
            };
            let mut rows = vec![(j, entry, 0)];
            self.walk(token, 1, &mut rows);
            out.extend(rows);
        }
        out
    }

    fn walk<'a>(&'a self, token: &Tag, depth: u32, out: &mut Vec<(usize, &'a JsonEntry, u32)>) {
        // A walk finds each entry at most once, so a document whose tags do
        // not form a tree (which no sealing produces) ends the walk once it
        // has returned as many entries as the document holds, instead of
        // looping; and no sealed document nests deeper than MAX_DEPTH, so a
        // chain of tags longer than that stops there, in bounded stack.
        if out.len() >= self.entries.len() || depth as usize > derive::MAX_DEPTH {
            return;
        }
        for (j, entry, child) in self.children(token) {
            if out.len() >= self.entries.len() {
                return;
            }
            out.push((j, entry, depth));
            if let Some(child) = child {
                self.walk(&child, depth + 1, out);
            }
        }
    }

    /// The node stored at `slot` as an extraction returns it: the entry
    /// with the header beside it. A scalar or an empty container opens on
    /// its own; a container with children opens only with its subtree.
    pub fn node(&self, slot: usize) -> Option<JsonNode> {
        self.entries.get(slot).map(|entry| JsonNode {
            entry: entry.clone(),
            header: self.header.clone(),
            slot: slot as u64,
            depth: None,
        })
    }

    pub(crate) fn new(
        header: JsonHeader,
        entries: Vec<JsonEntry>,
        selectors: JsonSelectorSet,
    ) -> Self {
        Self {
            header,
            entries,
            selectors,
        }
    }
}

impl Decryptable for JsonDocument {
    const DECRYPTABLE: bool = true;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for JsonDocument
where
    Self: crate::DecryptInto<P>,
    Ctx: Into<<Self as crate::DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// One entry as an extraction returns it: the entry, the document's header
/// grafted beside it, and the slot the entry is stored at in the document
/// (`j` on the wire), which its ciphertext is bound to. What `->` and the
/// walk return per row.
///
/// A row is the database's word, so it does not open on its own: the
/// selector the client derived opens the entry `->` returned
/// ([`JsonSelector::open`]), and the key that keyed a walk opens its rows
/// ([`JsonSubtreeKey::open`]), each after checking the rows are the ones
/// it asked for.
///
/// Deserializes from the entry's wire fields plus `h` and `j`, and tolerates
/// the envelope fields the SQL grafts beside them (`i`, `v`, `d`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NodeWire", into = "NodeWire")]
pub struct JsonNode {
    entry: JsonEntry,
    header: JsonHeader,
    slot: u64,
    depth: Option<u32>,
}

impl JsonNode {
    /// The entry.
    pub fn entry(&self) -> &JsonEntry {
        &self.entry
    }
    /// The document's header.
    pub fn header(&self) -> &JsonHeader {
        &self.header
    }
    /// The slot the entry is stored at in the document, `j` on the wire.
    /// The stored order is random, so it is not the node's place in the
    /// document.
    pub fn slot(&self) -> u64 {
        self.slot
    }
    /// The entry's depth below the walk's start, when the walk reported one.
    pub fn depth(&self) -> Option<u32> {
        self.depth
    }
}

/// The entry `->` returned, with the selector the client asked for: what
/// [`DecryptInto<Value>`](crate::DecryptInto) opens to the node's scalar,
/// or to the whole document for a sealed root asked for at `$`. Built only
/// by [`JsonSelector::open`], so it always carries the selector the entry
/// is checked against; an entry carrying another is refused with
/// [`Error::JsonWrongEntry`](crate::Error::JsonWrongEntry) before any key
/// is retrieved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonExtracted {
    node: JsonNode,
    selector: Tag,
}

impl JsonExtracted {
    pub(crate) fn keyed(node: JsonNode, selector: Tag) -> Self {
        Self { node, selector }
    }

    /// The row, as the database returned it.
    pub fn node(&self) -> &JsonNode {
        &self.node
    }

    /// The selector the read asked for.
    pub fn selector(&self) -> JsonSelector {
        JsonSelector(self.selector)
    }

    pub(crate) fn into_parts(self) -> (JsonNode, Tag) {
        (self.node, self.selector)
    }
}

impl Decryptable for JsonExtracted {
    const DECRYPTABLE: bool = true;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for JsonExtracted
where
    Self: crate::DecryptInto<P>,
    Ctx: Into<<Self as crate::DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// The entries the server returned for one subtree read, ready to open:
/// what `json_tree_subtree(doc, key.tokens(), budget)` yields, collected,
/// and what [`DecryptInto<Value>`](crate::DecryptInto),
/// `DecryptInto<Option<Value>>` and `DecryptInto<Vec<Value>>` open into the
/// value at the read's path. Built only by the key that keyed the read
/// ([`JsonSubtreeKey::open`]), so it always carries the key, and what
/// checks every row against it when the rows are opened (see
/// [`JsonSubtreeKey::open`] for the checks).
///
/// The rows are, for each token of the key that names a node, the node at
/// depth `0` and everything beneath it, so the four answers `jsonb #>`
/// gives are four answers here: an empty object's entry, an empty array's
/// entry, a scalar's entry, and no rows for a node the row does not have.
///
/// Past its budget, a read of a document with a sealed root returns the
/// root entry alone, at depth `0`, instead of rows it would be cheaper to
/// open whole: the client opens the document and evaluates the key's
/// concrete paths and probes over it, to the same values the walked rows
/// open to, a probe that finds an element included. A read of `$` under
/// the sealed root is answered with the same one row, the root, which
/// opens to the whole document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonSubtree {
    nodes: Vec<JsonNode>,
    key: JsonSubtreeKey,
}

impl JsonSubtree {
    /// The rows of the read `key` keyed.
    pub(crate) fn keyed(nodes: Vec<JsonNode>, key: JsonSubtreeKey) -> Self {
        Self { nodes, key }
    }

    /// The rows.
    pub fn nodes(&self) -> &[JsonNode] {
        &self.nodes
    }

    /// The path the read was keyed from.
    pub fn path(&self) -> &JsonPath {
        &self.key.path
    }

    pub(crate) fn into_parts(self) -> (Vec<JsonNode>, JsonSubtreeKey) {
        (self.nodes, self.key)
    }

    /// Whether the rows are the sealed root alone, at depth `0`: what the
    /// server returns in place of a read past its budget, and for a read of
    /// `$` under the sealed root. Either way it opens whole.
    pub fn is_sealed_root(&self) -> bool {
        matches!(
            self.nodes.as_slice(),
            [node] if node.slot == 0 && node.depth == Some(0) && node.header.sealed_root()
        )
    }
}

impl Decryptable for JsonSubtree {
    const DECRYPTABLE: bool = true;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for JsonSubtree
where
    Self: crate::DecryptInto<P>,
    Ctx: Into<<Self as crate::DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

// =============================================================================
// Wire form
// =============================================================================

/// Standard base64 with padding, as PostgreSQL's `encode(x, 'base64')`
/// writes it and `decode(x, 'base64')` reads it (which refuses the unpadded
/// form): every field the SQL compares, derives or decodes.
pub(crate) fn base64(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

/// The inverse of [`base64`]: padded, canonical.
pub(crate) fn unbase64(text: &str) -> Result<Vec<u8>, WireError> {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(text).map_err(|_| WireError("not base64"))
}

fn unbase64_16(text: &str) -> Result<Tag, WireError> {
    Tag::try_from(unbase64(text)?).map_err(|_| WireError("not 16 bytes"))
}

fn unbase64_8(text: &str) -> Result<ParentTag, WireError> {
    ParentTag::try_from(unbase64(text)?).map_err(|_| WireError("not 8 bytes"))
}

/// RFC 1924 base85: the ciphertext, which nothing in SQL decodes. Five
/// characters per four bytes; the alphabet has no `"` or `\`.
fn base85(bytes: &[u8]) -> String {
    base85_simd::encode(bytes)
}

fn unbase85(text: &str) -> Result<Vec<u8>, WireError> {
    base85_simd::decode(text).map_err(|_| WireError("not base85"))
}

/// A wire field that does not decode. Names the field's fault and never its
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a JSON index wire field does not decode: {0}")]
pub struct WireError(&'static str);

/// `h`, `sv` and `q`, as stored. All three are required: the selector set
/// `q` is the only place the value selectors live.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire {
    h: String,
    sv: Vec<EntryWire>,
    q: query::GroupWire,
}

/// One entry, as stored, `{s, c, x, p?, op?}`: the tags and the ordering
/// term in base64, the
/// ciphertext in base85.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryWire {
    s: String,
    c: String,
    x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    op: Option<String>,
}

impl From<&JsonEntry> for EntryWire {
    fn from(e: &JsonEntry) -> Self {
        Self {
            s: base64(&e.s),
            c: base85(&e.c),
            x: base64(&e.x),
            p: e.p.as_ref().map(|t| base64(t)),
            op: e.op.as_deref().map(base64),
        }
    }
}

impl TryFrom<EntryWire> for JsonEntry {
    type Error = WireError;

    fn try_from(w: EntryWire) -> Result<Self, WireError> {
        Ok(Self {
            s: unbase64_16(&w.s)?,
            c: unbase85(&w.c)?,
            x: unbase64_8(&w.x)?,
            p: w.p.as_deref().map(unbase64_8).transpose()?,
            op: w.op.as_deref().map(unbase64).transpose()?,
        })
    }
}

impl From<JsonDocument> for DocumentWire {
    fn from(doc: JsonDocument) -> Self {
        Self {
            h: base64(&doc.header.to_bytes()),
            sv: doc.entries.iter().map(EntryWire::from).collect(),
            q: query::GroupWire::from(&doc.selectors),
        }
    }
}

impl TryFrom<DocumentWire> for JsonDocument {
    type Error = WireError;

    fn try_from(w: DocumentWire) -> Result<Self, WireError> {
        let header =
            JsonHeader::from_bytes(&unbase64(&w.h)?).map_err(|_| WireError("not a header"))?;
        let entries =
            w.sv.into_iter()
                .map(JsonEntry::try_from)
                .collect::<Result<_, _>>()?;
        let selectors = JsonSelectorSet::try_from(w.q)?;
        Ok(Self {
            header,
            entries,
            selectors,
        })
    }
}

/// An extracted entry: the entry's fields, the grafted header and ordinal,
/// and whatever else the SQL grafted (`i`, `v`), which is ignored.
#[derive(Clone, Serialize, Deserialize)]
struct NodeWire {
    #[serde(flatten)]
    entry: EntryWire,
    h: String,
    j: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    d: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    i: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v: Option<serde_json::Value>,
}

impl From<JsonNode> for NodeWire {
    fn from(node: JsonNode) -> Self {
        Self {
            entry: EntryWire::from(&node.entry),
            h: base64(&node.header.to_bytes()),
            j: node.slot,
            d: node.depth,
            i: None,
            v: None,
        }
    }
}

impl TryFrom<NodeWire> for JsonNode {
    type Error = WireError;

    fn try_from(w: NodeWire) -> Result<Self, WireError> {
        Ok(Self {
            entry: JsonEntry::try_from(w.entry)?,
            header: JsonHeader::from_bytes(&unbase64(&w.h)?)
                .map_err(|_| WireError("not a header"))?,
            slot: w.j,
            depth: w.d,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_value_leaves_no_plaintext_in_the_value() {
        let mut value =
            serde_json::json!({"name": "Alice", "n": 34, "ok": true, "list": ["x", 1.5]});
        wipe_value(&mut value);
        assert_eq!(value, serde_json::json!({}), "the containers are emptied");
        let mut text = serde_json::json!("secret");
        wipe_value(&mut text);
        assert_eq!(
            text,
            serde_json::json!(""),
            "a string is overwritten and cleared"
        );
        let mut number = serde_json::json!(42);
        wipe_value(&mut number);
        assert_eq!(number, serde_json::json!(0));
    }

    #[test]
    fn the_header_round_trips_its_frozen_layout() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], true);
        let bytes = header.to_bytes();
        assert_eq!(bytes[0], JsonHeader::FORMAT_VERSION);
        assert_eq!(bytes[1], 1, "the sealed-root flag");
        assert_eq!(&bytes[2..6], &[0; 4], "the epoch is reserved at zero");
        assert_eq!(
            &bytes[22..38],
            &[9; 16],
            "the iv sits at offset 22, where the SQL reads it"
        );
        assert_eq!(JsonHeader::from_bytes(&bytes).unwrap(), header);
        let open = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], false);
        assert_eq!(JsonHeader::from_bytes(&open.to_bytes()).unwrap(), open);
        assert!(!JsonHeader::from_bytes(&open.to_bytes())
            .unwrap()
            .sealed_root());
        assert!(matches!(
            JsonHeader::from_bytes(&bytes[..10]),
            Err(JsonHeaderError::Truncated)
        ));
        assert!(matches!(
            JsonHeader::from_bytes(&[2]),
            Err(JsonHeaderError::UnknownVersion(2))
        ));
    }

    #[test]
    fn a_header_reads_back_what_it_was_made_with() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], false);
        assert_eq!(header.keyset_id(), Uuid::from_u128(7));
        assert_eq!(header.iv(), &[9; 16]);
        assert_eq!(header.tag(), &[1, 2, 3]);
        assert!(!header.sealed_root());
        let sealed = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], true);
        assert!(sealed.sealed_root());
    }

    #[test]
    fn every_truncation_of_a_header_is_refused() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], true);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 40 + 3, "the fixed fields, then the tag");
        // Short of the fixed fields, and short of the tag `tag_len` promises.
        for len in 0..bytes.len() {
            assert_eq!(
                JsonHeader::from_bytes(&bytes[..len]),
                Err(JsonHeaderError::Truncated),
                "{len} bytes"
            );
        }
        let bare = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![], true);
        assert_eq!(
            JsonHeader::from_bytes(&bare.to_bytes()),
            Ok(bare),
            "the fixed fields alone are a header with an empty tag"
        );
    }

    #[test]
    fn a_header_prints_its_keyset_and_layout_and_masks_the_key_identifiers() {
        let header = JsonHeader::new(Uuid::from_u128(7), [9; 16], vec![1, 2, 3], true);
        assert_eq!(
            format!("{header:?}"),
            format!(
                "stack_encrypt::json::JsonHeader {{ keyset_id: {:?}, iv: \"***\", tag: \"***\", sealed_root: true, epoch: 0 }}",
                Uuid::from_u128(7)
            )
        );
    }

    /// An entry at ordinal `o` under `parent`, as whoever holds `parent` can
    /// write one: its parent tag and its self tag as a member are public
    /// given the token.
    fn chained(iv: &[u8], parent: &Tag, o: u32) -> JsonEntry {
        JsonEntry {
            s: [0; 16],
            c: o.to_le_bytes().to_vec(),
            x: derive::self_tag(iv, &derive::member_token(parent, &[0; 16])),
            p: Some(derive::parent_tag(iv, parent, o)),
            op: None,
        }
    }

    #[test]
    fn a_walk_ends_on_a_chain_deeper_than_any_sealed_document() {
        let iv = [9; 16];
        let token = [1; 16];
        // A chain longer than any document the index seals: the first child
        // of each link's token, a thousand times.
        let mut entries = vec![JsonEntry {
            s: [0; 16],
            c: vec![0],
            x: derive::self_tag(&iv, &token),
            p: None,
            op: None,
        }];
        let mut parent = token;
        for _ in 0..1000 {
            entries.push(chained(&iv, &parent, 0));
            parent = derive::member_token(&parent, &[0; 16]);
        }
        let chain = JsonDocument::new(
            JsonHeader::new(Uuid::from_u128(7), iv, vec![], true),
            entries,
            JsonSelectorSet::default(),
        );
        let walked = chain.subtree(&[token]);
        assert_eq!(
            walked.len(),
            derive::MAX_DEPTH + 1,
            "the token's node, then cut at the deepest level"
        );
        assert_eq!(
            walked.last().map(|(_, _, depth)| *depth as usize),
            Some(derive::MAX_DEPTH),
            "no row below the deepest level a sealed document has"
        );
    }

    #[test]
    fn the_encodings_round_trip_and_refuse_what_they_are_not() {
        assert_eq!(base64(&[0, 15, 255]), "AA//");
        assert_eq!(unbase64("AA//").unwrap(), vec![0, 15, 255]);
        assert_eq!(base64(&[1; 16]).len(), 24, "a sixteen-byte tag, padded");
        assert_eq!(
            base64(&[1; 8]).len(),
            12,
            "an eight-byte parent tag, padded"
        );
        assert!(
            unbase64("AA/").is_err(),
            "unpadded, which the SQL refuses too"
        );
        assert!(unbase64("AA//=").is_err());
        assert!(unbase64("zz").is_err());
        assert!(unbase64_16("AA//").is_err());
        assert!(unbase64_8("AA//").is_err());
        assert_eq!(unbase64_8(&base64(&[7; 8])).unwrap(), [7; 8]);

        assert_eq!(base85(&[0, 15, 255]), "01y8");
        assert_eq!(unbase85("01y8").unwrap(), vec![0, 15, 255]);
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(unbase85(&base85(&bytes)).unwrap(), bytes);
        assert_eq!(base85(&bytes).len(), 320, "five characters per four bytes");
        assert!(
            !base85(&bytes).contains(['"', '\\']),
            "unescaped in a JSON string"
        );
        assert!(unbase85("\"").is_err());
        assert!(unbase85("z").is_err(), "a one-character tail is no byte");
    }
}
