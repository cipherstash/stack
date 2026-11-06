//! The leakage profile `L`: what `packages/eql/docs/reference/json-tree-leakage.md`
//! says the database learns, written as a function of the plaintext alone.
//!
//! [`l_store`] is what a set of stored rows reveals, [`l_query`] what one
//! query reveals on top of them. Neither takes a key or calls the crate: they
//! read the documents, the column's options and the query, and they name
//! every keyed value (a selector, a value selector, a token, an ordering
//! term, a self tag) by an opaque integer that is equal wherever the real
//! values are equal, so the profile states equality patterns and never
//! names. The simulator ([`super::simulator`]) builds a wire-shaped world
//! from this output and its own randomness, and the distinguishers
//! ([`super::distinguishers`]) compare it with the real one.
//!
//! Each field of the leakage types is one clause, and its doc comment quotes
//! the sentence of the page it encodes. Where the page is vague the clause is
//! as precise as the code forces, and says so. One clause is marked
//! **added to the page by #1362**: the code revealed it and the page as
//! #1363 published it did not say so. [`Clauses::as_published_in_1363`]
//! turns it off, and the calibration shows a distinguisher separating that
//! profile from the real scheme.
//!
//! **This module models the format of #1363** (`docs/plans/2026-10-17-json-tree-index.md`,
//! "Design change (2026-10-24)" and its decisions): a self tag `x` on every
//! entry, member tokens without an ordinal, element tokens with their
//! index, and a subtree read that sends the tokens of exactly the nodes it
//! names, with wildcards expanded on the client and a probe per expanded
//! array. The profile was first written against the format before it
//! (`{s, c, p?, op?}` entries, one head token and plaintext gates per read);
//! `docs/plans/2026-10-25-json-tree-leakage-before-and-after.md` records
//! what changed between the two.
//!
//! Since then a document's entries are stored in a uniformly random order
//! drawn when it is sealed, the root first, and `q`'s lists are shuffled
//! the same way ([`Leakage::stored_order`]); a needle's lists are sent
//! shuffled too, afresh for each query ([`Leakage::sent_order`]); each
//! entry's AAD binds its children's AEAD tags (the cascade), which changes
//! nothing stored. The profile numbers a row's nodes, and a needle's,
//! depth-first ([`flatten`]) for its own bookkeeping: that numbering is not
//! the order either is stored or sent in.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use serde_json::{Number, Value};
use stack_encrypt::json::{JsonPath, Segment};
use vitaminc_protected::Controlled;

pub use super::chain::Rule;

/// What every entry's ciphertext adds to its plaintext: the frame's version
/// byte, the 96-bit random nonce and the 128-bit GCM tag
/// (`vitaminc-encrypt`'s `Aes256Cipher`). The page's "less the AEAD's fixed
/// overhead".
pub const AEAD_OVERHEAD: usize = 1 + 12 + 16;

/// The length of the ZeroKMS key tag the header carries. The fake key source
/// the tests seal under mints 32-byte tags; it is a property of the key
/// service, not of any document, so it is a column constant here.
pub const KEY_TAG_LEN: usize = 32;

/// The bound a wildcard expands to when a read names none
/// (`JsonSubtreeKey::DEFAULT_BOUND`).
pub const DEFAULT_BOUND: u32 = 64;

/// The budget `json_tree_subtree` takes when the caller names none.
pub const DEFAULT_BUDGET: u32 = 64;

/// A column's configuration, which the database knows: it is in every
/// header (the root option) or in the plan the queries run under.
#[derive(Clone, Debug)]
pub struct Column {
    pub sealed_root: bool,
    pub ordered: Vec<JsonPath>,
}

/// A query, in plaintext: what the client asks.
#[derive(Clone, Debug)]
pub enum Query {
    /// `->` on a path.
    Extract(String),
    /// A subtree read of a path, `json_tree_subtree(doc, tokens, budget)`,
    /// its wildcards expanded to `bound` positions each.
    Subtree {
        path: String,
        bound: u32,
        budget: u32,
    },
    /// Containment, `@>`, of a needle document.
    Contains(Value),
    /// Equality at a path, `AtPath<Eq>`, of a scalar.
    Equals(String, Value),
    /// An ordering bound at a path, `AtPath<Gte>`, of a number or string.
    Order(String, Value),
}

impl Query {
    /// A subtree read at the default bound and budget.
    pub fn subtree(path: &str) -> Self {
        Self::Subtree {
            path: path.to_owned(),
            bound: DEFAULT_BOUND,
            budget: DEFAULT_BUDGET,
        }
    }

    /// A subtree read at `bound` and `budget`.
    pub fn subtree_with(path: &str, bound: u32, budget: u32) -> Self {
        Self::Subtree {
            path: path.to_owned(),
            bound,
            budget,
        }
    }
}

/// Which sort "the byte order of their key names' UTF-8 encodings" means:
/// the order of an object's members in the walk's order, which numbers the
/// profile's nodes ([`flatten`]). Nothing the database sees shows it now:
/// the stored order is random ([`StoredOrder::Random`]), a needle is sent in
/// a random order ([`SentOrder::Random`]), and a member's ordinal is a keyed
/// rank. The other reading is kept to show that: a profile read either way
/// is told from the real scheme by no distinguisher (the key-order reading
/// test in `calibration.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrder {
    /// Byte order of the UTF-8 key: serde_json's `Map` without
    /// `preserve_order`, which is what the walk iterates.
    Utf8Bytes,
    /// PostgreSQL `jsonb`'s own order: shorter keys first, then bytes. The
    /// other reading a reader could take of an unqualified "sorted order".
    JsonbLengthFirst,
}

/// What a string's ordering term orders and compares by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringOrder {
    /// The page: "Strings are ordered and compared after their case and
    /// accents are folded", and the term's length counts "a string whose
    /// folded UTF-8 form is `n` bytes". Unicode 16 NFC with case and accents
    /// folded (`vitaminc_ore::text`).
    Folded,
    /// The string's own bytes, as the profile first assumed (its corpus had
    /// only lower-case ASCII, where the two agree).
    Bytes,
}

/// What a number's ordering term tells equal by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberOrder {
    /// The page: equality "is as a 64-bit float", so two integers past
    /// 2^53 that round to one float share a term (the term is derived from
    /// `as_f64`).
    Float,
    /// Every distinct number its own term, as a reader could take "equal
    /// values carry equal terms" to mean.
    Exact,
}

/// The clauses of the profile that are on or off as a whole, and the
/// readings the page could leave open. The default is what the code needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clauses {
    /// How an object's members sort in the walk's order.
    pub key_order: KeyOrder,
    /// How a string's ordering term orders.
    pub string_order: StringOrder,
    /// What a number's ordering term tells equal by.
    pub number_order: NumberOrder,
    /// **Added to the page by #1362.** The rule a node's token takes under
    /// its parent's, member or element, which the database learns for every
    /// node a walk reaches: it tests the member rule against the hit's self
    /// tag and then the element rule (`json_tree_hit_token`), so the one
    /// that matches says whether the parent is an object or an array. The
    /// design's decision 2 ("no kind bit") keeps it out of the stored form;
    /// the walk reveals it anyway, below any token sent. Off, the profile
    /// states no rule, and every node takes the element rule with its
    /// ordinal, which is the coarsest world consistent with the rest.
    pub hit_rule: bool,
}

impl Default for Clauses {
    fn default() -> Self {
        Self {
            key_order: KeyOrder::Utf8Bytes,
            string_order: StringOrder::Folded,
            number_order: NumberOrder::Float,
            hit_rule: true,
        }
    }
}

impl Clauses {
    /// The page as #1363 published it (at `997c64b1e`): every clause #1362
    /// added to it off.
    pub fn as_published_in_1363() -> Self {
        Self {
            hit_rule: false,
            ..Self::default()
        }
    }
}

/// An opaque name for a path selector `s`: equal for every node anywhere in
/// the column whose wildcard-folded path is the same.
pub type SelId = usize;
/// An opaque name for a value selector `vs`.
pub type ValueId = usize;
/// An opaque name for a token that is a PRF of a path: the root's, and
/// under the sealed root each top-level field's or element's.
pub type HeadId = usize;
/// An opaque name for an ordering term's value: equal for equal values.
pub type OrderClass = usize;
/// An opaque name for a self tag the database cannot recompute: one per
/// entry, so equal nowhere.
pub type SelfTagId = usize;

/// How a node hangs off its parent, which decides its ordinal under the
/// parent's token: the `o` of its parent tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Root,
    /// An object member: its ordinal is its place in a random permutation
    /// of its object's members, drawn when the row was sealed.
    Member,
    /// An array element at this position, which is its ordinal.
    Element(u64),
}

/// The kind of leaf an ordering term is of. Each kind's terms are under a
/// key of its own: the order space's salt names its domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OrderKind {
    Number,
    String,
}

/// Where a column's key puts the strings' terms among the numbers', at an
/// ordered path that holds both. A CLLW term begins with a carry byte and
/// then `PRF(key, ε) + 128 × first bit`, and the two kinds' keys differ,
/// so under one key every string compares the same way with every negative
/// number (first bit 0) and the same way with every non-negative one (first
/// bit 1): the strings sort as one block, in one of three places.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Below every number.
    Below,
    /// Above the negative numbers and below the non-negative ones.
    Between,
    /// Above every number: jsonb's order, which sorts numbers first.
    Above,
}

impl Placement {
    pub const ALL: [Self; 3] = [Self::Below, Self::Between, Self::Above];
}

/// How a number's term and a string's compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KindOrder {
    /// The page: "the order between a number and a string depends on the
    /// column key and is not jsonb's". The key picks a [`Placement`], once
    /// per column, and the simulator does what the key does, drawing one.
    ByKey,
    /// A placement that does not depend on the key: what only a mutant
    /// states.
    Fixed(Placement),
}

/// The ordering term of one leaf, or of one query bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderingLeak {
    /// "The order of that leaf's value among every row that holds one, and
    /// which rows hold equal values." Equal values share a class; the
    /// classes' order within their kind is [`Leakage::ordering_ranks`].
    pub class: OrderClass,
    /// Whether the leaf is a number or a string: "the terms also show which
    /// leaves are numbers and which are strings", since each kind's terms
    /// are under a key of its own and so begin with that key's bytes.
    pub kind: OrderKind,
    /// "Its length is the leaf's length: one byte per bit of the value's
    /// order encoding plus one, so 65 bytes for every number and
    /// `8 × (n + 1) + 1` bytes for a string whose folded UTF-8 form is `n`
    /// bytes." (Beyond the page when the profile was first written; on it
    /// since #1363.)
    pub len: usize,
}

/// One entry of `sv`, as the page says a stored row shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryLeakage {
    /// "`s`, the path selector on every node: which paths the row has, and
    /// how many nodes sit at each. A selector is a keyed hash of the path,
    /// the same in every row of the column […] Array elements share their
    /// array's selector, so `$.tags[0]` and `$.tags[1]` look alike, but each
    /// element is its own entry."
    pub selector: SelId,
    /// The shape: the index in [`RowLeakage::entries`] of this node's
    /// parent. Not revealed at rest: the stored order is random
    /// ([`Leakage::stored_order`]) and no stored field links an entry to
    /// another, so the simulator reads it only below a token a query sends,
    /// to place the chain the token links ([`ReadLeak::reach`]): "see how
    /// the nodes beneath it nest, link each one to its parent".
    pub parent: Option<usize>,
    /// The node's ordinal under its parent, which a token's holder sees in
    /// the ordinals it probes: "each element's index: […] an element's index
    /// is the ordinal it is found at". A member's ordinal is its place in a
    /// random permutation of its object's members, drawn per row, which the
    /// holder sees and which says nothing about the member: two objects give
    /// two unrelated ones (`member_order_shared_across_parents`).
    pub step: Step,
    /// The rule this node's token takes under its parent's: "whether each
    /// node beneath is an object member or an array element […] the
    /// database tests its self tag against the member rule and then the
    /// element rule, and the one that matches says which"
    /// ([`Clauses::hit_rule`]). `None` for an entry that chains from no
    /// parent (the root, and the top-level entries of a sealed root).
    pub rule: Option<Rule>,
    /// "Which entries carry no `p` does show: with the sealed root on, those
    /// are the root's direct members […] With the sealed root off, only the
    /// root lacks one." (The root lacks one under the sealed root too.)
    pub has_parent_tag: bool,
    /// "`x`, the self tag on every entry: Nothing on its own. It is a hash
    /// of the entry's own token salted by the document's `iv`, so it is
    /// unrelated bytes in every row and links no entry to another, and since
    /// every entry carries one, its presence marks none." Named per entry,
    /// so no two are equal; an entry a query's token finds or reaches has
    /// its real self tag instead, in [`QueryLeakage::Subtree`]. `None` would
    /// be an entry without one, which only a mutant states.
    pub self_tag: Option<SelfTagId>,
    /// "Each ciphertext's length […] for each node the length of its key name
    /// (for an object member) plus, for a scalar, the length of its value,
    /// exactly, less the AEAD's fixed overhead. […] With the sealed root on,
    /// the root entry's length is the document's length as JSON." The fixed
    /// parts the page leaves out are written in [`ciphertext_len`]. The self
    /// tag sits beside the ciphertext, not in it, so it changes no
    /// ciphertext's length; it adds a fixed 12 base64 characters per entry,
    /// 19 with its key in compact JSON, which
    /// `distinguishers::stored_lengths` counts.
    pub ciphertext_len: usize,
    /// "`op`, the ordering term, only on number and string leaves at the
    /// paths the index orders."
    pub ordering: Option<OrderingLeak>,
}

/// One group of a projection, stored (`q`) or sent (a needle).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupLeakage {
    /// "One `{s, vs}` pair per node": the pairs of the nodes that sit
    /// directly in this group, in the walk's order, an object's members in
    /// [`Clauses::key_order`]. Neither list is stored or sent in this order:
    /// a stored `q`'s lists are shuffled ([`Leakage::stored_order`]), and so
    /// are a needle's ([`Leakage::sent_order`]). "Whether
    /// two rows hold the same value at the same path, through the value
    /// selector `vs`, a keyed hash of the path and the value (for an object
    /// or an array, of its kind alone)."
    pub pairs: Vec<(SelId, ValueId)>,
    /// "Nested by array element […] Which nodes sit inside the same array
    /// element, through the nesting, for every element that is an object or
    /// an array."
    pub elements: Vec<GroupLeakage>,
}

/// One stored row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowLeakage {
    /// The header's sealed-root flag: "whether the root is sealed".
    pub sealed_root: bool,
    /// The header's keyset: "the keyset the data key was minted under",
    /// which "is the same for every column it seals". One name for every row.
    pub keyset: usize,
    /// The header's key identifiers (the `iv` and the ZeroKMS tag): "the
    /// data key's identifier (unique to the row)". A different name in every
    /// row. The `iv` also salts every parent and self tag in the row.
    pub data_key: usize,
    /// "The number of entries", one per node, numbered as [`flatten`] walks
    /// the document (depth-first, the root first). The numbering is the
    /// profile's own: the entries are stored in the order
    /// [`Leakage::stored_order`] says, and every index into this list
    /// ([`EntryLeakage::parent`], [`ReadLeak::hits`], [`ReadLeak::reach`])
    /// names a node, not a slot.
    pub entries: Vec<EntryLeakage>,
    /// The containment projection `q`.
    pub projection: GroupLeakage,
}

/// One step of a token's derivation below its head, as the client derives
/// it from the path alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenStep {
    /// `H16("t" ‖ t(parent) ‖ s(member))`: a key step, by its selector.
    Member(SelId),
    /// `H16("t" ‖ t(array) ‖ s(element) ‖ LE32(i))`: a position step, by
    /// the element selector and the position.
    Element(SelId, u64),
}

/// A token, by name: a head, then the steps the client chains below it.
/// Two reads of one concrete path send one token, in every query: "Tokens
/// are column-wide and do not expire".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenName {
    pub head: HeadId,
    pub steps: Vec<TokenStep>,
}

/// One token of a subtree read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadLeak {
    /// "A token for exactly the node the path names, which the client
    /// derives from the path alone." For a wildcard, one per concrete path
    /// below the bound, in document order.
    pub token: TokenName,
    /// "plus a probe token for the element at index `N` of every array a
    /// wildcard expands", the last token at its level. The database is not
    /// told which tokens are probes; it can tell from their places in the
    /// list (`distinguishers::wildcard_positions`).
    pub probe: bool,
    /// Per row, the entry the token names, if the row has the node: "whoever
    /// holds it can find that node in any row (through its self tag `x`)".
    pub hits: Vec<Option<usize>>,
    /// Per row, the entries below that node the token links: "see how the
    /// nodes beneath it nest, link each one to its parent, and derive the
    /// tokens of the nodes beneath". Every strict descendant that chains
    /// from it, which under the sealed root excludes everything below the
    /// root ("the top-level fields chain from nothing"). Nothing above it:
    /// "nothing that covers `$.profile`".
    pub reach: Vec<Vec<usize>>,
}

/// What one query reveals, beyond the rows it returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryLeakage {
    /// "Path extraction […] The selector of the path asked. A position in the
    /// path reads as the wildcard, so a position is not sent."
    Extract { selector: SelId },
    /// "A subtree read […] A token for exactly the node the path names". The
    /// tokens' number gives the wildcards' bound away (`N + 1` per one-level
    /// wildcard, `N² + N + 1` for two levels), and which of them find a node
    /// in which row gives each expanded array's length below `N`, or that it
    /// is longer.
    Subtree {
        reads: Vec<ReadLeak>,
        /// The `budget` argument, in the clear in the call. Past it, with
        /// the root sealed, the database returns the root entry alone; it
        /// computes that from the walk it already sees, so the fallback
        /// tells it nothing more.
        budget: u32,
    },
    /// "Containment […] The needle's own projection: the selectors of its
    /// paths, the value selectors of its nodes, and its element grouping."
    /// The page does not mention `alt`, the extra one-pair projection a
    /// needle whose root is a scalar carries so that it matches a stored
    /// root array holding it; it is part of "the needle's own projection"
    /// here.
    Contains {
        needle: GroupLeakage,
        alt: Option<GroupLeakage>,
    },
    /// "Equality at a path, which is sent as a containment needle": the
    /// projection of the document that holds the value at the path.
    Equals { needle: GroupLeakage },
    /// "Ordering at a path […] The path's selector and the bound's own
    /// ordering term, which compares with the stored terms exactly as they
    /// compare with each other."
    Order {
        selector: SelId,
        bound: OrderingLeak,
    },
}

/// The order a row's entries and its projection's lists are stored in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoredOrder {
    /// The page: "The entries of `sv` are stored with the root first, where
    /// the database finds the sealed root, and every other entry in a
    /// uniformly random order drawn when the row is sealed and then
    /// discarded. [...] it shows nothing beyond the root's place", and "The
    /// pairs of each group and the groups of each list are stored in a
    /// random order, so the projection does not restate the document's
    /// order". Slot `0` holds the
    /// root; slots `1..n` hold the other nodes in a uniformly random
    /// permutation; every list of `q` is a uniformly random permutation of
    /// its pairs or groups. What stays visible is the rest of this profile:
    /// the selectors a row holds and how many of each, `q`'s grouping by
    /// array element, the entries without a parent tag (the chain heads),
    /// each ciphertext's length and the ordering terms.
    Random,
    /// The order before: depth-first, the root first, each node followed by
    /// everything beneath it, an object's members in key order, and `q` in
    /// the same walk's order. It gave every row's tree away (#1357). Only a
    /// mutant states it now.
    DepthFirst,
}

/// The order a containment or equality needle's lists are sent in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentOrder {
    /// The page: "A needle is sent in a random order too, drawn afresh for
    /// each query, so it shows no more of the order of the needle's keys
    /// than a stored row does." Every pair list and every element-group list
    /// of a needle (and its one-pair `alt`) is a uniformly random
    /// permutation, drawn independently for each query, so two queries for
    /// one needle send its pairs in two unrelated orders.
    Random,
    /// The walk's order, an object's members in [`Clauses::key_order`]: the
    /// order a needle was sent in before the client shuffled it, which told
    /// the database which of two sibling keys sorts first. Only a mutant
    /// states it now.
    Walk,
}

/// The leakage of a whole column: its rows and its queries, over one shared
/// set of opaque names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leakage {
    /// "The keyset the data key was minted under […] the same for every
    /// column it seals": one keyset per column, and the ZeroKMS tag's length.
    pub key_tag_len: usize,
    /// The order every row's entries and `q` are stored in.
    pub stored_order: StoredOrder,
    /// The order every needle is sent in.
    pub sent_order: SentOrder,
    pub rows: Vec<RowLeakage>,
    pub queries: Vec<QueryLeakage>,
    /// The rank of each [`OrderClass`] among the classes of its kind: "the
    /// order of that leaf's value among every row that holds one", and the
    /// bound's "place in the order of the stored values at every ordered
    /// path" ("leaves at two ordered paths compare with each other too, and
    /// two ordered paths holding equal values carry equal terms"; "within
    /// each kind the order is the values'"). A number's equality "is as a
    /// 64-bit float".
    pub ordering_ranks: Vec<usize>,
    /// How the two kinds' terms compare ([`KindOrder`]).
    pub kind_order: KindOrder,
    /// For each two classes of one kind next to each other in rank order,
    /// `(lower, higher)`, how many leading bits their order encodings
    /// share. A number's term and a string's share none: their keys
    /// differ. "Two
    /// values whose encodings share leading bits […] get terms that share
    /// leading bytes, […] so the term also shows how long that common
    /// prefix is". CLLW OPE writes one byte per bit, the PRF of the bits
    /// before it plus the bit at weight 128, with a carry from the right, so
    /// two terms agree to within one at every byte before the first bit
    /// their encodings differ in, and differ by about 128 there
    /// (`distinguishers::ordering_term_prefixes`). The common prefix of any
    /// two classes is the least of the adjacent ones between them, so the
    /// adjacent pairs are the whole clause. For a number the encoding is its
    /// `f64`'s order encoding, so its first bit is the sign and the next
    /// eleven the exponent's; for a string, the marker byte and then the
    /// folded text.
    pub ordering_prefixes: BTreeMap<(OrderClass, OrderClass), usize>,
}

// =============================================================================
// The opaque names
// =============================================================================

struct Interner<T> {
    ids: HashMap<T, usize>,
}

impl<T> Default for Interner<T> {
    fn default() -> Self {
        Self {
            ids: HashMap::new(),
        }
    }
}

impl<T: Hash + Eq> Interner<T> {
    fn id(&mut self, value: T) -> usize {
        let next = self.ids.len();
        *self.ids.entry(value).or_insert(next)
    }
}

/// A value an ordering term orders by. Numbers order as `f64` (the term is
/// derived from `as_f64`); strings by their order encoding's bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum OrderKey {
    /// The `f64`'s bits, and under [`NumberOrder::Exact`] an integer's own
    /// value beside them, which keeps integers that round to one float
    /// apart.
    Number(u64, Option<i128>),
    String(Vec<u8>),
}

impl OrderKey {
    /// The bytes the term is CLLW OPE over, one term byte per bit: a
    /// number's `f64` order encoding (`vitaminc_ore::order` at `F64`), and a
    /// string's marker and folded text as [`Ids::ordering`] keeps them.
    fn encoding(&self) -> Vec<u8> {
        match self {
            Self::Number(bits, _) => vitaminc_ore::order(
                vitaminc_ore::OrderTarget::F64,
                None,
                vitaminc_ore::Physical::Float(vitaminc_ore::Float::F64(f64::from_bits(*bits))),
            )
            .expect("a finite f64 has an order encoding")
            .bytes()
            .risky_ref()
            .clone(),
            Self::String(encoded) => encoded.clone(),
        }
    }
}

/// How many leading bits `a` and `b` share.
fn common_bits(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .map_or(8 * a.len().min(b.len()), |k| {
            8 * k + (a[k] ^ b[k]).leading_zeros() as usize
        })
}

/// The names shared by [`l_store`] and [`l_query`]: one id space per kind of
/// keyed value, so a query's selector is the stored selector's id when the
/// real bytes are equal.
#[derive(Default)]
pub struct Ids {
    selectors: Interner<Vec<Segment>>,
    values: Interner<(SelId, u8, Vec<u8>)>,
    heads: Interner<Vec<Segment>>,
    ordering: Interner<OrderKey>,
    ordering_keys: Vec<OrderKey>,
    self_tags: usize,
    pub clauses: Clauses,
}

impl Ids {
    pub fn new(clauses: Clauses) -> Self {
        Self {
            clauses,
            ..Self::default()
        }
    }

    /// The selector of a path, every array step read as the wildcard.
    fn selector(&mut self, path: &[Segment]) -> SelId {
        self.selectors.id(path
            .iter()
            .map(|s| match s {
                Segment::Key(k) => Segment::Key(k.clone()),
                Segment::Index(_) | Segment::Wildcard => Segment::Wildcard,
            })
            .collect())
    }

    fn value(&mut self, selector: SelId, value: &Value) -> ValueId {
        self.values
            .id((selector, kind_byte(value), canonical(value)))
    }

    fn head(&mut self, positional: &[Segment]) -> HeadId {
        self.heads.id(positional.to_vec())
    }

    fn self_tag(&mut self) -> SelfTagId {
        self.self_tags += 1;
        self.self_tags
    }

    fn ordering(&mut self, value: &Value) -> OrderingLeak {
        let key = match value {
            Value::Number(n) => {
                let f = n.as_f64().expect("a JSON number has an f64");
                assert!(
                    f != 0.0 || f.is_sign_positive(),
                    "the corpus has no -0.0, whose term the page does not describe"
                );
                let exact = match self.clauses.number_order {
                    NumberOrder::Float => None,
                    NumberOrder::Exact => n
                        .as_i64()
                        .map(i128::from)
                        .or_else(|| n.as_u64().map(i128::from)),
                };
                OrderKey::Number(f.to_bits(), exact)
            }
            Value::String(s) => OrderKey::String(match self.clauses.string_order {
                // The marker, then the folded text: the order encoding.
                StringOrder::Folded => vitaminc_ore::text(s)
                    .expect("the corpus holds assigned code points")
                    .risky_unwrap(),
                StringOrder::Bytes => {
                    let mut out = vec![vitaminc_ore::VARIABLE_WIDTH_MARKER];
                    out.extend_from_slice(s.as_bytes());
                    out
                }
            }),
            _ => unreachable!("only numbers and strings carry a term"),
        };
        // One byte per bit of the order encoding, plus one.
        let len = match &key {
            OrderKey::Number(..) => 8 * 8 + 1,
            OrderKey::String(encoded) => 8 * encoded.len() + 1,
        };
        let kind = match &key {
            OrderKey::Number(..) => OrderKind::Number,
            OrderKey::String(_) => OrderKind::String,
        };
        let class = self.ordering.id(key.clone());
        if class == self.ordering_keys.len() {
            self.ordering_keys.push(key);
        }
        OrderingLeak { class, kind, len }
    }

    /// The rank of every ordering class among the classes of its kind.
    pub fn ordering_ranks(&self) -> Vec<usize> {
        let mut ranks = vec![0; self.ordering_keys.len()];
        for kind in [OrderKind::Number, OrderKind::String] {
            for (rank, class) in self.of_kind(kind).into_iter().enumerate() {
                ranks[class] = rank;
            }
        }
        ranks
    }

    /// The classes of `kind`, in their order.
    fn of_kind(&self, kind: OrderKind) -> Vec<OrderClass> {
        let mut order: Vec<OrderClass> = (0..self.ordering_keys.len())
            .filter(|&c| {
                matches!(
                    (&self.ordering_keys[c], kind),
                    (OrderKey::Number(..), OrderKind::Number)
                        | (OrderKey::String(_), OrderKind::String)
                )
            })
            .collect();
        order.sort_by(
            |&a, &b| match (&self.ordering_keys[a], &self.ordering_keys[b]) {
                (OrderKey::Number(x, i), OrderKey::Number(y, j)) => f64::from_bits(*x)
                    .total_cmp(&f64::from_bits(*y))
                    .then(i.cmp(j)),
                (OrderKey::String(x), OrderKey::String(y)) => x.cmp(y),
                _ => unreachable!("one kind"),
            },
        );
        order
    }

    /// The leading bits each two classes of one kind next to each other in
    /// its order share ([`Leakage::ordering_prefixes`]).
    pub fn ordering_prefixes(&self) -> BTreeMap<(OrderClass, OrderClass), usize> {
        [OrderKind::Number, OrderKind::String]
            .into_iter()
            .flat_map(|kind| {
                self.of_kind(kind)
                    .windows(2)
                    .map(|pair| {
                        let shared = common_bits(
                            &self.ordering_keys[pair[0]].encoding(),
                            &self.ordering_keys[pair[1]].encoding(),
                        );
                        ((pair[0], pair[1]), shared)
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

// =============================================================================
// Plaintext helpers: what the scheme computes over, with no key
// =============================================================================

fn kind_byte(value: &Value) -> u8 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Object(_) => 4,
        Value::Array(_) => 5,
    }
}

/// A number's identity for its value selector: an integral value is one
/// value whichever JSON spelling it had (`2` and `2.0`), as `jsonb` compares
/// them.
fn canonical_number(number: &Number) -> Vec<u8> {
    if let Some(i) = number.as_i64() {
        return i128::from(i).to_le_bytes().to_vec();
    }
    if let Some(u) = number.as_u64() {
        return i128::from(u).to_le_bytes().to_vec();
    }
    let f = number.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e38 {
        return (f as i128).to_le_bytes().to_vec();
    }
    let mut out = vec![b'f'];
    out.extend_from_slice(&f.to_le_bytes());
    out
}

fn canonical(value: &Value) -> Vec<u8> {
    match value {
        Value::Null | Value::Object(_) | Value::Array(_) => Vec::new(),
        Value::Bool(b) => vec![u8::from(*b)],
        Value::Number(n) => canonical_number(n),
        Value::String(s) => s.as_bytes().to_vec(),
    }
}

/// One node of a document, as [`flatten`] numbers it.
pub struct Node<'a> {
    pub value: &'a Value,
    pub positional: Vec<Segment>,
    pub parent: Option<usize>,
    pub step: Step,
    pub label: Option<&'a str>,
    /// The nearest enclosing array element that is a container.
    pub element: Option<usize>,
    pub container_element: bool,
}

/// A document's nodes in the walk's order: depth-first, the root first, an
/// object's members in `order`, an array's elements in position order. The
/// profile's numbering of a row's nodes and of a needle's; not the order
/// either is stored or sent in ([`StoredOrder`], [`SentOrder`]).
pub fn flatten(doc: &Value, order: KeyOrder) -> Vec<Node<'_>> {
    let mut flattener = Flattener {
        order,
        out: Vec::new(),
    };
    flattener.visit(doc, Vec::new(), None, Step::Root, None, None);
    flattener.out
}

struct Flattener<'a> {
    order: KeyOrder,
    out: Vec<Node<'a>>,
}

impl<'a> Flattener<'a> {
    fn visit(
        &mut self,
        value: &'a Value,
        positional: Vec<Segment>,
        parent: Option<usize>,
        step: Step,
        label: Option<&'a str>,
        element: Option<usize>,
    ) {
        let container_element =
            matches!(step, Step::Element(_)) && matches!(value, Value::Object(_) | Value::Array(_));
        let index = self.out.len();
        self.out.push(Node {
            value,
            positional: positional.clone(),
            parent,
            step,
            label,
            element,
            container_element,
        });
        let child_element = if container_element {
            Some(index)
        } else {
            element
        };
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                match self.order {
                    KeyOrder::Utf8Bytes => keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes())),
                    KeyOrder::JsonbLengthFirst => {
                        keys.sort_by(|a, b| (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes())))
                    }
                }
                for key in keys {
                    let mut path = positional.clone();
                    path.push(Segment::Key(key.clone()));
                    self.visit(
                        &map[key],
                        path,
                        Some(index),
                        Step::Member,
                        Some(key),
                        child_element,
                    );
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    let mut path = positional.clone();
                    path.push(Segment::Index(i as u64));
                    self.visit(
                        item,
                        path,
                        Some(index),
                        Step::Element(i as u64),
                        None,
                        child_element,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Whether `pattern` covers `path`: `JsonPath::covers`, over segments.
fn covers(pattern: &[Segment], path: &[Segment]) -> bool {
    pattern.len() == path.len()
        && pattern.iter().zip(path).all(|(p, s)| match (p, s) {
            (Segment::Key(a), Segment::Key(b)) => a == b,
            (Segment::Wildcard, Segment::Index(_) | Segment::Wildcard) => true,
            (Segment::Index(a), Segment::Index(b)) => a == b,
            _ => false,
        })
}

fn segments(path: &str) -> Vec<Segment> {
    JsonPath::parse(path)
        .expect("the corpus names valid paths")
        .segments()
        .to_vec()
}

/// A node's ciphertext length: [`AEAD_OVERHEAD`] plus its plaintext, which
/// is the kind byte, the four-byte child count, the label (a tag byte, then
/// a four-byte length and the key for a member, or the eight-byte position
/// for an element) and, for a scalar, its value (a string's bytes, a
/// number's JSON text, one byte for a boolean, nothing for `null`). A sealed
/// root's plaintext is a marker byte and the document as compact JSON.
///
/// Where this is more precise than the page: "a number's length in digits"
/// is the length of serde_json's text for it, sign, point and exponent
/// included (`-2` is two, `1e300` five); a boolean's and a null's "length of
/// its value" are one and zero; an element's label is a fixed nine bytes, so
/// it adds nothing that varies.
pub fn ciphertext_len(node: &Node<'_>, sealed_root: bool, doc: &Value) -> usize {
    if node.parent.is_none() && sealed_root {
        return AEAD_OVERHEAD + 1 + serde_json::to_string(doc).expect("serializes").len();
    }
    let label = match node.step {
        Step::Root => 1,
        Step::Member => 1 + 4 + node.label.map_or(0, str::len),
        Step::Element(_) => 1 + 8,
    };
    let scalar = match node.value {
        Value::String(s) => s.len(),
        Value::Bool(_) => 1,
        Value::Number(n) => n.to_string().len(),
        Value::Null | Value::Object(_) | Value::Array(_) => 0,
    };
    AEAD_OVERHEAD + 1 + 4 + label + scalar
}

fn group(
    ids: &mut Ids,
    nodes: &[Node<'_>],
    selectors: &[SelId],
    parent: Option<usize>,
) -> GroupLeakage {
    let belongs = |i: usize, n: &Node<'_>| {
        if n.container_element {
            Some(i)
        } else {
            n.element
        }
    };
    let pairs = nodes
        .iter()
        .enumerate()
        .filter(|(i, n)| belongs(*i, n) == parent)
        .map(|(i, n)| (selectors[i], ids.value(selectors[i], n.value)))
        .collect();
    let elements = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.container_element && n.element == parent)
        .map(|(i, _)| group(ids, nodes, selectors, Some(i)))
        .collect();
    GroupLeakage { pairs, elements }
}

fn projection(ids: &mut Ids, doc: &Value) -> GroupLeakage {
    let nodes = flatten(doc, ids.clauses.key_order);
    let selectors: Vec<SelId> = nodes.iter().map(|n| ids.selector(&n.positional)).collect();
    group(ids, &nodes, &selectors, None)
}

/// Whether the node at `depth` chains from its parent, which is whether it
/// carries a parent tag: under the sealed root the top-level entries chain
/// from nothing.
fn chains(depth: usize, sealed_root: bool) -> bool {
    depth > 0 && !(sealed_root && depth == 1)
}

// =============================================================================
// L
// =============================================================================

/// What the stored rows reveal at rest, row by row.
pub fn l_store(column: &Column, ids: &mut Ids, docs: &[Value]) -> Vec<RowLeakage> {
    let ordered: Vec<Vec<Segment>> = column
        .ordered
        .iter()
        .map(|p| p.segments().to_vec())
        .collect();
    docs.iter()
        .enumerate()
        .map(|(r, doc)| {
            let nodes = flatten(doc, ids.clauses.key_order);
            let entries = nodes
                .iter()
                .map(|node| {
                    let depth = node.positional.len();
                    let ordering = (ordered.iter().any(|o| covers(o, &node.positional))
                        && matches!(node.value, Value::Number(_) | Value::String(_)))
                    .then(|| ids.ordering(node.value));
                    let has_parent_tag = chains(depth, column.sealed_root);
                    let rule = has_parent_tag.then_some(match node.step {
                        Step::Member if ids.clauses.hit_rule => Rule::Member,
                        _ => Rule::Element,
                    });
                    EntryLeakage {
                        selector: ids.selector(&node.positional),
                        parent: node.parent,
                        step: node.step,
                        rule,
                        has_parent_tag,
                        self_tag: Some(ids.self_tag()),
                        ciphertext_len: ciphertext_len(node, column.sealed_root, doc),
                        ordering,
                    }
                })
                .collect();
            RowLeakage {
                sealed_root: column.sealed_root,
                keyset: 0,
                data_key: r,
                entries,
                projection: projection(ids, doc),
            }
        })
        .collect()
}

/// Every strict descendant of node `at` that chains from it: in the walk's
/// numbering these are the nodes after it up to the end of its subtree.
fn descendants(nodes: &[Node<'_>], at: usize, sealed_root: bool) -> Vec<usize> {
    let mut inside = vec![false; nodes.len()];
    inside[at] = true;
    let mut out = Vec::new();
    for (i, node) in nodes.iter().enumerate().skip(at + 1) {
        if node.parent.is_some_and(|p| inside[p]) && chains(node.positional.len(), sealed_root) {
            inside[i] = true;
            out.push(i);
        }
    }
    out
}

/// One concrete path a read sends a token for.
struct Concrete {
    path: Vec<Segment>,
    token: TokenName,
    probe: bool,
}

/// The concrete paths a read of `segs` sends tokens for, in the order the
/// client sends them (`subtree_key_for` and `Expansion::descend` in
/// `derive.rs`): each wildcard step expanded to the positions `0 … N − 1`,
/// each in turn, then the probe at `N`, the element itself.
fn expand(ids: &mut Ids, sealed_root: bool, segs: &[Segment], bound: u32) -> Vec<Concrete> {
    fn descend(
        ids: &mut Ids,
        segs: &[Segment],
        bound: u32,
        at: Vec<Segment>,
        token: TokenName,
        k: usize,
        out: &mut Vec<Concrete>,
    ) {
        let Some(segment) = segs.get(k) else {
            out.push(Concrete {
                path: at,
                token,
                probe: false,
            });
            return;
        };
        let step = |i: u64, at: &[Segment], token: &TokenName, ids: &mut Ids| {
            let mut path = at.to_vec();
            path.push(Segment::Index(i));
            let s = ids.selector(&path);
            let mut token = token.clone();
            token.steps.push(TokenStep::Element(s, i));
            (path, token)
        };
        match segment {
            Segment::Key(key) => {
                let mut path = at;
                path.push(Segment::Key(key.clone()));
                let s = ids.selector(&path);
                let mut token = token;
                token.steps.push(TokenStep::Member(s));
                descend(ids, segs, bound, path, token, k + 1, out);
            }
            Segment::Index(i) => {
                let (path, token) = step(*i, &at, &token, ids);
                descend(ids, segs, bound, path, token, k + 1, out);
            }
            Segment::Wildcard => {
                for i in 0..u64::from(bound) {
                    let (path, token) = step(i, &at, &token, ids);
                    descend(ids, segs, bound, path, token, k + 1, out);
                }
                let (path, token) = step(u64::from(bound), &at, &token, ids);
                out.push(Concrete {
                    path,
                    token,
                    probe: true,
                });
            }
        }
    }

    let mut out = Vec::new();
    match segs.first() {
        // Under the sealed root the chain starts at the heads, each a PRF
        // of its path; a wildcard head is each position's head in turn.
        Some(first) if sealed_root => {
            let heads: Vec<(Segment, bool)> = match first {
                Segment::Wildcard => (0..u64::from(bound))
                    .map(|i| (Segment::Index(i), false))
                    .chain(std::iter::once((Segment::Index(u64::from(bound)), true)))
                    .collect(),
                step => vec![(step.clone(), false)],
            };
            for (step, probe) in heads {
                let at = vec![step];
                let token = TokenName {
                    head: ids.head(&at),
                    steps: Vec::new(),
                };
                if probe {
                    out.push(Concrete {
                        path: at,
                        token,
                        probe,
                    });
                } else {
                    descend(ids, segs, bound, at, token, 1, &mut out);
                }
            }
        }
        // `$` itself, under either root, or any path from an open root.
        _ => {
            let token = TokenName {
                head: ids.head(&[]),
                steps: Vec::new(),
            };
            descend(ids, segs, bound, Vec::new(), token, 0, &mut out);
        }
    }
    out
}

/// What one query reveals, over the stored `docs`.
pub fn l_query(column: &Column, ids: &mut Ids, docs: &[Value], query: &Query) -> QueryLeakage {
    match query {
        Query::Extract(path) => QueryLeakage::Extract {
            selector: ids.selector(&segments(path)),
        },
        Query::Subtree {
            path,
            bound,
            budget,
        } => {
            let order = ids.clauses.key_order;
            let flattened: Vec<Vec<Node<'_>>> = docs.iter().map(|d| flatten(d, order)).collect();
            let positions: Vec<HashMap<&[Segment], usize>> = flattened
                .iter()
                .map(|nodes| {
                    nodes
                        .iter()
                        .enumerate()
                        .map(|(i, n)| (n.positional.as_slice(), i))
                        .collect()
                })
                .collect();
            let reads = expand(ids, column.sealed_root, &segments(path), *bound)
                .into_iter()
                .map(|concrete| {
                    let hits: Vec<Option<usize>> = positions
                        .iter()
                        .map(|at| at.get(concrete.path.as_slice()).copied())
                        .collect();
                    let reach = hits
                        .iter()
                        .zip(&flattened)
                        .map(|(hit, nodes)| {
                            hit.map(|at| descendants(nodes, at, column.sealed_root))
                                .unwrap_or_default()
                        })
                        .collect();
                    ReadLeak {
                        token: concrete.token,
                        probe: concrete.probe,
                        hits,
                        reach,
                    }
                })
                .collect();
            QueryLeakage::Subtree {
                reads,
                budget: *budget,
            }
        }
        Query::Contains(needle) => {
            let alt = (!matches!(needle, Value::Object(_) | Value::Array(_))).then(|| {
                let s = ids.selector(&[Segment::Wildcard]);
                GroupLeakage {
                    pairs: vec![(s, ids.value(s, needle))],
                    elements: Vec::new(),
                }
            });
            QueryLeakage::Contains {
                needle: projection(ids, needle),
                alt,
            }
        }
        Query::Equals(path, value) => {
            let needle = segments(path)
                .iter()
                .rev()
                .fold(value.clone(), |inner, segment| match segment {
                    Segment::Key(key) => {
                        let mut map = serde_json::Map::new();
                        let _ = map.insert(key.clone(), inner);
                        Value::Object(map)
                    }
                    Segment::Index(_) | Segment::Wildcard => Value::Array(vec![inner]),
                });
            QueryLeakage::Equals {
                needle: projection(ids, &needle),
            }
        }
        Query::Order(path, value) => QueryLeakage::Order {
            selector: ids.selector(&segments(path)),
            bound: ids.ordering(value),
        },
    }
}

/// `L` over a whole column: [`l_store`] for the rows, then [`l_query`] for
/// each query in turn, over one set of names.
pub fn leak(column: &Column, clauses: Clauses, docs: &[Value], queries: &[Query]) -> Leakage {
    let mut ids = Ids::new(clauses);
    let rows = l_store(column, &mut ids, docs);
    let queries = queries
        .iter()
        .map(|q| l_query(column, &mut ids, docs, q))
        .collect();
    Leakage {
        key_tag_len: KEY_TAG_LEN,
        stored_order: StoredOrder::Random,
        sent_order: SentOrder::Random,
        rows,
        queries,
        ordering_ranks: ids.ordering_ranks(),
        kind_order: KindOrder::ByKey,
        ordering_prefixes: ids.ordering_prefixes(),
    }
}
