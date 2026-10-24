//! The leakage profile `L`: what `packages/eql/docs/reference/json-tree-leakage.md`
//! says the database learns, written as a function of the plaintext alone.
//!
//! [`l_store`] is what a set of stored rows reveals, [`l_query`] what one
//! query reveals on top of them. Neither takes a key or calls the crate: they
//! read the documents, the column's options and the query, and they name
//! every keyed value (a selector, a value selector, a token, an ordering
//! term) by an opaque integer that is equal wherever the real values are
//! equal, so the profile states equality patterns and never names. The
//! simulator ([`super::simulator`]) builds a wire-shaped world from this
//! output and its own randomness, and the distinguishers
//! ([`super::distinguishers`]) compare it with the real one.
//!
//! Each field of the leakage types is one clause, and its doc comment quotes
//! the sentence of the page it encodes. Where the page is vague the clause is
//! as precise as the code forces, and says so. One clause is marked
//! **beyond the page**: the code reveals it and the page does not say so.
//! [`Clauses::page_only`] turns it off, and the calibration shows a
//! distinguisher separating that profile from the real scheme.
//!
//! **This module is expected to change with the format.** The design change
//! of 2026-10-24 (member tokens without ordinals, a self tag `x` on every
//! entry, wildcards expanded on the client, no gates;
//! `docs/plans/2026-10-17-json-tree-index.md`, "Design change (2026-10-24)")
//! rewrites the subtree clauses of [`QueryLeakage`] and adds a clause for
//! `x`. When it lands, this file and the real-side adapter
//! ([`super::real`]) change together with the leakage page; the simulator
//! changes where the wire does; the distinguishers should not need to.

use std::collections::HashMap;
use std::hash::Hash;

use serde_json::{Number, Value};
use stack_encrypt::json::{JsonPath, Segment};

/// What every entry's ciphertext adds to its plaintext: the frame's version
/// byte, the 96-bit random nonce and the 128-bit GCM tag
/// (`vitaminc-encrypt`'s `Aes256Cipher`). The page's "less the AEAD's fixed
/// overhead".
pub const AEAD_OVERHEAD: usize = 1 + 12 + 16;

/// The length of the ZeroKMS key tag the header carries. The fake key source
/// the tests seal under mints 32-byte tags; it is a property of the key
/// service, not of any document, so it is a column constant here.
pub const KEY_TAG_LEN: usize = 32;

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
    /// A subtree read of a path (`json_tree_subtree`, `json_tree_subtree_at`).
    Subtree(String),
    /// Containment, `@>`, of a needle document.
    Contains(Value),
    /// Equality at a path, `AtPath<Eq>`, of a scalar.
    Equals(String, Value),
    /// An ordering bound at a path, `AtPath<Gte>`, of a number or string.
    Order(String, Value),
}

/// Which sort "the sorted order of their key names" means. The page does
/// not say; the code sorts by the keys' UTF-8 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrder {
    /// Byte order of the UTF-8 key: serde_json's `Map` without
    /// `preserve_order`, which is what the walk iterates.
    Utf8Bytes,
    /// PostgreSQL `jsonb`'s own order: shorter keys first, then bytes. The
    /// other reading a reader of the page could reasonably take.
    JsonbLengthFirst,
}

/// The clauses of the profile that are on or off as a whole, and the one
/// reading the page leaves open. The default is what the code needs;
/// [`Clauses::page_only`] is the page as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clauses {
    /// How "an object's members in the sorted order of their key names"
    /// sorts.
    pub key_order: KeyOrder,
    /// **Beyond the page.** An ordering term's length: `8 × n + 1` bytes for
    /// a value encoded in `n` bytes (`clww-ore`'s `OpeClww8VariableV1`). A
    /// number encodes in eight bytes, so its term is 65 bytes; a string in
    /// its UTF-8 bytes and one more, so its term is `8 × (len + 1) + 1`
    /// bytes and gives its length. The page says only that "a term's
    /// presence at an ordered path also says the leaf is a number or a
    /// string"; the length also says which, unless the string is seven bytes
    /// long, and repeats the string's length that `c` already shows. Off,
    /// every term is stated as one length.
    pub ordering_term_length: bool,
}

impl Default for Clauses {
    fn default() -> Self {
        Self {
            key_order: KeyOrder::Utf8Bytes,
            ordering_term_length: true,
        }
    }
}

impl Clauses {
    /// The page as written: every clause beyond it off.
    pub fn page_only() -> Self {
        Self {
            key_order: KeyOrder::Utf8Bytes,
            ordering_term_length: false,
        }
    }
}

/// An opaque name for a path selector `s`: equal for every node anywhere in
/// the column whose wildcard-folded path is the same.
pub type SelId = usize;
/// An opaque name for a value selector `vs`.
pub type ValueId = usize;
/// An opaque name for a chain head's token.
pub type HeadId = usize;
/// An opaque name for an ordering term's value: equal for equal values.
pub type OrderClass = usize;

/// How a node hangs off its parent, which decides its ordinal under the
/// parent's token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Root,
    /// An object member: its ordinal is its keyed rank among its siblings.
    Member,
    /// An array element at this position, which is its ordinal.
    Element(u64),
}

/// The ordering term of one leaf, or of one query bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderingLeak {
    /// "The order of that leaf's value among every row that holds one, and
    /// which rows hold equal values." Equal values share a class; the
    /// classes' order is [`Leakage::ordering_ranks`].
    pub class: OrderClass,
    /// **Beyond the page** ([`Clauses::ordering_term_length`]): the term's
    /// length in bytes.
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
    /// The shape: the position in [`RowLeakage::entries`] of this node's
    /// parent. "Which selector's path sits under which is not written down,
    /// but it is the same in every row, so an observer comparing rows learns
    /// it, and with it each row's parent and child relations and the node
    /// count of every subtree." The simulator uses it to place the chain
    /// below a token a query sends; at rest the order clause
    /// ([`RowLeakage::entries`]) is what shows it.
    pub parent: Option<usize>,
    /// How the node hangs off its parent, which a token's holder sees in the
    /// ordinals it probes: an element's ordinal is its position. The page
    /// says a token's holder can "see how the nodes nest, link each one to
    /// its parent"; it does not say that it also sees each element's
    /// position and each member's keyed rank. Vague; stated here as the code
    /// forces it.
    pub step: Step,
    /// The chain head this entry is, if it is one: under the sealed root a
    /// top-level field ("the top-level field the path starts with"), with the
    /// root open the root. A head's token is a keyed function of its path,
    /// "column-wide", so every row's entry at that path is one head.
    pub head: Option<HeadId>,
    /// "Which entries carry no `p` does show: with the sealed root on, those
    /// are the root's direct members […] With the sealed root off, only the
    /// root lacks one." (The root lacks one under the sealed root too.)
    pub has_parent_tag: bool,
    /// "Each ciphertext's length […] for each node the length of its key name
    /// (for an object member) plus, for a scalar, the length of its value,
    /// exactly, less the AEAD's fixed overhead. […] With the sealed root on,
    /// the root entry's length is the document's length as JSON." The fixed
    /// parts the page leaves out are written in [`ciphertext_len`].
    pub ciphertext_len: usize,
    /// "`op`, the ordering term, only on number and string leaves at the
    /// paths the index orders."
    pub ordering: Option<OrderingLeak>,
}

/// One group of a projection, stored (`q`) or sent (a needle).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupLeakage {
    /// "One `{s, vs}` pair per node, […] in the same order": the pairs of the
    /// nodes that sit directly in this group, in the walk's order.
    /// "Whether two rows hold the same value at the same path, through the
    /// value selector `vs`, a keyed hash of the path and the value (for an
    /// object or an array, of its kind alone)."
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
    /// row.
    pub data_key: usize,
    /// "The number of entries", and the entries in their stored order:
    /// "Entries are stored in depth-first order, the root first, each node
    /// followed by everything beneath it, and an object's members in the
    /// sorted order of their key names." The page does not say which sort;
    /// the code's is the keys' UTF-8 bytes (serde_json's `Map` without
    /// `preserve_order`), so that is the order here.
    pub entries: Vec<EntryLeakage>,
    /// The containment projection `q`.
    pub projection: GroupLeakage,
}

/// A gate of a subtree read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateLeak {
    /// "A gate is the step's selector".
    Selector(SelId),
    /// "or, for an array position, `#n:<selector>`, with the position `n` in
    /// the clear."
    Slot(u64, SelId),
}

/// The token a subtree read sends, by name: a head, then the array positions
/// the client chains below it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenName {
    pub head: HeadId,
    /// Each position step after the head: the element selector and the
    /// position.
    pub positions: Vec<(SelId, u64)>,
}

/// What one query reveals, beyond the rows it returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryLeakage {
    /// "Path extraction […] The selector of the path asked. A position in the
    /// path reads as the wildcard, so a position is not sent."
    Extract { selector: SelId },
    /// "A subtree read […] A token, and one gate per step below it. The token
    /// is not the token of the node you asked for: it is the token of the
    /// deepest node on the path the client can derive, which is the
    /// top-level field the path starts with or, while the path goes on
    /// through array positions, the element they reach."
    Subtree {
        token: TokenName,
        gates: Vec<GateLeak>,
        /// Per row, the entries the token lets the database link: "A token
        /// is a capability over the structure of its node's subtree in every
        /// row of the column: whoever holds it can find each node under that
        /// field in any row, see how the nodes nest, link each one to its
        /// parent, and derive the tokens of the nodes beneath." So: every
        /// strict descendant of the token's node, in every row.
        reach: Vec<Vec<usize>>,
        /// Per row, the nodes the path names (what the walk returns at depth
        /// `0`). Not a clause of its own: the database computes it from the
        /// token, the gates and the rows. Carried so a mutant profile can
        /// narrow `reach` to what a read would reveal if the token covered
        /// only the path asked (`token_reaches_named_nodes_only`).
        named: Vec<Vec<usize>>,
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

/// The leakage of a whole column: its rows and its queries, over one shared
/// set of opaque names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leakage {
    /// "The keyset the data key was minted under […] the same for every
    /// column it seals": one keyset per column, and the ZeroKMS tag's length.
    pub key_tag_len: usize,
    pub rows: Vec<RowLeakage>,
    pub queries: Vec<QueryLeakage>,
    /// The rank of each [`OrderClass`] among all of them: "the order of that
    /// leaf's value among every row that holds one", and the bound's "place
    /// in the order of the stored values at every ordered path" ("leaves at
    /// two ordered paths compare with each other too").
    pub ordering_ranks: Vec<usize>,
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
/// derived from `as_f64`); strings by their bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum OrderKey {
    Number(u64),
    String(Vec<u8>),
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

    fn ordering(&mut self, value: &Value) -> OrderingLeak {
        let (key, len) = match value {
            Value::Number(n) => {
                let f = n.as_f64().expect("a JSON number has an f64");
                assert!(
                    f != 0.0 || f.is_sign_positive(),
                    "the corpus has no -0.0, whose term the page does not describe"
                );
                (OrderKey::Number(f.to_bits()), 8 * 8 + 1)
            }
            Value::String(s) => (
                OrderKey::String(s.as_bytes().to_vec()),
                8 * (s.len() + 1) + 1,
            ),
            _ => unreachable!("only numbers and strings carry a term"),
        };
        let class = self.ordering.id(key.clone());
        if class == self.ordering_keys.len() {
            self.ordering_keys.push(key);
        }
        OrderingLeak {
            class,
            len: if self.clauses.ordering_term_length {
                len
            } else {
                65
            },
        }
    }

    /// The rank of every ordering class. The page does not say how a
    /// number's term compares with a string's, so a column that orders both
    /// is refused rather than guessed at.
    pub fn ordering_ranks(&self) -> Vec<usize> {
        let numbers = self
            .ordering_keys
            .iter()
            .any(|k| matches!(k, OrderKey::Number(_)));
        let strings = self
            .ordering_keys
            .iter()
            .any(|k| matches!(k, OrderKey::String(_)));
        assert!(
            !(numbers && strings),
            "the page does not say how a number's ordering term compares with a string's; \
             a world orders one kind of leaf"
        );
        let mut order: Vec<usize> = (0..self.ordering_keys.len()).collect();
        order.sort_by(
            |&a, &b| match (&self.ordering_keys[a], &self.ordering_keys[b]) {
                (OrderKey::Number(x), OrderKey::Number(y)) => {
                    f64::from_bits(*x).total_cmp(&f64::from_bits(*y))
                }
                (OrderKey::String(x), OrderKey::String(y)) => x.cmp(y),
                _ => unreachable!("refused above"),
            },
        );
        let mut ranks = vec![0; order.len()];
        for (rank, class) in order.into_iter().enumerate() {
            ranks[class] = rank;
        }
        ranks
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

/// One node of a document in its stored order.
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

/// A document's nodes in the order the page says they are stored:
/// depth-first, the root first, an object's members in `order`, an array's
/// elements in position order.
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
                    let is_head = if column.sealed_root {
                        depth == 1
                    } else {
                        depth == 0
                    };
                    let ordering = (ordered.iter().any(|o| covers(o, &node.positional))
                        && matches!(node.value, Value::Number(_) | Value::String(_)))
                    .then(|| ids.ordering(node.value));
                    EntryLeakage {
                        selector: ids.selector(&node.positional),
                        parent: node.parent,
                        step: node.step,
                        head: is_head.then(|| ids.head(&node.positional)),
                        has_parent_tag: depth > 0 && !(column.sealed_root && depth == 1),
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

/// The nodes of `nodes` that `pattern` reaches, as `JsonPath::select` finds
/// them: a key step into an array, or a position into an object, reaches
/// nothing.
fn reached(nodes: &[Node<'_>], pattern: &[Segment]) -> Vec<usize> {
    (0..nodes.len())
        .filter(|&i| covers(pattern, &nodes[i].positional))
        .collect()
}

/// Every strict descendant of node `at`: in the stored order these are the
/// positions after it up to the end of its subtree.
fn descendants(nodes: &[Node<'_>], at: usize) -> Vec<usize> {
    let mut inside = vec![false; nodes.len()];
    inside[at] = true;
    let mut out = Vec::new();
    for (i, node) in nodes.iter().enumerate().skip(at + 1) {
        if node.parent.is_some_and(|p| inside[p]) {
            inside[i] = true;
            out.push(i);
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
        Query::Subtree(path) => {
            let segs = segments(path);
            // The head: under the sealed root the top-level field (or
            // element) the path starts with, with the root open the root.
            let split = usize::from(column.sealed_root);
            assert!(
                segs.len() >= split && !segs[..split].contains(&Segment::Wildcard),
                "under the sealed root a subtree read names a top-level node: {path}"
            );
            let (head_path, rest) = segs.split_at(split);
            let head = ids.head(head_path);
            let mut prefix = head_path.to_vec();
            let mut positions = Vec::new();
            let mut gates = Vec::new();
            let mut chaining = true;
            for segment in rest {
                prefix.push(segment.clone());
                match (segment, chaining) {
                    (Segment::Index(i), true) => positions.push((ids.selector(&prefix), *i)),
                    (Segment::Index(i), false) => {
                        gates.push(GateLeak::Slot(*i, ids.selector(&prefix)))
                    }
                    (Segment::Key(_) | Segment::Wildcard, _) => {
                        chaining = false;
                        gates.push(GateLeak::Selector(ids.selector(&prefix)));
                    }
                }
            }
            let token_path = &segs[..split + positions.len()];
            let order = ids.clauses.key_order;
            let (reach, named) = docs
                .iter()
                .map(|doc| {
                    let nodes = flatten(doc, order);
                    let at = nodes.iter().position(|n| n.positional == token_path);
                    let reach = at.map(|at| descendants(&nodes, at)).unwrap_or_default();
                    let named = if gates.is_empty() {
                        at.into_iter().collect()
                    } else {
                        reached(&nodes, &segs)
                    };
                    (reach, named)
                })
                .unzip();
            QueryLeakage::Subtree {
                token: TokenName { head, positions },
                gates,
                reach,
                named,
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
        rows,
        queries,
        ordering_ranks: ids.ordering_ranks(),
    }
}
