//! The simulator: a wire-shaped world built from a [`Leakage`] and
//! randomness, with no plaintext and no key.
//!
//! Every keyed value is a fresh random string per opaque name (a selector
//! per [`SelId`](super::profile::SelId), a value selector per
//! [`ValueId`](super::profile::ValueId), a head token per
//! [`HeadId`](super::profile::HeadId), a self tag per
//! [`SelfTagId`](super::profile::SelfTagId)), so equality patterns are
//! exactly the profile's. Ciphertexts are random bytes of the stated length
//! behind the frame's public version byte. Ordering terms have CLLW OPE's
//! public layout under a key the simulator draws, over codes built from the
//! profile's ranks, lengths and shared prefixes, so they compare, repeat
//! and share leading bytes exactly as the profile says.
//!
//! The chain is the one place the simulator evaluates the real scheme's
//! public functions ([`super::chain`]): a token the database is sent has to
//! find the node the profile says it names, by that node's self tag, and
//! link the entries the profile says it reaches, by their parent tags and
//! self tags, with the real hash, or the database would notice. So the
//! simulator derives each token a query sends from its random head and the
//! steps the profile names (the member rule or the element rule, as the
//! client does), writes the self tag of that token on each entry the token
//! names, and below it chains every entry the token reaches: its parent tag
//! from its parent's token and its ordinal (an element's position, or a
//! member's rank under a keyed function the simulator samples itself), its
//! self tag from its own token, by the rule the profile states for it.
//! Every other parent and self tag is random bytes, as a tag under a token
//! the database never sees is to it.
//!
//! The stored order is drawn as the crate draws it
//! ([`StoredOrder::Random`]): per row, the root at slot `0` and the other
//! nodes at a uniformly random permutation of the slots `1..n`, and every
//! list of the stored `q` shuffled, each by Fisher–Yates over the
//! simulator's generator. The profile names nodes, not slots, so the tags
//! the chain programs follow each node to wherever it is stored. A needle's
//! lists are shuffled the same way, afresh for each query
//! ([`SentOrder::Random`]), as the client shuffles them.

use std::collections::{BTreeMap, HashMap};

use base64ct::{Base64, Encoding};
use proptest::prelude::RngCore;
use proptest::test_runner::TestRng;
use serde_json::{json, Value};

use super::chain::{
    cllw_ope, element_token, member_token, parent_tag, self_tag, shared_bits, simulated_rank, Rule,
    Tag16, Tag8,
};
use super::observe::QueryKind;
use super::profile::{
    GroupLeakage, KindOrder, Leakage, OrderKind, OrderingLeak, Placement, QueryLeakage, RowLeakage,
    SentOrder, Step, StoredOrder, TokenName, TokenStep,
};

/// The version byte `vitaminc-encrypt` writes at the front of every
/// ciphertext: public framing, not leakage.
pub const CIPHERTEXT_FRAME: u8 = 2;

/// A fixed-size random value per name, drawn on first use.
struct Names<const N: usize> {
    bytes: HashMap<usize, [u8; N]>,
}

impl<const N: usize> Names<N> {
    fn new() -> Self {
        Self {
            bytes: HashMap::new(),
        }
    }

    fn get(&mut self, id: usize, rng: &mut TestRng) -> [u8; N] {
        *self.bytes.entry(id).or_insert_with(|| random(rng))
    }
}

fn random<const N: usize>(rng: &mut TestRng) -> [u8; N] {
    let mut out = [0; N];
    rng.fill_bytes(&mut out);
    out
}

fn random_vec(rng: &mut TestRng, len: usize) -> Vec<u8> {
    let mut out = vec![0; len];
    rng.fill_bytes(&mut out);
    out
}

fn b64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// A uniform shuffle of `items` (Fisher–Yates). Each draw reduces a 64-bit
/// word modulo at most a few hundred, a bias below `2^-55`.
fn shuffle<T>(items: &mut [T], rng: &mut TestRng) {
    for i in (1..items.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

/// The tags a row's entries carry where some query's token links them.
#[derive(Default)]
struct Linked {
    x: HashMap<usize, Tag8>,
    p: HashMap<usize, Tag8>,
}

struct Simulator<'a> {
    leakage: &'a Leakage,
    rng: &'a mut TestRng,
    selectors: Names<16>,
    values: Names<16>,
    heads: Names<16>,
    keysets: Names<16>,
    ivs: Names<16>,
    self_tags: Names<8>,
    tags: HashMap<usize, Vec<u8>>,
    ordering: HashMap<usize, Vec<u8>>,
    rank_key: [u8; 32],
}

/// Build the rows' wire JSON and the queries' wire JSON from `leakage` and
/// `rng` alone. Where the profile leaves the place of the strings' ordering
/// terms among the numbers' to the column's key and the column orders both,
/// they go at `placement`, or at one drawn from `rng` for `None`: the
/// calibration passes each placement a key could pick in turn.
pub fn simulate(
    leakage: &Leakage,
    rng: &mut TestRng,
    placement: Option<Placement>,
) -> (Vec<Value>, Vec<(QueryKind, Value)>) {
    let rank_key = random(rng);
    let ordering = ordering_terms(leakage, rng, placement);
    let mut sim = Simulator {
        leakage,
        rng,
        selectors: Names::new(),
        values: Names::new(),
        heads: Names::new(),
        keysets: Names::new(),
        ivs: Names::new(),
        self_tags: Names::new(),
        tags: HashMap::new(),
        ordering,
        rank_key,
    };
    let linked = sim.link();
    let rows = leakage
        .rows
        .iter()
        .zip(linked)
        .map(|(row, linked)| sim.row(row, &linked))
        .collect();
    let queries = leakage.queries.iter().map(|q| sim.query(q)).collect();
    (rows, queries)
}

/// Every ordering class's term: a CLLW OPE term ([`cllw_ope`]) under its
/// kind's key over a code of the class's bit length, each kind's codes built
/// in rank order from the profile's shared prefixes alone ([`successor`]).
/// So within a kind the terms compare as the ranks do, are equal where the
/// classes are, are as long as the profile says, and share leading bytes
/// exactly as far as the profile says the values' encodings share leading
/// bits. Where a column orders both kinds, the two keys are drawn until the
/// strings' terms fall at `placement` among the numbers' ([`placed`]): the
/// one the profile fixes, else the one given, else one drawn at random, as
/// a column's key picks one.
fn ordering_terms(
    leakage: &Leakage,
    rng: &mut TestRng,
    placement: Option<Placement>,
) -> HashMap<usize, Vec<u8>> {
    let mut classes: BTreeMap<usize, (OrderKind, usize)> = BTreeMap::new();
    let mut note = |op: &OrderingLeak| {
        let _ = classes.insert(op.class, (op.kind, op.len - 1));
    };
    for row in &leakage.rows {
        for op in row.entries.iter().filter_map(|e| e.ordering.as_ref()) {
            note(op);
        }
    }
    for query in &leakage.queries {
        if let QueryLeakage::Order { bound, .. } = query {
            note(bound);
        }
    }
    let mut codes: HashMap<usize, (OrderKind, Vec<bool>)> = HashMap::new();
    for kind in [OrderKind::Number, OrderKind::String] {
        let mut mine: Vec<usize> = classes
            .iter()
            .filter(|(_, (k, _))| *k == kind)
            .map(|(&class, _)| class)
            .collect();
        mine.sort_by_key(|&class| (leakage.ordering_ranks[class], class));
        let mut previous: Option<(usize, Vec<bool>)> = None;
        for class in mine {
            let n = classes[&class].1;
            let code = match &previous {
                None => vec![false; n],
                Some((below, code)) => successor(
                    code,
                    n,
                    leakage.ordering_prefixes.get(&(*below, class)).copied(),
                ),
            };
            let _ = codes.insert(class, (kind, code.clone()));
            previous = Some((class, code));
        }
    }
    let both = [OrderKind::Number, OrderKind::String]
        .iter()
        .all(|kind| codes.values().any(|(k, _)| k == kind));
    let target = match leakage.kind_order {
        KindOrder::Fixed(fixed) => fixed,
        KindOrder::ByKey => {
            placement.unwrap_or_else(|| Placement::ALL[(rng.next_u32() % 3) as usize])
        }
    };
    for _ in 0..100_000 {
        let keys: [[u8; 32]; 2] = [random(rng), random(rng)];
        let terms: HashMap<usize, Vec<u8>> = codes
            .iter()
            .map(|(&class, (kind, code))| {
                let key = &keys[usize::from(*kind == OrderKind::String)];
                (class, cllw_ope(key, code))
            })
            .collect();
        if !both || placed(&terms, &codes, target) {
            return terms;
        }
    }
    panic!("no two keys put the strings {target:?} in 100,000 tries")
}

/// Whether the strings' terms sit at `placement` among the numbers': each
/// string below or above every number whose code begins with 0 (a negative
/// one, or every number where none is negative) as `placement` says, and
/// likewise for those whose code begins with 1, and sharing no leading
/// byte with any of them, as a number's and a string's term under two keys
/// share none. A pair of keys under which some string and some number tie
/// to within a carry at the front (about one pair in forty) is refused: a
/// real key like that makes a few such pairs compare by their later bytes,
/// which no clause states (`mod.rs`, "Out of reach").
fn placed(
    terms: &HashMap<usize, Vec<u8>>,
    codes: &HashMap<usize, (OrderKind, Vec<bool>)>,
    placement: Placement,
) -> bool {
    let of = |kind: OrderKind| {
        codes
            .iter()
            .filter(move |(_, (k, _))| *k == kind)
            .map(|(class, (_, code))| (&terms[class], code[0]))
    };
    of(OrderKind::String).all(|(string, _)| {
        of(OrderKind::Number).all(|(number, high)| {
            let above = match (placement, high) {
                (Placement::Below, _) | (Placement::Between, true) => false,
                (Placement::Above, _) | (Placement::Between, false) => true,
            };
            (string > number) == above && shared_bits(string, number) == 0
        })
    })
}

/// The least `n`-bit code above `below` that shares `shared` leading bits
/// with it. Codes built this way, in rank order from all zeros, share
/// exactly the prefixes the profile states, which is what any set of real
/// encodings does: at the bit where two neighbours part, the lower one has a
/// zero, which is where the code puts its one. A profile that states no
/// prefix (`None`, a mutant's) gets the latest branch that still sorts
/// above `below`; one that states an impossible prefix gets the nearest
/// branch before it, so a mutant's world still builds.
fn successor(below: &[bool], n: usize, shared: Option<usize>) -> Vec<bool> {
    let m = below.len();
    let extends = match shared {
        Some(l) => l >= m && m < n,
        None => m < n,
    };
    if extends {
        let mut code = below.to_vec();
        code.resize(n, false);
        return code;
    }
    let last = shared
        .unwrap_or(n)
        .min(n.saturating_sub(1))
        .min(m.saturating_sub(1));
    let mut code: Vec<bool> = match (0..=last).rev().find(|&i| !below[i]) {
        Some(at) => {
            let mut code = below[..at].to_vec();
            code.push(true);
            code
        }
        None => below[..n.min(m)].to_vec(),
    };
    code.resize(n, false);
    code
}

impl Simulator<'_> {
    fn selector(&mut self, id: usize) -> Tag16 {
        self.selectors.get(id, self.rng)
    }

    fn iv(&mut self, row: &RowLeakage) -> Tag16 {
        self.ivs.get(row.data_key, self.rng)
    }

    /// The token the client derives for `name`: its head's random token,
    /// then each step by its rule.
    fn token(&mut self, name: &TokenName) -> Tag16 {
        let mut t = self.heads.get(name.head, self.rng);
        for step in &name.steps {
            t = match *step {
                TokenStep::Member(s) => member_token(&t, &self.selector(s)),
                TokenStep::Element(s, i) => element_token(
                    &t,
                    &self.selector(s),
                    u32::try_from(i).expect("a small position"),
                ),
            };
        }
        t
    }

    /// The ordering term of class `class`, `len` bytes long: built once for
    /// every class by [`ordering_terms`].
    fn ordering(&self, class: usize, len: usize) -> Vec<u8> {
        let bytes = &self.ordering[&class];
        assert_eq!(bytes.len(), len, "one class, one length");
        bytes.clone()
    }

    /// A projection's wire form: in the walk's order, or with every list
    /// shuffled, as a stored `q` is under [`StoredOrder::Random`] and a
    /// needle under [`SentOrder::Random`].
    fn group(&mut self, group: &GroupLeakage, shuffled: bool) -> Value {
        let mut pairs: Vec<Value> = group
            .pairs
            .iter()
            .map(|&(s, vs)| {
                let s = self.selector(s);
                let vs = self.values.get(vs, self.rng);
                json!({"s": b64(&s), "vs": b64(&vs)})
            })
            .collect();
        let mut elements: Vec<Value> = group
            .elements
            .iter()
            .map(|g| self.group(g, shuffled))
            .collect();
        if shuffled {
            shuffle(&mut pairs, self.rng);
            shuffle(&mut elements, self.rng);
        }
        json!({"sv": pairs, "el": elements})
    }

    /// The slot each of a row's `n` nodes is stored at, by its index in the
    /// profile's numbering: the root at `0` and the rest at a uniformly
    /// random permutation of `1..n`, or the numbering itself where the
    /// profile states the depth-first order.
    fn slots(&mut self, n: usize) -> Vec<usize> {
        let mut slots: Vec<usize> = (0..n).collect();
        if self.leakage.stored_order == StoredOrder::Random {
            if let Some(rest) = slots.get_mut(1..) {
                shuffle(rest, self.rng);
            }
        }
        slots
    }

    /// Entry `i`'s ordinal under its parent, whose token is `parent`: an
    /// element's position, or a member's place in the random permutation
    /// its object's members are given in this row (simulated as a rank
    /// under the simulator's own key, salted by the row).
    fn ordinal(&mut self, row: &RowLeakage, i: usize, parent: &Tag16) -> u32 {
        let entry = &row.entries[i];
        match entry.step {
            Step::Element(n) => u32::try_from(n).expect("a small array"),
            Step::Member => {
                let iv = self.iv(row);
                let mine = self.selector(entry.selector);
                let my_rank = simulated_rank(&self.rank_key, &iv, parent, &mine);
                let siblings: Vec<usize> = (0..row.entries.len())
                    .filter(|&j| {
                        row.entries[j].parent == entry.parent && row.entries[j].step == Step::Member
                    })
                    .collect();
                let below = siblings
                    .into_iter()
                    .filter(|&j| {
                        let theirs = self.selector(row.entries[j].selector);
                        simulated_rank(&self.rank_key, &iv, parent, &theirs) < my_rank
                    })
                    .count();
                u32::try_from(below).expect("a small object")
            }
            Step::Root => 0,
        }
    }

    /// The self and parent tags every query's tokens link, row by row:
    /// each token's self tag on the entry it names, and below it the chain
    /// over the entries it reaches.
    ///
    /// Shallower named nodes first, so that where two reads link one entry
    /// the one that names it last sets its tags, and every chain below it
    /// is derived from that. Under the full profile the two always agree;
    /// under a profile that states other rules than the code's (the page as
    /// #1363 published it), this is what keeps the world consistent: a
    /// node a read names keeps the token the read sends, as the database's
    /// test of the member rule first then finds it.
    fn link(&mut self) -> Vec<Linked> {
        let mut linked: Vec<Linked> = self
            .leakage
            .rows
            .iter()
            .map(|_| Linked::default())
            .collect();
        let leakage = self.leakage;
        let depth = |row: &RowLeakage, mut at: usize| {
            let mut d = 0;
            while let Some(p) = row.entries[at].parent {
                d += 1;
                at = p;
            }
            d
        };
        let mut work = Vec::new();
        for query in &leakage.queries {
            let QueryLeakage::Subtree { reads, .. } = query else {
                continue;
            };
            for read in reads {
                let t = self.token(&read.token);
                for (r, row) in leakage.rows.iter().enumerate() {
                    let named = read.hits[r].map_or(0, |h| depth(row, h));
                    work.push((named, work.len(), r, t, read));
                }
            }
        }
        work.sort_by_key(|&(named, order, ..)| (named, order));
        for (_, _, r, t, read) in work {
            let row = &leakage.rows[r];
            let iv = self.iv(row);
            let mut tokens: HashMap<usize, Tag16> = HashMap::new();
            if let Some(h) = read.hits[r] {
                let _ = linked[r].x.insert(h, self_tag(&iv, &t));
                let _ = tokens.insert(h, t);
            }
            // Parents before children: the profile's numbering puts them
            // first, but a mutant's may not, so by depth.
            let mut reach = read.reach[r].clone();
            reach.sort_by_key(|&i| (depth(row, i), i));
            for c in reach {
                let entry = &row.entries[c];
                let Some(pt) = entry.parent.and_then(|p| tokens.get(&p).copied()) else {
                    continue;
                };
                let o = self.ordinal(row, c, &pt);
                let s = self.selector(entry.selector);
                let ct = match entry.rule {
                    Some(Rule::Member) => member_token(&pt, &s),
                    Some(Rule::Element) => element_token(&pt, &s, o),
                    None => continue,
                };
                // A node a read names keeps that read's token, as the
                // database's member-rule-first test then finds it.
                let ct = match linked[r].x.get(&c) {
                    Some(x) if *x == self_tag(&iv, &member_token(&pt, &s)) => member_token(&pt, &s),
                    _ => {
                        let _ = linked[r].x.insert(c, self_tag(&iv, &ct));
                        ct
                    }
                };
                if entry.has_parent_tag {
                    let _ = linked[r].p.insert(c, parent_tag(&iv, &pt, o));
                }
                let _ = tokens.insert(c, ct);
            }
        }
        linked
    }

    fn row(&mut self, row: &RowLeakage, linked: &Linked) -> Value {
        let iv = self.iv(row);
        let tag = self
            .tags
            .entry(row.data_key)
            .or_insert_with(|| random_vec(self.rng, self.leakage.key_tag_len))
            .clone();
        let keyset: [u8; 16] = self.keysets.get(row.keyset, self.rng);
        let mut header = vec![1, u8::from(row.sealed_root), 0, 0, 0, 0];
        header.extend_from_slice(&keyset);
        header.extend_from_slice(&iv);
        header.extend_from_slice(&u16::try_from(tag.len()).expect("a short tag").to_le_bytes());
        header.extend_from_slice(&tag);

        let by_node: Vec<Value> = row
            .entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let s = self.selector(entry.selector);
                let mut c = vec![CIPHERTEXT_FRAME];
                c.extend(random_vec(self.rng, entry.ciphertext_len - 1));
                let mut wire = json!({"s": b64(&s), "c": base85_simd::encode(&c)});
                if let Some(id) = entry.self_tag {
                    let x = match linked.x.get(&i) {
                        Some(x) => *x,
                        None => self.self_tags.get(id, self.rng),
                    };
                    wire["x"] = json!(b64(&x));
                }
                if entry.has_parent_tag {
                    let p: Tag8 = match linked.p.get(&i) {
                        Some(p) => *p,
                        None => random(self.rng),
                    };
                    wire["p"] = json!(b64(&p));
                }
                if let Some(op) = entry.ordering {
                    wire["op"] = json!(b64(&self.ordering(op.class, op.len)));
                }
                wire
            })
            .collect();
        let slots = self.slots(by_node.len());
        let mut entries = vec![Value::Null; by_node.len()];
        for (wire, slot) in by_node.into_iter().zip(slots) {
            entries[slot] = wire;
        }
        let q = self.group(
            &row.projection,
            self.leakage.stored_order == StoredOrder::Random,
        );
        json!({"h": b64(&header), "sv": entries, "q": q})
    }

    fn query(&mut self, query: &QueryLeakage) -> (QueryKind, Value) {
        match query {
            QueryLeakage::Extract { selector } => {
                (QueryKind::Extract, json!(b64(&self.selector(*selector))))
            }
            QueryLeakage::Subtree { reads, budget } => {
                let tokens: Vec<String> = reads
                    .iter()
                    .map(|read| b64(&self.token(&read.token)))
                    .collect();
                (QueryKind::Subtree, json!({"t": tokens, "budget": budget}))
            }
            QueryLeakage::Contains { needle, alt } => {
                let shuffled = self.leakage.sent_order == SentOrder::Random;
                let mut wire = self.group(needle, shuffled);
                if let Some(alt) = alt {
                    wire["alt"] = self.group(alt, shuffled);
                }
                (QueryKind::Contains, wire)
            }
            QueryLeakage::Equals { needle } => {
                let shuffled = self.leakage.sent_order == SentOrder::Random;
                (QueryKind::Equals, self.group(needle, shuffled))
            }
            QueryLeakage::Order { selector, bound } => {
                let s = self.selector(*selector);
                let op = self.ordering(bound.class, bound.len);
                (QueryKind::Order, json!({"s": b64(&s), "op": b64(&op)}))
            }
        }
    }
}
