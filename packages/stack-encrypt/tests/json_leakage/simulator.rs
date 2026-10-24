//! The simulator: a wire-shaped world built from a [`Leakage`] and
//! randomness, with no plaintext and no key.
//!
//! Every keyed value is a fresh random string per opaque name (a selector
//! per [`SelId`], a value selector per [`ValueId`], a head token per
//! [`HeadId`]), so equality patterns are exactly the profile's. Ciphertexts
//! are random bytes of the stated length behind the frame's public version
//! byte. Ordering terms are random bytes laid out so that byte order is the
//! profile's rank order.
//!
//! The chain is the one place the simulator evaluates the real scheme's
//! public functions ([`super::chain`]): a token the database is sent has to
//! derive the parent tags of exactly the entries the profile says it reaches,
//! with the real hash, or the database would notice. So the simulator gives
//! every node a token (heads random, every other node chained below its
//! parent with an ordinal: an element's position, or a member's rank under a
//! keyed function the simulator samples itself), and writes the chained
//! parent tag on every entry some query's [`QueryLeakage::Subtree::reach`]
//! names. Every other parent tag is random bytes, as a tag under a token the
//! database never sees is to it.

use std::collections::{HashMap, HashSet};

use base64ct::{Base64, Encoding};
use proptest::prelude::RngCore;
use proptest::test_runner::TestRng;
use serde_json::{json, Value};

use super::chain::{child_token, parent_tag, simulated_rank, Tag16};
use super::observe::QueryKind;
use super::profile::{GateLeak, GroupLeakage, Leakage, QueryLeakage, RowLeakage, Step};

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

struct Simulator<'a> {
    leakage: &'a Leakage,
    rng: &'a mut TestRng,
    selectors: Names<16>,
    values: Names<16>,
    heads: Names<16>,
    keysets: Names<16>,
    ivs: Names<16>,
    tags: HashMap<usize, Vec<u8>>,
    ordering: HashMap<usize, Vec<u8>>,
    rank_key: [u8; 32],
}

/// Build the rows' wire JSON and the queries' wire JSON from `leakage` and
/// `rng` alone.
pub fn simulate(leakage: &Leakage, rng: &mut TestRng) -> (Vec<Value>, Vec<(QueryKind, Value)>) {
    let rank_key = random(rng);
    let mut sim = Simulator {
        leakage,
        rng,
        selectors: Names::new(),
        values: Names::new(),
        heads: Names::new(),
        keysets: Names::new(),
        ivs: Names::new(),
        tags: HashMap::new(),
        ordering: HashMap::new(),
        rank_key,
    };
    let rows = leakage
        .rows
        .iter()
        .enumerate()
        .map(|(r, row)| sim.row(r, row))
        .collect();
    let queries = leakage.queries.iter().map(|q| sim.query(q)).collect();
    (rows, queries)
}

impl Simulator<'_> {
    fn selector(&mut self, id: usize) -> Tag16 {
        self.selectors.get(id, self.rng)
    }

    /// An ordering term of `len` bytes for class `class`: a zero byte, the
    /// class's rank big-endian, then random bytes, so byte order is rank
    /// order and equal classes are equal terms.
    fn ordering(&mut self, class: usize, len: usize) -> Vec<u8> {
        if let Some(bytes) = self.ordering.get(&class) {
            assert_eq!(bytes.len(), len, "one class, one length");
            return bytes.clone();
        }
        assert!(len >= 5, "a term is long enough to carry its rank");
        let rank = u32::try_from(self.leakage.ordering_ranks[class]).expect("a small world");
        let mut bytes = vec![0];
        bytes.extend_from_slice(&rank.to_be_bytes());
        bytes.extend(random_vec(self.rng, len - 5));
        let _ = self.ordering.insert(class, bytes.clone());
        bytes
    }

    fn group(&mut self, group: &GroupLeakage) -> Value {
        let pairs: Vec<Value> = group
            .pairs
            .iter()
            .map(|&(s, vs)| {
                let s = self.selector(s);
                let vs = self.values.get(vs, self.rng);
                json!({"s": b64(&s), "vs": b64(&vs)})
            })
            .collect();
        let elements: Vec<Value> = group.elements.iter().map(|g| self.group(g)).collect();
        json!({"sv": pairs, "el": elements})
    }

    /// Every entry's token and ordinal under its parent, where it has them.
    fn tokens(&mut self, row: &RowLeakage) -> (Vec<Option<Tag16>>, Vec<Option<u32>>) {
        let n = row.entries.len();
        let mut tokens: Vec<Option<Tag16>> = vec![None; n];
        let mut ordinals: Vec<Option<u32>> = vec![None; n];
        // A parent precedes its children only under the order clause; a
        // mutant that shuffles the stored order still names parents, so the
        // chain is resolved by depth rather than by position.
        let depth: Vec<usize> = row
            .entries
            .iter()
            .map(|entry| {
                let mut d = 0;
                let mut at = entry.parent;
                while let Some(p) = at {
                    d += 1;
                    at = row.entries[p].parent;
                }
                d
            })
            .collect();
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| (depth[i], i));
        for &i in &order {
            let entry = &row.entries[i];
            if let Some(head) = entry.head {
                tokens[i] = Some(self.heads.get(head, self.rng));
                continue;
            }
            let Some(parent) = entry.parent else { continue };
            let Some(parent_token) = tokens[parent] else {
                continue;
            };
            let ordinal = match entry.step {
                Step::Element(i) => u32::try_from(i).expect("a small array"),
                Step::Member => {
                    let mine = self.selector(entry.selector);
                    let my_rank = simulated_rank(&self.rank_key, &parent_token, &mine);
                    let siblings: Vec<usize> = (0..n)
                        .filter(|&j| {
                            row.entries[j].parent == Some(parent)
                                && row.entries[j].step == Step::Member
                        })
                        .collect();
                    let below = siblings
                        .into_iter()
                        .filter(|&j| {
                            let theirs = self.selector(row.entries[j].selector);
                            simulated_rank(&self.rank_key, &parent_token, &theirs) < my_rank
                        })
                        .count();
                    u32::try_from(below).expect("a small object")
                }
                Step::Root => continue,
            };
            ordinals[i] = Some(ordinal);
            let s = self.selector(entry.selector);
            tokens[i] = Some(child_token(&parent_token, &s, ordinal));
        }
        (tokens, ordinals)
    }

    fn row(&mut self, r: usize, row: &RowLeakage) -> Value {
        let iv: [u8; 16] = self.ivs.get(row.data_key, self.rng);
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

        let reached: HashSet<usize> = self
            .leakage
            .queries
            .iter()
            .filter_map(|q| match q {
                QueryLeakage::Subtree { reach, .. } => Some(reach[r].iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        let (tokens, ordinals) = self.tokens(row);
        let entries: Vec<Value> = row
            .entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let s = self.selector(entry.selector);
                let mut c = vec![CIPHERTEXT_FRAME];
                c.extend(random_vec(self.rng, entry.ciphertext_len - 1));
                let mut wire = json!({"s": b64(&s), "c": base85_simd::encode(&c)});
                if entry.has_parent_tag {
                    let chained = entry
                        .parent
                        .and_then(|p| tokens[p])
                        .zip(ordinals[i])
                        .filter(|_| reached.contains(&i));
                    let p = match chained {
                        Some((parent, o)) => parent_tag(&iv, &parent, o),
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
        let q = self.group(&row.projection);
        json!({"h": b64(&header), "sv": entries, "q": q})
    }

    fn query(&mut self, query: &QueryLeakage) -> (QueryKind, Value) {
        match query {
            QueryLeakage::Extract { selector } => {
                (QueryKind::Extract, json!(b64(&self.selector(*selector))))
            }
            QueryLeakage::Subtree { token, gates, .. } => {
                let mut t = self.heads.get(token.head, self.rng);
                for &(s, i) in &token.positions {
                    let s = self.selector(s);
                    t = child_token(&t, &s, u32::try_from(i).expect("a small position"));
                }
                let gates: Vec<String> = gates
                    .iter()
                    .map(|g| match *g {
                        GateLeak::Selector(s) => b64(&self.selector(s)),
                        GateLeak::Slot(n, s) => format!("#{n}:{}", b64(&self.selector(s))),
                    })
                    .collect();
                let mut wire = json!({"t": b64(&t)});
                if !gates.is_empty() {
                    wire["g"] = json!(gates);
                }
                (QueryKind::Subtree, wire)
            }
            QueryLeakage::Contains { needle, alt } => {
                let mut wire = self.group(needle);
                if let Some(alt) = alt {
                    wire["alt"] = self.group(alt);
                }
                (QueryKind::Contains, wire)
            }
            QueryLeakage::Equals { needle } => (QueryKind::Equals, self.group(needle)),
            QueryLeakage::Order { selector, bound } => {
                let s = self.selector(*selector);
                let op = self.ordering(bound.class, bound.len);
                (QueryKind::Order, json!({"s": b64(&s), "op": b64(&op)}))
            }
        }
    }
}
