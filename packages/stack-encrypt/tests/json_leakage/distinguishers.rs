//! The distinguishers: pure functions of an [`ObservedWorld`], each the
//! computation an observer holding the column (and, for the query features,
//! the terms it was sent) could run.
//!
//! Each returns an exact, combinatorial feature: byte strings are replaced by
//! integers in order of first appearance, so two worlds with the same
//! equality pattern give the same feature whatever their bytes. A real world
//! and a simulated one are compared feature by feature for equality; no
//! statistics are involved. The one source of chance is a collision of
//! random bytes (an eight-byte parent or self tag colliding with another,
//! say), which changes a feature with probability below `n² / 2^64` for `n`
//! tags in a world, about `10^-13` at the harness's sizes.
//!
//! The entries are stored in a random order, and a needle is sent in one, so
//! each distinguisher reads a world in its canonical order
//! ([`super::canonical`]): a row's root at position `0` and its other
//! entries, every list of `q` and every list of a needle, sorted by what an
//! observer sees of them without the stored or sent order. A *position*
//! below is a place in that order, and a selector's name is its first
//! appearance in it. Two features read the orders themselves: the stored
//! one, through the slot each entry came from
//! ([`walked_subtrees_are_contiguous`]), and the sent one, through the
//! queries as sent ([`repeated_needles_sent_alike`]). Like
//! [`member_order_shared_across_parents`] they carry their probability
//! bounds in their doc comments.
//!
//! What is deliberately not here, and why, is in the module docs
//! (`mod.rs`, "Out of reach").

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;

use super::chain::{
    element_token, hit_token, member_token, parent_tag, self_tag, shared_bits, Rule, Tag16, Tag8,
};
use super::observe::{ObservedGroup, ObservedQuery, ObservedRow, ObservedWorld};

/// One distinguisher: a name and the feature it computes, printed so that
/// any two features compare as strings and a mismatch reads as a diff.
pub struct Distinguisher {
    pub name: &'static str,
    pub run: fn(&ObservedWorld) -> String,
}

macro_rules! registry {
    ($($name:ident),+ $(,)?) => {
        /// Every distinguisher, in a fixed order.
        pub fn all() -> Vec<Distinguisher> {
            vec![$(Distinguisher {
                name: stringify!($name),
                run: |world| format!("{:?}", $name(world)),
            }),+]
        }
    };
}

registry!(
    wire_fields,
    term_fields,
    entry_counts,
    parent_tag_presence,
    ordering_term_presence,
    ciphertext_lengths,
    ciphertext_length_multisets,
    ciphertext_framing,
    stored_lengths,
    selector_pattern_within_rows,
    selector_pattern_across_rows,
    parent_tag_equalities,
    self_tag_equalities,
    cross_kind_equalities,
    headers,
    projections,
    value_selector_partitions,
    walked_subtrees_are_contiguous,
    token_counts,
    bound_recovery,
    token_hits,
    wildcard_positions,
    token_reach,
    hit_rules,
    ancestor_links,
    member_order_shared_across_rows,
    member_order_shared_across_parents,
    token_derivability,
    subtree_results,
    transcripts,
    repeated_needles_sent_alike,
    extraction_matches,
    containment_matches,
    ordering_term_order,
    ordering_term_prefixes,
    ordering_term_lengths,
    ordering_matches,
);

/// Integers for byte strings, in order of first appearance.
struct Canon<T> {
    ids: HashMap<T, usize>,
}

impl<T: Hash + Eq> Canon<T> {
    fn new() -> Self {
        Self {
            ids: HashMap::new(),
        }
    }

    fn id(&mut self, value: T) -> usize {
        let next = self.ids.len();
        *self.ids.entry(value).or_insert(next)
    }
}

/// The selectors of a world, named in one fixed traversal: every row's
/// entries, then every row's projection, then the queries.
fn selector_names(world: &ObservedWorld) -> Canon<Tag16> {
    let mut canon = Canon::new();
    for row in &world.rows {
        for entry in &row.entries {
            let _ = canon.id(entry.s);
        }
    }
    canon
}

// =============================================================================
// At rest: fields, counts and lengths
// =============================================================================

/// The wire keys of every row and entry. Catches a stored field the profile
/// does not account for, or one it invents.
pub fn wire_fields(world: &ObservedWorld) -> Vec<(Vec<String>, Vec<Vec<String>>)> {
    world
        .rows
        .iter()
        .map(|row| {
            (
                row.fields.clone(),
                row.entries.iter().map(|e| e.fields.clone()).collect(),
            )
        })
        .collect()
}

/// Every key path inside each row's projection `q` and inside each query
/// term as it is sent: catches a term field the profile does not account
/// for, which the parser (`observe`) would otherwise drop unread, as
/// [`wire_fields`] does for the rows and entries.
pub fn term_fields(world: &ObservedWorld) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    (
        world.rows.iter().map(|r| r.q_fields.clone()).collect(),
        world.query_fields.clone(),
    )
}

/// How many entries each row has: the node count.
pub fn entry_counts(world: &ObservedWorld) -> Vec<usize> {
    world.rows.iter().map(|r| r.entries.len()).collect()
}

/// Which entries carry a parent tag, by position: with the selectors
/// ([`selector_pattern_across_rows`]), which paths are chain heads and how
/// many heads each row has. Catches a leak in which entries are chain
/// heads.
pub fn parent_tag_presence(world: &ObservedWorld) -> Vec<Vec<bool>> {
    world
        .rows
        .iter()
        .map(|r| r.entries.iter().map(|e| e.p.is_some()).collect())
        .collect()
}

/// Which entries carry an ordering term, by position.
pub fn ordering_term_presence(world: &ObservedWorld) -> Vec<Vec<bool>> {
    world
        .rows
        .iter()
        .map(|r| r.entries.iter().map(|e| e.op.is_some()).collect())
        .collect()
}

/// Every ciphertext's length, by position. Catches anything a length says
/// that the profile's length clause does not.
pub fn ciphertext_lengths(world: &ObservedWorld) -> Vec<Vec<usize>> {
    world
        .rows
        .iter()
        .map(|r| r.entries.iter().map(|e| e.c.len()).collect())
        .collect()
}

/// Each row's ciphertext lengths as a multiset: what lengths reveal with the
/// order taken away.
pub fn ciphertext_length_multisets(world: &ObservedWorld) -> Vec<Vec<usize>> {
    ciphertext_lengths(world)
        .into_iter()
        .map(|mut lengths| {
            lengths.sort_unstable();
            lengths
        })
        .collect()
}

/// The ciphertexts' public framing (the set of leading version bytes) and
/// how many pairs of entries anywhere in the world share a ciphertext.
/// Catches a deterministic ciphertext (equal values sealing to equal bytes).
pub fn ciphertext_framing(world: &ObservedWorld) -> (BTreeSet<u8>, usize) {
    let mut frames = BTreeSet::new();
    let mut seen: HashMap<&[u8], usize> = HashMap::new();
    for row in &world.rows {
        for entry in &row.entries {
            let _ = frames.insert(entry.c[0]);
            *seen.entry(&entry.c).or_default() += 1;
        }
    }
    let pairs = seen.values().map(|n| n * (n - 1) / 2).sum();
    (frames, pairs)
}

/// Each row's length in characters as compact JSON, and each entry's: what
/// the stored size says, with every tag's and term's fixed width included.
/// The self tag adds 19 characters to every entry (`,"x":"` and twelve
/// base64 characters and a quote; 21 in PostgreSQL's `jsonb` text form,
/// which writes `, "x": "…"`), a constant, so it adds nothing that varies.
pub fn stored_lengths(world: &ObservedWorld) -> Vec<(usize, Vec<usize>)> {
    world
        .rows
        .iter()
        .map(|r| (r.chars, r.entries.iter().map(|e| e.chars).collect()))
        .collect()
}

// =============================================================================
// At rest: equality patterns
// =============================================================================

/// Which positions of a row share a selector, named within the row alone.
pub fn selector_pattern_within_rows(world: &ObservedWorld) -> Vec<Vec<usize>> {
    world
        .rows
        .iter()
        .map(|row| {
            let mut canon = Canon::new();
            row.entries.iter().map(|e| canon.id(e.s)).collect()
        })
        .collect()
}

/// Which positions anywhere in the column share a selector: the paths each
/// row has, linked across rows.
pub fn selector_pattern_across_rows(world: &ObservedWorld) -> Vec<Vec<usize>> {
    let mut canon = selector_names(world);
    world
        .rows
        .iter()
        .map(|row| row.entries.iter().map(|e| canon.id(e.s)).collect())
        .collect()
}

/// Every pair of entries, within a row or across rows, that share a parent
/// tag. The page says a tag "does not say which entry is the parent" and that
/// the same position in two rows is unrelated bytes, so this is expected
/// empty: siblings do not share a tag, because it is keyed by the child's
/// ordinal.
pub fn parent_tag_equalities(world: &ObservedWorld) -> Vec<((usize, usize), (usize, usize))> {
    let mut seen: HashMap<Tag8, Vec<(usize, usize)>> = HashMap::new();
    for (r, row) in world.rows.iter().enumerate() {
        for (j, entry) in row.entries.iter().enumerate() {
            if let Some(p) = entry.p {
                seen.entry(p).or_default().push((r, j));
            }
        }
    }
    let mut out: Vec<_> = seen
        .into_values()
        .filter(|at| at.len() > 1)
        .flat_map(|at| {
            let first = at[0];
            at.into_iter().skip(1).map(move |other| (first, other))
        })
        .collect();
    out.sort_unstable();
    out
}

/// An eight-byte tag's place: the row, the entry, and the field (`x` or
/// `p`).
pub type TagAt = (usize, usize, char);

/// Every pair of entries, within a row or across rows, whose self tag equals
/// another self tag or a parent tag anywhere in the world. The page: the
/// self tag "is unrelated bytes in every row and links no entry to
/// another", so this is expected empty: each is a hash of a distinct
/// token under its row's `iv`, in its own domain (`"x"`, where the parent
/// tag's is `"p"`).
pub fn self_tag_equalities(world: &ObservedWorld) -> Vec<(TagAt, TagAt)> {
    let mut seen: HashMap<Tag8, Vec<(usize, usize, char)>> = HashMap::new();
    for (r, row) in world.rows.iter().enumerate() {
        for (j, entry) in row.entries.iter().enumerate() {
            if let Some(x) = entry.x {
                seen.entry(x).or_default().push((r, j, 'x'));
            }
            if let Some(p) = entry.p {
                seen.entry(p).or_default().push((r, j, 'p'));
            }
        }
    }
    let mut out: Vec<_> = seen
        .into_values()
        .filter(|at| at.len() > 1 && at.iter().any(|(_, _, f)| *f == 'x'))
        .flat_map(|at| {
            let first = at[0];
            at.into_iter().skip(1).map(move |other| (first, other))
        })
        .collect();
    out.sort_unstable();
    out
}

/// Which kinds of value share a value with another kind, anywhere in the
/// world: the sixteen-byte ones (a selector `s`, stored or sent, a value
/// selector `vs`, a token, a keyset, an `iv`) with each other, and an
/// eight-byte tag (`x`, `p`) with the first eight bytes of any of them.
/// Every other feature names each kind in its own space, so a token equal
/// to its path's selector, or a value selector equal to a selector, would
/// leave them all unchanged; the database would see it. Expected empty:
/// each kind is a keyed hash or a PRF output in a domain of its own, or
/// random. Equalities within a kind are the other features' business, and
/// `self_tag_equalities` compares `x` with `p`.
pub fn cross_kind_equalities(world: &ObservedWorld) -> BTreeSet<(&'static str, &'static str)> {
    let mut wide: HashMap<Tag16, BTreeSet<&'static str>> = HashMap::new();
    let mut add = |kind: &'static str, value: Tag16| {
        let _ = wide.entry(value).or_default().insert(kind);
    };
    fn add_group(group: &ObservedGroup, add: &mut dyn FnMut(&'static str, Tag16)) {
        let mut pairs = Vec::new();
        pairs_of(group, &mut pairs);
        for (s, vs) in pairs {
            add("s", s);
            add("vs", vs);
        }
    }
    for row in &world.rows {
        add("keyset", row.header.keyset);
        add("iv", row.header.iv);
        for entry in &row.entries {
            add("s", entry.s);
        }
        add_group(&row.q, &mut add);
    }
    for query in &world.queries {
        match query {
            ObservedQuery::Extract { s } | ObservedQuery::Order { s, .. } => add("s", *s),
            ObservedQuery::Subtree { tokens, .. } => tokens.iter().for_each(|t| add("token", *t)),
            ObservedQuery::Contains { needle, alt } => {
                add_group(needle, &mut add);
                if let Some(alt) = alt {
                    add_group(alt, &mut add);
                }
            }
            ObservedQuery::Equals { needle } => add_group(needle, &mut add),
        }
    }
    let mut out = BTreeSet::new();
    let mut fronts: HashMap<Tag8, BTreeSet<&'static str>> = HashMap::new();
    for (value, kinds) in &wide {
        for a in kinds {
            for b in kinds {
                if a < b {
                    let _ = out.insert((*a, *b));
                }
            }
        }
        let mut front = Tag8::default();
        front.copy_from_slice(&value[..8]);
        fronts.entry(front).or_default().extend(kinds);
    }
    for row in &world.rows {
        for entry in &row.entries {
            for (kind, tag) in [("x", entry.x), ("p", entry.p)] {
                for other in tag.and_then(|t| fronts.get(&t)).into_iter().flatten() {
                    let _ = out.insert((kind, *other));
                }
            }
        }
    }
    out
}

/// Each header's public fields, and the equality patterns of its keyset,
/// `iv` and key tag across rows. Catches a shared `iv` (which would link
/// every row's parent tags) and a keyset that varies within a column.
#[allow(clippy::type_complexity)]
pub fn headers(world: &ObservedWorld) -> Vec<(u8, u8, [u8; 4], usize, usize, usize, usize, usize)> {
    let mut keysets = Canon::new();
    let mut ivs = Canon::new();
    let mut tags = Canon::new();
    world
        .rows
        .iter()
        .map(|row| {
            let h = &row.header;
            (
                h.version,
                h.flags,
                h.epoch,
                keysets.id(h.keyset),
                ivs.id(h.iv),
                tags.id(h.tag.clone()),
                h.tag.len(),
                h.trailing,
            )
        })
        .collect()
}

/// A projection with its tags named. Read only through `Debug`, which is
/// how every feature is compared.
#[derive(Debug)]
#[allow(dead_code)]
pub struct NamedGroup {
    pairs: Vec<(usize, usize)>,
    elements: Vec<NamedGroup>,
}

fn name_group(
    group: &ObservedGroup,
    selectors: &mut Canon<Tag16>,
    values: &mut Canon<Tag16>,
) -> NamedGroup {
    NamedGroup {
        pairs: group
            .pairs
            .iter()
            .map(|(s, vs)| (selectors.id(*s), values.id(*vs)))
            .collect(),
        elements: group
            .elements
            .iter()
            .map(|g| name_group(g, selectors, values))
            .collect(),
    }
}

/// Every row's projection `q`: its grouping by array element and which
/// pairs share a selector or a value selector across the column. Catches a
/// value equality or a grouping the profile does not state. (The stored
/// order of `q`'s lists is random; this reads them in the canonical order.)
pub fn projections(world: &ObservedWorld) -> Vec<NamedGroup> {
    let mut selectors = selector_names(world);
    let mut values = Canon::new();
    world
        .rows
        .iter()
        .map(|row| name_group(&row.q, &mut selectors, &mut values))
        .collect()
}

fn pairs_of(group: &ObservedGroup, out: &mut Vec<(Tag16, Tag16)>) {
    out.extend(group.pairs.iter().copied());
    for element in &group.elements {
        pairs_of(element, out);
    }
}

/// For each selector, the rows grouped by the value selector they hold
/// there: the frequency histogram of every path the page describes, with
/// grouping and order taken away.
pub fn value_selector_partitions(
    world: &ObservedWorld,
) -> BTreeMap<usize, BTreeMap<usize, Vec<usize>>> {
    let mut selectors = selector_names(world);
    let mut values = Canon::new();
    let mut out: BTreeMap<usize, BTreeMap<usize, Vec<usize>>> = BTreeMap::new();
    for (r, row) in world.rows.iter().enumerate() {
        let mut pairs = Vec::new();
        pairs_of(&row.q, &mut pairs);
        for (s, vs) in pairs {
            out.entry(selectors.id(s))
                .or_default()
                .entry(values.id(vs))
                .or_default()
                .push(r);
        }
    }
    out
}

// =============================================================================
// Under a token: the database's walk, with the real hash
// =============================================================================

/// A row's two lookups, as `eql_v4_internal.json_tree_index` builds them:
/// self tag to position and parent tag to position, the last entry winning
/// a repeated tag (`jsonb_object_agg` keeps the last value of a repeated
/// key).
pub(super) struct RowIndex {
    x: HashMap<Tag8, usize>,
    p: HashMap<Tag8, usize>,
}

pub(super) fn row_index(row: &ObservedRow) -> RowIndex {
    let mut index = RowIndex {
        x: HashMap::new(),
        p: HashMap::new(),
    };
    for (j, entry) in row.entries.iter().enumerate() {
        if let Some(x) = entry.x {
            let _ = index.x.insert(x, j);
        }
        if let Some(p) = entry.p {
            let _ = index.p.insert(p, j);
        }
    }
    index
}

/// One entry a walk from a token reaches.
#[derive(Clone, Copy, Debug)]
pub(super) struct Hit {
    pub(super) position: usize,
    /// The position of the hit's parent, `None` for the node the token
    /// names.
    pub(super) parent: Option<usize>,
    /// The ordinal the hit was probed at under its parent.
    pub(super) ordinal: Option<u32>,
    depth: usize,
    /// The hit's own token, when the database has one: the token sent, for
    /// the node it names, or the one the member rule or the element rule
    /// gives a hit whose self tag matches it. A hit with neither is returned
    /// and not descended into.
    token: Option<Tag16>,
    /// The rule that gave a hit below the named node its token.
    pub(super) rule: Option<Rule>,
    /// The token of the hit's parent (for the named node, its own).
    parent_token: Tag16,
}

/// A child as the database finds it: its position, the ordinal it was
/// probed at, and its token and the rule that gave it, if either matches.
type Child = (usize, u32, Option<(Tag16, Rule)>);

/// The children of the node whose token is `token`, as the database finds
/// them: the parent tag of ordinal `0, 1, 2, …` until the first miss, each
/// with the token the member rule or the element rule gives it.
fn children(row: &ObservedRow, index: &RowIndex, token: &Tag16) -> Vec<Child> {
    let iv = &row.header.iv;
    let mut out = Vec::new();
    for o in 0..u32::try_from(row.entries.len()).unwrap_or(u32::MAX) {
        let Some(&j) = index.p.get(&parent_tag(iv, token, o)) else {
            break;
        };
        let entry = &row.entries[j];
        out.push((j, o, hit_token(iv, token, &entry.s, entry.x.as_ref(), o)));
    }
    out
}

/// The node `token` names in `row`, found by its self tag, then everything
/// below it, depth first, bounded as the crate's walk (`JsonDocument::subtree`)
/// and the SQL's are: no deeper than the index seals, and no more hits than
/// entries.
pub(super) fn walk_with(row: &ObservedRow, index: &RowIndex, token: &Tag16) -> Vec<Hit> {
    fn go(
        row: &ObservedRow,
        index: &RowIndex,
        token: &Tag16,
        parent: usize,
        depth: usize,
        out: &mut Vec<Hit>,
    ) {
        if out.len() >= row.entries.len() || depth > 127 {
            return;
        }
        for (j, o, child) in children(row, index, token) {
            if out.len() >= row.entries.len() {
                return;
            }
            out.push(Hit {
                position: j,
                parent: Some(parent),
                ordinal: Some(o),
                depth,
                token: child.map(|(t, _)| t),
                rule: child.map(|(_, rule)| rule),
                parent_token: *token,
            });
            if let Some((child, _)) = child {
                go(row, index, &child, j, depth + 1, out);
            }
        }
    }
    let Some(&at) = index.x.get(&self_tag(&row.header.iv, token)) else {
        return Vec::new();
    };
    let mut out = vec![Hit {
        position: at,
        parent: None,
        ordinal: None,
        depth: 0,
        token: Some(*token),
        rule: None,
        parent_token: *token,
    }];
    go(row, index, token, at, 1, &mut out);
    out
}

/// The subtree reads of a world: each one's place among the queries, its
/// tokens and its budget.
fn subtree_queries(world: &ObservedWorld) -> Vec<(usize, &[Tag16], u32)> {
    world
        .queries
        .iter()
        .enumerate()
        .filter_map(|(i, q)| match q {
            ObservedQuery::Subtree { tokens, budget } => Some((i, tokens.as_slice(), *budget)),
            _ => None,
        })
        .collect()
}

/// For every subtree read, every row, and every token of the read that
/// finds a node there, the walk: computed once per world and handed to the
/// features that read it.
type Walks = Vec<Vec<Vec<(usize, Vec<Hit>)>>>;

fn walks(world: &ObservedWorld) -> Walks {
    let indexes: Vec<RowIndex> = world.rows.iter().map(row_index).collect();
    subtree_queries(world)
        .into_iter()
        .map(|(_, tokens, _)| {
            world
                .rows
                .iter()
                .zip(&indexes)
                .map(|(row, index)| {
                    tokens
                        .iter()
                        .enumerate()
                        .filter_map(|(k, t)| {
                            let hits = walk_with(row, index, t);
                            (!hits.is_empty()).then_some((k, hits))
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

/// How many tokens each subtree read sends: one for a path with no
/// wildcard, `N + 1` for one wildcard level, `N² + N + 1` for two.
pub fn token_counts(world: &ObservedWorld) -> Vec<usize> {
    subtree_queries(world)
        .into_iter()
        .map(|(_, tokens, _)| tokens.len())
        .collect()
}

/// The bound an observer recovers from a read's token count alone: every
/// `(levels, N)` with `N^levels + … + N + 1` equal to the count, up to three
/// levels (`(0, 0)` for a single token). One wildcard level at the default
/// bound sends 65 tokens, and 65 is `N + 1` for `N = 64` and nothing else;
/// two levels send 4,161, which is also one level at `N = 4160`, and which
/// tokens find nodes tells the two apart.
pub fn bound_recovery(world: &ObservedWorld) -> Vec<Vec<(u32, u64)>> {
    token_counts(world)
        .into_iter()
        .map(|count| {
            let count = count as u64;
            let mut out = Vec::new();
            if count == 1 {
                out.push((0, 0));
            }
            for levels in 1..=3u32 {
                for n in 1..count {
                    let sum: u64 = (0..=levels).map(|k| n.pow(k)).sum();
                    if sum == count {
                        out.push((levels, n));
                    }
                    if sum >= count {
                        break;
                    }
                }
            }
            out
        })
        .collect()
}

/// For every subtree read and every row, which of the read's tokens find a
/// node there (by its place in the list) and where: "which of the nodes
/// exist in each row". Catches a token that is not column-wide, a token
/// list in another order, and a token that names another node.
pub fn token_hits(world: &ObservedWorld) -> Vec<Vec<Vec<(usize, usize)>>> {
    walks(world)
        .into_iter()
        .map(|rows| {
            rows.into_iter()
                .map(|found| {
                    found
                        .iter()
                        .map(|(k, hits)| (*k, hits[0].position))
                        .collect()
                })
                .collect()
        })
        .collect()
}

/// What a one-level wildcard read gives away, read as one: with `N` the
/// count less one, per row, the positions below `N` whose tokens find a
/// node (which elements hold the rest of the path, `$.items[*].price`'s
/// `price`), whether the last token, the probe, finds one (the array is
/// longer than `N`), and, where both found something, whether the probe's
/// node carries a selector none of the others does (the probe names the
/// element, the others the path below it: the probe is told from the other
/// tokens by what it finds as well as by its place). `None` for a read of
/// one token.
#[allow(clippy::type_complexity)]
pub fn wildcard_positions(
    world: &ObservedWorld,
) -> Vec<Option<Vec<(Vec<usize>, bool, Option<bool>)>>> {
    let counts = token_counts(world);
    walks(world)
        .into_iter()
        .zip(counts)
        .map(|(rows, count)| {
            (count >= 2).then(|| {
                let n = count - 1;
                rows.iter()
                    .zip(&world.rows)
                    .map(|(found, row)| {
                        let positions: Vec<usize> =
                            found.iter().map(|(k, _)| *k).filter(|k| *k < n).collect();
                        let probe = found.iter().find(|(k, _)| *k == n);
                        let told = probe.filter(|_| !positions.is_empty()).map(|(_, hits)| {
                            let s = row.entries[hits[0].position].s;
                            found
                                .iter()
                                .filter(|(k, _)| *k < n)
                                .all(|(_, h)| row.entries[h[0].position].s != s)
                        });
                        (positions, probe.is_some(), told)
                    })
                    .collect()
            })
        })
        .collect()
}

/// One entry a token links: its position, its parent's position (`None`
/// for the node the token names) and its depth below that node.
pub type Link = (usize, Option<usize>, usize);

/// What one token of a read links in one row: its place in the list and
/// its links.
pub type Reached = (usize, Vec<Link>);

/// For every subtree read, every row and every token that finds a node,
/// what the token links: the node, each entry the walk below it reaches,
/// its parent and its depth, found by recomputing the real self and parent
/// tags over the row's `iv`. Catches a token that reaches more (or less)
/// than the profile's reach clause says: a token covers its node's whole
/// subtree in every row, and nothing above it.
pub fn token_reach(world: &ObservedWorld) -> Vec<Vec<Vec<Reached>>> {
    walks(world)
        .into_iter()
        .map(|rows| {
            rows.into_iter()
                .map(|found| {
                    found
                        .into_iter()
                        .map(|(k, hits)| {
                            let mut links: Vec<Link> = hits
                                .into_iter()
                                .map(|h| (h.position, h.parent, h.depth))
                                .collect();
                            links.sort_unstable();
                            (k, links)
                        })
                        .collect()
                })
                .collect()
        })
        .collect()
}

/// A reached node's rule: the place in the list of the token whose walk
/// reached it, its position, and the rule its self tag matched.
pub type RuleAt = (usize, usize, Option<Rule>);

/// For every node a walk reaches below a token, which rule its self tag
/// matched: the member rule (its parent is an object), the element rule
/// (an array), or neither. The database runs this test on every hit
/// (`json_tree_hit_token`), so it learns each reached node's parent's kind,
/// which the stored form keeps out (the design's "no kind bit").
pub fn hit_rules(world: &ObservedWorld) -> Vec<Vec<Vec<RuleAt>>> {
    walks(world)
        .into_iter()
        .map(|rows| {
            rows.into_iter()
                .map(|found| {
                    let mut rules: Vec<_> = found
                        .into_iter()
                        .flat_map(|(k, hits)| {
                            hits.into_iter()
                                .filter(|h| h.depth > 0)
                                .map(move |h| (k, h.position, h.rule))
                        })
                        .collect();
                    // The walk's order follows the members' random ordinals.
                    rules.sort_unstable();
                    rules
                })
                .collect()
        })
        .collect()
}

/// For every subtree read, every row and every token that finds a node,
/// whether the database can link that node to its parent with any token it
/// holds: every token of every read, and every token its walks derive. The
/// page: no token "over a top-level field or an array leaves the client
/// unless that field or array is itself what is read", so a node's parent
/// is linked only where some read named one of its ancestors. Catches a
/// read that sends an ancestor's token, as the gated read before #1363 sent
/// its top-level field's.
pub fn ancestor_links(world: &ObservedWorld) -> Vec<Vec<Vec<(usize, bool)>>> {
    let walks = walks(world);
    let below: Vec<BTreeSet<usize>> = (0..world.rows.len())
        .map(|r| {
            walks
                .iter()
                .flat_map(|rows| rows[r].iter())
                .flat_map(|(_, hits)| hits.iter().filter(|h| h.depth > 0).map(|h| h.position))
                .collect()
        })
        .collect();
    walks
        .iter()
        .map(|rows| {
            rows.iter()
                .enumerate()
                .map(|(r, found)| {
                    found
                        .iter()
                        .map(|(k, hits)| (*k, below[r].contains(&hits[0].position)))
                        .collect()
                })
                .collect()
        })
        .collect()
}

/// Whether the objects one token's holder walks in several rows, whose
/// members carry the same selectors, give those members one order of
/// ordinals across the rows: what a member's ordinal would do if it were a
/// function of the key, keyed or not, and what let a token's holder link a
/// key to an ordinal from row to row. The real scheme draws each object's
/// member ordinals as a fresh random permutation when the row is sealed,
/// which makes the answer "no". An array's elements, whose ordinal is their
/// position, agree in every row by design and are left out. Reported only
/// where chance cannot answer it.
///
/// The bound: `t` rows of one token over the same `m` member selectors
/// agree by chance with probability `(1 / m!)^(t − 1)`, the rows drawing
/// independently; tokens are counted once each, with the first set of
/// member selectors seen under them, so the groups are independent and the
/// chance that every group agrees is the product. The feature is `None`
/// unless that product is below `2^-40`.
pub fn member_order_shared_across_rows(world: &ObservedWorld) -> Option<bool> {
    let mut groups: BTreeMap<(Tag16, Vec<Tag16>), Vec<Vec<Tag16>>> = BTreeMap::new();
    let mut members_of: BTreeMap<Tag16, Vec<Tag16>> = BTreeMap::new();
    for rows in walks(world) {
        for (r, found) in rows.into_iter().enumerate() {
            let row = &world.rows[r];
            for (_, hits) in found {
                for ((_, parent_token), kids) in children_by_parent(hits) {
                    let order: Vec<Tag16> =
                        kids.iter().map(|h| row.entries[h.position].s).collect();
                    let mut members = order.clone();
                    members.sort_unstable();
                    members.dedup();
                    // Children with pairwise distinct selectors are an
                    // object's members: an array's elements share one.
                    if members.len() < 2 || members.len() != kids.len() {
                        continue;
                    }
                    let counted = members_of
                        .entry(parent_token)
                        .or_insert_with(|| members.clone());
                    if *counted != members {
                        continue;
                    }
                    groups
                        .entry((parent_token, members))
                        .or_default()
                        .push(order);
                }
            }
        }
    }
    let mut chance = 0.0f64;
    let mut shared = true;
    for ((_, members), orders) in &groups {
        let factorial: f64 = (1..=members.len()).map(|k| (k as f64).ln()).sum();
        chance -= factorial * (orders.len() - 1) as f64;
        shared &= orders.windows(2).all(|w| w[0] == w[1]);
    }
    (chance < -40.0 * 2f64.ln()).then_some(shared)
}

/// The hits of one walk below the node it names, grouped by their parent's
/// position and token, each group in the order of its ordinals.
fn children_by_parent(hits: Vec<Hit>) -> BTreeMap<(usize, Tag16), Vec<Hit>> {
    let mut by_parent: BTreeMap<(usize, Tag16), Vec<Hit>> = BTreeMap::new();
    for hit in hits.into_iter().filter(|h| h.depth > 0) {
        by_parent
            .entry((hit.parent.expect("below the node"), hit.parent_token))
            .or_default()
            .push(hit);
    }
    for kids in by_parent.values_mut() {
        kids.sort_by_key(|h| h.ordinal);
    }
    by_parent
}

/// Whether two objects a token's holder walks, under two tokens, whose
/// nodes share a selector and whose members carry the same selectors, give
/// those members one order of ordinals: what a member's ordinal would do if
/// it ranked the key names. The ordinals are a random permutation drawn per
/// object when the row is sealed, which makes the answer "no". With the
/// stored order random, the holder has no key order to set the ordinals
/// against (as it had before, where the stored order put the members in key
/// order); what it can still set them against is another object's. Reported
/// only where chance cannot answer it.
///
/// The bound: under one parent token the order of `m` members is a uniform
/// permutation, and distinct objects draw independently, so `t` tokens over
/// the same `m` member selectors give one order with probability
/// `(1 / m!)^(t − 1)`. Each token is counted once (its first
/// object of two or more members with distinct selectors, in the order the
/// queries, rows and tokens come), so the groups are independent and the
/// chance that every group agrees is the product. The feature is `None`
/// unless that product is below `2^-40`. The same path in two rows is one
/// token (tokens are column-wide), so it is the elements of an array of
/// like objects that decide it.
pub fn member_order_shared_across_parents(world: &ObservedWorld) -> Option<bool> {
    let mut counted: BTreeSet<Tag16> = BTreeSet::new();
    let mut groups: BTreeMap<(Tag16, Vec<Tag16>), Vec<Vec<Tag16>>> = BTreeMap::new();
    for rows in walks(world) {
        for (r, found) in rows.into_iter().enumerate() {
            let row = &world.rows[r];
            for (_, hits) in found {
                for ((parent, parent_token), kids) in children_by_parent(hits) {
                    // Children with pairwise distinct selectors are an
                    // object's members: an array's elements share one.
                    let order: Vec<Tag16> =
                        kids.iter().map(|h| row.entries[h.position].s).collect();
                    let mut members = order.clone();
                    members.sort_unstable();
                    members.dedup();
                    if members.len() < 2
                        || members.len() != kids.len()
                        || !counted.insert(parent_token)
                    {
                        continue;
                    }
                    groups
                        .entry((row.entries[parent].s, members))
                        .or_default()
                        .push(order);
                }
            }
        }
    }
    let mut chance = 0.0f64;
    let mut shared = true;
    for ((_, members), orders) in &groups {
        let factorial: f64 = (1..=members.len()).map(|k| (k as f64).ln()).sum();
        chance -= factorial * (orders.len() - 1) as f64;
        shared &= orders.windows(2).all(|w| w[0] == w[1]);
    }
    (chance < -40.0 * 2f64.ln()).then_some(shared)
}

/// Whether every subtree a walk links sits at consecutive stored slots, the
/// node its token names first: what a depth-first stored order gives every
/// subtree, and what the read check before the cascade required. This is
/// the one feature that reads the stored order, through the slot each
/// entry came from ([`ObservedRow::slots`]); every other reads the
/// canonical order. Reported only where chance cannot answer it.
///
/// The bound: a row of `n` entries stores its root at slot `0` and the
/// others at a uniformly random permutation of the `N = n − 1` slots after
/// it. Take `k` pairwise disjoint walked subtrees of sizes `m_1 … m_k`, none
/// holding the root: they all land as runs that start at their named nodes
/// with probability `(N − Σm + k)! · Π (m_i − 1)! / N!` (each run is a
/// block whose first entry is fixed). A walked subtree that holds the root
/// (its named node is `$` with the root open) must fill the `m − 1` slots
/// after it, which multiplies in `(m − 1)!` and takes those slots out of
/// `N` first. That every walked subtree is a run implies that the chosen
/// disjoint ones are, so the chosen family's probability bounds it; each
/// row takes its largest walked subtrees greedily, and rows are drawn
/// independently, so the chance for the whole world is at most the product
/// over the rows. The feature is `None` unless that product is below
/// `2^-40`.
pub fn walked_subtrees_are_contiguous(world: &ObservedWorld) -> Option<bool> {
    let ln_factorial = |n: usize| -> f64 { (2..=n).map(|k| (k as f64).ln()).sum() };
    let mut per_row: Vec<Vec<(usize, BTreeSet<usize>)>> = vec![Vec::new(); world.rows.len()];
    for rows in walks(world) {
        for (r, found) in rows.into_iter().enumerate() {
            for (_, hits) in found {
                let first = hits[0].position;
                let set: BTreeSet<usize> = hits.iter().map(|h| h.position).collect();
                if set.len() > 1 && !per_row[r].iter().any(|(_, s)| *s == set) {
                    per_row[r].push((first, set));
                }
            }
        }
    }
    let mut runs = true;
    let mut chance = 0.0f64;
    for (row, mut subtrees) in world.rows.iter().zip(per_row) {
        for (first, set) in &subtrees {
            let slots: BTreeSet<usize> = set.iter().map(|&j| row.slots[j]).collect();
            let start = row.slots[*first];
            runs &= slots.len() == set.len()
                && slots.first() == Some(&start)
                && slots.last() == Some(&(start + set.len() - 1));
        }
        subtrees.sort_by_key(|(_, set)| std::cmp::Reverse(set.len()));
        let mut taken: BTreeSet<usize> = BTreeSet::new();
        let mut free = row.entries.len().saturating_sub(1);
        let mut blocks = Vec::new();
        let mut favourable = 0.0;
        for (_, set) in subtrees {
            if !set.is_disjoint(&taken) {
                continue;
            }
            taken.extend(set.iter().copied());
            favourable += ln_factorial(set.len() - 1);
            if set.contains(&0) {
                free = free.saturating_sub(set.len() - 1);
            } else {
                blocks.push(set.len());
            }
        }
        let singles = free.saturating_sub(blocks.iter().sum::<usize>());
        favourable += ln_factorial(singles + blocks.len());
        chance += favourable - ln_factorial(row.entries.len().saturating_sub(1));
    }
    (chance < -40.0 * 2f64.ln()).then_some(runs)
}

/// Which subtree reads' tokens the database can derive from which others':
/// `(i, j)` when a token sent by query `j` is one the walks from query
/// `i`'s tokens derive in some row, or is a child token of one of `i`'s
/// tokens that finds a node somewhere, by the member rule under any
/// selector the column holds, by the element rule at an index below 4, or
/// by the element rule under the selector of the children its walks reach
/// at any index up to the longest token list sent or 64 (bounds on what the
/// harness tries, not on what the database can). The page: a token's holder can "derive the tokens of
/// the nodes beneath". Catches tokens that are not chained (a token
/// unrelated to its path's) as well as tokens chained where the profile
/// says they are not.
pub fn token_derivability(world: &ObservedWorld) -> BTreeSet<(usize, usize)> {
    let queries = subtree_queries(world);
    let walks = walks(world);
    let selectors: BTreeSet<Tag16> = world
        .rows
        .iter()
        .flat_map(|r| r.entries.iter().map(|e| e.s))
        .collect();
    let longest = queries
        .iter()
        .map(|(_, tokens, _)| u32::try_from(tokens.len()).unwrap_or(u32::MAX))
        .max()
        .unwrap_or(0)
        .max(64);
    let mut out = BTreeSet::new();
    for (q, &(i, tokens, _)) in queries.iter().enumerate() {
        let mut derived: BTreeSet<Tag16> = walks[q]
            .iter()
            .flatten()
            .flat_map(|(_, hits)| hits.iter().filter_map(|h| h.token))
            .collect();
        // From the tokens that find a node in some row: one that names
        // nothing anywhere (most of a wildcard's positions, on short arrays)
        // derives only the tokens of paths no row has.
        let found: BTreeSet<usize> = walks[q]
            .iter()
            .flat_map(|row| row.iter().map(|(k, _)| *k))
            .collect();
        for t in found.iter().map(|&k| &tokens[k]) {
            for s in &selectors {
                let _ = derived.insert(member_token(t, s));
                for o in 0..4 {
                    let _ = derived.insert(element_token(t, s, o));
                }
            }
        }
        // And by the element rule at every index up to the longest list
        // sent or 64, whichever is more, under the one selector an element of the found node can
        // carry: its children's, wherever a walk from it reaches one. This
        // links a read of `$.tags[10]` to one of `$.tags` in a column whose
        // arrays are all shorter.
        for (r, rows) in walks[q].iter().enumerate() {
            for (k, hits) in rows {
                let kids: BTreeSet<Tag16> = hits
                    .iter()
                    .filter(|h| h.depth == 1)
                    .map(|h| world.rows[r].entries[h.position].s)
                    .collect();
                for s in &kids {
                    for o in 0..=longest {
                        let _ = derived.insert(element_token(&tokens[*k], s, o));
                    }
                }
            }
        }
        for &(j, others, _) in &queries {
            if i != j && others.iter().any(|t| derived.contains(t)) {
                let _ = out.insert((i, j));
            }
        }
    }
    out
}

/// What one subtree read returns from one row.
#[derive(Debug, PartialEq, Eq)]
pub enum Returned {
    /// `(k, j, d)`: the place in the token list of the token whose node the
    /// row sits in, its position and its depth below that node, ordered by
    /// `k` then `j`.
    Rows(Vec<(usize, usize, usize)>),
    /// The root entry alone: the root is sealed, the budget is not `0`, and
    /// the read found more rows than the budget.
    RootAlone,
}

/// What each subtree read returns from each row, as `json_tree_subtree`
/// computes it: for each token in turn the node it names and everything
/// beneath it, or, past the budget under the sealed root, the root entry
/// alone. The database computes the fallback from the walk it already
/// sees, so it learns nothing from it; to someone who sees only the
/// results, a row answered with its root alone had more than `budget` rows
/// under the tokens.
pub fn subtree_results(world: &ObservedWorld) -> Vec<Vec<Returned>> {
    let budgets: Vec<u32> = subtree_queries(world)
        .into_iter()
        .map(|(_, _, budget)| budget)
        .collect();
    walks(world)
        .into_iter()
        .zip(budgets)
        .map(|(rows, budget)| {
            rows.into_iter()
                .zip(&world.rows)
                .map(|(found, row)| {
                    let mut out: Vec<(usize, usize, usize)> = found
                        .into_iter()
                        .flat_map(|(k, hits)| {
                            hits.into_iter().map(move |h| (k, h.position, h.depth))
                        })
                        .collect();
                    let sealed = row.header.flags & 1 == 1;
                    if sealed && budget > 0 && out.len() > budget as usize {
                        Returned::RootAlone
                    } else {
                        out.sort_unstable();
                        Returned::Rows(out)
                    }
                })
                .collect()
        })
        .collect()
}

// =============================================================================
// The queries
// =============================================================================

/// A query term with its tags named. Read only through `Debug`.
#[derive(Debug)]
#[allow(dead_code)]
pub enum NamedQuery {
    Extract(usize),
    Subtree(Vec<usize>, u32),
    Contains(NamedGroup, Option<NamedGroup>),
    Equals(NamedGroup),
    Order(usize, usize),
}

/// Every query term, its tags named across the column and the other terms:
/// which terms repeat (a query is deterministic, and a token is the same in
/// every read that names its node), which selectors a term shares with the
/// stored rows and with other terms (two paths that differ only in an array
/// position send one selector), a read's tokens in the order sent and its
/// budget, and a needle's shape.
pub fn transcripts(world: &ObservedWorld) -> Vec<NamedQuery> {
    let mut selectors = selector_names(world);
    let mut values = Canon::new();
    for row in &world.rows {
        let _ = name_group(&row.q, &mut selectors, &mut values);
    }
    let mut tokens = Canon::new();
    let mut terms = Canon::new();
    world
        .queries
        .iter()
        .map(|q| match q {
            ObservedQuery::Extract { s } => NamedQuery::Extract(selectors.id(*s)),
            ObservedQuery::Subtree {
                tokens: sent,
                budget,
            } => NamedQuery::Subtree(sent.iter().map(|t| tokens.id(*t)).collect(), *budget),
            ObservedQuery::Contains { needle, alt } => NamedQuery::Contains(
                name_group(needle, &mut selectors, &mut values),
                alt.as_ref()
                    .map(|a| name_group(a, &mut selectors, &mut values)),
            ),
            ObservedQuery::Equals { needle } => {
                NamedQuery::Equals(name_group(needle, &mut selectors, &mut values))
            }
            ObservedQuery::Order { s, op } => {
                NamedQuery::Order(selectors.id(*s), terms.id(op.clone()))
            }
        })
        .collect()
}

/// Whether a needle sent more than once is sent in one order every time:
/// what a needle sent in the walk's order does, and what one shuffled
/// afresh for each query does not. This reads the needles as sent
/// ([`ObservedWorld::sent`]); a needle's identity is its content, read in
/// the canonical order. Reported only where chance cannot answer it.
///
/// The bound: a needle's pair list of `m` pairs, `c_1, c_2, …` of them
/// alike, is sent in one of `m! / Π c_i!` arrangements, uniformly and
/// independently for each query, and so is its list of `k` element groups,
/// `d_1, d_2, …` of them alike, in one of `k! / Π d_j!`. Two sends of one
/// needle agree everywhere only if those two lists agree, which they do with
/// probability `Π c_i! / m! · Π d_j! / k!` (deeper lists only make it
/// smaller), and `t` sends agree with the first with that to the power
/// `t − 1`. The feature is `None` unless the product over the repeated
/// needles is below `2^-40`.
pub fn repeated_needles_sent_alike(world: &ObservedWorld) -> Option<bool> {
    fn needle(query: &ObservedQuery) -> Option<(&ObservedGroup, Option<&ObservedGroup>)> {
        match query {
            ObservedQuery::Contains { needle, alt } => Some((needle, alt.as_ref())),
            ObservedQuery::Equals { needle } => Some((needle, None)),
            _ => None,
        }
    }
    fn ln_arrangements<T: Ord>(items: &[T]) -> f64 {
        let ln_factorial = |n: usize| -> f64 { (2..=n).map(|k| (k as f64).ln()).sum() };
        let mut sorted: Vec<&T> = items.iter().collect();
        sorted.sort_unstable();
        let alike: f64 = sorted
            .chunk_by(|a, b| a == b)
            .map(|run| ln_factorial(run.len()))
            .sum();
        ln_factorial(items.len()) - alike
    }
    let mut repeats: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, query) in world.queries.iter().enumerate() {
        if let Some(content) = needle(query) {
            repeats.entry(format!("{content:?}")).or_default().push(i);
        }
    }
    let mut chance = 0.0f64;
    let mut alike = true;
    for sent in repeats.values().filter(|sent| sent.len() > 1) {
        let (canonical, _) = needle(&world.queries[sent[0]]).expect("a needle");
        let elements: Vec<String> = canonical
            .elements
            .iter()
            .map(|g| format!("{g:?}"))
            .collect();
        let once = ln_arrangements(&canonical.pairs) + ln_arrangements(&elements);
        chance -= once * (sent.len() - 1) as f64;
        let first = needle(&world.sent[sent[0]]);
        alike &= sent.iter().all(|&i| needle(&world.sent[i]) == first);
    }
    (chance < -40.0 * 2f64.ln()).then_some(alike)
}

/// For every extraction, the positions in each row whose selector it sent:
/// which rows `->` answers, and with how many entries.
pub fn extraction_matches(world: &ObservedWorld) -> Vec<Vec<Vec<usize>>> {
    world
        .queries
        .iter()
        .filter_map(|q| match q {
            ObservedQuery::Extract { s } => Some(
                world
                    .rows
                    .iter()
                    .map(|row| {
                        (0..row.entries.len())
                            .filter(|&j| row.entries[j].s == *s)
                            .collect()
                    })
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// `jsonb @>` over two projections, as the server decides it.
fn contains(stored: &ObservedGroup, needle: &ObservedGroup) -> bool {
    needle.pairs.iter().all(|p| stored.pairs.contains(p))
        && needle
            .elements
            .iter()
            .all(|n| stored.elements.iter().any(|s| contains(s, n)))
}

/// For every containment and equality needle, the rows it matches.
pub fn containment_matches(world: &ObservedWorld) -> Vec<Vec<usize>> {
    world
        .queries
        .iter()
        .filter_map(|q| {
            let (needle, alt) = match q {
                ObservedQuery::Contains { needle, alt } => (needle, alt.as_ref()),
                ObservedQuery::Equals { needle } => (needle, None),
                _ => return None,
            };
            Some(
                (0..world.rows.len())
                    .filter(|&r| {
                        let q = &world.rows[r].q;
                        contains(q, needle) || alt.is_some_and(|a| contains(q, a))
                    })
                    .collect(),
            )
        })
        .collect()
}

/// Every ordering term in the world, stored and sent, by its rank in byte
/// order (the order the SQL compares them in), ties sharing a rank. The
/// stored terms' ranks by position, then each bound's.
#[allow(clippy::type_complexity)]
pub fn ordering_term_order(world: &ObservedWorld) -> (Vec<Vec<Option<usize>>>, Vec<usize>) {
    let mut all: Vec<&[u8]> = world
        .rows
        .iter()
        .flat_map(|r| r.entries.iter().filter_map(|e| e.op.as_deref()))
        .collect();
    all.extend(world.queries.iter().filter_map(|q| match q {
        ObservedQuery::Order { op, .. } => Some(op.as_slice()),
        _ => None,
    }));
    all.sort_unstable();
    all.dedup();
    let rank = |op: &[u8]| all.binary_search(&op).expect("collected above");
    (
        world
            .rows
            .iter()
            .map(|r| {
                r.entries
                    .iter()
                    .map(|e| e.op.as_deref().map(rank))
                    .collect()
            })
            .collect(),
        world
            .queries
            .iter()
            .filter_map(|q| match q {
                ObservedQuery::Order { op, .. } => Some(rank(op)),
                _ => None,
            })
            .collect(),
    )
}

/// For every two distinct ordering terms in the world, stored and sent, by
/// their ranks in byte order, how many leading plaintext bits their values'
/// encodings share, read off the terms alone. A CLLW OPE term is a carry
/// byte, then one byte per plaintext bit: a keyed function of the bits
/// before it, plus the bit at weight 128, plus a carry of zero or one from
/// the byte to its right. So two terms differ by at most one, modulo 256, at
/// every byte before the first bit their plaintexts differ in, and by 127 to
/// 129 at that byte; the count is the bytes before it (after the carry
/// byte), or the shorter term's bit count when one encoding is a prefix of
/// the other. Exact: no carry can make a shared bit's bytes differ by more
/// than one, and none can bring a differing bit's within one. The page: the
/// term "shows how long that common prefix is". Of a number, the first bit
/// is its sign and the next eleven its exponent's, so this sorts numbers
/// into signs and binary orders of magnitude without any bound sent.
pub fn ordering_term_prefixes(world: &ObservedWorld) -> Vec<(usize, usize, usize)> {
    let mut all: Vec<&[u8]> = world
        .rows
        .iter()
        .flat_map(|r| r.entries.iter().filter_map(|e| e.op.as_deref()))
        .collect();
    all.extend(world.queries.iter().filter_map(|q| match q {
        ObservedQuery::Order { op, .. } => Some(op.as_slice()),
        _ => None,
    }));
    all.sort_unstable();
    all.dedup();
    let mut out = Vec::new();
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate().skip(i + 1) {
            out.push((i, j, shared_bits(a, b)));
        }
    }
    out
}

/// Every ordering term's length, stored and sent.
#[allow(clippy::type_complexity)]
pub fn ordering_term_lengths(world: &ObservedWorld) -> (Vec<Vec<Option<usize>>>, Vec<usize>) {
    (
        world
            .rows
            .iter()
            .map(|r| {
                r.entries
                    .iter()
                    .map(|e| e.op.as_ref().map(Vec::len))
                    .collect()
            })
            .collect(),
        world
            .queries
            .iter()
            .filter_map(|q| match q {
                ObservedQuery::Order { op, .. } => Some(op.len()),
                _ => None,
            })
            .collect(),
    )
}

/// For every ordering bound, the entries `col -> s >= bound` holds for: the
/// ones at its selector whose term is at least the bound's.
pub fn ordering_matches(world: &ObservedWorld) -> Vec<Vec<Vec<usize>>> {
    world
        .queries
        .iter()
        .filter_map(|q| match q {
            ObservedQuery::Order { s, op } => Some(
                world
                    .rows
                    .iter()
                    .map(|row| {
                        (0..row.entries.len())
                            .filter(|&j| {
                                let e = &row.entries[j];
                                e.s == *s && e.op.as_ref().is_some_and(|stored| stored >= op)
                            })
                            .collect()
                    })
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// The positions and depths a read of `tokens` reaches in `row`, token by
/// token in the walk's order: what `JsonDocument::subtree` returns.
pub fn walk_positions(row: &ObservedRow, tokens: &[Tag16]) -> Vec<(usize, usize)> {
    let index = row_index(row);
    tokens
        .iter()
        .flat_map(|t| walk_with(row, &index, t))
        .map(|h| (h.position, h.depth))
        .collect()
}
