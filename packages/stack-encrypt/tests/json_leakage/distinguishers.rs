//! The distinguishers: pure functions of an [`ObservedWorld`], each the
//! computation an observer holding the column (and, for the query features,
//! the terms it was sent) could run.
//!
//! Each returns an exact, combinatorial feature: byte strings are replaced by
//! integers in order of first appearance, so two worlds with the same
//! equality pattern give the same feature whatever their bytes. A real world
//! and a simulated one are compared feature by feature for equality; no
//! statistics are involved. The one source of chance is a collision of
//! random bytes (an eight-byte parent tag colliding with another, say), which
//! changes a feature with probability below `n² / 2^64` for `n` tags in a
//! world, about `10^-13` at the harness's sizes.
//!
//! What is deliberately not here, and why, is in the module docs
//! (`mod.rs`, "Out of reach").

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;

use super::chain::{child_token, parent_tag, Tag16, Tag8};
use super::observe::{ObservedGate, ObservedGroup, ObservedQuery, ObservedRow, ObservedWorld};

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
    entry_counts,
    parent_tag_presence,
    ordering_term_presence,
    ciphertext_lengths,
    ciphertext_length_multisets,
    ciphertext_framing,
    selector_pattern_within_rows,
    selector_pattern_across_rows,
    parent_tag_equalities,
    headers,
    projections,
    value_selector_partitions,
    chain_head_runs,
    selector_precedence,
    depth_recovery,
    token_reach,
    ordinal_patterns,
    member_ordinals_follow_key_order,
    token_derivability,
    gated_walk_results,
    transcripts,
    extraction_matches,
    containment_matches,
    ordering_term_order,
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

/// How many entries each row has: the node count.
pub fn entry_counts(world: &ObservedWorld) -> Vec<usize> {
    world.rows.iter().map(|r| r.entries.len()).collect()
}

/// Which entries carry a parent tag, by position. Catches a leak in which
/// entries are chain heads.
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

/// Every row's projection `q`: its grouping by array element, the order of
/// its pairs, and which pairs share a selector or a value selector across
/// the column. Catches a value equality, a grouping or an order the profile
/// does not state.
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
// At rest: what the order of the entries says
// =============================================================================

/// The runs that start at each entry without a parent tag (other than the
/// first): under the sealed root these are the top-level fields, and since
/// everything beneath a field follows it, each run's length is that field's
/// subtree size. "The node count of each top-level field's subtree can be
/// read off a single row exactly." Parent tags are keyed by ordinal, so no
/// two entries share one and there are no equal-tag runs to read; this is
/// the contiguity structure there is.
pub fn chain_head_runs(world: &ObservedWorld) -> Vec<Vec<(usize, usize)>> {
    let mut canon = selector_names(world);
    world
        .rows
        .iter()
        .map(|row| {
            let starts: Vec<usize> = (1..row.entries.len())
                .filter(|&j| row.entries[j].p.is_none())
                .collect();
            starts
                .iter()
                .enumerate()
                .map(|(k, &start)| {
                    let end = starts.get(k + 1).copied().unwrap_or(row.entries.len());
                    (canon.id(row.entries[start].s), end - start)
                })
                .collect()
        })
        .collect()
}

/// For every two selectors that occur in one row, which of them came first
/// in the rows that hold both: `(a first, b first)`. Under a depth-first
/// order with members sorted by key, every two sibling members appear in one
/// order in every row, which is "the alphabetical order of sibling key
/// names"; a stored order independent of the keys would show both.
pub fn selector_precedence(world: &ObservedWorld) -> BTreeMap<(usize, usize), (bool, bool)> {
    let mut canon = selector_names(world);
    let mut out: BTreeMap<(usize, usize), (bool, bool)> = BTreeMap::new();
    for row in &world.rows {
        let mut first: Vec<usize> = Vec::new();
        for entry in &row.entries {
            let id = canon.id(entry.s);
            if !first.contains(&id) {
                first.push(id);
            }
        }
        for (i, &a) in first.iter().enumerate() {
            for &b in &first[i + 1..] {
                let (key, a_first) = if a < b {
                    ((a, b), true)
                } else {
                    ((b, a), false)
                };
                let seen = out.entry(key).or_default();
                if a_first {
                    seen.0 = true;
                } else {
                    seen.1 = true;
                }
            }
        }
    }
    out
}

/// An observer's reconstruction of every row's depth sequence from the
/// stored order alone, as the page says one can: "an observer comparing rows
/// learns" which selector's path sits under which.
///
/// The attack: a selector's parent is among the selectors that precede it
/// in every row that holds it; of those it takes the one that itself has the
/// most such predecessors (the deepest candidate), and gives up where two
/// tie. An entry with no parent tag after the first is a top-level field
/// (depth 1). Each entry's depth is then its selector's chain of parents.
/// The attack is not always right (from order alone, a field that always
/// follows a sibling in every row reads as its child), and it does not need
/// to be: the feature is compared between worlds, and
/// `the_order_reveals_the_shape` checks that it is right on a corpus whose
/// rows vary.
pub fn depth_recovery(world: &ObservedWorld) -> Vec<Vec<Option<usize>>> {
    let mut canon = selector_names(world);
    let rows: Vec<Vec<usize>> = world
        .rows
        .iter()
        .map(|row| row.entries.iter().map(|e| canon.id(e.s)).collect())
        .collect();
    let mut candidates: HashMap<usize, BTreeSet<usize>> = HashMap::new();
    let mut heads: BTreeSet<usize> = BTreeSet::new();
    let mut roots: BTreeSet<usize> = BTreeSet::new();
    for (row, ids) in world.rows.iter().zip(&rows) {
        for (k, &b) in ids.iter().enumerate() {
            if k == 0 {
                let _ = roots.insert(b);
            } else if row.entries[k].p.is_none() {
                let _ = heads.insert(b);
            }
            let before: BTreeSet<usize> = ids[..k].iter().copied().filter(|&a| a != b).collect();
            let _ = candidates
                .entry(b)
                .and_modify(|c| *c = c.intersection(&before).copied().collect())
                .or_insert(before);
        }
    }
    let parent = |b: usize| -> Option<usize> {
        let cands = candidates.get(&b)?;
        let size = |a: &usize| candidates.get(a).map_or(0, BTreeSet::len);
        let best = cands.iter().map(size).max()?;
        let mut top = cands.iter().filter(|a| size(a) == best);
        let first = *top.next()?;
        top.next().is_none().then_some(first)
    };
    let depth = |b: usize| -> Option<usize> {
        let mut at = b;
        // A chain of parents longer than there are selectors is a cycle.
        for d in 0..=candidates.len() {
            if roots.contains(&at) {
                return Some(d);
            }
            if heads.contains(&at) {
                return Some(d + 1);
            }
            at = parent(at)?;
        }
        None
    };
    rows.iter()
        .map(|ids| ids.iter().map(|&b| depth(b)).collect())
        .collect()
}

// =============================================================================
// Under a token: the walk, with the real hash
// =============================================================================

/// One entry a walk from a token reaches.
#[derive(Clone, Copy, Debug)]
struct Hit {
    position: usize,
    /// The position of the hit's parent, or `None` for a child of the
    /// token's own node, which the walk never identifies.
    parent: Option<usize>,
    ordinal: u32,
    depth: usize,
    token: Tag16,
    parent_token: Tag16,
}

/// The children of the node whose token is `token`, as the database finds
/// them: the parent tag of ordinal `0, 1, 2, …` until the first miss.
fn children(
    row: &ObservedRow,
    index: &HashMap<Tag8, usize>,
    token: &Tag16,
) -> Vec<(usize, u32, Tag16)> {
    let mut out = Vec::new();
    for o in 0..u32::try_from(row.entries.len()).unwrap_or(u32::MAX) {
        let Some(&j) = index.get(&parent_tag(&row.header.iv, token, o)) else {
            break;
        };
        out.push((j, o, child_token(token, &row.entries[j].s, o)));
    }
    out
}

fn parent_index(row: &ObservedRow) -> HashMap<Tag8, usize> {
    let mut index = HashMap::new();
    for (j, entry) in row.entries.iter().enumerate() {
        if let Some(p) = entry.p {
            let _ = index.entry(p).or_insert(j);
        }
    }
    index
}

/// Everything below `token` in `row`, depth first, bounded as the SQL walk
/// is: no deeper than the index seals, and no more hits than entries.
fn walk(row: &ObservedRow, token: &Tag16) -> Vec<Hit> {
    fn go(
        row: &ObservedRow,
        index: &HashMap<Tag8, usize>,
        token: &Tag16,
        parent: Option<usize>,
        depth: usize,
        out: &mut Vec<Hit>,
    ) {
        if depth > 128 || out.len() >= row.entries.len() {
            return;
        }
        for (j, o, child) in children(row, index, token) {
            if out.len() >= row.entries.len() {
                return;
            }
            out.push(Hit {
                position: j,
                parent,
                ordinal: o,
                depth,
                token: child,
                parent_token: *token,
            });
            go(row, index, &child, Some(j), depth + 1, out);
        }
    }
    let index = parent_index(row);
    let mut out = Vec::new();
    go(row, &index, token, None, 1, &mut out);
    out
}

fn subtree_queries(world: &ObservedWorld) -> Vec<(usize, Tag16, &[ObservedGate])> {
    world
        .queries
        .iter()
        .enumerate()
        .filter_map(|(i, q)| match q {
            ObservedQuery::Subtree { t, gates } => Some((i, *t, gates.as_slice())),
            _ => None,
        })
        .collect()
}

/// One entry a token links: its position, its parent's position (`None`
/// for a child of the token's own node) and its depth below that node.
pub type Link = (usize, Option<usize>, usize);

/// For every subtree read and every row, what the token links: each entry
/// the walk from the token reaches, its parent among them, and its depth
/// below the token's node, found by recomputing the real parent tags over
/// the row's `iv`. Catches a token that reaches more (or less) than the
/// profile's reach clause says: the page says a token covers its node's
/// whole subtree, in every row, and not only the path asked for (#1360).
pub fn token_reach(world: &ObservedWorld) -> Vec<Vec<Vec<Link>>> {
    subtree_queries(world)
        .into_iter()
        .map(|(_, t, _)| {
            world
                .rows
                .iter()
                .map(|row| {
                    let mut hits: Vec<_> = walk(row, &t)
                        .into_iter()
                        .map(|h| (h.position, h.parent, h.depth))
                        .collect();
                    hits.sort_unstable();
                    hits
                })
                .collect()
        })
        .collect()
}

/// What the ordinals a walk probes say, in the two forms that do not depend
/// on the keyed rank's random order: how many reached nodes have children
/// that all share one selector (an array's elements, or an object's one
/// member) whose ordinals do not run in stored order, and every case where
/// one parent token ranks two child selectors one way in one row and the
/// other way in another. Both are zero for the real scheme: an element's
/// ordinal is its position, and a member's rank is a keyed function of its
/// parent's token and its key.
pub fn ordinal_patterns(world: &ObservedWorld) -> (usize, Vec<(usize, usize, usize)>) {
    let mut selectors = selector_names(world);
    let mut tokens = Canon::new();
    let mut out_of_order = 0;
    let mut ranked: BTreeMap<(usize, usize, usize), BTreeSet<bool>> = BTreeMap::new();
    for (_, t, _) in subtree_queries(world) {
        for row in &world.rows {
            let hits = walk(row, &t);
            let mut by_parent: BTreeMap<(Option<usize>, Tag16), Vec<Hit>> = BTreeMap::new();
            for hit in hits {
                by_parent
                    .entry((hit.parent, hit.parent_token))
                    .or_default()
                    .push(hit);
            }
            for ((_, parent_token), mut kids) in by_parent {
                kids.sort_by_key(|h| h.position);
                let same = kids
                    .windows(2)
                    .all(|w| row.entries[w[0].position].s == row.entries[w[1].position].s);
                if same
                    && kids
                        .iter()
                        .enumerate()
                        .any(|(i, h)| h.ordinal as usize != i)
                {
                    out_of_order += 1;
                }
                if !same {
                    let parent = tokens.id(parent_token);
                    for a in &kids {
                        for b in &kids {
                            let (sa, sb) = (
                                selectors.id(row.entries[a.position].s),
                                selectors.id(row.entries[b.position].s),
                            );
                            if sa < sb {
                                let _ = ranked
                                    .entry((parent, sa, sb))
                                    .or_default()
                                    .insert(a.ordinal < b.ordinal);
                            }
                        }
                    }
                }
            }
        }
    }
    let inconsistent = ranked
        .into_iter()
        .filter(|(_, seen)| seen.len() > 1)
        .map(|(key, _)| key)
        .collect();
    (out_of_order, inconsistent)
}

/// Whether the members a token's holder finds directly under a token it was
/// sent carry ordinals in their stored order, which is their keys' sorted
/// order: the question decision 11 (the keyed member rank) is there to make
/// the answer to "no". Reported only where chance cannot answer it.
///
/// The bound: a member's ordinal is its rank under a keyed function of its
/// parent's token and its key, so for one token the members of its largest
/// observed object fall in key order with probability `1 / k!` for `k`
/// members, and distinct tokens are independent keyed inputs. All of them
/// fall in key order by chance with probability at most the product of
/// `1 / k!` over the tokens sent. The feature is `None` unless that product
/// is below `2^-40`; above it, real and simulated could disagree by chance.
/// Only objects directly under a token sent are counted, since which deeper
/// nodes share a derived token depends on the ranks themselves.
pub fn member_ordinals_follow_key_order(world: &ObservedWorld) -> Option<bool> {
    let mut chance = 1.0f64;
    let mut all_in_order = true;
    let mut sent = BTreeSet::new();
    for (_, t, _) in subtree_queries(world) {
        if !sent.insert(t) {
            continue;
        }
        let mut widest = 0usize;
        for row in &world.rows {
            let mut kids: Vec<Hit> = walk(row, &t)
                .into_iter()
                .filter(|h| h.parent.is_none())
                .collect();
            let distinct: BTreeSet<Tag16> =
                kids.iter().map(|h| row.entries[h.position].s).collect();
            if kids.len() < 2 || distinct.len() != kids.len() {
                continue;
            }
            widest = widest.max(kids.len());
            kids.sort_by_key(|h| h.position);
            if kids
                .iter()
                .enumerate()
                .any(|(i, h)| h.ordinal as usize != i)
            {
                all_in_order = false;
            }
        }
        chance /= (1..=widest).map(|k| k as f64).product::<f64>();
    }
    (chance < 2f64.powi(-40)).then_some(all_in_order)
}

/// Which subtree reads' tokens the database can derive from which others':
/// `(i, j)` when the token sent by query `j` is one the walk from query
/// `i`'s token derives in some row, or is the child token of `i`'s under
/// any selector the column holds and an ordinal below 8 (a bound on what
/// the harness tries, not on what the database can). The page: a token's
/// holder can "derive the tokens of the nodes beneath". Catches tokens that
/// are not chained (a positional token unrelated to its head's) as well as
/// tokens chained where the profile says they are not.
pub fn token_derivability(world: &ObservedWorld) -> BTreeSet<(usize, usize)> {
    let queries = subtree_queries(world);
    let selectors: BTreeSet<Tag16> = world
        .rows
        .iter()
        .flat_map(|r| r.entries.iter().map(|e| e.s))
        .collect();
    let mut out = BTreeSet::new();
    for &(i, ti, _) in &queries {
        let mut derived: BTreeSet<Tag16> = world
            .rows
            .iter()
            .flat_map(|row| walk(row, &ti).into_iter().map(|h| h.token))
            .collect();
        for s in &selectors {
            for o in 0..8 {
                let _ = derived.insert(child_token(&ti, s, o));
            }
        }
        for &(j, tj, _) in &queries {
            if i != j && derived.contains(&tj) {
                let _ = out.insert((i, j));
            }
        }
    }
    out
}

/// What each subtree read returns from each row, as the SQL walk computes
/// it: from the token, through each gate (a child carrying the gate's
/// selector, or the child at ordinal `n` carrying it), then each node
/// reached with everything beneath it; with no gates, everything beneath the
/// token's node.
pub fn gated_walk_results(world: &ObservedWorld) -> Vec<Vec<Vec<usize>>> {
    subtree_queries(world)
        .into_iter()
        .map(|(_, t, gates)| {
            world
                .rows
                .iter()
                .map(|row| {
                    let index = parent_index(row);
                    let mut frontier: Vec<(Option<usize>, Tag16)> = vec![(None, t)];
                    for gate in gates {
                        let mut next = Vec::new();
                        for (_, token) in &frontier {
                            let kids = children(row, &index, token);
                            match gate {
                                ObservedGate::Selector(s) => next.extend(
                                    kids.iter()
                                        .filter(|(j, _, _)| row.entries[*j].s == *s)
                                        .map(|(j, _, child)| (Some(*j), *child)),
                                ),
                                ObservedGate::Slot(n, s) => next.extend(
                                    kids.get(*n as usize)
                                        .filter(|(j, _, _)| row.entries[*j].s == *s)
                                        .map(|(j, _, child)| (Some(*j), *child)),
                                ),
                            }
                        }
                        frontier = next;
                    }
                    let mut rows = Vec::new();
                    for (reached, token) in frontier {
                        rows.extend(reached);
                        rows.extend(walk(row, &token).into_iter().map(|h| h.position));
                    }
                    rows.sort_unstable();
                    rows
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
    Subtree(usize, Vec<(Option<u32>, usize)>),
    Contains(NamedGroup, Option<NamedGroup>),
    Equals(NamedGroup),
    Order(usize, usize),
}

/// Every query term, its tags named across the column and the other terms:
/// which terms repeat (a query is deterministic), which selectors a term
/// shares with the stored rows and with other terms (two paths that differ
/// only in an array position send one selector), a gate's position in the
/// clear, and a needle's shape.
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
            ObservedQuery::Subtree { t, gates } => NamedQuery::Subtree(
                tokens.id(*t),
                gates
                    .iter()
                    .map(|g| match g {
                        ObservedGate::Selector(s) => (None, selectors.id(*s)),
                        ObservedGate::Slot(n, s) => (Some(*n), selectors.id(*s)),
                    })
                    .collect(),
            ),
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

/// The positions and depths a walk from `token` reaches in `row`, in the
/// walk's order: what `JsonDocument::subtree` returns.
pub fn walk_positions(row: &ObservedRow, token: &Tag16) -> Vec<(usize, usize)> {
    walk(row, token)
        .into_iter()
        .map(|h| (h.position, h.depth))
        .collect()
}
