//! The canonical order: each stored row's entries, every list of its
//! projection `q` and every list of each needle sent, put in an order an
//! observer computes from the column and the queries without the stored or
//! sent order, so that the distinguishers can name an entry by its place
//! and still compare a real world with a simulated one for equality.
//!
//! The stored order is random ([`super::profile::StoredOrder::Random`]), and
//! so is the order a needle is sent in
//! ([`super::profile::SentOrder::Random`]), in the real scheme and in a
//! faithful simulation alike, independently. A feature that named an entry
//! by its slot, or a selector by the slot it first appears at, or a needle's
//! pairs in the order they came, would tell the two apart by chance alone.
//! So every distinguisher reads the world in this order instead:
//!
//! - Every name (a selector or a value selector) gets a rank from what is
//!   attached to it, in tiers compared in turn. At rest: a selector by, per
//!   row, whether the root carries it, a description of each entry carrying
//!   it, and its `q` pairs by their group's depth and their value
//!   selector's colour (per row, the depths it is stored at; per needle, the
//!   depths it is sent at); a value selector by that colour. Then,
//!   repeatedly until nothing more splits, the groups of `q` a name's pairs
//!   sit in, by the ranks of their pairs, of their parent group's and of
//!   their element groups'. Then the queries that name it (an extraction,
//!   an ordering bound, or a needle and the depth it sits at there), then
//!   where walks reach a selector's entries, then the needles' groups as
//!   `q`'s were. Names still tied are ones nothing tells apart (`$.a.b`
//!   and `$.a.b.c` in a row `{"a": {"b": {"c": {}}}}`, at rest); they are
//!   set apart one at a time, each followed by the refinement again, so
//!   that one choice orders the entries and `q` alike.
//! - Each row keeps its root at slot `0`, where every document stores it.
//!   The other entries are sorted by their selector's rank, their own
//!   description (ciphertext length, length in characters, wire fields,
//!   whether they carry a parent and a self tag, and their ordering term's
//!   rank among every term in the world), the first query and token whose
//!   token names them, and the first place a walk reaches them below the
//!   node a token names: the query, the token, and for each node on the way
//!   down what the walk shows beneath it and, for an array's elements, the
//!   ordinal (an object's members' ordinals are a random permutation,
//!   which would order them differently in every world).
//! - Every list of `q`, and of every needle and `alt`, is sorted by its
//!   pairs' ranks, and its element groups by their sorted contents.
//!
//! Two entries the sort ties agree on everything a distinguisher reads of
//! them but their random bytes (a ciphertext, a self tag or a parent tag no
//! token links), so which goes first changes no feature, and ties keep
//! their stored order. A tie between two entries some feature does tell
//! apart would make the positive control fail by chance; the descriptions
//! above are what keeps that from happening, and one that leaves out
//! something a feature reads is the first place to look if it does. The
//! walk tiers come after everything at rest, so that a world whose walks
//! differ (a mutant's) reorders only entries that agree at rest, and a
//! named node's place does not move with what the walks below it reach.
//!
//! Each entry's stored slot is kept beside it ([`ObservedRow::slots`]), and
//! each query as sent ([`ObservedWorld::sent`]), for the two features that
//! read the stored and the sent order themselves
//! ([`super::distinguishers::walked_subtrees_are_contiguous`],
//! [`super::distinguishers::repeated_needles_sent_alike`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::chain::Tag16;
use super::distinguishers::{row_index, walk_with, Hit};
use super::observe::{ObservedEntry, ObservedGroup, ObservedQuery, ObservedRow, ObservedWorld};

/// A place a walk reaches an entry below the node a token names: the
/// query's place among the queries, the token's place in its list, and a
/// step for each node on the way down to the entry ([`steps`]).
type Address = (usize, usize, Vec<String>);

/// Where the walks find an entry: the first query and token whose token
/// names it, and the first place a walk reaches it below the node a token
/// names.
type Found = (Option<(usize, usize)>, Option<Address>);

/// What an entry shows at rest, its selector aside: its ciphertext's length,
/// its length in characters, its wire fields, whether it carries a parent
/// tag and a self tag, and its ordering term's rank.
type EntryKey = (usize, usize, Vec<String>, bool, bool, Option<usize>);

/// A projection and what it is: a row's `q`, or a needle or `alt` sent.
type Projection<'a> = (String, &'a ObservedGroup);

/// `world` in the canonical order.
pub fn canonical(world: &ObservedWorld) -> ObservedWorld {
    let terms = term_ranks(world);
    let colours = value_colours(world);
    let rest = rest_ranks(world, &terms, &colours);
    let walks = walks(world);
    let ranks = ranks(world, &terms, &walks, &rest);
    let found = addresses(world, &walks, &terms, &ranks);
    let rows = world
        .rows
        .iter()
        .zip(&found)
        .map(|(row, found)| {
            let mut order: Vec<usize> = (1..row.entries.len()).collect();
            order.sort_by_key(|&j| {
                (
                    ranks[&row.entries[j].s],
                    entry_key(&row.entries[j], &terms),
                    found[j].clone(),
                )
            });
            if !row.entries.is_empty() {
                order.insert(0, 0);
            }
            ObservedRow {
                entries: order.iter().map(|&j| row.entries[j].clone()).collect(),
                slots: order.iter().map(|&j| row.slots[j]).collect(),
                q: group(&row.q, &ranks),
                ..row.clone()
            }
        })
        .collect();
    let queries = world
        .queries
        .iter()
        .map(|query| match query {
            ObservedQuery::Contains { needle, alt } => ObservedQuery::Contains {
                needle: group(needle, &ranks),
                alt: alt.as_ref().map(|a| group(a, &ranks)),
            },
            ObservedQuery::Equals { needle } => ObservedQuery::Equals {
                needle: group(needle, &ranks),
            },
            other => other.clone(),
        })
        .collect();
    ObservedWorld {
        rows,
        queries,
        sent: world.sent.clone(),
        query_fields: world.query_fields.clone(),
    }
}

/// Every ordering term in the world, stored and sent, by its rank in byte
/// order: the order the database compares them in.
fn term_ranks(world: &ObservedWorld) -> HashMap<Vec<u8>, usize> {
    let mut all: Vec<&Vec<u8>> = world
        .rows
        .iter()
        .flat_map(|r| r.entries.iter().filter_map(|e| e.op.as_ref()))
        .collect();
    all.extend(world.queries.iter().filter_map(|q| match q {
        ObservedQuery::Order { op, .. } => Some(op),
        _ => None,
    }));
    all.sort_unstable();
    all.dedup();
    all.into_iter()
        .enumerate()
        .map(|(rank, op)| (op.clone(), rank))
        .collect()
}

fn entry_key(entry: &ObservedEntry, terms: &HashMap<Vec<u8>, usize>) -> EntryKey {
    (
        entry.c.len(),
        entry.chars,
        entry.fields.clone(),
        entry.p.is_some(),
        entry.x.is_some(),
        entry.op.as_ref().map(|op| terms[op]),
    )
}

/// One walk: the query's place among the queries, the row, the token's
/// place in its list, and what the walk finds, the named node first.
type Walk = (usize, usize, usize, Vec<Hit>);

/// Every walk in the world that finds something.
fn walks(world: &ObservedWorld) -> Vec<Walk> {
    let indexes: Vec<_> = world.rows.iter().map(row_index).collect();
    let mut out = Vec::new();
    for (i, query) in world.queries.iter().enumerate() {
        let ObservedQuery::Subtree { tokens, .. } = query else {
            continue;
        };
        for (r, (row, index)) in world.rows.iter().zip(&indexes).enumerate() {
            for (k, token) in tokens.iter().enumerate() {
                let hits = walk_with(row, index, token);
                if !hits.is_empty() {
                    out.push((i, r, k, hits));
                }
            }
        }
    }
    out
}

/// For every row and every stored slot, where the walks find the entry
/// there, each node on the way described with `ranks`.
fn addresses(
    world: &ObservedWorld,
    walks: &[Walk],
    terms: &HashMap<Vec<u8>, usize>,
    ranks: &HashMap<Tag16, usize>,
) -> Vec<Vec<Found>> {
    let mut out: Vec<Vec<Found>> = world
        .rows
        .iter()
        .map(|row| vec![(None, None); row.entries.len()])
        .collect();
    for (i, r, k, hits) in walks {
        let (i, r, k) = (*i, *r, *k);
        let at = &mut out[r][hits[0].position].0;
        if at.is_none_or(|before| (i, k) < before) {
            *at = Some((i, k));
        }
        for (position, path) in steps(&world.rows[r], hits, terms, ranks) {
            let here = (i, k, path);
            let at = &mut out[r][position].1;
            if at.as_ref().is_none_or(|before| here < *before) {
                *at = Some(here);
            }
        }
    }
    out
}

/// For every selector, per row, where the walks find each entry carrying
/// it, sorted.
fn walk_tier(world: &ObservedWorld, found: &[Vec<Found>]) -> HashMap<Tag16, Vec<(usize, Found)>> {
    let mut out: HashMap<Tag16, Vec<(usize, Found)>> = HashMap::new();
    for (r, row) in world.rows.iter().enumerate() {
        for (j, entry) in row.entries.iter().enumerate() {
            out.entry(entry.s)
                .or_default()
                .push((r, found[r][j].clone()));
        }
    }
    out.values_mut().for_each(|found| found.sort_unstable());
    out
}

/// Every hit of one walk below the node it names, by its position, with its
/// path: for each node on the way down, its step under its parent and what
/// the walk shows beneath it (the node's selector's rank, its own
/// description, the rule its self tag matched, and the same of its children,
/// sorted). A step is the node's ordinal where it shares its selector with a
/// sibling (an array's elements, whose ordinal is their index) and nothing
/// where it does not (an object's members, whose ordinals are a random
/// permutation, which would order the members differently in every world).
fn steps(
    row: &ObservedRow,
    hits: &[Hit],
    terms: &HashMap<Vec<u8>, usize>,
    ranks: &HashMap<Tag16, usize>,
) -> Vec<(usize, Vec<String>)> {
    let mut first: HashMap<usize, usize> = HashMap::new();
    for (h, hit) in hits.iter().enumerate() {
        let _ = first.entry(hit.position).or_insert(h);
    }
    // The hit each hit hangs off: walks go depth first, so a parent comes
    // before its children.
    let parent: Vec<Option<usize>> = hits
        .iter()
        .enumerate()
        .map(|(h, hit)| {
            hit.parent
                .and_then(|p| first.get(&p).copied())
                .filter(|&p| p < h)
        })
        .collect();
    let mut kids: Vec<Vec<usize>> = vec![Vec::new(); hits.len()];
    for (h, p) in parent.iter().enumerate() {
        if let Some(p) = p {
            kids[*p].push(h);
        }
    }
    let s = |h: usize| row.entries[hits[h].position].s;
    let step = |h: usize, p: usize| {
        let twins = kids[p].iter().filter(|&&d| s(d) == s(h)).count();
        hits[h].ordinal.filter(|_| twins > 1)
    };
    let mut below: Vec<String> = vec![String::new(); hits.len()];
    for h in (0..hits.len()).rev() {
        let mut children: Vec<String> = kids[h]
            .iter()
            .map(|&c| format!("{:?}{}", step(c, h), below[c]))
            .collect();
        children.sort_unstable();
        below[h] = format!(
            "({} {:?} {:?} {children:?})",
            ranks[&s(h)],
            entry_key(&row.entries[hits[h].position], terms),
            hits[h].rule
        );
    }
    let mut paths: Vec<Vec<String>> = vec![Vec::new(); hits.len()];
    let mut out = Vec::new();
    for h in 1..hits.len() {
        let Some(p) = parent[h] else {
            continue;
        };
        let mut path = paths[p].clone();
        path.push(format!("{:?}{}", step(h, p), below[h]));
        paths[h] = path.clone();
        out.push((hits[h].position, path));
    }
    out
}

/// Every pair of a projection with the depth of its group, `0` for the top.
fn pairs_by_depth(group: &ObservedGroup, depth: usize, out: &mut Vec<(usize, Tag16, Tag16)>) {
    out.extend(group.pairs.iter().map(|&(s, vs)| (depth, s, vs)));
    for element in &group.elements {
        pairs_by_depth(element, depth + 1, out);
    }
}

/// Every needle and `alt` sent, by its query and role.
fn needles(world: &ObservedWorld) -> Vec<Projection<'_>> {
    world
        .queries
        .iter()
        .enumerate()
        .flat_map(|(i, query)| match query {
            ObservedQuery::Contains { needle, alt } => {
                std::iter::once((format!("{i} needle"), needle))
                    .chain(alt.iter().map(move |a| (format!("{i} alt"), a)))
                    .collect()
            }
            ObservedQuery::Equals { needle } => vec![(format!("{i} needle"), needle)],
            _ => Vec::new(),
        })
        .collect()
}

/// Every value selector's colour: per row, the depths of the stored pairs
/// that carry it, and per needle (and `alt`), the depths of its pairs that
/// do. A value selector is a keyed hash of a path and a value, so its
/// selector is fixed and is not repeated here.
fn value_colours(world: &ObservedWorld) -> HashMap<Tag16, String> {
    let mut stored: HashMap<Tag16, Vec<Vec<usize>>> = HashMap::new();
    for (r, row) in world.rows.iter().enumerate() {
        let mut pairs = Vec::new();
        pairs_by_depth(&row.q, 0, &mut pairs);
        for (depth, _, vs) in pairs {
            stored
                .entry(vs)
                .or_insert_with(|| vec![Vec::new(); world.rows.len()])[r]
                .push(depth);
        }
    }
    let mut sent: HashMap<Tag16, Vec<(String, usize)>> = HashMap::new();
    for (what, needle) in needles(world) {
        let mut pairs = Vec::new();
        pairs_by_depth(needle, 0, &mut pairs);
        for (depth, _, vs) in pairs {
            sent.entry(vs).or_default().push((what.clone(), depth));
        }
    }
    let mut out = HashMap::new();
    for vs in stored.keys().chain(sent.keys()) {
        let mut rows = stored
            .get(vs)
            .cloned()
            .unwrap_or_else(|| vec![Vec::new(); world.rows.len()]);
        rows.iter_mut().for_each(|depths| depths.sort_unstable());
        let mut needles = sent.get(vs).cloned().unwrap_or_default();
        needles.sort_unstable();
        let _ = out.insert(*vs, format!("{rows:?}{needles:?}"));
    }
    out
}

/// Ranks for `keys`, equal keys sharing one, in the keys' order.
fn dense<K: Ord>(keys: &HashMap<Tag16, K>) -> HashMap<Tag16, usize> {
    let mut distinct: Vec<&K> = keys.values().collect();
    distinct.sort_unstable();
    distinct.dedup();
    keys.iter()
        .map(|(s, k)| (*s, distinct.binary_search(&k).expect("listed")))
        .collect()
}

fn classes(ranks: &HashMap<Tag16, usize>) -> usize {
    ranks.values().collect::<BTreeSet<_>>().len()
}

/// A group's own pairs, by their selectors' and value selectors' ranks.
fn flat(group: &ObservedGroup, ranks: &HashMap<Tag16, usize>) -> String {
    let mut pairs: Vec<(usize, usize)> = group
        .pairs
        .iter()
        .map(|(s, vs)| (ranks[s], ranks[vs]))
        .collect();
    pairs.sort_unstable();
    format!("{pairs:?}")
}

/// Where each pair of `group` and below it sits, recorded for its selector
/// and for its value selector: the projection, the depth, the other half of
/// the pair, and the group's own pairs, its parent's and its element
/// groups'.
fn places(
    group: &ObservedGroup,
    what: &str,
    depth: usize,
    parent: Option<&str>,
    ranks: &HashMap<Tag16, usize>,
    out: &mut HashMap<Tag16, Vec<String>>,
) {
    let mine = flat(group, ranks);
    let mut elements: Vec<String> = group.elements.iter().map(|g| flat(g, ranks)).collect();
    elements.sort_unstable();
    for (s, vs) in &group.pairs {
        let around = format!("{what} {depth} {mine} {parent:?} {elements:?}");
        out.entry(*s)
            .or_default()
            .push(format!("value {} {around}", ranks[vs]));
        out.entry(*vs)
            .or_default()
            .push(format!("selector {} {around}", ranks[s]));
    }
    for element in &group.elements {
        places(element, what, depth + 1, Some(&mine), ranks, out);
    }
}

/// `ranks` split by where each name's pairs sit in `projections`,
/// repeatedly, until nothing more splits.
fn refine(
    mut ranks: HashMap<Tag16, usize>,
    projections: &[Projection<'_>],
) -> HashMap<Tag16, usize> {
    loop {
        let mut at: HashMap<Tag16, Vec<String>> = HashMap::new();
        for (what, projection) in projections {
            places(projection, what, 0, None, &ranks, &mut at);
        }
        let keys: HashMap<Tag16, (usize, Vec<String>)> = ranks
            .iter()
            .map(|(s, rank)| {
                let mut mine = at.remove(s).unwrap_or_default();
                mine.sort_unstable();
                (*s, (*rank, mine))
            })
            .collect();
        let next = dense(&keys);
        if classes(&next) == classes(&ranks) {
            return next;
        }
        ranks = next;
    }
}

/// Every row's `q`, by its row.
fn stored(world: &ObservedWorld) -> Vec<Projection<'_>> {
    world
        .rows
        .iter()
        .enumerate()
        .map(|(r, row)| (format!("row {r}"), &row.q))
        .collect()
}

/// Every name in the world (a selector or a value selector, stored or
/// sent) by what it shows at rest: a selector by, per row, whether the root
/// carries it, its entries and its `q` pairs; a value selector by its
/// colour; then both refined by the groups of `q` their pairs sit in. Names
/// nothing at rest tells apart share a rank.
fn rest_ranks(
    world: &ObservedWorld,
    terms: &HashMap<Vec<u8>, usize>,
    colours: &HashMap<Tag16, String>,
) -> HashMap<Tag16, usize> {
    type AtRest = (bool, Vec<EntryKey>, Vec<(usize, String)>);
    let blank = || -> Vec<AtRest> { vec![(false, Vec::new(), Vec::new()); world.rows.len()] };
    let mut at_rest: HashMap<Tag16, Vec<AtRest>> = HashMap::new();
    for (r, row) in world.rows.iter().enumerate() {
        for (j, entry) in row.entries.iter().enumerate() {
            let mine = &mut at_rest.entry(entry.s).or_insert_with(blank)[r];
            mine.0 |= j == 0;
            mine.1.push(entry_key(entry, terms));
        }
        let mut pairs = Vec::new();
        pairs_by_depth(&row.q, 0, &mut pairs);
        for (depth, s, vs) in pairs {
            at_rest.entry(s).or_insert_with(blank)[r]
                .2
                .push((depth, colours[&vs].clone()));
        }
    }
    let (selectors, values) = first_seen(world);
    let mut rest: HashMap<Tag16, (u8, String)> = HashMap::new();
    for s in selectors {
        let mut mine = at_rest.get(&s).cloned().unwrap_or_else(blank);
        for (_, entries, pairs) in &mut mine {
            entries.sort_unstable();
            pairs.sort_unstable();
        }
        let _ = rest.insert(s, (0, format!("{mine:?}")));
    }
    for vs in values {
        let _ = rest.insert(vs, (1, colours[&vs].clone()));
    }
    refine(dense(&rest), &stored(world))
}

/// Every name in the world by its rank (see the module docs for the
/// tiers), every one its own: `rest` first, then the queries that name it,
/// then where the walks find a selector's entries, then the needles'
/// groups as `q`'s were.
fn ranks(
    world: &ObservedWorld,
    terms: &HashMap<Vec<u8>, usize>,
    walks: &[Walk],
    rest: &HashMap<Tag16, usize>,
) -> HashMap<Tag16, usize> {
    let walked = walk_tier(world, &addresses(world, walks, terms, rest));
    let mut sent: HashMap<Tag16, Vec<String>> = HashMap::new();
    for (i, query) in world.queries.iter().enumerate() {
        match query {
            ObservedQuery::Extract { s } => {
                sent.entry(*s).or_default().push(format!("{i} extract"));
            }
            ObservedQuery::Order { s, op } => {
                sent.entry(*s)
                    .or_default()
                    .push(format!("{i} order {}", terms[op]));
            }
            _ => {}
        }
    }
    // A needle is sent in a random order, so only which needle a name is
    // in, and at what depth, says anything; the groups it sits in there are
    // the refinement's.
    for (what, needle) in needles(world) {
        let mut pairs = Vec::new();
        pairs_by_depth(needle, 0, &mut pairs);
        for (depth, s, vs) in pairs {
            for name in [s, vs] {
                sent.entry(name)
                    .or_default()
                    .push(format!("{what} {depth}"));
            }
        }
    }
    let (selectors, values) = first_seen(world);
    let seen: Vec<Tag16> = selectors.into_iter().chain(values).collect();
    // Its rank at rest, the queries that name it, where the walks find it.
    type Full = (usize, Vec<String>, Vec<(usize, Found)>);
    let full: HashMap<Tag16, Full> = seen
        .iter()
        .map(|s| {
            let mut queries = sent.get(s).cloned().unwrap_or_default();
            queries.sort_unstable();
            let walks = walked.get(s).cloned().unwrap_or_default();
            (*s, (rest[s], queries, walks))
        })
        .collect();
    let mut projections = stored(world);
    projections.extend(needles(world));
    // Refine by the projections' groups and by the walks, each walk's nodes
    // described with the ranks so far, until neither splits anything: a
    // query that tells two selectors apart tells apart the nodes the walks
    // find beneath theirs.
    let settle = |mut ranks: HashMap<Tag16, usize>| loop {
        let refined = refine(ranks, &projections);
        let walked = walk_tier(world, &addresses(world, walks, terms, &refined));
        let keys: HashMap<Tag16, (usize, Vec<(usize, Found)>)> = refined
            .iter()
            .map(|(s, rank)| (*s, (*rank, walked.get(s).cloned().unwrap_or_default())))
            .collect();
        let next = dense(&keys);
        if classes(&next) == classes(&refined) {
            return next;
        }
        ranks = next;
    };
    let mut ranks = settle(dense(&full));
    // Names still tied are ones nothing tells apart (`$.a.b` and `$.a.b.c`
    // in a row `{"a": {"b": {"c": {}}}}`, at rest, or two values of one
    // array that every row holds together). Each tie is broken once, for
    // the entries and `q` alike, by setting the first of them apart and
    // refining again, so that the choice carries to every name it bears
    // on.
    loop {
        let mut by_rank: BTreeMap<usize, Vec<Tag16>> = BTreeMap::new();
        for s in &seen {
            by_rank.entry(ranks[s]).or_default().push(*s);
        }
        let Some(chosen) = by_rank
            .values()
            .find(|tied| tied.len() > 1)
            .map(|tied| tied[0])
        else {
            return ranks;
        };
        let keys: HashMap<Tag16, (usize, bool)> = ranks
            .iter()
            .map(|(s, rank)| (*s, (*rank, *s != chosen)))
            .collect();
        ranks = settle(dense(&keys));
    }
}

/// Every selector and every value selector in the world, each in the order
/// it first appears: in the stored rows' entries, then their `q`, then the
/// queries.
fn first_seen(world: &ObservedWorld) -> (Vec<Tag16>, Vec<Tag16>) {
    let mut selectors: Vec<Tag16> = Vec::new();
    let mut values: Vec<Tag16> = Vec::new();
    let note = |list: &mut Vec<Tag16>, name: Tag16| {
        if !list.contains(&name) {
            list.push(name);
        }
    };
    for row in &world.rows {
        row.entries.iter().for_each(|e| note(&mut selectors, e.s));
    }
    let mut pairs = Vec::new();
    for row in &world.rows {
        pairs_by_depth(&row.q, 0, &mut pairs);
    }
    for (_, needle) in needles(world) {
        pairs_by_depth(needle, 0, &mut pairs);
    }
    for (_, s, vs) in pairs {
        note(&mut selectors, s);
        note(&mut values, vs);
    }
    for query in &world.queries {
        if let ObservedQuery::Extract { s } | ObservedQuery::Order { s, .. } = query {
            note(&mut selectors, *s);
        }
    }
    (selectors, values)
}

/// A projection in the canonical order: its pairs by their selectors' and
/// value selectors' ranks, its element groups (each in the canonical order
/// itself) by their contents.
fn group(stored: &ObservedGroup, ranks: &HashMap<Tag16, usize>) -> ObservedGroup {
    let mut pairs = stored.pairs.clone();
    pairs.sort_by_key(|(s, vs)| (ranks[s], ranks[vs]));
    let mut elements: Vec<ObservedGroup> =
        stored.elements.iter().map(|g| group(g, ranks)).collect();
    elements.sort_by_cached_key(|g| contents(g, ranks));
    ObservedGroup { pairs, elements }
}

/// A canonical group's contents, as a string that sorts it among its
/// siblings.
fn contents(group: &ObservedGroup, ranks: &HashMap<Tag16, usize>) -> String {
    let elements: Vec<String> = group.elements.iter().map(|g| contents(g, ranks)).collect();
    format!("{}{elements:?}", flat(group, ranks))
}
