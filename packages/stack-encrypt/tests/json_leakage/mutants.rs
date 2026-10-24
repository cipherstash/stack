//! Mutant profiles: each drops or coarsens one clause of `L`, so that the
//! simulator built from it reveals less (or other) than the real scheme in
//! exactly that respect. The calibration runs each and expects some
//! distinguisher to notice; a clause whose mutant nothing notices is either
//! not load-bearing or has no distinguisher, and is listed in
//! `calibration.rs` with the reason.
//!
//! A mutant transforms a [`Leakage`] value. It never sees the plaintext, so
//! it can only coarsen what `L` already states, which is the point: the
//! mutant is "the profile without this clause".

use std::collections::{BTreeMap, HashMap};

use proptest::prelude::RngCore;
use proptest::test_runner::TestRng;

use super::profile::{
    EntryLeakage, GateLeak, GroupLeakage, Leakage, QueryLeakage, RowLeakage, Step, AEAD_OVERHEAD,
};

/// One mutant: its name, the clause it drops (a field or sentence of the
/// profile), and the transformation.
pub struct Mutant {
    pub name: &'static str,
    pub clause: &'static str,
    pub apply: fn(&mut Leakage, &mut TestRng),
}

/// Fresh opaque names, far above any the profile hands out.
struct Fresh(usize);

impl Fresh {
    fn new() -> Self {
        Self(1 << 40)
    }

    fn next(&mut self) -> usize {
        self.0 += 1;
        self.0
    }
}

fn shuffle<T>(items: &mut [T], rng: &mut TestRng) {
    for i in (1..items.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

fn groups_mut(group: &mut GroupLeakage, f: &mut impl FnMut(&mut GroupLeakage)) {
    f(group);
    for element in &mut group.elements {
        groups_mut(element, f);
    }
}

/// Every projection in the leakage, stored and sent.
fn every_group(leakage: &mut Leakage, mut f: impl FnMut(&mut GroupLeakage)) {
    for row in &mut leakage.rows {
        groups_mut(&mut row.projection, &mut f);
    }
    for query in &mut leakage.queries {
        match query {
            QueryLeakage::Contains { needle, alt } => {
                groups_mut(needle, &mut f);
                if let Some(alt) = alt {
                    groups_mut(alt, &mut f);
                }
            }
            QueryLeakage::Equals { needle } => groups_mut(needle, &mut f),
            _ => {}
        }
    }
}

/// Reorder a row's entries: `order[k]` is the old position of the entry now
/// at `k`. Parents and every query's positions follow.
fn reorder(leakage: &mut Leakage, r: usize, order: &[usize]) {
    let mut new_at = vec![0; order.len()];
    for (k, &old) in order.iter().enumerate() {
        new_at[old] = k;
    }
    let row = &mut leakage.rows[r];
    let old = std::mem::take(&mut row.entries);
    row.entries = order
        .iter()
        .map(|&o| EntryLeakage {
            parent: old[o].parent.map(|p| new_at[p]),
            ..old[o].clone()
        })
        .collect();
    for query in &mut leakage.queries {
        if let QueryLeakage::Subtree { reach, named, .. } = query {
            for at in reach[r].iter_mut().chain(named[r].iter_mut()) {
                *at = new_at[*at];
            }
        }
    }
}

fn children(row: &RowLeakage) -> Vec<Vec<usize>> {
    let mut kids = vec![Vec::new(); row.entries.len()];
    for (i, entry) in row.entries.iter().enumerate() {
        if let Some(p) = entry.parent {
            kids[p].push(i);
        }
    }
    kids
}

// =============================================================================
// At rest
// =============================================================================

fn selectors_all_distinct(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for row in &mut l.rows {
        for entry in &mut row.entries {
            entry.selector = fresh.next();
        }
    }
    every_group(l, |g| {
        for pair in &mut g.pairs {
            pair.0 = fresh.next();
        }
    });
}

fn selectors_per_row_only(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for row in &mut l.rows {
        let mut mine: HashMap<usize, usize> = HashMap::new();
        for entry in &mut row.entries {
            entry.selector = *mine.entry(entry.selector).or_insert_with(|| fresh.next());
        }
        groups_mut(&mut row.projection, &mut |g| {
            for pair in &mut g.pairs {
                pair.0 = *mine.entry(pair.0).or_insert_with(|| fresh.next());
            }
        });
    }
}

/// Array positions kept in selectors, as if `$.a[0]` and `$.a[1]` had
/// different selectors: each element's selector is told apart by the
/// positions on its way down.
fn positions_in_selectors(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    let mut names: HashMap<(usize, Vec<u64>), usize> = HashMap::new();
    for row in &mut l.rows {
        let positions: Vec<Vec<u64>> = (0..row.entries.len())
            .map(|i| {
                let mut out = Vec::new();
                let mut at = Some(i);
                while let Some(j) = at {
                    if let Step::Element(n) = row.entries[j].step {
                        out.push(n);
                    }
                    at = row.entries[j].parent;
                }
                out
            })
            .collect();
        for (entry, positions) in row.entries.iter_mut().zip(positions) {
            if !positions.is_empty() {
                entry.selector = *names
                    .entry((entry.selector, positions))
                    .or_insert_with(|| fresh.next());
            }
        }
    }
}

fn entry_count_padded(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for row in &mut l.rows {
        row.entries.push(EntryLeakage {
            selector: fresh.next(),
            parent: Some(0),
            step: Step::Member,
            head: None,
            has_parent_tag: true,
            ciphertext_len: AEAD_OVERHEAD + 10,
            ordering: None,
        });
    }
}

fn order_random_permutation(l: &mut Leakage, rng: &mut TestRng) {
    for r in 0..l.rows.len() {
        let mut order: Vec<usize> = (1..l.rows[r].entries.len()).collect();
        shuffle(&mut order, rng);
        order.insert(0, 0);
        reorder(l, r, &order);
    }
}

/// Still depth-first, but an object's members in random order rather than
/// sorted by key.
fn members_unsorted(l: &mut Leakage, rng: &mut TestRng) {
    for r in 0..l.rows.len() {
        let kids = children(&l.rows[r]);
        let mut order = Vec::new();
        let mut stack = vec![0];
        while let Some(i) = stack.pop() {
            order.push(i);
            let mut mine = kids[i].clone();
            if mine
                .iter()
                .all(|&k| l.rows[r].entries[k].step == Step::Member)
            {
                shuffle(&mut mine, rng);
            }
            stack.extend(mine.into_iter().rev());
        }
        reorder(l, r, &order);
    }
}

fn parent_tag_on_every_entry(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            entry.has_parent_tag = true;
        }
    }
}

fn parent_tag_on_no_entry(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            entry.has_parent_tag = false;
        }
    }
}

fn ciphertext_length_bucketed(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            entry.ciphertext_len = entry.ciphertext_len.div_ceil(32) * 32;
        }
    }
}

fn sealed_root_length_hidden(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        if row.sealed_root {
            row.entries[0].ciphertext_len = AEAD_OVERHEAD + 6;
        }
    }
}

fn value_selectors_all_distinct(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    every_group(l, |g| {
        for pair in &mut g.pairs {
            pair.1 = fresh.next();
        }
    });
}

/// A value selector that names the path and nothing of the value.
fn value_selectors_path_only(l: &mut Leakage, _: &mut TestRng) {
    every_group(l, |g| {
        for pair in &mut g.pairs {
            pair.1 = pair.0;
        }
    });
}

fn flatten_group(group: &mut GroupLeakage) {
    let mut elements = std::mem::take(&mut group.elements);
    for element in &mut elements {
        flatten_group(element);
        group.pairs.append(&mut element.pairs);
    }
}

fn projection_flat(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        flatten_group(&mut row.projection);
    }
}

fn projection_shuffled(l: &mut Leakage, rng: &mut TestRng) {
    for row in &mut l.rows {
        groups_mut(&mut row.projection, &mut |g| shuffle(&mut g.pairs, rng));
    }
}

fn ordering_terms_absent(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            entry.ordering = None;
        }
    }
}

fn ordering_terms_unordered(l: &mut Leakage, rng: &mut TestRng) {
    shuffle(&mut l.ordering_ranks, rng);
}

/// Every stored term a class of its own, so equal values no longer show,
/// with the order otherwise kept: ties broken at random.
fn ordering_terms_all_distinct(l: &mut Leakage, rng: &mut TestRng) {
    let mut fresh = Fresh::new();
    let mut keyed: Vec<((usize, u64), usize)> = Vec::new();
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if let Some(op) = &mut entry.ordering {
                let class = fresh.next();
                keyed.push(((l.ordering_ranks[op.class], rng.next_u64()), class));
                op.class = class;
            }
        }
    }
    for query in &mut l.queries {
        if let QueryLeakage::Order { bound, .. } = query {
            let class = fresh.next();
            keyed.push(((l.ordering_ranks[bound.class], rng.next_u64()), class));
            bound.class = class;
        }
    }
    keyed.sort_unstable();
    let ranks: BTreeMap<usize, usize> = keyed
        .into_iter()
        .enumerate()
        .map(|(rank, (_, class))| (class, rank))
        .collect();
    // Rebuild the rank table densely over the new classes.
    let mut remap: HashMap<usize, usize> = HashMap::new();
    let mut table = Vec::new();
    for (class, rank) in ranks {
        let _ = remap.insert(class, table.len());
        table.push(rank);
    }
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if let Some(op) = &mut entry.ordering {
                op.class = remap[&op.class];
            }
        }
    }
    for query in &mut l.queries {
        if let QueryLeakage::Order { bound, .. } = query {
            bound.class = remap[&bound.class];
        }
    }
    l.ordering_ranks = table;
}

/// Equal values at two ordered paths get different terms: what the page's
/// summary sentence "Not revealed at rest: […] whether two different paths
/// hold the same value" would need, against its own `op` row ("leaves at
/// two ordered paths compare with each other too"). The order is kept, and
/// ties across paths are broken by path.
fn ordering_terms_per_path(l: &mut Leakage, _: &mut TestRng) {
    let mut keyed: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for row in &l.rows {
        for entry in &row.entries {
            if let Some(op) = &entry.ordering {
                let _ = keyed.insert((l.ordering_ranks[op.class], entry.selector), 0);
            }
        }
    }
    for query in &l.queries {
        if let QueryLeakage::Order { selector, bound } = query {
            let _ = keyed.insert((l.ordering_ranks[bound.class], *selector), 0);
        }
    }
    // Classes in (rank, path) order, so a class's index is its new rank.
    for (class, slot) in keyed.values_mut().enumerate() {
        *slot = class;
    }
    let old_ranks = l.ordering_ranks.clone();
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if let Some(op) = &mut entry.ordering {
                op.class = keyed[&(old_ranks[op.class], entry.selector)];
            }
        }
    }
    for query in &mut l.queries {
        if let QueryLeakage::Order { selector, bound } = query {
            bound.class = keyed[&(old_ranks[bound.class], *selector)];
        }
    }
    l.ordering_ranks = (0..keyed.len()).collect();
}

fn ordering_term_length_constant(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if let Some(op) = &mut entry.ordering {
                op.len = 65;
            }
        }
    }
    for query in &mut l.queries {
        if let QueryLeakage::Order { bound, .. } = query {
            bound.len = 65;
        }
    }
}

/// A member's ordinal is its place in the stored (key) order rather than a
/// keyed rank: what the chain would be without decision 11.
fn member_ranks_follow_key_order(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        let kids = children(row);
        for siblings in kids {
            let members: Vec<usize> = siblings
                .into_iter()
                .filter(|&k| row.entries[k].step == Step::Member)
                .collect();
            for (o, k) in members.into_iter().enumerate() {
                row.entries[k].step = Step::Element(o as u64);
            }
        }
    }
}

fn sealed_flag_flipped(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        row.sealed_root = !row.sealed_root;
    }
}

fn data_key_shared(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        row.data_key = 0;
    }
}

fn keyset_per_row(l: &mut Leakage, _: &mut TestRng) {
    for (r, row) in l.rows.iter_mut().enumerate() {
        row.keyset = r;
    }
}

/// Head tokens per row rather than column-wide.
fn tokens_per_row(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if entry.head.is_some() {
                entry.head = Some(fresh.next());
            }
        }
    }
}

// =============================================================================
// Queries
// =============================================================================

fn extraction_selector_fresh(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for query in &mut l.queries {
        if let QueryLeakage::Extract { selector } = query {
            *selector = fresh.next();
        }
    }
}

/// A query that repeats an earlier one sends unrelated terms: queries are
/// not deterministic.
fn queries_nondeterministic(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    let mut seen: Vec<QueryLeakage> = Vec::new();
    for query in &mut l.queries {
        if seen.contains(query) {
            match query {
                QueryLeakage::Extract { selector } => *selector = fresh.next(),
                QueryLeakage::Subtree { token, gates, .. } => {
                    token.head = fresh.next();
                    for gate in gates {
                        match gate {
                            GateLeak::Selector(s) | GateLeak::Slot(_, s) => *s = fresh.next(),
                        }
                    }
                }
                QueryLeakage::Contains { needle, .. } | QueryLeakage::Equals { needle } => {
                    groups_mut(needle, &mut |g| {
                        for pair in &mut g.pairs {
                            *pair = (fresh.next(), fresh.next());
                        }
                    });
                }
                QueryLeakage::Order { selector, .. } => *selector = fresh.next(),
            }
        } else {
            seen.push(query.clone());
        }
    }
}

/// No query's token links any entry: parent tags are random everywhere, as
/// if they were not chained from the tokens at all.
fn parent_tags_unchained(l: &mut Leakage, _: &mut TestRng) {
    for query in &mut l.queries {
        if let QueryLeakage::Subtree { reach, .. } = query {
            for row in reach {
                row.clear();
            }
        }
    }
}

/// A token links only what the read names: the nodes on the path below the
/// token's node and the subtrees of the nodes the path reaches. What the
/// page would say if the subtree read revealed no more than it asked for.
fn token_reaches_named_nodes_only(l: &mut Leakage, _: &mut TestRng) {
    for q in 0..l.queries.len() {
        let QueryLeakage::Subtree { reach, named, .. } = &l.queries[q] else {
            continue;
        };
        let narrowed: Vec<Vec<usize>> = reach
            .iter()
            .zip(named)
            .enumerate()
            .map(|(r, (reach, named))| {
                let row = &l.rows[r];
                reach
                    .iter()
                    .copied()
                    .filter(|&i| {
                        named.iter().any(|&n| {
                            // `i` is on the path to `n`, is `n`, or is below it.
                            let under = |a: usize, b: usize| {
                                let mut at = Some(a);
                                while let Some(j) = at {
                                    if j == b {
                                        return true;
                                    }
                                    at = row.entries[j].parent;
                                }
                                false
                            };
                            under(n, i) || under(i, n)
                        })
                    })
                    .collect()
            })
            .collect();
        if let QueryLeakage::Subtree { reach, .. } = &mut l.queries[q] {
            *reach = narrowed;
        }
    }
}

/// A token for a path through array positions is not chained from its
/// head's: the client would send an unrelated token.
fn position_tokens_unchained(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for query in &mut l.queries {
        if let QueryLeakage::Subtree { token, .. } = query {
            if !token.positions.is_empty() {
                token.head = fresh.next();
                token.positions.clear();
            }
        }
    }
}

fn slot_positions_hidden(l: &mut Leakage, _: &mut TestRng) {
    for query in &mut l.queries {
        if let QueryLeakage::Subtree { gates, .. } = query {
            for gate in gates {
                if let GateLeak::Slot(n, _) = gate {
                    *n = 0;
                }
            }
        }
    }
}

fn gates_dropped(l: &mut Leakage, _: &mut TestRng) {
    for query in &mut l.queries {
        if let QueryLeakage::Subtree { gates, .. } = query {
            gates.clear();
        }
    }
}

fn needle_flat(l: &mut Leakage, _: &mut TestRng) {
    for query in &mut l.queries {
        if let QueryLeakage::Contains { needle, .. } | QueryLeakage::Equals { needle } = query {
            flatten_group(needle);
        }
    }
}

fn needle_alt_dropped(l: &mut Leakage, _: &mut TestRng) {
    for query in &mut l.queries {
        if let QueryLeakage::Contains { alt, .. } = query {
            *alt = None;
        }
    }
}

/// A bound whose place among the stored terms is random.
fn bound_rank_random(l: &mut Leakage, rng: &mut TestRng) {
    let top = l.ordering_ranks.len() as u64 + 1;
    for q in 0..l.queries.len() {
        if let QueryLeakage::Order { bound, .. } = &mut l.queries[q] {
            bound.class = l.ordering_ranks.len();
            l.ordering_ranks
                .push((rng.next_u64() % top) as usize * 2 + 1);
        }
    }
    // Stored ranks on the even numbers, so a random bound never ties one.
    let stored = l.ordering_ranks.len()
        - l.queries
            .iter()
            .filter(|q| matches!(q, QueryLeakage::Order { .. }))
            .count();
    for rank in &mut l.ordering_ranks[..stored] {
        *rank *= 2;
    }
}

macro_rules! mutants {
    ($($name:ident => $clause:literal),+ $(,)?) => {
        /// Every mutant, in a fixed order.
        pub fn all() -> Vec<Mutant> {
            vec![$(Mutant {
                name: stringify!($name),
                clause: $clause,
                apply: $name,
            }),+]
        }
    };
}

mutants!(
    selectors_all_distinct => "EntryLeakage::selector (equality)",
    selectors_per_row_only => "EntryLeakage::selector (\"the same in every row\")",
    positions_in_selectors => "EntryLeakage::selector (\"Array elements share their array's selector\")",
    entry_count_padded => "RowLeakage::entries (\"the number of entries\")",
    order_random_permutation => "RowLeakage::entries (the stored order)",
    members_unsorted => "RowLeakage::entries (\"an object's members in the sorted order of their key names\")",
    parent_tag_on_every_entry => "EntryLeakage::has_parent_tag",
    parent_tag_on_no_entry => "EntryLeakage::has_parent_tag",
    ciphertext_length_bucketed => "EntryLeakage::ciphertext_len",
    sealed_root_length_hidden => "EntryLeakage::ciphertext_len (\"the root entry's length is the document's length as JSON\")",
    value_selectors_all_distinct => "GroupLeakage::pairs (value selector equality)",
    value_selectors_path_only => "GroupLeakage::pairs (\"a keyed hash of the path and the value\")",
    projection_flat => "GroupLeakage::elements (\"nested by array element\")",
    projection_shuffled => "GroupLeakage::pairs (\"in the same order\")",
    ordering_terms_absent => "EntryLeakage::ordering (presence)",
    ordering_terms_unordered => "Leakage::ordering_ranks (\"the order of that leaf's value among every row\")",
    ordering_terms_all_distinct => "OrderingLeak::class (\"which rows hold equal values\")",
    ordering_term_length_constant => "OrderingLeak::len (beyond the page)",
    ordering_terms_per_path => "OrderingLeak::class across paths (\"leaves at two ordered paths compare with each other too\")",
    member_ranks_follow_key_order => "EntryLeakage::step (a member's ordinal is its keyed rank)",
    sealed_flag_flipped => "RowLeakage::sealed_root",
    data_key_shared => "RowLeakage::data_key (\"the data key's identifier (unique to the row)\")",
    keyset_per_row => "RowLeakage::keyset (\"the keyset the data key was minted under\")",
    tokens_per_row => "EntryLeakage::head (\"Tokens are column-wide\")",
    extraction_selector_fresh => "QueryLeakage::Extract (\"The selector of the path asked\")",
    queries_nondeterministic => "every query term is a function of the query (\"Tokens are column-wide and do not expire\")",
    parent_tags_unchained => "QueryLeakage::Subtree::reach (a token links anything at all)",
    token_reaches_named_nodes_only => "QueryLeakage::Subtree::reach (\"its node's subtree in every row\", not the path asked)",
    position_tokens_unchained => "TokenName::positions (\"while the path goes on through array positions, the element they reach\")",
    slot_positions_hidden => "GateLeak::Slot (\"with the position n in the clear\")",
    gates_dropped => "QueryLeakage::Subtree::gates (\"one gate per step below it\")",
    needle_flat => "QueryLeakage::Contains::needle (\"its element grouping\")",
    needle_alt_dropped => "QueryLeakage::Contains::alt",
    bound_rank_random => "QueryLeakage::Order::bound (\"the bound's place in the order of the stored values\")",
);
