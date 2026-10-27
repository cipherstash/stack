//! Mutant profiles: each drops or coarsens one clause of `L`, so that the
//! simulator built from it reveals less (or other) than the real scheme in
//! exactly that respect. The calibration runs each and expects some
//! distinguisher to notice; a clause whose mutant nothing notices is either
//! not load-bearing or has no distinguisher, and is listed in
//! `calibration.rs` with the reason.
//!
//! A mutant transforms a [`Leakage`] value. It never sees the plaintext, so
//! it can only coarsen what `L` already states, which is the point: the
//! mutant is "the profile without this clause". A few state a format the
//! code does not have, to show the distinguishers would see it: the
//! pre-#1363 read's top-level token (`ancestor_token_sent`), the pre-#1363
//! member rule (`member_tokens_carry_ordinal`), the depth-first stored
//! order before the random one (`stored_order_depth_first`), the walk's
//! order a needle was sent in before it was shuffled
//! (`needles_sent_in_walk_order`).

use std::collections::{BTreeMap, HashMap};

use proptest::prelude::RngCore;
use proptest::test_runner::TestRng;

use super::profile::{
    EntryLeakage, GroupLeakage, KindOrder, Leakage, OrderKind, Placement, QueryLeakage, ReadLeak,
    RowLeakage, Rule, SentOrder, Step, StoredOrder, TokenName, TokenStep, AEAD_OVERHEAD,
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

/// Every token a subtree read sends, with the read's budget.
fn every_read(leakage: &mut Leakage, mut f: impl FnMut(&mut Vec<ReadLeak>)) {
    for query in &mut leakage.queries {
        if let QueryLeakage::Subtree { reads, .. } = query {
            f(reads);
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
            rule: Some(Rule::Member),
            has_parent_tag: true,
            self_tag: Some(fresh.next()),
            ciphertext_len: AEAD_OVERHEAD + 10,
            ordering: None,
        });
    }
}

/// Every node below depth one hangs off its grandparent instead of its
/// parent: the shape a token's walk links is not the document's.
fn parents_lifted(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        let parents: Vec<Option<usize>> = row.entries.iter().map(|e| e.parent).collect();
        for entry in &mut row.entries {
            if let Some(grandparent) = entry.parent.and_then(|p| parents[p]) {
                entry.parent = Some(grandparent);
            }
        }
    }
}

/// An array's elements sit at their positions reversed under its token,
/// so an element's ordinal is not its index.
fn element_ordinals_reversed(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for siblings in children(row) {
            let elements: Vec<usize> = siblings
                .into_iter()
                .filter(|&k| matches!(row.entries[k].step, Step::Element(_)))
                .collect();
            let n = elements.len() as u64;
            for k in elements {
                if let Step::Element(i) = row.entries[k].step {
                    row.entries[k].step = Step::Element(n - 1 - i);
                }
            }
        }
    }
}

/// A key tag of another length than the key service's.
fn key_tag_shortened(l: &mut Leakage, _: &mut TestRng) {
    l.key_tag_len = 16;
}

/// The stored order before the random one: depth-first, the root first,
/// an object's members in key order, and `q` in the same walk's order, which
/// gave every row's tree away (#1357).
fn stored_order_depth_first(l: &mut Leakage, _: &mut TestRng) {
    l.stored_order = StoredOrder::DepthFirst;
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
    let mut keyed: BTreeMap<(OrderKind, usize, usize), usize> = BTreeMap::new();
    for row in &l.rows {
        for entry in &row.entries {
            if let Some(op) = &entry.ordering {
                let _ = keyed.insert((op.kind, l.ordering_ranks[op.class], entry.selector), 0);
            }
        }
    }
    for query in &l.queries {
        if let QueryLeakage::Order { selector, bound } = query {
            let _ = keyed.insert((bound.kind, l.ordering_ranks[bound.class], *selector), 0);
        }
    }
    // Classes in (kind, rank, path) order, so a class's index orders it
    // within its kind.
    for (class, slot) in keyed.values_mut().enumerate() {
        *slot = class;
    }
    let old_ranks = l.ordering_ranks.clone();
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if let Some(op) = &mut entry.ordering {
                op.class = keyed[&(op.kind, old_ranks[op.class], entry.selector)];
            }
        }
    }
    for query in &mut l.queries {
        if let QueryLeakage::Order { selector, bound } = query {
            bound.class = keyed[&(bound.kind, old_ranks[bound.class], *selector)];
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

/// A number's and a string's terms compare in jsonb's order, numbers first,
/// whatever the key: the order the page says the scheme does not keep.
fn mixed_kinds_jsonb_order(l: &mut Leakage, _: &mut TestRng) {
    l.kind_order = KindOrder::Fixed(Placement::Above);
}

/// The terms show their order and lengths and no shared prefix beyond what
/// those force: what the page would say without "the term also shows how
/// long that common prefix is".
fn ordering_prefixes_hidden(l: &mut Leakage, _: &mut TestRng) {
    l.ordering_prefixes.clear();
}

/// A member's ordinal is its place in the key order rather than in a random
/// permutation: what the chain would be if the ordinals ranked the keys.
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

/// No entry carries a self tag.
fn self_tags_absent(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            entry.self_tag = None;
        }
    }
}

/// A self tag that is not salted by the row: the same node in two rows
/// carries the same one, named by its selector and its place among the
/// row's entries with that selector.
fn self_tags_linkable_across_rows(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    let mut names: HashMap<(usize, usize), usize> = HashMap::new();
    for row in &mut l.rows {
        let mut seen: HashMap<usize, usize> = HashMap::new();
        for entry in &mut row.entries {
            let k = seen.entry(entry.selector).or_default();
            let name = *names
                .entry((entry.selector, *k))
                .or_insert_with(|| fresh.next());
            *k += 1;
            entry.self_tag = Some(name);
        }
    }
}

/// A self tag that is not distinct per entry: the entries of a row that
/// share a selector (an array's elements) share one.
fn self_tags_per_selector(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for row in &mut l.rows {
        let mut names: HashMap<usize, usize> = HashMap::new();
        for entry in &mut row.entries {
            entry.self_tag = Some(*names.entry(entry.selector).or_insert_with(|| fresh.next()));
        }
    }
}

/// The member rule hidden: every member's token takes the element rule
/// with its ordinal, so the database's test of a hit's self tag never
/// says "member". What the page as #1363 published it states, which says
/// nothing of the rule ([`super::profile::Clauses::hit_rule`]).
fn hit_rule_uniform(l: &mut Leakage, _: &mut TestRng) {
    for row in &mut l.rows {
        for entry in &mut row.entries {
            if entry.rule == Some(Rule::Member) {
                entry.rule = Some(Rule::Element);
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

/// An ordering bound's selector unrelated to the stored one of its path.
fn order_selector_fresh(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    for query in &mut l.queries {
        if let QueryLeakage::Order { selector, .. } = query {
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
                QueryLeakage::Subtree { reads, .. } => {
                    for read in reads {
                        read.token.head = fresh.next();
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

/// A token finds its node in one row only, as a token salted per row
/// would: "Tokens are column-wide".
fn tokens_per_row(l: &mut Leakage, _: &mut TestRng) {
    every_read(l, |reads| {
        for read in reads {
            let mut kept = false;
            for (hit, reach) in read.hits.iter_mut().zip(&mut read.reach) {
                if hit.is_some() {
                    if kept {
                        *hit = None;
                        reach.clear();
                    }
                    kept = true;
                }
            }
        }
    });
}

/// No token finds or links anything: self and parent tags random
/// everywhere, as if they were not derived from the tokens at all.
fn tokens_find_nothing(l: &mut Leakage, _: &mut TestRng) {
    every_read(l, |reads| {
        for read in reads {
            read.hits.iter_mut().for_each(|h| *h = None);
            read.reach.iter_mut().for_each(Vec::clear);
        }
    });
}

/// A token finds its node and links nothing below it: what the page would
/// say if a read revealed no more than the node it names.
fn token_reaches_its_node_only(l: &mut Leakage, _: &mut TestRng) {
    every_read(l, |reads| {
        for read in reads {
            read.reach.iter_mut().for_each(Vec::clear);
        }
    });
}

/// A probe that finds its element links nothing below it: what the page
/// would say without its exception ("In a row where a probe finds an
/// element, the database also walks that element's subtree").
fn probe_reaches_nothing(l: &mut Leakage, _: &mut TestRng) {
    every_read(l, |reads| {
        for read in reads.iter_mut().filter(|r| r.probe) {
            read.reach.iter_mut().for_each(Vec::clear);
        }
    });
}

/// Each read also sends the token of the head its path starts from (the
/// top-level field under the sealed root, the root with it open), which
/// links that head's whole subtree in every row: the read before #1363,
/// which sent the top-level field's token for any path below it. Its hits
/// are the heads above the read's own hits, so a row where the read finds
/// nothing gets none.
fn ancestor_token_sent(l: &mut Leakage, _: &mut TestRng) {
    let rows = l.rows.clone();
    every_read(l, |reads| {
        let Some(first) = reads.iter().find(|r| !r.token.steps.is_empty()).cloned() else {
            return;
        };
        let head = |row: &RowLeakage, mut at: usize| {
            let depth = if row.sealed_root { 1 } else { 0 };
            let mut chain = vec![at];
            while let Some(p) = row.entries[at].parent {
                chain.push(p);
                at = p;
            }
            chain.iter().rev().nth(depth).copied()
        };
        let hits: Vec<Option<usize>> = rows
            .iter()
            .enumerate()
            .map(|(r, row)| {
                reads
                    .iter()
                    .find_map(|read| read.hits[r])
                    .and_then(|h| head(row, h))
            })
            .collect();
        let reach = rows
            .iter()
            .zip(&hits)
            .map(|(row, hit)| {
                let Some(top) = *hit else { return Vec::new() };
                (0..row.entries.len())
                    .filter(|&i| {
                        let mut at = i;
                        while row.entries[at].has_parent_tag {
                            match row.entries[at].parent {
                                Some(p) if p == top => return true,
                                Some(p) => at = p,
                                None => return false,
                            }
                        }
                        false
                    })
                    .collect()
            })
            .collect();
        reads.insert(
            0,
            ReadLeak {
                token: TokenName {
                    head: first.token.head,
                    steps: Vec::new(),
                },
                probe: false,
                hits,
                reach,
            },
        );
    });
}

/// A read's token is not derived from its path: every token with a step
/// below its head is unrelated to its head's, so no token is derivable
/// from another.
fn tokens_not_chained(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    every_read(l, |reads| {
        for read in reads {
            if !read.token.steps.is_empty() {
                read.token = TokenName {
                    head: fresh.next(),
                    steps: Vec::new(),
                };
            }
        }
    });
}

/// A member rule that hashes the ordinal, `H16("t" ‖ t(parent) ‖ s ‖
/// LE32(o))`: the client cannot derive a member's
/// token from the path, so a read through a key step below its head sends a
/// token that names nothing.
fn member_tokens_carry_ordinal(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    every_read(l, |reads| {
        for read in reads {
            if read
                .token
                .steps
                .iter()
                .any(|s| matches!(s, TokenStep::Member(_)))
            {
                read.token = TokenName {
                    head: fresh.next(),
                    steps: Vec::new(),
                };
                read.hits.iter_mut().for_each(|h| *h = None);
                read.reach.iter_mut().for_each(Vec::clear);
            }
        }
    });
}

/// An element's token without its index: every element of an array would
/// share one token.
fn element_tokens_without_index(l: &mut Leakage, _: &mut TestRng) {
    every_read(l, |reads| {
        for read in reads {
            for step in &mut read.token.steps {
                if let TokenStep::Element(_, i) = step {
                    *i = 0;
                }
            }
        }
    });
}

/// No probe is sent: a wildcard's tokens stop at `N − 1`.
fn probes_dropped(l: &mut Leakage, _: &mut TestRng) {
    every_read(l, |reads| reads.retain(|r| !r.probe));
}

/// The tokens are sent in an order unrelated to the paths they name.
fn token_list_shuffled(l: &mut Leakage, rng: &mut TestRng) {
    every_read(l, |reads| shuffle(reads, rng));
}

/// The token list padded with tokens that name nothing, to the next power
/// of two: a list whose length does not give the bound away.
fn token_list_padded(l: &mut Leakage, _: &mut TestRng) {
    let mut fresh = Fresh::new();
    let rows = l.rows.len();
    every_read(l, |reads| {
        let target = (reads.len() + 1).next_power_of_two();
        while reads.len() < target {
            reads.push(ReadLeak {
                token: TokenName {
                    head: fresh.next(),
                    steps: Vec::new(),
                },
                probe: false,
                hits: vec![None; rows],
                reach: vec![Vec::new(); rows],
            });
        }
    });
}

/// The budget is not sent: every read goes in full.
fn budget_not_sent(l: &mut Leakage, _: &mut TestRng) {
    for query in &mut l.queries {
        if let QueryLeakage::Subtree { budget, .. } = query {
            *budget = 0;
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

/// Every needle sent in the walk's order, an object's members in key byte
/// order: how the client sent a needle before it shuffled it, which told
/// the database which of two sibling keys sorts first, and sent one needle
/// in one order every time.
fn needles_sent_in_walk_order(l: &mut Leakage, _: &mut TestRng) {
    l.sent_order = SentOrder::Walk;
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
    parents_lifted => "EntryLeakage::parent (each node's parent, which a token's walk links)",
    element_ordinals_reversed => "EntryLeakage::step (\"an element's index is the ordinal it is found at\")",
    stored_order_depth_first => "Leakage::stored_order (\"stored in a random order […] with the root first\"): the depth-first order before",
    parent_tag_on_every_entry => "EntryLeakage::has_parent_tag",
    parent_tag_on_no_entry => "EntryLeakage::has_parent_tag",
    self_tags_absent => "EntryLeakage::self_tag (\"the self tag on every entry\")",
    self_tags_linkable_across_rows => "EntryLeakage::self_tag (\"salted by the document's iv, so it is unrelated bytes in every row\")",
    self_tags_per_selector => "EntryLeakage::self_tag (\"links no entry to another\")",
    ciphertext_length_bucketed => "EntryLeakage::ciphertext_len",
    sealed_root_length_hidden => "EntryLeakage::ciphertext_len (\"the root entry's length is the document's length as JSON\")",
    value_selectors_all_distinct => "GroupLeakage::pairs (value selector equality)",
    value_selectors_path_only => "GroupLeakage::pairs (\"a keyed hash of the path and the value\")",
    projection_flat => "GroupLeakage::elements (\"nested by array element\")",
    ordering_terms_absent => "EntryLeakage::ordering (presence)",
    ordering_terms_unordered => "Leakage::ordering_ranks (\"the order of that leaf's value among every row\")",
    ordering_terms_all_distinct => "OrderingLeak::class (\"which rows hold equal values\")",
    ordering_term_length_constant => "OrderingLeak::len (\"Its length is the leaf's length\")",
    ordering_terms_per_path => "OrderingLeak::class across paths (\"two ordered paths holding equal values carry equal terms\")",
    mixed_kinds_jsonb_order => "Leakage::kind_order (\"the order between a number and a string depends on the column key and is not jsonb's\")",
    ordering_prefixes_hidden => "Leakage::ordering_prefixes (\"the term also shows how long that common prefix is\")",
    member_ranks_follow_key_order => "EntryLeakage::step (a member's ordinal is a random permutation's)",
    hit_rule_uniform => "EntryLeakage::rule (the member or element rule a walk's hit matches; added to the page by #1362)",
    sealed_flag_flipped => "RowLeakage::sealed_root",
    data_key_shared => "RowLeakage::data_key (\"the data key's identifier (unique to the row)\")",
    keyset_per_row => "RowLeakage::keyset (\"the keyset the data key was minted under\")",
    key_tag_shortened => "Leakage::key_tag_len (the header's key tag, a column constant)",
    extraction_selector_fresh => "QueryLeakage::Extract (\"The selector of the path asked\")",
    order_selector_fresh => "QueryLeakage::Order::selector (\"The path's selector\")",
    queries_nondeterministic => "every query term is a function of the query (\"Tokens are column-wide and do not expire\")",
    tokens_per_row => "ReadLeak::hits in every row (\"find that node in any row\")",
    tokens_find_nothing => "ReadLeak::hits (a token finds its node, through its self tag x)",
    token_reaches_its_node_only => "ReadLeak::reach (\"the structure of its node's subtree in every row\")",
    probe_reaches_nothing => "ReadLeak::reach of a probe (\"the database also walks that element's subtree\")",
    ancestor_token_sent => "ReadLeak::token (\"nothing that covers $.profile\"): the pre-#1363 top-level token",
    tokens_not_chained => "TokenName::steps (\"derive the tokens of the nodes beneath\")",
    member_tokens_carry_ordinal => "TokenStep::Member (a member's token has no ordinal): the pre-#1363 member rule",
    element_tokens_without_index => "TokenStep::Element (an element's token carries its index)",
    probes_dropped => "ReadLeak::probe (\"a probe token for the element at index N of every array a wildcard expands\")",
    token_list_shuffled => "QueryLeakage::Subtree::reads (the tokens' order, which places each)",
    token_list_padded => "QueryLeakage::Subtree::reads (the tokens' number, which gives N away)",
    budget_not_sent => "QueryLeakage::Subtree::budget (the budget, in the clear)",
    needle_flat => "QueryLeakage::Contains::needle (\"its element grouping\")",
    needles_sent_in_walk_order => "Leakage::sent_order (\"A needle is sent in a random order too, drawn afresh for each query\"): the walk's order before",
    needle_alt_dropped => "QueryLeakage::Contains::alt",
    bound_rank_random => "QueryLeakage::Order::bound (\"the bound's place in the order of the stored values\")",
);
