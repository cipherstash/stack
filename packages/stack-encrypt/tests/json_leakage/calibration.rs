//! The checks: the full profile is indistinguishable from the real scheme
//! (the positive control), the page as #1363 published it is not (the
//! finding), and every clause's removal is noticed (the calibration).

use std::collections::BTreeSet;

use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
use serde_json::json;
use stack_encrypt::json::{JsonOptions, JsonPath};
use stack_encrypt::StackCipher;
use stack_kms::FakeDataKeySource;

use super::corpus::{handcrafted, random_world, World};
use super::distinguishers::{self, walk_positions};
use super::mutants;
use super::observe::{ObservedQuery, ObservedWorld};
use super::profile::{
    leak, Clauses, Column, KeyOrder, KindOrder, Leakage, NumberOrder, OrderKind, Placement, Query,
    QueryLeakage, StringOrder,
};
use super::{canonical, real, simulator};
use crate::common::stack_cipher;

/// The seed of every simulator run and every mutant's choices. Any seed
/// works; a fixed one makes a failure reproduce.
const SEED: [u8; 32] = *b"json_tree leakage profile, v4 #1";

fn rng() -> TestRng {
    TestRng::from_seed(RngAlgorithm::ChaCha, &SEED)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime")
}

fn real_world(
    runtime: &tokio::runtime::Runtime,
    cipher: &StackCipher<FakeDataKeySource>,
    world: &World,
) -> ObservedWorld {
    let (rows, queries) = runtime.block_on(real::world(
        cipher,
        &world.column,
        &world.docs,
        &world.queries,
    ));
    ObservedWorld::from_wire(&rows, &queries)
}

/// The placements of the strings' terms among the numbers' a simulation
/// tries: every one a key could pick where the profile leaves it to the key
/// and the column orders both kinds, since the real column's key picked one
/// and the simulator cannot know which; otherwise only the profile's own.
fn placements(leakage: &Leakage) -> Vec<Option<Placement>> {
    let kinds: BTreeSet<OrderKind> = leakage
        .rows
        .iter()
        .flat_map(|r| r.entries.iter().filter_map(|e| e.ordering.map(|o| o.kind)))
        .chain(leakage.queries.iter().filter_map(|q| match q {
            QueryLeakage::Order { bound, .. } => Some(bound.kind),
            _ => None,
        }))
        .collect();
    if leakage.kind_order == KindOrder::ByKey && kinds.len() == 2 {
        Placement::ALL.into_iter().map(Some).collect()
    } else {
        vec![None]
    }
}

/// Every distinguisher's feature of `world`, by name, read in its
/// canonical order ([`canonical`]): the stored order is random in the real
/// scheme and in the simulation, independently.
fn features(world: &ObservedWorld) -> Vec<(&'static str, String)> {
    let world = canonical::canonical(world);
    distinguishers::all()
        .into_iter()
        .map(|d| (d.name, (d.run)(&world)))
        .collect()
}

/// The distinguishers whose features differ between the real world and
/// the simulation of `leakage`, each with the two features: of the
/// simulations at every placement [`placements`] tries, the one fewest
/// distinguishers separate. So the worlds count as told apart only when no
/// placement a key could pick makes them agree.
fn separating(
    real: &[(&'static str, String)],
    leakage: &Leakage,
    rng: &mut TestRng,
) -> Vec<(&'static str, String, String)> {
    placements(leakage)
        .into_iter()
        .map(|placement| {
            let (rows, queries) = simulator::simulate(leakage, rng, placement);
            let simulated = ObservedWorld::from_wire(&rows, &queries);
            real.iter()
                .zip(features(&simulated))
                .filter_map(|((name, a), (_, b))| (*a != b).then(|| (*name, a.clone(), b)))
                .collect::<Vec<_>>()
        })
        .min_by_key(Vec::len)
        .expect("at least one placement")
}

fn report(separated: &[(&'static str, String, String)]) -> String {
    separated
        .iter()
        .map(|(name, real, sim)| format!("{name}:\n  real: {real}\n  sim:  {sim}"))
        .collect::<Vec<_>>()
        .join("\n")
}

mod given_the_full_profile {
    use super::*;

    /// The positive control on the handcrafted worlds: the simulator, given
    /// `L` and randomness, produces a world no distinguisher tells from the
    /// real one.
    #[test]
    fn no_distinguisher_separates_the_handcrafted_worlds() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        for world in handcrafted() {
            let real = real_world(&runtime, &cipher, &world);
            let leakage = leak(
                &world.column,
                Clauses::default(),
                &world.docs,
                &world.queries,
            );
            let separated = separating(&features(&real), &leakage, &mut rng());
            assert!(
                separated.is_empty(),
                "{}: the real scheme reveals more than L states:\n{}",
                world.name,
                report(&separated)
            );
        }
    }

    /// The positive control on 256 random columns, about three seconds.
    /// Deterministic: the runner's own generator is seeded, and so is every
    /// simulation.
    #[test]
    fn no_distinguisher_separates_random_worlds() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let config = Config {
            cases: 256,
            failure_persistence: None,
            rng_algorithm: RngAlgorithm::ChaCha,
            ..Config::default()
        };
        let mut runner = TestRunner::new_with_rng(config, rng());
        let result = runner.run(&random_world(), |world| {
            let real = real_world(&runtime, &cipher, &world);
            let leakage = leak(
                &world.column,
                Clauses::default(),
                &world.docs,
                &world.queries,
            );
            let separated = separating(&features(&real), &leakage, &mut rng());
            if separated.is_empty() {
                Ok(())
            } else {
                Err(TestCaseError::fail(format!(
                    "the real scheme reveals more than L states on {world:?}:\n{}",
                    report(&separated)
                )))
            }
        });
        assert!(result.is_ok(), "{result:?}");
    }
}

mod given_the_page_as_published_in_1363 {
    use super::*;

    /// The finding, held as a test: with only what the page stated at
    /// #1363's head, which says nothing of the rule a node's token takes
    /// under its parent's, a distinguisher separates the simulated world
    /// from the real one, and `hit_rules` is the one that names it. This
    /// branch adds the sentence to the page ("whether each node beneath is
    /// an object member or an array element, and each element's index");
    /// the test keeps it load-bearing.
    ///
    /// The rest of the set is what follows from it. A world that states no
    /// rule gives every member's token by the element rule, with its keyed
    /// rank as the index. But a read through a key step sends a token
    /// derived by the member rule, since that is the only token a client
    /// can derive from a path; so where such a read names a node below a
    /// member that another read's walk reaches (`$.nested.list[*].y[*]`
    /// below `$.nested.list`'s walk), the walk derives the member by the
    /// element rule and then fails to recognise the named node beneath it:
    /// what the walk links (`token_reach`), what the read returns
    /// (`subtree_results`) and which tokens derive which
    /// (`token_derivability`) all change. No world consistent with the
    /// tokens a client sends hides the rule: the page has to state it.
    #[test]
    fn the_hit_rule_separates_it_from_the_real_scheme() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let mut fired = std::collections::BTreeSet::new();
        for world in handcrafted() {
            let real = real_world(&runtime, &cipher, &world);
            let leakage = leak(
                &world.column,
                Clauses::as_published_in_1363(),
                &world.docs,
                &world.queries,
            );
            fired.extend(
                separating(&features(&real), &leakage, &mut rng())
                    .into_iter()
                    .map(|(n, _, _)| n),
            );
        }
        assert_eq!(
            fired.into_iter().collect::<Vec<_>>(),
            PAGE_AS_PUBLISHED_FIRES,
            "the page as #1363 published it is separated from the real scheme by the hit rule"
        );
    }

    /// What separates the page as #1363 published it from the real scheme.
    const PAGE_AS_PUBLISHED_FIRES: &[&str] = &[
        "hit_rules",
        "subtree_results",
        "token_derivability",
        "token_reach",
    ];
}

mod given_strings_ordered_by_their_bytes {
    use super::*;

    /// The page says strings are "ordered and compared after their case and
    /// accents are folded", and that the term's length counts the folded
    /// form. Read as the strings' own bytes (which the profile first
    /// assumed, on a corpus of lower-case ASCII where the two agree), the
    /// profile is told from the real scheme on the column whose names fold:
    /// `"Carol"` and `"carol"` share a term, and `"ál"`'s term is as long
    /// as `"al"`'s.
    #[test]
    fn the_ordering_terms_tell_it_apart() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let clauses = Clauses {
            string_order: StringOrder::Bytes,
            ..Clauses::default()
        };
        let world = handcrafted()
            .into_iter()
            .find(|w| w.name == "ordered strings")
            .expect("the corpus has it");
        let real = real_world(&runtime, &cipher, &world);
        let leakage = leak(&world.column, clauses, &world.docs, &world.queries);
        let fired: Vec<&str> = separating(&features(&real), &leakage, &mut rng())
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        for expected in ["ordering_term_lengths", "ordering_term_order"] {
            assert!(
                fired.contains(&expected),
                "folding shows in {expected}: {fired:?}"
            );
        }
    }
}

mod given_integers_ordered_exactly {
    use super::*;

    /// The page says a number's equality under its term "is as a 64-bit
    /// float": 9007199254740992 and 9007199254740993 round to one float and
    /// share a term. Read as every distinct number its own term, the profile
    /// is told from the real scheme on the column that holds both.
    #[test]
    fn the_ordering_terms_tell_it_apart() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let clauses = Clauses {
            number_order: NumberOrder::Exact,
            ..Clauses::default()
        };
        let world = handcrafted()
            .into_iter()
            .find(|w| w.name == "numbers and strings at one ordered path")
            .expect("the corpus has it");
        let real = real_world(&runtime, &cipher, &world);
        let leakage = leak(&world.column, clauses, &world.docs, &world.queries);
        let fired: Vec<&str> = separating(&features(&real), &leakage, &mut rng())
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        assert!(
            fired.contains(&"ordering_term_order"),
            "two integers that round to one float share a term: {fired:?}"
        );
    }
}

mod given_the_jsonb_reading_of_the_key_order {
    use super::*;

    /// The page once had to say which sort "the order of their key names"
    /// meant, because the stored order showed it, and then a needle did. Now
    /// neither does: the entries are stored in a random order, a needle is
    /// sent in one, and a member's ordinal is a random permutation's. So the
    /// two
    /// readings, the keys' UTF-8 bytes and `jsonb`'s (shorter keys first),
    /// give different profiles on a column whose keys sort differently the
    /// two ways (a row and a needle `{"a": …, "a b": …, "é": …, "0": …}`),
    /// and no distinguisher tells either from the real scheme: the key order
    /// is nothing the database learns, and the page need not say which.
    #[test]
    fn nothing_tells_it_apart() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let jsonb = Clauses {
            key_order: KeyOrder::JsonbLengthFirst,
            ..Clauses::default()
        };
        for world in &handcrafted()[..2] {
            let real = real_world(&runtime, &cipher, world);
            let bytes = leak(
                &world.column,
                Clauses::default(),
                &world.docs,
                &world.queries,
            );
            let leakage = leak(&world.column, jsonb, &world.docs, &world.queries);
            assert_ne!(
                leakage, bytes,
                "{}: the two readings differ in the profile",
                world.name
            );
            let separated = separating(&features(&real), &leakage, &mut rng());
            assert!(
                separated.is_empty(),
                "{}: the key order shows after all:\n{}",
                world.name,
                report(&separated)
            );
        }
    }
}

mod given_a_mutant_profile {
    use super::*;

    /// Mutants no distinguisher is expected to notice, with the reason. A
    /// mutant listed here that is noticed fails the test too, so the list
    /// stays true.
    const UNNOTICED: &[(&str, &str)] = &[];

    /// The calibration: for each clause, the profile without it is told
    /// from the real scheme by at least one distinguisher on some
    /// handcrafted world. Prints the table of which.
    #[test]
    fn every_clause_is_load_bearing() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let worlds: Vec<(Vec<(&'static str, String)>, Leakage)> = handcrafted()
            .iter()
            .map(|world| {
                (
                    features(&real_world(&runtime, &cipher, world)),
                    leak(
                        &world.column,
                        Clauses::default(),
                        &world.docs,
                        &world.queries,
                    ),
                )
            })
            .collect();
        let mut table = Vec::new();
        let mut failures = Vec::new();
        for mutant in mutants::all() {
            let mut fired = std::collections::BTreeSet::new();
            let mut rng = rng();
            for (real, leakage) in &worlds {
                let mut mutated = leakage.clone();
                (mutant.apply)(&mut mutated, &mut rng);
                fired.extend(
                    separating(real, &mutated, &mut rng)
                        .into_iter()
                        .map(|(n, _, _)| n),
                );
            }
            let expected_unnoticed = UNNOTICED.iter().any(|(name, _)| *name == mutant.name);
            if fired.is_empty() != expected_unnoticed {
                failures.push(mutant.name);
            }
            table.push(format!(
                "| `{}` | {} | {} |",
                mutant.name,
                mutant.clause,
                if fired.is_empty() {
                    "**none**".to_owned()
                } else {
                    fired
                        .iter()
                        .map(|n| format!("`{n}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ));
        }
        eprintln!(
            "| mutant | clause dropped | caught by |\n|---|---|---|\n{}",
            table.join("\n")
        );
        assert!(
            failures.is_empty(),
            "mutants whose detection disagrees with UNNOTICED: {failures:?}"
        );
    }
}

mod the_harness {
    use super::*;

    /// The harness's hash chain is the crate's: reading a sealed
    /// document's observed bytes with a subtree key's tokens finds exactly
    /// the entries `JsonDocument::subtree` does, at the same depths, for
    /// paths through members, positions and wildcards, and `$`.
    #[test]
    fn chain_is_the_crates_chain() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let doc = json!({"a": {"b": [1, {"c": 2}], "d": "e"}, "f": [[3], {"g": null}, [4, 5]]});
        for sealed_root in [true, false] {
            let options = JsonOptions {
                sealed_root,
                ..JsonOptions::new()
            };
            let column = Column {
                sealed_root,
                ordered: Vec::new(),
            };
            let (rows, _) = runtime.block_on(real::world(
                &cipher,
                &column,
                std::slice::from_ref(&doc),
                &[],
            ));
            let sealed: stack_encrypt::json::JsonDocument =
                serde_json::from_value(rows[0].clone()).expect("a document");
            let observed = ObservedWorld::from_wire(&rows, &[]);
            for (path, bound) in [
                ("$", 64),
                ("$.a", 64),
                ("$.a.b", 64),
                ("$.a.b[1].c", 64),
                ("$.f", 64),
                ("$.f[1]", 64),
                ("$.f[0]", 64),
                ("$.f[*]", 64),
                ("$.f[*].g", 64),
                ("$.f[*][*]", 1),
            ] {
                let key = runtime
                    .block_on(async {
                        cipher
                            .default_keyset()
                            .json_subtree_key_with_bound(
                                &JsonPath::parse(path).unwrap(),
                                &options,
                                bound,
                                stack_encrypt::nonempty!("users").with("profile"),
                            )
                            .await
                    })
                    .expect("derives");
                let tokens = key.token_bytes();
                let crates: Vec<(usize, usize)> = sealed
                    .subtree(&tokens)
                    .iter()
                    .map(|(j, _, d)| (*j, *d as usize))
                    .collect();
                assert_eq!(
                    walk_positions(&observed.rows[0], &tokens),
                    crates,
                    "{path} with the root sealed: {sealed_root}"
                );
                assert!(
                    !crates.is_empty(),
                    "{path} reaches something, so the comparison is not vacuous"
                );
            }
        }
    }

    /// What a wildcard read's token list gives away, on the real scheme:
    /// its count is the bound (65 tokens, so `N = 64`, at one level; 4,161,
    /// so `N = 64`, at two), the probe is the last token at its level and
    /// finds the element where the path's other tokens find the leaf below
    /// it, and which tokens find a node says which elements hold the rest of
    /// the path. `json_tree_subtree`'s comment once said "the server
    /// cannot tell a probe from any other token", which is true of a token's
    /// bytes and of nothing else; #1363 corrected it.
    #[test]
    fn a_read_gives_away_its_bound_and_its_probes() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let items = |n: usize| {
            json!({"items": (0..n)
                .map(|i| if i == 1 { json!({"sku": i}) } else { json!({"price": i, "tags": [i]}) })
                .collect::<Vec<_>>()})
        };
        let world = World {
            name: "items",
            column: Column {
                sealed_root: true,
                ordered: Vec::new(),
            },
            docs: vec![items(0), items(3), items(70)],
            queries: vec![
                Query::subtree("$.items[*].price"),
                Query::subtree("$.items[*].tags[*]"),
            ],
        };
        let observed = real_world(&runtime, &cipher, &world);
        assert_eq!(
            distinguishers::token_counts(&observed),
            [65, 4161],
            "one wildcard level sends N + 1 tokens, two send N² + N + 1"
        );
        // 4,161 is also one level at a bound of 4,160; which tokens find a
        // node (the 65th finds `$.items[0].tags[64]`'s absence, not an
        // item) is what tells the reading apart.
        assert_eq!(
            distinguishers::bound_recovery(&observed),
            [vec![(1, 64)], vec![(1, 4160), (2, 64)]],
            "the count alone gives the bound"
        );
        let price = &distinguishers::wildcard_positions(&observed)[0];
        let price = price.as_ref().expect("a wildcard read");
        // No items; three, the second without a price; seventy, the
        // second without a price, longer than the bound.
        assert_eq!(price[0], (vec![], false, None), "no items, no hits");
        assert_eq!(
            price[1],
            (vec![0, 2], false, None),
            "three items, the second without a price"
        );
        let mut most: Vec<usize> = (0..64).collect();
        most.retain(|&i| i != 1);
        assert_eq!(
            price[2],
            (most, true, Some(true)),
            "seventy items: the probe finds the element, under another selector"
        );
    }

    /// `distinguishers::cross_kind_equalities` can fire: it is empty on the
    /// real scheme, and a world in which one read's token is a stored
    /// selector, which every feature naming each kind on its own would miss,
    /// is told apart by it. No mutant can state that world, since the
    /// profile names each kind in a space of its own; this is the clause's
    /// check.
    #[test]
    fn cross_kind_equalities_see_a_token_that_is_a_selector() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let world = &handcrafted()[0];
        let mut observed = real_world(&runtime, &cipher, world);
        assert!(
            distinguishers::cross_kind_equalities(&observed).is_empty(),
            "no value is shared across kinds in the real scheme: {:?}",
            distinguishers::cross_kind_equalities(&observed)
        );
        let selector = observed.rows[0].entries[1].s;
        let read = observed
            .queries
            .iter_mut()
            .find_map(|q| match q {
                ObservedQuery::Subtree { tokens, .. } => Some(tokens),
                _ => None,
            })
            .expect("the corpus sends a subtree read");
        read[0] = selector;
        assert_eq!(
            distinguishers::cross_kind_equalities(&observed),
            [("s", "token")].into_iter().collect(),
            "a token equal to a stored selector is seen"
        );
    }

    /// A token for a position past every row's array finds nothing, and the
    /// database still links it to the array's token by the element rule:
    /// `token_derivability` tries indices up to the longest token list
    /// sent or 64, not only the first few.
    #[test]
    fn a_position_past_every_array_is_linked_to_its_array() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let world = handcrafted()
            .into_iter()
            .find(|w| w.name == "ordered strings")
            .expect("the corpus has it");
        let at = |path: &str| {
            world
                .queries
                .iter()
                .position(|q| matches!(q, Query::Subtree { path: p, .. } if p == path))
                .expect("the column reads it")
        };
        let observed = real_world(&runtime, &cipher, &world);
        let links = distinguishers::token_derivability(&observed);
        assert!(
            links.contains(&(at("$.tags"), at("$.tags[10]"))),
            "`$.tags[10]`'s token derives from `$.tags`'s: {links:?}"
        );
    }

    /// The stored order says nothing beyond the root's place: sealing one
    /// document four times stores its root at slot `0` every time and its
    /// other entries, and the pairs of `q`, in a fresh order each time. The
    /// document has twenty nodes, each at a path of its own and none inside
    /// an array, so its selectors tell each seal's order and `q` is one
    /// group of twenty pairs. The real scheme draws each order from the
    /// operating system: two seals put the nineteen other entries in one
    /// order with probability `1 / 19!`, about `10^-17`, and `q`'s pairs
    /// with `1 / 20!`, so across the six pairs of seals this fails by chance
    /// below `10^-15`.
    #[test]
    fn the_order_is_drawn_afresh_with_the_root_first() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let object = |prefix: &str, n: usize| {
            serde_json::Value::Object((0..n).map(|i| (format!("{prefix}{i}"), json!(i))).collect())
        };
        let doc = json!({"a": object("a", 6), "b": object("b", 6), "c": object("c", 4)});
        let world = World {
            name: "one document, sealed four times",
            column: Column {
                sealed_root: true,
                ordered: Vec::new(),
            },
            docs: vec![doc; 4],
            queries: vec![Query::Extract("$".into())],
        };
        let observed = real_world(&runtime, &cipher, &world);
        let ObservedQuery::Extract { s: root } = observed.queries[0] else {
            unreachable!("an extraction");
        };
        let orders: Vec<Vec<[u8; 16]>> = observed
            .rows
            .iter()
            .map(|row| row.entries.iter().map(|e| e.s).collect())
            .collect();
        let projections: Vec<Vec<[u8; 16]>> = observed
            .rows
            .iter()
            .map(|row| {
                assert!(row.q.elements.is_empty(), "no array, one group");
                row.q.pairs.iter().map(|(s, _)| *s).collect()
            })
            .collect();
        let mut first = orders[0].clone();
        first.sort_unstable();
        for (order, pairs) in orders.iter().zip(&projections) {
            assert_eq!(order.len(), 20, "one entry per node");
            assert_eq!(order[0], root, "the root at slot 0");
            let mut sorted = order.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, first, "one document: one multiset of selectors");
            let mut paired = pairs.clone();
            paired.sort_unstable();
            assert_eq!(paired, first, "`q` holds one pair per node");
        }
        for i in 0..orders.len() {
            for j in i + 1..orders.len() {
                assert_ne!(
                    orders[i][1..],
                    orders[j][1..],
                    "seals {i} and {j} store the other entries in one order"
                );
                assert_ne!(
                    projections[i], projections[j],
                    "seals {i} and {j} store `q`'s pairs in one order"
                );
            }
        }
    }
}
