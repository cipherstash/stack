//! The checks: the full profile is indistinguishable from the real scheme
//! (the positive control), the page as written is not (the finding), and
//! every clause's removal is noticed (the calibration).

use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
use serde_json::json;
use stack_encrypt::json::{JsonOptions, JsonPath};
use stack_encrypt::StackCipher;
use stack_kms::FakeDataKeySource;

use super::corpus::{handcrafted, random_world, World};
use super::distinguishers::{self, walk_positions};
use super::mutants;
use super::observe::ObservedWorld;
use super::profile::{flatten, leak, Clauses, Column, KeyOrder, Leakage};
use super::{real, simulator};
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

fn simulated_world(leakage: &Leakage, rng: &mut TestRng) -> ObservedWorld {
    let (rows, queries) = simulator::simulate(leakage, rng);
    ObservedWorld::from_wire(&rows, &queries)
}

/// Every distinguisher's feature of `world`, by name.
fn features(world: &ObservedWorld) -> Vec<(&'static str, String)> {
    distinguishers::all()
        .into_iter()
        .map(|d| (d.name, (d.run)(world)))
        .collect()
}

/// The distinguishers whose features differ between two worlds, each with
/// the two features.
fn separating(
    real: &[(&'static str, String)],
    simulated: &ObservedWorld,
) -> Vec<(&'static str, String, String)> {
    real.iter()
        .zip(features(simulated))
        .filter_map(|((name, a), (_, b))| (*a != b).then(|| (*name, a.clone(), b)))
        .collect()
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
            let simulated = simulated_world(&leakage, &mut rng());
            let separated = separating(&features(&real), &simulated);
            assert!(
                separated.is_empty(),
                "{}: the real scheme reveals more than L states:\n{}",
                world.name,
                report(&separated)
            );
        }
    }

    /// The positive control on random columns. Deterministic: the runner's
    /// own generator is seeded, and so is every simulation.
    #[test]
    fn no_distinguisher_separates_random_worlds() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let config = Config {
            cases: 48,
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
            let simulated = simulated_world(&leakage, &mut rng());
            let separated = separating(&features(&real), &simulated);
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

mod given_the_page_as_written {
    use super::*;

    /// The finding, held as a test: with only what the page states, a
    /// distinguisher separates the simulated world from the real one, and
    /// it is the ordering term's length. When the page states it, move the
    /// clause into the page's profile and this test changes with it.
    #[test]
    fn the_ordering_term_length_separates_it_from_the_real_scheme() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let mut fired = std::collections::BTreeSet::new();
        for world in handcrafted() {
            let real = real_world(&runtime, &cipher, &world);
            let leakage = leak(
                &world.column,
                Clauses::page_only(),
                &world.docs,
                &world.queries,
            );
            let simulated = simulated_world(&leakage, &mut rng());
            fired.extend(
                separating(&features(&real), &simulated)
                    .into_iter()
                    .map(|(n, _, _)| n),
            );
        }
        assert_eq!(
            fired.into_iter().collect::<Vec<_>>(),
            ["ordering_term_lengths"],
            "the page as written is separated from the real scheme by exactly the ordering term's length"
        );
    }
}

mod given_the_jsonb_reading_of_the_key_order {
    use super::*;

    /// The page's "sorted order of their key names" does not say which
    /// sort. Read as `jsonb`'s (shorter keys first), the profile is told
    /// from the real scheme on a row whose keys sort differently the two
    /// ways (`{"a": …, "a b": …, "é": …, "0": …}`): the sort is the keys'
    /// UTF-8 bytes, and a reader inferring key names from the order needs to
    /// know that.
    #[test]
    fn the_stored_order_tells_it_apart() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let clauses = Clauses {
            key_order: KeyOrder::JsonbLengthFirst,
            ..Clauses::default()
        };
        let world = &handcrafted()[0];
        let real = real_world(&runtime, &cipher, world);
        let leakage = leak(&world.column, clauses, &world.docs, &world.queries);
        let fired: Vec<&str> = separating(&features(&real), &simulated_world(&leakage, &mut rng()))
            .into_iter()
            .map(|(n, _, _)| n)
            .collect();
        assert!(
            fired.contains(&"selector_pattern_across_rows"),
            "the order of a row's selectors tells byte order from jsonb order: {fired:?}"
        );
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
                let simulated = simulated_world(&mutated, &mut rng);
                fired.extend(separating(real, &simulated).into_iter().map(|(n, _, _)| n));
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

    /// The harness's hash chain is the crate's: walking a sealed document's
    /// observed bytes from a subtree key's token finds exactly the entries
    /// `JsonDocument::subtree` does, at the same depths.
    #[test]
    fn chain_is_the_crates_chain() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let doc = json!({"a": {"b": [1, {"c": 2}], "d": "e"}, "f": [[3], {"g": null}]});
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
            for path in ["$.a", "$.f", "$.f[1]", "$.f[0]"] {
                let key = runtime
                    .block_on(async {
                        cipher
                            .default_keyset()
                            .json_subtree_key(
                                &JsonPath::parse(path).unwrap(),
                                &options,
                                stack_encrypt::nonempty!("users").with("profile"),
                            )
                            .await
                    })
                    .expect("derives");
                let crates: Vec<(usize, usize)> = sealed
                    .subtree(key.token_bytes())
                    .iter()
                    .map(|(j, _, d)| (*j, *d as usize))
                    .collect();
                assert_eq!(
                    walk_positions(&observed.rows[0], key.token_bytes()),
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

    /// The page's claim that the stored order reveals each row's shape holds
    /// on a column whose rows vary: the order-only attack of
    /// `distinguishers::depth_recovery` recovers every row's depth sequence
    /// exactly, from the stored rows alone.
    #[test]
    fn the_order_reveals_the_shape() {
        let runtime = runtime();
        let cipher = runtime.block_on(stack_cipher());
        let docs = vec![
            json!({"a": {"b": 1, "c": {"d": 2}}, "e": [1, {"f": 3}]}),
            json!({"a": {"c": {"d": 2}}, "e": []}),
            json!({"a": {"b": 1}, "e": [{"f": 3}]}),
            json!({"e": [{"f": 1}, {"g": 2}]}),
            json!({"e": [{"g": 1}]}),
            json!({"a": {"c": {}}}),
        ];
        let world = World {
            name: "varied shapes",
            column: Column {
                sealed_root: true,
                ordered: Vec::new(),
            },
            docs: docs.clone(),
            queries: Vec::new(),
        };
        let observed = real_world(&runtime, &cipher, &world);
        let truth: Vec<Vec<Option<usize>>> = docs
            .iter()
            .map(|doc| {
                flatten(doc, KeyOrder::Utf8Bytes)
                    .iter()
                    .map(|n| Some(n.positional.len()))
                    .collect()
            })
            .collect();
        assert_eq!(
            distinguishers::depth_recovery(&observed),
            truth,
            "the stored order alone gives every row's depth sequence"
        );
    }
}
