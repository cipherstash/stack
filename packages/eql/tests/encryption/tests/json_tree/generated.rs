//! The containment oracle over generated documents. proptest draws a case: a
//! batch of stored documents and a batch of needles (random values, values
//! derived from a stored document, and those with one edit). The documents
//! are stored encrypted beside their plaintexts, and every needle is asked
//! of both columns in a few set-based statements, so PostgreSQL's own
//! `jsonb` operators are the oracle and a case costs a handful of round
//! trips, not one per needle.
//!
//! **Replaying.** The RNG is ChaCha with a fixed seed ([`DEFAULT_SEED`]),
//! logged on every run. `PROPTEST_RNG_SEED` replaces the seed and
//! `PROPTEST_CASES` the case count ([`DEFAULT_CASES`]), as for any proptest
//! run. A failure shrinks to a small case and prints it, and proptest
//! appends its seed to `proptest-regressions/json_tree.txt` in this crate,
//! which every later run replays first. Commit that line with the fix.

use std::cell::{Cell, RefCell};
use std::fmt;

use proptest::collection::vec as vec_of;
use proptest::prelude::*;
use proptest::sample::{select, Index};
use proptest::strategy::ValueTree;
use proptest::test_runner::{
    Config, FileFailurePersistence, RngAlgorithm, RngSeed, TestCaseError, TestRunner,
};

use super::*;

/// The seed the run uses when `PROPTEST_RNG_SEED` is unset. Fixed, so every
/// CI run checks the same cases.
const DEFAULT_SEED: u64 = 1336;

/// The cases a run checks when `PROPTEST_CASES` is unset.
const DEFAULT_CASES: u32 = 64;

/// The largest batches a case holds.
const MAX_DOCUMENTS: usize = 64;
const MAX_NEEDLES: usize = 96;

/// Where proptest records a failing case's seed. `Direct` with the crate's
/// own path: the default (`SourceParallel`) resolves the test's source file
/// from the current directory, which for this nested workspace member is not
/// where `file!()` is relative to.
const REGRESSIONS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/proptest-regressions/json_tree.txt"
);

/// Numbers, several of them one value to `jsonb` in different
/// representations: `1`, `1.0` and `1e0`; `100` and `1e2` (an integer and a
/// float); `0`, `0.0` and `-0.0`; `0.5` and `5e-1`. A value is stored as
/// `serde_json` parsed it and PostgreSQL is sent `serde_json`'s spelling of
/// the same value, so each side sees one plaintext.
const NUMBERS: &[&str] = &[
    "0",
    "0.0",
    "-0.0",
    "1",
    "1.0",
    "1e0",
    "2",
    "2.00",
    "-1",
    "-1.0",
    "10",
    "1e1",
    "100",
    "1e2",
    "0.5",
    "5e-1",
    "1.5",
    "123456789012",
    "1e20",
];

/// Strings, some spelled like a number, a boolean or null, so that a kind
/// confused with another shows as a wrong answer.
const STRINGS: &[&str] = &["x", "y", "", "1", "1.0", "2", "true", "null", "a b", "ü"];

/// Object keys: few, so they repeat across levels and siblings. The `->`
/// paths are built from the first four.
const KEYS: &[&str] = &["a", "b", "c", "x", "1", ""];
const PATH_KEYS: &[&str] = &["a", "b", "c", "x"];

/// The run's configuration: proptest's defaults, which read
/// `PROPTEST_CASES` and `PROPTEST_RNG_SEED`, with this test's own default
/// for each one left unset.
fn config() -> Config {
    let mut config = Config::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = DEFAULT_CASES;
    }
    if config.rng_seed == RngSeed::Random {
        config.rng_seed = RngSeed::Fixed(DEFAULT_SEED);
    }
    config.rng_algorithm = RngAlgorithm::ChaCha;
    config.failure_persistence = Some(Box::new(FileFailurePersistence::Direct(REGRESSIONS)));
    // A shrink step is a round trip to the database: bound the search.
    config.max_shrink_time = 120_000;
    config
}

/// How to replay the run, for the log and every failure.
fn replay(config: &Config) -> String {
    format!(
        "seed {seed}, {cases} cases; replay with PROPTEST_RNG_SEED={seed} PROPTEST_CASES={cases}",
        seed = config.rng_seed,
        cases = config.cases
    )
}

// =============================================================================
// The generated values
// =============================================================================

/// One edit that turns a contained needle into a near miss. `at` picks the
/// node, in document order; an edit that does not fit the node's kind
/// changes its kind instead.
#[derive(Clone, Debug)]
enum Edit {
    Leaf {
        at: Index,
        to: Value,
    },
    Key {
        at: Index,
        key: String,
        value: Value,
    },
    Element {
        at: Index,
        value: Value,
    },
    Kind {
        at: Index,
    },
}

/// A needle as proptest draws it: derived ones name their stored document
/// by an [`Index`] into the case's documents, so they follow the documents
/// as those shrink. `keep` says, one member or element at a time in
/// document order, what a pruning keeps; once it runs out, nothing more is
/// kept, so shrinking it makes the needle smaller.
#[derive(Clone, Debug)]
enum NeedleSpec {
    Random(Value),
    Pruned {
        from: Index,
        keep: Vec<bool>,
        at: Option<Index>,
    },
    NearMiss {
        from: Index,
        keep: Vec<bool>,
        edit: Edit,
    },
}

/// Where a needle came from, for a failure message.
#[derive(Clone, Copy)]
enum Origin {
    Random,
    /// A pruning of the row's whole document: the row contains it.
    PrunedRoot(usize),
    /// A pruning of a node inside the row's document.
    PrunedNode(usize),
    NearMiss(usize),
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Random => write!(f, "random"),
            Origin::PrunedRoot(row) => write!(f, "pruned from row {row}"),
            Origin::PrunedNode(row) => write!(f, "pruned from a node of row {row}"),
            Origin::NearMiss(row) => write!(f, "near miss of row {row}"),
        }
    }
}

struct Needle {
    origin: Origin,
    value: Value,
}

/// One generated case: the documents stored, and the needles asked.
#[derive(Clone)]
struct Case {
    docs: Vec<Value>,
    needles: Vec<NeedleSpec>,
}

impl Case {
    /// The needles as values, each derived from the case's documents.
    fn needles(&self) -> Vec<Needle> {
        self.needles
            .iter()
            .map(|spec| match spec {
                NeedleSpec::Random(value) => Needle {
                    origin: Origin::Random,
                    value: value.clone(),
                },
                NeedleSpec::Pruned { from, keep, at } => {
                    let row = from.index(self.docs.len());
                    let doc = &self.docs[row];
                    let pointer = at.as_ref().map_or_else(String::new, |at| {
                        let pointers = pointers(doc);
                        at.get(&pointers).clone()
                    });
                    let node = doc.pointer(&pointer).unwrap();
                    Needle {
                        origin: if pointer.is_empty() {
                            Origin::PrunedRoot(row)
                        } else {
                            Origin::PrunedNode(row)
                        },
                        value: prune(node, &mut keep.iter()),
                    }
                }
                NeedleSpec::NearMiss { from, keep, edit } => {
                    let row = from.index(self.docs.len());
                    let mut value = prune(&self.docs[row], &mut keep.iter());
                    apply(edit, &mut value);
                    Needle {
                        origin: Origin::NearMiss(row),
                        value,
                    }
                }
            })
            .collect()
    }
}

/// Printed as JSON, one document and one needle per line: what proptest
/// shows for the minimal failing case.
impl fmt::Debug for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} stored documents:", self.docs.len())?;
        for (row, doc) in self.docs.iter().enumerate() {
            writeln!(f, "  row {row}: {doc}")?;
        }
        writeln!(f, "{} needles:", self.needles.len())?;
        for (i, needle) in self.needles().iter().enumerate() {
            writeln!(f, "  needle {i} ({}): {}", needle.origin, needle.value)?;
        }
        Ok(())
    }
}

/// A sub-document `v` contains: an object keeps the members, and an array
/// the elements, that `keep` says to keep, each pruned in turn; a scalar is
/// itself.
fn prune(v: &Value, keep: &mut std::slice::Iter<'_, bool>) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, member) in map {
                if keep.next().copied().unwrap_or(false) {
                    let _ = out.insert(key.clone(), prune(member, keep));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                if keep.next().copied().unwrap_or(false) {
                    out.push(prune(item, keep));
                }
            }
            Value::Array(out)
        }
        scalar => scalar.clone(),
    }
}

/// Every node's JSON pointer, in document order, the root (`""`) first.
fn pointers(v: &Value) -> Vec<String> {
    fn walk(v: &Value, at: String, out: &mut Vec<String>) {
        out.push(at.clone());
        match v {
            Value::Object(map) => {
                for (key, member) in map {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    walk(member, format!("{at}/{key}"), out);
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, format!("{at}/{i}"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, String::new(), &mut out);
    out
}

fn apply(edit: &Edit, needle: &mut Value) {
    let at = match edit {
        Edit::Leaf { at, .. }
        | Edit::Key { at, .. }
        | Edit::Element { at, .. }
        | Edit::Kind { at } => at,
    };
    let pointer = at.get(&pointers(needle)).clone();
    let node = needle.pointer_mut(&pointer).unwrap();
    match edit {
        Edit::Leaf { to, .. } if !node.is_object() && !node.is_array() && node != to => {
            *node = to.clone();
        }
        Edit::Key { key, value, .. } if node.is_object() => {
            let _ = node
                .as_object_mut()
                .unwrap()
                .insert(key.clone(), value.clone());
        }
        Edit::Element { value, .. } if node.is_array() => {
            node.as_array_mut().unwrap().push(value.clone());
        }
        _ => {
            *node = match node.take() {
                Value::Object(map) => Value::Array(map.into_iter().map(|(_, v)| v).collect()),
                Value::Array(items) => {
                    json!({ "a": items.into_iter().next().unwrap_or(Value::Null) })
                }
                scalar => Value::Array(vec![scalar]),
            };
        }
    }
}

mod strategies {
    use super::*;

    pub(super) fn scalar() -> BoxedStrategy<Value> {
        prop_oneof![
            4 => select(NUMBERS).prop_map(|text| serde_json::from_str::<Value>(text).unwrap()),
            3 => select(STRINGS).prop_map(|text| Value::String(text.to_owned())),
            2 => any::<bool>().prop_map(Value::Bool),
            1 => Just(Value::Null),
        ]
        .boxed()
    }

    fn key() -> BoxedStrategy<String> {
        select(KEYS).prop_map(str::to_owned).boxed()
    }

    /// An object of up to four members. A key drawn twice keeps its later
    /// value, as `jsonb` does.
    fn object_of(inner: BoxedStrategy<Value>) -> BoxedStrategy<Value> {
        vec_of((key(), inner), 0..5)
            .prop_map(|members| Value::Object(members.into_iter().collect()))
            .boxed()
    }

    /// An array: of anything, of objects, of arrays, or with some elements
    /// repeated.
    fn array_of(inner: BoxedStrategy<Value>) -> BoxedStrategy<Value> {
        prop_oneof![
            3 => vec_of(inner.clone(), 0..5).prop_map(Value::Array),
            1 => vec_of(object_of(inner.clone()), 1..4).prop_map(Value::Array),
            1 => vec_of(vec_of(inner.clone(), 0..3).prop_map(Value::Array), 1..4)
                .prop_map(Value::Array),
            1 => (vec_of(inner, 1..4), vec_of(any::<Index>(), 1..3)).prop_map(
                |(mut items, repeats)| {
                    for repeat in repeats {
                        let copy = repeat.get(&items).clone();
                        items.push(copy);
                    }
                    Value::Array(items)
                }
            ),
        ]
        .boxed()
    }

    /// A value with up to `depth` levels of recursion below it.
    pub(super) fn value(depth: u32) -> BoxedStrategy<Value> {
        scalar()
            .prop_recursive(depth, 48, 4, |inner| {
                prop_oneof![object_of(inner.clone()), array_of(inner)]
            })
            .boxed()
    }

    /// A stored document: mostly an object, sometimes a root array, and
    /// sometimes a root scalar.
    pub(super) fn document() -> BoxedStrategy<Value> {
        prop_oneof![
            6 => object_of(value(3)),
            3 => array_of(value(2)),
            1 => scalar(),
        ]
        .boxed()
    }

    fn keep() -> BoxedStrategy<Vec<bool>> {
        vec_of(proptest::bool::weighted(0.7), 0..32).boxed()
    }

    fn edit() -> BoxedStrategy<Edit> {
        prop_oneof![
            (any::<Index>(), scalar()).prop_map(|(at, to)| Edit::Leaf { at, to }),
            (any::<Index>(), key(), value(1)).prop_map(|(at, key, value)| Edit::Key {
                at,
                key,
                value
            }),
            (any::<Index>(), value(1)).prop_map(|(at, value)| Edit::Element { at, value }),
            any::<Index>().prop_map(|at| Edit::Kind { at }),
        ]
        .boxed()
    }

    fn needle() -> BoxedStrategy<NeedleSpec> {
        prop_oneof![
            1 => value(2).prop_map(NeedleSpec::Random),
            2 => (any::<Index>(), keep(), proptest::option::weighted(0.3, any::<Index>()))
                .prop_map(|(from, keep, at)| NeedleSpec::Pruned { from, keep, at }),
            2 => (any::<Index>(), keep(), edit())
                .prop_map(|(from, keep, edit)| NeedleSpec::NearMiss { from, keep, edit }),
        ]
        .boxed()
    }

    pub(super) fn case() -> BoxedStrategy<Case> {
        (
            vec_of(document(), 1..=MAX_DOCUMENTS),
            vec_of(needle(), 1..=MAX_NEEDLES),
        )
            .prop_map(|(docs, needles)| Case { docs, needles })
            .boxed()
    }
}

// =============================================================================
// The database
// =============================================================================

/// The two execution paths every containment answer is asked on.
#[derive(Clone, Copy, Debug)]
enum Scan {
    /// Sequential scans off: the planner takes the GIN index where it can.
    Index,
    /// Every index path off.
    Sequential,
}

impl Scan {
    const ALL: [Scan; 2] = [Scan::Index, Scan::Sequential];

    fn settings(self) -> &'static str {
        match self {
            Scan::Index => "SET enable_seqscan = off",
            Scan::Sequential => {
                "SET enable_seqscan = on; SET enable_bitmapscan = off; SET enable_indexscan = off; SET enable_indexonlyscan = off"
            }
        }
    }
}

/// The containment operators, with the SQL operator each spells.
#[derive(Clone, Copy, Debug)]
enum Containment {
    Contains,
    ContainedBy,
}

impl Containment {
    fn sql(self) -> &'static str {
        match self {
            Containment::Contains => "@>",
            Containment::ContainedBy => "<@",
        }
    }
}

/// One database session, cipher and runtime, built once for a whole run:
/// proptest's runner is synchronous, so the async work is driven on this
/// runtime.
struct Scenario {
    runtime: tokio::runtime::Runtime,
    cipher: Cipher,
    plan: ValuePlan<Value, Laid<Json, JsonDocument>>,
    db: RefCell<postgres::Client>,
}

fn scenario() -> Scenario {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let mut db = connect();
    // No primary key: the GIN index is the table's only index, so with
    // sequential scans off the planner has no other index to walk whole
    // and filter.
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_generated (id int NOT NULL, plain jsonb NOT NULL, doc public.eql_v4_json_tree NOT NULL);
         CREATE INDEX json_tree_generated_doc ON json_tree_generated USING gin ((eql_v4.json_tree_query(doc)) jsonb_path_ops);",
    )
    .unwrap();
    Scenario {
        runtime,
        cipher,
        plan: plan(),
        db: RefCell::new(db),
    }
}

impl Scenario {
    /// Replace the table's rows with the documents, each sealed beside its
    /// plaintext, in one statement. Row `i` is document `i`.
    fn store(&self, docs: &[Value]) {
        let ids: Vec<i32> = (0..docs.len() as i32).collect();
        let plains: Vec<String> = docs.iter().map(Value::to_string).collect();
        let sealed: Vec<String> = docs
            .iter()
            .map(|doc| {
                serde_json::to_string(&wait(&self.runtime, seal(&self.cipher, doc))).unwrap()
            })
            .collect();
        let mut db = self.db.borrow_mut();
        db.batch_execute("TRUNCATE json_tree_generated").unwrap();
        let _ = db
            .execute(
                "INSERT INTO json_tree_generated
                 SELECT id, plain::jsonb, doc::jsonb::public.eql_v4_json_tree
                 FROM unnest($1::int[], $2::text[], $3::text[]) AS u(id, plain, doc)",
                &[&ids, &plains, &sealed],
            )
            .unwrap();
        db.batch_execute("ANALYZE json_tree_generated").unwrap();
    }

    /// Each needle's operand for `containment`, as the SQL takes it.
    fn operands(&self, containment: Containment, needles: &[Needle]) -> Vec<String> {
        needles
            .iter()
            .map(|needle| {
                let query = match containment {
                    Containment::Contains => wait(
                        &self.runtime,
                        self.cipher
                            .query(op::Contains, &needle.value)
                            .on(&self.plan),
                    ),
                    Containment::ContainedBy => wait(
                        &self.runtime,
                        self.cipher
                            .query(op::ContainedBy, &needle.value)
                            .on(&self.plan),
                    ),
                }
                .unwrap();
                serde_json::to_string(&JsonTreeQuery::try_from(&query).unwrap()).unwrap()
            })
            .collect()
    }

    /// For each needle, the ids of the rows that `jsonb` selects over the
    /// plaintexts: the oracle.
    fn jsonb(&self, containment: Containment, needles: &[Needle]) -> Vec<Vec<i32>> {
        let texts: Vec<String> = needles.iter().map(|n| n.value.to_string()).collect();
        self.rows_per_needle(&format!("g.plain {} n.t::jsonb", containment.sql()), &texts)
    }

    /// For each operand, the ids of the rows the encrypted column selects,
    /// and the plan the statement ran under.
    fn encrypted(
        &self,
        containment: Containment,
        scan: Scan,
        operands: &[String],
    ) -> (String, Vec<Vec<i32>>) {
        let predicate = format!(
            "g.doc {} n.t::jsonb::eql_v4.query_json_tree",
            containment.sql()
        );
        self.db.borrow_mut().batch_execute(scan.settings()).unwrap();
        let explain = self
            .db
            .borrow_mut()
            .query(
                &format!("EXPLAIN {}", Self::per_needle(&predicate)),
                &[&operands],
            )
            .unwrap()
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        let rows = self.rows_per_needle(&predicate, operands);
        self.db.borrow_mut().batch_execute("RESET ALL").unwrap();
        (explain, rows)
    }

    /// The statement that answers every needle at once: one correlated
    /// subquery per needle, which the planner can serve from the index.
    fn per_needle(predicate: &str) -> String {
        format!(
            "SELECT coalesce((SELECT array_agg(g.id ORDER BY g.id) FROM json_tree_generated g WHERE {predicate}), '{{}}')
             FROM unnest($1::text[]) WITH ORDINALITY AS n(t, i) ORDER BY n.i"
        )
    }

    fn rows_per_needle(&self, predicate: &str, params: &[String]) -> Vec<Vec<i32>> {
        let sql = Self::per_needle(predicate);
        self.db
            .borrow_mut()
            .query(&sql, &[&params])
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .iter()
            .map(|r| r.get(0))
            .collect()
    }
}

/// Run `body` over a whole proptest run against one [`Scenario`], log what
/// ran, and fail with the minimal case and the way to replay it.
fn run(name: &str, body: impl Fn(&Scenario, &Case) -> Result<(), TestCaseError>) {
    let config = config();
    let replay = replay(&config);
    eprintln!("json_tree generated {name}: {replay}");
    let started = std::time::Instant::now();
    let scenario = scenario();
    let mut runner = TestRunner::new(config);
    let result = runner.run(&strategies::case(), |case| body(&scenario, &case));
    if let Err(error) = result {
        panic!("json_tree generated {name}: {replay}\n{error}");
    }
    eprintln!(
        "json_tree generated {name}: passed in {:?}",
        started.elapsed()
    );
}

// =============================================================================
// Tests
// =============================================================================

mod given_the_document_strategy {
    use super::*;

    /// Every feature the oracle relies on, counted over a run's worth of
    /// generated documents, so a change to the generator that stops
    /// producing one fails here, without a database.
    #[test]
    fn produces_every_feature_the_oracle_relies_on() {
        let mut runner = TestRunner::new(config());
        let strategy = strategies::document();
        let docs: Vec<Value> = (0..400)
            .map(|_| strategy.new_tree(&mut runner).unwrap().current())
            .collect();
        assertions::covers_every_feature(&assertions::Census::of(&docs));
    }
}

mod given_generated_documents_in_postgres {
    use super::*;

    /// Needs an EQL v4 installation. For every needle of every case, the
    /// rows encrypted `@>` selects are the rows `jsonb @>` selects over the
    /// plaintexts, on the index plan and on the sequential plan, each
    /// confirmed by `EXPLAIN`. A needle pruned from a row's whole document
    /// is checked to be contained by that row, and the near misses are
    /// checked to miss their row often.
    #[test]
    #[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
    fn contains_selects_the_rows_jsonb_contains_on_both_plans() {
        let (needles_asked, near_misses, near_misses_missing) =
            (Cell::new(0), Cell::new(0), Cell::new(0));
        run("@>", |scenario, case| {
            scenario.store(&case.docs);
            let needles = case.needles();
            let jsonb = scenario.jsonb(Containment::Contains, &needles);
            assertions::pruned_roots_are_contained(&needles, &jsonb)?;
            for (needle, rows) in needles.iter().zip(&jsonb) {
                if let Origin::NearMiss(row) = needle.origin {
                    near_misses.set(near_misses.get() + 1);
                    if !rows.contains(&(row as i32)) {
                        near_misses_missing.set(near_misses_missing.get() + 1);
                    }
                }
            }
            let operands = scenario.operands(Containment::Contains, &needles);
            for scan in Scan::ALL {
                let (plan, encrypted) = scenario.encrypted(Containment::Contains, scan, &operands);
                assertions::planned_as(&plan, scan)?;
                assertions::rows_match(
                    &format!("@> ({scan:?} plan)"),
                    case,
                    &needles,
                    &jsonb,
                    &encrypted,
                )?;
            }
            needles_asked.set(needles_asked.get() + needles.len());
            Ok(())
        });
        eprintln!(
            "json_tree generated @>: {} needles asked, {} near misses, {} of them missing their row",
            needles_asked.get(),
            near_misses.get(),
            near_misses_missing.get()
        );
        assert!(
            near_misses_missing.get() * 4 >= near_misses.get(),
            "the near misses should mostly miss the row they were made from: {} of {}",
            near_misses_missing.get(),
            near_misses.get()
        );
    }

    /// Needs an EQL v4 installation. For every needle of every case, the
    /// rows encrypted `<@` selects are the rows `jsonb <@` selects, less a
    /// stored root scalar when the needle is a root array: the one case the
    /// SQL documents it cannot answer, since a stored document carries no
    /// root-array alternative. That case is the whole difference, and the
    /// run must meet it. `jsonb_path_ops` has no `<@` strategy, so both
    /// plans scan; both are asked all the same.
    #[test]
    #[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
    fn contained_by_selects_the_rows_jsonb_does_except_a_root_scalar_in_a_root_array() {
        let excluded = Cell::new(0);
        run("<@", |scenario, case| {
            scenario.store(&case.docs);
            let needles = case.needles();
            let jsonb = scenario.jsonb(Containment::ContainedBy, &needles);
            let expected: Vec<Vec<i32>> = needles
                .iter()
                .zip(&jsonb)
                .map(|(needle, rows)| {
                    rows.iter()
                        .copied()
                        .filter(|id| {
                            let stored = &case.docs[*id as usize];
                            !(needle.value.is_array() && !stored.is_object() && !stored.is_array())
                        })
                        .collect()
                })
                .collect();
            excluded.set(
                excluded.get() + jsonb.iter().map(Vec::len).sum::<usize>()
                    - expected.iter().map(Vec::len).sum::<usize>(),
            );
            let operands = scenario.operands(Containment::ContainedBy, &needles);
            for scan in Scan::ALL {
                let (_, encrypted) = scenario.encrypted(Containment::ContainedBy, scan, &operands);
                assertions::rows_match(
                    &format!("<@ ({scan:?} plan)"),
                    case,
                    &needles,
                    &expected,
                    &encrypted,
                )?;
            }
            Ok(())
        });
        eprintln!(
            "json_tree generated <@: {} rows excluded as a root scalar in a root array",
            excluded.get()
        );
        assert!(
            excluded.get() > 0,
            "no stored root scalar sat inside a needle root array, so the `<@` exception went unexercised"
        );
    }

    /// Needs an EQL v4 installation. At every key path of one or two steps
    /// over the generated keys, the encrypted column has an entry exactly
    /// where `jsonb #>` finds a node (`#>` reads a key of an array as no
    /// node, as a strict path does), and a leaf's entry opens to the value
    /// `jsonb` holds there, compared by PostgreSQL's `jsonb =`, which
    /// compares numbers by value.
    #[test]
    #[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
    fn arrow_opens_a_leaf_to_the_value_jsonb_holds() {
        let mut paths: Vec<Vec<&str>> = PATH_KEYS.iter().map(|k| vec![*k]).collect();
        for a in PATH_KEYS {
            for b in PATH_KEYS {
                paths.push(vec![*a, *b]);
            }
        }
        let (leaves, containers) = (Cell::new(0), Cell::new(0));
        run("->", |scenario, case| {
            scenario.store(&case.docs);
            let keyset = scenario.cipher.default_keyset();
            let selectors: Vec<String> = paths
                .iter()
                .map(|steps| {
                    let path = JsonPath::parse(&format!("$.{}", steps.join("."))).unwrap();
                    wait(&scenario.runtime, keyset.json_selector(&path, column()))
                        .unwrap()
                        .to_string()
                })
                .collect();
            let keys: Vec<String> = paths
                .iter()
                .map(|steps| format!("{{{}}}", steps.join(",")))
                .collect();
            let rows = scenario
                .db
                .borrow_mut()
                .query(
                    "SELECT p.i, g.id, (g.plain #> p.k::text[])::text, jsonb_typeof(g.plain #> p.k::text[]), (g.doc -> p.s)::jsonb::text
                     FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS p(s, k, i)
                     CROSS JOIN json_tree_generated g ORDER BY p.i, g.id",
                    &[&selectors, &keys],
                )
                .unwrap();
            let mut opened: Vec<String> = Vec::new();
            let mut held: Vec<String> = Vec::new();
            let mut at: Vec<(String, i32)> = Vec::new();
            for row in rows {
                let path = format!("$.{}", paths[row.get::<_, i64>(0) as usize - 1].join("."));
                let id: i32 = row.get(1);
                let want: Option<String> = row.get(2);
                let kind: Option<String> = row.get(3);
                let got: Option<String> = row.get(4);
                assertions::entry_where_jsonb_has_a_node(
                    &path,
                    id,
                    case,
                    want.is_some(),
                    got.is_some(),
                )?;
                if let (Some(want), Some(got)) = (want, got) {
                    if matches!(kind.as_deref(), Some("object" | "array")) {
                        containers.set(containers.get() + 1);
                        continue;
                    }
                    let entry: JsonTreeEntry = serde_json::from_str(&got).unwrap();
                    let value = wait(
                        &scenario.runtime,
                        scenario.cipher.decrypt_as::<Value, _>(entry, column()),
                    )
                    .map_err(|e| {
                        TestCaseError::fail(format!(
                            "-> {path}, row {id}: the entry did not open: {e}"
                        ))
                    })?;
                    opened.push(value.to_string());
                    held.push(want);
                    at.push((path, id));
                }
            }
            let differing: Vec<i64> = scenario
                .db
                .borrow_mut()
                .query(
                    "SELECT i FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS u(opened, held, i)
                     WHERE opened::jsonb IS DISTINCT FROM held::jsonb ORDER BY i",
                    &[&opened, &held],
                )
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
            assertions::leaves_open_to_the_jsonb_value(&differing, &at, &opened, &held, case)?;
            leaves.set(leaves.get() + opened.len());
            Ok(())
        });
        eprintln!(
            "json_tree generated ->: {} leaves opened, {} containers found at {} paths",
            leaves.get(),
            containers.get(),
            paths.len()
        );
        assert!(
            leaves.get() > 50 && containers.get() > 10,
            "the paths should reach many leaves and containers: {} leaves, {} containers",
            leaves.get(),
            containers.get()
        );
    }
}

pub(super) mod assertions {
    use super::*;

    /// The rows `encrypted` selected for each needle are the rows `expected`
    /// says; every disagreement is named with its needle and the stored
    /// documents on each side.
    pub(super) fn rows_match(
        what: &str,
        case: &Case,
        needles: &[Needle],
        expected: &[Vec<i32>],
        encrypted: &[Vec<i32>],
    ) -> Result<(), TestCaseError> {
        let show = |ids: Vec<i32>| -> String {
            ids.iter()
                .map(|id| format!("\n      row {id}: {}", case.docs[*id as usize]))
                .collect()
        };
        let disagreements: Vec<String> = needles
            .iter()
            .zip(expected.iter().zip(encrypted))
            .enumerate()
            .filter(|(_, (_, (expected, encrypted)))| expected != encrypted)
            .map(|(i, (needle, (expected, encrypted)))| {
                let only_jsonb = expected.iter().copied().filter(|id| !encrypted.contains(id)).collect();
                let only_encrypted = encrypted.iter().copied().filter(|id| !expected.contains(id)).collect();
                format!(
                    "{what}, needle {i} ({}): {}\n    jsonb: {expected:?}\n    encrypted: {encrypted:?}\n    only jsonb:{}\n    only encrypted:{}",
                    needle.origin,
                    needle.value,
                    show(only_jsonb),
                    show(only_encrypted),
                )
            })
            .collect();
        prop_assert!(
            disagreements.is_empty(),
            "{} needles answered differently from jsonb:\n{}",
            disagreements.len(),
            disagreements.join("\n")
        );
        Ok(())
    }

    /// The plan the statement ran under is the one `scan` asks for: a
    /// bitmap scan over the GIN index, or a sequential scan and no index.
    pub(super) fn planned_as(plan: &str, scan: Scan) -> Result<(), TestCaseError> {
        let as_asked = match scan {
            Scan::Index => plan.contains("Bitmap Index Scan on json_tree_generated_doc"),
            Scan::Sequential => {
                plan.contains("Seq Scan on json_tree_generated")
                    && !plan.contains("Index Scan")
                    && !plan.contains("Bitmap")
            }
        };
        prop_assert!(
            as_asked,
            "the {scan:?} plan should be the one asked for:\n{plan}"
        );
        Ok(())
    }

    /// A needle pruned from a row's whole document is contained by that
    /// row: the generator's own claim, checked by the oracle.
    pub(super) fn pruned_roots_are_contained(
        needles: &[Needle],
        jsonb: &[Vec<i32>],
    ) -> Result<(), TestCaseError> {
        for (needle, rows) in needles.iter().zip(jsonb) {
            if let Origin::PrunedRoot(row) = needle.origin {
                prop_assert!(
                    rows.contains(&(row as i32)),
                    "row {row} should contain its own pruning {}, but jsonb selects {rows:?}",
                    needle.value
                );
            }
        }
        Ok(())
    }

    pub(super) fn entry_where_jsonb_has_a_node(
        path: &str,
        id: i32,
        case: &Case,
        jsonb_has_a_node: bool,
        encrypted_has_an_entry: bool,
    ) -> Result<(), TestCaseError> {
        prop_assert_eq!(
            encrypted_has_an_entry,
            jsonb_has_a_node,
            "-> {}, row {}: the encrypted column should have an entry exactly where jsonb has a node\n    stored: {}",
            path,
            id,
            &case.docs[id as usize]
        );
        Ok(())
    }

    pub(super) fn leaves_open_to_the_jsonb_value(
        differing: &[i64],
        at: &[(String, i32)],
        opened: &[String],
        held: &[String],
        case: &Case,
    ) -> Result<(), TestCaseError> {
        let report: Vec<String> = differing
            .iter()
            .map(|i| {
                let i = *i as usize - 1;
                let (path, id) = &at[i];
                format!(
                    "-> {path}, row {id}: opened {}, jsonb holds {}\n    stored: {}",
                    opened[i], held[i], case.docs[*id as usize]
                )
            })
            .collect();
        prop_assert!(
            report.is_empty(),
            "leaves should open to the value jsonb holds:\n{}",
            report.join("\n")
        );
        Ok(())
    }

    /// The features the generator is meant to cover, counted.
    #[derive(Debug, Default)]
    pub(super) struct Census {
        root_objects: usize,
        root_arrays: usize,
        root_scalars: usize,
        empty_objects: usize,
        empty_arrays: usize,
        arrays_of_objects: usize,
        arrays_of_arrays: usize,
        duplicate_elements: usize,
        keys_on_two_levels: usize,
        float_spelled_integers: usize,
        numeric_strings: usize,
        booleans: usize,
        nulls: usize,
        max_depth: usize,
    }

    impl Census {
        pub(super) fn of(docs: &[Value]) -> Self {
            let mut census = Census::default();
            for doc in docs {
                match doc {
                    Value::Object(_) => census.root_objects += 1,
                    Value::Array(_) => census.root_arrays += 1,
                    _ => census.root_scalars += 1,
                }
                let mut keys =
                    std::collections::BTreeMap::<&str, std::collections::BTreeSet<usize>>::new();
                census.walk(doc, 0, &mut keys);
                if keys.values().any(|depths| depths.len() > 1) {
                    census.keys_on_two_levels += 1;
                }
            }
            census
        }

        fn walk<'v>(
            &mut self,
            v: &'v Value,
            depth: usize,
            keys: &mut std::collections::BTreeMap<&'v str, std::collections::BTreeSet<usize>>,
        ) {
            self.max_depth = self.max_depth.max(depth);
            match v {
                Value::Object(map) => {
                    if map.is_empty() {
                        self.empty_objects += 1;
                    }
                    for (key, member) in map {
                        let _ = keys.entry(key).or_default().insert(depth);
                        self.walk(member, depth + 1, keys);
                    }
                }
                Value::Array(items) => {
                    if items.is_empty() {
                        self.empty_arrays += 1;
                    }
                    if items.iter().any(Value::is_object) {
                        self.arrays_of_objects += 1;
                    }
                    if items.iter().any(Value::is_array) {
                        self.arrays_of_arrays += 1;
                    }
                    if items
                        .iter()
                        .enumerate()
                        .any(|(i, a)| items[i + 1..].contains(a))
                    {
                        self.duplicate_elements += 1;
                    }
                    for item in items {
                        self.walk(item, depth + 1, keys);
                    }
                }
                Value::Number(n) => {
                    if n.is_f64() && n.as_f64().is_some_and(|f| f.fract() == 0.0) {
                        self.float_spelled_integers += 1;
                    }
                }
                Value::String(s) => {
                    if s.parse::<f64>().is_ok() {
                        self.numeric_strings += 1;
                    }
                }
                Value::Bool(_) => self.booleans += 1,
                Value::Null => self.nulls += 1,
            }
        }
    }

    pub(super) fn covers_every_feature(census: &Census) {
        let counts = [
            ("root objects", census.root_objects),
            ("root arrays", census.root_arrays),
            ("root scalars", census.root_scalars),
            ("empty objects", census.empty_objects),
            ("empty arrays", census.empty_arrays),
            ("arrays of objects", census.arrays_of_objects),
            ("arrays of arrays", census.arrays_of_arrays),
            ("duplicate array elements", census.duplicate_elements),
            ("a key on two levels", census.keys_on_two_levels),
            ("integers spelled as floats", census.float_spelled_integers),
            ("strings spelled as numbers", census.numeric_strings),
            ("booleans", census.booleans),
            ("nulls", census.nulls),
        ];
        for (what, count) in counts {
            assert!(
                count > 0,
                "the generated documents should hold {what}: {census:?}"
            );
        }
        assert!(
            census.max_depth >= 4,
            "the generated documents should nest at least four levels: {census:?}"
        );
    }
}
