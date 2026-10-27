//! The EQL v4 range query domains and `eql_v4.between` (ADR-0009, decision 7).
//!
//! A `Between` query is one term holding both bounds, and in SQL it is one
//! operand: `WHERE eql_v4.between(col, $1::eql_v4.query_integer_range_ore)`.
//! A range is `{"v": 4, "i": {…}, "lo": <term>, "hi": <term>}`, each bound the
//! value the single-bound query domain for the same term holds under its term
//! key (`ob` for block ORE, `op` for CLLW OPE).
//!
//! The order terms, stored and in each bound, are the engine's: Stack Encrypt
//! derives the block ORE (`ob`) and CLLW OPE (`op`) terms of EQL v4's ordered
//! types, so a row is a real `IntegerOrdOre`, `TextOrdOpe`, …, and a bound is
//! the term the single-bound query of that type carries. Nothing here derives
//! an order term itself. The smoke test ranges over every family with
//! ordered types.
//!
//! The PostgreSQL tests need an EQL v4 installation (`mise run
//! test:encryption:postgres`); the others need no database.

mod common;

use eql_bindings::encryption::targets;
use eql_bindings::v4::{self, integer, text, DomainType};
use serde_json::{json, Value};
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::target::IndexSpec;
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{Encrypt, KeysetCipher, Label};

fn identifier() -> Value {
    json!({"t": "users", "c": "age"})
}

fn label() -> Label {
    Label::new(["users", "age"]).unwrap()
}

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

/// The value the engine seals for `value` as the EQL type `name`, as the
/// JSON text a driver binds: its order term (`ob` or `op`) is what `between`
/// compares a bound against.
async fn stored(
    keyset: &KeysetCipher<'_, common::Observed>,
    name: &str,
    value: ValueFrame,
) -> String {
    let bytes = targets::encrypt(name, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    String::from_utf8(bytes).unwrap()
}

/// The order term the engine derives for `value` queried as the EQL type
/// `name` through `index` (`"ore_block"` for a block ORE bound, `"ope"` for a
/// CLLW OPE one): what a range holds under `lo` and `hi`, the same value the
/// single-bound query domain holds under `ob` or `op`.
async fn bound(
    keyset: &KeysetCipher<'_, common::Observed>,
    name: &str,
    index: &str,
    value: ValueFrame,
) -> Value {
    let spec = IndexSpec::parse(index).unwrap();
    let bytes = targets::query(name, &spec, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    let mut query: Value = serde_json::from_slice(&bytes).unwrap();
    let term = match index {
        "ore_block" => "ob",
        "ope" => "op",
        other => panic!("no range over the {other} index"),
    };
    query[term].take()
}

/// A range over the bounds `lo` and `hi`, read through the binding `T` (so
/// the binding accepts it) and written back as the JSON text a driver binds.
fn range<T: DomainType + serde::Serialize + serde::de::DeserializeOwned>(
    lo: Value,
    hi: Value,
) -> String {
    let value: T =
        serde_json::from_value(json!({"v": 4, "i": identifier(), "lo": lo, "hi": hi})).unwrap();
    serde_json::to_string(&value).unwrap()
}

#[tokio::test]
async fn range_bindings_hold_two_bounds_of_their_term_and_refuse_anything_else() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let lo_ob = bound(&keyset, "IntegerOrdOre", "ore_block", frame(10i32)).await;
    let hi_ob = bound(&keyset, "IntegerOrdOre", "ore_block", frame(30i32)).await;
    let lo_op = bound(&keyset, "IntegerOrd", "ope", frame(10i32)).await;
    let hi_op = bound(&keyset, "IntegerOrd", "ope", frame(30i32)).await;

    // Each bound is what the single-bound query operand holds as `ob`: the
    // same value reads as either. (A block-ORE term carries a nonce, so two
    // derivations of one value differ; one derivation is used for both.)
    let ore: integer::IntegerRangeOreQuery = serde_json::from_value(json!({
        "v": 4, "i": identifier(), "lo": lo_ob, "hi": hi_ob,
    }))
    .unwrap();
    let single: integer::IntegerOrdOreQuery =
        serde_json::from_value(json!({"v": 4, "i": identifier(), "ob": lo_ob})).unwrap();
    assert_eq!(ore.lo, single.ob);
    assert_ne!(ore.lo, ore.hi);
    let json = serde_json::to_value(&ore).unwrap();
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["hi", "i", "lo", "v"]);
    assert_eq!(
        integer::IntegerRangeOreQuery::sql_domain_static(),
        "eql_v4.query_integer_range_ore"
    );
    assert_eq!(
        integer::IntegerRangeOreQuery::term_json_keys_static(),
        Some(&["lo", "hi"][..])
    );

    let ope: integer::IntegerRangeOpeQuery = serde_json::from_value(json!({
        "v": 4, "i": identifier(),
        "lo": lo_op.clone(), "hi": hi_op.clone(),
    }))
    .unwrap();
    let single: integer::IntegerOrdOpeQuery = serde_json::from_value(json!({
        "v": 4, "i": identifier(), "op": lo_op.clone(),
    }))
    .unwrap();
    assert_eq!(ope.lo, single.op);

    let good = json!({"v": 4, "i": identifier(), "lo": lo_op, "hi": hi_op});
    let refused = |change: &dyn Fn(&mut Value)| {
        let mut value = good.clone();
        change(&mut value);
        serde_json::from_value::<integer::IntegerRangeOpeQuery>(value).is_err()
    };
    assert!(
        refused(&|v| v["c"] = json!("ciphertext")),
        "a range holds no ciphertext"
    );
    assert!(refused(&|v| v["v"] = json!(3)), "a range is EQL v4 only");
    assert!(refused(&|v| {
        v.as_object_mut().unwrap().remove("hi");
    }));
    assert!(
        refused(&|v| v["op"] = v["lo"].clone()),
        "a range is not a single-bound operand"
    );
    // An ORE bound is an `ob` array, not an `op` string.
    assert!(serde_json::from_value::<integer::IntegerRangeOreQuery>(good).is_err());
}

#[test]
fn every_ordered_family_has_an_ore_and_an_ope_range() {
    let domains: Vec<&str> = v4::all_range_query()
        .iter()
        .map(|d| d.sql_domain())
        .collect();
    let families = [
        "integer",
        "smallint",
        "bigint",
        "date",
        "timestamp",
        "numeric",
        "text",
        "real",
        "double",
    ];
    let expected: Vec<String> = families
        .iter()
        .flat_map(|f| {
            [
                format!("eql_v4.query_{f}_range_ore"),
                format!("eql_v4.query_{f}_range_ope"),
            ]
        })
        .collect();
    assert_eq!(domains, expected);
    for d in v4::all_range_query() {
        assert_eq!(
            d.term_json_keys(),
            Some(&["lo", "hi"][..]),
            "{}",
            d.sql_domain()
        );
    }
}

/// Run `EXPLAIN (FORMAT JSON) query` and return the plan as JSON. The simple
/// query protocol hands back text, which spares a JSON column type.
fn explain(db: &mut postgres::Client, query: &str) -> Value {
    let messages = db
        .simple_query(&format!("EXPLAIN (FORMAT JSON) {query}"))
        .unwrap();
    let text = messages
        .iter()
        .find_map(|m| match m {
            postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_owned),
            _ => None,
        })
        .expect("EXPLAIN returns one row");
    serde_json::from_str(&text).unwrap()
}

/// The index-scan nodes of a plan, as `(Index Name, Index Cond)`.
fn index_scans(plan: &Value, found: &mut Vec<(String, String)>) {
    match plan {
        Value::Object(node) => {
            if matches!(
                node.get("Node Type").and_then(Value::as_str),
                Some("Index Scan" | "Index Only Scan" | "Bitmap Index Scan")
            ) {
                found.push((
                    node["Index Name"].as_str().unwrap_or_default().to_owned(),
                    node.get("Index Cond")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                ));
            }
            node.values().for_each(|v| index_scans(v, found));
        }
        Value::Array(items) => items.iter().for_each(|v| index_scans(v, found)),
        _ => {}
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn connect() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

fn sqlstate(error: &postgres::Error) -> String {
    error
        .code()
        .map(|c| c.code().to_owned())
        .unwrap_or_default()
}

const INTEGERS: [i32; 12] = [-1000, -5, -1, 0, 1, 7, 10, 20, 29, 30, 31, 1000];

/// Integer rows in all three ordered column domains, each value's real
/// The engine's `IntegerOrdOre`, `IntegerOrd` and `IntegerOrdOpe` values of
/// each of `INTEGERS`: `ob` for `_ord_ore`, `op` for `_ord` and `_ord_ope`.
fn integer_table(runtime: &tokio::runtime::Runtime, db: &mut postgres::Client) {
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    db.batch_execute(
        "CREATE TEMP TABLE v4_int_range (
            n int PRIMARY KEY,
            ore public.eql_v4_integer_ord_ore,
            ord public.eql_v4_integer_ord,
            ope public.eql_v4_integer_ord_ope
        );",
    )
    .unwrap();
    for n in INTEGERS {
        let row = |name: &str| runtime.block_on(stored(&keyset, name, frame(n)));
        db.execute(
            "INSERT INTO v4_int_range VALUES ($1,
                $2::text::jsonb::public.eql_v4_integer_ord_ore,
                $3::text::jsonb::public.eql_v4_integer_ord,
                $4::text::jsonb::public.eql_v4_integer_ord_ope)",
            &[
                &n,
                &row("IntegerOrdOre"),
                &row("IntegerOrd"),
                &row("IntegerOrdOpe"),
            ],
        )
        .unwrap();
    }
}

/// Needs an EQL v4 installation. Rows inside, outside and exactly at both
/// bounds, for ORE and OPE, over integers.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_between_finds_integers_in_an_inclusive_range() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    {
        let mut db = connect();
        integer_table(&runtime, &mut db);

        let ore = |lo: i32, hi: i32| {
            range::<integer::IntegerRangeOreQuery>(
                runtime.block_on(bound(&keyset, "IntegerOrdOre", "ore_block", frame(lo))),
                runtime.block_on(bound(&keyset, "IntegerOrdOre", "ore_block", frame(hi))),
            )
        };
        let ope = |lo: i32, hi: i32| {
            range::<integer::IntegerRangeOpeQuery>(
                runtime.block_on(bound(&keyset, "IntegerOrd", "ope", frame(lo))),
                runtime.block_on(bound(&keyset, "IntegerOrd", "ope", frame(hi))),
            )
        };
        let mut found = |column: &str, domain: &str, range: &str| -> Vec<i32> {
            db.query(
                &format!(
                    "SELECT n FROM v4_int_range \
                     WHERE eql_v4.between({column}, $1::text::jsonb::eql_v4.{domain}) ORDER BY n"
                ),
                &[&range],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect()
        };
        // (lo, hi) and the rows the plaintext range holds, bounds included.
        let cases: [(i32, i32, &[i32]); 6] = [
            // Both bounds are rows: both are in.
            (10, 30, &[10, 20, 29, 30]),
            // Across zero, where a sign-blind order would break.
            (-5, 1, &[-5, -1, 0, 1]),
            // Neither bound is a row.
            (8, 28, &[10, 20]),
            // A range of one value.
            (31, 31, &[31]),
            // Between two rows: nothing.
            (2, 6, &[]),
            // The whole of i32.
            (i32::MIN, i32::MAX, &INTEGERS),
        ];
        for (lo, hi, want) in cases {
            assert_eq!(
                found("ore", "query_integer_range_ore", &ore(lo, hi)),
                want,
                "ORE [{lo}, {hi}]"
            );
            for column in ["ord", "ope"] {
                assert_eq!(
                    found(column, "query_integer_range_ope", &ope(lo, hi)),
                    want,
                    "OPE {column} [{lo}, {hi}]"
                );
            }
        }

        // A range whose low bound is above its high bound matches nothing,
        // as with SQL `BETWEEN`: the SQL does not reorder the bounds.
        assert_eq!(
            found("ore", "query_integer_range_ore", &ore(30, 10)),
            Vec::<i32>::new()
        );
        assert_eq!(
            found("ope", "query_integer_range_ope", &ope(30, 10)),
            Vec::<i32>::new()
        );

        // A NULL range is NULL, so no row, not an error.
        let none: Vec<i32> = db
            .query(
                "SELECT n FROM v4_int_range WHERE eql_v4.between(ore, NULL::eql_v4.query_integer_range_ore)",
                &[],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert!(none.is_empty());

        // A range over the other term has no `between` for the column. The
        // statement fails when it is parsed, with 42725 ("not unique"):
        // PostgreSQL resolves a function's domain arguments as their base
        // type, `jsonb`, which every `between` overload takes.
        let err = db
            .query(
                "SELECT n FROM v4_int_range WHERE eql_v4.between(ore, $1::text::jsonb::eql_v4.query_integer_range_ope)",
                &[&ope(10, 30)],
            )
            .unwrap_err();
        assert_eq!(sqlstate(&err), "42725", "{err}");
    }
}

/// Needs an EQL v4 installation. The same over text, whose ordered domains
/// also carry `hm`.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_between_finds_text_in_an_inclusive_range() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let words = [
        "apple",
        "banana",
        "blueberry",
        "cherry",
        "date",
        "elderberry",
        "fig",
    ];
    let mut rows = Vec::new();
    for (id, word) in words.iter().enumerate() {
        let ore = runtime.block_on(stored(&keyset, "TextOrdOre", frame(word.to_string())));
        let ope = runtime.block_on(stored(&keyset, "TextOrdOpe", frame(word.to_string())));
        rows.push((id as i32, ore, ope));
    }
    {
        let mut db = connect();
        db.batch_execute(
            "CREATE TEMP TABLE v4_text_range (
                id int PRIMARY KEY,
                ore public.eql_v4_text_ord_ore,
                ope public.eql_v4_text_ord_ope
            );",
        )
        .unwrap();
        for (id, ore, ope) in &rows {
            db.execute(
                "INSERT INTO v4_text_range VALUES ($1,
                    $2::text::jsonb::public.eql_v4_text_ord_ore,
                    $3::text::jsonb::public.eql_v4_text_ord_ope)",
                &[id, ore, ope],
            )
            .unwrap();
        }
        let mut found = |column: &str, domain: &str, range: &str| -> Vec<String> {
            db.query(
                &format!(
                    "SELECT id FROM v4_text_range \
                     WHERE eql_v4.between({column}, $1::text::jsonb::eql_v4.{domain}) ORDER BY id"
                ),
                &[&range],
            )
            .unwrap()
            .iter()
            .map(|r| words[r.get::<_, i32>(0) as usize].to_owned())
            .collect()
        };
        let cases: [(&str, &str, &[&str]); 4] = [
            // Both bounds are rows: both are in.
            ("banana", "date", &["banana", "blueberry", "cherry", "date"]),
            // Neither bound is a row.
            ("b", "c", &["banana", "blueberry"]),
            ("fig", "fig", &["fig"]),
            ("dog", "eel", &[]),
        ];
        for (lo, hi, want) in cases {
            let ore = range::<text::TextRangeOreQuery>(
                runtime.block_on(bound(
                    &keyset,
                    "TextOrdOre",
                    "ore_block",
                    frame(lo.to_string()),
                )),
                runtime.block_on(bound(
                    &keyset,
                    "TextOrdOre",
                    "ore_block",
                    frame(hi.to_string()),
                )),
            );
            assert_eq!(
                found("ore", "query_text_range_ore", &ore),
                want,
                "ORE [{lo}, {hi}]"
            );
            let ope = range::<text::TextRangeOpeQuery>(
                runtime.block_on(bound(&keyset, "TextOrd", "ope", frame(lo.to_string()))),
                runtime.block_on(bound(&keyset, "TextOrd", "ope", frame(hi.to_string()))),
            );
            assert_eq!(
                found("ope", "query_text_range_ope", &ope),
                want,
                "OPE [{lo}, {hi}]"
            );
        }
    }
}

/// Needs an EQL v4 installation. `eql_v4.between` inlines, so a btree on the
/// column's order term serves it as one index scan with both bounds in the
/// index condition. A `between` the planner could not inline would be a
/// filter on every row, and no index scan would appear.
///
/// Validity, not preference: like the SQLx suite's index-engagement tests,
/// this turns sequential scans off on a small table, so it proves the index
/// can serve the range, not that the planner prefers it at scale.
///
/// Checked twice: with the range as a literal, and as a driver sends it, a
/// `$1` of the range domain under a generic plan. With a literal the planner
/// folds both bounds to constants, so only the generic plan shows that
/// `between` still inlines when its range is a parameter used twice.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_between_uses_the_order_term_index() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    {
        let mut db = connect();
        integer_table(&runtime, &mut db);
        db.batch_execute(
            "CREATE INDEX v4_int_range_ore ON v4_int_range USING btree (eql_v4.ord_term_ore(ore));
             CREATE INDEX v4_int_range_ope ON v4_int_range USING btree (eql_v4.ord_term(ope));
             ANALYZE v4_int_range;
             SET enable_seqscan = off;",
        )
        .unwrap();
        let ore = range::<integer::IntegerRangeOreQuery>(
            runtime.block_on(bound(&keyset, "IntegerOrdOre", "ore_block", frame(10i32))),
            runtime.block_on(bound(&keyset, "IntegerOrdOre", "ore_block", frame(30i32))),
        );
        let ope = range::<integer::IntegerRangeOpeQuery>(
            runtime.block_on(bound(&keyset, "IntegerOrd", "ope", frame(10i32))),
            runtime.block_on(bound(&keyset, "IntegerOrd", "ope", frame(30i32))),
        );
        for (column, domain, index, range) in [
            ("ore", "query_integer_range_ore", "v4_int_range_ore", &ore),
            ("ope", "query_integer_range_ope", "v4_int_range_ope", &ope),
        ] {
            let query = format!(
                "SELECT n FROM v4_int_range WHERE eql_v4.between({column}, '{}'::jsonb::eql_v4.{domain})",
                range.replace('\'', "''")
            );
            let plan = explain(&mut db, &query);
            let mut scans = Vec::new();
            index_scans(&plan, &mut scans);
            let (_, cond) = scans
                .iter()
                .find(|(name, _)| name == index)
                .unwrap_or_else(|| panic!("{column}: no index scan on {index}:\n{plan:#}"));
            assert!(
                cond.contains(">=") && cond.contains("<="),
                "{column}: both bounds are index conditions, one range scan: {cond}"
            );
            assert!(
                !cond.contains("between"),
                "{column}: between was inlined: {cond}"
            );
            // The plan answers the same rows the function does.
            let n: Vec<i32> = db
                .query(&format!("{query} ORDER BY n"), &[])
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
            assert_eq!(n, [10, 20, 29, 30], "{column}");

            // The range as a parameter, under a generic plan.
            db.batch_execute(&format!(
                "SET plan_cache_mode = force_generic_plan;
                 PREPARE generic_{column}(eql_v4.{domain}) AS
                   SELECT n FROM v4_int_range WHERE eql_v4.between({column}, $1);"
            ))
            .unwrap();
            let execute = format!("EXECUTE generic_{column}('{}')", range.replace('\'', "''"));
            let plan = explain(&mut db, &execute);
            let mut scans = Vec::new();
            index_scans(&plan, &mut scans);
            let (_, cond) = scans
                .iter()
                .find(|(name, _)| name == index)
                .unwrap_or_else(|| {
                    panic!("{column}: generic: no index scan on {index}:\n{plan:#}")
                });
            assert!(
                cond.contains(">=") && cond.contains("<=") && cond.contains("$1"),
                "{column}: generic: both bounds, from the parameter, are index conditions: {cond}"
            );
            assert!(
                !cond.contains("between"),
                "{column}: generic: between was inlined: {cond}"
            );
            db.batch_execute(&format!(
                "DEALLOCATE generic_{column}; RESET plan_cache_mode;"
            ))
            .unwrap();
        }
        db.batch_execute("RESET enable_seqscan;").unwrap();
    }
}

/// Needs an EQL v4 installation. The range domains' CHECKs admit exactly the
/// shape the bindings write.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_range_domains_check_their_shape() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let term =
        |name: &str, index: &str, n: i32| runtime.block_on(bound(&keyset, name, index, frame(n)));
    let ore = json!({"v": 4, "i": identifier(), "lo": term("IntegerOrdOre", "ore_block", 1), "hi": term("IntegerOrdOre", "ore_block", 2)});
    let ope = json!({"v": 4, "i": identifier(), "lo": term("IntegerOrd", "ope", 1), "hi": term("IntegerOrd", "ope", 2)});
    {
        let mut db = connect();
        let cast = |db: &mut postgres::Client, value: &Value, domain: &str| {
            db.query_one(
                &format!("SELECT $1::text::jsonb::eql_v4.{domain}::text"),
                &[&value.to_string()],
            )
            .map(|_| ())
        };
        cast(&mut db, &ore, "query_integer_range_ore").unwrap();
        cast(&mut db, &ope, "query_integer_range_ope").unwrap();
        let with = |value: &Value, change: &dyn Fn(&mut Value)| {
            let mut v = value.clone();
            change(&mut v);
            v
        };
        for (value, domain, why) in [
            (
                with(&ore, &|v| v["c"] = json!("x")),
                "query_integer_range_ore",
                "no ciphertext",
            ),
            (
                with(&ore, &|v| v["v"] = json!(3)),
                "query_integer_range_ore",
                "EQL v4 only",
            ),
            (
                with(&ore, &|v| v["v"] = json!(null)),
                "query_integer_range_ore",
                "a JSON null version is not v4",
            ),
            (
                with(&ope, &|v| v["v"] = json!(null)),
                "query_integer_range_ope",
                "a JSON null version is not v4",
            ),
            (
                with(&ore, &|v| {
                    v.as_object_mut().unwrap().remove("hi");
                }),
                "query_integer_range_ore",
                "both bounds",
            ),
            (
                with(&ore, &|v| v["lo"] = json!([])),
                "query_integer_range_ore",
                "a non-empty ORE bound",
            ),
            (
                ope.clone(),
                "query_integer_range_ore",
                "an ORE bound is an array",
            ),
            (
                ore.clone(),
                "query_integer_range_ope",
                "an OPE bound is a string",
            ),
        ] {
            let err = cast(&mut db, &value, domain).unwrap_err();
            assert_eq!(sqlstate(&err), "23514", "{why}: {err}");
        }
    }
}

/// Five values of `family`, strictly ascending: what the smoke test stores
/// and ranges over. `None` for a family whose ordered types the engine does
/// not produce. A new ordered family must add a row here, or the test fails
/// naming it.
fn ascending(family: &str) -> Option<[Value; 5]> {
    Some(match family {
        "integer" => [-20, -1, 0, 7, 100].map(Value::from),
        "smallint" => [-300, -1, 0, 5, 300].map(Value::from),
        "bigint" => [i64::MIN + 1, -1, 0, 1 << 40, i64::MAX].map(Value::from),
        "text" => ["apple", "banana", "cherry", "damson", "elderberry"].map(Value::from),
        // `real` values are exact in f32; both float widths order as f64.
        "real" => [-2.5, -0.5, 0.0, 1.25, 1e10].map(Value::from),
        "double" => [-1e300, -1.0, 0.0, 2.5, 1e300].map(Value::from),
        // Days since 1970-01-01.
        "date" => [-719_162, -1, 0, 19_782, 30_000].map(Value::from),
        // Seconds since the epoch.
        "timestamp" => [-1_000_000_000, -1, 0, 1_700_000_000, 4_000_000_000_i64].map(Value::from),
        // Hundredths: -12.50, -0.01, 0.00, 1.50, 99999.99.
        "numeric" => [-1_250, -1, 0, 150, 9_999_999].map(Value::from),
        other => panic!("no smoke-test values for the ordered family {other:?}: add them here"),
    })
}

/// `value` as the plaintext `family`'s types seal.
fn frame_of(family: &str, value: &Value) -> ValueFrame {
    match family {
        "integer" => frame(i32::try_from(value.as_i64().unwrap()).unwrap()),
        "smallint" => frame(i16::try_from(value.as_i64().unwrap()).unwrap()),
        "bigint" => frame(value.as_i64().unwrap()),
        "real" => frame(value.as_f64().unwrap() as f32),
        "double" => frame(value.as_f64().unwrap()),
        "text" => frame(value.as_str().unwrap().to_owned()),
        "date" => frame(Date::from_days_since_epoch(value.as_i64().unwrap() as i32).unwrap()),
        "timestamp" => frame(Timestamp::new(value.as_i64().unwrap(), 0).unwrap()),
        "numeric" => frame(Decimal::new(i128::from(value.as_i64().unwrap()), 2).unwrap()),
        other => panic!("no plaintext for the ordered family {other:?}"),
    }
}

/// Needs an EQL v4 installation. A smoke test over every ordered family
/// and every `between` overload, generated from the catalog: five ascending
/// rows per family in each column domain that carries an ordering term, and
/// a range from the second value to the fourth, which must find exactly the
/// rows at both bounds and the one inside, and neither row outside. For text
/// it also checks that an order-term index serves `between`, for ORE on
/// `_ord_ore` and for OPE on `_search`.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_between_smoke_test_over_every_ordered_family() {
    let runtime = runtime();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let ranges = v4::all_range_query();
    let mut checked = 0;
    let mut skipped = Vec::new();

    for family in eql_domains::CATALOG
        .iter()
        .filter(|f| !f.range_terms().is_empty())
    {
        let table = format!("v4_smoke_{}", family.name);
        let columns: Vec<&eql_domains::Domain> = family
            .domains
            .iter()
            .filter(|d| d.terms.iter().any(|t| t.range_suffix().is_some()))
            .collect();
        // A family's ordered types are producible together or not at all,
        // and a family with none has no row to range over.
        let producible: Vec<bool> = columns
            .iter()
            .map(|d| {
                targets::target(&d.rust_struct_name(family.name)).is_some_and(|t| t.producible)
            })
            .collect();
        if producible.iter().all(|p| !p) {
            assert!(ascending(family.name).is_none(), "{}", family.name);
            skipped.push(family.name);
            continue;
        }
        assert!(producible.iter().all(|p| *p), "{}", family.name);
        let values = ascending(family.name)
            .unwrap_or_else(|| panic!("{}: its ordered types are producible", family.name));
        let type_of = |suffix: &str| {
            family
                .domains
                .iter()
                .find(|d| d.name == suffix)
                .unwrap_or_else(|| panic!("{} has no {suffix} domain", family.name))
                .rust_struct_name(family.name)
        };
        db.batch_execute(&format!(
            "CREATE TEMP TABLE {table} (id int PRIMARY KEY, {})",
            columns
                .iter()
                .map(|d| format!("c_{} public.eql_v4_{}", d.name, d.full_name(family.name)))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .unwrap();

        for (id, value) in values.iter().enumerate() {
            let payloads: Vec<String> = columns
                .iter()
                .map(|d| {
                    runtime.block_on(stored(
                        &keyset,
                        &d.rust_struct_name(family.name),
                        frame_of(family.name, value),
                    ))
                })
                .collect();
            let placeholders: Vec<String> = columns
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    format!(
                        "${}::text::jsonb::public.eql_v4_{}",
                        i + 2,
                        d.full_name(family.name)
                    )
                })
                .collect();
            let id = id as i32;
            let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&id];
            params.extend(
                payloads
                    .iter()
                    .map(|p| p as &(dyn postgres::types::ToSql + Sync)),
            );
            db.execute(
                &format!(
                    "INSERT INTO {table} VALUES ($1, {})",
                    placeholders.join(", ")
                ),
                &params,
            )
            .unwrap();
        }

        for term in family.range_terms() {
            let (name, index) = match term {
                eql_domains::Term::Ore => (type_of("ord_ore"), "ore_block"),
                eql_domains::Term::Ope => (type_of("ord"), "ope"),
                other => unreachable!("{other:?} has no range"),
            };
            let bound_of = |v: &Value| {
                runtime.block_on(bound(&keyset, &name, index, frame_of(family.name, v)))
            };
            let domain = family.range_query_name(term);
            let range = json!({"v": 4, "i": identifier(), "lo": bound_of(&values[1]), "hi": bound_of(&values[3])});
            // The binding for the domain accepts the range.
            ranges
                .iter()
                .find(|r| r.sql_domain() == format!("eql_v4.{domain}"))
                .unwrap_or_else(|| panic!("no binding for {domain}"))
                .parse_value(&range)
                .unwrap();
            for d in family.range_columns(term) {
                let found: Vec<i32> = db
                    .query(
                        &format!(
                            "SELECT id FROM {table} \
                             WHERE eql_v4.between(c_{}, $1::text::jsonb::eql_v4.{domain}) ORDER BY id",
                            d.name
                        ),
                        &[&range.to_string()],
                    )
                    .unwrap()
                    .iter()
                    .map(|r| r.get(0))
                    .collect();
                assert_eq!(
                    found,
                    [1, 2, 3],
                    "{}: between(_{}, {domain})",
                    family.name,
                    d.name
                );
                checked += 1;
            }
        }

        if family.name == "text" {
            let range = |term: eql_domains::Term| {
                let (name, index) = match term {
                    eql_domains::Term::Ore => ("TextOrdOre", "ore_block"),
                    _ => ("TextOrd", "ope"),
                };
                let bound_of =
                    |v: &Value| runtime.block_on(bound(&keyset, name, index, frame_of("text", v)));
                json!({"v": 4, "i": identifier(), "lo": bound_of(&values[1]), "hi": bound_of(&values[3])})
                    .to_string()
            };
            db.batch_execute(&format!(
                "CREATE INDEX {table}_ore ON {table} USING btree (eql_v4.ord_term_ore(c_ord_ore));
                 CREATE INDEX {table}_search ON {table} USING btree (eql_v4.ord_term(c_search));
                 ANALYZE {table};
                 SET enable_seqscan = off;"
            ))
            .unwrap();
            for (column, domain, index, value) in [
                (
                    "c_ord_ore",
                    "query_text_range_ore",
                    format!("{table}_ore"),
                    range(eql_domains::Term::Ore),
                ),
                (
                    "c_search",
                    "query_text_range_ope",
                    format!("{table}_search"),
                    range(eql_domains::Term::Ope),
                ),
            ] {
                let plan = explain(
                    &mut db,
                    &format!(
                        "SELECT id FROM {table} WHERE eql_v4.between({column}, '{}'::jsonb::eql_v4.{domain})",
                        value.replace('\'', "''")
                    ),
                );
                let mut scans = Vec::new();
                index_scans(&plan, &mut scans);
                let (_, cond) = scans
                    .iter()
                    .find(|(name, _)| *name == index)
                    .unwrap_or_else(|| {
                        panic!("text {column}: no index scan on {index}:\n{plan:#}")
                    });
                assert!(
                    cond.contains(">=") && cond.contains("<="),
                    "text {column}: {cond}"
                );
            }
            db.batch_execute("RESET enable_seqscan;").unwrap();
        }
    }
    // The 5 number families, date, timestamp and numeric with 3 overloads
    // each, and text's 5.
    assert_eq!(
        checked, 29,
        "every between overload of a producible type was exercised"
    );
    assert!(
        skipped.is_empty(),
        "every ordered family is producible: {skipped:?}"
    );
}

/// Needs an EQL v4 installation. The range parameter must be cast to its
/// exact range domain. An uncast `$1`, a `jsonb` parameter, or a range of
/// another family matches several `between` overloads (PostgreSQL resolves
/// a function's domain arguments as their base type, `jsonb`), so preparing
/// the statement fails with 42725, before any value is bound. The
/// single-bound operators resolve an uncast `$1` on the same column.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_between_needs_the_exact_range_domain() {
    let mut db = connect();
    db.batch_execute("CREATE TEMP TABLE v4_range_cast (ore public.eql_v4_integer_ord_ore);")
        .unwrap();
    for range in [
        "$1",
        "$1::jsonb",
        "$1::eql_v4.query_bigint_range_ore",
        "$1::eql_v4.query_integer_range_ope",
    ] {
        let err = db
            .prepare(&format!(
                "SELECT 1 FROM v4_range_cast WHERE eql_v4.between(ore, {range})"
            ))
            .unwrap_err();
        assert_eq!(sqlstate(&err), "42725", "{range}: {err}");
        assert!(
            err.as_db_error()
                .is_some_and(|e| e.message().contains("is not unique")),
            "{range}: {err}"
        );
    }
    db.prepare(
        "SELECT 1 FROM v4_range_cast WHERE eql_v4.between(ore, $1::eql_v4.query_integer_range_ore)",
    )
    .unwrap();
    db.prepare("SELECT 1 FROM v4_range_cast WHERE ore < $1")
        .unwrap();
}

/// A role and a database of its own, made by the superuser connection and
/// dropped on the way out, panic or not. Roles are cluster-global, so the
/// name carries the process id.
struct NonSuperuserDatabase {
    name: String,
}

impl NonSuperuserDatabase {
    fn create(admin: &mut postgres::Client) -> Self {
        let name = format!("eql_v4_nosuper_{}", std::process::id());
        // One statement per call: a multi-statement query runs in one
        // transaction, and `CREATE DATABASE` / `DROP DATABASE` refuse one.
        for statement in [
            format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
            format!("DROP ROLE IF EXISTS {name}"),
            format!("CREATE ROLE {name} LOGIN NOSUPERUSER PASSWORD '{name}'"),
            format!("CREATE DATABASE {name} OWNER {name}"),
        ] {
            admin.batch_execute(&statement).unwrap();
        }
        Self { name }
    }

    fn connect(&self) -> postgres::Client {
        let url = std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL");
        let mut config: postgres::Config = url.parse().unwrap();
        config
            .dbname(&self.name)
            .user(&self.name)
            .password(&self.name);
        config.connect(postgres::NoTls).unwrap()
    }
}

impl Drop for NonSuperuserDatabase {
    fn drop(&mut self) {
        let name = &self.name;
        let mut admin = connect();
        let _ = admin.batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"));
        let _ = admin.batch_execute(&format!("DROP ROLE IF EXISTS {name}"));
    }
}

/// Needs an EQL v4 installation, and a superuser on `EQL_TEST_DATABASE_URL`
/// who can create a role and a database. A non-superuser install skips the
/// block ORE btree opclass, and `ore_fallback.sql` disables the
/// single-bound ORE domains. Every ORE range domain is disabled the same way,
/// naming its family's OPE range, which stays usable. The bundle is the one
/// `mise run test:encryption:postgres` builds and installs.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_non_superuser_install_disables_the_ore_ranges() {
    let bundle = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../release/cipherstash-encrypt-v4.sql"
    ))
    .expect("the v4 bundle: run `mise run build`");
    let mut admin = connect();
    let database = NonSuperuserDatabase::create(&mut admin);
    let mut db = database.connect();
    db.batch_execute(&bundle).unwrap();

    let opclass: bool = db
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_opclass c
               JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
              WHERE am.amname = 'btree' AND c.opcdefault
                AND c.opcintype = 'eql_v4_internal.ore_block_v2'::pg_catalog.regtype)",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(!opclass, "a non-superuser install created the ORE opclass");

    let cast = |db: &mut postgres::Client, value: &Value, domain: &str| {
        db.query_one(
            &format!("SELECT $1::text::jsonb::{domain}::text"),
            &[&value.to_string()],
        )
        .map(|_| ())
    };
    let ore = json!({"v": 4, "i": identifier(), "lo": ["00"], "hi": ["00"]});
    let ope = json!({"v": 4, "i": identifier(), "lo": "00", "hi": "00"});
    let mut checked = 0;
    for family in eql_domains::CATALOG
        .iter()
        .filter(|f| f.range_terms().contains(&eql_domains::Term::Ore))
    {
        let ore_range = format!("eql_v4.{}", family.range_query_name(eql_domains::Term::Ore));
        let ope_range = format!("eql_v4.{}", family.range_query_name(eql_domains::Term::Ope));
        let err = cast(&mut db, &ore, &ore_range).unwrap_err();
        assert_eq!(sqlstate(&err), "0A000", "{ore_range}: {err}");
        let db_error = err.as_db_error().unwrap();
        assert!(db_error.message().contains(&ore_range), "{err}");
        assert!(
            db_error.hint().is_some_and(|h| h.contains(&ope_range)),
            "{ore_range}: {:?}",
            db_error.hint()
        );
        cast(&mut db, &ope, &ope_range).unwrap();
        checked += 1;
    }
    assert_eq!(checked, 9, "every ordered family has an ORE range");
    drop(db);
}
