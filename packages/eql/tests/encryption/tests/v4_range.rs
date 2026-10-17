//! The EQL v4 range query domains and `eql_v4.between` (ADR-0009, decision 7).
//!
//! A `Between` query is one term holding both bounds, and in SQL it is one
//! operand: `WHERE eql_v4.between(col, $1::eql_v4.query_integer_range_ore)`.
//! A range is `{"v": 4, "i": {…}, "lo": <term>, "hi": <term>}`, each bound the
//! value the single-bound query domain for the same term holds under its term
//! key (`ob` for block ORE, `op` for CLLW OPE).
//!
//! EQL v4's ordered types are not producible yet: EQL compares block-ORE and
//! CLLW-OPE terms, and Stack Encrypt does not derive those for EQL (#1132,
//! #1236). So the order terms here come from cipherstash-client's ORE and OPE
//! indexers, the code that writes the terms EQL's comparators are built for,
//! run offline over `FakeDataKeySource`'s index key as
//! `ste_vec_selectors.rs` does. The rest of each stored value (`v`, `i`, `c`,
//! and `hm` for text) is a real Stack Encrypt `Integer` or `TextEq`. Nothing
//! here derives an order term itself.
//!
//! The PostgreSQL tests need an EQL v4 installation (`mise run
//! test:encryption:postgres`); the others need no database.

mod common;

use cipherstash_client::encryption::{IndexTerm, OpeIndexer, OreIndexer, Plaintext};
use cipherstash_client::zerokms;
use eql_bindings::encryption::plaintext::Int32;
use eql_bindings::v4::{self, integer, text, DomainType};
use eql_bindings::Identifier;
use serde_json::{json, Value};
use stack_encrypt::NonEmpty;
use stack_kms::{FakeDataKeySource, IndexKeySource};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "age").unwrap()
}

fn identifier() -> Value {
    json!({"t": "users", "c": "age"})
}

/// `FakeDataKeySource`'s index key for the default keyset, as the key type
/// cipherstash-client's indexers take.
async fn index_key() -> zerokms::IndexKey {
    let (_, key) = FakeDataKeySource::new().load_index_key(None).await.unwrap();
    zerokms::IndexKey::from(*key.key())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `ob` value cipherstash-client writes for `plaintext`: one hex block
/// for a number, one per block for text. `query` asks for the query form.
fn ob(key: &zerokms::IndexKey, plaintext: Plaintext, query: bool) -> Value {
    let term = if query {
        OreIndexer.encrypt_for_query(&plaintext, key)
    } else {
        OreIndexer.encrypt(&plaintext, key)
    };
    match term.unwrap() {
        IndexTerm::OreFull(bytes) => json!([hex(&bytes)]),
        IndexTerm::OreArray(blocks) => {
            Value::Array(blocks.iter().map(|b| Value::String(hex(b))).collect())
        }
        other => panic!("not an ORE term: {other:?}"),
    }
}

/// The `op` value cipherstash-client writes for `plaintext`.
fn op(key: &zerokms::IndexKey, plaintext: Plaintext) -> Value {
    match OpeIndexer.encrypt(&plaintext, key).unwrap() {
        IndexTerm::OpeFixed(bytes) | IndexTerm::OpeVariable(bytes) => Value::String(hex(&bytes)),
        other => panic!("not an OPE term: {other:?}"),
    }
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
    let key = index_key().await;
    let (lo, hi) = (Plaintext::Int(Some(10)), Plaintext::Int(Some(30)));

    // Each bound is what the single-bound query operand holds as `ob`: the
    // same value reads as either. (A block-ORE term carries a nonce, so two
    // derivations of one value differ; one derivation is used for both.)
    let lo_ob = ob(&key, lo.clone(), true);
    let ore: integer::IntegerRangeOreQuery = serde_json::from_value(json!({
        "v": 4, "i": identifier(), "lo": lo_ob, "hi": ob(&key, hi.clone(), true),
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
        "lo": op(&key, lo.clone()), "hi": op(&key, hi.clone()),
    }))
    .unwrap();
    let single: integer::IntegerOrdOpeQuery = serde_json::from_value(json!({
        "v": 4, "i": identifier(), "op": op(&key, lo.clone()),
    }))
    .unwrap();
    assert_eq!(ope.lo, single.op);

    let good = json!({"v": 4, "i": identifier(), "lo": op(&key, lo.clone()), "hi": op(&key, hi)});
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
/// Stack Encrypt `Integer` (`v`, `i`, `c`) with cipherstash-client's order
/// term added: `ob` for `_ord_ore`, `op` for `_ord` and `_ord_ope`.
fn integer_table(
    runtime: &tokio::runtime::Runtime,
    db: &mut postgres::Client,
    key: &zerokms::IndexKey,
) {
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
        let stored: integer::Integer = runtime
            .block_on(async { keyset.encrypt_as(&Int32(n), column()).await })
            .unwrap();
        let base = serde_json::to_value(&stored).unwrap();
        let with = |k: &str, term: Value| {
            let mut v = base.clone();
            v[k] = term;
            v.to_string()
        };
        db.execute(
            "INSERT INTO v4_int_range VALUES ($1,
                $2::text::jsonb::public.eql_v4_integer_ord_ore,
                $3::text::jsonb::public.eql_v4_integer_ord,
                $4::text::jsonb::public.eql_v4_integer_ord_ope)",
            &[
                &n,
                &with("ob", ob(key, Plaintext::Int(Some(n)), false)),
                &with("op", op(key, Plaintext::Int(Some(n)))),
                &with("op", op(key, Plaintext::Int(Some(n)))),
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
    let key = runtime.block_on(index_key());
    {
        let mut db = connect();
        integer_table(&runtime, &mut db, &key);

        let ore = |lo: i32, hi: i32| {
            range::<integer::IntegerRangeOreQuery>(
                ob(&key, Plaintext::Int(Some(lo)), true),
                ob(&key, Plaintext::Int(Some(hi)), true),
            )
        };
        let ope = |lo: i32, hi: i32| {
            range::<integer::IntegerRangeOpeQuery>(
                op(&key, Plaintext::Int(Some(lo))),
                op(&key, Plaintext::Int(Some(hi))),
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

        // A range whose low bound is above its high bound matches nothing:
        // the client refuses one, and the SQL does not reorder it.
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

        // A range over the other term has no `between` for the column, so the
        // call fails at plan time. PostgreSQL reports it as ambiguous: with no
        // exact match it treats both domains as `jsonb`, which every
        // `between` overload would take.
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
    let key = runtime.block_on(index_key());
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
        let stored: text::TextEq = runtime
            .block_on(async { keyset.encrypt_as(&word.to_string(), column()).await })
            .unwrap();
        let base = serde_json::to_value(&stored).unwrap();
        let mut ore = base.clone();
        ore["ob"] = ob(&key, Plaintext::Text(Some(word.to_string())), false);
        let mut ope = base;
        ope["op"] = op(&key, Plaintext::Text(Some(word.to_string())));
        rows.push((id as i32, ore.to_string(), ope.to_string()));
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
        let text = |s: &str| Plaintext::Text(Some(s.to_owned()));
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
                ob(&key, text(lo), true),
                ob(&key, text(hi), true),
            );
            assert_eq!(
                found("ore", "query_text_range_ore", &ore),
                want,
                "ORE [{lo}, {hi}]"
            );
            let ope = range::<text::TextRangeOpeQuery>(op(&key, text(lo)), op(&key, text(hi)));
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
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_between_uses_the_order_term_index() {
    let runtime = runtime();
    let key = runtime.block_on(index_key());
    {
        let mut db = connect();
        integer_table(&runtime, &mut db, &key);
        db.batch_execute(
            "CREATE INDEX v4_int_range_ore ON v4_int_range USING btree (eql_v4.ord_term_ore(ore));
             CREATE INDEX v4_int_range_ope ON v4_int_range USING btree (eql_v4.ord_term(ope));
             ANALYZE v4_int_range;
             SET enable_seqscan = off;",
        )
        .unwrap();
        let ore = range::<integer::IntegerRangeOreQuery>(
            ob(&key, Plaintext::Int(Some(10)), true),
            ob(&key, Plaintext::Int(Some(30)), true),
        );
        let ope = range::<integer::IntegerRangeOpeQuery>(
            op(&key, Plaintext::Int(Some(10))),
            op(&key, Plaintext::Int(Some(30))),
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
        }
        db.batch_execute("RESET enable_seqscan;").unwrap();
    }
}

/// Needs an EQL v4 installation. The range domains' CHECKs admit exactly the
/// shape the bindings write.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_range_domains_check_their_shape() {
    let key = runtime().block_on(index_key());
    let (lo, hi) = (Plaintext::Int(Some(1)), Plaintext::Int(Some(2)));
    let ore = json!({"v": 4, "i": identifier(), "lo": ob(&key, lo.clone(), true), "hi": ob(&key, hi.clone(), true)});
    let ope = json!({"v": 4, "i": identifier(), "lo": op(&key, lo), "hi": op(&key, hi)});
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
