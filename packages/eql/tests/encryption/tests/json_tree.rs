//! The JSON tree family end to end: a document sealed by Stack Encrypt's
//! JSON index into `public.eql_v4_json_tree`, queried with the v4 SQL, and
//! opened again. The unit tests need no database; the PostgreSQL test
//! installs nothing itself (`mise run test:encryption:postgres` installs the
//! v4 bundle built from the tree) and is the oracle the design asks for:
//! `@>` and `<@` over the encrypted column against PostgreSQL's own
//! `jsonb @>` over the plaintexts, for the design's corpus and random
//! documents, with a GIN index on the projection that the planner is shown
//! to use.

mod common;

use eql_bindings::v4::json_tree::{
    JsonTree, JsonTreeDocument, JsonTreeEntry, JsonTreeLeafQuery, JsonTreeQuery, JsonTreeSubtree,
};
use eql_bindings::Identifier;
use serde_json::{json, Map, Value};
use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPath, JsonSubtreeKey};
use stack_encrypt::plan::{Laid, ValuePlan};
use stack_encrypt::target::{Json, Layout};
use stack_encrypt::{op, NonEmpty, Plan};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

type Cipher = stack_encrypt::StackCipher<common::Observed>;

/// Seal `value` as the EQL type under the identifier, laid out by the
/// `json_tree` layout with the same ordered paths as [`plan`].
async fn seal(cipher: &Cipher, value: &Value) -> JsonTreeDocument {
    cipher
        .default_keyset()
        .run(JsonTree::new(options()).encryption(), value, column())
        .await
        .unwrap()
}

/// The plan a query derives through: the engine's own document target
/// under the label `users/profile`, which is the same context as the
/// identifier the EQL target stores (the same two parts, rendered
/// `users/profile`), so its selectors are the stored document's, laid
/// out by the JSON index with `$.hello` and `$.number` ordered, the paths
/// the ordering queries below ask at. An EQL type takes its context as
/// an identifier and runs through `encrypt_as`, not through the chain.
fn plan() -> ValuePlan<Value, Laid<Json, JsonDocument>> {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_with_layout(Json::new(options()))
        .build()
        .unwrap()
}

/// The index options the corpus is sealed under: `$.hello` and
/// `$.number` carry ordering terms.
fn options() -> JsonOptions {
    JsonOptions::default()
        .ordering(["$.hello", "$.number"])
        .unwrap()
}

/// Padded standard base64, as the wire spells a selector.
fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
async fn a_document_round_trips_through_the_typed_target() {
    let (cipher, calls) = common::cipher().await;
    let stored = seal(&cipher, &fixture()).await;
    assert_eq!(stored.sv.len(), 10, "one entry per node");
    assert_eq!(
        calls.lock().unwrap().generate,
        vec![vec!["users/profile".to_string()]],
        "one data key for the document, under the column's descriptor"
    );

    let wire = serde_json::to_value(&stored).unwrap();
    assert_eq!(wire["v"], 4);
    assert_eq!(wire["i"], json!({"t": "users", "c": "profile"}));
    assert!(wire["h"].is_string());
    let keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["h", "i", "q", "sv", "v"]);

    let opened: Value = cipher
        .decrypt_as(stored.clone(), Default::default())
        .await
        .unwrap();
    assert_eq!(opened, fixture());
    let opened: Value = cipher
        .decrypt_as(stored.clone(), column().into())
        .await
        .unwrap();
    assert_eq!(opened, fixture());

    let wrong = Identifier::for_column("users", "bio").unwrap();
    let refused = cipher
        .decrypt_as::<Value, _>(stored.clone(), wrong.into())
        .await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::ContextMismatch { .. })),
        "{refused:?}"
    );
    assert_eq!(
        calls.lock().unwrap().retrieve.len(),
        2,
        "the refused open retrieved no key"
    );

    // An entry lifted from the stored document, with the header and its
    // ordinal grafted as `->` grafts them, opens to its scalar.
    let mut entry = stored.sv[1].clone();
    entry.h = Some(stored.h.clone());
    entry.j = Some(1);
    entry.i = Some(stored.i.clone());
    entry.v = Some(stored.v);
    let scalar: Value = cipher.decrypt_as(entry, column()).await.unwrap();
    assert_eq!(scalar, json!("world-1"));
    let bare = stored.sv[1].clone();
    assert!(cipher.decrypt_as::<Value, _>(bare, column()).await.is_err());
}

#[tokio::test]
async fn the_query_operands_are_the_engines_terms_in_the_sql_contract() {
    let (cipher, _) = common::cipher().await;
    let plan = plan();
    let query = cipher
        .query(op::Contains, &json!({"nested": {"list": [{"x": 2}]}}))
        .on(&plan)
        .await
        .unwrap();
    let operand = JsonTreeQuery::try_from(&query).unwrap();
    assert_eq!(
        serde_json::to_value(&operand).unwrap(),
        serde_json::to_value(&query).unwrap()
    );
    assert_eq!(operand.el.len(), 1);

    let bound = cipher
        .query(op::AtPath(op::Gte), &("$.number", 1))
        .on(&plan)
        .await
        .unwrap();
    let leaf = JsonTreeLeafQuery::try_from(&bound).unwrap();
    assert_eq!(
        serde_json::to_value(&leaf).unwrap(),
        serde_json::to_value(&bound).unwrap()
    );
    assert_eq!(leaf.s.0.as_str(), bound.selector().to_string());

    // The engine's document under the label and the EQL document under the
    // identifier carry the same selectors: one context, two spellings.
    let engine = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let typed = seal(&cipher, &fixture()).await;
    assert_eq!(engine.entries().len(), typed.sv.len());
    for (a, b) in engine.entries().iter().zip(&typed.sv) {
        assert_eq!(base64(a.selector()), b.s.0.as_str());
    }
    assert_eq!(
        serde_json::to_value(engine.projection()).unwrap(),
        serde_json::to_value(&typed.q).unwrap(),
        "and the same projection"
    );
    let opened: Value = cipher.open(engine).using(&plan).await.unwrap();
    assert_eq!(opened, fixture());
}

// =============================================================================
// PostgreSQL
// =============================================================================

/// Settle a chain or a pending on the test's runtime: both are
/// `IntoFuture`, not `Future`.
fn wait<F: std::future::IntoFuture>(runtime: &tokio::runtime::Runtime, f: F) -> F::Output {
    runtime.block_on(f.into_future())
}

fn connect() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

/// A small deterministic generator over a few keys and values, so needles
/// drawn from it overlap stored documents often.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn value(&mut self, depth: u32) -> Value {
        match self.below(if depth == 0 { 4 } else { 6 }) {
            0 => json!(self.below(3)),
            1 => json!(["x", "y", "z"][self.below(3) as usize]),
            2 => json!(self.below(2) == 0),
            3 => Value::Null,
            4 => Value::Array((0..self.below(4)).map(|_| self.value(depth - 1)).collect()),
            _ => {
                let mut map = Map::new();
                for _ in 0..self.below(4) {
                    let key = ["a", "b", "c"][self.below(3) as usize].to_owned();
                    let _ = map.insert(key, self.value(depth - 1));
                }
                Value::Object(map)
            }
        }
    }
}

/// The design's corpus (`containment-oracle.sql`), the cross-element cases
/// included, plus random documents.
fn corpus() -> Vec<Value> {
    let mut docs: Vec<Value> = [
        r#"{"a":[{"x":1,"y":5},{"x":7,"y":2}]}"#,
        r#"{"a":[{"x":1,"y":2,"z":3}]}"#,
        r#"{"a":[{"x":1}]}"#,
        r#"{"a":[{"b":[{"x":1},{"y":2}]}]}"#,
        r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
        r#"{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}"#,
        r#"{"a":[{"b":{"c":1,"d":2}},{"b":{"c":3,"d":2}}]}"#,
        r#"{"a":[{"b":{"c":1,"d":5}},{"b":{"c":3,"d":2}}]}"#,
        r#"{"a":[[1,2],[3,4]]}"#,
        r#"{"a":[1,2]}"#,
        r#"{"a":{"b":1}}"#,
        r#"{"a":{}}"#,
        r#"{"a":[1]}"#,
        r#"{"a":1}"#,
        r#"[1,[2]]"#,
        r#"[1,2]"#,
        r#"[1]"#,
        r#"{"a":null}"#,
        r#"{"a":"2"}"#,
        r#"{"a":2}"#,
        r#"["a"]"#,
        r#""a""#,
        r#"[["a"]]"#,
        r#"{"a":[{"t":[{"u":1,"v":2}]},{"t":[{"u":1},{"v":2}]}]}"#,
        r#"{"a":[{"t":[{"u":1},{"v":2}]}]}"#,
        r#"{"a":[{}]}"#,
        r#"{"a":[[]]}"#,
        r#"{}"#,
        r#"[]"#,
        r#"2"#,
        r#"true"#,
        r#"null"#,
    ]
    .iter()
    .map(|text| serde_json::from_str(text).unwrap())
    .collect();
    let mut rng = Lcg(7);
    for _ in 0..40 {
        docs.push(rng.value(3));
    }
    docs
}

/// The needles: the corpus's own documents, plus the design's needles that
/// are not themselves stored.
fn needles() -> Vec<Value> {
    let mut needles = corpus();
    needles.extend(
        [
            r#"{"a":[{"x":1,"y":2}]}"#,
            r#"{"a":[{"x":1},{"x":1}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":4}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3}]}"#,
            r#"{"a":[{"b":{"c":1,"d":2}}]}"#,
            r#"{"a":[[1,4]]}"#,
            r#"{"a":[[1,2]]}"#,
            r#"{"a":[[1],[4]]}"#,
            r#"{"a":[]}"#,
            r#"[2]"#,
            r#"[[2]]"#,
            r#"[1,1,1]"#,
            r#"{"a":2.0}"#,
            r#"2.0"#,
            r#"{"a":[{"t":[{"u":1,"v":2}]}]}"#,
            r#"{"a":["x"]}"#,
        ]
        .iter()
        .map(|text| serde_json::from_str::<Value>(text).unwrap()),
    );
    let mut rng = Lcg(11);
    for _ in 0..40 {
        needles.push(rng.value(2));
    }
    needles
}

/// Needs an EQL v4 installation. Every document of the corpus is stored
/// encrypted beside its plaintext; for every needle, the rows `@>` and `<@`
/// select over the encrypted column are the rows PostgreSQL's own `jsonb`
/// operators select over the plaintext column.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_containment_over_the_encrypted_column_is_jsonb_containment() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let plan = plan();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_docs (id int PRIMARY KEY, plain jsonb NOT NULL, doc public.eql_v4_json_tree NOT NULL);
         CREATE INDEX json_tree_docs_doc ON json_tree_docs USING gin ((eql_v4.json_tree_query(doc)) jsonb_path_ops);",
    )
    .unwrap();

    let docs = corpus();
    for (id, plain) in docs.iter().enumerate() {
        let stored = wait(&runtime, seal(&cipher, plain));
        let stored = serde_json::to_string(&stored).unwrap();
        db.execute(
            "INSERT INTO json_tree_docs VALUES ($1, $2::text::jsonb, $3::text::jsonb::public.eql_v4_json_tree)",
            &[&(id as i32), &plain.to_string(), &stored],
        )
        .unwrap();
    }

    let ids = |db: &mut postgres::Client, sql: &str, param: &str| -> Vec<i32> {
        db.query(sql, &[&param])
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .iter()
            .map(|r| r.get(0))
            .collect()
    };
    let mut checked = 0;
    for needle in needles() {
        let query = wait(&runtime, cipher.query(op::Contains, &needle).on(&plan)).unwrap();
        let operand = serde_json::to_string(&JsonTreeQuery::try_from(&query).unwrap()).unwrap();
        let plain = needle.to_string();
        let expected = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE plain @> $1::text::jsonb ORDER BY id",
            &plain,
        );
        let encrypted = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree ORDER BY id",
            &operand,
        );
        assert_eq!(encrypted, expected, "@> {needle}");
        let function_form = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE eql_v4.json_tree_contains(doc, $1::text::jsonb::eql_v4.query_json_tree) ORDER BY id",
            &operand,
        );
        assert_eq!(function_form, expected, "json_tree_contains {needle}");

        // `<@`: a stored root scalar inside a needle root array is the one
        // case the SQL cannot answer (a stored document carries no `alt`).
        let reverse = wait(&runtime, cipher.query(op::ContainedBy, &needle).on(&plan)).unwrap();
        let reverse = serde_json::to_string(&JsonTreeQuery::try_from(&reverse).unwrap()).unwrap();
        let mut expected = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE plain <@ $1::text::jsonb ORDER BY id",
            &plain,
        );
        if needle.is_array() {
            expected.retain(|id| {
                let stored = &docs[*id as usize];
                stored.is_object() || stored.is_array()
            });
        }
        let encrypted = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE doc <@ $1::text::jsonb::eql_v4.query_json_tree ORDER BY id",
            &reverse,
        );
        assert_eq!(encrypted, expected, "<@ {needle}");
        checked += 1;
    }
    assert!(
        checked > 80,
        "the corpus should hold many needles: {checked}"
    );

    // The GIN index serves `@>`: with sequential scans discouraged, the
    // plan is a bitmap scan over the index.
    db.batch_execute("SET enable_seqscan = off").unwrap();
    let needle = wait(
        &runtime,
        cipher
            .query(op::Contains, &json!({"a": [{"x": 1}]}))
            .on(&plan),
    )
    .unwrap();
    let operand = serde_json::to_string(&JsonTreeQuery::try_from(&needle).unwrap()).unwrap();
    let explain: Vec<String> = db
        .query(
            "EXPLAIN SELECT id FROM json_tree_docs WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree",
            &[&operand],
        )
        .unwrap()
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect();
    let text = explain.join("\n");
    assert!(
        text.contains("Bitmap Index Scan on json_tree_docs_doc"),
        "the GIN index should serve containment:\n{text}"
    );
    db.batch_execute("SET enable_seqscan = on").unwrap();

    // Not STRICT, so inlinable; a NULL on either side is still NULL.
    let nulls = db
        .query_one(
            "SELECT (NULL::public.eql_v4_json_tree @> $1::text::jsonb::eql_v4.query_json_tree) IS NULL
                AND ((SELECT doc FROM json_tree_docs WHERE id = 0) @> NULL::eql_v4.query_json_tree) IS NULL",
            &[&operand],
        )
        .unwrap();
    assert!(nulls.get::<_, bool>(0));
}

/// Needs an EQL v4 installation. Extraction by selector opens to the leaf;
/// the subtree walk by a client-derived token returns exactly the nodes
/// under it and reassembles; the array functions count and list elements;
/// the orderings at a path select the rows the plaintexts say.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_extracts_walks_and_orders_by_path() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_rows (id int PRIMARY KEY, doc public.eql_v4_json_tree NOT NULL)",
    )
    .unwrap();
    let rows = [
        (1, fixture()),
        (
            2,
            json!({"hello": "world-2", "nested": {"deep": "other", "list": []}, "number": 7}),
        ),
        (3, json!({"hello": "aaa", "number": -3, "tags": ["x", "y"]})),
    ];
    for (id, plain) in &rows {
        let stored = wait(&runtime, seal(&cipher, plain));
        let stored = serde_json::to_string(&stored).unwrap();
        db.execute(
            "INSERT INTO json_tree_rows VALUES ($1, $2::text::jsonb::public.eql_v4_json_tree)",
            &[id, &stored],
        )
        .unwrap();
    }
    let selector = |path: &str| {
        wait(
            &runtime,
            keyset.json_selector(&JsonPath::parse(path).unwrap(), column()),
        )
        .unwrap()
        .to_string()
    };
    let subtree_key = |path: &str| {
        wait(
            &runtime,
            keyset.json_subtree_key(
                &JsonPath::parse(path).unwrap(),
                &JsonOptions::default(),
                column(),
            ),
        )
        .unwrap()
    };
    let entry = |row: &postgres::Row| -> JsonTreeEntry {
        serde_json::from_str(&row.get::<_, String>(0)).unwrap()
    };
    let open =
        |e: JsonTreeEntry| -> Value { wait(&runtime, cipher.decrypt_as(e, column())).unwrap() };

    // `->` by selector opens to the leaf; a missing path is NULL.
    let hello = selector("$.hello");
    let row = db
        .query_one(
            "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_rows WHERE id = 2",
            &[&hello],
        )
        .unwrap();
    assert_eq!(open(entry(&row)), json!("world-2"));
    let missing = db
        .query_one(
            "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_rows WHERE id = 3",
            &[&selector("$.nested.deep")],
        )
        .unwrap();
    assert!(missing.get::<_, Option<String>>(0).is_none());
    let exists: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE eql_v4.json_tree_path_exists(doc::jsonb, $1::text) ORDER BY id",
            &[&selector("$.nested.deep")],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(exists, [1, 2]);

    // Every element of an array shares its selector: the path query returns
    // one row per element, each opening to its value.
    let tags: Vec<Value> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_path_query(doc::jsonb, $1::text) e WHERE id = 3",
            &[&selector("$.tags[*]")],
        )
        .unwrap()
        .iter()
        .map(|r| open(entry(r)))
        .collect();
    assert_eq!(tags, vec![json!("x"), json!("y")]);

    // The subtree under `$.nested`, from a token derived on the client from
    // the path alone: six entries in row 1, reassembling the sub-document;
    // two in row 2.
    let nested = subtree_key("$.nested");
    assert!(nested.gates().is_empty(), "a chain head's token");
    for (id, expected) in [
        (1, fixture()["nested"].clone()),
        (2, rows[1].1["nested"].clone()),
    ] {
        let walked: Vec<JsonTreeEntry> = db
            .query(
                "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text) e WHERE id = $2",
                &[&nested.token(), &id],
            )
            .unwrap()
            .iter()
            .map(entry)
            .collect();
        assert_eq!(walked.len(), if id == 1 { 6 } else { 2 });
        assert!(walked
            .iter()
            .all(|e| e.d.is_some() && e.j.is_some() && e.h.is_some()));
        let value: Value = wait(
            &runtime,
            cipher.decrypt_as(JsonTreeSubtree::from_key(&nested, walked), column()),
        )
        .unwrap();
        assert_eq!(value, expected, "row {id}");
    }
    let garbage: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text) e",
            &[&"00".repeat(16)],
        )
        .unwrap()
        .get(0);
    assert_eq!(garbage, 0, "a wrong token unlocks nothing in any row");

    // The budget: past it the walk returns the sealed root alone, at depth
    // 0, and the rows open to the value at the walked path; at it, or
    // with the budget off, the walk is complete; a wrong token still
    // yields nothing under any budget.
    let walked = |db: &mut postgres::Client, budget: i32| -> Vec<JsonTreeEntry> {
        db.query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text, $2::int) e WHERE id = 1",
            &[&nested.token(), &budget],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect()
    };
    assert_eq!(walked(&mut db, 6).len(), 6, "at the budget, the subtree");
    assert_eq!(walked(&mut db, 0).len(), 6, "budget 0 never falls back");
    let root = walked(&mut db, 5);
    assert_eq!(root.len(), 1, "past the budget, the root alone");
    assert_eq!((root[0].j, root[0].d), (Some(0), Some(0)));
    // The key that keyed the walk builds the rows, so the path the
    // fallback is opened at is always there.
    let value: Value = wait(
        &runtime,
        cipher.decrypt_as(JsonTreeSubtree::from_key(&nested, root), column()),
    )
    .unwrap();
    assert_eq!(value, fixture()["nested"]);
    let garbage: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text, 1) e",
            &[&"00".repeat(16)],
        )
        .unwrap()
        .get(0);
    assert_eq!(garbage, 0);
    // The fallback opens to what the walk opens to, as a list too, so a
    // caller's result does not change shape when a document grows past the
    // budget: `$.nested`'s member values from `json_tree_subtree`, whose
    // rows are the head's descendants (its key has no gates), and the list
    // itself from the gated walk to `$.nested.list`, whose rows are the
    // node the gates reach. The key says which.
    let sorted = |mut values: Vec<Value>| {
        values.sort_by_key(ToString::to_string);
        values
    };
    let open_list = |rows: Vec<JsonTreeEntry>, key: &JsonSubtreeKey| -> Vec<Value> {
        wait(
            &runtime,
            cipher.decrypt_as(JsonTreeSubtree::from_key(key, rows), column()),
        )
        .unwrap()
    };
    let walked_members = walked(&mut db, 0);
    assert_eq!(walked_members.len(), 6);
    let fallen_back = walked(&mut db, 5);
    assert_eq!(fallen_back.len(), 1);
    let members = sorted(vec![json!("constant"), json!([{"x": 1}, {"x": 2}])]);
    assert_eq!(sorted(open_list(walked_members, &nested)), members);
    assert_eq!(sorted(open_list(fallen_back, &nested)), members);
    let list = subtree_key("$.nested.list");
    let list_rows = |db: &mut postgres::Client, budget: i32| -> Vec<JsonTreeEntry> {
        db.query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text[], $3::int) e WHERE id = 1",
            &[&list.token(), &list.gates(), &budget],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect()
    };
    let walked_list = list_rows(&mut db, 0);
    assert_eq!(
        walked_list.len(),
        5,
        "the list, its two elements and their x"
    );
    let fallen_back = list_rows(&mut db, 3);
    assert_eq!(fallen_back.len(), 1);
    assert_eq!(
        open_list(walked_list, &list),
        vec![fixture()["nested"]["list"].clone()]
    );
    assert_eq!(
        open_list(fallen_back, &list),
        vec![fixture()["nested"]["list"].clone()]
    );
    // The budget is gated on the header's sealed-root flag, the bit
    // `JsonHeader` writes: with the flags byte cleared, the same document
    // has no root to return and is walked out under any budget.
    let unflagged: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows,
               eql_v4.json_tree_subtree(
                 jsonb_set(doc::jsonb, '{h}', to_jsonb(encode(set_byte(decode(doc::jsonb ->> 'h', 'base64'), 1, 0), 'base64')))::public.eql_v4_json_tree,
                 $1::text, 1) e
             WHERE id = 1",
            &[&nested.token()],
        )
        .unwrap()
        .get(0);
    assert_eq!(unflagged, 6, "an unsealed root is walked out");

    // A path below the head walks from the head's token through one gate
    // per step: `$.nested.list[*].x` is the list's selector, then every
    // element's (the wildcard's), then x's; each `x` comes back as a
    // complete subtree.
    let xs = subtree_key("$.nested.list[*].x");
    assert_eq!(xs.token(), nested.token(), "anchored at the head");
    assert_eq!(xs.gates().len(), 3);
    let walked: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text[]) e WHERE id = 1",
            &[&xs.token(), &xs.gates()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    let values: Vec<Value> = wait(
        &runtime,
        cipher.decrypt_as(JsonTreeSubtree::from_key(&xs, walked), column()),
    )
    .unwrap();
    assert_eq!(values, vec![json!(1), json!(2)]);
    // Past the budget, the gated walk falls back the same way, and the
    // wildcard path selects every subtree over the whole document.
    let root: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text[], 1) e WHERE id = 1",
            &[&xs.token(), &xs.gates()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    assert_eq!(root.len(), 1);
    assert_eq!(root[0].d, Some(0));
    let values: Vec<Value> = wait(
        &runtime,
        cipher.decrypt_as(JsonTreeSubtree::from_key(&xs, root), column()),
    )
    .unwrap();
    assert_eq!(values, vec![json!(1), json!(2)]);

    // A positional path below a key step: the second element's subtree,
    // through the list's selector and the position `#1`, with the selector
    // every element of the list carries.
    let second = subtree_key("$.nested.list[1]");
    assert_eq!(
        second.gates()[1],
        format!("#1:{}", selector("$.nested.list[*]"))
    );
    let walked: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text[]) e WHERE id = 1",
            &[&second.token(), &second.gates()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    let value: Value = wait(
        &runtime,
        cipher.decrypt_as(JsonTreeSubtree::from_key(&second, walked), column()),
    )
    .unwrap();
    assert_eq!(value, json!({"x": 2}));

    // The array functions, by the head's token and the list's gate.
    let list = subtree_key("$.nested.list");
    assert_eq!(list.gates().len(), 1);
    let counts: Vec<(i32, i32)> = db
        .query(
            "SELECT id, eql_v4.json_tree_child_count(doc, $1::text, $2::text[]) FROM json_tree_rows ORDER BY id",
            &[&list.token(), &list.gates()],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(counts, [(1, 2), (2, 0), (3, 0)]);
    let elements: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_children(doc, $1::text, $2::text[]) e WHERE id = 1",
            &[&list.token(), &list.gates()],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    assert_eq!(elements.len(), 2);
    assert_eq!(
        elements.iter().map(|e| (e.j, e.d)).collect::<Vec<_>>(),
        [(Some(5), Some(1)), (Some(7), Some(1))]
    );
    // The head's own children, with no gate: deep and list.
    let members: i32 = db
        .query_one(
            "SELECT eql_v4.json_tree_child_count(doc, $1::text) FROM json_tree_rows WHERE id = 1",
            &[&nested.token()],
        )
        .unwrap()
        .get(0);
    assert_eq!(members, 2);

    // Orderings at a path: the rows whose `$.number` is in range, and
    // sorted by the leaf's term.
    let at_least_one = wait(
        &runtime,
        cipher
            .query(op::AtPath(op::Gte), &("$.number", 1))
            .on(&plan),
    )
    .unwrap();
    let at_least_one =
        serde_json::to_string(&JsonTreeLeafQuery::try_from(&at_least_one).unwrap()).unwrap();
    let number = selector("$.number");
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_tree_leaf ORDER BY id",
            &[&number, &at_least_one],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [1, 2]);
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE (doc -> $1::text) < $2::text::jsonb::eql_v4.query_json_tree_leaf ORDER BY id",
            &[&number, &at_least_one],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [3]);
    let sorted: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows ORDER BY eql_v4.ord_term(doc -> $1::text), id",
            &[&number],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(sorted, [3, 1, 2], "-3, 1, 7");
    let text = selector("$.hello");
    let sorted: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows ORDER BY eql_v4.ord_term(doc -> $1::text), id",
            &[&text],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(sorted, [3, 1, 2], "aaa, world-1, world-2");

    // An ordering operand that lost its `query_json_tree_leaf` cast is plain
    // jsonb, and every comparison of an entry with plain jsonb raises,
    // either way round, instead of comparing the entry's ciphertext.
    for op in ["<", "<=", ">", ">=", "=", "<>"] {
        for sql in [
            format!("SELECT id FROM json_tree_rows WHERE (doc -> $1::text) {op} $2::text::jsonb"),
            format!("SELECT id FROM json_tree_rows WHERE $2::text::jsonb {op} (doc -> $1::text)"),
        ] {
            match db.query(&sql, &[&number, &at_least_one]) {
                Ok(rows) => panic!("{sql} must be blocked, but returned {} rows", rows.len()),
                Err(error) => {
                    let message = error
                        .as_db_error()
                        .map(|e| e.message().to_owned())
                        .unwrap_or_else(|| error.to_string());
                    assert!(
                        message.contains(&format!(
                            "operator {op} is not supported for public.eql_v4_json_tree_entry"
                        )),
                        "{sql}: {message}"
                    );
                }
            }
        }
    }

    // The native jsonb operators are blocked on the column. The operand is
    // typed, as every EQL jsonb domain requires: an untyped literal resolves
    // to the native operator on the base type.
    match db.query("SELECT doc ? 'hello'::text FROM json_tree_rows", &[]) {
        Ok(rows) => panic!(
            "native `?` must be blocked, but returned {} rows",
            rows.len()
        ),
        Err(error) => {
            let message = error
                .as_db_error()
                .map(|e| e.message().to_owned())
                .unwrap_or_else(|| error.to_string());
            assert!(
                message.contains("operator ? is not supported for public.eql_v4_json_tree"),
                "native `?` must be blocked: {message}"
            );
        }
    }
}

/// A document of the flat shape: four nodes, under PostgreSQL's TOAST
/// threshold, so the row sits inline in the heap.
fn flat_document(i: i64) -> Value {
    json!({"number": i, "hello": format!("h{}", i % 17), "flag": i % 2 == 0})
}

/// A document of the nested shape: about 220 nodes, well over the TOAST
/// threshold, so the heap holds a pointer and the document sits in the
/// TOAST relation.
fn nested_document(i: i64) -> Value {
    let orders: Vec<Value> = (0..12)
        .map(|k| {
            let items: Vec<Value> = (0..5)
                .map(|m| json!({"sku": format!("s{}", (i + k + m) % 23), "qty": m + 1, "gift": m == 0}))
                .collect();
            json!({"id": i * 100 + k, "total": (i + k) % 997, "items": items})
        })
        .collect();
    json!({"number": i, "hello": format!("h{}", i % 17), "orders": orders})
}

/// Needs an EQL v4 installation. The planner chooses the indexes on its
/// own, with every setting at its default, on both shapes a stored
/// document takes: inline (a small document, under the TOAST threshold)
/// and TOASTed (a large one, where the heap holds a pointer and a
/// sequential scan looks cheap by page count). `json_tree_query` is
/// plpgsql with `COST 1000` for exactly that reason: the planner cannot
/// see that evaluating it detoasts the row, so its cost has to say so.
/// The oracle test above shows the GIN index with sequential scans turned
/// off; this one shows it with them on, which is what a customer's
/// database runs. The ordering path is held the same way: a functional
/// btree on `ord_term(doc -> selector)` serves a range at a path. Both
/// are asked three times: as one-shot statements, planned with their
/// operands in view; as a prepared statement executed past its fifth run,
/// where `plan_cache_mode = auto` may plan once for any operand; and as
/// the same statement under `plan_cache_mode = force_generic_plan`, since
/// `auto` keeps a custom plan whenever it costs less than the generic one
/// and would otherwise leave the generic plan untested.
///
/// The last block is a control: with the function's cost set to the
/// minimum for one transaction, the planner prefers the sequential scan
/// on the TOASTed table, which is what the assertion above guards
/// against. Read it as "the assertion can fail", not as a target.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_planner_picks_the_indexes_without_help() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let plan = plan();
    let mut db = connect();

    let version: i32 = db
        .query_one("SHOW server_version_num", &[])
        .unwrap()
        .get::<_, String>(0)
        .parse()
        .unwrap();

    // The operands: a containment needle per shape, and one range bound at
    // `$.number`, whose selector the functional index is built on.
    let bound = wait(
        &runtime,
        cipher
            .query(op::AtPath(op::Gte), &("$.number", 1))
            .on(&plan),
    )
    .unwrap();
    let number = bound.selector().to_string();
    let leaf = |value: i64| {
        let query = wait(
            &runtime,
            cipher
                .query(op::AtPath(op::Gte), &("$.number", value))
                .on(&plan),
        )
        .unwrap();
        serde_json::to_string(&JsonTreeLeafQuery::try_from(&query).unwrap()).unwrap()
    };
    let needle = |value: Value| {
        let query = wait(&runtime, cipher.query(op::Contains, &value).on(&plan)).unwrap();
        serde_json::to_string(&JsonTreeQuery::try_from(&query).unwrap()).unwrap()
    };

    let explain =
        |db: &mut postgres::Client, sql: &str, params: &[&(dyn postgres::types::ToSql + Sync)]| {
            db.query(&format!("EXPLAIN {sql}"), params)
                .unwrap_or_else(|e| panic!("{sql}: {e}"))
                .iter()
                .map(|r| r.get::<_, String>(0))
                .collect::<Vec<_>>()
                .join("\n")
        };

    struct Shape {
        name: &'static str,
        rows: i64,
        document: fn(i64) -> Value,
        needle: Value,
        inline: bool,
    }
    let shapes = [
        Shape {
            name: "flat",
            rows: 1000,
            document: flat_document,
            needle: json!({"hello": "h3"}),
            inline: true,
        },
        Shape {
            name: "nested",
            rows: 300,
            document: nested_document,
            needle: json!({"orders": [{"items": [{"sku": "s7", "gift": true}]}]}),
            inline: false,
        },
    ];

    for shape in &shapes {
        let table = format!("json_tree_plan_{}", shape.name);
        db.batch_execute(&format!(
            "CREATE TEMP TABLE {table} (id int PRIMARY KEY, doc public.eql_v4_json_tree NOT NULL);
             CREATE INDEX {table}_gin ON {table} USING gin ((eql_v4.json_tree_query(doc)) jsonb_path_ops);
             CREATE INDEX {table}_ord ON {table} (eql_v4.ord_term(doc -> '{number}'::text));"
        ))
        .unwrap();
        for i in 0..shape.rows {
            let stored = wait(&runtime, seal(&cipher, &(shape.document)(i)));
            let stored = serde_json::to_string(&stored).unwrap();
            db.execute(
                &format!(
                    "INSERT INTO {table} VALUES ($1, $2::text::jsonb::public.eql_v4_json_tree)"
                ),
                &[&(i as i32), &stored],
            )
            .unwrap();
        }
        db.batch_execute(&format!("ANALYZE {table}")).unwrap();

        // The two storage regimes the shapes stand for, pinned, so the test
        // keeps meaning when a document's size changes. Read from the TOAST
        // relation itself: a value stored out of line is one `chunk_id`
        // there, so the count of distinct chunk ids is the count of
        // TOASTed rows, on every supported version (`pg_column_toast_chunk_id`
        // is PostgreSQL 17 only, and `pg_column_size` reports the stored
        // size, which says nothing about where it is stored).
        let (column, toasted): (i32, i64) = {
            let column: i32 = db
                .query_one(
                    &format!("SELECT avg(pg_column_size(doc))::int FROM {table}"),
                    &[],
                )
                .unwrap()
                .get(0);
            let toast: String = db
                .query_one(
                    "SELECT reltoastrelid::regclass::text FROM pg_class WHERE oid = $1::text::regclass",
                    &[&table],
                )
                .unwrap()
                .get(0);
            let toasted: i64 = db
                .query_one(
                    &format!("SELECT count(DISTINCT chunk_id) FROM {toast}"),
                    &[],
                )
                .unwrap()
                .get(0);
            (column, toasted)
        };
        if shape.inline {
            assert_eq!(
                toasted, 0,
                "{}: every row inline, {column} bytes on average",
                shape.name
            );
        } else {
            assert_eq!(
                toasted, shape.rows,
                "{}: every row TOASTed, {column} bytes on average",
                shape.name
            );
        }

        // Containment: a bitmap scan over the GIN index, on its own.
        let operand = needle(shape.needle.clone());
        let text = explain(
            &mut db,
            &format!("SELECT id FROM {table} WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree"),
            &[&operand],
        );
        assert!(
            text.contains(&format!("Bitmap Index Scan on {table}_gin")),
            "{} on PostgreSQL {version}: containment should use the GIN index without help:\n{text}",
            shape.name
        );
        let matched: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree"),
                &[&operand],
            )
            .unwrap()
            .get(0);
        assert!(
            matched > 0,
            "{}: the needle should match some rows",
            shape.name
        );

        // A range at the ordered path: the functional btree.
        let operand = leaf(shape.rows - 5);
        let text = explain(
            &mut db,
            &format!("SELECT id FROM {table} WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_tree_leaf"),
            &[&number, &operand],
        );
        assert!(
            text.contains(&format!("Index Scan using {table}_ord"))
                || text.contains(&format!("Bitmap Index Scan on {table}_ord")),
            "{} on PostgreSQL {version}: a range at an ordered path should use the btree without help:\n{text}",
            shape.name
        );
        let matched: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_tree_leaf"),
                &[&number, &operand],
            )
            .unwrap()
            .get(0);
        assert_eq!(matched, 5, "{}: the top five numbers", shape.name);

        // The same two queries as a pooled driver runs them: one prepared
        // statement, executed past the five custom plans after which
        // `plan_cache_mode = auto` may switch to a generic plan, whose
        // operand is a parameter the planner cannot see. The selector stays
        // a literal, as it has to for the functional index to match.
        // `EXPLAIN EXECUTE` shows the plan the cache would run next. Under
        // `auto` that may still be a custom plan (the cache keeps one while
        // it costs less than the generic plan), so each statement is then
        // explained again under `force_generic_plan`, which is the plan a
        // pooled driver can reach whatever the costs say.
        let containment = needle(shape.needle.clone());
        let range = leaf(shape.rows - 5);
        for literal in [&containment, &range] {
            assert!(!literal.contains('\''), "an operand embeds as a literal");
        }
        db.batch_execute(&format!(
            "PREPARE {table}_contains(text) AS
               SELECT id FROM {table} WHERE doc @> $1::jsonb::eql_v4.query_json_tree;
             PREPARE {table}_range(text) AS
               SELECT id FROM {table} WHERE (doc -> '{number}'::text) >= $1::jsonb::eql_v4.query_json_tree_leaf;"
        ))
        .unwrap();
        for (statement, operand, index, what) in [
            ("contains", &containment, "_gin", "containment"),
            ("range", &range, "_ord", "a range at an ordered path"),
        ] {
            for _ in 0..6 {
                db.batch_execute(&format!("EXECUTE {table}_{statement}('{operand}')"))
                    .unwrap();
            }
            let explain_execute = |db: &mut postgres::Client| {
                db.simple_query(&format!("EXPLAIN EXECUTE {table}_{statement}('{operand}')"))
                    .unwrap()
                    .into_iter()
                    .filter_map(|message| match message {
                        postgres::SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let uses_index = |text: &str| {
                text.contains(&format!("Index Scan using {table}{index}"))
                    || text.contains(&format!("Bitmap Index Scan on {table}{index}"))
            };
            let text = explain_execute(&mut db);
            assert!(
                uses_index(&text),
                "{} on PostgreSQL {version}: {what} from a prepared statement past its fifth execution should use the index:\n{text}",
                shape.name
            );
            db.batch_execute("SET plan_cache_mode = force_generic_plan")
                .unwrap();
            let text = explain_execute(&mut db);
            db.batch_execute("RESET plan_cache_mode").unwrap();
            assert!(
                text.contains("$1"),
                "{} on PostgreSQL {version}: {what} under force_generic_plan should be planned with its operand as a parameter:\n{text}",
                shape.name
            );
            assert!(
                uses_index(&text),
                "{} on PostgreSQL {version}: {what} from a prepared statement's generic plan should use the index:\n{text}",
                shape.name
            );
        }
    }

    // The control: with `json_tree_query` priced as if it were free, the
    // planner takes the sequential scan over the TOASTed table.
    let mut tx = db.transaction().unwrap();
    tx.batch_execute("ALTER FUNCTION eql_v4.json_tree_query(public.eql_v4_json_tree) COST 1")
        .unwrap();
    let operand = needle(shapes[1].needle.clone());
    let text = tx
        .query(
            "EXPLAIN SELECT id FROM json_tree_plan_nested WHERE doc @> $1::text::jsonb::eql_v4.query_json_tree",
            &[&operand],
        )
        .unwrap()
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    tx.rollback().unwrap();
    assert!(
        text.contains("Seq Scan on json_tree_plan_nested"),
        "on PostgreSQL {version}, with the function priced as free the planner should take the sequential scan, which is what the cost guards against:\n{text}"
    );
}

/// Needs an EQL v4 installation. A position names an array element and
/// nothing else, in every row of the column, as a strict SQL/JSON path does
/// (`jsonb_path_query_first(plain, 'strict $.a[1]')`): where a
/// row's node at the path is an object, an object member ranked at that
/// ordinal is not returned, whether the client derived the position's
/// token (`$.a[1]`, directly after the head) or the walk took it as a gate
/// (`$.h.a[0]`, below a key step). Each walk's rows open to the plaintext's
/// value at the strict path, or come back empty where it has none. (`#>`
/// would not do as the oracle: it reads `1` as a key of an object.)
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_position_reaches_array_elements_only() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_positions (id int PRIMARY KEY, plain jsonb NOT NULL, doc public.eql_v4_json_tree NOT NULL)",
    )
    .unwrap();
    let rows = [
        json!({"a": [{"x": 1}, {"x": 2}], "h": {"a": [{"x": 3}, {"x": 4}]}}),
        json!({"a": {"k": {"x": 9}, "m": {"x": 6}}, "h": {"a": {"k": {"x": 8}, "m": {"x": 5}}}}),
        json!({"a": {"0": {"x": 7}, "1": {"x": 7}}, "h": {"a": {"0": {"x": 7}}}}),
    ];
    for (id, plain) in (1..).zip(&rows) {
        let stored = wait(&runtime, seal(&cipher, plain));
        let stored = serde_json::to_string(&stored).unwrap();
        db.execute(
            "INSERT INTO json_tree_positions VALUES ($1, $2::text::jsonb, $3::text::jsonb::public.eql_v4_json_tree)",
            &[&id, &plain.to_string(), &stored],
        )
        .unwrap();
    }
    for path in ["$.a[1]", "$.h.a[0]"] {
        let key = wait(
            &runtime,
            keyset.json_subtree_key(&JsonPath::parse(path).unwrap(), &options(), column()),
        )
        .unwrap();
        for id in 1..=3 {
            let walked: Vec<JsonTreeEntry> = db
                .query(
                    "SELECT e::jsonb::text FROM json_tree_positions, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text[], 0) e WHERE id = $3",
                    &[&key.token(), &key.gates(), &id],
                )
                .unwrap()
                .iter()
                .map(|r| serde_json::from_str(&r.get::<_, String>(0)).unwrap())
                .collect();
            let expected: Option<String> = db
                .query_one(
                    "SELECT jsonb_path_query_first(plain, ('strict ' || $1::text)::jsonpath, '{}', true)::text FROM json_tree_positions WHERE id = $2",
                    &[&path, &id],
                )
                .unwrap()
                .get(0);
            match expected {
                None => assert!(walked.is_empty(), "{path}, row {id}: jsonb has no node"),
                Some(expected) => {
                    let value: Value = wait(
                        &runtime,
                        cipher.decrypt_as(JsonTreeSubtree::from_key(&key, walked), column()),
                    )
                    .unwrap();
                    assert_eq!(
                        value,
                        serde_json::from_str::<Value>(&expected).unwrap(),
                        "{path}, row {id}"
                    );
                }
            }
        }
    }
    // A position gate that does not name the elements' selector admits
    // nothing: an ordinal alone cannot tell an element from a member.
    let key = wait(
        &runtime,
        keyset.json_subtree_key(&JsonPath::parse("$.h.a[0]").unwrap(), &options(), column()),
    )
    .unwrap();
    let bare = [key.gates()[0].clone(), "#0".to_owned()];
    let none: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_positions, eql_v4.json_tree_subtree_at(doc, $1::text, $2::text[], 0) e",
            &[&key.token(), &bare.as_slice()],
        )
        .unwrap()
        .get(0);
    assert_eq!(none, 0);
    let counts: Vec<(i32, i32)> = db
        .query(
            "SELECT id, eql_v4.json_tree_child_count(doc, $1::text, $2::text[]) FROM json_tree_positions ORDER BY id",
            &[&key.token(), &key.gates()],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(
        counts,
        [(1, 1), (2, 0), (3, 0)],
        "one member, x, under $.h.a[0] in row 1 only"
    );
}

/// Needs an EQL v4 installation. A stored document is untrusted input: its
/// parent tags are not authenticated, so whoever holds a token can write a
/// chain of them deeper than any sealed document. A child's token is a
/// hash of its parent's, so the chain cannot loop back, and the walk, which
/// carries no depth bound, still ends after one row per entry: here a chain
/// of 300, past the 127 levels a sealed document can nest.
/// `statement_timeout` turns a walk that would not end into a failure
/// instead of a hung suite.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_walks_end_on_hostile_documents() {
    let mut db = connect();
    db.batch_execute("SET statement_timeout = '10s'").unwrap();
    // A root, then 300 entries each the only child of the one before, under
    // the all-zero token. `flags` is the header's flags byte, so the same
    // document is built with its root sealed and not.
    let chain = |flags: i32| {
        format!(
            "WITH RECURSIVE k AS (
               SELECT set_byte(set_byte(decode(repeat('00', 40), 'hex'), 0, 1), 1, {flags}) AS h,
                      decode(repeat('00', 16), 'hex') AS iv
             ), link(n, t) AS (
                 SELECT 0, decode(repeat('00', 16), 'hex')
               UNION ALL
                 SELECT n + 1, eql_v4_internal.json_tree_child_token(t, decode(repeat('00', 16), 'hex'), 0) FROM link WHERE n < 299
             )
             SELECT (jsonb_build_object(
               'v', 4, 'i', jsonb_build_object('t', 'users', 'c', 'profile'),
               'h', (SELECT encode(h, 'base64') FROM k),
               'sv', jsonb_build_array(jsonb_build_object('s', 'AAAAAAAAAAAAAAAAAAAAAA==', 'c', '00'))
                     || (SELECT jsonb_agg(jsonb_build_object('s', 'AAAAAAAAAAAAAAAAAAAAAA==', 'c', '00', 'p', eql_v4_internal.json_tree_parent_tag(k.iv, link.t, 0)) ORDER BY n) FROM link, k),
               'q', '{{\"sv\": [], \"el\": []}}'::jsonb))::public.eql_v4_json_tree"
        )
    };
    let token = "AAAAAAAAAAAAAAAAAAAAAA==".to_owned();
    for (flags, budget, expected) in [(0, 0, 300), (0, 64, 300), (1, 0, 300), (1, 64, 1)] {
        let doc = chain(flags);
        let walked: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_subtree(d.doc, $1::text, {budget}) e"),
                &[&token],
            )
            .unwrap_or_else(|error| panic!("flags {flags}, budget {budget}: {error}"))
            .get(0);
        assert_eq!(walked, expected, "flags {flags}, budget {budget}");
        let children: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_children(d.doc, $1::text) e"),
                &[&token],
            )
            .unwrap()
            .get(0);
        assert_eq!(children, 1);
    }
}

/// Needs an EQL v4 installation. Entries that share a parent tag do not
/// multiply a walk. Here every level of a 60-level chain is written twice:
/// two entries with the same `p`, so the same parent and ordinal, and the
/// same `s`, told apart only by `c`. Walked once per copy, the rows would
/// double at every level, 2^60 in all; the walk keeps one entry per tag and
/// reads its recursion through the entry count, so it returns one row per
/// level, under no budget (`0`), under an open root, and under a budget
/// above the entry count, and still falls back past a budget below it.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_walks_do_not_multiply_on_duplicated_entries() {
    let mut db = connect();
    db.batch_execute("SET statement_timeout = '10s'").unwrap();
    const LEVELS: i64 = 60;
    let doc = |flags: i32| {
        format!(
            "WITH RECURSIVE k AS (
               SELECT set_byte(set_byte(decode(repeat('00', 40), 'hex'), 0, 1), 1, {flags}) AS h,
                      decode(repeat('00', 16), 'hex') AS iv
             ), link(n, t) AS (
                 SELECT 0, decode(repeat('00', 16), 'hex')
               UNION ALL
                 SELECT n + 1, eql_v4_internal.json_tree_child_token(t, decode(repeat('00', 16), 'hex'), 0) FROM link WHERE n < {last}
             ), copy(c) AS (VALUES ('00'), ('01'))
             SELECT (jsonb_build_object(
               'v', 4, 'i', jsonb_build_object('t', 'users', 'c', 'profile'),
               'h', (SELECT encode(h, 'base64') FROM k),
               'sv', jsonb_build_array(jsonb_build_object('s', 'AAAAAAAAAAAAAAAAAAAAAA==', 'c', '00'))
                     || (SELECT jsonb_agg(jsonb_build_object('s', 'AAAAAAAAAAAAAAAAAAAAAA==', 'c', copy.c, 'p', eql_v4_internal.json_tree_parent_tag(k.iv, link.t, 0)) ORDER BY n, copy.c) FROM link, k, copy),
               'q', '{{\"sv\": [], \"el\": []}}'::jsonb))::public.eql_v4_json_tree",
            last = LEVELS - 1
        )
    };
    let token = "AAAAAAAAAAAAAAAAAAAAAA==".to_owned();
    let entries = 1 + 2 * LEVELS;
    for (flags, budget, expected) in [
        (0, 0, LEVELS),
        (1, 0, LEVELS),
        (0, 10, LEVELS),
        (1, 200, LEVELS),
        (1, 10, 1),
    ] {
        let doc = doc(flags);
        let stored: i64 = db
            .query_one(
                &format!("SELECT jsonb_array_length(d.doc::jsonb -> 'sv')::bigint FROM ({doc}) AS d(doc)"),
                &[],
            )
            .unwrap()
            .get(0);
        assert_eq!(stored, entries);
        let walked: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_subtree(d.doc, $1::text, {budget}) e"),
                &[&token],
            )
            .unwrap_or_else(|error| panic!("flags {flags}, budget {budget}: {error}"))
            .get(0);
        assert_eq!(walked, expected, "flags {flags}, budget {budget}");
        assert!(walked <= entries);
        let children: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_children(d.doc, $1::text) e"),
                &[&token],
            )
            .unwrap()
            .get(0);
        assert_eq!(children, 1, "flags {flags}");
    }
}
