//! The JSON tree family end to end: a document sealed by Stack Encrypt's
//! JSON index into `public.eql_v4_json_search`, queried with the v4 SQL, and
//! opened again. A document seals and opens through the EQL types
//! (`JsonTreeDocument`, `JsonTreeExtracted`, `JsonTreeSubtree`), as a
//! `JsonPlaintext`. A query's operand derives through a data plan that
//! names the type `JsonSearch` under the same column and options
//! ([`contains`], [`contained_by`], [`gte_at`]), the path a language SDK
//! takes. A record field's reference derives the same operands
//! (`tests/json_tree_field_references.rs`). The unit tests need no database; the PostgreSQL test
//! installs nothing itself (`mise run test:encryption:postgres` installs the
//! v4 bundle built from the tree) and is the oracle the design asks for:
//! `@>` and `<@` over the encrypted column against PostgreSQL's own
//! `jsonb @>` over the plaintexts, for the design's corpus and random
//! documents, with a GIN index on the projection that the planner is shown
//! to use, and again as proptest properties over generated batches of
//! documents and needles (`json_tree/generated.rs`; `PROPTEST_RNG_SEED`
//! replays a run).

mod common;

use eql_bindings::encryption::EqlTargets;
use eql_bindings::v4::json_tree::{
    JsonTree, JsonTreeChild, JsonTreeDocument, JsonTreeEntry, JsonTreeExtracted, JsonTreeLeafQuery,
    JsonTreeQuery, JsonTreeSubtree,
};
use eql_bindings::Identifier;
use serde_json::{json, Map, Value};
use stack_encrypt::dynamic::{self, record, Op, Operand, ValueFrame};
use stack_encrypt::json::{
    JsonChildPlaintext, JsonDocument, JsonLeafQuery, JsonOptions, JsonPath, JsonPlaintext,
    JsonQuery, JsonSelector, JsonSubtreeKey, Segment,
};
use stack_encrypt::target::{json_document, Borrowed, CallerContext};
use stack_encrypt::{AsProtectedRef as _, DecryptFrom, Label, NonEmpty};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

type Cipher = stack_encrypt::StackCipher<common::RecordingKeySource>;

/// Seal `value` as the EQL type under the identifier, laid out by the
/// `json_tree` layout with the same ordered paths as [`plan`].
async fn seal(cipher: &Cipher, value: &Value) -> JsonTreeDocument {
    cipher
        .default_keyset()
        .run(JsonTree::new(options()).encryption(), value, column())
        .await
        .unwrap()
}

/// The paths that carry ordering terms: `$.hello` and `$.number`, the
/// paths the ordering queries below ask at. [`options`] seals under them,
/// and [`plan`] names them, so a query derives under the options its
/// document was sealed under.
const ORDERED: [&str; 2] = ["$.hello", "$.number"];

/// The plan a query derives through: a data plan with one `json` field,
/// `profile`, that names the EQL type `JsonSearch` under `users/profile`.
/// That context is the identifier [`seal`] stores (the same two parts), so
/// a query's selectors are the stored document's. A document sealed on its
/// own, with no record, has no field reference, so it is queried through a data
/// plan, as a language SDK queries one.
fn plan() -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "target": {"name": "JsonSearch", "options": {"ordered": ORDERED}}
        }
    });
    record::plan_with(
        dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap()
}

/// The index options the corpus is sealed under: the [`ORDERED`] paths
/// carry ordering terms.
fn options() -> JsonOptions {
    JsonOptions::default().ordering(ORDERED).unwrap()
}

/// The operand of one JSON operator on [`plan`]'s field, with the named
/// inputs a binding sends: the bytes the SQL binds.
async fn operand(cipher: &Cipher, operator: Op, inputs: Value) -> Vec<u8> {
    let inputs = ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(&inputs)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap();
    let term = dynamic::query_term(
        &cipher.default_keyset(),
        &plan(),
        "profile",
        operator,
        inputs,
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap();
    let Operand::One(bytes) = term.operand() else {
        panic!("{}: one operand", term.operator());
    };
    bytes.clone()
}

/// The needle of `col @> needle`: the `eql_v4.query_json` operand.
async fn contains(cipher: &Cipher, needle: &Value) -> JsonTreeQuery {
    let bytes = operand(cipher, Op::Contains, json!({"json": needle.to_string()})).await;
    serde_json::from_slice(&bytes).unwrap()
}

/// The needle of `col <@ needle`: the `eql_v4.query_json` operand.
async fn contained_by(cipher: &Cipher, needle: &Value) -> JsonTreeQuery {
    let bytes = operand(cipher, Op::ContainedBy, json!({"json": needle.to_string()})).await;
    serde_json::from_slice(&bytes).unwrap()
}

/// The bound of `(col -> selector) >= bound` at `path`: the
/// `eql_v4.query_json_leaf` operand.
async fn gte_at(cipher: &Cipher, path: &str, value: Value) -> JsonTreeLeafQuery {
    let bytes = operand(
        cipher,
        Op::GteAt,
        json!({"path": path, "json": value.to_string()}),
    )
    .await;
    serde_json::from_slice(&bytes).unwrap()
}

/// The scalar an extracted entry opens to under the column, through the
/// selector that asked for it.
async fn extract(
    cipher: &Cipher,
    asked: &JsonSelector,
    entry: JsonTreeEntry,
) -> Result<Value, stack_encrypt::Error> {
    JsonPlaintext::decrypt_from_with_context(
        JsonTreeExtracted::from_selector(asked, entry),
        cipher,
        column(),
    )
    .await
    .map(|opened| opened.value().clone())
}

/// The value the rows of a read open to under the column, through the key
/// that keyed the read. No node at the path is an error.
async fn read_one(
    cipher: &Cipher,
    key: &JsonSubtreeKey,
    rows: Vec<JsonTreeEntry>,
) -> Result<Value, stack_encrypt::Error> {
    JsonPlaintext::decrypt_from_with_context(JsonTreeSubtree::from_key(key, rows), cipher, column())
        .await
        .map(|opened| opened.value().clone())
}

/// [`read_one`], with `None` where the row has no node at the path.
async fn read_optional(
    cipher: &Cipher,
    key: &JsonSubtreeKey,
    rows: Vec<JsonTreeEntry>,
) -> Result<Option<Value>, stack_encrypt::Error> {
    Option::<JsonPlaintext>::decrypt_from_with_context(
        JsonTreeSubtree::from_key(key, rows),
        cipher,
        column(),
    )
    .await
    .map(|opened| opened.map(|value| value.value().clone()))
}

/// The rows of a read as a list: one value per concrete path the key named
/// that the row has.
async fn read_list(
    cipher: &Cipher,
    key: &JsonSubtreeKey,
    rows: Vec<JsonTreeEntry>,
) -> Result<Vec<Value>, stack_encrypt::Error> {
    Vec::<JsonPlaintext>::decrypt_from_with_context(
        JsonTreeSubtree::from_key(key, rows),
        cipher,
        column(),
    )
    .await
    .map(|opened| opened.iter().map(|value| value.value().clone()).collect())
}

/// What one entry `json_tree_children` returned opens to under the column,
/// through the key of its parent's path.
async fn open_child(
    cipher: &Cipher,
    parent: &JsonSubtreeKey,
    entry: JsonTreeEntry,
) -> Result<Child, stack_encrypt::Error> {
    JsonChildPlaintext::decrypt_from_with_context(
        JsonTreeChild::from_key(parent, entry),
        cipher,
        column(),
    )
    .await
    .map(|opened| Child::of(&opened))
}

/// An opened child: an object's member by its key, or an array's element
/// by its index, with its value.
#[derive(Clone, Debug, PartialEq)]
enum Child {
    Member(String, Value),
    Element(u64, Value),
}

impl Child {
    fn of(opened: &JsonChildPlaintext) -> Self {
        let value = opened.value().clone();
        match (opened.key(), opened.index()) {
            (Some(key), None) => Child::Member(key.to_owned(), value),
            (None, Some(index)) => Child::Element(index, value),
            other => panic!("a child has a key or an index, not {other:?}"),
        }
    }
}

/// Padded standard base64, as the wire spells a selector.
/// A projection with every list sorted: `q` as the sets `jsonb @>` reads.
fn as_set(q: &Value) -> Value {
    let mut sv = q["sv"].as_array().cloned().unwrap_or_default();
    sv.sort_by_key(|pair| pair.to_string());
    let mut el: Vec<Value> = q["el"]
        .as_array()
        .map(|groups| groups.iter().map(as_set).collect())
        .unwrap_or_default();
    el.sort_by_key(|group| group.to_string());
    json!({"sv": sv, "el": el})
}

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

    let opened = JsonPlaintext::decrypt_from(stored.clone(), &cipher)
        .await
        .unwrap();
    assert_eq!(opened.value(), &fixture());
    let opened = JsonPlaintext::decrypt_from_with_context(stored.clone(), &cipher, column())
        .await
        .unwrap();
    assert_eq!(opened.value(), &fixture());

    let wrong = Identifier::for_column("users", "bio").unwrap();
    let refused = JsonPlaintext::decrypt_from_with_context(stored.clone(), &cipher, wrong).await;
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
    // slot grafted as `->` grafts them, opens to its scalar through the
    // selector that asked for it, and only through that one. The entries
    // are stored in a random order: `$.hello` is the one entry carrying its
    // selector.
    let keyset = cipher.default_keyset();
    let selector = |path: &str| {
        let path = JsonPath::parse(path).unwrap();
        let keyset = keyset.clone();
        async move { keyset.json_selector(&path, column()).await.unwrap() }
    };
    let hello = selector("$.hello").await;
    let at = stored
        .sv
        .iter()
        .position(|e| serde_json::to_value(&e.s).unwrap() == json!(hello.to_string()))
        .expect("the document has $.hello");
    let mut entry = stored.sv[at].clone();
    entry.h = Some(stored.h.clone());
    entry.j = Some(at as u64);
    entry.i = Some(stored.i.clone());
    entry.v = Some(stored.v);
    let scalar = extract(&cipher, &hello, entry.clone()).await.unwrap();
    assert_eq!(scalar, json!("world-1"));
    let asked = JsonTreeExtracted::from_selector(&hello, entry.clone());
    assert_eq!(asked.entry(), &entry);
    assert_eq!(asked.selector(), &hello);
    let number = selector("$.number").await;
    let refused = extract(&cipher, &number, entry).await;
    assert!(
        matches!(
            refused,
            Err(stack_encrypt::Error::JsonWrongEntry {
                expected: "the entry at the path asked for"
            })
        ),
        "another path's selector refuses the entry: {refused:?}"
    );
    let bare = stored.sv[at].clone();
    assert!(extract(&cipher, &hello, bare).await.is_err());
}

/// An entry lifted from the stored document as `json_tree_children` returns
/// it (the header, its slot and depth 1 grafted) opens on its own through
/// the key of its parent's path, and is refused under another parent's.
#[tokio::test]
async fn a_child_opens_through_the_key_of_its_parent() {
    let (cipher, calls) = common::cipher().await;
    let stored = seal(&cipher, &fixture()).await;
    let keyset = cipher.default_keyset();
    let key = |path: &str| {
        let path = JsonPath::parse(path).unwrap();
        let keyset = keyset.clone();
        async move {
            keyset
                .json_subtree_key(&path, &options(), column())
                .await
                .unwrap()
        }
    };
    // `$.nested.deep` is the one entry carrying its selector.
    let deep = keyset
        .json_selector(&JsonPath::parse("$.nested.deep").unwrap(), column())
        .await
        .unwrap();
    let at = stored
        .sv
        .iter()
        .position(|e| serde_json::to_value(&e.s).unwrap() == json!(deep.to_string()))
        .expect("the document has $.nested.deep");
    let mut entry = stored.sv[at].clone();
    entry.h = Some(stored.h.clone());
    entry.j = Some(at as u64);
    entry.d = Some(1);
    entry.i = Some(stored.i.clone());
    entry.v = Some(stored.v);

    let nested = key("$.nested").await;
    let child = JsonTreeChild::from_key(&nested, entry.clone());
    assert_eq!(child.entry(), &entry, "the entry as the server sent it");
    assert_eq!(
        child.parent_path().to_string(),
        "$.nested",
        "the parent it is checked against"
    );
    let opened = open_child(&cipher, &nested, entry.clone()).await.unwrap();
    assert_eq!(
        opened,
        Child::Member("deep".into(), json!("constant")),
        "the child's key and value"
    );

    let hello = key("$.hello").await;
    let refused = open_child(&cipher, &hello, entry.clone()).await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "a child of another node: {refused:?}"
    );
    let retrieved = calls.lock().unwrap().retrieve.len();
    let bare = stored.sv[at].clone();
    assert!(
        open_child(&cipher, &nested, bare).await.is_err(),
        "an entry with no header or slot does not open"
    );
    assert_eq!(
        calls.lock().unwrap().retrieve.len(),
        retrieved,
        "the bare entry retrieved no key"
    );
}

#[tokio::test]
async fn the_query_operands_are_the_engines_terms_in_the_sql_contract() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    // A containment operand is the engine's query term, and reads as the
    // SQL contract's type without changing.
    let bytes = operand(
        &cipher,
        Op::Contains,
        json!({"json": json!({"nested": {"list": [{"x": 2}]}}).to_string()}),
    )
    .await;
    let query: JsonQuery = serde_json::from_slice(&bytes).unwrap();
    let operand_json: Value = serde_json::from_slice(&bytes).unwrap();
    let needle = JsonTreeQuery::try_from(&query).unwrap();
    assert_eq!(
        needle,
        serde_json::from_slice::<JsonTreeQuery>(&bytes).unwrap()
    );
    assert_eq!(serde_json::to_value(&needle).unwrap(), operand_json);
    assert_eq!(needle.el.len(), 1);

    // An ordering operand is the engine's leaf query, the same way.
    let bytes = operand(&cipher, Op::GteAt, json!({"path": "$.number", "json": "1"})).await;
    let bound: JsonLeafQuery = serde_json::from_slice(&bytes).unwrap();
    let leaf = JsonTreeLeafQuery::try_from(&bound).unwrap();
    assert_eq!(
        serde_json::to_value(&leaf).unwrap(),
        serde_json::from_slice::<Value>(&bytes).unwrap()
    );
    assert_eq!(leaf, gte_at(&cipher, "$.number", json!(1)).await);
    assert_eq!(leaf.s.0.as_str(), bound.selector().to_string());

    // The engine's document under the label and the EQL document under the
    // identifier carry the same selectors: one context, two spellings. Each
    // is stored in its own random order, so they compare as multisets, and
    // the projections as the sets `jsonb @>` reads.
    let label: Label = "users/profile".parse().unwrap();
    let engine: JsonDocument = keyset
        .run(
            json_document::<_, Borrowed>(options()),
            &fixture(),
            CallerContext::from(NonEmpty::from(label.clone())),
        )
        .await
        .unwrap();
    let typed = seal(&cipher, &fixture()).await;
    assert_eq!(engine.entries().len(), typed.sv.len());
    let mut a: Vec<String> = engine
        .entries()
        .iter()
        .map(|e| base64(e.selector()))
        .collect();
    let mut b: Vec<String> = typed.sv.iter().map(|e| e.s.0.as_str().to_owned()).collect();
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b, "the same selectors");
    assert_eq!(
        as_set(&serde_json::to_value(engine.selector_set()).unwrap()),
        as_set(&serde_json::to_value(&typed.q).unwrap()),
        "and the same projection"
    );
    // The query finds the document: the needle's set is inside the projection.
    assert!(query.matches(engine.selector_set()));
    let opened = JsonPlaintext::decrypt_from_with_context(engine, &cipher, NonEmpty::from(label))
        .await
        .unwrap();
    assert_eq!(opened.value(), &fixture());
}

// =============================================================================
// PostgreSQL
// =============================================================================

/// Settle a pending or one of the async helpers above on the test's
/// runtime: a pending is `IntoFuture`, not `Future`.
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
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_docs (id int PRIMARY KEY, plain jsonb NOT NULL, doc public.eql_v4_json_search NOT NULL);
         CREATE INDEX json_tree_docs_doc ON json_tree_docs USING gin ((eql_v4.json_tree_query(doc)) jsonb_path_ops);",
    )
    .unwrap();

    let docs = corpus();
    for (id, plain) in docs.iter().enumerate() {
        let stored = wait(&runtime, seal(&cipher, plain));
        let stored = serde_json::to_string(&stored).unwrap();
        db.execute(
            "INSERT INTO json_tree_docs VALUES ($1, $2::text::jsonb, $3::text::jsonb::public.eql_v4_json_search)",
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
        let operand = serde_json::to_string(&wait(&runtime, contains(&cipher, &needle))).unwrap();
        let plain = needle.to_string();
        let expected = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE plain @> $1::text::jsonb ORDER BY id",
            &plain,
        );
        let encrypted = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE doc @> $1::text::jsonb::eql_v4.query_json ORDER BY id",
            &operand,
        );
        assert_eq!(encrypted, expected, "@> {needle}");
        let function_form = ids(
            &mut db,
            "SELECT id FROM json_tree_docs WHERE eql_v4.json_tree_contains(doc, $1::text::jsonb::eql_v4.query_json) ORDER BY id",
            &operand,
        );
        assert_eq!(function_form, expected, "json_tree_contains {needle}");

        // `<@`: a stored root scalar inside a needle root array is the one
        // case the SQL cannot answer (a stored document carries no `alt`).
        let reverse =
            serde_json::to_string(&wait(&runtime, contained_by(&cipher, &needle))).unwrap();
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
            "SELECT id FROM json_tree_docs WHERE doc <@ $1::text::jsonb::eql_v4.query_json ORDER BY id",
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
    let needle = wait(&runtime, contains(&cipher, &json!({"a": [{"x": 1}]})));
    let operand = serde_json::to_string(&needle).unwrap();
    let explain: Vec<String> = db
        .query(
            "EXPLAIN SELECT id FROM json_tree_docs WHERE doc @> $1::text::jsonb::eql_v4.query_json",
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
            "SELECT (NULL::public.eql_v4_json_search @> $1::text::jsonb::eql_v4.query_json) IS NULL
                AND ((SELECT doc FROM json_tree_docs WHERE id = 0) @> NULL::eql_v4.query_json) IS NULL",
            &[&operand],
        )
        .unwrap();
    assert!(nulls.get::<_, bool>(0));
}

// =============================================================================
// PostgreSQL: generated documents
// =============================================================================

/// The containment oracle again, over documents and needles proptest
/// generates. A crate root's modules resolve beside it, and a file there would
/// be a test target of its own, hence the path.
#[allow(clippy::unwrap_used)]
#[path = "json_tree/generated.rs"]
mod generated;

/// Native jsonb functions on a stored document and on an entry read the
/// envelope, and installing EQL leaves them unambiguous on plain jsonb.
#[path = "json_tree/native_functions.rs"]
mod native_functions;

/// The element-scoped predicate, through a data plan, against the column.
#[path = "json_tree/elements.rs"]
mod elements;

/// The compiled predicate, through a data plan, against the column and
/// against `jsonb_path_match` over the plaintexts.
#[path = "json_tree/predicate.rs"]
mod predicate;

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
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_rows (id int PRIMARY KEY, doc public.eql_v4_json_search NOT NULL)",
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
            "INSERT INTO json_tree_rows VALUES ($1, $2::text::jsonb::public.eql_v4_json_search)",
            &[id, &stored],
        )
        .unwrap();
    }
    let selector_of = |path: &str| -> JsonSelector {
        wait(
            &runtime,
            keyset.json_selector(&JsonPath::parse(path).unwrap(), column()),
        )
        .unwrap()
    };
    let selector = |path: &str| selector_of(path).to_string();
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
    let open = |asked: &JsonSelector, e: JsonTreeEntry| -> Value {
        wait(&runtime, extract(&cipher, asked, e)).unwrap()
    };

    // `->` by selector opens to the leaf; a missing path is NULL.
    let hello = selector("$.hello");
    let row = db
        .query_one(
            "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_rows WHERE id = 2",
            &[&hello],
        )
        .unwrap();
    assert_eq!(open(&selector_of("$.hello"), entry(&row)), json!("world-2"));
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
    // one row per element, each opening to its value, in the stored order,
    // which is random: the client recovers element order from the labels.
    let mut tags: Vec<Value> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_path_query(doc::jsonb, $1::text) e WHERE id = 3",
            &[&selector("$.tags[*]")],
        )
        .unwrap()
        .iter()
        .map(|r| open(&selector_of("$.tags[*]"), entry(r)))
        .collect();
    tags.sort_by_key(Value::to_string);
    assert_eq!(tags, vec![json!("x"), json!("y")]);
    // `->` at a wildcard path takes the first entry carrying the selector
    // in the stored order: an unspecified element of the row, the same one
    // every time, and one of the elements `jsonb_path_query` returns.
    let first: Vec<Value> = (0..3)
        .map(|_| {
            let row = db
                .query_one(
                    "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_rows WHERE id = 3",
                    &[&selector("$.tags[*]")],
                )
                .unwrap();
            open(&selector_of("$.tags[*]"), entry(&row))
        })
        .collect();
    assert!(
        tags.contains(&first[0]),
        "`->` at a wildcard is one of the elements"
    );
    assert!(
        first.iter().all(|v| v == &first[0]),
        "the same one every time"
    );

    // The read of `$.nested`, from a token derived on the client from the
    // path alone: nested itself and its six entries in row 1, reassembling
    // the sub-document; nested and two in row 2; nothing in row 3.
    let nested = subtree_key("$.nested");
    assert_eq!(nested.tokens().len(), 1, "one token for one node");
    let read = |db: &mut postgres::Client,
                key: &JsonSubtreeKey,
                id: i32,
                budget: i32|
     -> Vec<JsonTreeEntry> {
        db.query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text[], $2::int) e WHERE id = $3",
            &[&key.tokens(), &budget, &id],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect()
    };
    for (id, expected) in [
        (1, Some(fixture()["nested"].clone())),
        (2, Some(rows[1].1["nested"].clone())),
        (3, None),
    ] {
        let walked = read(&mut db, &nested, id, 0);
        assert_eq!(walked.len(), [0, 7, 3, 0][id as usize], "row {id}");
        assert!(walked
            .iter()
            .all(|e| e.d.is_some() && e.j.is_some() && e.h.is_some() && e.v.is_some()));
        let value: Option<Value> = wait(&runtime, read_optional(&cipher, &nested, walked)).unwrap();
        assert_eq!(value, expected, "row {id}");
    }
    // The default budget, as a caller who names none gets it.
    let defaulted: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text[]) e WHERE id = 1",
            &[&nested.tokens()],
        )
        .unwrap()
        .get(0);
    assert_eq!(defaulted, 7, "under the default budget of 64");
    let garbage: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text[]) e",
            &[&vec!["AAAAAAAAAAAAAAAAAAAAAA==".to_owned()]],
        )
        .unwrap()
        .get(0);
    assert_eq!(garbage, 0, "a wrong token finds nothing in any row");

    // The budget counts rows, the node a token names included: past it the
    // read returns the sealed root alone, at depth 0, and the rows open to
    // the value at the path; at it, or with the budget off, the read is
    // complete; a wrong token still yields nothing under any budget.
    assert_eq!(
        read(&mut db, &nested, 1, 7).len(),
        7,
        "at the budget, the subtree"
    );
    assert_eq!(
        read(&mut db, &nested, 1, 0).len(),
        7,
        "budget 0 never falls back"
    );
    let root = read(&mut db, &nested, 1, 6);
    assert_eq!(root.len(), 1, "past the budget, the root alone");
    assert_eq!((root[0].j, root[0].d), (Some(0), Some(0)));
    let value: Value = wait(&runtime, read_one(&cipher, &nested, root)).unwrap();
    assert_eq!(value, fixture()["nested"]);
    let garbage: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows, eql_v4.json_tree_subtree(doc, $1::text[], 1) e",
            &[&vec!["AAAAAAAAAAAAAAAAAAAAAA==".to_owned()]],
        )
        .unwrap()
        .get(0);
    assert_eq!(garbage, 0);
    // The budget is gated on the header's sealed-root flag, the bit
    // `JsonHeader` writes: with the flags byte cleared, the same document
    // has no root to return and is read in full under any budget.
    let unflagged: i64 = db
        .query_one(
            "SELECT count(*) FROM json_tree_rows,
               eql_v4.json_tree_subtree(
                 jsonb_set(doc::jsonb, '{h}', to_jsonb(encode(set_byte(decode(doc::jsonb ->> 'h', 'base64'), 1, 0), 'base64')))::public.eql_v4_json_search,
                 $1::text[], 1) e
             WHERE id = 1",
            &[&nested.tokens()],
        )
        .unwrap()
        .get(0);
    assert_eq!(unflagged, 7, "an unsealed root is read in full");

    // A wildcard: the client expands `$.nested.list[*].x` to one token per
    // position below the bound and a probe at it; each `x` comes back as a
    // node of its own. Past the budget the read falls back the same way,
    // and the concrete paths are evaluated over the whole document.
    let xs = subtree_key("$.nested.list[*].x");
    assert_eq!(xs.tokens().len(), 65, "64 positions and the probe");
    for budget in [0, 1, 64] {
        let rows = read(&mut db, &xs, 1, budget);
        let values: Vec<Value> = wait(&runtime, read_list(&cipher, &xs, rows)).unwrap();
        assert_eq!(values, vec![json!(1), json!(2)], "budget {budget}");
    }

    // A position below a key step: the second element's own token.
    let second = subtree_key("$.nested.list[1]");
    let value: Value = wait(
        &runtime,
        read_one(&cipher, &second, read(&mut db, &second, 1, 0)),
    )
    .unwrap();
    assert_eq!(value, json!({"x": 2}));

    // The array functions, by the list's own token: a count per row, NULL
    // where the row has no list.
    let list = subtree_key("$.nested.list");
    let counts: Vec<(i32, Option<i32>)> = db
        .query(
            "SELECT id, eql_v4.json_tree_child_count(doc, $1::text) FROM json_tree_rows ORDER BY id",
            &[&list.tokens()[0]],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(counts, [(1, Some(2)), (2, Some(0)), (3, None)]);
    let elements: Vec<JsonTreeEntry> = db
        .query(
            "SELECT e::jsonb::text FROM json_tree_rows, eql_v4.json_tree_children(doc, $1::text) e WHERE id = 1",
            &[&list.tokens()[0]],
        )
        .unwrap()
        .iter()
        .map(entry)
        .collect();
    // `json_tree_children` returns an array's elements in position order,
    // whatever slots they are stored at: compared unsorted.
    let found: Vec<(Option<u64>, Option<u32>)> = elements.iter().map(|e| (e.j, e.d)).collect();
    let first = slot(
        &mut db,
        "json_tree_rows",
        1,
        &subtree_key("$.nested.list[0]"),
    );
    let second = slot(
        &mut db,
        "json_tree_rows",
        1,
        &subtree_key("$.nested.list[1]"),
    );
    assert_eq!(
        found,
        vec![(Some(first), Some(1)), (Some(second), Some(1))],
        "both elements, in position order, each at the slot it is stored at"
    );
    let members: i32 = db
        .query_one(
            "SELECT eql_v4.json_tree_child_count(doc, $1::text) FROM json_tree_rows WHERE id = 1",
            &[&nested.tokens()[0]],
        )
        .unwrap()
        .get(0);
    assert_eq!(members, 2, "nested's own members: deep and list");
    // The sealed root's members chain from nothing, so its token cannot
    // count them: NULL, not a count of zero.
    let root_key = subtree_key("$");
    let root_count: Option<i32> = db
        .query_one(
            "SELECT eql_v4.json_tree_child_count(doc, $1::text) FROM json_tree_rows WHERE id = 1",
            &[&root_key.tokens()[0]],
        )
        .unwrap()
        .get(0);
    assert_eq!(root_count, None);

    // Orderings at a path: the rows whose `$.number` is in range, and
    // sorted by the leaf's term.
    let at_least_one = wait(&runtime, gte_at(&cipher, "$.number", json!(1)));
    let at_least_one = serde_json::to_string(&at_least_one).unwrap();
    let number = selector("$.number");
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_leaf ORDER BY id",
            &[&number, &at_least_one],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [1, 2]);
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM json_tree_rows WHERE (doc -> $1::text) < $2::text::jsonb::eql_v4.query_json_leaf ORDER BY id",
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

    // An ordering operand that lost its `query_json_leaf` cast is plain
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
                            "operator {op} is not supported for public.eql_v4_json_entry"
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
                message.contains("operator ? is not supported for public.eql_v4_json_search"),
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
    let mut db = connect();

    let version: i32 = db
        .query_one("SHOW server_version_num", &[])
        .unwrap()
        .get::<_, String>(0)
        .parse()
        .unwrap();

    // The operands: a containment needle per shape, and one range bound at
    // `$.number`, whose selector the functional index is built on.
    let bound = wait(&runtime, gte_at(&cipher, "$.number", json!(1)));
    let number = bound.s.0.as_str().to_owned();
    let leaf = |value: i64| {
        let query = wait(&runtime, gte_at(&cipher, "$.number", json!(value)));
        serde_json::to_string(&query).unwrap()
    };
    let needle = |value: Value| {
        let query = wait(&runtime, contains(&cipher, &value));
        serde_json::to_string(&query).unwrap()
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
            "CREATE TEMP TABLE {table} (id int PRIMARY KEY, doc public.eql_v4_json_search NOT NULL);
             CREATE INDEX {table}_gin ON {table} USING gin ((eql_v4.json_tree_query(doc)) jsonb_path_ops);
             CREATE INDEX {table}_ord ON {table} (eql_v4.ord_term(doc -> '{number}'::text));"
        ))
        .unwrap();
        for i in 0..shape.rows {
            let stored = wait(&runtime, seal(&cipher, &(shape.document)(i)));
            let stored = serde_json::to_string(&stored).unwrap();
            db.execute(
                &format!(
                    "INSERT INTO {table} VALUES ($1, $2::text::jsonb::public.eql_v4_json_search)"
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
            &format!("SELECT id FROM {table} WHERE doc @> $1::text::jsonb::eql_v4.query_json"),
            &[&operand],
        );
        assert!(
            text.contains(&format!("Bitmap Index Scan on {table}_gin")),
            "{} on PostgreSQL {version}: containment should use the GIN index without help:\n{text}",
            shape.name
        );
        let matched: i64 = db
            .query_one(
                &format!(
                    "SELECT count(*) FROM {table} WHERE doc @> $1::text::jsonb::eql_v4.query_json"
                ),
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
            &format!("SELECT id FROM {table} WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_leaf"),
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
                &format!("SELECT count(*) FROM {table} WHERE (doc -> $1::text) >= $2::text::jsonb::eql_v4.query_json_leaf"),
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
               SELECT id FROM {table} WHERE doc @> $1::jsonb::eql_v4.query_json;
             PREPARE {table}_range(text) AS
               SELECT id FROM {table} WHERE (doc -> '{number}'::text) >= $1::jsonb::eql_v4.query_json_leaf;"
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
    tx.batch_execute("ALTER FUNCTION eql_v4.json_tree_query(public.eql_v4_json_search) COST 1")
        .unwrap();
    let operand = needle(shapes[1].needle.clone());
    let text = tx
        .query(
            "EXPLAIN SELECT id FROM json_tree_plan_nested WHERE doc @> $1::text::jsonb::eql_v4.query_json",
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

// =============================================================================
// Subtree reads against jsonb
// =============================================================================

/// `path` in PostgreSQL's SQL/JSON path language, strict: a key quoted as a
/// JSON string, so the keys that stress the path encoding (`.`, `[`, `*`,
/// `$`, quotes, backslashes, the empty key) name exactly one member. Strict,
/// because a lax path reads `$.a[0]` on an object as `$.a`, and `#>` reads a
/// position as a key; the index reads a position as an element only.
fn pg_path(path: &JsonPath) -> String {
    let mut out = String::from("strict $");
    for segment in path.segments() {
        match segment {
            Segment::Key(key) => {
                out.push('.');
                out.push_str(&serde_json::to_string(key).unwrap());
            }
            Segment::Index(index) => out.push_str(&format!("[{index}]")),
            Segment::Wildcard => out.push_str("[*]"),
        }
    }
    out
}

/// Every node's path in `value`, positionally, the root first.
fn node_paths(value: &Value) -> Vec<JsonPath> {
    fn visit(value: &Value, at: &str, out: &mut Vec<String>) {
        out.push(at.to_owned());
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    visit(
                        child,
                        &format!("{at}[{}]", serde_json::to_string(key).unwrap()),
                        out,
                    );
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    visit(child, &format!("{at}[{i}]"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    visit(value, "$", &mut out);
    out.iter()
        .map(|text| JsonPath::parse(text).unwrap())
        .collect()
}

/// A temp table of `documents` sealed under `options`, beside their
/// plaintexts, ids from 1.
fn store(
    db: &mut postgres::Client,
    runtime: &tokio::runtime::Runtime,
    cipher: &Cipher,
    table: &str,
    options: &JsonOptions,
    documents: &[Value],
) {
    db.batch_execute(&format!(
        "CREATE TEMP TABLE {table} (id int PRIMARY KEY, plain jsonb NOT NULL, doc public.eql_v4_json_search NOT NULL)"
    ))
    .unwrap();
    for (id, plain) in (1..).zip(documents) {
        let stored = wait(
            runtime,
            cipher.default_keyset().run(
                JsonTree::new(options.clone()).encryption(),
                plain,
                column(),
            ),
        )
        .unwrap();
        db.execute(
            &format!("INSERT INTO {table} VALUES ($1, $2::text::jsonb, $3::text::jsonb::public.eql_v4_json_search)"),
            &[&id, &plain.to_string(), &serde_json::to_string(&stored).unwrap()],
        )
        .unwrap();
    }
}

/// The slot the node `key` names is stored at in row `id`: the entries are
/// stored in a random order, so a test finds a node by its self tag, as the
/// server does.
fn slot(db: &mut postgres::Client, table: &str, id: i32, key: &JsonSubtreeKey) -> u64 {
    let j: i64 = db
        .query_one(
            &format!(
                "SELECT (e.o - 1)::bigint FROM {table}, jsonb_array_elements(doc::jsonb -> 'sv') WITH ORDINALITY AS e(v, o)
                 WHERE id = $2 AND e.v ->> 'x' = eql_v4_internal.json_tree_self_tag(eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'), decode($1::text, 'base64'))"
            ),
            &[&key.tokens()[0], &id],
        )
        .unwrap_or_else(|error| panic!("{table} {} in row {id}: {error}", key.path()))
        .get(0);
    j as u64
}

/// The rows `json_tree_subtree(doc, key.tokens(), budget)` returns in row `id`.
fn subtree_rows(
    db: &mut postgres::Client,
    table: &str,
    id: i32,
    key: &JsonSubtreeKey,
    budget: i32,
) -> Vec<JsonTreeEntry> {
    db.query(
        &format!("SELECT e::jsonb::text FROM {table}, eql_v4.json_tree_subtree(doc, $1::text[], $2::int) e WHERE id = $3"),
        &[&key.tokens(), &budget, &id],
    )
    .unwrap_or_else(|error| panic!("{table} {}: {error}", key.path()))
    .iter()
    .map(|r| serde_json::from_str(&r.get::<_, String>(0)).unwrap())
    .collect()
}

/// What `jsonb_path_query_first(plain, 'strict <path>')` holds in row `id`.
fn jsonb_first(db: &mut postgres::Client, table: &str, id: i32, path: &JsonPath) -> Option<Value> {
    db.query_one(
        &format!("SELECT jsonb_path_query_first(plain, $1::text::jsonpath, '{{}}', true)::text FROM {table} WHERE id = $2"),
        &[&pg_path(path), &id],
    )
    .unwrap()
    .get::<_, Option<String>>(0)
    .map(|text| serde_json::from_str(&text).unwrap())
}

/// What `jsonb_path_query(plain, 'strict <path>')` returns in row `id`,
/// one concrete path at a time: the wildcards are expanded over the
/// plaintext's own arrays, and each concrete path is asked of `jsonb` with
/// [`jsonb_first`]. Strict mode aborts the whole query on the first element
/// a step does not fit (`.x` on a number), where the index answers for each
/// element on its own, so asking each concrete path keeps strict mode's
/// answer for every element without its abort. In document order.
fn jsonb_all(
    db: &mut postgres::Client,
    table: &str,
    id: i32,
    plain: &Value,
    path: &JsonPath,
) -> Vec<Value> {
    fn expand(value: Option<&Value>, at: JsonPath, rest: &[Segment], out: &mut Vec<JsonPath>) {
        let Some((step, rest)) = rest.split_first() else {
            out.push(at);
            return;
        };
        match step {
            Segment::Wildcard => {
                let len = value.and_then(Value::as_array).map_or(0, Vec::len);
                for i in 0..len {
                    let next = value.and_then(|v| v.as_array()).and_then(|a| a.get(i));
                    expand(next, append(&at, &Segment::Index(i as u64)), rest, out);
                }
            }
            Segment::Key(key) => {
                let next = value.and_then(Value::as_object).and_then(|o| o.get(key));
                expand(next, append(&at, step), rest, out);
            }
            Segment::Index(i) => {
                let next = value
                    .and_then(Value::as_array)
                    .and_then(|a| a.get(*i as usize));
                expand(next, append(&at, step), rest, out);
            }
        }
    }
    let mut concrete = Vec::new();
    expand(
        Some(plain),
        JsonPath::root(),
        path.segments(),
        &mut concrete,
    );
    concrete
        .iter()
        .filter_map(|q| jsonb_first(db, table, id, q))
        .collect()
}

/// `at` with one more step.
fn append(at: &JsonPath, step: &Segment) -> JsonPath {
    let text = match step {
        Segment::Key(key) => format!("[{}]", serde_json::to_string(key).unwrap()),
        Segment::Index(i) => format!("[{i}]"),
        Segment::Wildcard => "[*]".to_owned(),
    };
    JsonPath::parse(&format!("{at}{text}")).unwrap()
}

/// The child count jsonb gives the node at `path` in row `id`: an object's
/// keys, an array's length, `0` for a scalar (where jsonb raises), NULL
/// where there is no node.
fn jsonb_child_count(
    db: &mut postgres::Client,
    table: &str,
    id: i32,
    path: &JsonPath,
) -> Option<i32> {
    db.query_one(
        &format!(
            "SELECT CASE WHEN v IS NULL THEN NULL
                      WHEN jsonb_typeof(v) = 'object' THEN (SELECT count(*)::int FROM jsonb_object_keys(v))
                      WHEN jsonb_typeof(v) = 'array' THEN jsonb_array_length(v)
                      ELSE 0 END
             FROM (SELECT jsonb_path_query_first(plain, $1::text::jsonpath, '{{}}', true) AS v FROM {table} WHERE id = $2) AS q"
        ),
        &[&pg_path(path), &id],
    )
    .unwrap()
    .get(0)
}

/// The documents the read oracle stores: nested empties, degenerate roots,
/// the keys that stress the path encoding, numbers that `jsonb` spells
/// differently, a `null` leaf beside an absent key, a wide object, and the
/// shapes #1356 found.
fn read_documents() -> Vec<Value> {
    let wide: Map<String, Value> = (0..300).map(|i| (format!("k{i}"), json!(i))).collect();
    let mut deep = json!(1);
    for _ in 0..40 {
        deep = json!({"d": [deep]});
    }
    vec![
        json!({"p": {}, "l": [{}, [], "s", {"x": 1}], "h": {"p": {}, "l": [[], {}, null]}}),
        json!({"p": [], "l": [[]], "h": {"p": []}}),
        json!({"p": "text", "l": ["a", 0, false], "h": {"p": 7, "l": [true]}}),
        json!({"q": 1, "h": {"q": null}}),
        json!({"p": null, "l": [], "h": []}),
        json!({"p": {"a": 1, "b": [2, {"c": null}]}, "l": [{"a": [1, 2]}, 5], "h": {"p": {"a": {"b": {}}}, "l": [{"a": 1}]}}),
        json!({"p": [[], {}], "l": [[{}], [[]]], "h": {"l": [[{"x": []}]]}}),
        json!({"a": {}}),
        json!([[]]),
        json!({"a": [{}]}),
        json!([]),
        json!({}),
        json!("scalar"),
        json!(7),
        json!(null),
        json!([{"x": 1}, {"y": 2}, 3]),
        json!({
            "": 1,
            "a.b": {"[*]": [{"$": 2}]},
            "\"\\": null,
            "é✓": ["unicode"],
            "0": {"x": "the key 0"},
            "arr": [{"x": "the index 0"}],
            "*": {"[": {"]": true}},
        }),
        json!({"n": [2, 2.0, 1e30, -0.0, -9223372036854775808i64, 18446744073709551615u64, 1.5, 1e-7]}),
        json!({"null": null, "nested": {"null": null}}),
        json!({"wide": wide}),
        json!({"deep": deep}),
    ]
}

/// Needs an EQL v4 installation. Every read of a path with no wildcard
/// returns the node the path names with everything beneath it, so it answers
/// as `jsonb` does: an empty object, an empty array, a scalar (`null`
/// included) and a node the document does not have are four different
/// answers, held here to `jsonb_path_query_first(plain, 'strict <path>')`
/// over the plaintexts, as `Option<Value>`, `Value` and `Vec<Value>`. Every
/// node of every document is read, at a chain head, under positions and
/// deep, plus paths no document has, with the root sealed and open, read
/// in full (budget 0), past a budget of 1 (where every read of more than
/// one row falls back to the sealed root) and under the default. The same
/// pass holds `json_tree_child_count` and `json_tree_children` to `jsonb`'s
/// counts, and `->` to the read for every scalar at a path with no
/// position.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_every_subtree_read_answers_as_jsonb_does() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let documents = read_documents();
    // Every node's path, but of the wide object's 300 members only the
    // first, the last and one past it: each member is the same read.
    let mut paths: Vec<JsonPath> = documents
        .iter()
        .flat_map(node_paths)
        .filter(|p| {
            !matches!(p.segments(), [Segment::Key(w), Segment::Key(k)]
                if w == "wide" && !["k0", "k299"].contains(&k.as_str()))
        })
        .collect();
    for extra in [
        "$.q",
        "$.p.missing",
        "$[0]",
        "$[1]",
        "$.l[9]",
        "$.h.l[0][0]",
        r#"$["0"]"#,
        "$.arr[1]",
        r#"$["a.b"]["[*]"][0]["$"]"#,
        "$.n[7]",
        "$.wide.k300",
    ] {
        paths.push(JsonPath::parse(extra).unwrap());
    }
    paths.sort();
    paths.dedup();
    let mut checked = [0usize; 4];
    for sealed_root in [true, false] {
        let options = JsonOptions {
            sealed_root,
            ..JsonOptions::default()
        };
        let table = if sealed_root {
            "json_tree_reads_sealed"
        } else {
            "json_tree_reads_open"
        };
        store(&mut db, &runtime, &cipher, table, &options, &documents);
        for path in &paths {
            let key = wait(&runtime, keyset.json_subtree_key(path, &options, column())).unwrap();
            assert_eq!(key.tokens().len(), 1, "{path}: one token");
            let selector = wait(&runtime, keyset.json_selector(path, column())).unwrap();
            for id in 1..=documents.len() as i32 {
                let expected = jsonb_first(&mut db, table, id, path);
                checked[match &expected {
                    None => 0,
                    Some(Value::Object(o)) if o.is_empty() => 1,
                    Some(Value::Array(a)) if a.is_empty() => 2,
                    Some(_) => 3,
                }] += 1;
                let at = format!("{table} {path}, row {id}");
                for budget in [0, 1, 64] {
                    let rows = subtree_rows(&mut db, table, id, &key, budget);
                    let fell_back = sealed_root && rows.len() == 1 && rows[0].j == Some(0);
                    if expected.is_none() {
                        assert!(rows.is_empty(), "{at}: no node, no row");
                    } else if budget == 0 {
                        assert!(
                            !fell_back || path.segments().is_empty(),
                            "{at}: read in full"
                        );
                    }
                    let opened: Option<Value> =
                        wait(&runtime, read_optional(&cipher, &key, rows.clone()))
                            .unwrap_or_else(|error| panic!("{at}, budget {budget}: {error}"));
                    assert_eq!(opened, expected, "{at}, budget {budget}, as Option<Value>");
                    let list: Vec<Value> =
                        wait(&runtime, read_list(&cipher, &key, rows.clone())).unwrap();
                    assert_eq!(
                        list,
                        expected.clone().into_iter().collect::<Vec<_>>(),
                        "{at}, as Vec<Value>"
                    );
                    let one: Result<Value, _> = wait(&runtime, read_one(&cipher, &key, rows));
                    match (&expected, one) {
                        (Some(expected), Ok(one)) => assert_eq!(&one, expected, "{at}, as Value"),
                        (None, Err(stack_encrypt::Error::OpenedType { expected })) => {
                            assert_eq!(expected, "a node at the walked path", "{at}")
                        }
                        (expected, one) => panic!("{at}: {expected:?} opened as {one:?}"),
                    }
                }

                // The children and their count, by the node's own token.
                let count: Option<i32> = db
                    .query_one(
                        &format!("SELECT eql_v4.json_tree_child_count(doc, $1::text) FROM {table} WHERE id = $2"),
                        &[&key.tokens()[0], &id],
                    )
                    .unwrap()
                    .get(0);
                let children: i64 = db
                    .query_one(
                        &format!("SELECT count(*) FROM {table}, eql_v4.json_tree_children(doc, $1::text) e WHERE id = $2"),
                        &[&key.tokens()[0], &id],
                    )
                    .unwrap()
                    .get(0);
                if sealed_root && path.segments().is_empty() {
                    assert_eq!(
                        count, None,
                        "{at}: the sealed root's members chain from nothing"
                    );
                    assert_eq!(children, 0, "{at}");
                } else {
                    assert_eq!(
                        count,
                        jsonb_child_count(&mut db, table, id, path),
                        "{at}: child_count"
                    );
                    assert_eq!(children, i64::from(count.unwrap_or(0)), "{at}: children");
                }

                // `->` returns the first entry at the path's selector, which
                // reads a position as the wildcard: for a scalar at a path
                // with no position it is the read's node.
                if !path
                    .segments()
                    .iter()
                    .any(|s| matches!(s, Segment::Index(_)))
                    && expected
                        .as_ref()
                        .is_some_and(|v| !v.is_object() && !v.is_array())
                {
                    let arrow: Option<String> = db
                        .query_one(
                            &format!(
                                "SELECT (doc -> $1::text)::jsonb::text FROM {table} WHERE id = $2"
                            ),
                            &[&selector.to_string(), &id],
                        )
                        .unwrap()
                        .get(0);
                    let entry: JsonTreeEntry = serde_json::from_str(&arrow.unwrap()).unwrap();
                    let value: Value = wait(&runtime, extract(&cipher, &selector, entry)).unwrap();
                    assert_eq!(Some(value), expected, "{at}: `->` and the read agree");
                }
            }
        }
    }
    assert!(
        checked.iter().all(|n| *n > 0),
        "the corpus reaches no node, `{{}}`, `[]` and other values: {checked:?}"
    );
}

/// The entries `json_tree_children(doc, token)` returns in row `id` for the
/// token of `key`, in the order the SQL returns them.
fn children_rows(
    db: &mut postgres::Client,
    table: &str,
    id: i32,
    key: &JsonSubtreeKey,
) -> Vec<JsonTreeEntry> {
    db.query(
        &format!("SELECT e::jsonb::text FROM {table}, eql_v4.json_tree_children(doc, $1::text) e WHERE id = $2"),
        &[&key.tokens()[0], &id],
    )
    .unwrap_or_else(|error| panic!("{table} {}: {error}", key.path()))
    .iter()
    .map(|r| serde_json::from_str(&r.get::<_, String>(0)).unwrap())
    .collect()
}

/// Needs an EQL v4 installation. Every entry `json_tree_children` returns
/// for a node's token opens on its own through the key of the node's path,
/// to the value `jsonb` holds there: an array's elements in position
/// order, an object's members in any order. A child with children of its
/// own does not open alone ([`stack_encrypt::Error::JsonNotALeaf`]) and is
/// read with a subtree read. Every node of every document of the read
/// oracle is a parent here, with the root sealed and open; the sealed root
/// has no children to return. An array's elements opened against the key
/// of another array that holds them too (`$.l` for `$.h.l`) are refused.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_each_child_opens_against_its_parent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let documents = read_documents();
    // The wide object's members are scalars, with no children: its own
    // path reads all 300 of them.
    let mut paths: Vec<JsonPath> = documents
        .iter()
        .flat_map(node_paths)
        .filter(|p| !matches!(p.segments(), [Segment::Key(w), Segment::Key(_)] if w == "wide"))
        .collect();
    paths.sort();
    paths.dedup();
    // What a child opens to: its value, or `None` for a container with
    // children, which does not open alone.
    let leaf = |value: &Value| match value {
        Value::Object(members) if !members.is_empty() => None,
        Value::Array(items) if !items.is_empty() => None,
        other => Some(other.clone()),
    };
    // What a child opens to: its key or index with its value, or `None`.
    let member = |(key, value): (&String, &Value)| {
        leaf(value).map(|value| Child::Member(key.clone(), value))
    };
    let element = |(index, value): (usize, &Value)| {
        leaf(value).map(|value| Child::Element(index as u64, value))
    };
    let mut opened = [0usize; 2];
    for sealed_root in [true, false] {
        let options = JsonOptions {
            sealed_root,
            ..JsonOptions::default()
        };
        let table = if sealed_root {
            "json_tree_children_sealed"
        } else {
            "json_tree_children_open"
        };
        store(&mut db, &runtime, &cipher, table, &options, &documents);
        let key = |path: &JsonPath| {
            wait(&runtime, keyset.json_subtree_key(path, &options, column())).unwrap()
        };
        for path in &paths {
            let parent = key(path);
            for id in 1..=documents.len() as i32 {
                let at = format!("{table} {path}, row {id}");
                let rows = children_rows(&mut db, table, id, &parent);
                if sealed_root && path.segments().is_empty() {
                    assert!(
                        rows.is_empty(),
                        "{at}: the sealed root's members chain from nothing"
                    );
                    continue;
                }
                let plain = jsonb_first(&mut db, table, id, path);
                let mut expected: Vec<Option<Child>> = match &plain {
                    Some(Value::Array(items)) => items.iter().enumerate().map(element).collect(),
                    Some(Value::Object(members)) => members.iter().map(member).collect(),
                    _ => Vec::new(),
                };
                let mut got: Vec<Option<Child>> = rows
                    .into_iter()
                    .map(
                        |entry| match wait(&runtime, open_child(&cipher, &parent, entry)) {
                            Ok(value) => {
                                opened[0] += 1;
                                Some(value)
                            }
                            Err(stack_encrypt::Error::JsonNotALeaf) => {
                                opened[1] += 1;
                                None
                            }
                            Err(error) => panic!("{at}: {error}"),
                        },
                    )
                    .collect();
                // An object's members come back in the random order their
                // ordinals were drawn in, each with its key. A member with
                // children does not open, so its key is not known: those
                // are compared by count.
                if matches!(plain, Some(Value::Object(_))) {
                    expected.sort_by_key(|child| format!("{child:?}"));
                    got.sort_by_key(|child| format!("{child:?}"));
                }
                assert_eq!(
                    got, expected,
                    "{at}: each child opens to its key or index and its value"
                );
            }
        }

        // `$.l`'s elements, offered as `$.h.l`'s: each carries `$.l[*]`'s
        // selector, not `$.h.l[*]`'s, and is refused, or does not open
        // alone if it has children of its own.
        let (outer, inner) = (
            key(&JsonPath::parse("$.l").unwrap()),
            key(&JsonPath::parse("$.h.l").unwrap()),
        );
        let rows = children_rows(&mut db, table, 1, &outer);
        assert!(!rows.is_empty(), "{table}: row 1 has elements at $.l");
        for entry in rows {
            let refused = wait(&runtime, open_child(&cipher, &inner, entry));
            assert!(
                matches!(
                    refused,
                    Err(stack_encrypt::Error::JsonWrongEntry { .. }
                        | stack_encrypt::Error::JsonNotALeaf)
                ),
                "{table}: a child of $.l under $.h.l: {refused:?}"
            );
        }
    }
    assert!(
        opened.iter().all(|n| *n > 0),
        "the corpus opens children and refuses containers with children: {opened:?}"
    );
}

/// Whether a read of `pattern` at `bound` over `value` finds an array longer
/// than the bound at a wildcard level it reaches, which is when one of its
/// probes names a node.
fn truncated(value: &Value, pattern: &[Segment], bound: usize) -> bool {
    let Some((step, rest)) = pattern.split_first() else {
        return false;
    };
    match (step, value) {
        (Segment::Key(key), Value::Object(map)) => {
            map.get(key).is_some_and(|v| truncated(v, rest, bound))
        }
        (Segment::Index(i), Value::Array(items)) => items
            .get(*i as usize)
            .is_some_and(|v| truncated(v, rest, bound)),
        (Segment::Wildcard, Value::Array(items)) => {
            items.len() > bound || items.iter().any(|v| truncated(v, rest, bound))
        }
        _ => false,
    }
}

/// Needs an EQL v4 installation. A wildcard read answers as
/// `jsonb_path_query(plain, 'strict <path>')` when every array it expands is
/// at most the bound long, in document order, and fails with the bound
/// otherwise, never with part of the list: at the bound minus one, at it
/// and one past it, under one wildcard and two, with the root sealed and
/// open, read in full, past a budget of 1 (the sealed-root fallback, which
/// evaluates the same probes) and under the default.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_wildcard_reads_answer_as_jsonb_path_query() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let row = |n: usize, inner: usize| -> Value {
        let items: Vec<Value> = (0..n)
            .map(|i| json!({"x": i, "y": (0..inner).map(|k| json!({"z": k * 10 + i})).collect::<Vec<_>>()}))
            .collect();
        json!({"items": items, "top": (0..n).collect::<Vec<_>>(), "obj": {"items": [{"x": "o"}]}})
    };
    let mut cases: Vec<(u32, Vec<Value>)> = Vec::new();
    for bound in [3u32, 64] {
        let n = bound as usize;
        cases.push((
            bound,
            vec![
                row(n - 1, n - 1),
                row(n, n),
                row(n + 1, 1),
                row(1, n + 1),
                row(0, 0),
                json!({"items": {"0": {"x": 1}}, "top": {}}),
                json!([{"x": 1}, {"x": 2}]),
                json!({"items": [1, [2], {"x": null}]}),
            ],
        ));
    }
    let patterns = [
        "$.items[*].x",
        "$.items[*]",
        "$.top[*]",
        "$.items[*].y[*].z",
        "$.items[*].y[*]",
        "$.obj.items[*].x",
        "$[*].x",
        "$.items[0].y[*].z",
        "$.missing[*]",
    ];
    let mut outcomes = [0usize; 2];
    for (bound, documents) in &cases {
        for sealed_root in [true, false] {
            let options = JsonOptions {
                sealed_root,
                ..JsonOptions::default()
            };
            let table = format!(
                "json_tree_wild_{bound}_{}",
                if sealed_root { "sealed" } else { "open" }
            );
            store(&mut db, &runtime, &cipher, &table, &options, documents);
            for pattern in patterns {
                let path = JsonPath::parse(pattern).unwrap();
                let key = wait(
                    &runtime,
                    keyset.json_subtree_key_with_bound(&path, &options, *bound, column()),
                )
                .unwrap();
                for (id, plain) in (1..).zip(documents) {
                    let expected = jsonb_all(&mut db, &table, id, plain, &path);
                    let too_long = truncated(plain, path.segments(), *bound as usize);
                    outcomes[usize::from(too_long)] += 1;
                    for budget in [0, 1, 64] {
                        let at = format!("{table} {pattern}, row {id}, budget {budget}");
                        let rows = subtree_rows(&mut db, &table, id, &key, budget);
                        let list: Result<Vec<Value>, stack_encrypt::Error> =
                            wait(&runtime, read_list(&cipher, &key, rows.clone()));
                        let one: Result<Option<Value>, stack_encrypt::Error> =
                            wait(&runtime, read_optional(&cipher, &key, rows));
                        if too_long {
                            for result in [list.map(|_| ()), one.map(|_| ())] {
                                match result {
                                    Err(stack_encrypt::Error::JsonWildcardTruncated {
                                        bound: b,
                                    }) => {
                                        assert_eq!(b, *bound, "{at}: the error names the bound")
                                    }
                                    other => panic!(
                                        "{at}: an array past the bound must fail, got {other:?}"
                                    ),
                                }
                            }
                        } else {
                            assert_eq!(list.unwrap(), expected, "{at}: as jsonb_path_query");
                            match (one, expected.len()) {
                                (Ok(found), 0 | 1) => {
                                    assert_eq!(found, expected.first().cloned(), "{at}")
                                }
                                (Err(stack_encrypt::Error::OpenedType { .. }), _) => {}
                                (other, n) => panic!("{at}: {n} nodes opened as {other:?}"),
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        outcomes.iter().all(|n| *n > 0),
        "both answers reached: {outcomes:?}"
    );
}

/// Needs an EQL v4 installation. A position names an array element and
/// nothing else, in every row of the column, as a strict SQL/JSON path does
/// (`jsonb_path_query_first(plain, 'strict $.a[1]')`): where a row's node at
/// the path is an object, a member is not returned, the member named `"1"`
/// included, whether the position follows a head (`$.a[1]`) or a key step
/// (`$.h.a[0]`). A member's token and an element's are different hashes,
/// so no entry there carries the element's self tag.
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
    let documents = [
        json!({"a": [{"x": 1}, {"x": 2}], "h": {"a": [{"x": 3}, {"x": 4}]}}),
        json!({"a": {"k": {"x": 9}, "m": {"x": 6}}, "h": {"a": {"k": {"x": 8}, "m": {"x": 5}}}}),
        json!({"a": {"0": {"x": 7}, "1": {"x": 7}}, "h": {"a": {"0": {"x": 7}}}}),
    ];
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_positions",
        &options(),
        &documents,
    );
    for path in ["$.a[1]", "$.h.a[0]"] {
        let path = JsonPath::parse(path).unwrap();
        let key = wait(
            &runtime,
            keyset.json_subtree_key(&path, &options(), column()),
        )
        .unwrap();
        for id in 1..=3 {
            let walked = subtree_rows(&mut db, "json_tree_positions", id, &key, 0);
            let expected = jsonb_first(&mut db, "json_tree_positions", id, &path);
            if expected.is_none() {
                assert!(walked.is_empty(), "{path}, row {id}: jsonb has no node");
            }
            let value: Option<Value> =
                wait(&runtime, read_optional(&cipher, &key, walked)).unwrap();
            assert_eq!(value, expected, "{path}, row {id}");
        }
        let counts: Vec<(i32, Option<i32>)> = db
            .query(
                "SELECT id, eql_v4.json_tree_child_count(doc, $1::text) FROM json_tree_positions ORDER BY id",
                &[&key.tokens()[0]],
            )
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        assert_eq!(
            counts,
            [(1, Some(1)), (2, None), (3, None)],
            "{path}: x, in row 1 only"
        );
    }
}

/// Needs an EQL v4 installation. What `->` and the reads return is checked
/// by the client to be what it asked for: every entry of a row is genuine
/// and opens under its own selector and position, so an answer made of the
/// wrong entries would open unless the client refuses it. Real rows come
/// back from PostgreSQL here, from a database answering the wrong question
/// (another path's entry, the sealed root, another position's subtree with
/// its self tag forged) and from stored rows tampered with (a self tag
/// forged so the read finds the wrong node, a top-level field moved under
/// another node, two entries swapped in `sv`). Each is refused: an entry
/// that is not the one asked for at the top of a read as `JsonWrongEntry`;
/// anything changed beneath the node a read names as `Aead`, since every
/// node's ciphertext commits to its children's tags; and a moved entry as
/// `Aead`, since its ciphertext is bound to the slot it was sealed at. Two
/// answers are allowed by design and shown to open: another row's node at
/// the path (ADR 0010), and the node at the same selector under another
/// element at the top of a read, which nothing the node binds tells apart.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_hostile_answers_are_refused_by_the_client() {
    use stack_encrypt::Error;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let other =
        json!({"hello": "world-2", "nested": {"deep": "other", "list": [{"x": 3}]}, "number": 2});
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_hostile",
        &JsonOptions::default(),
        &[fixture(), fixture(), other.clone()],
    );
    let selector_of = |path: &str| -> JsonSelector {
        wait(
            &runtime,
            keyset.json_selector(&JsonPath::parse(path).unwrap(), column()),
        )
        .unwrap()
    };
    let subtree_key = |path: &str| -> JsonSubtreeKey {
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
    let arrow = |db: &mut postgres::Client, id: i32, selector: &JsonSelector| -> JsonTreeEntry {
        let row = db
            .query_one(
                "SELECT (doc -> $1::text)::jsonb::text FROM json_tree_hostile WHERE id = $2",
                &[&selector.to_string(), &id],
            )
            .unwrap();
        serde_json::from_str(&row.get::<_, String>(0)).unwrap()
    };
    let read = |db: &mut postgres::Client, id: i32, key: &JsonSubtreeKey| {
        subtree_rows(db, "json_tree_hostile", id, key, 0)
    };
    let extracted = |asked: &JsonSelector, entry: JsonTreeEntry| -> Result<Value, Error> {
        wait(&runtime, extract(&cipher, asked, entry))
    };
    let opened = |key: &JsonSubtreeKey, rows: Vec<JsonTreeEntry>| -> Result<Value, Error> {
        wait(&runtime, read_one(&cipher, key, rows))
    };
    let wrong = |result: Result<Value, Error>, what: &str| {
        assert!(
            matches!(result, Err(Error::JsonWrongEntry { .. })),
            "{what}: {result:?}"
        );
    };
    // The self tag a read of `key` finds in row `id`.
    let x_of = |db: &mut postgres::Client, id: i32, key: &JsonSubtreeKey| -> String {
        db.query_one(
            "SELECT eql_v4_internal.json_tree_self_tag(eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'), decode($1::text, 'base64')) FROM json_tree_hostile WHERE id = $2",
            &[&key.tokens()[0], &id],
        )
        .unwrap()
        .get(0)
    };

    // `->` on `$.hello` answered with the row's `$.number`, and with the
    // sealed root, which opens to the whole document.
    let hello = selector_of("$.hello");
    assert_eq!(
        extracted(&hello, arrow(&mut db, 1, &hello)).unwrap(),
        json!("world-1")
    );
    wrong(
        extracted(&hello, arrow(&mut db, 1, &selector_of("$.number"))),
        "another path's entry",
    );
    let root = arrow(&mut db, 1, &selector_of("$"));
    wrong(extracted(&hello, root.clone()), "the sealed root");
    assert_eq!(
        extracted(&selector_of("$"), root).unwrap(),
        fixture(),
        "`$`"
    );

    // The read of `$.nested.list[1]` answered with `$.nested.list[0]`'s
    // rows, its self tag forged to the second element's: the chain finds
    // none of the second element's children among them, and the first
    // element, sealed over its own `x`, does not open.
    let second = subtree_key("$.nested.list[1]");
    assert_eq!(
        opened(&second, read(&mut db, 1, &second)).unwrap(),
        json!({"x": 2})
    );
    let mut forged = read(&mut db, 1, &subtree_key("$.nested.list[0]"));
    // The read returns its rows by slot; the element itself is at depth 0.
    let top = forged.iter().position(|e| e.d == Some(0)).unwrap();
    forged[top].x = serde_json::from_value(json!(x_of(&mut db, 1, &second))).unwrap();
    let refused = opened(&second, forged);
    assert!(
        matches!(refused, Err(Error::Aead)),
        "another position's subtree: {refused:?}"
    );

    // Allowed: `$.nested.list[0].x` for `$.nested.list[1].x`, self tag
    // forged; the same selector, the same label.
    let second_x = subtree_key("$.nested.list[1].x");
    let mut forged = read(&mut db, 1, &subtree_key("$.nested.list[0].x"));
    forged[0].x = serde_json::from_value(json!(x_of(&mut db, 1, &second_x))).unwrap();
    assert_eq!(
        opened(&second_x, forged).unwrap(),
        json!(1),
        "another element's x, by design"
    );
    // Allowed: another row's node at the path, with its own header.
    let nested = subtree_key("$.nested");
    assert_eq!(
        opened(&nested, read(&mut db, 3, &nested)).unwrap(),
        other["nested"],
        "ADR 0010"
    );

    // A truncated read and a reordered one.
    let mut truncated = read(&mut db, 1, &nested);
    let _ = truncated.pop();
    assert!(opened(&nested, truncated).is_err(), "a truncated read");
    let mut reordered = read(&mut db, 1, &nested);
    reordered.swap(2, 3);
    reordered.reverse();
    assert_eq!(
        opened(&nested, reordered).unwrap(),
        fixture()["nested"],
        "the rows are placed by the chain, not by the order they came in"
    );

    // A stored row whose `$.number` is moved under `$.nested`: a parent tag
    // at the ordinal after its two members and a member's self tag. The
    // read takes it for nested's third member and returns it after nested's
    // subtree; nested, sealed over the tags of its two members, does not
    // open.
    let number = subtree_key("$.number");
    let number_at = slot(&mut db, "json_tree_hostile", 1, &number);
    db.execute(
        &format!(
            "UPDATE json_tree_hostile SET doc = jsonb_set(jsonb_set(doc::jsonb, '{{sv,{number_at},p}}',
               to_jsonb(eql_v4_internal.json_tree_parent_tag(
                 eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'), decode($1::text, 'base64'), 2))),
               '{{sv,{number_at},x}}',
               to_jsonb(eql_v4_internal.json_tree_self_tag(
                 eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'),
                 eql_v4_internal.json_tree_member_token(decode($1::text, 'base64'), decode(doc::jsonb -> 'sv' -> {number_at} ->> 's', 'base64')))))::public.eql_v4_json_search
             WHERE id = 1"
        ),
        &[&nested.tokens()[0]],
    )
    .unwrap();
    let rows = read(&mut db, 1, &nested);
    assert_eq!(rows.len(), 8, "the read took number for a member");
    assert!(
        rows.iter()
            .any(|e| (e.j, e.d) == (Some(number_at), Some(1))),
        "number among nested's members"
    );
    let refused = opened(&nested, rows);
    assert!(
        matches!(refused, Err(Error::Aead)),
        "a top-level field as a member: {refused:?}"
    );

    // A stored row whose `$.hello` carries `$.number`'s self tag: the read
    // of `$.number` finds hello, whose selector is not number's.
    let hello_at = slot(&mut db, "json_tree_hostile", 2, &subtree_key("$.hello"));
    let number_at = slot(&mut db, "json_tree_hostile", 2, &number);
    let deep_at = slot(
        &mut db,
        "json_tree_hostile",
        2,
        &subtree_key("$.nested.deep"),
    );
    db.execute(
        &format!(
            "UPDATE json_tree_hostile SET doc = jsonb_set(jsonb_set(doc::jsonb, '{{sv,{hello_at},x}}', doc::jsonb -> 'sv' -> {number_at} -> 'x'),
               '{{sv,{number_at},x}}', '\"AAAAAAAAAAA=\"')::public.eql_v4_json_search WHERE id = 2"
        ),
        &[],
    )
    .unwrap();
    wrong(
        opened(&number, read(&mut db, 2, &number)),
        "a forged self tag",
    );

    // A stored row whose `deep` and `number` swapped places: each entry is
    // found where it now sits, and fails to open there.
    db.execute(
        &format!(
            "UPDATE json_tree_hostile SET doc = jsonb_set(jsonb_set(doc::jsonb,
               '{{sv,{deep_at}}}', doc::jsonb -> 'sv' -> {number_at}), '{{sv,{number_at}}}', doc::jsonb -> 'sv' -> {deep_at})::public.eql_v4_json_search
             WHERE id = 2"
        ),
        &[],
    )
    .unwrap();
    let deep = selector_of("$.nested.deep");
    let moved = extracted(&deep, arrow(&mut db, 2, &deep));
    assert!(
        matches!(moved, Err(Error::JsonNotALeaf)),
        "`->`: a moved entry cannot be told from a container, so both are named: {moved:?}"
    );
    let moved = opened(&nested, read(&mut db, 2, &nested));
    assert!(matches!(moved, Err(Error::Aead)), "the read: {moved:?}");
}

/// A small deterministic generator of documents with arrays of objects, so
/// that a selector has several elements under it.
fn tamper_document(rng: &mut Lcg, depth: u32) -> Value {
    match rng.below(if depth == 0 { 3 } else { 6 }) {
        0 => json!(rng.below(4)),
        1 => json!(["s", "t", "u"][rng.below(3) as usize]),
        2 => Value::Null,
        3 | 4 => Value::Array(
            (0..rng.below(4))
                .map(|_| tamper_document(rng, depth - 1))
                .collect(),
        ),
        _ => {
            let mut map = Map::new();
            for _ in 0..rng.below(4) {
                let key = ["a", "b", "c", "0"][rng.below(4) as usize].to_owned();
                let _ = map.insert(key, tamper_document(rng, depth - 1));
            }
            Value::Object(map)
        }
    }
}

/// Every answer the read check cannot tell from the right one, by design:
/// the value at every concrete path that shares `path`'s selector and last
/// step, under another element of an array before it.
fn same_selector_values(plain: &Value, path: &JsonPath) -> Vec<Value> {
    let segments = path.segments();
    let pattern: Vec<String> = segments
        .iter()
        .enumerate()
        .map(|(i, segment)| match segment {
            Segment::Key(key) => format!("[{}]", serde_json::to_string(key).unwrap()),
            Segment::Index(n) if i + 1 == segments.len() => format!("[{n}]"),
            _ => "[*]".to_owned(),
        })
        .collect();
    JsonPath::parse(&format!("${}", pattern.concat()))
        .unwrap()
        .select(plain)
        .into_iter()
        .cloned()
        .collect()
}

/// Needs an EQL v4 installation. No tampering with a stored row makes a
/// read answer wrongly without saying so. Random documents are stored, one
/// random change is made to each stored row (a self tag, parent tag or
/// selector rewritten, two entries swapped, an entry dropped or
/// duplicated, a node moved under another parent, an entry swapped with
/// the same position of another row, a read's rows truncated), and every
/// path of the untampered document is then read. The client either opens
/// exactly the `jsonb` answer over the untampered plaintext, or refuses, or
/// opens one of the answers it allows by design, each modelled here: no
/// node (`None`, the database withholding the rows, which no row can prove
/// it should have returned), and the node at the same selector and last
/// step under another element. Nothing else is accepted.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_reads_never_answer_wrongly_under_tampering() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE json_tree_tamper (id int PRIMARY KEY, plain jsonb NOT NULL, doc public.eql_v4_json_search NOT NULL)",
    )
    .unwrap();
    let mut rng = Lcg(0x5eed_7a3e);
    let mut outcomes = std::collections::BTreeMap::<&str, usize>::new();
    const MUTATIONS: u64 = 9;
    for round in 0..120i32 {
        let id = round;
        let mut plain = Value::Object(Map::new());
        while plain.as_object().is_some_and(Map::is_empty) {
            plain = json!({"a": tamper_document(&mut rng, 3), "b": [tamper_document(&mut rng, 2), tamper_document(&mut rng, 2)]});
        }
        let stored = serde_json::to_value(wait(&runtime, seal(&cipher, &plain))).unwrap();
        let other = serde_json::to_value(wait(&runtime, seal(&cipher, &plain))).unwrap();
        let sv = stored["sv"].as_array().unwrap().clone();
        let n = sv.len();
        let pick = |rng: &mut Lcg| rng.below(n as u64) as usize;
        let mut tampered = stored.clone();
        let mutation = rng.below(MUTATIONS);
        let mut truncate_rows = false;
        let what = match mutation {
            0 => {
                let (i, k) = (pick(&mut rng), pick(&mut rng));
                tampered["sv"][i]["x"] = sv[k]["x"].clone();
                "a self tag copied from another entry"
            }
            1 => {
                let (i, k) = (pick(&mut rng), pick(&mut rng));
                match sv[k].get("p") {
                    Some(p) => tampered["sv"][i]["p"] = p.clone(),
                    None => {
                        let _ = tampered["sv"][i].as_object_mut().unwrap().remove("p");
                    }
                }
                "a parent tag copied, or removed"
            }
            2 => {
                let (i, k) = (pick(&mut rng), pick(&mut rng));
                tampered["sv"][i]["s"] = sv[k]["s"].clone();
                "a selector rewritten"
            }
            3 => {
                let (i, k) = (pick(&mut rng), pick(&mut rng));
                tampered["sv"].as_array_mut().unwrap().swap(i, k);
                "two entries swapped"
            }
            4 => {
                let i = pick(&mut rng);
                if n > 1 {
                    let _ = tampered["sv"].as_array_mut().unwrap().remove(i);
                }
                "an entry dropped"
            }
            5 => {
                let (i, k) = (pick(&mut rng), pick(&mut rng));
                tampered["sv"]
                    .as_array_mut()
                    .unwrap()
                    .insert(k, sv[i].clone());
                "an entry duplicated"
            }
            6 => {
                let i = pick(&mut rng);
                tampered["sv"][i] = other["sv"][i].clone();
                "an entry swapped with another row's at its position"
            }
            7 => {
                truncate_rows = true;
                "a read's rows truncated"
            }
            _ => "a node moved under another parent",
        };
        let inserted = db.execute(
            "INSERT INTO json_tree_tamper VALUES ($1, $2::text::jsonb, $3::text::jsonb::public.eql_v4_json_search)",
            &[&id, &plain.to_string(), &tampered.to_string()],
        );
        if inserted.is_err() {
            *outcomes.entry("refused by the domain CHECK").or_default() += 1;
            continue;
        }
        let paths = node_paths(&plain);
        if mutation == 8 && paths.len() > 2 {
            // Move a random non-root node under a random container (not
            // itself or beneath it) as that container's next child.
            let from = &paths[1 + pick(&mut rng) % (paths.len() - 1)];
            let containers: Vec<&JsonPath> = paths
                .iter()
                .filter(|p| {
                    !p.segments().starts_with(from.segments())
                        && p.select(&plain)
                            .first()
                            .is_some_and(|v| v.is_object() || v.is_array())
                        && !p.segments().is_empty()
                })
                .collect();
            if let Some(to) = containers.get(pick(&mut rng) % containers.len().max(1)) {
                let to_key = wait(
                    &runtime,
                    keyset.json_subtree_key(to, &JsonOptions::default(), column()),
                )
                .unwrap();
                let from_key = wait(
                    &runtime,
                    keyset.json_subtree_key(from, &JsonOptions::default(), column()),
                )
                .unwrap();
                let width = match to.select(&plain)[0] {
                    Value::Object(m) => m.len(),
                    Value::Array(a) => a.len(),
                    _ => 0,
                } as i32;
                let member = matches!(from.segments().last(), Some(Segment::Key(_)));
                db.execute(
                    "UPDATE json_tree_tamper SET doc = (
                       SELECT jsonb_set(jsonb_set(doc::jsonb, ARRAY['sv', j::text, 'p'],
                                to_jsonb(eql_v4_internal.json_tree_parent_tag(iv, t, $3))),
                              ARRAY['sv', j::text, 'x'],
                              to_jsonb(eql_v4_internal.json_tree_self_tag(iv, CASE WHEN $4
                                THEN eql_v4_internal.json_tree_member_token(t, s)
                                ELSE eql_v4_internal.json_tree_element_token(t, s, $3) END)))
                       FROM (SELECT eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h') AS iv,
                                    decode($2::text, 'base64') AS t,
                                    ((SELECT nodes FROM eql_v4_internal.json_tree_index(doc::jsonb))
                                      ->> eql_v4_internal.json_tree_self_tag(eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'), decode($1::text, 'base64'))) AS j,
                                    decode(doc::jsonb -> 'sv' -> ((SELECT nodes FROM eql_v4_internal.json_tree_index(doc::jsonb))
                                      ->> eql_v4_internal.json_tree_self_tag(eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'), decode($1::text, 'base64')))::integer ->> 's', 'base64') AS s) AS q
                     )::public.eql_v4_json_search WHERE id = $5",
                    &[&from_key.tokens()[0], &to_key.tokens()[0], &width, &member, &id],
                )
                .unwrap();
            }
        }
        for path in &paths {
            let key = wait(
                &runtime,
                keyset.json_subtree_key(path, &JsonOptions::default(), column()),
            )
            .unwrap();
            let expected = path.select(&plain).first().cloned().cloned();
            let allowed = same_selector_values(&plain, path);
            for budget in [0, 1] {
                let mut rows = subtree_rows(&mut db, "json_tree_tamper", id, &key, budget);
                if truncate_rows && rows.len() > 1 {
                    let _ = rows.pop();
                }
                let opened: Result<Option<Value>, stack_encrypt::Error> =
                    wait(&runtime, read_optional(&cipher, &key, rows));
                let outcome = match opened {
                    Err(_) => "refused",
                    Ok(found) if found == expected => "the right answer",
                    Ok(None) => "withheld",
                    Ok(Some(found)) if allowed.contains(&found) => "another element at the selector",
                    Ok(found) => panic!(
                        "round {round}, {what}: {path} at budget {budget} opened to {found:?}, where jsonb holds {expected:?}"
                    ),
                };
                *outcomes.entry(outcome).or_default() += 1;
            }
        }
    }
    assert!(
        outcomes.get("refused").copied().unwrap_or(0) > 0,
        "{outcomes:?}"
    );
    assert!(
        outcomes.get("the right answer").copied().unwrap_or(0) > 0,
        "{outcomes:?}"
    );
    eprintln!("tampering outcomes: {outcomes:?}");
}

// =============================================================================
// Hostile documents
// =============================================================================

/// A document built in SQL: a root, then `levels` levels each holding
/// `copies` entries, every one a member (selector all zero) of the level
/// above with that member's self tag, at the ordinals `0 … copies − 1` when
/// `spread`, else all at ordinal 0 (one parent tag, repeated). `flags` is
/// the header's flags byte. Built from the SQL chain primitives, as whoever
/// holds the all-zero token could build one.
fn forged_chain(flags: i32, levels: i64, copies: i64, spread: bool) -> String {
    let ordinal = if spread { "copy.c" } else { "0" };
    format!(
        "WITH RECURSIVE k AS (
           SELECT set_byte(set_byte(decode(repeat('00', 40), 'hex'), 0, 1), 1, {flags}) AS h,
                  decode(repeat('00', 16), 'hex') AS iv
         ), link(n, t) AS (
             SELECT 0, decode(repeat('00', 16), 'hex')
           UNION ALL
             SELECT n + 1, eql_v4_internal.json_tree_member_token(t, decode(repeat('00', 16), 'hex')) FROM link WHERE n < {last}
         ), copy(c) AS (SELECT generate_series(0, {copies} - 1))
         SELECT (jsonb_build_object(
           'v', 4, 'i', jsonb_build_object('t', 'users', 'c', 'profile'),
           'h', (SELECT encode(h, 'base64') FROM k),
           'sv', jsonb_build_array(jsonb_build_object('s', 'AAAAAAAAAAAAAAAAAAAAAA==', 'c', '00',
                   'x', (SELECT eql_v4_internal.json_tree_self_tag(k.iv, decode(repeat('00', 16), 'hex')) FROM k)))
                 || (SELECT jsonb_agg(jsonb_build_object(
                       's', 'AAAAAAAAAAAAAAAAAAAAAA==', 'c', to_hex(copy.c),
                       'x', eql_v4_internal.json_tree_self_tag(k.iv, eql_v4_internal.json_tree_member_token(link.t, decode(repeat('00', 16), 'hex'))),
                       'p', eql_v4_internal.json_tree_parent_tag(k.iv, link.t, {ordinal})) ORDER BY n, copy.c)
                     FROM link, k, copy),
           'q', '{{\"sv\": [], \"el\": []}}'::jsonb))::public.eql_v4_json_search",
        last = levels - 1
    )
}

/// Needs an EQL v4 installation. A stored document is untrusted input: its
/// self tags and parent tags are not authenticated, so whoever holds a
/// token can write a chain of them deeper than any sealed document. The
/// read, which carries no depth bound, still ends: here a chain of 300,
/// past the 127 levels a sealed document can nest, under the sealed root
/// and not, in full and past a budget. `statement_timeout` turns a read
/// that would not end into a failure instead of a hung suite.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_walks_end_on_hostile_documents() {
    let mut db = connect();
    db.batch_execute("SET statement_timeout = '10s'").unwrap();
    let token = vec!["AAAAAAAAAAAAAAAAAAAAAA==".to_owned()];
    for (flags, budget, expected) in [(0, 0, 301), (0, 64, 301), (1, 0, 301), (1, 64, 1)] {
        let doc = forged_chain(flags, 300, 1, false);
        let walked: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_subtree(d.doc, $1::text[], {budget}) e"),
                &[&token],
            )
            .unwrap_or_else(|error| panic!("flags {flags}, budget {budget}: {error}"))
            .get(0);
        assert_eq!(
            walked, expected,
            "flags {flags}, budget {budget}: the root and its chain"
        );
        let children: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_children(d.doc, $1::text) e"),
                &[&token[0]],
            )
            .unwrap()
            .get(0);
        assert_eq!(children, 1);
    }
}

/// Needs an EQL v4 installation. Entries that share a parent tag do not
/// multiply a read. Here every level of a 60-level chain is written twice:
/// two entries with the same `p`, so the same parent and ordinal, the same
/// `s` and the same self tag, told apart only by `c`. The map keeps one
/// entry per tag, so the read returns one row per level and the root, under
/// no budget (`0`), under an open root, and under a budget above the entry
/// count, and still falls back past a budget below it.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_walks_do_not_multiply_on_duplicated_entries() {
    let mut db = connect();
    db.batch_execute("SET statement_timeout = '10s'").unwrap();
    const LEVELS: i64 = 60;
    let token = vec!["AAAAAAAAAAAAAAAAAAAAAA==".to_owned()];
    let entries = 1 + 2 * LEVELS;
    for (flags, budget, expected) in [
        (0, 0, LEVELS + 1),
        (1, 0, LEVELS + 1),
        (0, 10, LEVELS + 1),
        (1, 200, LEVELS + 1),
        (1, 10, 1),
    ] {
        let doc = forged_chain(flags, LEVELS, 2, false);
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
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_subtree(d.doc, $1::text[], {budget}) e"),
                &[&token],
            )
            .unwrap_or_else(|error| panic!("flags {flags}, budget {budget}: {error}"))
            .get(0);
        assert_eq!(walked, expected, "flags {flags}, budget {budget}");
        assert!(walked <= entries);
        let children: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_children(d.doc, $1::text) e"),
                &[&token[0]],
            )
            .unwrap()
            .get(0);
        assert_eq!(children, 1, "flags {flags}");
    }
}

/// Needs an EQL v4 installation. A member's token is a hash of its
/// parent's and its selector, not of the probe that found it, so two
/// entries forged under one parent, at ordinals 0 and 1, with one selector
/// and the member rule's self tag, derive one token: the read visits the
/// subtree beneath it once for each, and level after level the rows would
/// double, 2^60 for 60 levels. The read takes its recursion through `LIMIT`
/// the entry count times the number of tokens, so it ends at that, and
/// returns no more rows than that under any budget.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_walks_do_not_multiply_on_forged_member_tags() {
    let mut db = connect();
    db.batch_execute("SET statement_timeout = '10s'").unwrap();
    const LEVELS: i64 = 60;
    let token = vec!["AAAAAAAAAAAAAAAAAAAAAA==".to_owned()];
    let entries = 1 + 2 * LEVELS;
    for (flags, budget) in [(0, 0), (1, 0), (1, 64), (1, 1000)] {
        let doc = forged_chain(flags, LEVELS, 2, true);
        let walked: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_subtree(d.doc, $1::text[], {budget}) e"),
                &[&token],
            )
            .unwrap_or_else(|error| panic!("flags {flags}, budget {budget}: {error}"))
            .get(0);
        assert!(
            walked <= entries,
            "flags {flags}, budget {budget}: {walked} rows"
        );
        if flags == 1 && budget == 64 {
            assert_eq!(walked, 1, "past the budget, the sealed root");
        }
        let children: i64 = db
            .query_one(
                &format!("SELECT count(*) FROM ({doc}) AS d(doc), eql_v4.json_tree_children(d.doc, $1::text) e"),
                &[&token[0]],
            )
            .unwrap()
            .get(0);
        assert_eq!(children, 2, "flags {flags}: both forged children");
    }
}
