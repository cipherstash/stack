//! The worlds the harness compares: handcrafted columns that exercise every
//! clause, and a proptest generator of random columns over a small, shared
//! key vocabulary, so that rows have paths and values in common and the
//! equality patterns are rich.

use proptest::prelude::*;
use serde_json::{json, Map, Value};
use stack_encrypt::json::JsonPath;

use super::profile::{Column, Query};

/// A column, its rows and the queries sent to it.
#[derive(Clone, Debug)]
pub struct World {
    pub name: &'static str,
    pub column: Column,
    pub docs: Vec<Value>,
    pub queries: Vec<Query>,
}

fn ordered(paths: &[&str]) -> Vec<JsonPath> {
    paths.iter().map(|p| JsonPath::parse(p).unwrap()).collect()
}

/// The design's fixture document, with the shapes of `json_index.rs` around
/// it and rows that vary it, so that each clause has something to show.
fn shapes() -> Vec<Value> {
    vec![
        json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1}),
        json!({"hello": "world-2", "nested": {"deep": "constant", "list": [{"x": 2}]}, "number": 5}),
        json!({"hello": "world-1", "nested": {"list": [{"x": 1, "y": [true, null]}, 3, [4, {"x": 1}]]}, "number": -2}),
        json!({"number": 3, "nested": {"deep": "other", "list": []}, "zeta": {"k": "v", "a": 1}}),
        json!({"a": "b", "a b": 1, "é": [], "0": {}}),
        json!({"a": {"b": {"c": {"d": [1, "x", false]}}}}),
        json!({"n": 18446744073709551615u64, "m": -9223372036854775808i64, "f": 1e300, "g": 2.5}),
        json!([[1, 2], [3, [4, {"a": null}]]]),
        json!([{"x": 1}, {"y": 2}]),
        json!({}),
        json!([]),
        json!("a"),
        json!(2.5),
        json!(null),
        json!(true),
    ]
}

fn shape_queries(sealed_root: bool) -> Vec<Query> {
    // `$.nested` is only ever read through gates, so its token is sent but
    // nothing under it is named whole: what that token reaches beyond the
    // paths asked is the page's subtree-read clause. `$.zeta` is read twice,
    // for determinism.
    let mut queries = vec![
        Query::Subtree("$.nested.list".into()),
        Query::Subtree("$.nested.list[1]".into()),
        Query::Subtree("$.nested.list[*].x".into()),
        Query::Subtree("$.zeta".into()),
        Query::Subtree("$[1]".into()),
        Query::Subtree("$[1][1]".into()),
        Query::Subtree("$.zeta".into()),
        Query::Extract("$.nested.list[0].x".into()),
        Query::Extract("$.nested.list[1].x".into()),
        Query::Extract("$.hello".into()),
        Query::Extract("$".into()),
        Query::Contains(json!({"nested": {"list": [{"x": 1}]}})),
        Query::Contains(json!("a")),
        Query::Contains(json!({"hello": "world-1"})),
        Query::Contains(json!([{"x": 1}])),
        Query::Equals("$.hello".into(), json!("world-1")),
        Query::Equals("$.nested.list[*].x".into(), json!(2)),
        Query::Order("$.number".into(), json!(0)),
        Query::Order("$.nested.list[*].x".into(), json!(2)),
        Query::Order("$.number".into(), json!(5)),
        Query::Order("$.number".into(), json!(0)),
    ];
    if !sealed_root {
        queries.extend([
            Query::Subtree("$".into()),
            Query::Subtree("$.a.b".into()),
            Query::Subtree("$[*].x".into()),
        ]);
    }
    queries
}

/// A column that orders strings, so the string half of the ordering clause
/// has something to compare (a world orders one kind of leaf; see
/// [`super::profile::Ids::ordering_ranks`]).
fn names() -> World {
    World {
        name: "ordered strings",
        column: Column {
            sealed_root: true,
            ordered: ordered(&["$.name", "$.tags[*]"]),
        },
        docs: vec![
            json!({"name": "carol", "tags": ["b", "aa"]}),
            json!({"name": "al", "tags": ["aa"]}),
            json!({"name": "carol", "age": 3}),
            json!({"name": "bob", "tags": []}),
            json!({"tags": ["zzzzzzzz", "b"]}),
        ],
        queries: vec![
            Query::Order("$.name".into(), json!("b")),
            Query::Order("$.tags[*]".into(), json!("aa")),
            Query::Subtree("$.tags".into()),
            Query::Subtree("$.tags[1]".into()),
        ],
    }
}

/// A column with three wide top-level objects, each read whole, so that
/// whether members' ordinals follow their keys' order is decidable rather
/// than a coin toss (see `distinguishers::member_ordinals_follow_key_order`).
fn wide() -> World {
    let object = |prefix: &str, n: usize| {
        Value::Object(
            (0..n)
                .map(|i| (format!("{prefix}{i}"), Value::from(i as u64)))
                .collect(),
        )
    };
    World {
        name: "wide objects",
        column: Column {
            sealed_root: true,
            ordered: Vec::new(),
        },
        docs: vec![
            json!({"w1": object("a", 8), "w2": object("b", 8), "w3": object("c", 8)}),
            json!({"w1": object("a", 5), "w3": object("c", 8)}),
        ],
        queries: vec![
            Query::Subtree("$.w1".into()),
            Query::Subtree("$.w2".into()),
            Query::Subtree("$.w3".into()),
        ],
    }
}

/// The handcrafted worlds: the shapes under each root option, and a column
/// of ordered strings.
pub fn handcrafted() -> Vec<World> {
    vec![
        World {
            name: "shapes, sealed root",
            column: Column {
                sealed_root: true,
                ordered: ordered(&["$.number", "$.nested.list[*].x"]),
            },
            docs: shapes(),
            queries: shape_queries(true),
        },
        World {
            name: "shapes, open root",
            column: Column {
                sealed_root: false,
                ordered: ordered(&["$.number", "$.nested.list[*].x"]),
            },
            docs: shapes(),
            queries: shape_queries(false),
        },
        names(),
        wide(),
    ]
}

// =============================================================================
// Random columns
// =============================================================================

const KEYS: &[&str] = &["a", "b", "c", "list", "n", "name", "tags", "zz"];

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (-3i64..6).prop_map(Value::from),
        prop::sample::select(vec!["x", "yy", "x", "zzz", "ab", ""]).prop_map(Value::from),
    ]
}

fn object(
    inner: impl Strategy<Value = Value>,
    size: std::ops::Range<usize>,
) -> impl Strategy<Value = Value> {
    prop::collection::btree_map(prop::sample::select(KEYS), inner, size).prop_map(|members| {
        Value::Object(
            members
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect::<Map<String, Value>>(),
        )
    })
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            object(inner, 0..4),
        ]
    })
}

/// Every value under the key `n` made a number, since the random columns
/// order `$.n` and `$.list[*].n` and a world orders one kind of leaf.
fn numberize(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let v = if k == "n" && !v.is_number() {
                        Value::from(i64::try_from(v.to_string().len() % 7).unwrap())
                    } else {
                        numberize(v)
                    };
                    (k, v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(numberize).collect()),
        other => other,
    }
}

fn document() -> impl Strategy<Value = Value> {
    prop_oneof![
        8 => object(value(), 0..5),
        1 => prop::collection::vec(value(), 0..3).prop_map(Value::Array),
        1 => leaf(),
    ]
    .prop_map(numberize)
}

fn query(sealed_root: bool) -> impl Strategy<Value = Query> {
    let mut subtree = vec![
        "$.a",
        "$.list",
        "$.list[0]",
        "$.list[1]",
        "$.list[1].n",
        "$.a.b",
        "$.list[*].a",
        "$.tags[0].a",
        "$.a.list[2]",
        "$[0]",
        "$[1].a",
        "$[0][1]",
        "$.a.tags[*]",
    ];
    if !sealed_root {
        subtree.extend(["$", "$[*].a", "$.list[*]"]);
    }
    prop_oneof![
        3 => prop::sample::select(subtree).prop_map(|p| Query::Subtree(p.into())),
        2 => prop::sample::select(vec!["$", "$.a", "$.a.b", "$.list[0].n", "$.list[3].n", "$.tags[*]"])
            .prop_map(|p| Query::Extract(p.into())),
        2 => prop_oneof![
            leaf(),
            object(leaf(), 1..3),
            prop::collection::vec(leaf(), 1..3).prop_map(Value::Array),
            object(prop::collection::vec(object(leaf(), 1..2), 1..2).prop_map(Value::Array), 1..2),
        ]
        .prop_map(|v| Query::Contains(numberize(v))),
        1 => (prop::sample::select(vec!["$.a", "$.tags[0]", "$.list[*].b"]),
              prop_oneof![(-3i64..6).prop_map(Value::from), prop::sample::select(vec!["x", "ab"]).prop_map(Value::from)])
            .prop_map(|(p, v)| Query::Equals(p.into(), v)),
        1 => (prop::sample::select(vec!["$.n", "$.list[*].n"]), -3i64..6)
            .prop_map(|(p, v)| Query::Order(p.into(), Value::from(v))),
    ]
}

/// A random column: a root option, two to six documents, and four to ten
/// queries, some of which repeat.
pub fn random_world() -> impl Strategy<Value = World> {
    any::<bool>().prop_flat_map(|sealed_root| {
        (
            prop::collection::vec(document(), 2..7),
            prop::collection::vec(query(sealed_root), 4..11),
        )
            .prop_map(move |(docs, queries)| World {
                name: "random",
                column: Column {
                    sealed_root,
                    ordered: ordered(&["$.n", "$.list[*].n"]),
                },
                docs,
                queries,
            })
    })
}
