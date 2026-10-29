//! The compiled predicate end to end: documents sealed by Stack Encrypt's
//! JSON index, jsonpath predicates compiled by the `match` operator through
//! a data plan over eql-bindings' target table, with a resolver that names
//! the compiled predicate domain ([`Eql`]; the Go guest's does not yet),
//! and `eql_v4.json_tree_match` and `@@` over the stored column,
//! against PostgreSQL's own `jsonb_path_match` over the plaintexts and
//! against the WHERE a hand writes from the operators the leaves stand for.

use super::elements::{derive, eql_text, frame_of, Eql};
use super::*;

use stack_encrypt::dynamic::{self, record, OpSpec, Operand};
use stack_encrypt::KeysetCipher;

/// The paths the documents order: what the predicates' ranges ask at.
const ORDERED: [&str; 4] = [
    "$.age",
    "$.name",
    "$.contacts[*].calls",
    "$.contacts[*].relationship",
];

fn people_options() -> JsonOptions {
    JsonOptions::default().ordering(ORDERED).unwrap()
}

/// `profile` under `users/profile`, the column the documents are sealed
/// under, naming `JsonSearch` with [`people_options`].
fn people_plan() -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "null": "sql",
            "target": {"name": "JsonSearch", "options": {"ordered": ORDERED}}
        }
    });
    record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Eql).unwrap()
}

/// Documents with every field absent, `null` or a value of the one type its
/// path holds, and arrays only where the predicates name `[*]`.
fn people() -> Vec<Value> {
    vec![
        json!({"age": 34, "name": "ann", "tags": ["admin", "ops"],
               "contacts": [{"relationship": "sibling", "calls": 3},
                            {"relationship": "friend", "calls": 7}]}),
        json!({"age": 17, "name": "bob",
               "contacts": [{"relationship": "friend", "calls": 9},
                            {"relationship": "sibling", "calls": 7}]}),
        json!({"age": null, "name": "cat", "tags": []}),
        json!({"name": null, "contacts": []}),
        json!({}),
        json!({"age": 60, "tags": ["ops"], "contacts": [{"relationship": "sibling"}]}),
        json!({"age": 18, "name": "dan", "ok": true}),
    ]
}

/// Each row's answer under `sql`, which takes `params`, NULL as `None`.
fn answers(
    db: &mut postgres::Client,
    sql: &str,
    params: &[&(dyn postgres::types::ToSql + Sync)],
) -> Vec<(i32, Option<bool>)> {
    db.query(sql, params)
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

/// `match`'s operand for `predicate` under `vars`.
fn compiled(
    runtime: &tokio::runtime::Runtime,
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    predicate: &str,
    vars: &Value,
) -> String {
    eql_text(&derive(
        runtime,
        keyset,
        plan,
        "match",
        json!({"predicate": predicate, "vars": vars.to_string(), "wildcard_bound": 4}),
    ))
}

/// Needs an EQL v4 installation. For each predicate, `json_tree_match` and
/// `@@` over the encrypted column answer what `jsonb_path_match` answers of
/// the same predicate and variables over the plaintexts, row by row, NULL
/// included: equality, `!=` and the orderings with absent paths and JSON
/// `null`s, wildcards, filters, and `&&`, `||` and `!` over them.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_compiled_predicate_answers_as_jsonb_path_match() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_people",
        &people_options(),
        &people(),
    );
    let vars = json!({"min": 18, "who": "ann", "r": "sibling", "n": 5, "tag": "ops"});
    for predicate in [
        "$.age >= $min",
        "!($.age >= $min)",
        "$.age < 18",
        "$.age == null",
        "$.age != null",
        "$.age != 34",
        "$.name == $who",
        "$.name != $who",
        "$.name > \"bob\"",
        "!($.name <= \"bob\")",
        "$.ok == true",
        "exists($.tags)",
        "exists($.tags[*])",
        "$.tags[*] == $tag",
        "exists($.tags[*] ? (@ == $tag))",
        "$.contacts[*].calls > $n",
        "$.contacts[*].relationship == $r",
        "exists($.contacts[*] ? (@.relationship == $r))",
        "exists($.contacts[*] ? (@.relationship == $r && @.calls > $n))",
        "!exists($.contacts[*] ? (@.relationship == $r && @.calls > $n))",
        "$.age >= $min && exists($.contacts[*] ? (@.relationship == $r && @.calls > $n))",
        "$.name == $who || $.tags[*] == $tag",
        "!($.age < $min || $.name == null) && exists($.name)",
        "$.age > 20 && $.age < 50",
    ] {
        let operand = compiled(&runtime, &keyset, &plan, predicate, &vars);
        let matched = answers(
            &mut db,
            "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
               FROM json_tree_people ORDER BY id",
            &[&operand],
        );
        let by_operator = answers(
            &mut db,
            "SELECT id, doc @@ $1::text::jsonb::eql_v4.query_json_predicate \
               FROM json_tree_people ORDER BY id",
            &[&operand],
        );
        let plaintext = answers(
            &mut db,
            "SELECT id, jsonb_path_match(plain, $1::text::jsonpath, $2::text::jsonb) \
               FROM json_tree_people ORDER BY id",
            &[&predicate, &vars.to_string()],
        );
        assert_eq!(matched, plaintext, "{predicate}: against jsonb_path_match");
        assert_eq!(by_operator, matched, "{predicate}: @@ is json_tree_match");
    }
}

/// Needs an EQL v4 installation. A compiled predicate answers what the
/// hand-written WHERE answers, NULL included, each leaf by the operand its
/// own operator derives: `json_tree_path_exists` for the path, `@>` for
/// the `null` needle and the equalities, `->` and `>=` for the ordering,
/// and `json_tree_element_match` for the filter. And what `match` refuses
/// it refuses before anything is derived, at the offset of the construct.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_compiled_predicate_answers_as_its_operators() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_operators",
        &people_options(),
        &people(),
    );
    let one =
        |operator: &str, input: Value| eql_text(&derive(&runtime, &keyset, &plan, operator, input));
    let Operand::Text(age) = derive(
        &runtime,
        &keyset,
        &plan,
        "selector",
        json!({"path": "$.age"}),
    ) else {
        panic!("a selector is text")
    };
    let null_age = one("eq_at", json!({"path": "$.age", "json": "null"}));
    let at_least = one("gte_at", json!({"path": "$.age", "json": "18"}));
    let sibling_over_five = one(
        "element_match",
        json!({"path": "$.contacts[*]", "wildcard_bound": 4, "predicates": [
            {"member": "relationship", "op": "eq", "json": "\"sibling\""},
            {"member": "calls", "op": "gt", "json": "5"},
        ]}),
    );
    let ann = one("eq_at", json!({"path": "$.name", "json": "\"ann\""}));

    let predicate =
        "!($.age >= 18 && exists($.contacts[*] ? (@.relationship == \"sibling\" && @.calls > 5))) \
                     || $.name == \"ann\"";
    let operand = compiled(&runtime, &keyset, &plan, predicate, &json!({}));
    let matched = answers(
        &mut db,
        "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
           FROM json_tree_operators ORDER BY id",
        &[&operand],
    );
    let written = answers(
        &mut db,
        "SELECT id, (NOT (eql_v4.json_tree_path_exists(doc, $1::text) \
                         AND NOT (doc @> $2::text::jsonb::eql_v4.query_json) \
                         AND (doc -> $1::text) >= $3::text::jsonb::eql_v4.query_json_leaf \
                         AND eql_v4.json_tree_element_match(doc, $4::text::jsonb::eql_v4.query_json_elements))) \
                    OR doc @> $5::text::jsonb::eql_v4.query_json \
           FROM json_tree_operators ORDER BY id",
        &[&age, &null_age, &at_least, &sibling_over_five, &ann],
    );
    assert_eq!(
        matched, written,
        "the tree against the operators written out"
    );
    let plaintext = answers(
        &mut db,
        "SELECT id, jsonb_path_match(plain, $1::text::jsonpath) FROM json_tree_operators ORDER BY id",
        &[&predicate],
    );
    assert_eq!(matched, plaintext, "and against jsonb_path_match");

    for (text, reason, at) in [
        ("$.age + 1 > 18", "json_predicate_unsupported", 6),
        ("$.name like_regex \"^a\"", "json_predicate_unsupported", 7),
        ("$.age.size() > 1", "json_predicate_unsupported", 5),
        (
            "$.tags[*] != \"ops\"",
            "json_predicate_not_equal_at_wildcard",
            10,
        ),
        ("$.age > $missing", "json_predicate_unknown_variable", 8),
    ] {
        let error = dynamic::check_query(
            &plan,
            "profile",
            OpSpec::Match,
            frame_of(&json!({"predicate": text})),
            &Eql,
        )
        .unwrap_err();
        let payload = stack_encrypt::ErrorPayload::payload(&error);
        assert_eq!(payload["reason"], json!(reason), "{text}: {payload:?}");
        assert_eq!(payload["at"], json!(at), "{text}: {payload:?}");
    }
    let error = dynamic::check_query(
        &plan,
        "profile",
        OpSpec::Match,
        frame_of(&json!({"predicate": "$.height > 1"})),
        &Eql,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            dynamic::Error::Cipher(stack_encrypt::Error::Term(
                stack_encrypt::sem::TermError::JsonPathNotOrdered
            ))
        ),
        "a range at a path the column does not order: {error:?}"
    );
}

/// SQLSTATE `check_violation`, a value its domain's CHECK refuses.
const CHECK_VIOLATION: &str = "23514";
/// SQLSTATE `raise_exception`, which an operator blocker raises.
const RAISE_EXCEPTION: &str = "P0001";
/// SQLSTATE `ambiguous_function`, an operator PostgreSQL cannot choose.
const AMBIGUOUS_FUNCTION: &str = "42725";
/// SQLSTATE `invalid_parameter_value`, which a probe's hit raises with.
const INVALID_PARAMETER_VALUE: &str = "22023";

/// The SQLSTATE a statement fails with, or `None` if it succeeds.
fn sqlstate(
    db: &mut postgres::Client,
    sql: &str,
    params: &[&(dyn postgres::types::ToSql + Sync)],
) -> Option<String> {
    match db.query(sql, params) {
        Ok(_) => None,
        Err(error) => match error.as_db_error() {
            Some(e) => Some(e.code().code().to_owned()),
            None => panic!("{sql}: not a database error: {error}"),
        },
    }
}

/// A JSON value as an SQL string literal.
fn literal(value: &Value) -> String {
    let text = match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    format!("'{}'", text.replace('\'', "''"))
}

/// The WHERE a hand writes from the operators a compiled tree's leaves
/// stand for, over the column `doc`, each leaf's operand inlined: `@>`
/// for `contains`, `json_tree_path_exists` for `exists`, `->` and the
/// orderings for `cmp`, and `json_tree_element_match` for `elements`.
fn written(tree: &Value) -> String {
    let node = tree.as_object().expect("a node is an object");
    assert_eq!(node.len(), 1, "a node has one key: {tree}");
    let (kind, operand) = node.iter().next().unwrap();
    let list = |join: &str| {
        let parts: Vec<String> = operand.as_array().unwrap().iter().map(written).collect();
        format!("({})", parts.join(join))
    };
    match kind.as_str() {
        "and" => list(" AND "),
        "or" => list(" OR "),
        "not" => format!("(NOT {})", written(operand)),
        "contains" => format!("(doc @> {}::jsonb::eql_v4.query_json)", literal(operand)),
        "exists" => format!(
            "eql_v4.json_tree_path_exists(doc, {}::text)",
            literal(operand)
        ),
        "cmp" => {
            let parts: Vec<String> = operand
                .as_object()
                .unwrap()
                .iter()
                .map(|(bound, leaf)| {
                    let op = match bound.as_str() {
                        "gt" => ">",
                        "gte" => ">=",
                        "lt" => "<",
                        "lte" => "<=",
                        other => panic!("a bound named {other}"),
                    };
                    format!(
                        "((doc -> {}::text) {op} {}::jsonb::eql_v4.query_json_leaf)",
                        literal(&leaf["s"]),
                        literal(leaf)
                    )
                })
                .collect();
            format!("({})", parts.join(" AND "))
        }
        "elements" => format!(
            "eql_v4.json_tree_element_match(doc, {}::jsonb::eql_v4.query_json_elements)",
            literal(operand)
        ),
        other => panic!("a node of kind {other}"),
    }
}

/// The first node of `kind` in `tree`, depth first.
fn find<'a>(tree: &'a Value, kind: &str) -> Option<&'a Value> {
    let (key, operand) = tree.as_object()?.iter().next()?;
    if key == kind {
        return Some(tree);
    }
    match operand {
        Value::Array(children) => children.iter().find_map(|child| find(child, kind)),
        Value::Object(_) if key == "not" => find(operand, kind),
        _ => None,
    }
}

/// Each row's answer under the compiled `operand` by `json_tree_match`,
/// by `@@`, and under the WHERE written from it, in `table`.
fn three_ways(
    db: &mut postgres::Client,
    table: &str,
    operand: &str,
) -> [Vec<(i32, Option<bool>)>; 3] {
    let tree: Value = serde_json::from_str(operand).unwrap();
    [
        answers(
            db,
            &format!(
                "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
                   FROM {table} ORDER BY id"
            ),
            &[&operand],
        ),
        answers(
            db,
            &format!(
                "SELECT id, doc @@ $1::text::jsonb::eql_v4.query_json_predicate FROM {table} ORDER BY id"
            ),
            &[&operand],
        ),
        answers(
            db,
            &format!("SELECT id, {} FROM {table} ORDER BY id", written(&tree)),
            &[],
        ),
    ]
}

/// Each row's answer under `jsonb_path_match` of `predicate` over the
/// plaintexts in `table`.
fn plaintext(db: &mut postgres::Client, table: &str, predicate: &str) -> Vec<(i32, Option<bool>)> {
    answers(
        db,
        &format!("SELECT id, jsonb_path_match(plain, $1::text::jsonpath) FROM {table} ORDER BY id"),
        &[&predicate],
    )
}

/// Needs an EQL v4 installation. The predicate domain's CHECK takes
/// one-key nodes, each kind's operand by its own domain's rule, and refuses
/// everything else. The values are operands the engine derived and their
/// parts: selectors, a needle, a root scalar's needle with its `alt`, leaf
/// operands at two paths, an element predicate and one of its tokens.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_predicate_domain_checks_each_node() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    let one = |operator: &str, input: Value| -> Value {
        serde_json::from_str(&eql_text(&derive(
            &runtime, &keyset, &plan, operator, input,
        )))
        .unwrap()
    };
    let Operand::Text(selector) = derive(
        &runtime,
        &keyset,
        &plan,
        "selector",
        json!({"path": "$.age"}),
    ) else {
        panic!("a selector is text")
    };
    let needle = one("eq_at", json!({"path": "$.name", "json": "\"ann\""}));
    let root_one = one("contains", json!({"json": "1"}));
    assert!(
        root_one.get("alt").is_some(),
        "a root scalar's needle has an alt"
    );
    let leaf = one("gt_at", json!({"path": "$.age", "json": "18"}));
    let other = one("gt_at", json!({"path": "$.name", "json": "\"a\""}));
    let elements = one(
        "element_match",
        json!({"path": "$.contacts[*]", "wildcard_bound": 1, "predicates": [
            {"member": "calls", "op": "gt", "json": "5"}
        ]}),
    );
    let token = &elements["m"][0]["t"][0];
    let compiled_tree: Value = serde_json::from_str(&compiled(
        &runtime,
        &keyset,
        &plan,
        "$.age >= 18 && (exists($.tags) || !($.name == \"ann\")) \
         && exists($.contacts[*] ? (@.calls > 5))",
        &json!({}),
    ))
    .unwrap();
    let without = |value: &Value, key: &str| {
        let mut value = value.clone();
        let _ = value.as_object_mut().unwrap().remove(key);
        value
    };

    let valid = [
        compiled_tree,
        json!({"exists": selector}),
        json!({"contains": needle}),
        json!({"contains": root_one}),
        json!({"cmp": {"gt": leaf}}),
        json!({"cmp": {"gte": leaf, "lt": leaf}}),
        json!({"elements": elements}),
        json!({"not": {"exists": selector}}),
        json!({"and": [{"exists": selector}, {"or": [{"cmp": {"lte": leaf}}]}]}),
    ];
    let invalid = [
        ("not an object", json!([])),
        ("no key", json!({})),
        (
            "two keys",
            json!({"exists": selector, "not": {"exists": selector}}),
        ),
        ("an unknown kind", json!({"xor": []})),
        ("an empty and", json!({"and": []})),
        ("an empty or", json!({"or": []})),
        ("an and not a list", json!({"and": {"exists": selector}})),
        ("an invalid child", json!({"or": [{"exists": 1}]})),
        (
            "a deep invalid child",
            json!({"not": {"not": {"and": [{}]}}}),
        ),
        ("not of a list", json!({"not": [{"exists": selector}]})),
        ("exists not text", json!({"exists": [selector]})),
        (
            "a needle missing el",
            json!({"contains": without(&needle, "el")}),
        ),
        (
            "a needle with a bad pair",
            json!({"contains": {"sv": [{"s": 1}], "el": []}}),
        ),
        ("no bound", json!({"cmp": {}})),
        ("a bound by another name", json!({"cmp": {"eq": leaf}})),
        (
            "two lower bounds",
            json!({"cmp": {"gt": leaf, "gte": leaf}}),
        ),
        (
            "bounds at two selectors",
            json!({"cmp": {"gt": leaf, "lt": other}}),
        ),
        (
            "a bound with no term",
            json!({"cmp": {"gt": without(&leaf, "op")}}),
        ),
        (
            "cmp with tokens",
            json!({"cmp": {"t": [token], "gt": leaf}}),
        ),
        ("elements with no members", json!({"elements": {"m": []}})),
        (
            "elements of bounds alone",
            json!({"elements": {"m": [{"gt": leaf}]}}),
        ),
    ];
    let cast = "SELECT $1::text::jsonb::eql_v4.query_json_predicate";
    for value in &valid {
        assert_eq!(
            sqlstate(&mut db, cast, &[&value.to_string()]),
            None,
            "valid: {value}"
        );
    }
    for (why, value) in &invalid {
        assert_eq!(
            sqlstate(&mut db, cast, &[&value.to_string()]).as_deref(),
            Some(CHECK_VIOLATION),
            "{why}: {value}"
        );
    }
    // The element member's CHECK, through the bounds validator the two
    // domains share, refuses what it refused.
    let mut member_and_more = elements["m"][0].clone();
    let _ = member_and_more
        .as_object_mut()
        .unwrap()
        .insert("x".into(), json!(1));
    for (why, value) in [
        ("no tokens", json!({"m": [{"gt": leaf}]})),
        ("no bound", json!({"m": [{"t": [token]}]})),
        ("another key", json!({"m": [member_and_more]})),
    ] {
        assert_eq!(
            sqlstate(
                &mut db,
                "SELECT $1::text::jsonb::eql_v4.query_json_elements",
                &[&value.to_string()]
            )
            .as_deref(),
            Some(CHECK_VIOLATION),
            "{why}: {value}"
        );
    }
}

/// Needs an EQL v4 installation. For every predicate over every document:
/// `json_tree_match` and `@@` answer what the WHERE written from the
/// compiled tree's leaves answers, NULL included, and `jsonb_path_match`
/// what all three answer, over the plaintext the document was sealed
/// from. Every field is absent, `null` or a value of the one type its path
/// holds.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_compiled_predicate_answers_as_the_operators_written_out() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_written",
        &people_options(),
        &[
            json!({"age": 1, "name": "ann", "tags": ["a", "b"]}),
            json!({"age": 3, "name": "bob"}),
            json!({"age": 5, "tags": []}),
            json!({"age": null, "name": null}),
            json!({}),
            json!({"name": "dan", "tags": ["c"]}),
            json!({"age": 3, "ok": true, "tags": ["a"]}),
        ],
    );
    for predicate in [
        "$.age == 3",
        "$.age != 3",
        "$.age == null",
        "$.age != null",
        "$.age < 3",
        "!($.age < 3)",
        "$.age >= 3",
        "$.name > \"ann\"",
        "$.name != \"ann\"",
        "$.ok == true",
        "$.ok != true",
        "exists($.tags)",
        "exists($.tags[*])",
        "$.tags[*] == \"a\"",
        "exists($.tags[*] ? (@ == \"c\"))",
        "$.age > 1 && $.name == \"bob\" || !exists($.tags)",
        "$.age >= 1 && $.age <= 3",
        "!($.age >= 2 || $.name == \"dan\")",
    ] {
        let operand = compiled(&runtime, &keyset, &plan, predicate, &json!({}));
        let [matched, by_operator, by_hand] = three_ways(&mut db, "json_tree_written", &operand);
        assert_eq!(matched, by_hand, "{predicate}: against the WHERE");
        assert_eq!(by_operator, matched, "{predicate}: @@ is json_tree_match");
        assert_eq!(
            matched,
            plaintext(&mut db, "json_tree_written", predicate),
            "{predicate}: against jsonb_path_match"
        );
    }
}

/// Needs an EQL v4 installation. A NULL leaf follows SQL's three-valued
/// logic: an ordering of a node with no ordering term (a boolean at an
/// ordered path) is NULL, and so is `not` of it; `and` with a false child
/// is false and `or` with a true one true. jsonpath answers each the same:
/// a boolean against a number is unknown. The ordering leaf alone, without
/// the guards `match` puts beside it, is NULL also where the path is
/// absent, as `(col -> s) < $1` is.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_null_leaf_is_unknown_under_and_or_and_not() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_unknown",
        &people_options(),
        &[json!({"age": true, "name": "eve"})],
    );
    for (predicate, want) in [
        ("$.age < 3", None),
        ("!($.age < 3)", None),
        ("$.age < 3 && exists($.name)", None),
        ("$.age < 3 && $.name == \"x\"", Some(false)),
        ("$.age < 3 || exists($.name)", Some(true)),
        ("$.age < 3 || $.name == \"x\"", None),
    ] {
        let operand = compiled(&runtime, &keyset, &plan, predicate, &json!({}));
        let [matched, by_operator, by_hand] = three_ways(&mut db, "json_tree_unknown", &operand);
        assert_eq!(matched, [(1, want)], "{predicate}");
        assert_eq!(by_operator, matched, "{predicate}: @@ is json_tree_match");
        assert_eq!(by_hand, matched, "{predicate}: against the WHERE");
        assert_eq!(
            plaintext(&mut db, "json_tree_unknown", predicate),
            matched,
            "{predicate}: against jsonb_path_match"
        );
    }

    let compiled_lt: Value =
        serde_json::from_str(&compiled(&runtime, &keyset, &plan, "$.age < 3", &json!({}))).unwrap();
    let cmp = find(&compiled_lt, "cmp")
        .expect("an ordering compiles to a cmp leaf")
        .to_string();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_cmp_alone",
        &people_options(),
        &[
            json!({}),
            json!({"age": null}),
            json!({"age": 1}),
            json!({"age": 4}),
        ],
    );
    assert_eq!(
        answers(
            &mut db,
            "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
               FROM json_tree_cmp_alone ORDER BY id",
            &[&cmp],
        ),
        [(1, None), (2, None), (3, Some(true)), (4, Some(false))],
        "the cmp leaf alone"
    );
}

/// Needs an EQL v4 installation. A `contains` leaf is `@>`, the needle's
/// `alt` included: a root scalar matches a root array that holds it.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_contains_leaf_is_the_containment_operator() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_roots",
        &people_options(),
        &[json!([1, 2]), json!(1), json!({"a": [1]}), json!([[1]])],
    );
    let needle = |json: &str| {
        eql_text(&derive(
            &runtime,
            &keyset,
            &plan,
            "contains",
            json!({"json": json}),
        ))
    };
    let root_one = needle("1");
    for json in ["1", "[1]", "{\"a\": [1]}", "[[1]]", "[]"] {
        let held = needle(json);
        let tree = format!(r#"{{"contains": {held}}}"#);
        let matched = answers(
            &mut db,
            "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
               FROM json_tree_roots ORDER BY id",
            &[&tree],
        );
        let contained = answers(
            &mut db,
            "SELECT id, doc @> $1::text::jsonb::eql_v4.query_json FROM json_tree_roots ORDER BY id",
            &[&held],
        );
        assert_eq!(matched, contained, "{json}");
    }
    assert_eq!(
        answers(
            &mut db,
            "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
               FROM json_tree_roots ORDER BY id",
            &[&format!(r#"{{"contains": {root_one}}}"#)],
        ),
        [
            (1, Some(true)),
            (2, Some(true)),
            (3, Some(false)),
            (4, Some(false))
        ],
        "the root scalar, and a root array holding it through `alt`"
    );
}

/// Needs an EQL v4 installation. An `elements` leaf is
/// `json_tree_element_match` over the document the tree opened once; a leaf
/// the answer does not depend on is not read, so it cannot raise, and one
/// the answer depends on raises as the function does.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_an_elements_leaf_is_the_element_match() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_calls",
        &people_options(),
        &[
            json!({"contacts": [{"calls": 3}, {"calls": 7}]}),
            json!({"contacts": [{"calls": 1}]}),
            json!({"contacts": []}),
        ],
    );
    let calls_over = |n: i64, bound: u32| {
        eql_text(&derive(
            &runtime,
            &keyset,
            &plan,
            "element_match",
            json!({"path": "$.contacts[*]", "wildcard_bound": bound, "predicates": [
                {"member": "calls", "op": "gt", "json": n.to_string()}
            ]}),
        ))
    };
    let selector =
        |path: &str| match derive(&runtime, &keyset, &plan, "selector", json!({"path": path})) {
            Operand::Text(selector) => selector,
            other => panic!("a selector is text, got {other:?}"),
        };
    let over_five = calls_over(5, 2);
    let tree_match = |db: &mut postgres::Client, tree: &str| {
        answers(
            db,
            "SELECT id, eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
               FROM json_tree_calls ORDER BY id",
            &[&tree],
        )
    };
    let matched = tree_match(&mut db, &format!(r#"{{"elements": {over_five}}}"#));
    let element = answers(
        &mut db,
        "SELECT id, eql_v4.json_tree_element_match(doc, $1::text::jsonb::eql_v4.query_json_elements) \
           FROM json_tree_calls ORDER BY id",
        &[&over_five],
    );
    assert_eq!(matched, element, "the element match itself");
    assert_eq!(
        matched,
        [(1, Some(true)), (2, Some(false)), (3, Some(false))]
    );
    let two_leaves = format!(
        r#"{{"and": [{{"elements": {over_five}}}, {{"not": {{"elements": {}}}}}]}}"#,
        calls_over(7, 2)
    );
    assert_eq!(
        tree_match(&mut db, &two_leaves),
        [(1, Some(true)), (2, Some(false)), (3, Some(false))],
        "two element leaves over one opened document"
    );

    // A bound of one: the two-contact row is longer than the bound.
    let raising = format!(r#"{{"elements": {}}}"#, calls_over(5, 1));
    let present = json!({"exists": selector("$.contacts")}).to_string();
    let absent = json!({"exists": selector("$.none")}).to_string();
    let on_row_one =
        "SELECT eql_v4.json_tree_match(doc, $1::text::jsonb::eql_v4.query_json_predicate) \
                        FROM json_tree_calls WHERE id = 1";
    for (tree, want) in [
        (format!(r#"{{"and": [{absent}, {raising}]}}"#), None),
        (format!(r#"{{"or": [{present}, {raising}]}}"#), None),
        (
            format!(r#"{{"and": [{present}, {raising}]}}"#),
            Some(INVALID_PARAMETER_VALUE),
        ),
        (raising.clone(), Some(INVALID_PARAMETER_VALUE)),
    ] {
        assert_eq!(
            sqlstate(&mut db, on_row_one, &[&tree]).as_deref(),
            want,
            "{tree}"
        );
    }
}

/// Needs an EQL v4 installation. `@@` takes a typed predicate; with a
/// `jsonpath` it is still blocked; an untyped operand resolves to neither
/// silently; and a NULL argument is NULL.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_operator_takes_a_typed_predicate_and_jsonpath_stays_blocked() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = people_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_typed",
        &people_options(),
        &[json!({"age": 3})],
    );
    let exists =
        |path: &str| match derive(&runtime, &keyset, &plan, "selector", json!({"path": path})) {
            Operand::Text(selector) => json!({"exists": selector}).to_string(),
            other => panic!("a selector is text, got {other:?}"),
        };
    let (age, none) = (exists("$.age"), exists("$.none"));
    let answer: Option<bool> = db
        .query_one(
            "SELECT doc @@ $1::text::jsonb::eql_v4.query_json_predicate FROM json_tree_typed",
            &[&age],
        )
        .unwrap()
        .get(0);
    assert_eq!(answer, Some(true));
    let bound: Option<bool> = db
        .query_typed(
            "SELECT doc @@ $1::eql_v4.query_json_predicate FROM json_tree_typed",
            &[(&none, postgres::types::Type::TEXT)],
        )
        .unwrap()[0]
        .get(0);
    assert_eq!(bound, Some(false), "a bound parameter cast to the domain");
    assert_eq!(
        sqlstate(
            &mut db,
            "SELECT doc @@ '$.age == 3'::jsonpath FROM json_tree_typed",
            &[]
        )
        .as_deref(),
        Some(RAISE_EXCEPTION),
        "a jsonpath is blocked"
    );
    for untyped in [
        format!(
            "SELECT doc @@ {} FROM json_tree_typed",
            literal(&json!(none))
        ),
        "SELECT doc @@ '$.age == 3' FROM json_tree_typed".to_owned(),
    ] {
        assert_eq!(
            sqlstate(&mut db, &untyped, &[]).as_deref(),
            Some(AMBIGUOUS_FUNCTION),
            "an untyped operand is refused, not read as native jsonb: {untyped}"
        );
    }
    let predicate = format!(
        "{}::jsonb::eql_v4.query_json_predicate",
        literal(&json!(none))
    );
    for sql in [
        format!("SELECT eql_v4.json_tree_match(NULL, {predicate})"),
        "SELECT eql_v4.json_tree_match(doc, NULL) FROM json_tree_typed".to_owned(),
        format!("SELECT NULL::public.eql_v4_json_search @@ {predicate}"),
    ] {
        let answer: Option<bool> = db.query_one(&sql, &[]).unwrap().get(0);
        assert_eq!(answer, None, "{sql}");
    }
}
