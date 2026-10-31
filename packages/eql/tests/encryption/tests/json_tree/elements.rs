//! The element-scoped predicate end to end: documents sealed by Stack
//! Encrypt's JSON index, the `element_match` operand derived through a data
//! plan over eql-bindings' target table, and
//! `eql_v4.json_tree_element_match` over the stored column. The resolver
//! here ([`Eql`]) names the document's leaf, element-scoped and compiled
//! predicate domains, so the engine answers `element_match` and `match`
//! through it. The Go guest's resolver names the leaf domain alone (its
//! `targets` tests pin that), so the Go SDK is not offered either operator
//! until the Go side takes them.
//!
//! These tests pin:
//!
//! - the operand domain's CHECK, member by member, over a derived operand
//!   and its parts;
//! - that one element must satisfy every member: two elements each matching
//!   half of the predicate are not a match, where the component orderings
//!   over `json_tree_path_query` are, under the sealed root and the open one;
//! - each bound's comparison, a field with no ordering term, and an absent
//!   field;
//! - that a probe's hit raises: an array longer than the bound, and a token
//!   that names a node at another selector than its member's;
//! - that `json_tree_subtree` is `json_tree_subtree_indexed` without `k`,
//!   under every budget, and what `k` is, the sealed-root fallback's `0`
//!   included.

use super::*;

use eql_bindings::encryption::targets::{self as eql_targets, Target};
use stack_encrypt::dynamic::{
    self, record, OpSpec, Operand, TargetDescriptor, TargetError, TargetResolver, ValueFrame,
};
use stack_encrypt::{KeysetCipher, Label, Pending, StackCipher};

/// eql-bindings' table as the engine's resolver, naming each type's leaf,
/// element predicate and compiled predicate domains: a host that answers
/// `element_match` and `match`. Not the Go guest's resolver, which names
/// the leaf domain alone.
pub(super) struct Eql;

fn describe(target: &Target) -> TargetDescriptor {
    let mut descriptor = TargetDescriptor::new(
        target.name,
        target.family,
        target.suffix,
        target.plaintext_kind(),
        target.sql_domain,
        target.indexes.iter().map(|key| (*key).to_owned()).collect(),
        target.query.map(str::to_owned),
        target.query_sql_domain.map(str::to_owned),
        target.producible,
        target.reason.map(str::to_owned),
    );
    if let Some(domain) = target.leaf_query_sql_domain() {
        descriptor = descriptor.with_leaf_query_sql_domain(domain);
    }
    if let Some(domain) = target.elements_query_sql_domain() {
        descriptor = descriptor.with_elements_query_sql_domain(domain);
    }
    if let Some(domain) = target.predicate_query_sql_domain() {
        descriptor = descriptor.with_predicate_query_sql_domain(domain);
    }
    descriptor
}

impl TargetResolver for Eql {
    fn targets(&self) -> Vec<TargetDescriptor> {
        eql_targets::targets().iter().map(describe).collect()
    }
    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        options: Option<&dynamic::TargetOptions>,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::encrypt_with(name, options, keyset, label, plaintext)
            .map_err(|error| TargetError::Other(Box::new(error)))
    }
    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a StackCipher<K>,
        label: &Label,
        stored: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
        eql_targets::decrypt(name, cipher, label, stored)
            .map_err(|error| TargetError::Other(Box::new(error)))
    }
    fn query<'a, K: 'static>(
        &self,
        name: &str,
        index: &stack_encrypt::target::IndexSpec,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::query(name, index, keyset, label, plaintext)
            .map_err(|error| TargetError::Other(Box::new(error)))
    }
}

const RELATIONSHIP: &str = "$.extra.emergency_contacts[*].relationship";
const CALLS: &str = "$.extra.emergency_contacts[*].previous_call_count";

/// The documents' index options: each contact's relationship and call
/// count carry ordering terms.
fn contact_options() -> JsonOptions {
    JsonOptions::default()
        .ordering([RELATIONSHIP, CALLS])
        .unwrap()
}

/// `profile` under `users/profile`, the column the documents are sealed
/// under, naming `JsonSearch` with [`contact_options`].
fn contact_plan() -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "null": "sql",
            "target": {"name": "JsonSearch", "options": {"ordered": [RELATIONSHIP, CALLS]}}
        }
    });
    record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Eql).unwrap()
}

pub(super) fn frame_of(value: &Value) -> ValueFrame {
    ValueFrame::from_bytes(&dynamic::frame::serde::to_vec(value).unwrap()).unwrap()
}

/// The operand of `operator` on `profile` for `input`, as the SQL binds
/// it: an EQL operand's JSON text, or a list of tokens.
pub(super) fn derive(
    runtime: &tokio::runtime::Runtime,
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    operator: &str,
    input: Value,
) -> Operand {
    let term = wait(
        runtime,
        dynamic::query_term(
            keyset,
            plan,
            "profile",
            OpSpec::parse(operator).unwrap(),
            frame_of(&input),
            &Eql,
        )
        .unwrap(),
    )
    .unwrap();
    term.operand().clone()
}

pub(super) fn eql_text(operand: &Operand) -> String {
    match operand {
        Operand::One(bytes) => String::from_utf8(bytes.clone()).unwrap(),
        other => panic!("one EQL operand, got {other:?}"),
    }
}

/// The contacts array's elements, which every `element_match` here reads.
const ELEMENTS: &str = "$.extra.emergency_contacts[*]";

/// SQLSTATE `check_violation`, a value its domain's CHECK refuses.
const CHECK_VIOLATION: &str = "23514";
/// SQLSTATE `invalid_parameter_value`, which a probe's hit raises with.
const INVALID_PARAMETER_VALUE: &str = "22023";

/// [`contact_options`] with the root sealed or open.
fn layout_options(sealed: bool) -> JsonOptions {
    let mut options = contact_options();
    options.sealed_root = sealed;
    options
}

/// [`contact_plan`] with the root sealed or open.
fn layout_plan(sealed: bool) -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "null": "sql",
            "target": {"name": "JsonSearch", "options": {
                "sealed_root": sealed,
                "ordered": [RELATIONSHIP, CALLS]
            }}
        }
    });
    record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Eql).unwrap()
}

/// A contact with each field present when given.
fn contact(relationship: Option<&str>, calls: Option<i64>) -> Value {
    let mut fields = Map::new();
    if let Some(relationship) = relationship {
        let _ = fields.insert("relationship".into(), json!(relationship));
    }
    if let Some(calls) = calls {
        let _ = fields.insert("previous_call_count".into(), json!(calls));
    }
    Value::Object(fields)
}

/// A document holding `list` as its contacts.
fn contacts_document(list: Vec<Value>) -> Value {
    json!({"name": "x", "extra": {"emergency_contacts": list}})
}

/// The `element_match` operand over the contacts at `bound`, as JSON text.
fn element_match(
    runtime: &tokio::runtime::Runtime,
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    bound: u32,
    predicates: Value,
) -> String {
    eql_text(&derive(
        runtime,
        keyset,
        plan,
        "element_match",
        json!({"path": ELEMENTS, "wildcard_bound": bound, "predicates": predicates}),
    ))
}

/// "relationship is Sibling and more than five calls", read to `bound`.
fn sibling_with_more_than_five_calls(
    runtime: &tokio::runtime::Runtime,
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    bound: u32,
) -> String {
    element_match(
        runtime,
        keyset,
        plan,
        bound,
        json!([
            {"member": "relationship", "op": "eq", "json": "\"Sibling\""},
            {"member": "previous_call_count", "op": "gt", "json": "5"}
        ]),
    )
}

/// The ids `json_tree_element_match` holds of in `table`, for `operand`.
fn matching(db: &mut postgres::Client, table: &str, operand: &str) -> Vec<i32> {
    db.query(
        &format!(
            "SELECT id FROM {table} \
             WHERE eql_v4.json_tree_element_match(doc, $1::text::jsonb::eql_v4.query_json_elements) ORDER BY id"
        ),
        &[&operand],
    )
    .unwrap_or_else(|error| panic!("{table}: {error}"))
    .iter()
    .map(|row| row.get(0))
    .collect()
}

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

/// The one token of a read of the concrete `path` under `options`.
fn token(
    runtime: &tokio::runtime::Runtime,
    keyset: &KeysetCipher<'_, common::Observed>,
    options: &JsonOptions,
    path: &str,
) -> String {
    let key = wait(
        runtime,
        keyset.json_subtree_key(&JsonPath::parse(path).unwrap(), options, column()),
    )
    .unwrap();
    let tokens = key.tokens();
    assert_eq!(tokens.len(), 1, "{path} names one node");
    tokens[0].clone()
}

/// Needs an EQL v4 installation. The customer's predicate, a Sibling with
/// more than five calls in one contact: the element predicate answers it,
/// where `@>` and an ordering over `json_tree_path_query` answer "some
/// contact is a Sibling and some has more than five calls". A row with a
/// contact past the bound fails the query. `json_tree_subtree` is the
/// indexed read without `k`, and `k` pairs a contact's two fields.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_an_element_predicate_holds_of_one_element() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = contact_plan();
    let mut db = connect();
    let contacts = |list: Value| json!({"name": "x", "extra": {"emergency_contacts": list}});
    let documents = [
        // Each contact holds one half of the predicate.
        contacts(json!([
            {"relationship": "Sibling", "previous_call_count": 3},
            {"relationship": "Friend", "previous_call_count": 7}
        ])),
        // One contact holds both.
        contacts(json!([
            {"relationship": "Friend", "previous_call_count": 9},
            {"relationship": "Sibling", "previous_call_count": 7}
        ])),
        // Neither.
        contacts(json!([{"relationship": "Friend", "previous_call_count": 9}])),
        // No contacts.
        json!({"name": "y"}),
        // Folded equality: "sibling" ties with "Sibling".
        contacts(json!([{"relationship": "sibling", "previous_call_count": 6}])),
    ];
    store(
        &mut db,
        &runtime,
        &cipher,
        "json_tree_elements",
        &contact_options(),
        &documents,
    );
    let ids = |db: &mut postgres::Client,
               sql: &str,
               params: &[&(dyn postgres::types::ToSql + Sync)]|
     -> Vec<i32> {
        db.query(sql, params)
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
            .iter()
            .map(|row| row.get(0))
            .collect()
    };

    let predicate = |bound: u32| {
        eql_text(&derive(
            &runtime,
            &keyset,
            &plan,
            "element_match",
            json!({"path": "$.extra.emergency_contacts[*]", "wildcard_bound": bound, "predicates": [
                {"member": "relationship", "op": "eq", "json": "\"Sibling\""},
                {"member": "previous_call_count", "op": "gt", "json": "5"}
            ]}),
        ))
    };
    let element_scoped = "SELECT id FROM json_tree_elements \
         WHERE eql_v4.json_tree_element_match(doc, $1::text::jsonb::eql_v4.query_json_elements) ORDER BY id";
    assert_eq!(
        ids(&mut db, element_scoped, &[&predicate(4)]),
        [2, 5],
        "one contact a Sibling with more than five calls, the folded spelling included"
    );

    // The superset: containment on the relationship, an ordering over every
    // call count.
    let needle = eql_text(&derive(
        &runtime,
        &keyset,
        &plan,
        "eq_at",
        json!({"path": RELATIONSHIP, "json": "\"Sibling\""}),
    ));
    let Operand::Text(calls_selector) =
        derive(&runtime, &keyset, &plan, "selector", json!({"path": CALLS}))
    else {
        panic!("a selector is text")
    };
    let five = eql_text(&derive(
        &runtime,
        &keyset,
        &plan,
        "gt_at",
        json!({"path": CALLS, "json": "5"}),
    ));
    let superset = "SELECT id FROM json_tree_elements \
         WHERE doc @> $1::text::jsonb::eql_v4.query_json \
           AND EXISTS (SELECT 1 FROM eql_v4.json_tree_path_query(doc, $2::text) AS e \
                        WHERE e > $3::text::jsonb::eql_v4.query_json_leaf) ORDER BY id";
    assert_eq!(
        ids(&mut db, superset, &[&needle, &calls_selector, &five]),
        [1, 2],
        "some contact a Sibling and some over five: row 1's halves answer it, and \
         containment is exact, so the folded spelling does not"
    );

    // A bound below the longest array: the probe names the element at it.
    let error = db.query(element_scoped, &[&predicate(1)]).unwrap_err();
    assert_eq!(
        error.code(),
        Some(&postgres::error::SqlState::INVALID_PARAMETER_VALUE),
        "{error}"
    );
    let message = error
        .as_db_error()
        .map(|db| db.message())
        .unwrap_or_default();
    assert!(
        message.contains("longer than the bound"),
        "the message says why: {message}"
    );
    // At exactly the longest array's length, it answers.
    assert_eq!(ids(&mut db, element_scoped, &[&predicate(2)]), [2, 5]);

    // `json_tree_subtree` is the indexed read without `k`, and the `k`-th
    // token of each field's read names a field of one contact.
    let tokens = |path: &str| match derive(
        &runtime,
        &keyset,
        &plan,
        "subtree",
        json!({"path": path, "wildcard_bound": 2}),
    ) {
        Operand::TextList(tokens) => tokens,
        other => panic!("{other:?}"),
    };
    let (relationships, counts) = (tokens(RELATIONSHIP), tokens(CALLS));
    for budget in [0, 1, 64] {
        for id in 1..=5 {
            let plain: Vec<String> = db
                .query(
                    "SELECT r::jsonb::text FROM json_tree_elements, eql_v4.json_tree_subtree(doc, $1::text[], $2::int) AS r WHERE id = $3",
                    &[&relationships, &budget, &id],
                )
                .unwrap()
                .iter()
                .map(|row| row.get(0))
                .collect();
            let indexed: Vec<String> = db
                .query(
                    "SELECT r.entry::jsonb::text FROM json_tree_elements, eql_v4.json_tree_subtree_indexed(doc, $1::text[], $2::int) AS r WHERE id = $3",
                    &[&relationships, &budget, &id],
                )
                .unwrap()
                .iter()
                .map(|row| row.get(0))
                .collect();
            assert_eq!(plain, indexed, "row {id}, budget {budget}");
        }
    }
    let paired: Vec<(i32, i32)> = db
        .query(
            "SELECT r.k, c.k FROM json_tree_elements,
                    eql_v4.json_tree_subtree_indexed(doc, $1::text[], 0) AS r
               JOIN eql_v4.json_tree_subtree_indexed(doc, $2::text[], 0) AS c ON c.k = r.k
              WHERE id = 2 ORDER BY r.k",
            &[&relationships, &counts],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(paired, [(1, 1), (2, 2)], "one pair per contact, by k");
    let fallback: Vec<i32> = db
        .query(
            "SELECT r.k FROM json_tree_elements, eql_v4.json_tree_subtree_indexed(doc, $1::text[], 1) AS r WHERE id = 2",
            &[&relationships],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        fallback,
        [0],
        "past the budget, the sealed root alone, at k = 0"
    );

    // A member whose full path the field does not order is refused before
    // anything is derived.
    let error = dynamic::check_query(
        &plan,
        "profile",
        OpSpec::ElementMatch,
        frame_of(
            &json!({"path": "$.extra.emergency_contacts[*]", "predicates": [
                {"member": "name", "op": "eq", "json": "\"x\""}
            ]}),
        ),
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
        "{error:?}"
    );
}

/// Needs an EQL v4 installation. The operand domain's CHECK takes a list
/// of members, each tokens and one or two bounds at one selector, and every
/// member's tokens as many as every other's. The values are a derived
/// operand and its parts: two of its tokens, and the leaf operands it holds
/// at each field.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_elements_operand_domain_checks_each_member() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = contact_plan();
    let mut db = connect();
    let derived = sibling_with_more_than_five_calls(&runtime, &keyset, &plan, 1);
    let operand: Value = serde_json::from_str(&derived).unwrap();
    let (relationship, calls) = (&operand["m"][0], &operand["m"][1]);
    // The relationship's leaf, and the call count's: two selectors.
    let (leaf, other) = (&relationship["gte"], &calls["gt"]);
    // The read at bound 1 is one element and the probe: two tokens.
    let (a, b) = (&relationship["t"][0], &relationship["t"][1]);
    assert!(a.is_string() && b.is_string() && a != b);
    let without = |key: &str| {
        let mut bound = leaf.clone();
        let _ = bound.as_object_mut().unwrap().remove(key);
        bound
    };
    let mut leaf_and_more = leaf.clone();
    let _ = leaf_and_more
        .as_object_mut()
        .unwrap()
        .insert("x".into(), json!(1));

    let valid = [
        operand.clone(),
        json!({"m": [{"t": [a, b], "gt": leaf}]}),
        json!({"m": [{"t": [a], "gte": leaf, "lte": leaf}]}),
        json!({"m": [{"t": [a], "gt": leaf, "lt": leaf}, {"t": [b], "lte": other}]}),
    ];
    let invalid = [
        ("not an object", json!([])),
        ("no members", json!({"m": []})),
        ("members not a list", json!({"m": {}})),
        ("no m", json!({})),
        (
            "another key",
            json!({"m": [{"t": [a], "gt": leaf}], "x": 1}),
        ),
        ("a member not an object", json!({"m": [a]})),
        ("no tokens", json!({"m": [{"gt": leaf}]})),
        ("empty tokens", json!({"m": [{"t": [], "gt": leaf}]})),
        ("a token not text", json!({"m": [{"t": [1], "gt": leaf}]})),
        ("tokens not a list", json!({"m": [{"t": a, "gt": leaf}]})),
        ("no bound", json!({"m": [{"t": [a]}]})),
        (
            "two lower bounds",
            json!({"m": [{"t": [a], "gt": leaf, "gte": leaf}]}),
        ),
        (
            "two upper bounds",
            json!({"m": [{"t": [a], "lt": leaf, "lte": leaf}]}),
        ),
        (
            "a bound by another name",
            json!({"m": [{"t": [a], "eq": leaf}]}),
        ),
        (
            "a bound with no term",
            json!({"m": [{"t": [a], "gt": without("op")}]}),
        ),
        (
            "a bound with no selector",
            json!({"m": [{"t": [a], "gt": without("s")}]}),
        ),
        (
            "a bound with another key",
            json!({"m": [{"t": [a], "gt": leaf_and_more}]}),
        ),
        (
            "a bound not an object",
            json!({"m": [{"t": [a], "gt": leaf["s"]}]}),
        ),
        (
            "bounds at two selectors",
            json!({"m": [{"t": [a], "gt": leaf, "lt": other}]}),
        ),
        (
            "members of two widths",
            json!({"m": [{"t": [a], "gt": leaf}, {"t": [a, b], "gt": other}]}),
        ),
    ];
    let cast = "SELECT $1::text::jsonb::eql_v4.query_json_elements";
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
}

/// Needs an EQL v4 installation. A Sibling with more than five calls, as
/// the element predicate and as the component orderings, under the sealed
/// root and the open one: only a row where one contact is both answers the
/// first, where the second also answers a row whose two contacts each hold
/// half, or whose fields sit in different contacts.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_one_element_must_satisfy_every_member() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let documents = [
        contacts_document(vec![
            contact(Some("Sibling"), Some(3)),
            contact(Some("Friend"), Some(7)),
        ]),
        contacts_document(vec![
            contact(Some("Friend"), Some(9)),
            contact(Some("Sibling"), Some(7)),
        ]),
        contacts_document(vec![contact(Some("Friend"), Some(9))]),
        contacts_document(vec![contact(Some("Sibling"), None), contact(None, Some(8))]),
        contacts_document(vec![]),
        contacts_document(vec![contact(Some("Sibling"), Some(6))]),
    ];
    for sealed in [true, false] {
        let table = if sealed {
            "sealed_contacts"
        } else {
            "open_contacts"
        };
        let plan = layout_plan(sealed);
        store(
            &mut db,
            &runtime,
            &cipher,
            table,
            &layout_options(sealed),
            &documents,
        );
        let predicate = sibling_with_more_than_five_calls(&runtime, &keyset, &plan, 2);
        assert_eq!(
            matching(&mut db, table, &predicate),
            [2, 6],
            "{table}: one contact both a Sibling and over five calls"
        );

        let selector = |path: &str| match derive(
            &runtime,
            &keyset,
            &plan,
            "selector",
            json!({"path": path}),
        ) {
            Operand::Text(selector) => selector,
            other => panic!("a selector is text, got {other:?}"),
        };
        let leaf = |operator: &str, path: &str, value: &str| {
            eql_text(&derive(
                &runtime,
                &keyset,
                &plan,
                operator,
                json!({"path": path, "json": value}),
            ))
        };
        let superset: Vec<i32> = db
            .query(
                &format!(
                    "SELECT id FROM {table}
                      WHERE EXISTS (SELECT 1 FROM eql_v4.json_tree_path_query(doc, $1::text) AS e
                                     WHERE e >= $2::text::jsonb::eql_v4.query_json_leaf
                                       AND e <= $3::text::jsonb::eql_v4.query_json_leaf)
                        AND EXISTS (SELECT 1 FROM eql_v4.json_tree_path_query(doc, $4::text) AS e
                                     WHERE e > $5::text::jsonb::eql_v4.query_json_leaf)
                      ORDER BY id"
                ),
                &[
                    &selector(RELATIONSHIP),
                    &leaf("gte_at", RELATIONSHIP, "\"Sibling\""),
                    &leaf("lte_at", RELATIONSHIP, "\"Sibling\""),
                    &selector(CALLS),
                    &leaf("gt_at", CALLS, "5"),
                ],
            )
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(
            superset,
            [1, 2, 4, 6],
            "{table}: the component orderings, some contact a Sibling and some over five"
        );

        let nulls: Option<bool> = db
            .query_one(
                "SELECT eql_v4.json_tree_element_match(NULL, $1::text::jsonb::eql_v4.query_json_elements)",
                &[&predicate],
            )
            .unwrap()
            .get(0);
        assert_eq!(nulls, None, "NULL in, NULL out");
    }
}

/// Needs an EQL v4 installation. Each bound compares as its operator does
/// on an entry, `between` and `eq` at one value are equality, and a field
/// with no ordering term, or no field at all, satisfies no bound.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_each_bound_compares_as_its_operator() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = contact_plan();
    let mut db = connect();
    store(
        &mut db,
        &runtime,
        &cipher,
        "five_calls",
        &contact_options(),
        &[contacts_document(vec![contact(Some("Sibling"), Some(5))])],
    );
    let calls = |op: &str, value: i64| json!({"member": "previous_call_count", "op": op, "json": value.to_string()});
    let between = |low: i64, high: i64| {
        json!({"member": "previous_call_count", "op": "between",
               "low": low.to_string(), "high": high.to_string()})
    };
    for (predicates, want) in [
        (json!([calls("gt", 5)]), false),
        (json!([calls("gt", 4)]), true),
        (json!([calls("gte", 5)]), true),
        (json!([calls("gte", 6)]), false),
        (json!([calls("lt", 5)]), false),
        (json!([calls("lt", 6)]), true),
        (json!([calls("lte", 5)]), true),
        (json!([calls("lte", 4)]), false),
        (json!([between(5, 5)]), true),
        (json!([between(4, 4)]), false),
        (json!([calls("eq", 5)]), true),
        (json!([calls("eq", 4)]), false),
        (json!([calls("gt", 4), calls("lt", 6)]), true),
        (json!([calls("gt", 5), calls("lt", 6)]), false),
        (json!([calls("gt", 4), calls("lt", 5)]), false),
    ] {
        let operand = element_match(&runtime, &keyset, &plan, 1, predicates.clone());
        let got = !matching(&mut db, "five_calls", &operand).is_empty();
        assert_eq!(got, want, "{predicates}");
    }

    // A call count with no ordering term, in a column that orders only the
    // relationship; and a contact with no call count.
    let relationship_only = JsonOptions::default().ordering([RELATIONSHIP]).unwrap();
    store(
        &mut db,
        &runtime,
        &cipher,
        "unordered_calls",
        &relationship_only,
        &[contacts_document(vec![contact(Some("Sibling"), Some(5))])],
    );
    store(
        &mut db,
        &runtime,
        &cipher,
        "no_calls",
        &contact_options(),
        &[contacts_document(vec![contact(Some("Sibling"), None)])],
    );
    let any_calls = element_match(&runtime, &keyset, &plan, 1, json!([calls("gte", 0)]));
    // The member's first token names the unordered call count, which holds
    // no term.
    let member: Value = serde_json::from_str(&any_calls).unwrap();
    let tokens: Vec<String> = serde_json::from_value(member["m"][0]["t"].clone()).unwrap();
    let found: Vec<bool> = db
        .query(
            "SELECT r.entry::jsonb ? 'op' FROM unordered_calls,
                    eql_v4.json_tree_subtree_indexed(doc, $1::text[], 0) AS r WHERE r.k = 1",
            &[&tokens],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(found, [false], "the call count is found, with no term");
    for table in ["unordered_calls", "no_calls"] {
        assert_eq!(
            matching(&mut db, table, &any_calls),
            Vec::<i32>::new(),
            "{table}: no term, or no field: no bound holds"
        );
    }
}

/// Needs an EQL v4 installation. A member's token that names a node at
/// another selector than its bounds' is the probe's hit: the array is
/// longer than the bound, and the predicate raises rather than answer over
/// part of it. An array exactly as long as the bound does not. A node at
/// the element's selector raises wherever its token sits in the member's
/// list: here, a document whose call count's entry is moved to the
/// element's selector, which the member's first token then names.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_probe_hit_raises() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let plan = contact_plan();
    let mut db = connect();
    let predicate = sibling_with_more_than_five_calls(&runtime, &keyset, &plan, 2);
    let two_contacts = contacts_document(vec![
        contact(Some("Friend"), Some(1)),
        contact(Some("Sibling"), Some(9)),
    ]);
    store(
        &mut db,
        &runtime,
        &cipher,
        "within_bound",
        &contact_options(),
        std::slice::from_ref(&two_contacts),
    );
    assert_eq!(
        matching(&mut db, "within_bound", &predicate),
        [1],
        "within the bound"
    );

    // A third contact: the element at the bound is a node, at the
    // element's selector, which the probe names.
    store(
        &mut db,
        &runtime,
        &cipher,
        "past_bound",
        &contact_options(),
        &[
            two_contacts,
            contacts_document(vec![
                contact(Some("Sibling"), Some(9)),
                contact(Some("Friend"), Some(1)),
                contact(Some("Friend"), Some(1)),
            ]),
        ],
    );
    let query = "SELECT id FROM past_bound \
         WHERE eql_v4.json_tree_element_match(doc, $1::text::jsonb::eql_v4.query_json_elements) ORDER BY id";
    let error = db.query(query, &[&predicate]).unwrap_err();
    assert_eq!(
        error.code(),
        Some(&postgres::error::SqlState::INVALID_PARAMETER_VALUE),
        "a row past the bound fails the query, though an element within it matches: {error}"
    );
    let message = error
        .as_db_error()
        .map(|db| db.message())
        .unwrap_or_default();
    assert!(
        message.contains("longer than the bound"),
        "the message says why: {message}"
    );

    // A node at the element's selector, named by a member's first token.
    store(
        &mut db,
        &runtime,
        &cipher,
        "forged_selector",
        &contact_options(),
        &[contacts_document(vec![contact(Some("Sibling"), Some(9))])],
    );
    let only_calls = element_match(
        &runtime,
        &keyset,
        &plan,
        2,
        json!([{"member": "previous_call_count", "op": "gt", "json": "5"}]),
    );
    let member: Value = serde_json::from_str(&only_calls).unwrap();
    let first = member["m"][0]["t"][0].as_str().unwrap().to_owned();
    let Operand::Text(element_selector) = derive(
        &runtime,
        &keyset,
        &plan,
        "selector",
        json!({"path": ELEMENTS}),
    ) else {
        panic!("a selector is text")
    };
    let moved = db
        .execute(
            "UPDATE forged_selector SET doc = jsonb_set(doc::jsonb, ARRAY['sv', (
                 SELECT (e.o - 1)::text
                   FROM jsonb_array_elements(doc::jsonb -> 'sv') WITH ORDINALITY AS e(v, o)
                  WHERE e.v ->> 'x' = eql_v4_internal.json_tree_self_tag(
                          eql_v4_internal.json_tree_iv(doc::jsonb ->> 'h'), decode($1::text, 'base64'))),
               's'], to_jsonb($2::text))::public.eql_v4_json_search",
            &[&first, &element_selector],
        )
        .unwrap();
    assert_eq!(moved, 1);
    assert_eq!(
        sqlstate(
            &mut db,
            "SELECT eql_v4.json_tree_element_match(doc, $1::text::jsonb::eql_v4.query_json_elements) FROM forged_selector",
            &[&only_calls],
        )
        .as_deref(),
        Some(INVALID_PARAMETER_VALUE),
        "a node at the element's selector is never a member's field"
    );
}

/// Needs an EQL v4 installation. `json_tree_subtree` returns what
/// `json_tree_subtree_indexed` does, without `k`, under every budget; every
/// row carries the place of the token that found its node, the rows
/// beneath that node included; and the sealed root's fallback comes back
/// alone with `k = 0`. The tokens name nothing (`$.missing`), an object
/// with one member (`$.obj`), the two contacts' relationships, and the
/// element past the last, which the document does not hold.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_indexed_read_is_the_subtree_read_with_k() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    let document = json!({
        "obj": {"child": "c"},
        "extra": {"emergency_contacts": [
            {"relationship": "Sibling", "previous_call_count": 1},
            {"relationship": "Friend", "previous_call_count": 2}
        ]}
    });
    for sealed in [false, true] {
        let table = if sealed { "sealed_read" } else { "open_read" };
        let options = layout_options(sealed);
        store(
            &mut db,
            &runtime,
            &cipher,
            table,
            &options,
            std::slice::from_ref(&document),
        );
        let tokens: Vec<String> = [
            "$.missing",
            "$.obj",
            "$.extra.emergency_contacts[1].relationship",
            "$.extra.emergency_contacts[0].relationship",
            "$.extra.emergency_contacts[2]",
        ]
        .iter()
        .map(|path| token(&runtime, &keyset, &options, path))
        .collect();
        for budget in [0, 1, 2, 3, 64] {
            let read: Vec<Value> = db
                .query(
                    &format!(
                        "SELECT r::jsonb::text FROM {table}, eql_v4.json_tree_subtree(doc, $1::text[], $2::int) AS r"
                    ),
                    &[&tokens, &budget],
                )
                .unwrap()
                .iter()
                .map(|row| serde_json::from_str(&row.get::<_, String>(0)).unwrap())
                .collect();
            let indexed: Vec<(i32, Value)> = db
                .query(
                    &format!(
                        "SELECT r.k, r.entry::jsonb::text FROM {table}, eql_v4.json_tree_subtree_indexed(doc, $1::text[], $2::int) AS r"
                    ),
                    &[&tokens, &budget],
                )
                .unwrap()
                .iter()
                .map(|row| {
                    (
                        row.get(0),
                        serde_json::from_str(&row.get::<_, String>(1)).unwrap(),
                    )
                })
                .collect();
            let entries: Vec<Value> = indexed.iter().map(|(_, entry)| entry.clone()).collect();
            assert_eq!(
                read, entries,
                "{table}, budget {budget}: the same rows in order"
            );
            let ks: Vec<i32> = indexed.iter().map(|(k, _)| *k).collect();
            let mut sorted = ks.clone();
            sorted.sort_unstable();
            assert_eq!(ks, sorted, "{table}, budget {budget}: ordered by k");
            // Four nodes, at d = 0 and 1, from four of the five tokens.
            if sealed && budget > 0 && budget < 4 {
                assert_eq!(indexed.len(), 1, "{table}, budget {budget}: the root alone");
                assert_eq!(ks, [0], "the root is found by no token");
                assert_eq!(indexed[0].1["j"], 0, "the root entry");
            } else {
                // Within one `k` the rows come in the order the entries
                // are stored, which sealing draws at random.
                let mut found: Vec<(i32, i64)> = indexed
                    .iter()
                    .map(|(k, entry)| (*k, entry["d"].as_i64().unwrap()))
                    .collect();
                found.sort_unstable();
                assert_eq!(
                    found,
                    [(2, 0), (2, 1), (3, 0), (4, 0)],
                    "{table}, budget {budget}: k is the place of the token whose node a row sits in"
                );
            }
        }
    }
}
