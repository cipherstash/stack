//! EQL v4's `TextSearch`: one column answering `=`, `<` and `@@`, whose
//! query carries only the term its operator reads (ADR-0002, amended
//! 2026-10-19).
//!
//! A stored value carries all three terms, each the one the single-index
//! type stores (`TextEq`'s `hm`, `TextOrd`'s `op`, `TextMatch`'s `bf`).
//! Text that cuts no match token (one letter, or none: a two-letter word is
//! a token of its own) stores the empty filter, where `TextMatch` refuses
//! it, so `=` and `<` find it and no `@@` query does. A query is built
//! through the projection of the index that answers its operator, so `=` and
//! `<` on such text work and a match query on it is refused. Against an EQL
//! v4 database: a query with any one term is a `query_text_search`, one with
//! none is not, and each operator refuses an operand without its term (or
//! with it `null`, or an empty filter) rather than matching no row.

mod common;

use eql_bindings::encryption::targets;
use eql_bindings::v4::text::{
    TextSearch, TextSearchEqualityQuery, TextSearchMatchQuery, TextSearchOrderQuery,
    TextSearchQuery,
};
use eql_bindings::Identifier;
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::sem::TermError;
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{Encrypt, Label, NonEmpty};

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("people", "name").unwrap()
}

fn label() -> Label {
    Label::new(["people", "name"]).unwrap()
}

/// The index a query on `TextSearch` is asked through, by its key.
fn index(key: &str) -> IndexSpec {
    IndexSpec::parse(key).unwrap()
}

/// The stored JSON the named type writes for `text`.
async fn stored(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    text: &str,
) -> serde_json::Value {
    let bytes = targets::encrypt(name, keyset, &label(), frame(text))
        .unwrap()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `TextSearch` query for `text` through the index `key`.
async fn query(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    key: &str,
    text: &str,
) -> Result<serde_json::Value, stack_encrypt::Error> {
    let bytes = targets::query("TextSearch", &index(key), keyset, &label(), frame(text))
        .unwrap()
        .await?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

fn keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[tokio::test]
async fn a_stored_value_carries_the_three_single_index_terms() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let search = stored(&keyset, "TextSearch", "Alice").await;
    assert_eq!(keys(&search), ["bf", "c", "hm", "i", "op", "v"]);
    assert_eq!(search["v"], 4);
    assert_eq!(search["hm"], stored(&keyset, "TextEq", "Alice").await["hm"]);
    assert_eq!(
        search["op"],
        stored(&keyset, "TextOrd", "Alice").await["op"]
    );
    assert_eq!(
        search["bf"],
        stored(&keyset, "TextMatch", "Alice").await["bf"]
    );
    let opened = targets::decrypt(
        "TextSearch",
        &cipher,
        &label(),
        search.to_string().as_bytes(),
    )
    .unwrap()
    .await
    .unwrap();
    assert_eq!(opened.risky_ref(), frame("Alice").risky_ref());
}

/// Text that cuts no match token (one letter, or none) has no filter.
/// `TextSearch` stores
/// it with the empty filter and the same `hm` and `op` as `TextEq` and
/// `TextOrd`, so `=` and `<` find it and no match query does. `TextMatch`,
/// which has no other term to find it by, still refuses it.
#[tokio::test]
async fn short_text_stores_the_empty_filter_where_text_match_refuses_it() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for text in ["A", "", "  "] {
        let search = stored(&keyset, "TextSearch", text).await;
        assert_eq!(keys(&search), ["bf", "c", "hm", "i", "op", "v"], "{text:?}");
        assert_eq!(search["bf"], serde_json::json!([]), "{text:?}");
        assert_eq!(
            search["hm"],
            stored(&keyset, "TextEq", text).await["hm"],
            "{text:?}"
        );
        assert_eq!(
            search["op"],
            stored(&keyset, "TextOrd", text).await["op"],
            "{text:?}"
        );
        let opened = targets::decrypt(
            "TextSearch",
            &cipher,
            &label(),
            search.to_string().as_bytes(),
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(opened.risky_ref(), frame(text).risky_ref(), "{text:?}");

        let refused = targets::encrypt("TextMatch", &keyset, &label(), frame(text))
            .unwrap()
            .await
            .unwrap_err();
        assert!(
            matches!(
                refused,
                stack_encrypt::Error::Term(TermError::EmptyTermText)
            ),
            "TextMatch {text:?}: {refused:?}"
        );
    }
}

/// Each index's query carries its term alone, and it is the stored one.
#[tokio::test]
async fn a_query_carries_only_the_term_its_operator_reads() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let search = stored(&keyset, "TextSearch", "Alice").await;
    for (key, term) in [("eq", "hm"), ("ope", "op"), ("match", "bf")] {
        let q = query(&keyset, key, "Alice").await.unwrap();
        assert_eq!(keys(&q), {
            let mut expected = vec!["i", "v", term];
            expected.sort_unstable();
            expected
        });
        assert_eq!(q[term], search[term], "{key}: the stored {term}");
        assert_eq!(q["v"], 4);
    }
    // An index the type does not carry is refused before anything runs.
    let Err(refused) = targets::query("TextSearch", &IndexSpec::Ore, &keyset, &label(), frame("x"))
    else {
        panic!("an ore query on TextSearch was dispatched");
    };
    assert!(
        matches!(
            refused,
            targets::TargetError::NoIndex {
                name: "TextSearch",
                index: "ore"
            }
        ),
        "{refused:?}"
    );
}

/// `=` and `<` on text that cuts no match token: the query carries `hm` or
/// `op`, never an empty filter. A match query on it is refused, as a
/// `TextMatchQuery` is, rather than sent as a filter that matches every row.
#[tokio::test]
async fn short_text_is_queried_by_equality_and_order_and_refused_for_match() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let eq = query(&keyset, "eq", "A").await.unwrap();
    assert_eq!(keys(&eq), ["hm", "i", "v"]);
    assert!(eq["hm"].as_str().is_some_and(|hm| !hm.is_empty()));
    let ord = query(&keyset, "ope", "A").await.unwrap();
    assert_eq!(keys(&ord), ["i", "op", "v"]);
    assert!(ord["op"].as_str().is_some_and(|op| !op.is_empty()));
    // The order term of "A" sorts before "Alice"'s: a prefix first.
    let alice = stored(&keyset, "TextSearch", "Alice").await;
    assert!(ord["op"].as_str().unwrap() < alice["op"].as_str().unwrap());

    let refused = query(&keyset, "match", "A").await.unwrap_err();
    assert!(
        matches!(
            refused,
            stack_encrypt::Error::Term(TermError::EmptyTermText)
        ),
        "{refused:?}"
    );
}

/// The typed path: each projection derives its one term and converts into
/// the `TextSearchQuery` the by-name dispatch writes, byte for byte.
#[tokio::test]
async fn the_typed_projections_are_what_the_dispatch_writes() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let text = "A".to_owned();
    let eq: TextSearchEqualityQuery = keyset.encrypt_as(&text, column()).await.unwrap();
    let ord: TextSearchOrderQuery = keyset.encrypt_as(&text, column()).await.unwrap();
    for (typed, key) in [
        (TextSearchQuery::from(eq), "eq"),
        (TextSearchQuery::from(ord), "ope"),
    ] {
        assert_eq!(
            serde_json::to_value(&typed).unwrap(),
            query(&keyset, key, "A").await.unwrap(),
            "{key}"
        );
    }
    let matched: TextSearchMatchQuery = keyset
        .encrypt_as(&"Alice".to_owned(), column())
        .await
        .unwrap();
    let matched = TextSearchQuery::from(matched);
    assert!(matched.hm.is_none() && matched.op.is_none() && matched.bf.is_some());
    assert_eq!(
        serde_json::to_value(&matched).unwrap(),
        query(&keyset, "match", "Alice").await.unwrap()
    );
    // A query with no term deserializes, as the JSON Schema allows; it is
    // the database that refuses it.
    let bare: TextSearchQuery = serde_json::from_value(serde_json::json!({
        "v": 4, "i": {"t": "people", "c": "name"}
    }))
    .unwrap();
    assert!(bare.hm.is_none() && bare.op.is_none() && bare.bf.is_none());

    // The stored value round-trips through the typed path too.
    let stored: TextSearch = keyset
        .encrypt_as(&"Alice".to_owned(), column())
        .await
        .unwrap();
    let opened: String = cipher.decrypt_as(stored, column().into()).await.unwrap();
    assert_eq!(opened, "Alice");
    // And short text through the typed path stores the empty filter, as the
    // dispatch does.
    let short: TextSearch = keyset.encrypt_as(&text, column()).await.unwrap();
    assert!(short.bf.0 .0.is_empty());
    assert_eq!(
        serde_json::to_value(&short.bf).unwrap(),
        serde_json::json!([])
    );
    let opened: String = cipher.decrypt_as(short, column().into()).await.unwrap();
    assert_eq!(opened, "A");
}

// ---- PostgreSQL -------------------------------------------------------------

fn connect() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

/// SQLSTATE `check_violation`.
const CHECK_VIOLATION: &str = "23514";
/// SQLSTATE `invalid_parameter_value`.
const INVALID_PARAMETER_VALUE: &str = "22023";

/// The rows whose `name` the SQL's predicate selects, the operand bound as
/// `$1`.
fn ids(db: &mut postgres::Client, sql: &str, operand: &serde_json::Value) -> Vec<i32> {
    let mut ids: Vec<i32> = db
        .query(sql, &[&operand.to_string()])
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .iter()
        .map(|r| r.get(0))
        .collect();
    ids.sort_unstable();
    ids
}

/// The error the SQL raises with the operand bound as `$1`.
fn refusal(db: &mut postgres::Client, sql: &str, operand: &serde_json::Value) -> postgres::Error {
    match db.query(sql, &[&operand.to_string()]) {
        Ok(rows) => panic!("{sql}: answered {} rows, expected a refusal", rows.len()),
        Err(error) => error,
    }
}

fn sqlstate(error: &postgres::Error) -> &str {
    error.code().map_or("", |code| code.code())
}

/// Needs an EQL v4 installation. Rows written through the by-name dispatch,
/// queried with operands that carry one term each: `=`, `<`, `>` and `@@`
/// find the rows the plaintexts say, one-letter and empty text, stored with
/// the empty filter, included on `=` and `<` and found by no `@@`; a
/// `query_text_search` holds any one term and refuses none; and each
/// operator refuses an operand without its term, naming the term, never the
/// operand.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_answers_each_operator_through_its_own_term() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    db.batch_execute(
        "CREATE TEMP TABLE v4_search (id int PRIMARY KEY, name public.eql_v4_text_search);",
    )
    .unwrap();
    // 4 and 5 cut no match token: stored with `"bf": []`, which the
    // domain's CHECK accepts.
    let names = [(1, "alice"), (2, "Bob"), (3, "carol"), (4, "A"), (5, "")];
    for (id, name) in names {
        let value = runtime.block_on(stored(&keyset, "TextSearch", name));
        db.execute(
            "INSERT INTO v4_search VALUES ($1, $2::text::jsonb::public.eql_v4_text_search)",
            &[&id, &value.to_string()],
        )
        .unwrap();
    }
    let q = |key: &str, text: &str| runtime.block_on(query(&keyset, key, text)).unwrap();
    let select = |predicate: &str| format!("SELECT id FROM v4_search WHERE {predicate}");
    let operand = "$1::text::jsonb::eql_v4.query_text_search";

    // Each operator through its own term.
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name = {operand}")),
            &q("eq", "Bob")
        ),
        [2]
    );
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name <> {operand}")),
            &q("eq", "Bob")
        ),
        [1, 3, 4, 5]
    );
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name < {operand}")),
            &q("ope", "bob")
        ),
        [1, 4, 5]
    );
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name >= {operand}")),
            &q("ope", "bob")
        ),
        [2, 3]
    );
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name @@ {operand}")),
            &q("match", "aro")
        ),
        [3]
    );
    // One-letter text, which has no match term, on `=` and `<`/`>`: stored
    // and queried.
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name = {operand}")),
            &q("eq", "A")
        ),
        [4]
    );
    assert_eq!(
        ids(&mut db, &select(&format!("name = {operand}")), &q("eq", "")),
        [5]
    );
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name > {operand}")),
            &q("ope", "Bo")
        ),
        [2, 3]
    );
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name < {operand}")),
            &q("ope", "Bo")
        ),
        [1, 4, 5]
    );
    // The function forms, as PostgREST calls them.
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("eql_v4.lt(name, {operand})")),
            &q("ope", "bob")
        ),
        [1, 4, 5]
    );
    // No match query finds a stored empty filter: `matches` needs the stored
    // filter to contain the query's, and a query's is never empty.
    for needle in ["ali", "alic", "Bob", "aro", "xyz"] {
        let found = ids(
            &mut db,
            &select(&format!("name @@ {operand}")),
            &q("match", needle),
        );
        assert!(
            !found.contains(&4) && !found.contains(&5),
            "{needle:?} matched an empty filter: {found:?}"
        );
    }
    assert_eq!(
        ids(
            &mut db,
            &select(&format!("name @@ {operand}")),
            &q("match", "ali")
        ),
        [1]
    );

    // The domain holds a query with any one term, and refuses one with none.
    let full = q("eq", "x");
    for key in ["eq", "ope", "match"] {
        db.query(&format!("SELECT {operand}"), &[&q(key, "xyz").to_string()])
            .unwrap_or_else(|e| panic!("{key}: {e}"));
    }
    let mut bare = full.clone();
    bare.as_object_mut().unwrap().remove("hm");
    let error = refusal(&mut db, &format!("SELECT {operand}"), &bare);
    assert_eq!(sqlstate(&error), CHECK_VIOLATION, "{error}");
    // The v3 operand is untouched: it still requires every term.
    let mut v3 = q("eq", "x");
    v3["v"] = 3.into();
    // Only when the v3 bundle is installed beside v4; this database may
    // hold v4 alone.
    let has_v3: bool = db
        .query_one(
            "SELECT to_regtype('eql_v3.query_text_search') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    if has_v3 {
        let error = refusal(
            &mut db,
            "SELECT $1::text::jsonb::eql_v3.query_text_search",
            &v3,
        );
        assert_eq!(sqlstate(&error), CHECK_VIOLATION, "{error}");
    }

    // Each operator refuses an operand without the term it reads, naming
    // the term and never the operand.
    for (predicate, key, missing) in [
        ("name = {}", "ope", "hm"),
        ("name <> {}", "match", "hm"),
        ("name < {}", "eq", "op"),
        ("name >= {}", "match", "op"),
        ("name @@ {}", "eq", "bf"),
        ("name @@ {}", "ope", "bf"),
        ("eql_v4.eq_term({}) IS NOT NULL", "ope", "hm"),
        ("eql_v4.ord_term({}) IS NOT NULL", "eq", "op"),
        ("eql_v4.match_term({}) IS NOT NULL", "ope", "bf"),
    ] {
        let sql = select(&predicate.replace("{}", operand));
        let without = q(key, "carol");
        let error = refusal(&mut db, &sql, &without);
        assert_eq!(sqlstate(&error), INVALID_PARAMETER_VALUE, "{sql}: {error}");
        let message = error
            .as_db_error()
            .map(|e| e.message().to_owned())
            .unwrap_or_default();
        assert!(
            message.contains(&format!(
                "eql_v4.query_text_search value has no \"{missing}\" term"
            )),
            "{sql}: {message}"
        );
        let carried = without.as_object().unwrap();
        for term in ["hm", "op", "bf"].iter().filter_map(|t| carried.get(*t)) {
            let shown = term.to_string();
            let shown = shown.trim_matches('"');
            assert!(
                !message.contains(shown),
                "{sql}: the message quotes the operand"
            );
        }
    }

    // A term that is JSON `null`, or a filter with no positions, is as
    // missing as an absent one. Neither comes from Stack Encrypt, which
    // leaves an absent term out and never builds an empty query filter; a
    // hand-built operand is refused rather than compared as NULL (no row),
    // or as the empty filter only the short-text rows store.
    let mut null_hm = q("eq", "carol");
    null_hm["hm"] = serde_json::Value::Null;
    let mut empty_bf = q("match", "carol");
    empty_bf["bf"] = serde_json::json!([]);
    for (predicate, operand_value, missing) in [
        ("name = {}", &null_hm, "hm"),
        ("eql_v4.eq_term({}) IS NOT NULL", &null_hm, "hm"),
        ("name @@ {}", &empty_bf, "bf"),
        ("eql_v4.match_term({}) IS NOT NULL", &empty_bf, "bf"),
    ] {
        let sql = select(&predicate.replace("{}", operand));
        let error = refusal(&mut db, &sql, operand_value);
        assert_eq!(sqlstate(&error), INVALID_PARAMETER_VALUE, "{sql}: {error}");
        let message = error
            .as_db_error()
            .map(|e| e.message().to_owned())
            .unwrap_or_default();
        assert!(
            message.contains(&format!(
                "eql_v4.query_text_search value has no \"{missing}\" term"
            )),
            "{sql}: {message}"
        );
    }

    // The ORE twin follows the same rule, and a present `ob` is still a
    // non-empty array. Its order term is EQL's block ORE, which the engine
    // does not derive, so only the equality and match operands are real.
    // An installer that could not create the ORE operator class (no
    // superuser) poisons the ORE domains, and then there is nothing to test.
    let poisoned: bool = db
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'eql_ore_unavailable' \
             AND contypid = 'eql_v4.query_text_search_ore'::regtype)",
            &[],
        )
        .unwrap()
        .get(0);
    if poisoned {
        return;
    }
    let ore = "$1::text::jsonb::eql_v4.query_text_search_ore";
    db.query(&format!("SELECT {ore}"), &[&q("eq", "xyz").to_string()])
        .unwrap();
    db.query(&format!("SELECT {ore}"), &[&q("match", "xyz").to_string()])
        .unwrap();
    let mut empty_ob = q("eq", "xyz");
    empty_ob["ob"] = serde_json::json!([]);
    let error = refusal(&mut db, &format!("SELECT {ore}"), &empty_ob);
    assert_eq!(sqlstate(&error), CHECK_VIOLATION, "{error}");
    let error = refusal(&mut db, &format!("SELECT {ore}"), &bare);
    assert_eq!(sqlstate(&error), CHECK_VIOLATION, "{error}");
    let error = refusal(
        &mut db,
        &format!("SELECT eql_v4.ord_term_ore({ore}) IS NOT NULL"),
        &q("eq", "xyz"),
    );
    assert_eq!(sqlstate(&error), INVALID_PARAMETER_VALUE, "{error}");
}
