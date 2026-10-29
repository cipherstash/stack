//! Native jsonb FUNCTIONS on EQL v4's JSON tree domains raise (#1439).
//!
//! `public.eql_v4_json_search` and `public.eql_v4_json_entry` are domains
//! over `jsonb`, so a native function such as `jsonb_path_match` accepts
//! them and runs over the stored envelope (`{v, i, h, sv, q}`), not the
//! document: it finds none of the user's keys and returns false for every
//! row, with no error. `src/v3/json_tree/blockers.sql` puts an overload of
//! each such function in `public` with the domain as its first argument,
//! and it raises `feature_not_supported` instead.
//!
//! These tests pin:
//!
//! - every blocked function raises `0A000` on a stored document and on an
//!   extracted entry, in every arity and with a named argument, and with the
//!   arguments bound as parameters (the customer's query in #1439);
//! - the set of overloads is exactly the list here, and each matches its
//!   native function's signature, so a blocker added or dropped later fails
//!   this file until it is listed;
//! - the documented limits: an untyped argument resolves to the native
//!   function, and a plain-jsonb call whose first argument is untyped becomes
//!   ambiguous;
//! - what is left alone: plain jsonb, an explicit `::jsonb` cast, EQL's own
//!   reads, and the three functions deliberately not blocked because the
//!   native function already raises on these domains.
//!
//! The document is the corpus's [`fixture`], sealed by Stack Encrypt's JSON
//! index under the fake key source, and the entry is the one `->` extracts
//! at the selector Stack Encrypt derives for `$.hello`.

use super::*;

use postgres::types::Type;

/// SQLSTATE `feature_not_supported`, which every blocker raises with.
const FEATURE_NOT_SUPPORTED: &str = "0A000";
/// SQLSTATE `ambiguous_function`.
const AMBIGUOUS_FUNCTION: &str = "42725";

const DOCUMENT_DOMAIN: &str = "public.eql_v4_json_search";
const ENTRY_DOMAIN: &str = "public.eql_v4_json_entry";

/// The jsonpath functions, each `(target, path, vars DEFAULT '{}', silent
/// DEFAULT false)`.
const JSONPATH_FUNCTIONS: &[&str] = &[
    "jsonb_path_exists",
    "jsonb_path_exists_tz",
    "jsonb_path_match",
    "jsonb_path_match_tz",
    "jsonb_path_query",
    "jsonb_path_query_tz",
    "jsonb_path_query_array",
    "jsonb_path_query_array_tz",
    "jsonb_path_query_first",
    "jsonb_path_query_first_tz",
];

/// The extraction and editing functions.
const OTHER_FUNCTIONS: &[&str] = &[
    "jsonb_extract_path",
    "jsonb_extract_path_text",
    "jsonb_each",
    "jsonb_each_text",
    "jsonb_object_keys",
    "jsonb_typeof",
    "jsonb_strip_nulls",
    "jsonb_set",
    "jsonb_insert",
    "jsonb_pretty",
];

/// Not blocked: on either domain the native function already raises, and an
/// overload would make `jsonb_array_elements($1)` on plain jsonb ambiguous.
const NATIVELY_LOUD: &[&str] = &[
    "jsonb_array_elements",
    "jsonb_array_elements_text",
    "jsonb_array_length",
];

/// A connection with the sealed [`fixture`] stored as row 1 of the temp
/// table `docs`, the selector of `$.hello` in it, and the cipher that
/// sealed it.
struct Stored {
    runtime: tokio::runtime::Runtime,
    cipher: Cipher,
    db: postgres::Client,
    selector: String,
}

/// Seal [`fixture`] and store it in `docs.doc`.
fn setup() -> Stored {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = wait(&runtime, common::cipher());
    let stored = wait(&runtime, seal(&cipher, &fixture()));
    let selector = wait(
        &runtime,
        cipher
            .default_keyset()
            .json_selector(&JsonPath::parse("$.hello").unwrap(), column()),
    )
    .unwrap()
    .to_string();
    let mut db = connect();
    db.batch_execute("CREATE TEMP TABLE docs (id integer, doc public.eql_v4_json_search)")
        .unwrap();
    db.execute(
        "INSERT INTO docs VALUES (1, $1::text::jsonb::public.eql_v4_json_search)",
        &[&serde_json::to_string(&stored).unwrap()],
    )
    .unwrap();
    Stored {
        runtime,
        cipher,
        db,
        selector,
    }
}

/// The two domain values a caller can reach, as SQL over `docs`.
fn values(selector: &str) -> [(&'static str, String); 2] {
    [
        (DOCUMENT_DOMAIN, "doc".to_string()),
        (ENTRY_DOMAIN, format!("(doc -> '{selector}'::text)")),
    ]
}

/// Every blocked call on `v`, with every argument typed: `(function, SQL)`.
fn blocked_calls(v: &str) -> Vec<(&'static str, String)> {
    let mut calls = Vec::new();
    for &f in JSONPATH_FUNCTIONS {
        calls.push((f, format!("{f}({v}, '$.a'::jsonpath)")));
        calls.push((f, format!("{f}({v}, '$.a'::jsonpath, '{{}}'::jsonb)")));
        calls.push((f, format!("{f}({v}, '$.a'::jsonpath, '{{}}'::jsonb, true)")));
        calls.push((f, format!("{f}({v}, '$.a'::jsonpath, silent => true)")));
    }
    for f in ["jsonb_extract_path", "jsonb_extract_path_text"] {
        calls.push((f, format!("{f}({v}, 'a'::text)")));
        calls.push((f, format!("{f}({v}, 'a'::text, 'b'::text)")));
        calls.push((f, format!("{f}({v}, VARIADIC ARRAY['a', 'b'])")));
    }
    for f in [
        "jsonb_each",
        "jsonb_each_text",
        "jsonb_object_keys",
        "jsonb_typeof",
        "jsonb_strip_nulls",
        "jsonb_pretty",
    ] {
        calls.push((f, format!("{f}({v})")));
    }
    calls.push((
        "jsonb_strip_nulls",
        format!("jsonb_strip_nulls({v}, strip_in_arrays => true)"),
    ));
    for f in ["jsonb_set", "jsonb_insert"] {
        calls.push((f, format!("{f}({v}, '{{a}}'::text[], '1'::jsonb)")));
        calls.push((f, format!("{f}({v}, '{{a}}'::text[], '1'::jsonb, true)")));
    }
    calls
}

/// The SQLSTATE and message of a statement that must fail.
fn db_error<T: std::fmt::Debug>(result: Result<T, postgres::Error>, sql: &str) -> (String, String) {
    match result {
        Ok(rows) => panic!("{sql} must fail, but returned {rows:?}"),
        Err(error) => match error.as_db_error() {
            Some(e) => (e.code().code().to_owned(), e.message().to_owned()),
            None => panic!("{sql}: expected a database error, got {error}"),
        },
    }
}

/// Assert `result` is the blocker's raise for `function` on `domain`.
fn assert_blocked<T: std::fmt::Debug>(
    result: Result<T, postgres::Error>,
    function: &str,
    domain: &str,
    sql: &str,
) {
    let (code, message) = db_error(result, sql);
    assert_eq!(
        code, FEATURE_NOT_SUPPORTED,
        "{sql} must raise feature_not_supported: {message}"
    );
    assert!(
        message.starts_with(&format!("{function} is not supported for {domain}: ")),
        "{sql} must name the function and the domain: {message}"
    );
}

#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_every_typed_call_of_a_blocked_function_raises() {
    let Stored {
        mut db, selector, ..
    } = setup();

    let mut checked = 0;
    for (domain, value) in values(&selector) {
        for (function, call) in blocked_calls(&value) {
            let sql = format!("SELECT {call} FROM docs");
            let result = db.query(&sql, &[]).map(|r| r.len());
            assert_blocked(result, function, domain, &sql);
            checked += 1;
        }
    }
    assert_eq!(checked, 2 * (JSONPATH_FUNCTIONS.len() * 4 + 6 + 6 + 1 + 4));
}

/// The query from #1439, with its arguments bound as text parameters and
/// cast in the SQL, as a filter compiler writes it. It returned no rows and
/// no error.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_jsonpath_filter_from_the_issue_raises_with_bound_parameters() {
    let Stored { mut db, .. } = setup();

    let sql = "SELECT id FROM docs \
               WHERE jsonb_path_match(doc, $1::jsonpath, $2::jsonb)";
    let result = db
        .query_typed(
            sql,
            &[
                (&r#"$."score" == $val"#, Type::TEXT),
                (&r#"{"val": 3.14}"#, Type::TEXT),
            ],
        )
        .map(|r| r.len());
    assert_blocked(result, "jsonb_path_match", DOCUMENT_DOMAIN, sql);

    let sql = "SELECT id FROM docs WHERE jsonb_path_exists(doc, $1::jsonpath)";
    let result = db
        .query_typed(sql, &[(&"$.score", Type::TEXT)])
        .map(|r| r.len());
    assert_blocked(result, "jsonb_path_exists", DOCUMENT_DOMAIN, sql);
}

/// The overloads in `public` on the two domains are exactly the listed
/// functions, on both domains, and none of the natively loud ones.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_blocked_set_is_exactly_the_listed_functions() {
    let mut db = connect();

    let found: Vec<(String, String)> = db
        .query(
            "SELECT p.proname::text, p.proargtypes[0]::regtype::text
               FROM pg_proc p
              WHERE p.pronamespace = 'public'::regnamespace
                AND p.pronargs >= 1
                AND p.proargtypes[0] IN ('public.eql_v4_json_search'::regtype,
                                         'public.eql_v4_json_entry'::regtype)
                AND starts_with(p.proname::text, 'jsonb_')
              ORDER BY 1, 2",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();

    let mut expected: Vec<(String, String)> = JSONPATH_FUNCTIONS
        .iter()
        .chain(OTHER_FUNCTIONS)
        .flat_map(|f| {
            ["eql_v4_json_entry", "eql_v4_json_search"]
                .into_iter()
                .map(move |d| (f.to_string(), d.to_string()))
        })
        .collect();
    expected.sort();
    assert_eq!(found, expected);
    for f in NATIVELY_LOUD {
        assert!(
            !found.iter().any(|(name, _)| name == f),
            "{f} is deliberately not blocked"
        );
    }
}

/// Each overload shadows a native function of the same name: the native
/// function's arguments after the first are a prefix of the overload's,
/// with the same variadic position, and both return the same type, as a set
/// or not. An overload with a different argument type would never win, and
/// one with another return type would fail a composed expression before it
/// raised. The overload may carry an argument the native function gains in a
/// later PostgreSQL (`jsonb_strip_nulls(..., strip_in_arrays)` in 18).
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_every_blocker_matches_its_native_signature() {
    let mut db = connect();

    let unmatched: Vec<String> = db
        .query(
            "SELECT p.oid::regprocedure::text
               FROM pg_proc p
              WHERE p.pronamespace = 'public'::regnamespace
                AND p.pronargs >= 1
                AND p.proargtypes[0] IN ('public.eql_v4_json_search'::regtype,
                                         'public.eql_v4_json_entry'::regtype)
                AND NOT EXISTS (
                  SELECT 1 FROM pg_proc n
                   WHERE n.pronamespace = 'pg_catalog'::regnamespace
                     AND n.proname = p.proname
                     AND n.proargtypes[0] = 'jsonb'::regtype
                     AND n.pronargs <= p.pronargs
                     AND n.prorettype = p.prorettype
                     AND n.proretset = p.proretset
                     AND n.provariadic = p.provariadic
                     AND NOT EXISTS (
                       SELECT 1 FROM generate_series(1, n.pronargs - 1) AS i
                        WHERE n.proargtypes[i] <> p.proargtypes[i]
                     )
                )
              ORDER BY 1",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        unmatched.is_empty(),
        "blockers with no native function of a matching signature: {unmatched:?}"
    );
}

/// The documented limit: an overload wins only on an exact match of every
/// argument's type. With an untyped literal anywhere, PostgreSQL treats the
/// domain as jsonb and the native function runs over the envelope, where
/// a document key finds nothing and an envelope key finds the envelope's
/// own field. Pinned so that it cannot change unnoticed; the docs tell
/// callers to cast.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_an_untyped_argument_still_resolves_to_the_native_function() {
    let Stored { mut db, .. } = setup();

    let matched: bool = db
        .query_one(
            "SELECT jsonb_path_match(doc, '$.a == 1', '{}') FROM docs",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        !matched,
        "the native function finds nothing in the envelope"
    );

    let extracted: Option<String> = db
        .query_one(
            "SELECT jsonb_extract_path(doc, 'score')::text FROM docs",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(extracted, None);

    let version: Option<String> = db
        .query_one("SELECT jsonb_extract_path(doc, 'v')::text FROM docs", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        version.as_deref(),
        Some("4"),
        "an envelope key returns the envelope's field"
    );
}

/// The cost of the overloads, also documented: a plain-jsonb call whose
/// first argument is untyped has two candidates PostgreSQL cannot choose
/// between, and must cast. The jsonb operators already behave this way
/// once EQL is installed. A function left unblocked is unaffected.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_an_untyped_first_argument_is_ambiguous_until_cast() {
    let mut db = connect();

    let sql = "SELECT jsonb_typeof('{}')";
    let (code, message) = db_error(db.query_one(sql, &[]), sql);
    assert_eq!(
        code, AMBIGUOUS_FUNCTION,
        "an untyped first argument is ambiguous: {message}"
    );

    let kind: String = db
        .query_one("SELECT jsonb_typeof('{}'::jsonb)", &[])
        .unwrap()
        .get(0);
    assert_eq!(kind, "object");

    let elements: i64 = db
        .query_one("SELECT count(*) FROM jsonb_array_elements('[1, 2]')", &[])
        .unwrap()
        .get(0);
    assert_eq!(elements, 2);
}

/// Plain jsonb, an explicit cast of the column, and EQL's own reads are not
/// touched by the overloads.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_plain_jsonb_casts_and_eql_reads_are_unaffected() {
    let Stored {
        runtime,
        cipher,
        mut db,
        selector,
    } = setup();

    let row = db
        .query_one(
            r#"SELECT jsonb_path_match('{"a": 1}'::jsonb, '$.a == 1'::jsonpath),
                      jsonb_typeof(doc::jsonb),
                      (SELECT count(*) FROM jsonb_object_keys(doc::jsonb))
                 FROM docs"#,
            &[],
        )
        .unwrap();
    let (matched, kind, keys): (bool, String, i64) = (row.get(0), row.get(1), row.get(2));
    assert!(matched);
    assert_eq!(kind, "object");
    assert_eq!(keys, 5, "v, i, h, sv and q");

    // A leaf's token: it finds the `$.hello` node, which has no children.
    let leaf = wait(
        &runtime,
        cipher.default_keyset().json_subtree_key(
            &JsonPath::parse("$.hello").unwrap(),
            &JsonOptions::default(),
            column(),
        ),
    )
    .unwrap();
    let row = db
        .query_one(
            &format!(
                "SELECT eql_v4.json_tree_path_exists(doc, '{selector}'),
                        (doc -> '{selector}'::text) IS NOT NULL,
                        (SELECT count(*) FROM eql_v4.json_tree_children(doc, $1::text))
                   FROM docs"
            ),
            &[&leaf.tokens()[0]],
        )
        .unwrap();
    let (exists, extracted, children): (bool, bool, i64) = (row.get(0), row.get(1), row.get(2));
    assert!(exists);
    assert!(extracted);
    assert_eq!(children, 0);
}

/// The three functions left unblocked already raise on both domains: the
/// envelope and an entry are objects, not arrays.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_unblocked_array_functions_raise_natively() {
    let Stored {
        mut db, selector, ..
    } = setup();

    for (_, value) in values(&selector) {
        for f in NATIVELY_LOUD {
            let sql = format!("SELECT {f}({value}) FROM docs");
            let (_, message) = db_error(db.query(&sql, &[]).map(|r| r.len()), &sql);
            assert!(
                message.starts_with("cannot "),
                "{sql} must raise the native error: {message}"
            );
        }
    }
}
