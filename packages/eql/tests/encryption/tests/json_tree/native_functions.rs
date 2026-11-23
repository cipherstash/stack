//! Native jsonb functions on EQL v4's JSON tree domains (#1439).
//!
//! `public.eql_v4_json_search` and `public.eql_v4_json_entry` are domains
//! over `jsonb`, so a native function such as `jsonb_path_match` accepts
//! them and runs over the stored envelope (`{v, i, h, sv, q}`), not the
//! document. EQL does not overload these functions. An overload taking the
//! domain would make every plain-jsonb call whose first argument is untyped
//! (`jsonb_typeof($1)`) ambiguous in the whole database, and would still
//! lose to the native function whenever another argument is untyped
//! (`jsonb_path_match(col, '$.a == 1')`).
//!
//! These tests pin what `docs/reference/json-tree-leakage.md` says instead:
//!
//! - a native jsonpath function finds nothing of the document, however its
//!   arguments are written, and an envelope key returns the envelope's own
//!   field;
//! - the array functions raise on both domains;
//! - installing EQL leaves a plain-jsonb call with an untyped first
//!   argument resolving to the native function, and puts no overload of a
//!   native jsonb function in `public`.
//!
//! The document is the corpus's [`fixture`], sealed by Stack Encrypt's JSON
//! index under the fake key source, and the entry is the one `->` extracts
//! at the selector Stack Encrypt derives for `$.hello`.

use super::*;

use postgres::types::Type;

/// Raise on both domains: the envelope and an entry are objects.
const ARRAY_FUNCTIONS: &[&str] = &[
    "jsonb_array_elements",
    "jsonb_array_elements_text",
    "jsonb_array_length",
];

/// A connection with the sealed [`fixture`] stored as row 1 of the temp
/// table `docs`, and the selector of `$.hello` in it.
struct Stored {
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
    Stored { db, selector }
}

/// The two domain values a caller can reach, as SQL over `docs`.
fn values(selector: &str) -> [String; 2] {
    ["doc".to_string(), format!("(doc -> '{selector}'::text)")]
}

/// `$.hello` is in the document, and a native jsonpath function on either
/// domain says it is not: typed, untyped, or bound as the filter compiler
/// in #1439 binds it. No error tells the caller.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_native_jsonpath_function_finds_nothing_of_the_document() {
    let Stored { mut db, selector } = setup();

    for value in values(&selector) {
        for sql in [
            format!("SELECT jsonb_path_exists({value}, '$.hello'::jsonpath) FROM docs"),
            format!("SELECT jsonb_path_exists({value}, '$.hello') FROM docs"),
            format!(
                r#"SELECT jsonb_path_match({value}, '$.hello == "world-1"'::jsonpath) FROM docs"#
            ),
            format!(r#"SELECT jsonb_path_match({value}, '$.hello == "world-1"') FROM docs"#),
        ] {
            let found: bool = db.query_one(&sql, &[]).unwrap().get(0);
            assert!(!found, "{sql}: the native function reads the envelope");
        }
    }

    let sql = "SELECT jsonb_path_match(doc, $1::text::jsonpath, $2::text::jsonb) FROM docs";
    let found: bool = db
        .query_one(sql, &[&"$.hello == $h", &r#"{"h": "world-1"}"#])
        .unwrap()
        .get(0);
    assert!(!found, "{sql}: bound parameters read the envelope too");
}

/// A key of the document returns nothing, and a key of the envelope
/// returns the envelope's own field.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_a_native_extraction_reads_the_envelope_keys() {
    let Stored { mut db, .. } = setup();

    let row = db
        .query_one(
            "SELECT jsonb_extract_path(doc, 'hello')::text,
                    jsonb_extract_path(doc, 'v')::text,
                    (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(doc) AS k)
               FROM docs",
            &[],
        )
        .unwrap();
    let (hello, version, keys): (Option<String>, Option<String>, Vec<String>) =
        (row.get(0), row.get(1), row.get(2));
    assert_eq!(hello, None, "a document key finds nothing");
    assert_eq!(
        version.as_deref(),
        Some("4"),
        "an envelope key finds its field"
    );
    assert_eq!(keys, ["h", "i", "q", "sv", "v"]);
}

/// The array functions raise natively on both domains: the envelope and an
/// entry are objects, not arrays.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_the_array_functions_raise_on_both_domains() {
    let Stored { mut db, selector } = setup();

    for value in values(&selector) {
        for f in ARRAY_FUNCTIONS {
            let sql = format!("SELECT {f}({value}) FROM docs");
            let error = db.query(&sql, &[]).expect_err(&format!("{sql} must raise"));
            let message = error.as_db_error().map(|e| e.message().to_owned());
            assert!(
                message.as_deref().is_some_and(|m| m.starts_with("cannot ")),
                "{sql} must raise the native error: {error}"
            );
        }
    }
}

/// With EQL installed, a plain-jsonb call whose first argument is untyped
/// (a bare literal, or a parameter the driver sends with no type) still
/// resolves to the native function, because nothing in `public` overloads
/// it. An overload of any of these names fails the catalog check.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_installing_eql_leaves_untyped_plain_jsonb_calls_unambiguous() {
    let mut db = connect();

    let row = db
        .query_one(
            r#"SELECT jsonb_typeof('{}'),
                      jsonb_path_exists('{"a": 1}', '$.a'),
                      (SELECT count(*) FROM jsonb_each_text('{"a": "b"}'))"#,
            &[],
        )
        .unwrap();
    let (kind, exists, pairs): (String, bool, i64) = (row.get(0), row.get(1), row.get(2));
    assert_eq!(kind, "object");
    assert!(exists);
    assert_eq!(pairs, 1);

    let statement = db.prepare("SELECT jsonb_typeof($1)").unwrap();
    assert_eq!(
        statement.params(),
        [Type::JSONB],
        "an untyped parameter resolves to the native function's jsonb"
    );

    let overloads: Vec<String> = db
        .query(
            "SELECT p.oid::regprocedure::text
               FROM pg_proc p
              WHERE p.pronamespace = 'public'::regnamespace
                AND EXISTS (
                  SELECT 1 FROM pg_proc n
                   WHERE n.pronamespace = 'pg_catalog'::regnamespace
                     AND n.proname = p.proname
                     AND n.pronargs > 0
                     AND n.proargtypes[0] = 'jsonb'::regtype)
              ORDER BY 1",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        overloads.is_empty(),
        "public overloads a native jsonb function: {overloads:?}"
    );
}
