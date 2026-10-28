//! The Python `stackencrypt._eql` parity checks.
//!
//! The first is the twin of `go_eql_parity.rs`: the committed
//! `languages/python/python/stackencrypt/_eql.py` must be byte for byte what
//! the catalog renders. The second reads the two rendered outputs back and
//! compares every marker with the Go `Types` row of the same position,
//! attribute by attribute, so the two languages cannot disagree about a type
//! even if one emitter changes how it reads the catalog.

use std::fs;

use eql_codegen::go_eql::render_go_eql;
use eql_codegen::py_eql::{render_py_eql, PY_EQL_PATH};
use eql_codegen::repo_root;

#[test]
fn py_eql_matches_the_committed_file() {
    let path = repo_root().join(PY_EQL_PATH);
    let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "committed Python module {} is missing or unreadable ({e}); run `mise run types:generate` and commit",
            path.display()
        )
    });
    assert_eq!(
        render_py_eql(),
        committed,
        "{}: the committed Python module is stale or hand-edited — run `mise run types:generate` and commit the result",
        path.display()
    );
}

/// One attribute value, as both languages can express it.
#[derive(Debug, PartialEq)]
enum Value {
    Str(Option<String>),
    List(Vec<String>),
    Bool(bool),
}

/// The ten attributes, in the order both outputs write them, with the Go
/// field each one is. Go writes an absent value as `""`; Python as `None`.
const ATTRIBUTES: [(&str, &str); 10] = [
    ("name", "Name"),
    ("family", "Family"),
    ("suffix", "Suffix"),
    ("plaintext", "Plaintext"),
    ("sql_domain", "SQLDomain"),
    ("indexes", "Indexes"),
    ("query", "Query"),
    ("query_sql_domain", "QuerySQLDomain"),
    ("producible", "Producible"),
    ("reason", "Reason"),
];

/// The attributes that are absent rather than empty when Go writes `""`.
const OPTIONAL: [&str; 4] = ["plaintext", "query", "query_sql_domain", "reason"];

/// Read one double-quoted string at the start of `s`, with the two escapes
/// both emitters write (`\"` and `\\`); return it and the rest of `s`.
fn quoted(s: &str) -> (String, &str) {
    let mut chars = s
        .strip_prefix('"')
        .expect("a string literal")
        .char_indices();
    let mut out = String::new();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return (out, &s[at + 2..]),
            '\\' => match chars.next() {
                Some((_, e @ ('"' | '\\'))) => out.push(e),
                other => panic!("an escape neither emitter writes: {other:?}"),
            },
            c => out.push(c),
        }
    }
    panic!("an unterminated string literal: {s}")
}

/// The strings of a list literal whose opening bracket has been read, up to
/// `close`; return them and the rest after `close`.
fn strings(mut s: &str, close: char) -> (Vec<String>, &str) {
    let mut out = Vec::new();
    loop {
        s = s.trim_start_matches([',', ' ']);
        if let Some(rest) = s.strip_prefix(close) {
            return (out, rest);
        }
        let (item, rest) = quoted(s);
        out.push(item);
        s = rest;
    }
}

/// Every row of the Go `Types` table, as (Go field, value) pairs.
fn go_rows() -> Vec<Vec<(String, Value)>> {
    let go = render_go_eql();
    let table = go
        .split("var Types = []Type{\n")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("the Go Types table");
    table
        .lines()
        .map(|line| {
            let mut s = line
                .trim()
                .strip_prefix('{')
                .and_then(|l| l.strip_suffix("},"))
                .expect("one Go table row per line");
            let mut fields = Vec::new();
            while !s.is_empty() {
                let (key, rest) = s.split_once(": ").expect("a Go field");
                let (value, rest) = if rest.starts_with('"') {
                    let (v, rest) = quoted(rest);
                    (Value::Str(Some(v)), rest)
                } else if let Some(rest) = rest.strip_prefix("[]string{") {
                    let (v, rest) = strings(rest, '}');
                    (Value::List(v), rest)
                } else if let Some(rest) = rest.strip_prefix("nil") {
                    (Value::List(Vec::new()), rest)
                } else if let Some(rest) = rest.strip_prefix("true") {
                    (Value::Bool(true), rest)
                } else if let Some(rest) = rest.strip_prefix("false") {
                    (Value::Bool(false), rest)
                } else {
                    panic!("a Go value neither emitter writes: {rest}")
                };
                fields.push((key.to_owned(), value));
                s = rest.trim_start_matches(", ");
            }
            fields
        })
        .collect()
}

/// A class body after its docstring. The docstring quotes catalog text, so
/// a reason containing ` = ` would otherwise read as an attribute.
fn after_docstring(class: &str) -> &str {
    let body = class
        .strip_prefix("    \"\"\"")
        .expect("every marker class opens with a docstring");
    let end = body.find("\"\"\"").expect("a closed docstring");
    &body[end + 3..]
}

#[test]
fn a_docstring_line_with_an_equals_sign_is_not_an_attribute() {
    let class = "    \"\"\"The EQL type ...\n\n    The engine cannot produce it yet: a = b.\n    \"\"\"\n\n    name = \"X\"\n";
    let attributes: Vec<&str> = after_docstring(class)
        .lines()
        .filter_map(|line| line.strip_prefix("    "))
        .filter_map(|line| line.split_once(" = ").map(|(key, _)| key))
        .collect();
    assert_eq!(attributes, ["name"]);
}

/// Every marker class of the Python module, as (attribute, value) pairs.
fn py_rows() -> Vec<Vec<(String, Value)>> {
    let py = render_py_eql();
    py.split("(Marker):\n")
        .skip(1)
        .map(|class| {
            after_docstring(class)
                .lines()
                .filter_map(|line| line.strip_prefix("    "))
                .filter_map(|line| line.split_once(" = "))
                .map(|(key, raw)| {
                    let value = if raw.starts_with('"') {
                        Value::Str(Some(quoted(raw).0))
                    } else if raw == "None" {
                        Value::Str(None)
                    } else if let Some(rest) = raw.strip_prefix('(') {
                        Value::List(strings(rest, ')').0)
                    } else if raw == "True" || raw == "False" {
                        Value::Bool(raw == "True")
                    } else {
                        panic!("a Python value the emitter does not write: {raw}")
                    };
                    (key.to_owned(), value)
                })
                .collect()
        })
        .collect()
}

#[test]
fn every_python_marker_matches_the_go_row_in_the_same_position() {
    let go = go_rows();
    let py = py_rows();
    assert_eq!(py.len(), go.len(), "one marker per Go Types row");
    assert!(!py.is_empty(), "the catalog renders no rows");

    for (py_row, go_row) in py.iter().zip(&go) {
        let keys: Vec<&str> = py_row.iter().map(|(k, _)| k.as_str()).collect();
        let expected: Vec<&str> = ATTRIBUTES.iter().map(|(py, _)| *py).collect();
        assert_eq!(
            keys, expected,
            "a marker carries exactly the ten attributes"
        );

        for (py_key, go_key) in ATTRIBUTES {
            let py_value = &py_row.iter().find(|(k, _)| k == py_key).unwrap().1;
            let go_value = &go_row
                .iter()
                .find(|(k, _)| k == go_key)
                .unwrap_or_else(|| panic!("a Go row without {go_key}"))
                .1;
            let go_value = match go_value {
                Value::Str(Some(s)) if s.is_empty() && OPTIONAL.contains(&py_key) => {
                    &Value::Str(None)
                }
                other => other,
            };
            assert_eq!(
                py_value, go_value,
                "{py_key} of {:?} differs from the Go row's {go_key}",
                py_row[0].1
            );
        }
    }
}
