//! The golden corpus covers version 1. Every tag, every map key kind, every
//! numbered refusal rule and every clause of *Reading by type* in
//! STORAGE.md has a row that shows it, so another implementation that
//! passes the corpus is held to all of it.
//!
//! What a row covers is read from the row itself: its bytes, through the
//! reference reader, which says which rule refuses a blob, and for a
//! `reads` row, its type and whether it reads. A row's name or `rule` text
//! is never trusted. The rules and clauses are tied to STORAGE.md's text,
//! so a rule or a clause added there fails this test until it is listed
//! here and a row shows it.
#![cfg(feature = "serde")]

#[allow(dead_code)]
mod support;

use std::collections::BTreeSet;

use serde_json::Value as Json;

use support::reference::{decode, Broken, Refusal};
use support::{unhex, Model};

const SPEC: &str = include_str!("../STORAGE.md");

fn corpus() -> Json {
    serde_json::from_str(include_str!("../testdata/storage-v1.json")).expect("corpus is JSON")
}

fn rows<'a>(corpus: &'a Json, section: &str) -> &'a [Json] {
    corpus[section].as_array().expect("a section is an array")
}

fn name(row: &Json) -> &str {
    row["name"].as_str().expect("a row has a name")
}

fn blob(row: &Json) -> Vec<u8> {
    unhex(row["blob"].as_str().expect("a row has a blob"))
}

/// The text of the STORAGE.md section headed `heading`, up to the next
/// heading of any level.
fn section(heading: &str) -> &'static str {
    let start = SPEC
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("STORAGE.md has {heading:?}"))
        + heading.len()
        + 2;
    let rest = &SPEC[start..];
    &rest[..rest.find("\n#").unwrap_or(rest.len())]
}

/// `text` with every run of whitespace one space, as the text reads when
/// its line breaks are ignored.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// =============================================================================
// Tags and keys, in the vectors
// =============================================================================

const ARRAY: u8 = 0xF0;
const OBJECT: u8 = 0xF1;
const SOME: u8 = 0xF5;
const MAP: u8 = 0xF6;

/// The tag a node starts with.
fn tag(node: &Model) -> u8 {
    match node {
        Model::Null => 0x00,
        Model::Bool(false) => 0x02,
        Model::Bool(true) => 0x03,
        Model::I8(_) => 0x0C,
        Model::I16(_) => 0x0E,
        Model::I32(_) => 0x04,
        Model::I64(_) => 0x05,
        Model::I128(_) => 0x10,
        Model::U8(_) => 0x0D,
        Model::U16(_) => 0x0F,
        Model::U32(_) => 0x06,
        Model::U64(_) => 0x07,
        Model::U128(_) => 0x11,
        Model::F32(_) => 0x08,
        Model::F64(_) => 0x09,
        Model::Text(_) => 0x0A,
        Model::Bytes(_) => 0x0B,
        Model::Some(_) => SOME,
        Model::Array(_) => ARRAY,
        Model::Object(_) => OBJECT,
        Model::Map(_) => MAP,
    }
}

/// Every node in `node`, itself first, and each map's keys in `keys`.
fn walk<'m>(node: &'m Model, nodes: &mut Vec<&'m Model>, keys: &mut Vec<&'m Model>) {
    nodes.push(node);
    match node {
        Model::Some(inner) => walk(inner, nodes, keys),
        Model::Array(items) => items.iter().for_each(|i| walk(i, nodes, keys)),
        Model::Object(entries) => entries.iter().for_each(|(_, v)| walk(v, nodes, keys)),
        Model::Map(entries) => {
            for (k, v) in entries {
                keys.push(k);
                walk(v, nodes, keys);
            }
        }
        _ => {}
    }
}

/// The scalar tags in STORAGE.md's table: each row starts `` | `0xNN` ``.
fn scalar_tags() -> BTreeSet<u8> {
    let tags: BTreeSet<u8> = section("## Layout")
        .lines()
        .filter_map(|line| line.strip_prefix("| `0x"))
        .map(|rest| u8::from_str_radix(&rest[..2], 16).expect("a hex tag"))
        .collect();
    assert_eq!(tags.len(), 17, "STORAGE.md's scalar table");
    tags
}

/// A map's key is an integer of any width, text or bytes.
fn key_tags() -> BTreeSet<u8> {
    [
        0x0C, 0x0E, 0x04, 0x05, 0x10, 0x0D, 0x0F, 0x06, 0x07, 0x11, 0x0A, 0x0B,
    ]
    .into()
}

/// The tags a node may start with.
fn node_tags() -> BTreeSet<u8> {
    let mut tags = scalar_tags();
    tags.extend([ARRAY, OBJECT, SOME, MAP]);
    tags
}

fn missing(want: &BTreeSet<u8>, have: &BTreeSet<u8>) -> Vec<String> {
    want.difference(have)
        .map(|t| format!("0x{t:02X}"))
        .collect()
}

#[test]
fn every_tag_is_in_a_vector() {
    let corpus = corpus();
    let mut have = BTreeSet::new();
    for row in rows(&corpus, "vectors") {
        let node = decode(&blob(row)).unwrap_or_else(|e| panic!("{}: {e:?}", name(row)));
        let (mut nodes, mut keys) = (Vec::new(), Vec::new());
        walk(&node, &mut nodes, &mut keys);
        have.extend(nodes.into_iter().chain(keys).map(tag));
    }
    let gaps = missing(&node_tags(), &have);
    assert!(gaps.is_empty(), "no vector holds {gaps:?}");
}

#[test]
fn every_key_kind_is_in_a_vector() {
    let corpus = corpus();
    let mut have = BTreeSet::new();
    for row in rows(&corpus, "vectors") {
        let node = decode(&blob(row)).expect("a vector reads");
        let (mut nodes, mut keys) = (Vec::new(), Vec::new());
        walk(&node, &mut nodes, &mut keys);
        have.extend(keys.into_iter().map(tag));
    }
    let gaps = missing(&key_tags(), &have);
    assert!(gaps.is_empty(), "no vector has a map key of {gaps:?}");
}

// =============================================================================
// Refusals, in the refused rows
// =============================================================================

/// The number of the rule in STORAGE.md's *Reading* that refuses a blob.
fn rule(refusal: Refusal) -> u8 {
    match refusal {
        Refusal::NotABlob => 1,
        Refusal::UnsupportedVersion => 2,
        Refusal::Malformed(broken) => match broken {
            Broken::NotOneNode => 3,
            Broken::Tag { .. } => 4,
            Broken::PastTheEnd => 5,
            Broken::NotUtf8 => 6,
            Broken::RepeatedField => 7,
            Broken::RepeatedKey => 8,
            Broken::TooDeep => 9,
        },
    }
}

/// What the reference refuses each refused row for. A row whose class is
/// not the one the reference gives fails here, as it does in the corpus
/// test.
fn refusals() -> Vec<(String, Refusal)> {
    let corpus = corpus();
    rows(&corpus, "refused")
        .iter()
        .map(|row| {
            let refusal = decode(&blob(row)).expect_err(name(row));
            let class = match refusal {
                Refusal::NotABlob => "not_a_blob",
                Refusal::UnsupportedVersion => "unsupported_version",
                Refusal::Malformed(_) => "malformed",
            };
            assert_eq!(row["refusal"], class, "{}", name(row));
            (name(row).to_owned(), refusal)
        })
        .collect()
}

#[test]
fn every_reading_rule_has_a_refused_row() {
    // The rules are the numbered list in *Reading*; the reference knows
    // nine. A rule added there needs the reference to know it first.
    let numbered = section("## Reading")
        .lines()
        .filter(|line| {
            let digits = line.chars().take_while(char::is_ascii_digit).count();
            digits > 0 && line[digits..].starts_with(". ")
        })
        .count();
    assert_eq!(numbered, 9, "STORAGE.md's reading rules");

    let have: BTreeSet<u8> = refusals().iter().map(|(_, r)| rule(*r)).collect();
    let gaps: Vec<u8> = (1..=9).filter(|rule| !have.contains(rule)).collect();
    assert!(gaps.is_empty(), "no refused row breaks rule {gaps:?}");
}

#[test]
fn every_refused_tag_and_key_kind_has_a_refused_row() {
    let (mut as_node, mut as_key) = (BTreeSet::new(), BTreeSet::new());
    for (_, refusal) in refusals() {
        if let Refusal::Malformed(Broken::Tag { byte, as_key: key }) = refusal {
            if key {
                as_key.insert(byte);
            } else {
                as_node.insert(byte);
            }
        }
    }

    // The tags the frame and the sealed leaf know but this profile refuses,
    // as *Layout* lists them, and a byte that is no tag at all.
    let known: BTreeSet<u8> = [0x01, 0x12, 0x13, 0x14, 0x15, 0xF2, 0xF3, 0xF4].into();
    let listed = words(section("## Layout"));
    for phrase in ["`0x01`", "`0x12` to `0x15`", "`0xF2`", "`0xF3` and `0xF4`"] {
        assert!(
            listed.contains(phrase),
            "STORAGE.md lists {phrase} as refused"
        );
    }
    let gaps = missing(&known, &as_node);
    assert!(
        gaps.is_empty(),
        "no refused row starts a node with {gaps:?}"
    );
    assert!(
        as_node
            .iter()
            .any(|b| !node_tags().contains(b) && !known.contains(b)),
        "no refused row starts a node with a byte that is no tag"
    );

    // A key may be an integer, text or bytes, so every other node is
    // refused as one.
    let refused_keys: BTreeSet<u8> = node_tags().difference(&key_tags()).copied().collect();
    let gaps = missing(&refused_keys, &as_key);
    assert!(gaps.is_empty(), "no refused row has a map key of {gaps:?}");
}

// =============================================================================
// Reading by type, in the reads rows
// =============================================================================

/// One row as a clause sees it: the type it is read as (none for a
/// vector, which is read through `deserialize_any`), its node, and whether
/// it reads.
struct Row<'r> {
    ty: Option<&'r Json>,
    node: Model,
    reads: bool,
}

impl Row<'_> {
    /// The kind of the type, and what follows it: `("u8", null)`,
    /// `("option", T)`, `("struct", [[name, T], …])`.
    fn kind(&self) -> (&str, &Json) {
        match self.ty {
            None => ("any", &Json::Null),
            Some(Json::String(name)) => (name, &Json::Null),
            Some(Json::Object(kind)) => {
                let (kind, inner) = kind.iter().next().expect("a type names its kind");
                (kind, inner)
            }
            Some(other) => panic!("a type is a name or an object: {other}"),
        }
    }

    fn is(&self, kind: &str) -> bool {
        self.kind().0 == kind
    }

    fn is_integer_type(&self) -> bool {
        INTEGERS.contains(&self.kind().0)
    }

    fn is_float_type(&self) -> bool {
        matches!(self.kind().0, "f32" | "f64")
    }

    fn is_struct(&self) -> bool {
        self.is("struct") || self.is("struct_deny_unknown")
    }

    /// A struct type's field names, and which of them are options.
    fn fields(&self) -> Vec<(&str, bool)> {
        self.kind()
            .1
            .as_array()
            .expect("fields")
            .iter()
            .map(|pair| {
                let optional = pair[1]
                    .as_object()
                    .is_some_and(|t| t.contains_key("option"));
                (pair[0].as_str().expect("a field name"), optional)
            })
            .collect()
    }

    /// An enum type's variant named `name`, by its kind.
    fn variant(&self, name: &str) -> Option<&str> {
        self.kind()
            .1
            .as_array()?
            .iter()
            .find(|v| v[0] == name)
            .and_then(|v| v[1].as_str())
    }

    /// The keys of an object or a map node whose keys are all text.
    fn text_keys(&self) -> Option<Vec<&str>> {
        match &self.node {
            Model::Object(entries) => Some(entries.iter().map(|(k, _)| k.as_str()).collect()),
            Model::Map(entries) => entries
                .iter()
                .map(|(k, _)| match k {
                    Model::Text(k) => Some(k.as_str()),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }

    /// The node has a key that is not one of the struct's fields.
    fn has_unknown_key(&self) -> bool {
        let fields = self.fields();
        self.text_keys()
            .is_some_and(|keys| keys.iter().any(|k| !fields.iter().any(|(f, _)| f == k)))
    }

    /// The node holds every field of the struct.
    fn has_every_field(&self) -> bool {
        let keys = self.text_keys().unwrap_or_default();
        self.fields().iter().all(|(f, _)| keys.contains(f))
    }
}

const INTEGERS: [&str; 10] = [
    "i8", "i16", "i32", "i64", "i128", "u8", "u16", "u32", "u64", "u128",
];

/// The integer type a node is written as, if it is an integer.
fn integer(node: &Model) -> Option<&'static str> {
    Some(match node {
        Model::I8(_) => "i8",
        Model::I16(_) => "i16",
        Model::I32(_) => "i32",
        Model::I64(_) => "i64",
        Model::I128(_) => "i128",
        Model::U8(_) => "u8",
        Model::U16(_) => "u16",
        Model::U32(_) => "u32",
        Model::U64(_) => "u64",
        Model::U128(_) => "u128",
        _ => return None,
    })
}

fn is_float(node: &Model) -> bool {
    matches!(node, Model::F32(_) | Model::F64(_))
}

/// One clause of *Reading by type*: words quoted from it, whether a row
/// that shows it reads or is refused, and what such a row looks like.
struct Clause {
    quote: &'static str,
    reads: bool,
    shown_by: fn(&Row) -> bool,
}

const fn reads(quote: &'static str, shown_by: fn(&Row) -> bool) -> Clause {
    Clause {
        quote,
        reads: true,
        shown_by,
    }
}

const fn refuses(quote: &'static str, shown_by: fn(&Row) -> bool) -> Clause {
    Clause {
        quote,
        reads: false,
        shown_by,
    }
}

/// The clauses, bullet by bullet. A clause that says a type reads only
/// some nodes is listed twice: one row that reads, one that is refused.
const CLAUSES: &[&[Clause]] = &[
    &[
        reads("An integer reads as any integer type it fits", |r| {
            r.is_integer_type() && integer(&r.node).is_some_and(|w| w != r.kind().0)
        }),
        refuses("any integer type it fits", |r| {
            r.is_integer_type() && integer(&r.node).is_some()
        }),
        // The vectors are read through `deserialize_any`.
        reads("sees it at its written width", |r| {
            r.ty.is_none() && integer(&r.node).is_some()
        }),
        reads("A float type reads a float", |r| {
            r.is_float_type() && is_float(&r.node)
        }),
        reads("or an integer", |r| {
            r.is_float_type() && integer(&r.node).is_some()
        }),
        refuses("an integer type never reads a float", |r| {
            r.is_integer_type() && is_float(&r.node)
        }),
    ],
    &[
        reads("An `Option` reads null as `None`", |r| {
            r.is("option") && r.node == Model::Null
        }),
        reads("`some` as `Some`", |r| {
            r.is("option") && matches!(r.node, Model::Some(_))
        }),
        reads("any other node as `Some` holding that node", |r| {
            r.is("option") && !matches!(r.node, Model::Null | Model::Some(_))
        }),
        reads("reads its old null as `None` instead", |r| {
            let inner = r.kind().1;
            r.is("option")
                && r.node == Model::Null
                && (inner == "unit" || inner.get("option").is_some())
        }),
    ],
    &[
        reads("An enum reads a variant's name as a unit variant", |r| {
            r.is("enum") && matches!(&r.node, Model::Text(n) if r.variant(n) == Some("unit"))
        }),
        reads(
            "or as a newtype variant whose value is read from null",
            |r| {
                r.is("enum") && matches!(&r.node, Model::Text(n) if r.variant(n) == Some("newtype"))
            },
        ),
        reads(
            "an object of one entry whose value is null as a unit variant",
            |r| match &r.node {
                Model::Object(e) => {
                    r.is("enum")
                        && e.len() == 1
                        && e[0].1 == Model::Null
                        && r.variant(&e[0].0) == Some("unit")
                }
                _ => false,
            },
        ),
        refuses("A map of one entry is not a variant", |r| {
            r.is("enum") && matches!(&r.node, Model::Map(e) if e.len() == 1)
        }),
    ],
    &[
        reads("A struct reads an object", |r| {
            r.is_struct() && matches!(r.node, Model::Object(_))
        }),
        reads("or a map whose keys are all text", |r| {
            r.is_struct() && matches!(r.node, Model::Map(_)) && r.text_keys().is_some()
        }),
        refuses("a map whose keys are all text", |r| {
            r.is_struct() && matches!(r.node, Model::Map(_)) && r.text_keys().is_none()
        }),
        reads("A map reads a map", |r| {
            r.is("map") && matches!(r.node, Model::Map(_))
        }),
        reads("A map reads a map or an object", |r| {
            r.is("map") && matches!(r.node, Model::Object(_))
        }),
        reads("A sequence reads only an array", |r| {
            r.is("seq") && matches!(r.node, Model::Array(_))
        }),
        refuses("A sequence reads only an array", |r| {
            r.is("seq") && !matches!(r.node, Model::Array(_))
        }),
        reads("a string only text", |r| {
            r.is("text") && matches!(r.node, Model::Text(_))
        }),
        refuses("a string only text", |r| {
            r.is("text") && !matches!(r.node, Model::Text(_))
        }),
        reads("bytes only bytes", |r| {
            r.is("bytes") && matches!(r.node, Model::Bytes(_))
        }),
        refuses("bytes only bytes", |r| {
            r.is("bytes") && !matches!(r.node, Model::Bytes(_))
        }),
        reads("A struct ignores unknown keys", |r| {
            r.is("struct") && r.has_unknown_key()
        }),
        refuses("unless it denies them", |r| {
            r.is("struct_deny_unknown") && r.has_unknown_key() && r.has_every_field()
        }),
        reads("reads a missing `Option` field as `None`", |r| {
            r.is_struct()
                && r.text_keys().is_some()
                && r.fields().iter().any(|(f, optional)| {
                    *optional && !r.text_keys().unwrap_or_default().contains(f)
                })
        }),
    ],
];

#[test]
fn every_clause_of_reading_by_type_has_a_row() {
    let spec = section("### Reading by type");
    let bullets: Vec<String> = spec
        .split("\n- ")
        .skip(1)
        .map(|bullet| words(&bullet[..bullet.find("\n\n").unwrap_or(bullet.len())]))
        .collect();
    assert_eq!(
        bullets.len(),
        CLAUSES.len(),
        "the bullets of *Reading by type*"
    );

    let corpus = corpus();
    let vectors = rows(&corpus, "vectors").iter().map(|row| Row {
        ty: None,
        node: decode(&blob(row)).expect("a vector reads"),
        reads: true,
    });
    let typed = rows(&corpus, "reads").iter().map(|row| Row {
        ty: Some(&row["type"]),
        node: decode(&blob(row)).unwrap_or_else(|e| panic!("{}: {e:?}", name(row))),
        reads: row.get("reads_as").is_some(),
    });
    let all: Vec<Row> = vectors.chain(typed).collect();

    let mut gaps = Vec::new();
    for (bullet, clauses) in bullets.iter().zip(CLAUSES) {
        for clause in *clauses {
            assert!(
                bullet.contains(clause.quote),
                "{:?} is not in the bullet {bullet:?}",
                clause.quote
            );
            if !all
                .iter()
                .any(|row| row.reads == clause.reads && (clause.shown_by)(row))
            {
                let how = if clause.reads { "reads" } else { "is refused" };
                gaps.push(format!("{:?} ({how})", clause.quote));
            }
        }
    }
    assert!(gaps.is_empty(), "no row shows {gaps:#?}");
}
