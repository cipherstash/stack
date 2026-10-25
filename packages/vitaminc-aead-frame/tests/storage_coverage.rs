//! The golden corpus covers version 1. Every tag, every map key kind, every
//! part of every numbered refusal rule and every clause of *Reading by
//! type* in STORAGE.md has a row that shows it, so another implementation
//! that passes the corpus is held to all of it.
//!
//! What a row covers is read from the row itself: its bytes, through the
//! reference reader, which says which part of which rule refuses a blob,
//! and for a `reads` row, its type and whether it reads. A row's name or
//! `rule` text is never trusted.
//!
//! The rules, the clauses and the grammar they come from are pinned to
//! STORAGE.md's text, word for word. Any change to that text fails this
//! test until the lists here say what the new text asks for, and a row
//! shows it.
#![cfg(feature = "serde")]

#[allow(dead_code)]
mod support;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde_json::Value as Json;
use vitaminc_aead_frame::storage;
use vitaminc_protected::Controlled;

use support::reference::{decode, tag_of, Broken, Refusal, KEY_TAGS};
use support::typed::{read_as, schema, Typed};
use support::{unhex, Model};

/// STORAGE.md, with its line endings as `\n` whatever the checkout made
/// them.
fn spec() -> &'static str {
    static SPEC: OnceLock<String> = OnceLock::new();
    SPEC.get_or_init(|| include_str!("../STORAGE.md").replace("\r\n", "\n"))
}

/// The text of the STORAGE.md section headed `heading`, up to the next
/// heading of any level: a line of one or more `#`, then a space.
fn section(heading: &str) -> &'static str {
    let spec = spec();
    let start = spec
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("STORAGE.md has {heading:?}"))
        + heading.len()
        + 2;
    let rest = &spec[start..];
    let end = rest
        .match_indices("\n#")
        .map(|(at, _)| at)
        .find(|&at| rest[at + 1..].trim_start_matches('#').starts_with(' '))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// `text` with every run of whitespace one space, as the text reads when
/// its line breaks are ignored.
fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

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

fn tags(list: &[u8]) -> BTreeSet<u8> {
    list.iter().copied().collect()
}

fn missing(want: &BTreeSet<u8>, have: &BTreeSet<u8>) -> Vec<String> {
    want.difference(have)
        .map(|t| format!("0x{t:02X}"))
        .collect()
}

// =============================================================================
// Tags and keys, in the vectors
// =============================================================================

/// The grammar's line for a map's key, which `KEY_TAGS` spells out.
const KEY_GRAMMAR: &str = "key = integer / text / bytes";

/// The scalar tags in STORAGE.md's table, whose rows start `` | `0xNN` ``,
/// and the four container tags.
fn node_tags() -> BTreeSet<u8> {
    let mut tags: BTreeSet<u8> = section("## Layout")
        .lines()
        .filter_map(|line| line.strip_prefix("| `0x"))
        .map(|rest| u8::from_str_radix(&rest[..2], 16).expect("a hex tag"))
        .collect();
    assert_eq!(tags.len(), 17, "STORAGE.md's scalar table");
    tags.extend([0xF0, 0xF1, 0xF5, 0xF6]);
    tags
}

/// Every node in `node` that is a value, itself first, into `values`, and
/// every map key into `keys`.
fn walk<'m>(node: &'m Model, values: &mut Vec<&'m Model>, keys: &mut Vec<&'m Model>) {
    values.push(node);
    match node {
        Model::Some(inner) => walk(inner, values, keys),
        Model::Array(items) => items.iter().for_each(|i| walk(i, values, keys)),
        Model::Object(entries) => entries.iter().for_each(|(_, v)| walk(v, values, keys)),
        Model::Map(entries) => {
            for (k, v) in entries {
                keys.push(k);
                walk(v, values, keys);
            }
        }
        _ => {}
    }
}

/// The tags of every value, and of every map key, in the vectors.
fn vector_tags() -> (BTreeSet<u8>, BTreeSet<u8>) {
    let corpus = corpus();
    let (mut values, mut keys) = (BTreeSet::new(), BTreeSet::new());
    for row in rows(&corpus, "vectors") {
        let node = decode(&blob(row)).unwrap_or_else(|e| panic!("{}: {e:?}", name(row)));
        let (mut v, mut k) = (Vec::new(), Vec::new());
        walk(&node, &mut v, &mut k);
        values.extend(v.into_iter().map(tag_of));
        keys.extend(k.into_iter().map(tag_of));
    }
    (values, keys)
}

#[test]
fn every_tag_is_a_value_in_a_vector() {
    let (values, _) = vector_tags();
    let gaps = missing(&node_tags(), &values);
    assert!(gaps.is_empty(), "no vector holds a value of {gaps:?}");
}

#[test]
fn every_key_kind_is_in_a_vector() {
    assert!(
        words(section("## Layout")).contains(KEY_GRAMMAR),
        "STORAGE.md's grammar for a map's key is still {KEY_GRAMMAR:?}"
    );
    let (_, keys) = vector_tags();
    let gaps = missing(&tags(&KEY_TAGS), &keys);
    assert!(gaps.is_empty(), "no vector has a map key of {gaps:?}");
}

// =============================================================================
// Refusals, in the refused rows
// =============================================================================

/// A refused row as a rule sees it: the reference's refusal, and the
/// blob's length.
struct Refused {
    refusal: Refusal,
    len: usize,
}

fn is_integer(tag: u8) -> bool {
    tag != 0x0A && tag != 0x0B && KEY_TAGS.contains(&tag)
}

/// Words quoted from a rule, and what a refusal for that part of it is.
type Part = (&'static str, fn(&Refused) -> bool);

/// One of STORAGE.md's numbered reading rules, word for word, and its
/// parts: words quoted from it, and what a refusal for that part is.
struct Rule {
    text: &'static str,
    parts: &'static [Part],
}

const RULES: &[Rule] = &[
    Rule {
        text: "it is shorter than four bytes, or does not start with `\"VCS\"`: it is not a blob (`ErrorKind::NotABlob`);",
        parts: &[
            ("shorter than four bytes", |r| {
                r.refusal == Refusal::NotABlob && r.len < 4
            }),
            ("does not start with `\"VCS\"`", |r| {
                r.refusal == Refusal::NotABlob && r.len >= 4
            }),
        ],
    },
    Rule {
        text: "its version is one the reader does not read (`ErrorKind::UnsupportedVersion`): this is reported apart from every other refusal, so a caller can tell a reader that needs upgrading from a corrupt blob;",
        parts: &[("its version is one the reader does not read", |r| {
            r.refusal == Refusal::UnsupportedVersion
        })],
    },
    Rule {
        text: "the body after the header is not exactly one node: it is truncated, or bytes follow the node;",
        parts: &[
            ("it is truncated", |r| {
                r.refusal == Refusal::Malformed(Broken::NotOneNode { trailing: false })
            }),
            ("bytes follow the node", |r| {
                r.refusal == Refusal::Malformed(Broken::NotOneNode { trailing: true })
            }),
        ],
    },
    Rule {
        text: "a node, or a map's key, starts with a byte the grammar above does not allow there;",
        parts: &[
            ("a node", |r| {
                matches!(
                    r.refusal,
                    Refusal::Malformed(Broken::Tag { as_key: false, .. })
                )
            }),
            ("a map's key", |r| {
                matches!(
                    r.refusal,
                    Refusal::Malformed(Broken::Tag { as_key: true, .. })
                )
            }),
        ],
    },
    Rule {
        text: "a length or count runs past the end of the blob;",
        parts: &[
            ("a length", |r| {
                r.refusal == Refusal::Malformed(Broken::PastTheEnd { count: false })
            }),
            ("or count", |r| {
                r.refusal == Refusal::Malformed(Broken::PastTheEnd { count: true })
            }),
        ],
    },
    Rule {
        text: "an object's key or a text scalar is not valid UTF-8;",
        parts: &[
            ("an object's key", |r| {
                r.refusal == Refusal::Malformed(Broken::NotUtf8 { key: true })
            }),
            ("a text scalar", |r| {
                r.refusal == Refusal::Malformed(Broken::NotUtf8 { key: false })
            }),
        ],
    },
    Rule {
        text: "one object has two entries whose keys are the same bytes;",
        parts: &[("two entries whose keys are the same bytes", |r| {
            r.refusal == Refusal::Malformed(Broken::RepeatedField)
        })],
    },
    Rule {
        text: "one map has two equal keys: two integers of the same value, whatever their widths (`1u8` and `1u64`, `5i8` and `5u128`), or two text keys, or two bytes keys, with the same bytes. Text and bytes never equal each other or an integer;",
        parts: &[
            ("two integers of the same value, whatever their widths", |r| {
                matches!(r.refusal, Refusal::Malformed(Broken::RepeatedKey { first, second })
                    if first != second && is_integer(first) && is_integer(second))
            }),
            ("two text keys", |r| {
                r.refusal
                    == Refusal::Malformed(Broken::RepeatedKey {
                        first: 0x0A,
                        second: 0x0A,
                    })
            }),
            ("two bytes keys", |r| {
                r.refusal
                    == Refusal::Malformed(Broken::RepeatedKey {
                        first: 0x0B,
                        second: 0x0B,
                    })
            }),
        ],
    },
    Rule {
        text: "a node is deeper than 128.",
        parts: &[("deeper than 128", |r| {
            r.refusal == Refusal::Malformed(Broken::TooDeep)
        })],
    },
];

/// The numbered rules in *Reading*, each as its words: a line that starts
/// `N. `, and the indented lines that continue it.
fn numbered_rules() -> Vec<String> {
    let mut rules: Vec<String> = Vec::new();
    let mut open = false;
    for line in section("## Reading").lines() {
        let digits = line.chars().take_while(char::is_ascii_digit).count();
        if let Some(rest) = line[digits..].strip_prefix(". ").filter(|_| digits > 0) {
            rules.push(rest.to_owned());
            open = true;
        } else if open && line.starts_with(' ') {
            let rule = rules.last_mut().expect("an open rule");
            rule.push(' ');
            rule.push_str(line);
        } else {
            open = false;
        }
    }
    rules.iter().map(|rule| words(rule)).collect()
}

/// What the reference refuses each refused row for. A row whose class is
/// not the one the reference gives fails here, as it does in the corpus
/// test.
fn refusals(corpus: &Json) -> Vec<Refused> {
    rows(corpus, "refused")
        .iter()
        .map(|row| {
            let bytes = blob(row);
            let refusal = decode(&bytes).expect_err(name(row));
            let class = match refusal {
                Refusal::NotABlob => "not_a_blob",
                Refusal::UnsupportedVersion => "unsupported_version",
                Refusal::Malformed(_) => "malformed",
            };
            assert_eq!(row["refusal"], class, "{}", name(row));
            Refused {
                refusal,
                len: bytes.len(),
            }
        })
        .collect()
}

#[test]
fn every_part_of_every_reading_rule_has_a_refused_row() {
    let texts: Vec<&str> = RULES.iter().map(|rule| rule.text).collect();
    assert_eq!(numbered_rules(), texts, "STORAGE.md's reading rules");

    let refused = refusals(&corpus());
    let mut gaps = Vec::new();
    for (number, rule) in (1..).zip(RULES) {
        for (quote, shown_by) in rule.parts {
            assert!(rule.text.contains(quote), "{quote:?} is in rule {number}");
            if !refused.iter().any(shown_by) {
                gaps.push(format!("rule {number}: {quote:?}"));
            }
        }
    }
    assert!(gaps.is_empty(), "no refused row breaks {gaps:#?}");
}

/// The sentence in *Layout* that names the tags the profile refuses, which
/// `REFUSED_TAGS` spells out.
const REFUSED_SENTENCE: &str = "In particular the tags the frame and the sealed leaf know but this profile does not are refused: `0x01` (JavaScript `undefined`), `0x12` to `0x15` (date, timestamp, decimal, typed null), `0xF2` (passthrough), `0xF3` and `0xF4` (logical-type envelopes).";

const REFUSED_TAGS: [u8; 8] = [0x01, 0x12, 0x13, 0x14, 0x15, 0xF2, 0xF3, 0xF4];

#[test]
fn every_refused_tag_and_key_kind_has_a_refused_row() {
    assert!(
        words(section("## Layout")).contains(REFUSED_SENTENCE),
        "STORAGE.md's refused tags are still {REFUSED_SENTENCE:?}"
    );
    let (mut as_node, mut as_key) = (BTreeSet::new(), BTreeSet::new());
    for refused in refusals(&corpus()) {
        if let Refusal::Malformed(Broken::Tag { byte, as_key: key }) = refused.refusal {
            if key {
                as_key.insert(byte);
            } else {
                as_node.insert(byte);
            }
        }
    }

    let known = tags(&REFUSED_TAGS);
    let gaps = missing(&known, &as_node);
    assert!(
        gaps.is_empty(),
        "no refused row starts a node with {gaps:?}"
    );
    let node_tags = node_tags();
    assert!(
        as_node
            .iter()
            .any(|b| !node_tags.contains(b) && !known.contains(b)),
        "no refused row starts a node with a byte that is no tag"
    );

    // A key may be an integer, text or bytes, so every other node is
    // refused as one.
    let refused_keys: BTreeSet<u8> = node_tags.difference(&tags(&KEY_TAGS)).copied().collect();
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
        if !self.is("enum") {
            return None;
        }
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

/// Whether `node`, written as a blob, reads as `ty`.
fn reads_as(ty: &Json, node: &Model) -> bool {
    let blob = storage::to_vec(node).expect("writes").risky_unwrap();
    read_as(schema(ty));
    storage::from_slice::<Typed>(&blob).is_ok()
}

/// The type and node a refused row would be, but for what a clause is
/// about.
type ButFor = fn(&Row) -> Option<(Json, Model)>;

/// One clause of *Reading by type*: words quoted from it, whether a row
/// that shows it reads or is refused, and what such a row looks like.
///
/// A refused row could be refused for more than one reason. So a clause
/// about a container says what the row would be `but_for` what the clause
/// is about: that type and node must read, or the refusal is not the
/// clause's.
struct Clause {
    quote: &'static str,
    reads: bool,
    shown_by: fn(&Row) -> bool,
    but_for: Option<ButFor>,
}

const fn reads(quote: &'static str, shown_by: fn(&Row) -> bool) -> Clause {
    Clause {
        quote,
        reads: true,
        shown_by,
        but_for: None,
    }
}

const fn refuses(quote: &'static str, shown_by: fn(&Row) -> bool) -> Clause {
    Clause {
        quote,
        reads: false,
        shown_by,
        but_for: None,
    }
}

const fn refuses_but_for(
    quote: &'static str,
    shown_by: fn(&Row) -> bool,
    but_for: ButFor,
) -> Clause {
    Clause {
        quote,
        reads: false,
        shown_by,
        but_for: Some(but_for),
    }
}

/// One bullet of *Reading by type*, word for word, and its clauses. A
/// clause that says a type reads only some nodes is listed twice: one row
/// that reads, one that is refused.
struct Bullet {
    text: &'static str,
    clauses: &'static [Clause],
}

const BULLETS: &[Bullet] = &[
    Bullet {
        text: "An integer reads as any integer type it fits; a type that reads through `deserialize_any` sees it at its written width. A float type reads a float or an integer, as serde's float types do; an integer type never reads a float.",
        clauses: &[
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
    },
    Bullet {
        text: "An `Option` reads null as `None`, `some` as `Some`, and any other node as `Some` holding that node, so a blob written before a field became optional reads. A type whose own value is written as null (unit, a unit struct, an `Option`) reads its old null as `None` instead.",
        clauses: &[
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
    },
    Bullet {
        text: "An enum reads a variant's name as a unit variant, or as a newtype variant whose value is read from null; and an object of one entry whose value is null as a unit variant. A map of one entry is not a variant.",
        clauses: &[
            reads("An enum reads a variant's name as a unit variant", |r| {
                matches!(&r.node, Model::Text(n) if r.variant(n) == Some("unit"))
            }),
            reads("or as a newtype variant whose value is read from null", |r| {
                matches!(&r.node, Model::Text(n) if r.variant(n) == Some("newtype"))
            }),
            reads(
                "an object of one entry whose value is null as a unit variant",
                |r| match &r.node {
                    Model::Object(e) => {
                        e.len() == 1 && e[0].1 == Model::Null && r.variant(&e[0].0) == Some("unit")
                    }
                    _ => false,
                },
            ),
            refuses_but_for(
                "A map of one entry is not a variant",
                |r| r.is("enum") && matches!(&r.node, Model::Map(e) if e.len() == 1),
                // The same entry, as an object, is a variant.
                |r| match &r.node {
                    Model::Map(e) => match &e[0] {
                        (Model::Text(k), v) => Some((
                            r.ty?.clone(),
                            Model::Object(vec![(k.clone(), v.clone())]),
                        )),
                        _ => None,
                    },
                    _ => None,
                },
            ),
        ],
    },
    Bullet {
        text: "A struct reads an object, or a map whose keys are all text. A map reads a map or an object. A sequence reads only an array, a string only text, and bytes only bytes. A struct ignores unknown keys unless it denies them, and reads a missing `Option` field as `None`, as serde's derive does.",
        clauses: &[
            reads("A struct reads an object", |r| {
                r.is_struct() && matches!(r.node, Model::Object(_))
            }),
            reads("or a map whose keys are all text", |r| {
                r.is_struct() && matches!(r.node, Model::Map(_)) && r.text_keys().is_some()
            }),
            refuses_but_for(
                "a map whose keys are all text",
                |r| r.is_struct() && matches!(r.node, Model::Map(_)) && r.text_keys().is_none(),
                // The same map, without the keys that are not text.
                |r| match &r.node {
                    Model::Map(e) => Some((
                        r.ty?.clone(),
                        Model::Map(
                            e.iter()
                                .filter(|(k, _)| matches!(k, Model::Text(_)))
                                .cloned()
                                .collect(),
                        ),
                    )),
                    _ => None,
                },
            ),
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
            refuses_but_for(
                "unless it denies them",
                |r| r.is("struct_deny_unknown") && r.has_unknown_key(),
                // The same struct, ignoring them.
                |r| Some((serde_json::json!({ "struct": r.kind().1 }), r.node.clone())),
            ),
            reads("reads a missing `Option` field as `None`", |r| {
                let keys = r.text_keys().unwrap_or_default();
                r.is_struct()
                    && r.text_keys().is_some()
                    && r.fields()
                        .iter()
                        .any(|(f, optional)| *optional && !keys.contains(f))
            }),
        ],
    },
];

#[test]
fn every_clause_of_reading_by_type_has_a_row() {
    let bullets: Vec<String> = section("### Reading by type")
        .split("\n- ")
        .skip(1)
        .map(|bullet| words(&bullet[..bullet.find("\n\n").unwrap_or(bullet.len())]))
        .collect();
    let texts: Vec<&str> = BULLETS.iter().map(|b| b.text).collect();
    assert_eq!(bullets, texts, "the bullets of *Reading by type*");

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
    for bullet in BULLETS {
        for clause in bullet.clauses {
            assert!(
                bullet.text.contains(clause.quote),
                "{:?} is in its bullet",
                clause.quote
            );
            let shown = all.iter().any(|row| {
                row.reads == clause.reads
                    && (clause.shown_by)(row)
                    && clause.but_for.is_none_or(|but_for| {
                        but_for(row).is_some_and(|(ty, node)| reads_as(&ty, &node))
                    })
            });
            if !shown {
                let how = if clause.reads { "reads" } else { "is refused" };
                gaps.push(format!("{:?} ({how})", clause.quote));
            }
        }
    }
    assert!(gaps.is_empty(), "no row shows {gaps:#?}");
}
