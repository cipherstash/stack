//! The storage profile: the golden corpus, which pins version 1 byte for
//! byte, and what the serde mapping writes, reads and refuses.
#![cfg(feature = "serde")]

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use quickcheck_macros::quickcheck;
use serde::de::{self, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use vitaminc_aead_frame::serde::{Error, PathSegment};
use vitaminc_aead_frame::storage::{from_slice, to_vec, HEADER, SOME};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn blob(body: &[u8]) -> Vec<u8> {
    [&HEADER[..], body].concat()
}

// =============================================================================
// The model: one value of the storage data model, whatever type wrote it
// =============================================================================

/// A node as the corpus describes it. It reads through `deserialize_any`,
/// so it sees exactly what a blob holds, and writes it back the same way.
#[derive(Debug, Clone, PartialEq)]
enum Model {
    Null,
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    /// The bits, so a NaN's payload compares.
    F32(u32),
    F64(u64),
    Text(String),
    Bytes(Vec<u8>),
    Some(Box<Model>),
    Array(Vec<Model>),
    Object(Vec<(String, Model)>),
}

impl Serialize for Model {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Model::Null => s.serialize_unit(),
            Model::Bool(v) => s.serialize_bool(*v),
            Model::I8(v) => s.serialize_i8(*v),
            Model::I16(v) => s.serialize_i16(*v),
            Model::I32(v) => s.serialize_i32(*v),
            Model::I64(v) => s.serialize_i64(*v),
            Model::I128(v) => s.serialize_i128(*v),
            Model::U8(v) => s.serialize_u8(*v),
            Model::U16(v) => s.serialize_u16(*v),
            Model::U32(v) => s.serialize_u32(*v),
            Model::U64(v) => s.serialize_u64(*v),
            Model::U128(v) => s.serialize_u128(*v),
            Model::F32(bits) => s.serialize_f32(f32::from_bits(*bits)),
            Model::F64(bits) => s.serialize_f64(f64::from_bits(*bits)),
            Model::Text(v) => s.serialize_str(v),
            Model::Bytes(v) => s.serialize_bytes(v),
            Model::Some(v) => s.serialize_some(v.as_ref()),
            Model::Array(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Model::Object(entries) => {
                let mut map = s.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Model {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Model;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any node")
            }
            fn visit_unit<E>(self) -> Result<Model, E> {
                Ok(Model::Null)
            }
            fn visit_some<D: de::Deserializer<'de>>(self, d: D) -> Result<Model, D::Error> {
                Ok(Model::Some(Box::new(Model::deserialize(d)?)))
            }
            fn visit_bool<E>(self, v: bool) -> Result<Model, E> {
                Ok(Model::Bool(v))
            }
            fn visit_i8<E>(self, v: i8) -> Result<Model, E> {
                Ok(Model::I8(v))
            }
            fn visit_i16<E>(self, v: i16) -> Result<Model, E> {
                Ok(Model::I16(v))
            }
            fn visit_i32<E>(self, v: i32) -> Result<Model, E> {
                Ok(Model::I32(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Model, E> {
                Ok(Model::I64(v))
            }
            fn visit_i128<E>(self, v: i128) -> Result<Model, E> {
                Ok(Model::I128(v))
            }
            fn visit_u8<E>(self, v: u8) -> Result<Model, E> {
                Ok(Model::U8(v))
            }
            fn visit_u16<E>(self, v: u16) -> Result<Model, E> {
                Ok(Model::U16(v))
            }
            fn visit_u32<E>(self, v: u32) -> Result<Model, E> {
                Ok(Model::U32(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Model, E> {
                Ok(Model::U64(v))
            }
            fn visit_u128<E>(self, v: u128) -> Result<Model, E> {
                Ok(Model::U128(v))
            }
            fn visit_f32<E>(self, v: f32) -> Result<Model, E> {
                Ok(Model::F32(v.to_bits()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Model, E> {
                Ok(Model::F64(v.to_bits()))
            }
            fn visit_str<E>(self, v: &str) -> Result<Model, E> {
                Ok(Model::Text(v.to_owned()))
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Model, E> {
                Ok(Model::Bytes(v.to_vec()))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Model, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Model::Array(items))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Model, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    entries.push(entry);
                }
                Ok(Model::Object(entries))
            }
        }
        d.deserialize_any(V)
    }
}

/// A corpus value: `null`, or an object of one entry naming the kind.
fn model(json: &Json) -> Model {
    let Some(object) = json.as_object() else {
        assert!(json.is_null(), "a value is null or a kind: {json}");
        return Model::Null;
    };
    assert_eq!(object.len(), 1, "a value names one kind: {json}");
    let (kind, value) = object.iter().next().expect("one entry");
    let text = || value.as_str().expect("a string");
    let hex64 = || u64::from_str_radix(text(), 16).expect("hex bits");
    match kind.as_str() {
        "bool" => Model::Bool(value.as_bool().expect("a bool")),
        "i8" => Model::I8(text().parse().expect("i8")),
        "i16" => Model::I16(text().parse().expect("i16")),
        "i32" => Model::I32(text().parse().expect("i32")),
        "i64" => Model::I64(text().parse().expect("i64")),
        "i128" => Model::I128(text().parse().expect("i128")),
        "u8" => Model::U8(text().parse().expect("u8")),
        "u16" => Model::U16(text().parse().expect("u16")),
        "u32" => Model::U32(text().parse().expect("u32")),
        "u64" => Model::U64(text().parse().expect("u64")),
        "u128" => Model::U128(text().parse().expect("u128")),
        "f32_bits" => Model::F32(u32::try_from(hex64()).expect("32 bits")),
        "f64_bits" => Model::F64(hex64()),
        "text" => Model::Text(text().to_owned()),
        "bytes" => Model::Bytes(unhex(text())),
        "some" => Model::Some(Box::new(model(value))),
        "array" => Model::Array(
            value
                .as_array()
                .expect("an array")
                .iter()
                .map(model)
                .collect(),
        ),
        "object" => Model::Object(
            value
                .as_array()
                .expect("an array of entries")
                .iter()
                .map(|entry| {
                    let pair = entry.as_array().expect("a [key, value] pair");
                    (pair[0].as_str().expect("a key").to_owned(), model(&pair[1]))
                })
                .collect(),
        ),
        // A deep value, spelled short: its leaf wrapped `depth` times.
        "nest" => {
            let depth = value["depth"].as_u64().expect("a depth");
            (0..depth).fold(model(&value["leaf"]), |inner, _| {
                match value["kind"].as_str().expect("a kind") {
                    "array" => Model::Array(vec![inner]),
                    "object" => Model::Object(vec![("k".into(), inner)]),
                    "some" => Model::Some(Box::new(inner)),
                    other => panic!("unknown nest kind {other}"),
                }
            })
        }
        other => panic!("unknown kind {other}"),
    }
}

// =============================================================================
// The golden corpus
// =============================================================================

fn corpus() -> Json {
    serde_json::from_str(include_str!("../testdata/storage-v1.json")).expect("corpus is JSON")
}

fn rows<'a>(corpus: &'a Json, section: &str) -> &'a [Json] {
    corpus[section].as_array().expect("a section is an array")
}

fn field<'a>(row: &'a Json, name: &str) -> &'a str {
    row[name]
        .as_str()
        .unwrap_or_else(|| panic!("{name} in {row}"))
}

#[test]
fn the_corpus_header_is_the_one_written() {
    let corpus = corpus();
    assert_eq!(corpus["version"], 1);
    assert_eq!(unhex(field(&corpus, "header")), HEADER);
}

/// Every vector reads as its value, and its value writes as its bytes.
#[test]
fn every_vector_reads_and_writes_byte_for_byte() {
    let corpus = corpus();
    let vectors = rows(&corpus, "vectors");
    assert!(!vectors.is_empty());
    for row in vectors {
        let name = field(row, "name");
        let bytes = unhex(field(row, "blob"));
        let value = model(&row["value"]);
        let read: Model = from_slice(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(read, value, "{name} reads as its value");
        let written = to_vec(&value).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(written, bytes, "{name} writes as its bytes");
    }
}

/// Every refused row is refused, with the error of its class, whatever
/// type reads it.
#[test]
fn every_refused_row_is_refused_by_its_class() {
    let corpus = corpus();
    let refused = rows(&corpus, "refused");
    assert!(!refused.is_empty());
    for row in refused {
        let name = field(row, "name");
        let bytes = unhex(field(row, "blob"));
        let message = match field(row, "refusal") {
            "not_a_blob" => "not a storage blob",
            "unsupported_version" => "an unsupported storage version",
            "malformed" => "malformed storage blob",
            other => panic!("{name}: unknown refusal {other}"),
        };
        let error = from_slice::<Model>(&bytes).expect_err(name);
        assert_eq!(error.message(), message, "{name}");
        assert!(error.path().is_empty(), "{name}: refused before any value");
        // Checked before the type sees anything: even a type that reads
        // nothing is refused the same way.
        let error = from_slice::<de::IgnoredAny>(&bytes).expect_err(name);
        assert_eq!(error.message(), message, "{name}");
    }
}

#[test]
fn corpus_names_are_unique() {
    let corpus = corpus();
    let mut seen = std::collections::HashSet::new();
    for section in ["vectors", "refused"] {
        for row in rows(&corpus, section) {
            assert!(seen.insert(field(row, "name").to_owned()), "{row}");
        }
    }
}

// =============================================================================
// Options
// =============================================================================

#[test]
fn none_some_unit_and_some_none_are_three_blobs() {
    let none: Option<Option<()>> = None;
    let some_none: Option<Option<()>> = Some(None);
    let some_some: Option<Option<()>> = Some(Some(()));
    assert_eq!(to_vec(&none).expect("writes"), blob(&[0x00]));
    assert_eq!(to_vec(&some_none).expect("writes"), blob(&[SOME, 0x00]));
    assert_eq!(
        to_vec(&some_some).expect("writes"),
        blob(&[SOME, SOME, 0x00])
    );
    for value in [none, some_none, some_some] {
        let back: Option<Option<()>> = from_slice(&to_vec(&value).expect("writes")).expect("reads");
        assert_eq!(back, value);
    }
    assert_eq!(to_vec(&Some(())).expect("writes"), blob(&[SOME, 0x00]));
    assert_eq!(from_slice::<Option<()>>(&blob(&[SOME, 0x00])), Ok(Some(())));
    assert_eq!(from_slice::<Option<()>>(&blob(&[0x00])), Ok(None));
}

/// serde reads an untagged, internally tagged or flattened type from a
/// buffer it fills through `deserialize_any`. The marker is a node of its
/// own there too, so the option survives.
#[test]
fn an_option_survives_serde_buffering() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(tag = "type")]
    enum Tagged {
        A {
            flag: Option<()>,
            nested: Option<Option<u8>>,
        },
    }
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(untagged)]
    enum Untagged {
        A {
            flag: Option<()>,
            nested: Option<Option<u8>>,
        },
    }
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Inner {
        flag: Option<()>,
        nested: Option<Option<u8>>,
    }
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Flattened {
        id: u8,
        #[serde(flatten)]
        inner: Inner,
    }

    for (flag, nested) in [
        (None, None),
        (Some(()), Some(None)),
        (Some(()), Some(Some(7))),
        (None, Some(None)),
    ] {
        let tagged = Tagged::A { flag, nested };
        assert_eq!(
            from_slice::<Tagged>(&to_vec(&tagged).expect("writes")),
            Ok(tagged)
        );
        let untagged = Untagged::A { flag, nested };
        assert_eq!(
            from_slice::<Untagged>(&to_vec(&untagged).expect("writes")),
            Ok(untagged)
        );
        let flattened = Flattened {
            id: 1,
            inner: Inner { flag, nested },
        };
        assert_eq!(
            from_slice::<Flattened>(&to_vec(&flattened).expect("writes")),
            Ok(flattened)
        );
    }
}

/// A self-describing value under an option keeps its shape: a `Some`
/// holding an array is not read as an array.
#[test]
fn a_self_describing_option_keeps_its_shape() {
    for value in [
        None,
        Some(Json::Null),
        Some(serde_json::json!([1])),
        Some(serde_json::json!({"a": null})),
    ] {
        let back: Option<Json> = from_slice(&to_vec(&value).expect("writes")).expect("reads");
        assert_eq!(back, value);
    }
}

/// A blob written before a field became optional reads as `Some`.
#[test]
fn a_field_that_became_optional_reads_its_old_value_as_some() {
    #[derive(Serialize)]
    struct Before {
        n: u32,
        name: String,
    }
    #[derive(Deserialize, PartialEq, Debug)]
    struct After {
        n: Option<u32>,
        name: Option<String>,
    }
    let bytes = to_vec(&Before {
        n: 7,
        name: "x".into(),
    })
    .expect("writes");
    assert_eq!(
        from_slice::<After>(&bytes),
        Ok(After {
            n: Some(7),
            name: Some("x".into()),
        })
    );
    // The documented exception: a unit's null was always the null.
    let bytes = to_vec(&()).expect("writes");
    assert_eq!(from_slice::<Option<()>>(&bytes), Ok(None));
}

#[test]
fn a_marked_option_is_not_read_as_its_payload() {
    let bytes = to_vec(&Some(5u8)).expect("writes");
    assert_eq!(bytes, blob(&[SOME, 0x0D, 5]));
    let error = from_slice::<u8>(&bytes).expect_err("an option is not a u8");
    assert_eq!(error.message(), "expected u8, found an optional value");
    let error = from_slice::<String>(&blob(&[SOME, 0x0A, 1, 0, 0, 0, b'x'])).expect_err("refused");
    assert_eq!(
        error.message(),
        "expected a string, found an optional value"
    );
    #[derive(Deserialize, Debug)]
    enum E {
        A,
    }
    assert!(from_slice::<E>(&blob(&[SOME, 0x0A, 1, 0, 0, 0, b'A'])).is_err());
}

// =============================================================================
// The rest of the mapping
// =============================================================================

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
enum Shape {
    Red,
    Name(String),
    Match(Option<()>),
    Pair(u8, u8),
    Point { x: i32, y: i32 },
}

#[test]
fn every_variant_form_is_pinned() {
    let cases = [
        (Shape::Red, "0a03000000526564"),
        (
            Shape::Name("acme".into()),
            "f101000000040000004e616d650a0400000061636d65",
        ),
        (Shape::Match(None), "f101000000050000004d6174636800"),
        (Shape::Match(Some(())), "f101000000050000004d61746368f500"),
        (
            Shape::Pair(1, 2),
            "f1010000000400000050616972f0020000000d010d02",
        ),
        (
            Shape::Point { x: 1, y: -1 },
            "f10100000005000000506f696e74f102000000010000007804010000000100000079 04ffffffff",
        ),
    ];
    for (shape, hex) in cases {
        let expected = blob(&unhex(&hex.replace(' ', "")));
        assert_eq!(to_vec(&shape).expect("writes"), expected, "{shape:?}");
        assert_eq!(from_slice::<Shape>(&expected), Ok(shape));
    }
}

/// Written in its compact form when the format is not human readable, as
/// a `uuid::Uuid` is.
#[derive(PartialEq, Debug)]
struct Compact(u16);

impl Serialize for Compact {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.0.to_string())
        } else {
            s.serialize_u16(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Compact {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        assert!(!d.is_human_readable());
        u16::deserialize(d).map(Compact)
    }
}

#[test]
fn a_struct_writes_its_fields_in_order_and_skips_what_it_skips() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Unit;
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Meters(u16);
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Pair(u8, i8);
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Record {
        b: u8,
        a: char,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        gone: Option<u8>,
        #[serde(with = "serde_bytes")]
        raw: Vec<u8>,
        list: Vec<u8>,
        pair: (bool, ()),
        unit: Unit,
        meters: Meters,
        tuple: Pair,
        compact: Compact,
    }
    let record = Record {
        b: 1,
        a: 'é',
        gone: None,
        raw: vec![1, 2],
        list: vec![3],
        pair: (true, ()),
        unit: Unit,
        meters: Meters(7),
        tuple: Pair(1, -1),
        compact: Compact(9),
    };
    let bytes = to_vec(&record).expect("writes");
    let read: Model = from_slice(&bytes).expect("reads");
    assert_eq!(
        read,
        Model::Object(vec![
            ("b".into(), Model::U8(1)),
            ("a".into(), Model::Text("é".into())),
            ("raw".into(), Model::Bytes(vec![1, 2])),
            ("list".into(), Model::Array(vec![Model::U8(3)])),
            (
                "pair".into(),
                Model::Array(vec![Model::Bool(true), Model::Null])
            ),
            ("unit".into(), Model::Null),
            ("meters".into(), Model::U16(7)),
            (
                "tuple".into(),
                Model::Array(vec![Model::U8(1), Model::I8(-1)])
            ),
            ("compact".into(), Model::U16(9)),
        ])
    );
    assert_eq!(from_slice::<Record>(&bytes), Ok(record));
}

#[test]
fn an_ordered_map_writes_the_same_bytes_every_time() {
    let map: BTreeMap<String, u16> = (0..50).map(|i| (format!("k{i}"), i)).collect();
    let first = to_vec(&map).expect("writes");
    assert_eq!(to_vec(&map.clone()).expect("writes"), first);
    assert_eq!(from_slice::<BTreeMap<String, u16>>(&first), Ok(map.clone()));
    // A hash map reads back as the same entries, in whatever order.
    let hashed: HashMap<String, u16> = map.into_iter().collect();
    let back: HashMap<String, u16> = from_slice(&to_vec(&hashed).expect("writes")).expect("reads");
    assert_eq!(back, hashed);
}

#[test]
fn integers_read_at_any_width_that_fits() {
    let bytes = to_vec(&200u8).expect("writes");
    assert_eq!(from_slice::<u64>(&bytes), Ok(200));
    assert_eq!(from_slice::<i16>(&bytes), Ok(200));
    assert!(from_slice::<i8>(&bytes).is_err());
    let bytes = to_vec(&u128::MAX).expect("writes");
    assert_eq!(from_slice::<u128>(&bytes), Ok(u128::MAX));
}

#[test]
fn a_map_key_must_be_text() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum Color {
        Red,
    }
    #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
    struct Id(String);
    // Text keys, in every form a key may take.
    let by_color = BTreeMap::from([(Color::Red, 1u8)]);
    assert_eq!(
        from_slice::<BTreeMap<Color, u8>>(&to_vec(&by_color).expect("writes")),
        Ok(by_color)
    );
    let by_char = BTreeMap::from([('x', 1u8)]);
    assert_eq!(
        from_slice::<BTreeMap<char, u8>>(&to_vec(&by_char).expect("writes")),
        Ok(by_char)
    );
    let by_id = BTreeMap::from([(Id("a".into()), 1u8)]);
    assert_eq!(
        from_slice::<BTreeMap<Id, u8>>(&to_vec(&by_id).expect("writes")),
        Ok(by_id)
    );
    // Anything else is refused on the way out, without the key.
    let error = to_vec(&BTreeMap::from([(41u32, 1u8)])).expect_err("an integer key");
    assert_eq!(error.message(), "a map key must be a string");
    assert!(!error.to_string().contains("41"));
    // And a key type that reads only integers is refused on the way in.
    let bytes = to_vec(&BTreeMap::from([("41", 1u8)])).expect("writes");
    assert!(from_slice::<BTreeMap<u32, u8>>(&bytes).is_err());
}

#[test]
fn a_transport_frame_and_a_blob_never_read_as_each_other() {
    let value = BTreeMap::from([("a", Some(1u8))]);
    let frame = vitaminc_aead_frame::serde::to_vec(&value).expect("writes");
    let stored = to_vec(&value).expect("writes");
    assert_eq!(
        from_slice::<BTreeMap<String, Option<u8>>>(&frame)
            .expect_err("a frame is not a blob")
            .message(),
        "not a storage blob"
    );
    assert!(
        vitaminc_aead_frame::serde::from_slice::<BTreeMap<String, Option<u8>>>(&stored).is_err()
    );
    // Nor does a frame behind a blob's header: the marker is not in the
    // frame's grammar.
    assert!(vitaminc_aead_frame::serde::from_slice::<Option<u8>>(&[SOME, 0x0D, 1]).is_err());
}

// =============================================================================
// Refusals when writing
// =============================================================================

#[derive(Serialize)]
#[serde(untagged)]
enum Nest {
    Leaf,
    Array(Vec<Nest>),
    Some(Option<Box<Nest>>),
}

fn arrays(n: usize) -> Nest {
    (0..n).fold(Nest::Leaf, |inner, _| Nest::Array(vec![inner]))
}

fn somes(n: usize) -> Nest {
    (0..n).fold(Nest::Leaf, |inner, _| Nest::Some(Some(Box::new(inner))))
}

#[test]
fn depth_is_bounded_on_the_way_out_as_on_the_way_in() {
    for nest in [arrays, somes] {
        let ok = to_vec(&nest(128)).expect("128 levels below the root");
        assert!(from_slice::<de::IgnoredAny>(&ok).is_ok());
        let error = to_vec(&nest(129)).expect_err("129 levels");
        assert_eq!(error.message(), "value nests deeper than 128 levels");
    }
    // A struct variant's payload is one level below its object, and its
    // fields two.
    #[derive(Serialize)]
    enum V {
        S { inner: Nest },
    }
    assert!(to_vec(&V::S { inner: arrays(126) }).is_ok());
    let error = to_vec(&V::S { inner: arrays(127) }).expect_err("too deep");
    assert_eq!(
        error.path()[..2],
        [
            PathSegment::Key("S".into()),
            PathSegment::Key("inner".into())
        ]
    );
}

#[test]
fn a_repeated_key_is_refused() {
    struct Twice;
    impl Serialize for Twice {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(None)?;
            map.serialize_entry("k", &1u8)?;
            map.serialize_entry("k", &2u8)?;
            map.end()
        }
    }
    let error = to_vec(&Twice).expect_err("a repeated key");
    assert_eq!(error.message(), "duplicate key");
}

#[test]
fn a_container_length_must_match_its_children() {
    struct Liar;
    impl Serialize for Liar {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(2))?;
            seq.serialize_element(&1u8)?;
            seq.end()
        }
    }
    let error = to_vec(&Liar).expect_err("a wrong length");
    assert_eq!(
        error.message(),
        "container length does not match its children"
    );
    // An unknown length is counted.
    struct Unknown;
    impl Serialize for Unknown {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(None)?;
            seq.serialize_element(&1u8)?;
            seq.serialize_element(&2u8)?;
            seq.end()
        }
    }
    assert_eq!(
        to_vec(&Unknown).expect("writes"),
        blob(&unhex("f0020000000d010d02"))
    );
}

#[test]
fn a_map_entry_written_out_of_turn_is_refused() {
    struct KeyKey;
    impl Serialize for KeyKey {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(None)?;
            map.serialize_key("a")?;
            map.serialize_key("b")?;
            map.end()
        }
    }
    struct ValueFirst;
    impl Serialize for ValueFirst {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(None)?;
            map.serialize_value(&1u8)?;
            map.end()
        }
    }
    struct KeyOnly;
    impl Serialize for KeyOnly {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(None)?;
            map.serialize_key("a")?;
            map.end()
        }
    }
    assert_eq!(
        to_vec(&KeyKey).expect_err("refused").message(),
        "a map key was written before the previous value"
    );
    assert_eq!(
        to_vec(&ValueFirst).expect_err("refused").message(),
        "a map value was written before its key"
    );
    assert_eq!(
        to_vec(&KeyOnly).expect_err("refused").message(),
        "a map key was written without its value"
    );
}

/// An error says where it happened, by the names the type declares and
/// positions, and never prints a value.
#[test]
fn an_error_carries_its_path_and_no_value() {
    #[derive(Serialize)]
    struct Outer {
        list: Vec<Inner>,
    }
    #[derive(Serialize)]
    enum Inner {
        T(u8, Bad),
    }
    struct Bad;
    impl Serialize for Bad {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("s3cr3t"))
        }
    }
    let error = to_vec(&Outer {
        list: vec![Inner::T(1, Bad)],
    })
    .expect_err("refused");
    assert_eq!(
        error.path(),
        [
            PathSegment::Key("list".into()),
            PathSegment::Index(0),
            PathSegment::Key("T".into()),
            PathSegment::Index(1),
        ]
    );
    assert!(!format!("{error} {error:?}").contains("s3cr3t"));

    let bytes = to_vec(&BTreeMap::from([("secret_looking_key", "x")])).expect("writes");
    let error = from_slice::<BTreeMap<String, u8>>(&bytes).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Entry(0)]);
    assert!(!format!("{error} {error:?}").contains("secret_looking_key"));
}

#[test]
fn the_header_errors_say_which_they_are() {
    let error: Error = from_slice::<()>(&[]).expect_err("empty");
    assert_eq!(error.to_string(), "not a storage blob");
    let error = from_slice::<()>(&[b'V', b'C', b'S', 2, 0]).expect_err("version 2");
    assert_eq!(error.to_string(), "an unsupported storage version");
    let error = from_slice::<()>(&blob(&[0x00, 0x00])).expect_err("trailing");
    assert_eq!(error.to_string(), "malformed storage blob");
}

// =============================================================================
// Properties
// =============================================================================

/// Refused, or read and written back as the same bytes: the reader accepts
/// one node per meaning, and the model writes it as it read it.
fn refused_or_canonical(bytes: &[u8]) -> bool {
    match from_slice::<Model>(bytes) {
        Ok(model) => to_vec(&model).expect("what reads, writes") == bytes,
        Err(_) => true,
    }
}

#[quickcheck]
fn accepted_bytes_write_back_exactly(body: Vec<u8>) -> bool {
    refused_or_canonical(&blob(&body))
}

/// Random bytes rarely get past the first tag, so start from a blob with
/// every kind of node in it and overwrite one byte.
#[quickcheck]
fn a_corrupted_blob_is_refused_or_canonical(at: usize, byte: u8) -> bool {
    let mut bytes = to_vec(&Model::Object(vec![
        ("a".into(), Model::Some(Box::new(Model::Null))),
        (
            "b".into(),
            Model::Array(vec![
                Model::Bool(true),
                Model::I16(-2),
                Model::U128(7),
                Model::F64(1.5f64.to_bits()),
                Model::Text("xy".into()),
                Model::Bytes(vec![1]),
                Model::Object(vec![]),
            ]),
        ),
    ]))
    .expect("writes");
    let at = at % bytes.len();
    bytes[at] = byte;
    refused_or_canonical(&bytes)
}
