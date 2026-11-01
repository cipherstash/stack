//! The storage profile: the golden corpus, which pins version 1 byte for
//! byte, an independent reader that the crate must agree with, and what the
//! serde mapping writes, reads and refuses.
#![cfg(feature = "serde")]

mod support;

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use quickcheck::{Arbitrary, Gen};
use quickcheck_macros::quickcheck;
use serde::de;
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use vitaminc_aead_frame::serde::PathSegment;
use vitaminc_aead_frame::storage::{self, from_slice, Error, ErrorKind, HEADER, MAP, SOME};
use vitaminc_protected::Controlled;

use support::reference::{decode, key_value, Refusal};
use support::typed::{read_as, schema, Typed};
use support::{blob, erase, model, unhex, Model};

/// Write `value`, and take the blob out of its `Protected`.
fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    storage::to_vec(value).map(Controlled::risky_unwrap)
}

/// The class the reference gives a refusal, as the crate names it.
fn kind(refusal: Refusal) -> ErrorKind {
    match refusal {
        Refusal::NotABlob => ErrorKind::NotABlob,
        Refusal::UnsupportedVersion => ErrorKind::UnsupportedVersion,
        Refusal::Malformed(_) => ErrorKind::Malformed,
    }
}

/// The crate and the reference agree on `bytes`: both refuse it, by the
/// same class, or both read it, as the same value, which writes back as
/// exactly `bytes`.
fn agree(bytes: &[u8]) -> bool {
    match (decode(bytes), from_slice::<Model>(bytes)) {
        (Ok(reference), Ok(ours)) => {
            ours == erase(&reference) && to_vec(&reference).expect("what reads, writes") == bytes
        }
        (Err(refusal), Err(error)) => error.kind() == kind(refusal),
        _ => false,
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

fn refusal(name: &str, class: &str) -> ErrorKind {
    match class {
        "not_a_blob" => ErrorKind::NotABlob,
        "unsupported_version" => ErrorKind::UnsupportedVersion,
        "malformed" => ErrorKind::Malformed,
        "mismatch" => ErrorKind::Mismatch,
        other => panic!("{name}: unknown refusal {other}"),
    }
}

#[test]
fn the_corpus_header_is_the_one_written() {
    let corpus = corpus();
    assert_eq!(corpus["version"], 1);
    assert_eq!(unhex(field(&corpus, "header")), HEADER);
}

/// Every vector reads as its value, through the reference exactly and
/// through serde as serde sees it, and its value writes as its bytes.
#[test]
fn every_vector_reads_and_writes_byte_for_byte() {
    let corpus = corpus();
    let vectors = rows(&corpus, "vectors");
    assert!(!vectors.is_empty());
    for row in vectors {
        let name = field(row, "name");
        let bytes = unhex(field(row, "blob"));
        let value = model(&row["value"]);
        assert_eq!(decode(&bytes), Ok(value.clone()), "{name}: the reference");
        let read: Model = from_slice(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(read, erase(&value), "{name} reads as its value");
        assert!(from_slice::<de::IgnoredAny>(&bytes).is_ok(), "{name} skips");
        let written = to_vec(&value).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(written, bytes, "{name} writes as its bytes");
    }
}

/// Every refused row is refused, by its class, whatever type reads it.
#[test]
fn every_refused_row_is_refused_by_its_class() {
    let corpus = corpus();
    let refused = rows(&corpus, "refused");
    assert!(!refused.is_empty());
    for row in refused {
        let name = field(row, "name");
        let bytes = unhex(field(row, "blob"));
        let class = refusal(name, field(row, "refusal"));
        assert_eq!(
            decode(&bytes).map_err(kind),
            Err(class),
            "{name}: the reference"
        );
        let error = from_slice::<Model>(&bytes).expect_err(name);
        assert_eq!(error.kind(), class, "{name}");
        assert!(error.path().is_empty(), "{name}: refused before any value");
        // Checked before the type sees anything: even a type that reads
        // nothing is refused the same way.
        let error = from_slice::<de::IgnoredAny>(&bytes).expect_err(name);
        assert_eq!(error.kind(), class, "{name}");
    }
}

/// Every reads row reads as its type says, or is refused as a mismatch.
/// What it reads as writes back as a blob the same type reads the same way.
#[test]
fn every_typed_read_reads_as_its_type() {
    let corpus = corpus();
    let reads = rows(&corpus, "reads");
    assert!(!reads.is_empty());
    for row in reads {
        let name = field(row, "name");
        let bytes = unhex(field(row, "blob"));
        assert!(decode(&bytes).is_ok(), "{name}: a well-formed blob");
        read_as(schema(&row["type"]));
        match row.get("reads_as") {
            Some(expected) => {
                let expected = model(expected);
                let Typed(read) = from_slice(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(read, expected, "{name}");
                let canonical = to_vec(&expected).expect("writes");
                let Typed(again) = from_slice(&canonical).expect("reads");
                assert_eq!(again, expected, "{name}: canonical");
            }
            None => {
                let class = refusal(name, field(row, "refusal"));
                let error = from_slice::<Typed>(&bytes).expect_err(name);
                assert_eq!(error.kind(), class, "{name}");
            }
        }
    }
}

#[test]
fn corpus_names_are_unique() {
    let corpus = corpus();
    let mut seen = std::collections::HashSet::new();
    for section in ["vectors", "refused", "reads"] {
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
/// own there too, so an option inside such a type survives.
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

/// The documented limit: serde writes a flattened `Option` field's `Some`
/// without telling the format, so no marker is written for it, and reads
/// it back as `Some` whenever its type reads from the entries left over.
/// A struct of only optional fields always does. It is serde's doing, and
/// JSON does the same.
#[test]
fn a_flattened_option_field_is_serdes_to_decide() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct AllOptional {
        z: Option<()>,
    }
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Required {
        z: u8,
    }
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Flat<T> {
        id: u8,
        #[serde(flatten)]
        extra: Option<T>,
    }
    let none = Flat::<AllOptional> { id: 1, extra: None };
    let bytes = to_vec(&none).expect("writes");
    assert!(!bytes.contains(&SOME), "no marker is written");
    assert_eq!(
        from_slice::<Flat<AllOptional>>(&bytes),
        Ok(Flat {
            id: 1,
            extra: Some(AllOptional { z: None }),
        })
    );
    let json: Flat<AllOptional> =
        serde_json::from_str(&serde_json::to_string(&none).expect("writes")).expect("reads");
    assert_eq!(json.extra, Some(AllOptional { z: None }), "JSON alike");
    // A type that cannot read from nothing reads back `None`.
    let none = Flat::<Required> { id: 1, extra: None };
    assert_eq!(
        from_slice::<Flat<Required>>(&to_vec(&none).expect("writes")),
        Ok(none)
    );
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
    assert_eq!(error.kind(), ErrorKind::Mismatch);
    assert_eq!(error.message(), "expected u8, found an optional value");
    let error = from_slice::<String>(&blob(&[SOME, 0x0A, 1, 0, 0, 0, b'x'])).expect_err("refused");
    assert_eq!(
        error.message(),
        "expected a string, found an optional value"
    );
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
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
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
        scores: BTreeMap<u8, u8>,
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
        scores: BTreeMap::from([(2, 3)]),
    };
    let bytes = to_vec(&record).expect("writes");
    assert_eq!(
        decode(&bytes),
        Ok(Model::Object(vec![
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
            (
                "scores".into(),
                Model::Map(vec![(Model::U8(2), Model::U8(3))])
            ),
        ]))
    );
    assert_eq!(from_slice::<Record>(&bytes), Ok(record));
}

#[test]
fn an_ordered_map_writes_the_same_bytes_every_time() {
    let map: BTreeMap<String, u16> = (0..50).map(|i| (format!("k{i}"), i)).collect();
    let first = to_vec(&map).expect("writes");
    assert_eq!(first[HEADER.len()], MAP);
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

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
enum Color {
    Red,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
struct Id(String);

/// Round trip one map, and check its key node's bytes.
fn key_round_trip<K>(key: K, node: &[u8])
where
    K: Serialize + for<'de> Deserialize<'de> + Ord + fmt::Debug + Clone,
{
    let map = BTreeMap::from([(key, 0u8)]);
    let bytes = to_vec(&map).expect("writes");
    let mut expected = vec![MAP, 1, 0, 0, 0];
    expected.extend_from_slice(node);
    expected.extend_from_slice(&[0x0D, 0]);
    assert_eq!(bytes, blob(&expected), "{map:?}");
    assert_eq!(from_slice::<BTreeMap<K, u8>>(&bytes), Ok(map));
}

#[test]
fn a_map_key_is_an_integer_text_or_bytes() {
    key_round_trip(-1i8, &[0x0C, 0xFF]);
    key_round_trip(-2i16, &[0x0E, 0xFE, 0xFF]);
    key_round_trip(3i32, &[0x04, 3, 0, 0, 0]);
    key_round_trip(4i64, &[0x05, 4, 0, 0, 0, 0, 0, 0, 0]);
    key_round_trip(5i128, &[[0x10, 5].as_slice(), &[0; 15]].concat());
    key_round_trip(6u8, &[0x0D, 6]);
    key_round_trip(7u16, &[0x0F, 7, 0]);
    key_round_trip(8u32, &[0x06, 8, 0, 0, 0]);
    key_round_trip(9u64, &[0x07, 9, 0, 0, 0, 0, 0, 0, 0]);
    key_round_trip(10u128, &[[0x11, 10].as_slice(), &[0; 15]].concat());
    key_round_trip("k".to_owned(), &[0x0A, 1, 0, 0, 0, b'k']);
    key_round_trip('c', &[0x0A, 1, 0, 0, 0, b'c']);
    key_round_trip(Color::Red, &[0x0A, 3, 0, 0, 0, b'R', b'e', b'd']);
    key_round_trip(Id("i".into()), &[0x0A, 1, 0, 0, 0, b'i']);
    key_round_trip(Compact(1), &[0x0F, 1, 0]);
    key_round_trip(
        serde_bytes::ByteBuf::from(vec![1, 2]),
        &[0x0B, 2, 0, 0, 0, 1, 2],
    );
    // Equal values of two widths are one key, refused as a repeat.
    struct TwoWidths;
    impl Serialize for TwoWidths {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(None)?;
            map.serialize_entry(&1u8, &())?;
            map.serialize_entry(&1u64, &())?;
            map.end()
        }
    }
    let error = to_vec(&TwoWidths).expect_err("a repeated key");
    assert_eq!(error.kind(), ErrorKind::Unwritable);
    assert_eq!(error.message(), "duplicate key");
}

/// A key written in its `Display` form is the text it formats to.
#[test]
fn a_displayed_key_or_value_is_its_text() {
    struct Shown(&'static str);
    impl Serialize for Shown {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(&format_args!("<{}>", self.0))
        }
    }
    impl PartialEq for Shown {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for Shown {}
    impl PartialOrd for Shown {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Shown {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.cmp(other.0)
        }
    }
    assert_eq!(
        to_vec(&Shown("a")).expect("writes"),
        to_vec("<a>").expect("writes")
    );
    assert_eq!(
        to_vec(&BTreeMap::from([(Shown("k"), Shown("v"))])).expect("writes"),
        to_vec(&BTreeMap::from([("<k>", "<v>")])).expect("writes")
    );
    // Nested too deep, a displayed value is refused as any other.
    let error = to_vec(&nested(arrays(129), Nest::Shown)).expect_err("too deep");
    assert_eq!(error.message(), "value nests deeper than 128 levels");
    // A `Display` that fails is the type's refusal, and says nothing of it.
    struct Fails;
    impl fmt::Display for Fails {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }
    struct Failing;
    impl Serialize for Failing {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(&Fails)
        }
    }
    let error = to_vec(&Failing).expect_err("refused");
    assert_eq!(error.message(), "a value its type could not write");
}

/// Each kind of key that is not an integer, text or bytes is refused on the
/// way out, without the key.
#[test]
fn any_other_key_is_refused() {
    fn refused<K: Serialize>(key: K) {
        struct One<K>(K);
        impl<K: Serialize> Serialize for One<K> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut map = s.serialize_map(Some(1))?;
                map.serialize_entry(&self.0, &0u8)?;
                map.end()
            }
        }
        let error = to_vec(&One(key)).expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::Unwritable);
        assert_eq!(
            error.message(),
            "a map key must be an integer, text or bytes"
        );
        assert_eq!(error.path(), [PathSegment::Entry(0)]);
    }
    #[derive(Serialize)]
    struct Unit;
    #[derive(Serialize)]
    struct Tuple(u8, u8);
    #[derive(Serialize)]
    struct Fields {
        a: u8,
    }
    #[derive(Serialize)]
    enum Variants {
        N(u8),
        T(u8, u8),
        S { a: u8 },
    }
    refused(true);
    refused(1.5f32);
    refused(2.5f64);
    refused(None::<u8>);
    refused(Some(1u8));
    refused(());
    refused(Unit);
    refused(Variants::N(1));
    refused(vec![1u8]);
    refused((1u8, 2u8));
    refused(Tuple(1, 2));
    refused(Variants::T(1, 2));
    refused(BTreeMap::from([(1u8, 1u8)]));
    refused(Fields { a: 1 });
    refused(Variants::S { a: 1 });
}

/// A key with a text form for people and a compact one, chosen as a type
/// with both chooses: by `is_human_readable`. It reads back only in the mode
/// it was written in.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Modal(u8);

impl Serialize for Modal {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mode = if s.is_human_readable() {
            "human"
        } else {
            "compact"
        };
        s.collect_str(&format_args!("{mode}-{}", self.0))
    }
}

impl<'de> Deserialize<'de> for Modal {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mode = if d.is_human_readable() {
            "human-"
        } else {
            "compact-"
        };
        let text = <&str>::deserialize(d)?;
        text.strip_prefix(mode)
            .and_then(|n| n.parse().ok())
            .map(Modal)
            .ok_or_else(|| de::Error::custom("a key in the other mode"))
    }
}

/// A text key is read in the mode its profile's key writer wrote it in:
/// compact in a blob, human readable in a transport frame.
#[test]
fn a_text_key_reads_in_the_mode_it_was_written_in() {
    let map = BTreeMap::from([(Modal(1), 10u8), (Modal(2), 20)]);
    let blob = to_vec(&map).expect("writes");
    assert!(blob.windows(9).any(|w| w == b"compact-1"));
    assert_eq!(from_slice::<BTreeMap<Modal, u8>>(&blob), Ok(map));

    let map = BTreeMap::from([(Modal(1), 10u8)]);
    let frame = vitaminc_aead_frame::serde::to_vec(&map).expect("writes");
    assert!(frame.windows(7).any(|w| w == b"human-1"));
    let back: BTreeMap<Modal, u8> = vitaminc_aead_frame::serde::from_slice(&frame).expect("reads");
    assert_eq!(back, map);
}

/// A key type that reads only integers does not read text, nor a string
/// type an integer; a struct reads only text keys.
#[test]
fn a_key_reads_only_as_its_kind() {
    let bytes = to_vec(&BTreeMap::from([("41", 1u8)])).expect("writes");
    assert!(from_slice::<BTreeMap<u32, u8>>(&bytes).is_err());
    let bytes = to_vec(&BTreeMap::from([(41u32, 1u8)])).expect("writes");
    let error = from_slice::<BTreeMap<String, u8>>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "expected a string, found an integer");
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct S {
        a: u8,
    }
    let error = from_slice::<S>(&bytes).expect_err("refused");
    assert_eq!(error.kind(), ErrorKind::Mismatch);
    assert_eq!(error.message(), "expected a field name, found an integer");
    // A map is an object to a type that reads a scalar.
    let error = from_slice::<u8>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "expected u8, found an object");
}

/// A key type whose read takes nothing would leave its node for the value.
#[test]
fn a_key_that_reads_nothing_is_refused() {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Debug)]
    struct Lazy;
    impl<'de> Deserialize<'de> for Lazy {
        fn deserialize<D: de::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            Ok(Lazy)
        }
    }
    let bytes = to_vec(&BTreeMap::from([(1u8, 2u8)])).expect("writes");
    let error = from_slice::<BTreeMap<Lazy, u8>>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "a value its type did not read");
    // Nor may a whole value read nothing.
    let error = from_slice::<Lazy>(&bytes).expect_err("refused");
    assert_eq!(error.kind(), ErrorKind::Mismatch);
    assert_eq!(error.message(), "the value did not read the whole blob");
}

#[test]
fn a_transport_frame_and_a_blob_never_read_as_each_other() {
    let value = BTreeMap::from([("a", Some(1u8))]);
    let frame = vitaminc_aead_frame::serde::to_vec(&value).expect("writes");
    let stored = to_vec(&value).expect("writes");
    let error = from_slice::<BTreeMap<String, Option<u8>>>(&frame).expect_err("not a blob");
    assert_eq!(error.kind(), ErrorKind::NotABlob);
    assert!(
        vitaminc_aead_frame::serde::from_slice::<BTreeMap<String, Option<u8>>>(&stored).is_err()
    );
    // Nor does a frame behind a blob's header: the marker and the map are
    // not in the frame's grammar.
    assert!(vitaminc_aead_frame::serde::from_slice::<Option<u8>>(&[SOME, 0x0D, 1]).is_err());
    assert!(
        vitaminc_aead_frame::serde::from_slice::<BTreeMap<u8, u8>>(&[MAP, 0, 0, 0, 0]).is_err()
    );
}

// =============================================================================
// Refusals when writing
// =============================================================================

#[derive(Serialize)]
#[serde(untagged)]
enum Nest {
    Leaf,
    #[serde(serialize_with = "Nest::shown")]
    Shown,
    Array(Vec<Nest>),
    Some(Option<Box<Nest>>),
    Map(BTreeMap<u8, Nest>),
}

/// `outer` with its innermost leaf replaced by `leaf`.
fn nested(outer: Nest, leaf: Nest) -> Nest {
    match outer {
        Nest::Array(mut items) => Nest::Array(vec![nested(items.remove(0), leaf)]),
        Nest::Some(Some(inner)) => Nest::Some(Some(Box::new(nested(*inner, leaf)))),
        Nest::Map(mut map) => {
            let inner = map.remove(&0).expect("one entry");
            Nest::Map(BTreeMap::from([(0, nested(inner, leaf))]))
        }
        _ => leaf,
    }
}

impl Nest {
    fn shown<S: serde::Serializer>(s: S) -> Result<S::Ok, S::Error> {
        s.collect_str("shown")
    }
}

fn arrays(n: usize) -> Nest {
    (0..n).fold(Nest::Leaf, |inner, _| Nest::Array(vec![inner]))
}

fn somes(n: usize) -> Nest {
    (0..n).fold(Nest::Leaf, |inner, _| Nest::Some(Some(Box::new(inner))))
}

fn maps(n: usize) -> Nest {
    (0..n).fold(Nest::Leaf, |inner, _| {
        Nest::Map(BTreeMap::from([(0, inner)]))
    })
}

#[test]
fn depth_is_bounded_on_the_way_out_as_on_the_way_in() {
    for nest in [arrays, somes, maps] {
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
    struct FieldTwice;
    impl Serialize for FieldTwice {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut object = s.serialize_struct("FieldTwice", 2)?;
            object.serialize_field("k", &1u8)?;
            object.serialize_field("k", &2u8)?;
            object.end()
        }
    }
    for error in [
        to_vec(&Twice).expect_err("a repeated key"),
        to_vec(&FieldTwice).expect_err("a repeated field"),
    ] {
        assert_eq!(error.kind(), ErrorKind::Unwritable);
        assert_eq!(error.message(), "duplicate key");
    }
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
    let error = to_vec(&BTreeMap::from([(1u8, Bad)])).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Entry(0)]);

    let bytes = to_vec(&BTreeMap::from([("secret_looking_key", "x")])).expect("writes");
    let error = from_slice::<BTreeMap<String, u8>>(&bytes).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Entry(0)]);
    assert!(!format!("{error} {error:?}").contains("secret_looking_key"));
}

#[test]
fn the_header_errors_say_which_they_are() {
    let error = from_slice::<()>(&[]).expect_err("empty");
    assert_eq!(error.kind(), ErrorKind::NotABlob);
    assert_eq!(error.to_string(), "not a storage blob");
    let error = from_slice::<()>(&[b'V', b'C', b'S', 2, 0]).expect_err("version 2");
    assert_eq!(error.kind(), ErrorKind::UnsupportedVersion);
    assert_eq!(error.to_string(), "an unsupported storage version");
    let error = from_slice::<()>(&blob(&[0x00, 0x00])).expect_err("trailing");
    assert_eq!(error.kind(), ErrorKind::Malformed);
    assert_eq!(error.to_string(), "malformed storage blob");
    assert_eq!(
        format!("{error:?}"),
        "Error(Malformed, malformed storage blob)"
    );
}

#[test]
fn a_blob_is_protected_and_redacted() {
    let blob = storage::to_vec("s3cr3t").expect("writes");
    assert!(!format!("{blob:?}").contains("s3cr3t"));
    assert_eq!(from_slice::<&str>(blob.risky_ref()), Ok("s3cr3t"));
}

// =============================================================================
// Properties
// =============================================================================

#[quickcheck]
fn any_bytes_are_read_alike(body: Vec<u8>) -> bool {
    agree(&blob(&body))
}

/// Random bytes rarely get past the first tag, so start from a blob with
/// every kind of node in it and overwrite one byte.
#[quickcheck]
fn a_corrupted_blob_is_read_alike(at: usize, byte: u8) -> bool {
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
                Model::Map(vec![
                    (Model::U8(1), Model::Null),
                    (Model::I64(-1), Model::Bool(false)),
                    (Model::Text("k".into()), Model::Map(vec![])),
                    (Model::Bytes(vec![2]), Model::U32(3)),
                ]),
            ]),
        ),
    ]))
    .expect("writes");
    let at = at % bytes.len();
    bytes[at] = byte;
    agree(&bytes)
}

/// A value of the model, at most `depth` containers deep, whose maps never
/// repeat a key.
#[derive(Debug, Clone)]
struct Value(Model);

fn arbitrary_model(g: &mut Gen, depth: usize) -> Model {
    let choices = if depth == 0 { 18 } else { 22 };
    let small = |g: &mut Gen| usize::arbitrary(g) % 4;
    match u8::arbitrary(g) % choices {
        0 => Model::Null,
        1 => Model::Bool(bool::arbitrary(g)),
        2 => Model::I8(i8::arbitrary(g)),
        3 => Model::I16(i16::arbitrary(g)),
        4 => Model::I32(i32::arbitrary(g)),
        5 => Model::I64(i64::arbitrary(g)),
        6 => Model::I128(i128::arbitrary(g)),
        7 => Model::U8(u8::arbitrary(g)),
        8 => Model::U16(u16::arbitrary(g)),
        9 => Model::U32(u32::arbitrary(g)),
        10 => Model::U64(u64::arbitrary(g)),
        11 => Model::U128(u128::arbitrary(g)),
        12 => Model::F32(u32::arbitrary(g)),
        13 => Model::F64(u64::arbitrary(g)),
        14 => Model::Text(String::arbitrary(g)),
        15 => Model::Bytes(Vec::arbitrary(g)),
        16 | 17 => Model::Null,
        18 => Model::Some(Box::new(arbitrary_model(g, depth - 1))),
        19 => Model::Array(
            (0..small(g))
                .map(|_| arbitrary_model(g, depth - 1))
                .collect(),
        ),
        20 => {
            let mut entries: Vec<(String, Model)> = Vec::new();
            for _ in 0..small(g) {
                let key = String::arbitrary(g);
                if entries.iter().all(|(k, _)| *k != key) {
                    entries.push((key, arbitrary_model(g, depth - 1)));
                }
            }
            Model::Object(entries)
        }
        _ => {
            let mut entries: Vec<(Model, Model)> = Vec::new();
            for _ in 0..small(g) {
                let key = arbitrary_key(g);
                let same = key_value(&key);
                if entries.iter().all(|(k, _)| key_value(k) != same) {
                    entries.push((key, arbitrary_model(g, depth - 1)));
                }
            }
            Model::Map(entries)
        }
    }
}

/// A map key, with small integers often enough that two widths of one
/// value meet.
fn arbitrary_key(g: &mut Gen) -> Model {
    let small = i8::arbitrary(g) % 3;
    match u8::arbitrary(g) % 8 {
        0 => Model::I8(small),
        1 => Model::I64(small.into()),
        2 => Model::U16(small.unsigned_abs().into()),
        3 => Model::U128(u128::arbitrary(g)),
        4 => Model::I128(i128::arbitrary(g)),
        5 => Model::Text(String::arbitrary(g)),
        6 => Model::Bytes(Vec::arbitrary(g)),
        _ => Model::U8(small.unsigned_abs()),
    }
}

impl Arbitrary for Value {
    fn arbitrary(g: &mut Gen) -> Self {
        Value(arbitrary_model(g, 4))
    }
}

/// Any value writes, and the reference reads it back exactly.
#[quickcheck]
fn any_value_writes_and_reads_back(Value(value): Value) -> bool {
    let bytes = to_vec(&value).expect("a value without repeated keys writes");
    decode(&bytes) == Ok(value.clone()) && from_slice::<Model>(&bytes) == Ok(erase(&value))
}
