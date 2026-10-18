//! serde over the transport frame: what reads, what writes, what is
//! refused, and that an error never echoes a value.
#![cfg(feature = "serde")]

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Visitor};
use serde::{Deserialize, Serialize};
use vitaminc_aead::plaintext::{Int, Logical, MapSink, Physical, Raw, Sink};
use vitaminc_aead::{Encrypt, FrameWriter};
use vitaminc_aead_frame::serde::{from_slice, to_vec, Error, PathSegment};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A host's call options: a tagged keyset selector and an optional context.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Options {
    keyset: Keyset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
enum Keyset {
    Default {},
    Any {},
    Name(String),
    Id(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// The bytes the Go SDK's codec (`vcffi.Marshal`) writes for
/// `{"keyset": {"name": "acme"}, "context": "tenants/acme"}`: Go orders an
/// object's keys, so `context` comes first.
const GO_OPTIONS: &str = "f10200000007000000636f6e746578740a0c00000074656e616e74732f61636d65060000006b6579736574f101000000040000006e616d650a0400000061636d65";

/// `{"keyset": {"default": {}}}`, as Go writes it.
const GO_DEFAULT: &str = "f101000000060000006b6579736574f1010000000700000064656661756c74f100000000";

#[test]
fn reads_the_options_a_go_host_writes() {
    let options: Options = from_slice(&unhex(GO_OPTIONS)).expect("reads");
    assert_eq!(
        options,
        Options {
            keyset: Keyset::Name("acme".into()),
            context: Some("tenants/acme".into()),
        }
    );
    let options: Options = from_slice(&unhex(GO_DEFAULT)).expect("reads");
    assert_eq!(
        options,
        Options {
            keyset: Keyset::Default {},
            context: None,
        }
    );
}

#[test]
fn writes_what_a_go_host_reads() {
    // A struct writes its fields in declaration order; with one field the
    // bytes are Go's exactly.
    let bytes = to_vec(&Options {
        keyset: Keyset::Default {},
        context: None,
    })
    .expect("writes");
    assert_eq!(bytes, unhex(GO_DEFAULT));
}

#[test]
fn every_variant_form_round_trips() {
    for keyset in [
        Keyset::Default {},
        Keyset::Any {},
        Keyset::Name("acme".into()),
        Keyset::Id(vec![7; 16]),
    ] {
        let options = Options {
            keyset,
            context: None,
        };
        let back: Options = from_slice(&to_vec(&options).expect("writes")).expect("reads");
        assert_eq!(back, options);
    }
}

/// A unit variant is its name, a string; a newtype, tuple or struct variant
/// is an object of one entry.
#[test]
fn enums_are_externally_tagged() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "lowercase")]
    enum Index {
        Eq,
        Match { k: u8 },
        Pair(u32, String),
    }
    let unit = to_vec(&Index::Eq).expect("writes");
    assert_eq!(
        unit,
        to_vec(&"eq").expect("writes"),
        "a unit variant is its name"
    );
    for index in [Index::Eq, Index::Match { k: 6 }, Index::Pair(7, "x".into())] {
        let back: Index = from_slice(&to_vec(&index).expect("writes")).expect("reads");
        assert_eq!(back, index);
    }
    // An object of one entry naming a unit variant, with a null payload,
    // reads as the unit variant too.
    let mut bytes = Vec::new();
    {
        let mut map = FrameWriter::new(&mut bytes).map(Some(1)).expect("map");
        map.entry("eq")
            .expect("entry")
            .scalar(None, Physical::Null)
            .expect("null");
        map.end().expect("end");
    }
    assert_eq!(from_slice::<Index>(&bytes).expect("reads"), Index::Eq);
}

/// Every scalar kind serde has round trips at its own width.
#[test]
fn scalars_round_trip() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct All {
        b: bool,
        i8: i8,
        i16: i16,
        i32: i32,
        i64: i64,
        i128: i128,
        u8: u8,
        u16: u16,
        u32: u32,
        u64: u64,
        u128: u128,
        f32: f32,
        f64: f64,
        c: char,
        s: String,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
        none: Option<u8>,
        some: Option<u8>,
        unit: (),
        seq: Vec<u16>,
        tuple: (u8, String),
        map: BTreeMap<String, i64>,
    }
    let all = All {
        b: true,
        i8: -8,
        i16: -300,
        i32: -70_000,
        i64: i64::MIN,
        i128: i128::MIN,
        u8: 200,
        u16: 60_000,
        u32: u32::MAX,
        u64: u64::MAX,
        u128: u128::MAX,
        f32: -0.0,
        f64: 2.25,
        c: 'é',
        s: "café".into(),
        bytes: vec![0, 1, 0xfe, 0xff],
        none: None,
        some: Some(3),
        unit: (),
        seq: vec![1, 2, 3],
        tuple: (1, "x".into()),
        map: BTreeMap::from([("a".into(), -1), ("b".into(), 2)]),
    };
    let back: All = from_slice(&to_vec(&all).expect("writes")).expect("reads");
    assert_eq!(back, all);
    assert_eq!(back.f32.to_bits(), (-0.0f32).to_bits());
}

/// What a type that reads through `deserialize_any` was handed.
#[derive(Debug, PartialEq)]
enum Seen {
    U32(u32),
    U64(u64),
    I32(i32),
    Str(String),
    Bytes(Vec<u8>),
    Unit,
}

impl<'de> Deserialize<'de> for Seen {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Seen;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("anything")
            }
            fn visit_u32<E>(self, v: u32) -> Result<Seen, E> {
                Ok(Seen::U32(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Seen, E> {
                Ok(Seen::U64(v))
            }
            fn visit_i32<E>(self, v: i32) -> Result<Seen, E> {
                Ok(Seen::I32(v))
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Seen, E> {
                Ok(Seen::Str(v.into()))
            }
            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Seen, E> {
                Ok(Seen::Bytes(v.into()))
            }
            fn visit_unit<E>(self) -> Result<Seen, E> {
                Ok(Seen::Unit)
            }
        }
        d.deserialize_any(V)
    }
}

/// A frame keeps an integer's width, and `deserialize_any` reports it: a
/// type whose identity depends on the width (a context part) can tell a
/// `u32` 7 from a `u64` 7. Text and bytes are borrowed from the input.
#[test]
fn deserialize_any_reports_the_exact_width_and_borrows() {
    let seen: Vec<Seen> = from_slice(
        &to_vec(&(7u32, 7u64, -7i32, "x", serde_bytes::Bytes::new(&[1, 2]), ())).expect("writes"),
    )
    .expect("reads");
    assert_eq!(
        seen,
        [
            Seen::U32(7),
            Seen::U64(7),
            Seen::I32(-7),
            Seen::Str("x".into()),
            Seen::Bytes(vec![1, 2]),
            Seen::Unit
        ]
    );
    let bytes = to_vec(&"borrowed").expect("writes");
    let borrowed: &str = from_slice(&bytes).expect("reads");
    assert_eq!(borrowed, "borrowed");
}

/// serde's own integer types read any integer that fits, as in every
/// format; one that does not fit is refused.
#[test]
fn integers_read_at_any_width_that_fits() {
    let wide: u64 = from_slice(&to_vec(&7u8).expect("writes")).expect("reads");
    assert_eq!(wide, 7);
    let narrow: u8 = from_slice(&to_vec(&7u64).expect("writes")).expect("reads");
    assert_eq!(narrow, 7);
    assert!(from_slice::<u8>(&to_vec(&300u32).expect("writes")).is_err());
}

#[test]
fn an_absent_optional_key_is_none_and_a_missing_required_key_is_refused() {
    #[derive(Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    struct Stats {
        rows: u64,
        #[serde(default)]
        confidence: Option<f64>,
    }
    #[derive(Serialize)]
    struct OnlyRows {
        rows: u64,
    }
    #[derive(Serialize)]
    struct NullConfidence {
        rows: u64,
        confidence: Option<f64>,
    }
    let stats: Stats = from_slice(&to_vec(&OnlyRows { rows: 3 }).expect("writes")).expect("reads");
    assert_eq!((stats.rows, stats.confidence), (3, None));
    let stats: Stats = from_slice(
        &to_vec(&NullConfidence {
            rows: 3,
            confidence: None,
        })
        .expect("writes"),
    )
    .expect("reads");
    assert_eq!(stats.confidence, None, "null is None too");

    #[derive(Serialize)]
    struct Empty {}
    let error = from_slice::<Stats>(&to_vec(&Empty {}).expect("writes")).expect_err("refused");
    assert!(error.message().contains("missing field"), "{error}");
}

#[test]
fn an_unknown_key_is_refused_without_naming_it() {
    #[derive(Serialize)]
    struct Extra {
        keyset: Keyset,
        secret_looking_key: u8,
    }
    let error = from_slice::<Options>(
        &to_vec(&Extra {
            keyset: Keyset::Default {},
            secret_looking_key: 1,
        })
        .expect("writes"),
    )
    .expect_err("refused");
    let text = format!("{error} {error:?}");
    assert!(text.contains("unknown key"), "{text}");
    assert!(text.contains("keyset, context"), "{text}");
    // Neither the message nor the path repeats the key.
    assert!(!text.contains("secret_looking_key"), "{text}");
    assert!(error.path().is_empty(), "{text}");
}

/// A wrong type names the kind found, never the value, even deep in the
/// tree; the path says where.
#[test]
fn errors_never_echo_a_value_and_carry_the_path() {
    #[derive(Deserialize, Debug)]
    struct Config {
        #[allow(dead_code)]
        client_key: u64,
    }
    #[derive(Serialize)]
    struct Sent<'a> {
        client_key: &'a str,
    }
    let error = from_slice::<Config>(
        &to_vec(&Sent {
            client_key: "c1i3nt-k3y-s3cr3t",
        })
        .expect("writes"),
    )
    .expect_err("refused");
    let text = format!("{error} {error:?}");
    assert!(!text.contains("s3cr3t"), "{text}");
    assert!(text.contains("found a string"), "{text}");
    assert_eq!(error.field(), Some("client_key"));
    assert_eq!(error.path(), [PathSegment::Key("client_key".into())]);

    // Inside an enum variant and an array.
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    enum Outer {
        Wrap(Vec<u8>),
    }
    let error =
        from_slice::<Outer>(&to_vec(&BTreeMap::from([("Wrap", vec!["no"])])).expect("writes"))
            .expect_err("refused");
    assert_eq!(
        error.path(),
        [PathSegment::Key("Wrap".into()), PathSegment::Index(0)]
    );
    assert_eq!(error.to_string(), "Wrap[0]: expected u8, found a string");
}

/// The frame parser refuses a repeated key before serde sees anything.
#[test]
fn a_repeated_key_is_refused() {
    let mut bytes = Vec::new();
    bytes.push(vitaminc_aead_frame::OBJECT);
    bytes.extend_from_slice(&2u32.to_le_bytes());
    for _ in 0..2 {
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(b'k');
        bytes.extend_from_slice(&to_vec(&1u8).expect("writes"));
    }
    let error = from_slice::<BTreeMap<String, u8>>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "malformed frame");
}

#[test]
fn trailing_bytes_and_a_truncated_frame_are_refused() {
    let mut bytes = to_vec(&1u8).expect("writes");
    bytes.push(0);
    assert!(from_slice::<u8>(&bytes).is_err());
    let bytes = to_vec(&"text").expect("writes");
    assert!(from_slice::<String>(&bytes[..bytes.len() - 1]).is_err());
}

/// serde has no data model for a date, a timestamp or a decimal, and a
/// passthrough is a transport choice, not data: both are refused.
#[test]
fn a_logical_scalar_and_a_passthrough_are_refused() {
    let date = vitaminc_aead::to_frame(Raw(Some(Logical::Date), Physical::Int(Int::I32(1))))
        .expect("frames");
    let error = from_slice::<Seen>(date.risky_ref_for_test()).expect_err("refused");
    assert!(error.message().contains("logical type"), "{error}");

    let mut bytes = Vec::new();
    {
        let mut map = FrameWriter::new(&mut bytes).map(Some(1)).expect("map");
        map.entry("p")
            .expect("entry")
            .passthrough(1u32)
            .expect("passthrough");
        map.end().expect("end");
    }
    let error = from_slice::<BTreeMap<String, Seen>>(&bytes).expect_err("refused");
    assert!(error.message().contains("passthrough"), "{error}");
    // A map's key is data, so the entry is placed by position only.
    assert_eq!(error.path(), [PathSegment::Entry(0)]);
    assert_eq!(error.field(), None);
    // Even a field nobody reads: an ignored key is skipped, not refused.
    #[derive(Deserialize)]
    struct Nothing {}
    from_slice::<Nothing>(&bytes).expect("an ignored passthrough is skipped");
}

#[test]
fn a_map_key_must_be_a_string() {
    let error = to_vec(&BTreeMap::from([(1u8, 2u8)])).expect_err("refused");
    assert_eq!(error.message(), "a map key must be a string");
}

/// A frame the vitaminc writer produced from a source reads through serde
/// to the same value: one format, two ways in.
#[test]
fn reads_a_frame_a_sink_wrote() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct User {
        name: String,
        age: u32,
    }
    let mut bytes = Vec::new();
    {
        let mut map = FrameWriter::new(&mut bytes).map(Some(2)).expect("map");
        "alice"
            .visit(map.entry("name").expect("entry"))
            .expect("name");
        34u32.visit(map.entry("age").expect("entry")).expect("age");
        map.end().expect("end");
    }
    assert_eq!(
        from_slice::<User>(&bytes).expect("reads"),
        User {
            name: "alice".into(),
            age: 34
        }
    );
}

/// A test-only view of a protected frame's bytes.
trait RiskyRefForTest {
    fn risky_ref_for_test(&self) -> &[u8];
}

impl RiskyRefForTest for vitaminc_protected::Protected<Vec<u8>> {
    fn risky_ref_for_test(&self) -> &[u8] {
        use vitaminc_protected::Controlled;
        self.risky_ref()
    }
}

#[test]
fn error_display_has_no_path_at_the_root() {
    let error: Error = from_slice::<u8>(&to_vec(&"x").expect("writes")).expect_err("refused");
    assert_eq!(error.to_string(), "expected u8, found a string");
    assert!(error.path().is_empty());
}

/// A map key is text: a string, a char, a unit variant or a newtype around
/// one is written as its text, and anything else is refused.
#[test]
fn map_keys_are_text_and_nothing_else() {
    #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
    #[serde(rename_all = "lowercase")]
    enum Key {
        Alpha,
    }
    #[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
    struct Wrapped(String);

    let by_char: BTreeMap<String, u8> =
        from_slice(&to_vec(&BTreeMap::from([('c', 1u8)])).expect("writes")).expect("reads");
    assert_eq!(by_char, BTreeMap::from([("c".to_owned(), 1)]));
    let by_variant: BTreeMap<String, u8> =
        from_slice(&to_vec(&BTreeMap::from([(Key::Alpha, 2u8)])).expect("writes")).expect("reads");
    assert_eq!(by_variant, BTreeMap::from([("alpha".to_owned(), 2)]));
    let by_newtype: BTreeMap<String, u8> =
        from_slice(&to_vec(&BTreeMap::from([(Wrapped("w".into()), 3u8)])).expect("writes"))
            .expect("reads");
    assert_eq!(by_newtype, BTreeMap::from([("w".to_owned(), 3)]));

    /// One key of each kind serde can serialize that is not text.
    #[derive(Serialize)]
    enum NotText {
        Variant(u8),
    }
    #[derive(Serialize)]
    struct Unit;
    #[derive(Serialize)]
    struct Pair(u8, u8);
    #[derive(Serialize)]
    struct Record {
        a: u8,
    }
    fn refused<K: Serialize>(key: K) {
        struct OneEntry<K>(K);
        impl<K: Serialize> Serialize for OneEntry<K> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(1))?;
                map.serialize_entry(&self.0, &0u8)?;
                map.end()
            }
        }
        let error = to_vec(&OneEntry(key)).expect_err("a key that is not text");
        assert_eq!(error.message(), "a map key must be a string");
    }
    refused(true);
    refused(1i8);
    refused(1i16);
    refused(1i32);
    refused(1i64);
    refused(1u8);
    refused(1u16);
    refused(1u32);
    refused(1u64);
    refused(1.0f32);
    refused(1.0f64);
    refused(serde_bytes::Bytes::new(&[1]));
    refused(None::<u8>);
    refused(Some("text"));
    refused(());
    refused(Unit);
    refused(NotText::Variant(1));
    refused(vec![1u8]);
    refused((1u8, 2u8));
    refused(Pair(1, 2));
    refused(BTreeMap::from([("a", 1u8)]));
    refused(Record { a: 1 });
}

/// Every struct shape round trips.
#[test]
fn every_struct_shape_round_trips() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Unit;
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Newtype(u32);
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Tuple(u8, String);
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct All {
        unit: Unit,
        newtype: Newtype,
        tuple: Tuple,
    }
    let all = All {
        unit: Unit,
        newtype: Newtype(7),
        tuple: Tuple(1, "x".into()),
    };
    assert_eq!(
        from_slice::<All>(&to_vec(&all).expect("writes")).expect("reads"),
        all
    );
    // A newtype struct is its inner value; a unit struct is null.
    assert_eq!(
        to_vec(&Newtype(7)).expect("writes"),
        to_vec(&7u32).expect("writes")
    );
    assert_eq!(to_vec(&Unit).expect("writes"), to_vec(&()).expect("writes"));
}

/// The format is binary both ways, so a type with a compact form uses it.
#[test]
fn the_format_is_not_human_readable() {
    struct Form;
    impl Serialize for Form {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let human = s.is_human_readable();
            s.serialize_bool(human)
        }
    }
    impl<'de> Deserialize<'de> for Form {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            assert!(!d.is_human_readable());
            bool::deserialize(d).map(|_| Form)
        }
    }
    let bytes = to_vec(&Form).expect("writes");
    assert_eq!(bytes, to_vec(&false).expect("writes"));
    from_slice::<Form>(&bytes).expect("reads");
}

/// What `size_hint` a sequence and a map report: the entries left.
#[test]
fn sequences_and_maps_report_their_length() {
    struct Hints(Vec<Option<usize>>);
    impl<'de> Deserialize<'de> for Hints {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Hints;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a sequence or a map")
                }
                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Hints, A::Error> {
                    let mut hints = vec![seq.size_hint()];
                    while seq.next_element::<de::IgnoredAny>()?.is_some() {
                        hints.push(seq.size_hint());
                    }
                    Ok(Hints(hints))
                }
                fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Hints, A::Error> {
                    let mut hints = vec![map.size_hint()];
                    while map
                        .next_entry::<de::IgnoredAny, de::IgnoredAny>()?
                        .is_some()
                    {
                        hints.push(map.size_hint());
                    }
                    Ok(Hints(hints))
                }
            }
            d.deserialize_any(V)
        }
    }
    let seq: Hints = from_slice(&to_vec(&[1u8, 2]).expect("writes")).expect("reads");
    assert_eq!(seq.0, [Some(2), Some(1), Some(0)]);
    let map: Hints = from_slice(&to_vec(&BTreeMap::from([("a", 1u8), ("b", 2)])).expect("writes"))
        .expect("reads");
    assert_eq!(map.0, [Some(2), Some(1), Some(0)]);
}

/// A field nobody reads is stepped over whatever it holds, and the fields
/// after it still read.
#[test]
fn an_ignored_field_of_any_shape_is_skipped() {
    #[derive(Serialize)]
    struct Sent {
        nested: BTreeMap<String, Vec<u8>>,
        list: Vec<BTreeMap<String, u8>>,
        scalar: String,
        last: u32,
    }
    #[derive(Deserialize, Debug, PartialEq)]
    struct Read {
        last: u32,
    }
    let sent = Sent {
        nested: BTreeMap::from([("a".into(), vec![1, 2]), ("b".into(), vec![])]),
        list: vec![BTreeMap::from([("k".into(), 1)]), BTreeMap::new()],
        scalar: "x".into(),
        last: 9,
    };
    assert_eq!(
        from_slice::<Read>(&to_vec(&sent).expect("writes")).expect("reads"),
        Read { last: 9 }
    );
}

/// A unit variant may carry a null payload, `{"eq": null}`, and the null is
/// read, so what follows still reads; and a value that leaves part of the
/// frame unread is refused.
#[test]
fn a_unit_variant_reads_its_null_payload() {
    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "lowercase")]
    enum Index {
        Eq,
        Ore,
    }
    let mut bytes = Vec::new();
    {
        let mut out = FrameWriter::new(&mut bytes).seq(Some(2)).expect("seq");
        {
            let mut map = vitaminc_aead::plaintext::SeqSink::element(&mut out)
                .expect("element")
                .map(Some(1))
                .expect("map");
            map.entry("eq")
                .expect("entry")
                .scalar(None, Physical::Null)
                .expect("null");
            map.end().expect("end");
        }
        "ore"
            .visit(vitaminc_aead::plaintext::SeqSink::element(&mut out).expect("element"))
            .expect("ore");
        vitaminc_aead::plaintext::SeqSink::end(out).expect("end");
    }
    assert_eq!(
        from_slice::<Vec<Index>>(&bytes).expect("reads"),
        [Index::Eq, Index::Ore]
    );

    // A type that reads only the first element of a sequence leaves the
    // rest unread, and is refused by the array itself.
    #[derive(Debug)]
    struct FirstOnly;
    impl<'de> Deserialize<'de> for FirstOnly {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = FirstOnly;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a sequence")
                }
                fn visit_seq<A: de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<FirstOnly, A::Error> {
                    let _ = seq.next_element::<u8>()?;
                    Ok(FirstOnly)
                }
            }
            d.deserialize_seq(V)
        }
    }
    let error = from_slice::<FirstOnly>(&to_vec(&[1u8, 2]).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "an array longer than expected");
}

/// An array or a passthrough is not an enum.
#[test]
fn an_array_is_not_an_enum() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    enum E {
        A,
    }
    let error = from_slice::<E>(&to_vec(&[1u8]).expect("writes")).expect_err("refused");
    assert_eq!(
        error.message(),
        "expected an enum: a variant name, or an object of one entry"
    );
    let error = from_slice::<E>(&to_vec(&1u8).expect("writes")).expect_err("refused");
    assert_eq!(
        error.message(),
        "expected an enum: a variant name, or an object of one entry"
    );
}

/// An error's path prints as keys joined by dots and indexes in brackets,
/// and its `Debug` is its `Display`, wrapped.
#[test]
fn an_error_path_prints_as_written() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Inner {
        n: u8,
    }
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Outer {
        outer: Vec<Inner>,
    }
    #[derive(Serialize)]
    struct SentInner {
        n: &'static str,
    }
    #[derive(Serialize)]
    struct SentOuter {
        outer: Vec<SentInner>,
    }
    let error = from_slice::<Outer>(
        &to_vec(&SentOuter {
            outer: vec![SentInner { n: "x" }],
        })
        .expect("writes"),
    )
    .expect_err("refused");
    assert_eq!(error.to_string(), "outer[0].n: expected u8, found a string");
    assert_eq!(
        format!("{error:?}"),
        "Error(outer[0].n: expected u8, found a string)"
    );

    // Reading, a later element is named by its own index.
    let error =
        from_slice::<Vec<u8>>(&to_vec(&(1u8, 2u8, "x")).expect("writes")).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Index(2)]);

    // The path of an error while writing names the element too.
    let error = to_vec(&(0u8, BTreeMap::from([(1u8, 1u8)]))).expect_err("a key that is not text");
    assert_eq!(error.path(), [PathSegment::Index(1)]);
    assert_eq!(error.to_string(), "[1]: a map key must be a string");
}

/// An unknown variant is refused without naming it: neither the message
/// nor the path repeats the tag a host sent.
#[test]
fn an_unknown_variant_is_refused_without_naming_it() {
    let mut tagged = BTreeMap::new();
    tagged.insert("secret_looking_tag", BTreeMap::<&str, u8>::new());
    let mut options = BTreeMap::new();
    options.insert("keyset", tagged);
    let error = from_slice::<Options>(&to_vec(&options).expect("writes")).expect_err("refused");
    let text = format!("{error} {error:?}");
    assert!(text.contains("unknown variant"), "{text}");
    assert!(!text.contains("secret_looking_tag"), "{text}");
    assert_eq!(error.path(), [PathSegment::Key("keyset".into())]);

    let error =
        from_slice::<Keyset>(&to_vec(&"secret_looking_tag").expect("writes")).expect_err("refused");
    assert!(!format!("{error} {error:?}").contains("secret_looking_tag"));
    assert!(error.path().is_empty());
}

/// An error inside a known variant's payload is placed under the variant.
#[test]
fn an_error_in_a_payload_is_placed_under_its_variant() {
    let mut tagged = BTreeMap::new();
    tagged.insert("name", 7u8);
    let error = from_slice::<Keyset>(&to_vec(&tagged).expect("writes")).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Key("name".into())]);
    assert_eq!(error.message(), "expected a string, found an integer");
}

/// A struct with no fields expects no keys, and says so.
#[test]
fn an_unknown_key_where_none_is_expected_says_none() {
    let mut fields = BTreeMap::new();
    fields.insert("x", 1u8);
    let mut tagged = BTreeMap::new();
    tagged.insert("default", fields);
    let error = from_slice::<Keyset>(&to_vec(&tagged).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "an unknown key, expected none");
    assert_eq!(error.path(), [PathSegment::Key("default".into())]);
}

/// Map keys and variant names are borrowed from the input, so a type whose
/// keys are `&str` reads them without a copy.
#[test]
fn map_keys_and_variant_names_borrow_from_the_input() {
    let mut map = BTreeMap::new();
    map.insert("email", 1u8);
    map.insert("name", 2u8);
    let bytes = to_vec(&map).expect("writes");
    let back: BTreeMap<&str, u8> = from_slice(&bytes).expect("reads");
    assert_eq!(back, map);

    struct Name<'a>(&'a str);
    impl<'de> Deserialize<'de> for Name<'de> {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Name<'de>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an enum")
                }
                fn visit_enum<A: de::EnumAccess<'de>>(
                    self,
                    data: A,
                ) -> Result<Name<'de>, A::Error> {
                    let (name, variant): (&'de str, _) = data.variant()?;
                    de::VariantAccess::unit_variant(variant)?;
                    Ok(Name(name))
                }
            }
            d.deserialize_enum("Name", &[], V)
        }
    }
    let bare = to_vec(&"eq").expect("writes");
    let name: Name<'_> = from_slice(&bare).expect("reads");
    assert_eq!(name.0, "eq");
    let mut tagged = BTreeMap::new();
    tagged.insert("ore", ());
    let tagged = to_vec(&tagged).expect("writes");
    let name: Name<'_> = from_slice(&tagged).expect("reads");
    assert_eq!(name.0, "ore");
}

/// A bare variant name has a null payload: a newtype variant reads its
/// payload from null, so one enum covers both `"match"` and
/// `{"match": {...}}`; a variant whose payload cannot be null is refused,
/// at the variant.
#[test]
fn a_bare_variant_name_reads_a_null_payload() {
    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(deny_unknown_fields)]
    struct MatchOptions {
        k: u8,
    }
    #[derive(Deserialize, PartialEq, Debug)]
    #[serde(rename_all = "lowercase")]
    enum Output {
        Eq,
        Match(Option<MatchOptions>),
        Name(String),
        Pair(u8, u8),
        Range { lo: u8 },
    }
    let read = |bytes: Vec<u8>| from_slice::<Output>(&bytes);

    assert_eq!(read(to_vec(&"eq").unwrap()).unwrap(), Output::Eq);
    assert_eq!(
        read(to_vec(&"match").unwrap()).unwrap(),
        Output::Match(None)
    );
    let mut opts = BTreeMap::new();
    opts.insert("k", 3u8);
    let mut tagged = BTreeMap::new();
    tagged.insert("match", opts);
    assert_eq!(
        read(to_vec(&tagged).unwrap()).unwrap(),
        Output::Match(Some(MatchOptions { k: 3 }))
    );
    let mut null = BTreeMap::new();
    null.insert("match", ());
    assert_eq!(read(to_vec(&null).unwrap()).unwrap(), Output::Match(None));

    let error = read(to_vec(&"name").unwrap()).expect_err("refused");
    assert_eq!(error.message(), "expected a string, found null");
    assert_eq!(error.path(), [PathSegment::Key("name".into())]);
    for bare in ["pair", "range"] {
        let error = read(to_vec(&bare).unwrap()).expect_err("refused");
        assert!(error.message().starts_with("expected a "), "{error}");
        assert!(
            error.message().ends_with(" variant, found a unit variant"),
            "{error}"
        );
    }
}

/// A type that returns without reading the deserializer it was handed.
#[derive(Debug, PartialEq)]
struct Unread;

impl<'de> Deserialize<'de> for Unread {
    fn deserialize<D: de::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Ok(Unread)
    }
}

/// A container a type stopped reading early is refused where it is, not
/// left for the enclosing object to misread as its next key or value.
#[test]
fn a_container_must_be_read_to_its_end() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Pair {
        pair: (u8,),
        n: u8,
    }
    #[derive(Serialize)]
    struct Sent {
        pair: (u8, u8),
        n: u8,
    }
    let bytes = to_vec(&Sent { pair: (1, 2), n: 3 }).expect("writes");
    let error = from_slice::<Pair>(&bytes).expect_err("refused");
    assert_eq!(error.to_string(), "pair: an array longer than expected");

    // An object whose last key is read but not its value.
    #[derive(Debug)]
    struct KeyOnly;
    impl<'de> Deserialize<'de> for KeyOnly {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = KeyOnly;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<KeyOnly, A::Error> {
                    let _ = map.next_key::<&str>()?;
                    Ok(KeyOnly)
                }
            }
            d.deserialize_map(V)
        }
    }
    let one = BTreeMap::from([("k", 1u8)]);
    let error = from_slice::<KeyOnly>(&to_vec(&one).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "an object with entries left unread");
    // And one that stops before its last entry.
    let two = BTreeMap::from([("j", 1u8), ("k", 2u8)]);
    let error = from_slice::<KeyOnly>(&to_vec(&two).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "an object with entries left unread");
}

/// A child whose type read nothing is refused at its own path, wherever it
/// sits: an element, an entry's value, an enum's payload, or the root.
#[test]
fn a_value_its_type_did_not_read_is_refused() {
    let error = from_slice::<Vec<Unread>>(&to_vec(&[1u8]).expect("writes")).expect_err("refused");
    assert_eq!(error.to_string(), "[0]: a value its type did not read");

    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Holder {
        held: Unread,
    }
    let error = from_slice::<Holder>(&to_vec(&BTreeMap::from([("held", 1u8)])).expect("writes"))
        .expect_err("refused");
    assert_eq!(error.to_string(), "held: a value its type did not read");

    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    #[serde(rename_all = "lowercase")]
    enum Tagged {
        Name(Unread),
    }
    let error = from_slice::<Tagged>(&to_vec(&BTreeMap::from([("name", 1u8)])).expect("writes"))
        .expect_err("refused");
    assert_eq!(error.to_string(), "a value its type did not read");

    let error = from_slice::<Unread>(&to_vec(&1u8).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "the value did not read the whole frame");
}

/// A type's own error message is dropped, reading and writing, since it
/// may print the value it refused. serde's own messages that name no value
/// are kept.
#[test]
fn a_types_own_message_is_never_printed() {
    #[derive(Deserialize, Debug)]
    #[serde(try_from = "String")]
    struct Token;
    impl TryFrom<String> for Token {
        type Error = String;
        fn try_from(value: String) -> Result<Self, String> {
            Err(format!("bad token {value}"))
        }
    }
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Config {
        token: Token,
    }
    let bytes = to_vec(&BTreeMap::from([("token", "s3cr3t")])).expect("writes");
    let error = from_slice::<Config>(&bytes).expect_err("refused");
    assert_eq!(error.to_string(), "token: a value its type does not accept");
    assert!(!format!("{error:?}").contains("s3cr3t"));

    #[derive(Serialize)]
    struct Leaky {
        #[serde(serialize_with = "leak")]
        token: &'static str,
    }
    fn leak<S: serde::Serializer>(value: &&str, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(format!("bad token {value}")))
    }
    let error = to_vec(&Leaky { token: "s3cr3t" }).expect_err("refused");
    assert_eq!(error.to_string(), "token: a value its type could not write");

    // A length names no value, so serde's message for it is kept.
    let error = from_slice::<(u8, u8)>(&to_vec(&[1u8]).expect("writes")).expect_err("refused");
    assert_eq!(
        error.message(),
        "expected a tuple of size 2, found a length of 1"
    );
}

/// A tuple or struct variant writes each part to a buffer of its own, and
/// still counts its depth from the top of the document: a value nested too
/// deep is refused where the limit is crossed, not after the whole value
/// has been descended.
#[test]
fn a_variant_part_counts_its_depth_from_the_top() {
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    #[serde(rename_all = "lowercase")]
    enum Tree {
        Node(Box<Tree>, u8),
        Leaf,
    }
    fn tree(depth: usize) -> Tree {
        (0..depth).fold(Tree::Leaf, |t, _| Tree::Node(Box::new(t), 0))
    }
    // Each node is an object and an array: two levels. The leaf under 64
    // nodes sits at the limit.
    let at_limit = tree(64);
    let bytes = to_vec(&at_limit).expect("writes at the limit");
    assert_eq!(from_slice::<Tree>(&bytes).expect("reads"), at_limit);

    let error = to_vec(&tree(65)).expect_err("too deep");
    assert!(error.message().contains("nests deeper"), "{error}");
    // Refused at the 65th node, before its parts were written.
    assert_eq!(error.path().len(), 2 * 64);

    // A value far deeper is refused at the same place, without descending
    // all the way down.
    let deep = tree(100_000);
    let error = to_vec(&deep).expect_err("too deep");
    assert_eq!(error.path().len(), 2 * 64);
    // Dropped iteratively: a recursive drop this deep would itself
    // overflow the stack.
    let mut next = deep;
    while let Tree::Node(child, _) = next {
        next = *child;
    }
}

/// A key the type accepts as data (a map's key, a flattened entry) is never
/// printed: its entry is placed by position. A field the type declares is
/// still named.
#[test]
fn a_key_only_a_host_chose_is_placed_by_position() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Context {
        known: u8,
        ctx: BTreeMap<String, u8>,
    }
    let bytes = to_vec(&serde_json::json!({
        "known": 1u8,
        "ctx": { "a": 1u8, "secret_looking_key": "s3cr3t" },
    }))
    .expect("writes");
    let error = from_slice::<Context>(&bytes).expect_err("refused");
    assert_eq!(error.to_string(), "ctx{1}: expected u8, found a string");
    assert_eq!(error.field(), Some("ctx"));
    assert!(!format!("{error:?}").contains("secret_looking_key"));

    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Flattened {
        known: u8,
        #[serde(flatten)]
        rest: BTreeMap<String, u8>,
    }
    let bytes = to_vec(&serde_json::json!({
        "known": 1u8,
        "secret_looking_key": [1u8],
    }))
    .expect("writes");
    let error = from_slice::<Flattened>(&bytes).expect_err("refused");
    assert!(!format!("{error} {error:?}").contains("secret_looking_key"));

    // A passthrough under a flattened key fails while serde buffers the
    // entry, through this format: the entry is placed by position.
    let mut bytes = Vec::new();
    {
        let mut map = FrameWriter::new(&mut bytes).map(Some(2)).expect("map");
        map.entry("known")
            .expect("entry")
            .scalar(None, Physical::Int(Int::U8(1)))
            .expect("known");
        map.entry("secret_looking_key")
            .expect("entry")
            .passthrough(1u32)
            .expect("passthrough");
        map.end().expect("end");
    }
    let error = from_slice::<Flattened>(&bytes).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Entry(1)]);
    assert!(!format!("{error} {error:?}").contains("secret_looking_key"));

    // Writing, a map's key is placed by position too.
    let sent = BTreeMap::from([("secret_looking_key", BTreeMap::from([(1u8, 1u8)]))]);
    let error = to_vec(&sent).expect_err("a key that is not text");
    assert_eq!(error.path(), [PathSegment::Entry(0)]);
    assert_eq!(error.to_string(), "{0}: a map key must be a string");
    // A later entry is placed by its own position.
    let sent = BTreeMap::from([
        ("a", BTreeMap::new()),
        ("secret_looking_key", BTreeMap::from([(1u8, 1u8)])),
    ]);
    let error = to_vec(&sent).expect_err("a key that is not text");
    assert_eq!(error.path(), [PathSegment::Entry(1)]);
}

/// A variant read through `#[serde(other)]` accepts a tag the type does not
/// declare. An error in its payload is placed by position, so the tag is
/// never printed.
#[test]
fn a_variant_read_through_other_is_not_named() {
    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "lowercase")]
    enum Mode {
        Strict,
        #[serde(other)]
        Unknown,
    }
    let bytes = to_vec(&BTreeMap::from([("secret_looking_tag", [1u8])])).expect("writes");
    let error = from_slice::<Mode>(&bytes).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Entry(0)]);
    assert!(!format!("{error} {error:?}").contains("secret_looking_tag"));
    // A declared variant is still named.
    let bytes = to_vec(&BTreeMap::from([("strict", [1u8])])).expect("writes");
    let error = from_slice::<Mode>(&bytes).expect_err("refused");
    assert_eq!(error.path(), [PathSegment::Key("strict".into())]);
    let _ = (Mode::Strict, Mode::Unknown);
}

/// JavaScript's `undefined` sits over null and reads as null: an absent
/// optional field a JS host sends as `undefined` is `None`.
#[test]
fn undefined_reads_as_null() {
    #[derive(Deserialize, Debug, PartialEq)]
    struct Options {
        context: Option<String>,
        unit: (),
    }
    let mut bytes = Vec::new();
    {
        let mut map = FrameWriter::new(&mut bytes).map(Some(2)).expect("map");
        map.entry("context")
            .expect("entry")
            .scalar(Some(Logical::Undefined), Physical::Null)
            .expect("undefined");
        map.entry("unit")
            .expect("entry")
            .scalar(Some(Logical::Undefined), Physical::Null)
            .expect("undefined");
        map.end().expect("end");
    }
    assert_eq!(
        from_slice::<Options>(&bytes).expect("reads"),
        Options {
            context: None,
            unit: ()
        }
    );
}

/// A visitor that asks for a value before its key is refused, rather than
/// reading the key's own bytes as the value.
#[test]
fn a_value_read_before_its_key_is_refused() {
    #[derive(Debug)]
    struct ValueFirst;
    impl<'de> Deserialize<'de> for ValueFirst {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = ValueFirst;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<ValueFirst, A::Error> {
                    let _ = map.next_value::<u8>()?;
                    Ok(ValueFirst)
                }
            }
            d.deserialize_map(V)
        }
    }
    let bytes = to_vec(&BTreeMap::from([("k", 1u8)])).expect("writes");
    let error = from_slice::<ValueFirst>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "a map value was read before its key");
}

/// A visitor that asks for a second key while a value is pending is
/// refused, rather than reading the value's own bytes as the key.
#[test]
fn a_key_read_before_the_previous_value_is_refused() {
    #[derive(Debug)]
    struct KeyTwice;
    impl<'de> Deserialize<'de> for KeyTwice {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = KeyTwice;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an object")
                }
                fn visit_map<A: de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<KeyTwice, A::Error> {
                    let _ = map.next_key::<String>()?;
                    let _ = map.next_key::<String>()?;
                    Ok(KeyTwice)
                }
            }
            d.deserialize_map(V)
        }
    }
    let bytes = to_vec(&BTreeMap::from([("a", "x"), ("b", "y")])).expect("writes");
    let error = from_slice::<KeyTwice>(&bytes).expect_err("refused");
    assert_eq!(
        error.message(),
        "a map key was read before the previous value"
    );
}

/// A map's keys and values are written in turn: a value with no key, a
/// second key while one is pending, and a key left without its value at the
/// end are each refused, rather than writing a misaligned entry or losing a
/// key.
#[test]
fn a_map_entry_written_out_of_turn_is_refused() {
    use serde::ser::SerializeMap;

    enum Order {
        ValueFirst,
        KeyTwice,
        KeyLast,
    }
    impl Serialize for Order {
        fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut map = s.serialize_map(None)?;
            map.serialize_entry("kept", &1u32)?;
            match self {
                Order::ValueFirst => map.serialize_value(&2u32)?,
                Order::KeyTwice => {
                    map.serialize_key("dropped")?;
                    map.serialize_key("replaced")?;
                }
                Order::KeyLast => map.serialize_key("dropped")?,
            }
            map.end()
        }
    }
    for (order, message) in [
        (Order::ValueFirst, "a map value was written before its key"),
        (
            Order::KeyTwice,
            "a map key was written before the previous value",
        ),
        (Order::KeyLast, "a map key was written without its value"),
    ] {
        let error = to_vec(&order).expect_err("refused");
        assert_eq!(error.message(), message);
    }
}

/// A struct or a map reads an object and nothing else. serde's derived
/// struct visitor would also read an array by position, which would let a
/// host send `[9]` where `{"rows": 9}` belongs.
#[test]
fn a_struct_or_map_reads_only_an_object() {
    #[derive(Deserialize, Debug)]
    #[allow(dead_code)]
    struct Point {
        x: u8,
        y: u8,
    }
    let error = from_slice::<Point>(&to_vec(&(1u8, 2u8)).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "expected struct Point, found an array");
    let error = from_slice::<Point>(&to_vec(&1u8).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "expected struct Point, found an integer");
    let error =
        from_slice::<BTreeMap<String, u8>>(&to_vec(&[1u8]).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "expected a map, found an array");

    let mut point = BTreeMap::new();
    point.insert("x", 1u8);
    point.insert("y", 2u8);
    let read: Point = from_slice(&to_vec(&point).expect("writes")).expect("reads");
    assert_eq!((read.x, read.y), (1, 2));
}

/// Text and bytes are kept apart: a string reads only text, and bytes read
/// only bytes, though serde's own visitors would take either.
#[test]
fn a_string_reads_only_text_and_bytes_only_bytes() {
    let bytes = to_vec(&serde_bytes::Bytes::new(b"acme")).expect("writes");
    let text = to_vec(&"acme").expect("writes");

    let error = from_slice::<String>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "expected a string, found bytes");
    let error = from_slice::<&str>(&bytes).expect_err("refused");
    assert_eq!(error.message(), "expected a borrowed string, found bytes");
    let error = from_slice::<serde_bytes::ByteBuf>(&text).expect_err("refused");
    assert_eq!(error.message(), "expected byte array, found a string");
    let error = from_slice::<&[u8]>(&text).expect_err("refused");
    assert_eq!(
        error.message(),
        "expected a borrowed byte array, found a string"
    );
    let error = from_slice::<String>(&to_vec(&[1u8]).expect("writes")).expect_err("refused");
    assert_eq!(error.message(), "expected a string, found an array");

    assert_eq!(from_slice::<&str>(&text).expect("reads"), "acme");
    assert_eq!(from_slice::<&[u8]>(&bytes).expect("reads"), b"acme");
    assert_eq!(
        from_slice::<serde_bytes::ByteBuf>(&bytes)
            .expect("reads")
            .into_vec(),
        b"acme"
    );

    // A logical scalar or a passthrough still says which it was.
    let date = vitaminc_aead::to_frame(Raw(Some(Logical::Date), Physical::Int(Int::I32(1))))
        .expect("frames");
    let error = from_slice::<String>(date.risky_ref_for_test()).expect_err("refused");
    assert!(error.message().contains("logical type"), "{error}");
    let error = from_slice::<BTreeMap<String, u8>>(date.risky_ref_for_test()).expect_err("refused");
    assert!(error.message().contains("logical type"), "{error}");
    let mut passthrough = Vec::new();
    {
        let mut map = FrameWriter::new(&mut passthrough)
            .map(Some(1))
            .expect("map");
        map.entry("p")
            .expect("entry")
            .passthrough(1u32)
            .expect("passthrough");
        map.end().expect("end");
    }
    let error = from_slice::<BTreeMap<String, String>>(&passthrough).expect_err("refused");
    assert!(error.message().contains("passthrough"), "{error}");
    let error =
        from_slice::<BTreeMap<String, serde_bytes::ByteBuf>>(&passthrough).expect_err("refused");
    assert!(error.message().contains("passthrough"), "{error}");
}
