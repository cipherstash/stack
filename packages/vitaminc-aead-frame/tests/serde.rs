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
    let text = error.to_string();
    assert!(text.contains("unknown key"), "{text}");
    assert!(text.contains("keyset, context"), "{text}");
    // The key is on the path, which a caller may report or not, but the
    // message itself does not repeat it.
    assert!(!error.message().contains("secret_looking_key"), "{text}");
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
    assert_eq!(error.field(), Some("p"));
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
