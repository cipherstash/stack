//! Gate fact 1 (#1384): code outside the engine can walk a decrypted record
//! frame and recover each field's value kind, with only the public API of
//! `stack-encrypt`'s `dynamic` module.
//!
//! The record is built with `ValueFrame::of`, the same type and writer
//! `dynamic::decrypt` returns its opened records in. This test does not
//! decrypt: it proves the reading half, which is the half the extension owns.

use stack_encrypt::dynamic::frame::Frame;
use stack_encrypt::dynamic::plaintext::{
    Encrypt, Error, FixedType, Int, Logical, MapSink, Physical, SeqSink, Sink, SourceError, Width,
};
use stack_encrypt::dynamic::ValueFrame;

/// A record the way a Python model would describe itself: text, an integer,
/// a date and a passthrough subtree.
struct User;

impl Encrypt for User {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(4))?;
        map.entry("email")?
            .scalar(None, Physical::Text("ada@example.com"))?;
        map.entry("age")?
            .scalar(None, Physical::Int(Int::I64(36)))?;
        map.entry("born")?
            .scalar(Some(Logical::Date), Physical::Int(Int::I32(-25_567)))?;
        map.entry("nickname")?.passthrough(Nickname)?;
        map.end()
    }
}

/// A record with the other shapes a field can have: a typed null, a
/// sequence and a nested map. The typed null is written as a plain null.
struct Shapes;

impl Encrypt for Shapes {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(3))?;
        let date = FixedType::new(Some(Logical::Date), Width::I32).expect("a date has a width");
        map.entry("left")?.typed_null(date)?;
        let mut tags = map.entry("tags")?.seq(Some(2))?;
        tags.element()?.scalar(None, Physical::Text("a"))?;
        tags.element()?.scalar(None, Physical::Int(Int::I64(2)))?;
        tags.end()?;
        let mut address = map.entry("address")?.map(Some(1))?;
        address
            .entry("city")?
            .scalar(None, Physical::Text("London"))?;
        address.end()?;
        map.end()
    }
}

#[derive(Clone)]
struct Nickname;

impl Encrypt for Nickname {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Text("ada"))
    }
}

/// What the reader records for one field: its key, the logical type, and the
/// physical kind. Values are not recorded, so the test never copies plaintext.
#[derive(Debug, PartialEq)]
struct Seen {
    key: String,
    logical: Option<String>,
    physical: &'static str,
    passthrough: bool,
}

#[derive(Debug)]
struct ReadError;

impl Error for ReadError {
    fn source(_: SourceError) -> Self {
        ReadError
    }
}

/// The reader: a `Sink` written outside the engine crate.
struct Reader<'a> {
    seen: &'a mut Vec<Seen>,
    key: Option<String>,
    passthrough: bool,
}

fn physical_name(value: &Physical<'_>) -> &'static str {
    match value {
        Physical::Null => "null",
        Physical::Bool(_) => "bool",
        Physical::Int(_) => "int",
        Physical::Float(_) => "float",
        Physical::Text(_) => "text",
        Physical::Bytes(_) => "bytes",
    }
}

impl Sink for Reader<'_> {
    type Ok = ();
    type Error = ReadError;
    type Seq = Self;
    type Map = Self;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), ReadError> {
        self.seen.push(Seen {
            key: self.key.unwrap_or_default(),
            logical: ty.map(|ty| format!("{ty:?}")),
            physical: physical_name(&value),
            passthrough: self.passthrough,
        });
        Ok(())
    }

    fn typed_null(self, ty: FixedType) -> Result<(), ReadError> {
        self.scalar(ty.logical(), Physical::Null)
    }

    fn seq(self, _: Option<usize>) -> Result<Self, ReadError> {
        Ok(self)
    }

    fn map(self, _: Option<usize>) -> Result<Self, ReadError> {
        Ok(self)
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), ReadError> {
        value.visit(Reader {
            seen: self.seen,
            key: self.key,
            passthrough: true,
        })
    }
}

impl SeqSink for Reader<'_> {
    type Ok = ();
    type Error = ReadError;
    type Element<'s>
        = Reader<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<Reader<'_>, ReadError> {
        Ok(Reader {
            seen: self.seen,
            key: self.key.clone(),
            passthrough: self.passthrough,
        })
    }

    fn end(self) -> Result<(), ReadError> {
        Ok(())
    }
}

impl MapSink for Reader<'_> {
    type Ok = ();
    type Error = ReadError;
    type Entry<'s>
        = Reader<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Reader<'_>, ReadError> {
        Ok(Reader {
            seen: self.seen,
            key: Some(key.to_owned()),
            passthrough: self.passthrough,
        })
    }

    fn end(self) -> Result<(), ReadError> {
        Ok(())
    }
}

fn read(frame: Frame<'_>) -> Vec<Seen> {
    let mut seen = Vec::new();
    frame
        .visit(Reader {
            seen: &mut seen,
            key: None,
            passthrough: false,
        })
        .expect("a validated frame walks without error");
    seen
}

fn seen(key: &str, logical: Option<&str>, physical: &'static str, passthrough: bool) -> Seen {
    Seen {
        key: key.to_owned(),
        logical: logical.map(str::to_owned),
        physical,
        passthrough,
    }
}

#[test]
fn an_outside_sink_recovers_each_field_kind_from_a_record_frame() {
    let record = ValueFrame::of(User).expect("the record is in the value model");
    let frame = Frame::parse(record.risky_ref()).expect("a ValueFrame is one frame");

    assert_eq!(
        read(frame),
        vec![
            seen("email", None, "text", false),
            seen("age", None, "int", false),
            seen("born", Some("Date"), "int", false),
            seen("nickname", None, "text", true),
        ],
    );
}

#[test]
fn an_outside_sink_reads_a_typed_null_a_sequence_and_a_nested_map() {
    let record = ValueFrame::of(Shapes).expect("the record is in the value model");
    let frame = Frame::parse(record.risky_ref()).expect("a ValueFrame is one frame");

    assert_eq!(
        read(frame),
        vec![
            // A frame writer writes a typed null as the plain null: a
            // frame is plaintext, so padding hides nothing in it (vitaminc's
            // FrameWriter). A decrypted record's null carries no type, and
            // the extension takes a field's type from its plan.
            seen("left", None, "null", false),
            seen("tags", None, "text", false),
            seen("tags", None, "int", false),
            seen("city", None, "text", false),
        ],
    );
}

#[test]
fn malformed_frame_bytes_are_refused_before_any_walk() {
    let record = ValueFrame::of(User).expect("the record is in the value model");
    let bytes = record.risky_ref();
    let truncated = &bytes[..bytes.len() - 1];

    assert!(Frame::parse(truncated).is_err());
}
