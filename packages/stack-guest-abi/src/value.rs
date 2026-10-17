//! [`HostValue`]: a value a guest hands its host, and how it crosses the
//! boundary.
//!
//! Every structured output a guest returns (a list of workspace ids, the
//! fields of a token, the last error) crosses as one transport frame, the
//! encoding vitaminc's `Frame` and `FrameWriter` define and the Go module
//! reads with `vcffi`. A `HostValue` describes itself to vitaminc's
//! [`Encrypt`] model, so [`encode`](HostValue::encode) is vitaminc's own
//! frame writer, and [`decode`](HostValue::decode) reads a frame back
//! through a [`Sink`], for the tests that check what a host is given.

use vitaminc_aead::plaintext::{
    visit_map, visit_seq, Encrypt, Float, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};
use vitaminc_aead_frame::{to_frame, Frame, FrameError, FrameWriteError};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroizing;

/// A value a guest hands its host: a scalar, a list or a map with string
/// keys.
///
/// Integers are 64-bit, unsigned where the value cannot be negative, so the
/// host reads one integer type per field. Bytes are held in [`Protected`],
/// as a client key is, and wiped when the value drops.
pub enum HostValue {
    /// No value.
    Null,
    /// A boolean.
    Bool(bool),
    /// An unsigned integer.
    UInt(u64),
    /// A signed integer.
    Int(i64),
    /// A float.
    Float(f64),
    /// Text, wiped when dropped: a guest hands secrets back as text (an
    /// access token), and the guest heap is not cleared when it frees.
    Text(Zeroizing<String>),
    /// Bytes.
    Bytes(Protected<Vec<u8>>),
    /// A list.
    List(Vec<HostValue>),
    /// A map, in the order its entries were given.
    Map(Vec<(String, HostValue)>),
}

impl HostValue {
    /// Text, from anything that converts to a `String`.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(Zeroizing::new(value.into()))
    }

    /// A structured field as a host value: a JSON number becomes an
    /// unsigned integer if it is one, then a signed integer, then a float.
    pub fn from_json(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(value) => Self::Bool(value),
            serde_json::Value::Number(number) => {
                if let Some(value) = number.as_u64() {
                    Self::UInt(value)
                } else if let Some(value) = number.as_i64() {
                    Self::Int(value)
                } else {
                    Self::Float(number.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(value) => Self::Text(Zeroizing::new(value)),
            serde_json::Value::Array(items) => {
                Self::List(items.into_iter().map(Self::from_json).collect())
            }
            serde_json::Value::Object(entries) => Self::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (key, Self::from_json(value)))
                    .collect(),
            ),
        }
    }

    /// This value as a transport frame.
    ///
    /// The frame is returned bare, as every guest output is: it becomes a
    /// registered buffer, which the registry wipes when the host releases
    /// it. Its capacity is its length: registering a `Vec` with spare
    /// capacity reallocates it (`into_boxed_slice`), and the allocation left
    /// behind is not wiped. So the frame is copied into an exactly sized
    /// buffer, and the writer's own buffer is wiped when it drops.
    ///
    /// # Errors
    ///
    /// [`FrameWriteError`] for a map with a repeated key or a value nested
    /// deeper than a frame carries. A guest builds its outputs itself, so
    /// either is a bug in the guest.
    pub fn encode(&self) -> Result<Vec<u8>, FrameWriteError> {
        let frame = to_frame(self)?;
        let mut out = Vec::with_capacity(frame.risky_ref().len());
        out.extend_from_slice(frame.risky_ref());
        Ok(out)
    }

    /// Read one value from a transport frame.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the bytes are not exactly one frame, or the
    /// frame holds a scalar a `HostValue` does not (a 32-bit float, a date).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let frame = Frame::parse(bytes).map_err(DecodeError::Frame)?;
        frame.visit(ValueSink(Root))
    }

    /// The entry under `key`, if this is a map that has one.
    pub fn get(&self, key: &str) -> Option<&HostValue> {
        match self {
            Self::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text, if this is text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text.as_str()),
            _ => None,
        }
    }
}

/// Why [`HostValue::decode`] refused its bytes.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The bytes are not exactly one well-formed frame.
    #[error(transparent)]
    Frame(FrameError),
    /// The frame holds a scalar no `HostValue` holds.
    #[error("the frame holds a scalar a host value does not")]
    Scalar,
    /// The frame's source failed (it cannot: a parsed frame is complete).
    #[error("the frame could not be read")]
    Source,
}

impl vitaminc_aead::plaintext::Error for DecodeError {
    fn source(_: SourceError) -> Self {
        Self::Source
    }
}

/// Walks the value, leaving it where it is.
impl Encrypt for &HostValue {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            HostValue::Null => sink.scalar(None, Physical::Null),
            HostValue::Bool(b) => sink.scalar(None, Physical::Bool(*b)),
            HostValue::UInt(u) => sink.scalar(None, Physical::Int((*u).into())),
            HostValue::Int(i) => sink.scalar(None, Physical::Int((*i).into())),
            HostValue::Float(f) => sink.scalar(None, Physical::Float(Float::F64(*f))),
            HostValue::Text(text) => sink.scalar(None, Physical::Text(text.as_str())),
            HostValue::Bytes(bytes) => sink.scalar(None, Physical::Bytes(bytes.risky_ref())),
            HostValue::List(items) => visit_seq(sink, Some(items.len()), items),
            HostValue::Map(entries) => visit_map(
                sink,
                Some(entries.len()),
                entries.iter().map(|(key, value)| (key.as_str(), value)),
            ),
        }
    }
}

/// Where a finished value goes: back to the caller, or into its parent.
trait Put {
    type Ok;
    fn put(self, value: HostValue) -> Self::Ok;
}

struct Root;

impl Put for Root {
    type Ok = HostValue;
    fn put(self, value: HostValue) -> HostValue {
        value
    }
}

struct Element<'s>(&'s mut Vec<HostValue>);

impl Put for Element<'_> {
    type Ok = ();
    fn put(self, value: HostValue) {
        self.0.push(value);
    }
}

struct Entry<'s>(&'s mut Vec<(String, HostValue)>, String);

impl Put for Entry<'_> {
    type Ok = ();
    fn put(self, value: HostValue) {
        self.0.push((self.1, value));
    }
}

/// Builds the value a frame describes.
struct ValueSink<O>(O);

impl<O: Put> Sink for ValueSink<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Seq = ValueSeq<O>;
    type Map = ValueMap<O>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<O::Ok, DecodeError> {
        let value = match (ty, value) {
            (None, Physical::Null) => HostValue::Null,
            (None, Physical::Bool(b)) => HostValue::Bool(b),
            (None, Physical::Int(int)) => {
                if let Some(u) = int.to_u128().and_then(|u| u64::try_from(u).ok()) {
                    HostValue::UInt(u)
                } else if let Some(i) = int.to_i128().and_then(|i| i64::try_from(i).ok()) {
                    HostValue::Int(i)
                } else {
                    return Err(DecodeError::Scalar);
                }
            }
            (None, Physical::Float(Float::F64(f))) => HostValue::Float(f),
            (None, Physical::Text(text)) => HostValue::Text(Zeroizing::new(text.to_owned())),
            (None, Physical::Bytes(bytes)) => HostValue::Bytes(Protected::new(bytes.to_vec())),
            _ => return Err(DecodeError::Scalar),
        };
        Ok(self.0.put(value))
    }

    fn seq(self, _: Option<usize>) -> Result<ValueSeq<O>, DecodeError> {
        Ok(ValueSeq {
            out: self.0,
            items: Vec::new(),
        })
    }

    fn map(self, _: Option<usize>) -> Result<ValueMap<O>, DecodeError> {
        Ok(ValueMap {
            out: self.0,
            entries: Vec::new(),
        })
    }

    /// A guest never hands its host a passthrough.
    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<O::Ok, DecodeError> {
        Err(DecodeError::Scalar)
    }
}

struct ValueSeq<O> {
    out: O,
    items: Vec<HostValue>,
}

impl<O: Put> SeqSink for ValueSeq<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Element<'s>
        = ValueSink<Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<ValueSink<Element<'_>>, DecodeError> {
        Ok(ValueSink(Element(&mut self.items)))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        Ok(self.out.put(HostValue::List(self.items)))
    }
}

struct ValueMap<O> {
    out: O,
    entries: Vec<(String, HostValue)>,
}

impl<O: Put> MapSink for ValueMap<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Entry<'s>
        = ValueSink<Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<ValueSink<Entry<'_>>, DecodeError> {
        Ok(ValueSink(Entry(&mut self.entries, key.to_owned())))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        Ok(self.out.put(HostValue::Map(self.entries)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An encoded frame has no spare capacity, so registering it does not
    /// reallocate and leave an unwiped copy behind.
    #[test]
    fn an_encoded_frame_has_no_spare_capacity() {
        let out = HostValue::Map(vec![(
            "access_token".to_string(),
            HostValue::text("a-bearer-token"),
        )])
        .encode()
        .unwrap();
        assert_eq!(out.capacity(), out.len());
    }

    /// Text is held as `Zeroizing<String>`, so a secret a guest hands back
    /// as text (the auth guest's access token) is wiped when the value is
    /// dropped, by every path that builds one: the constructor, JSON and a
    /// decoded frame. A plain `String` here would leave it in freed guest
    /// memory.
    #[test]
    fn text_is_wiped_on_drop() {
        fn held(value: HostValue) -> Zeroizing<String> {
            match value {
                HostValue::Text(text) => text,
                _ => panic!("not text"),
            }
        }
        assert_eq!(held(HostValue::text("token")).as_str(), "token");
        assert_eq!(
            held(HostValue::from_json(serde_json::json!("token"))).as_str(),
            "token"
        );
        let frame = HostValue::text("token").encode().unwrap();
        assert_eq!(held(HostValue::decode(&frame).unwrap()).as_str(), "token");
    }

    #[test]
    fn a_value_reads_back_as_it_was_written() {
        let value = HostValue::Map(vec![
            ("null".into(), HostValue::Null),
            ("yes".into(), HostValue::Bool(true)),
            ("big".into(), HostValue::UInt(u64::MAX)),
            ("negative".into(), HostValue::Int(-2)),
            ("half".into(), HostValue::Float(0.5)),
            ("name".into(), HostValue::text("alice")),
            ("key".into(), HostValue::Bytes(Protected::new(vec![1, 2]))),
            (
                "ids".into(),
                HostValue::List(vec![HostValue::text("a"), HostValue::List(vec![])]),
            ),
        ]);
        let bytes = value.encode().expect("encodes");
        let back = HostValue::decode(&bytes).expect("decodes");
        assert!(matches!(back.get("null"), Some(HostValue::Null)));
        assert!(matches!(back.get("yes"), Some(HostValue::Bool(true))));
        assert!(matches!(back.get("big"), Some(HostValue::UInt(u64::MAX))));
        assert!(matches!(back.get("negative"), Some(HostValue::Int(-2))));
        assert!(matches!(back.get("half"), Some(HostValue::Float(f)) if *f == 0.5));
        assert_eq!(back.get("name").and_then(HostValue::as_text), Some("alice"));
        assert!(matches!(back.get("key"), Some(HostValue::Bytes(b)) if b.risky_ref() == &[1, 2]));
        assert!(matches!(back.get("ids"), Some(HostValue::List(items)) if items.len() == 2));
    }

    #[test]
    fn a_map_with_a_repeated_key_does_not_encode() {
        let value = HostValue::Map(vec![
            ("a".into(), HostValue::Null),
            ("a".into(), HostValue::Null),
        ]);
        assert!(value.encode().is_err());
    }

    #[test]
    fn bytes_that_are_not_one_frame_do_not_decode() {
        assert!(matches!(HostValue::decode(&[]), Err(DecodeError::Frame(_))));
    }

    #[test]
    fn json_numbers_keep_their_integer_type() {
        assert!(matches!(
            HostValue::from_json(serde_json::json!(2)),
            HostValue::UInt(2)
        ));
        assert!(matches!(
            HostValue::from_json(serde_json::json!(-2)),
            HostValue::Int(-2)
        ));
        assert!(matches!(
            HostValue::from_json(serde_json::json!(0.5)),
            HostValue::Float(f) if f == 0.5
        ));
    }
}
