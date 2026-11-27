//! Helpers that read a map frame one entry at a time, and write a map frame
//! in a given order.
//!
//! A frame is an [`OwnedFrame`]: a byte buffer that contains one value, in
//! the encoding of vitaminc, CipherStash's cryptography library. A map frame
//! contains a map. A sink receives a value from a frame one part at a time:
//! one scalar, array or map.
//!
//! The addon passes a record's row, and its stored row, between JavaScript
//! and the engine as one map frame each. The engine is the `stack-encrypt`
//! crate. The map has one entry for each of the record's fields. These
//! helpers split such a frame into one frame for each entry. They also
//! write entries back as one map, in the order given.

use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::dynamic::plaintext::{
    Error as SinkError, FixedType, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};
use stack_encrypt::{Buffer, Encrypt, EncryptRef};
use vitaminc_aead::frame::{FrameError, FrameWriteError};
use vitaminc_aead::{Frame, FrameWriter};

/// Returns the entries of a map frame, each as its own frame, in the map's
/// order. Returns `None` when the frame is not a map.
pub(crate) fn entries(frame: &OwnedFrame) -> Option<Vec<(String, OwnedFrame)>> {
    let buffers = frame.visit(Split).ok()?;
    buffers
        .into_iter()
        .map(|(key, buffer)| {
            OwnedFrame::from_buffer(buffer)
                .map(|frame| (key, frame))
                .ok()
        })
        .collect()
}

/// Returns the bytes of a frame that contains only a bytes value, or `None`
/// for any other frame.
pub(crate) fn bytes_of(frame: &OwnedFrame) -> Option<Vec<u8>> {
    frame.visit(BytesOf).ok()
}

/// One entry of a map that [`Map`] writes.
pub(crate) enum Entry<'a> {
    /// A value, written as it is.
    Value(&'a OwnedFrame),
    /// Bytes, written as a bytes value.
    Bytes(Vec<u8>),
    /// A frame given as its encoded bytes, such as a passthrough output's.
    /// A passthrough output is a value the engine stores as given, without
    /// encryption. The frame is parsed from the bytes and written without a
    /// copy.
    Frame(&'a [u8]),
    /// A nested map.
    Map(Map<'a>),
    /// A null.
    Null,
}

/// A map whose entries are written in the order given.
pub(crate) struct Map<'a>(pub(crate) Vec<(&'a str, Entry<'a>)>);

impl Encrypt for &Map<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(self.0.len()))?;
        for (key, entry) in &self.0 {
            let sink = map.entry(key)?;
            match entry {
                Entry::Value(frame) => {
                    let _ = frame.visit(sink)?;
                }
                Entry::Bytes(bytes) => {
                    let _ = sink.scalar(None, Physical::Bytes(bytes))?;
                }
                Entry::Frame(bytes) => {
                    let frame = Frame::parse(bytes)
                        .map_err(|error: FrameError| S::Error::source(SourceError::new(error)))?;
                    let _ = frame.visit(sink)?;
                }
                Entry::Map(inner) => {
                    let _ = inner.visit(sink)?;
                }
                Entry::Null => {
                    let _ = sink.scalar(None, Physical::Null)?;
                }
            }
        }
        map.end()
    }
}

/// A sink that writes each entry of a map into its own buffer.
struct Split;

/// The entries that [`Split`] has written so far.
struct Collect(Vec<(String, Buffer)>);

/// Returns the error that [`Split`] gives for any value that is not a map.
fn not_a_map() -> FrameWriteError {
    FrameWriteError::source(SourceError::msg("not a map"))
}

impl Sink for Split {
    type Ok = Vec<(String, Buffer)>;
    type Error = FrameWriteError;
    type Seq = NotAMap;
    type Map = Collect;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<Self::Ok, FrameWriteError> {
        Err(not_a_map())
    }
    fn typed_null(self, _: FixedType) -> Result<Self::Ok, FrameWriteError> {
        Err(not_a_map())
    }
    fn seq(self, _: Option<usize>) -> Result<NotAMap, FrameWriteError> {
        Err(not_a_map())
    }
    fn map(self, len: Option<usize>) -> Result<Collect, FrameWriteError> {
        Ok(Collect(Vec::with_capacity(len.unwrap_or(0).min(256))))
    }
    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<Self::Ok, FrameWriteError> {
        Err(not_a_map())
    }
}

impl MapSink for Collect {
    type Ok = Vec<(String, Buffer)>;
    type Error = FrameWriteError;
    type Entry<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_>, FrameWriteError> {
        self.0.push((key.to_owned(), Buffer::new()));
        match self.0.last_mut() {
            Some((_, buffer)) => Ok(FrameWriter::new(buffer)),
            None => Err(not_a_map()),
        }
    }

    fn end(self) -> Result<Self::Ok, FrameWriteError> {
        Ok(self.0)
    }
}

/// A type that is never created, because [`Split`] refuses a sequence
/// before it would create one.
struct NotAMap;

impl SeqSink for NotAMap {
    type Ok = Vec<(String, Buffer)>;
    type Error = FrameWriteError;
    type Element<'s>
        = Split
    where
        Self: 's;

    fn element(&mut self) -> Result<Split, FrameWriteError> {
        Err(not_a_map())
    }
    fn end(self) -> Result<Self::Ok, FrameWriteError> {
        Err(not_a_map())
    }
}

/// A sink that reads one bytes value.
struct BytesOf;

/// An error with no text. The caller writes its own message.
struct NotBytes;

impl SinkError for NotBytes {
    fn source(_: SourceError) -> Self {
        Self
    }
}

impl Sink for BytesOf {
    type Ok = Vec<u8>;
    type Error = NotBytes;
    type Seq = NoBytes;
    type Map = NoBytes;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Vec<u8>, NotBytes> {
        match (ty, value) {
            (None, Physical::Bytes(bytes)) => Ok(bytes.to_vec()),
            _ => Err(NotBytes),
        }
    }
    fn typed_null(self, _: FixedType) -> Result<Vec<u8>, NotBytes> {
        Err(NotBytes)
    }
    fn seq(self, _: Option<usize>) -> Result<NoBytes, NotBytes> {
        Err(NotBytes)
    }
    fn map(self, _: Option<usize>) -> Result<NoBytes, NotBytes> {
        Err(NotBytes)
    }
    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<Vec<u8>, NotBytes> {
        Err(NotBytes)
    }
}

/// A type that is never created, because [`BytesOf`] refuses an array or a
/// map before it would create one.
struct NoBytes;

impl SeqSink for NoBytes {
    type Ok = Vec<u8>;
    type Error = NotBytes;
    type Element<'s> = BytesOf;
    fn element(&mut self) -> Result<BytesOf, NotBytes> {
        Err(NotBytes)
    }
    fn end(self) -> Result<Vec<u8>, NotBytes> {
        Err(NotBytes)
    }
}

impl MapSink for NoBytes {
    type Ok = Vec<u8>;
    type Error = NotBytes;
    type Entry<'s> = BytesOf;
    fn entry(&mut self, _: &str) -> Result<BytesOf, NotBytes> {
        Err(NotBytes)
    }
    fn end(self) -> Result<Vec<u8>, NotBytes> {
        Err(NotBytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{bytes_of, entries, Entry, Map};
    use stack_encrypt::dynamic::frame::OwnedFrame;

    #[test]
    fn a_map_splits_into_its_entries_and_writes_back_in_order() {
        let a = OwnedFrame::of("x").unwrap();
        let written = OwnedFrame::of(&Map(vec![
            ("b", Entry::Value(&a)),
            ("a", Entry::Bytes(vec![1, 2])),
            ("c", Entry::Null),
        ]))
        .unwrap();
        let split = entries(&written).unwrap();
        let keys: Vec<_> = split.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["b", "a", "c"]);
        assert_eq!(split[0].1.frame(), a.frame());
        assert_eq!(bytes_of(&split[1].1), Some(vec![1, 2]));
        assert_eq!(bytes_of(&split[2].1), None);
    }

    #[test]
    fn anything_but_a_map_is_refused() {
        let text = OwnedFrame::of("x").unwrap();
        assert!(entries(&text).is_none());
    }
}
