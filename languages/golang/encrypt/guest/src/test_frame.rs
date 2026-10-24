//! Frames written by hand for tests: objects entry by entry, so a test can
//! send what no writer would (a repeated key, an integer of any width).

use serde::{Serialize, Serializer};
use stack_encrypt::dynamic::frame::serde::to_vec;

/// A test input, written as raw frame bytes by [`frame`].
pub(crate) enum V {
    Obj(Vec<(&'static str, V)>),
    Arr(Vec<V>),
    Str(String),
    Bytes(Vec<u8>),
    I32(i32),
    U32(u32),
    U64(u64),
    Bool(bool),
    Null,
}

struct RawBytes<'a>(&'a [u8]);

impl Serialize for RawBytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

/// The frame bytes of `v`.
pub(crate) fn frame(v: &V) -> Vec<u8> {
    let scalar = |r: Result<Vec<u8>, _>| r.expect("a scalar frames");
    let container = |tag: u8, len: usize| {
        let mut out = vec![tag];
        out.extend_from_slice(&u32::try_from(len).expect("short").to_le_bytes());
        out
    };
    match v {
        V::Obj(entries) => {
            let mut out = container(stack_encrypt::dynamic::frame::OBJECT, entries.len());
            for (key, value) in entries {
                out.extend_from_slice(&u32::try_from(key.len()).expect("short").to_le_bytes());
                out.extend_from_slice(key.as_bytes());
                out.extend_from_slice(&frame(value));
            }
            out
        }
        V::Arr(items) => {
            let mut out = container(stack_encrypt::dynamic::frame::ARRAY, items.len());
            for item in items {
                out.extend_from_slice(&frame(item));
            }
            out
        }
        V::Str(text) => scalar(to_vec(text)),
        V::Bytes(bytes) => scalar(to_vec(&RawBytes(bytes))),
        V::I32(n) => scalar(to_vec(n)),
        V::U32(n) => scalar(to_vec(n)),
        V::U64(n) => scalar(to_vec(n)),
        V::Bool(b) => scalar(to_vec(b)),
        V::Null => scalar(to_vec(&())),
    }
}

/// An object of `entries`, in order.
pub(crate) fn obj(entries: Vec<(&'static str, V)>) -> V {
    V::Obj(entries)
}

/// An empty object.
pub(crate) fn empty() -> V {
    V::Obj(Vec::new())
}

/// A string.
pub(crate) fn s(text: &str) -> V {
    V::Str(text.to_owned())
}
