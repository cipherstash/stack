//! A second reader of version 1, written from STORAGE.md alone and sharing
//! no code with the crate: no leaf codec, no serde. The tests hold the
//! crate to it, so a reading of the specification that only the crate's
//! code makes shows up as a disagreement.

use super::Model;

/// Why the reference refuses a blob: the specification's three classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotABlob,
    UnsupportedVersion,
    Malformed,
}

const MAX_DEPTH: usize = 128;

/// Read a whole blob as the node it holds.
pub fn decode(bytes: &[u8]) -> Result<Model, Refusal> {
    if bytes.len() < 4 || &bytes[..3] != b"VCS" {
        return Err(Refusal::NotABlob);
    }
    if bytes[3] != 1 {
        return Err(Refusal::UnsupportedVersion);
    }
    let mut reader = Reader {
        bytes: &bytes[4..],
        at: 0,
    };
    let node = reader.node(0).ok_or(Refusal::Malformed)?;
    if reader.at != reader.bytes.len() {
        return Err(Refusal::Malformed);
    }
    Ok(node)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        if self.bytes.len() - self.at < n {
            return None;
        }
        let taken = &self.bytes[self.at..self.at + n];
        self.at += n;
        Some(taken)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes(N).map(|b| b.try_into().expect("N bytes"))
    }

    fn u32(&mut self) -> Option<usize> {
        Some(u32::from_le_bytes(self.array()?) as usize)
    }

    fn text(&mut self) -> Option<String> {
        let len = self.u32()?;
        String::from_utf8(self.bytes(len)?.to_vec()).ok()
    }

    fn node(&mut self, depth: usize) -> Option<Model> {
        if depth > MAX_DEPTH {
            return None;
        }
        let tag = self.array::<1>()?[0];
        Some(match tag {
            0x00 => Model::Null,
            0x02 => Model::Bool(false),
            0x03 => Model::Bool(true),
            0x0C => Model::I8(i8::from_le_bytes(self.array()?)),
            0x0E => Model::I16(i16::from_le_bytes(self.array()?)),
            0x04 => Model::I32(i32::from_le_bytes(self.array()?)),
            0x05 => Model::I64(i64::from_le_bytes(self.array()?)),
            0x10 => Model::I128(i128::from_le_bytes(self.array()?)),
            0x0D => Model::U8(u8::from_le_bytes(self.array()?)),
            0x0F => Model::U16(u16::from_le_bytes(self.array()?)),
            0x06 => Model::U32(u32::from_le_bytes(self.array()?)),
            0x07 => Model::U64(u64::from_le_bytes(self.array()?)),
            0x11 => Model::U128(u128::from_le_bytes(self.array()?)),
            0x08 => Model::F32(u32::from_le_bytes(self.array()?)),
            0x09 => Model::F64(u64::from_le_bytes(self.array()?)),
            0x0A => Model::Text(self.text()?),
            0x0B => {
                let len = self.u32()?;
                Model::Bytes(self.bytes(len)?.to_vec())
            }
            0xF5 => Model::Some(Box::new(self.node(depth + 1)?)),
            0xF0 => {
                let count = self.u32()?;
                let mut items = Vec::new();
                for _ in 0..count {
                    items.push(self.node(depth + 1)?);
                }
                Model::Array(items)
            }
            0xF1 => {
                let count = self.u32()?;
                let mut entries: Vec<(String, Model)> = Vec::new();
                for _ in 0..count {
                    let key = self.text()?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return None;
                    }
                    entries.push((key, self.node(depth + 1)?));
                }
                Model::Object(entries)
            }
            0xF6 => {
                let count = self.u32()?;
                let mut entries: Vec<(Model, Model)> = Vec::new();
                for _ in 0..count {
                    let key = self.node(depth + 1)?;
                    let same = key_value(&key)?;
                    if entries
                        .iter()
                        .any(|(k, _)| key_value(k) == Some(same.clone()))
                    {
                        return None;
                    }
                    entries.push((key, self.node(depth + 1)?));
                }
                Model::Map(entries)
            }
            _ => return None,
        })
    }
}

/// A map key's value, for finding a repeat: an integer as a number whatever
/// its width; text and bytes as themselves, never equal to each other.
/// Anything else is no key at all.
#[derive(Clone, PartialEq)]
pub enum KeyValue {
    Integer(i128),
    /// Above `i128::MAX`, so only a `u128` holds it.
    Huge(u128),
    Text(String),
    Bytes(Vec<u8>),
}

pub fn key_value(key: &Model) -> Option<KeyValue> {
    let int = |v: i128| Some(KeyValue::Integer(v));
    match key {
        Model::I8(v) => int((*v).into()),
        Model::I16(v) => int((*v).into()),
        Model::I32(v) => int((*v).into()),
        Model::I64(v) => int((*v).into()),
        Model::I128(v) => int(*v),
        Model::U8(v) => int((*v).into()),
        Model::U16(v) => int((*v).into()),
        Model::U32(v) => int((*v).into()),
        Model::U64(v) => int((*v).into()),
        Model::U128(v) => Some(match i128::try_from(*v) {
            Ok(v) => KeyValue::Integer(v),
            Err(_) => KeyValue::Huge(*v),
        }),
        Model::Text(v) => Some(KeyValue::Text(v.clone())),
        Model::Bytes(v) => Some(KeyValue::Bytes(v.clone())),
        _ => None,
    }
}
