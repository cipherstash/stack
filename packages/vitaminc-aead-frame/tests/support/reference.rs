//! A second reader of version 1, written from STORAGE.md alone and sharing
//! no code with the crate: no leaf codec, no serde. The tests hold the
//! crate to it, so a reading of the specification that only the crate's
//! code makes shows up as a disagreement.

use super::Model;

/// Why the reference refuses a blob: the specification's three classes,
/// and for a malformed blob, the rule it breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotABlob,
    UnsupportedVersion,
    Malformed(Broken),
}

/// Which of the rules numbered 3 to 9 in STORAGE.md's *Reading* a
/// malformed blob breaks, the first the reader meets, and which part of
/// the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// 3: the body ends before its node does, or bytes follow its node.
    NotOneNode { trailing: bool },
    /// 4: a byte the grammar does not allow where it is, as a node or as a
    /// map's key.
    Tag { byte: u8, as_key: bool },
    /// 5: a length, or a count, larger than the bytes left when it is read.
    PastTheEnd { count: bool },
    /// 6: an object's key, or a text scalar, is not UTF-8.
    NotUtf8 { key: bool },
    /// 7: one object has two entries with the same key.
    RepeatedField,
    /// 8: one map has two equal keys, starting with these tags.
    RepeatedKey { first: u8, second: u8 },
    /// 9: a node is deeper than 128.
    TooDeep,
}

const MAX_DEPTH: usize = 128;

/// The tags a map's key may start with: every integer width, text, bytes.
pub const KEY_TAGS: [u8; 12] = [
    0x0C, 0x0E, 0x04, 0x05, 0x10, 0x0D, 0x0F, 0x06, 0x07, 0x11, 0x0A, 0x0B,
];

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
    let node = reader.node(0).map_err(Refusal::Malformed)?;
    if reader.at != reader.bytes.len() {
        return Err(Refusal::Malformed(Broken::NotOneNode { trailing: true }));
    }
    Ok(node)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// The next `n` bytes, or `short` if the blob ends first.
    fn take(&mut self, n: usize, short: Broken) -> Result<&[u8], Broken> {
        if self.left() < n {
            return Err(short);
        }
        let taken = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(taken)
    }

    /// A fixed-width field: a blob that ends inside one is truncated.
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Broken> {
        self.take(N, Broken::NotOneNode { trailing: false })
            .map(|b| b.try_into().expect("N bytes"))
    }

    fn u32(&mut self) -> Result<usize, Broken> {
        Ok(u32::from_le_bytes(self.array()?) as usize)
    }

    /// The bytes a length counts: a length the blob cannot hold runs past
    /// its end.
    fn counted(&mut self) -> Result<&[u8], Broken> {
        let len = self.u32()?;
        self.take(len, Broken::PastTheEnd { count: false })
    }

    /// A count of children: more than the bytes left runs past the end of
    /// the blob, since a child is at least one byte. A count the bytes left
    /// could hold, whose children then end early, is truncated.
    fn count(&mut self) -> Result<usize, Broken> {
        let count = self.u32()?;
        if count > self.left() {
            return Err(Broken::PastTheEnd { count: true });
        }
        Ok(count)
    }

    /// A text scalar, or an object's key when `key`.
    fn text(&mut self, key: bool) -> Result<String, Broken> {
        String::from_utf8(self.counted()?.to_vec()).map_err(|_| Broken::NotUtf8 { key })
    }

    fn node(&mut self, depth: usize) -> Result<Model, Broken> {
        if depth > MAX_DEPTH {
            return Err(Broken::TooDeep);
        }
        let tag = self.array::<1>()?[0];
        Ok(match tag {
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
            0x0A => Model::Text(self.text(false)?),
            0x0B => Model::Bytes(self.counted()?.to_vec()),
            0xF5 => Model::Some(Box::new(self.node(depth + 1)?)),
            0xF0 => {
                let count = self.count()?;
                let mut items = Vec::new();
                for _ in 0..count {
                    items.push(self.node(depth + 1)?);
                }
                Model::Array(items)
            }
            0xF1 => {
                let count = self.count()?;
                let mut entries: Vec<(String, Model)> = Vec::new();
                for _ in 0..count {
                    let key = self.text(true)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(Broken::RepeatedField);
                    }
                    entries.push((key, self.node(depth + 1)?));
                }
                Model::Object(entries)
            }
            0xF6 => {
                let count = self.count()?;
                let mut entries: Vec<(Model, Model)> = Vec::new();
                for _ in 0..count {
                    let byte = *self
                        .bytes
                        .get(self.at)
                        .ok_or(Broken::NotOneNode { trailing: false })?;
                    if !KEY_TAGS.contains(&byte) {
                        return Err(Broken::Tag { byte, as_key: true });
                    }
                    let key = self.node(depth + 1)?;
                    let same = key_value(&key).expect("a key tag reads as a key");
                    if let Some((earlier, _)) = entries
                        .iter()
                        .find(|(k, _)| key_value(k) == Some(same.clone()))
                    {
                        return Err(Broken::RepeatedKey {
                            first: tag_of(earlier),
                            second: byte,
                        });
                    }
                    entries.push((key, self.node(depth + 1)?));
                }
                Model::Map(entries)
            }
            byte => {
                return Err(Broken::Tag {
                    byte,
                    as_key: false,
                })
            }
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

/// The tag a node starts with.
pub fn tag_of(node: &Model) -> u8 {
    match node {
        Model::Null => 0x00,
        Model::Bool(false) => 0x02,
        Model::Bool(true) => 0x03,
        Model::I8(_) => 0x0C,
        Model::I16(_) => 0x0E,
        Model::I32(_) => 0x04,
        Model::I64(_) => 0x05,
        Model::I128(_) => 0x10,
        Model::U8(_) => 0x0D,
        Model::U16(_) => 0x0F,
        Model::U32(_) => 0x06,
        Model::U64(_) => 0x07,
        Model::U128(_) => 0x11,
        Model::F32(_) => 0x08,
        Model::F64(_) => 0x09,
        Model::Text(_) => 0x0A,
        Model::Bytes(_) => 0x0B,
        Model::Some(_) => 0xF5,
        Model::Array(_) => 0xF0,
        Model::Object(_) => 0xF1,
        Model::Map(_) => 0xF6,
    }
}
