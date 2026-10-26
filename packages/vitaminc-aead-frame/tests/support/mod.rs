//! What the storage tests share: the value model the corpus describes, an
//! independent decoder for it, and the types the corpus reads blobs as.

pub mod reference;
pub mod typed;

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

use serde::de::{self, Visitor};
use serde::ser::{SerializeMap, SerializeSeq, SerializeStruct};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use vitaminc_aead_frame::storage::HEADER;

pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

pub fn blob(body: &[u8]) -> Vec<u8> {
    [&HEADER[..], body].concat()
}

/// A name for serde's `&'static str` slots, kept for the rest of the run.
/// Each distinct name is kept once.
pub fn leak(name: &str) -> &'static str {
    static NAMES: Mutex<Option<HashSet<&'static str>>> = Mutex::new(None);
    let mut names = NAMES.lock().expect("not poisoned");
    let names = names.get_or_insert_with(HashSet::new);
    if let Some(kept) = names.get(name) {
        return kept;
    }
    let kept: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(kept);
    kept
}

// =============================================================================
// The model: one node of the storage data model
// =============================================================================

/// A node as the corpus describes it. It writes as exactly that node: an
/// object as a struct does, a map as a map does.
///
/// Read through serde (`deserialize_any`), an object and a map both arrive
/// as `visit_map`, so a read model holds every one as a [`Model::Map`]; see
/// [`erase`]. The [`reference`] decoder reads the bytes, and tells them
/// apart.
#[derive(Debug, Clone, PartialEq)]
pub enum Model {
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
    Map(Vec<(Model, Model)>),
}

/// What reading `model` through serde gives: every object a map with text
/// keys.
pub fn erase(model: &Model) -> Model {
    match model {
        Model::Some(inner) => Model::Some(Box::new(erase(inner))),
        Model::Array(items) => Model::Array(items.iter().map(erase).collect()),
        Model::Object(entries) => Model::Map(
            entries
                .iter()
                .map(|(k, v)| (Model::Text(k.clone()), erase(v)))
                .collect(),
        ),
        Model::Map(entries) => {
            Model::Map(entries.iter().map(|(k, v)| (erase(k), erase(v))).collect())
        }
        other => other.clone(),
    }
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
                let mut object = s.serialize_struct("Object", entries.len())?;
                for (key, value) in entries {
                    object.serialize_field(leak(key), value)?;
                }
                object.end()
            }
            Model::Map(entries) => {
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
                Ok(Model::Map(entries))
            }
        }
        d.deserialize_any(V)
    }
}

/// A corpus value: `null`, or an object of one entry naming the kind.
pub fn model(json: &Json) -> Model {
    let Some(object) = json.as_object() else {
        assert!(json.is_null(), "a value is null or a kind: {json}");
        return Model::Null;
    };
    assert_eq!(object.len(), 1, "a value names one kind: {json}");
    let (kind, value) = object.iter().next().expect("one entry");
    let text = || value.as_str().expect("a string");
    let hex64 = || u64::from_str_radix(text(), 16).expect("hex bits");
    let pairs = || {
        value
            .as_array()
            .expect("an array of entries")
            .iter()
            .map(|entry| entry.as_array().expect("a [key, value] pair"))
    };
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
            pairs()
                .map(|pair| (pair[0].as_str().expect("a key").to_owned(), model(&pair[1])))
                .collect(),
        ),
        "map" => Model::Map(
            pairs()
                .map(|pair| (model(&pair[0]), model(&pair[1])))
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
                    "map" => Model::Map(vec![(Model::U8(0), inner)]),
                    other => panic!("unknown nest kind {other}"),
                }
            })
        }
        other => panic!("unknown kind {other}"),
    }
}
