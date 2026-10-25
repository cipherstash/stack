//! The types the corpus's `reads` rows read blobs as, described in JSON,
//! and read through serde exactly as a derived type would read them. Each
//! read gives the [`Model`] of the value in the form that type writes, so
//! writing it gives the canonical blob.
//!
//! A type is a string (`"u8"` … `"u128"`, `"i8"` … `"i128"`, `"f32"`,
//! `"f64"`, `"bool"`, `"unit"`, `"text"`, `"bytes"`) or an object of one
//! entry: `{"option": T}`, `{"seq": T}`, `{"map": [K, V]}`,
//! `{"struct": [[name, T], …]}`, or `{"enum": [[name, "unit"],
//! [name, "newtype", T], [name, "tuple", [T, …]], [name, "struct",
//! [[name, T], …]], …]}`. A struct ignores unknown keys, and reads a
//! missing `Option` field as `None`, as serde's derive does.

use std::cell::RefCell;
use std::fmt;

use serde::de::{self, DeserializeSeed, IgnoredAny, Visitor};
use serde::Deserialize;
use serde_json::Value as Json;

use super::{leak, Model};

pub enum Schema {
    Unit,
    Bool,
    I8,
    I16,
    I32,
    I64,
    I128,
    U8,
    U16,
    U32,
    U64,
    U128,
    F32,
    F64,
    Text,
    Bytes,
    Option(Box<Schema>),
    Seq(Box<Schema>),
    Map(Box<Schema>, Box<Schema>),
    Struct(Fields),
    Enum(Vec<Variant>),
}

pub struct Fields {
    names: &'static [&'static str],
    types: Vec<Schema>,
}

pub struct Variant {
    name: &'static str,
    kind: VariantKind,
}

pub enum VariantKind {
    Unit,
    Newtype(Schema),
    Tuple(Vec<Schema>),
    Struct(Fields),
}

pub fn schema(json: &Json) -> Schema {
    if let Some(name) = json.as_str() {
        return match name {
            "unit" => Schema::Unit,
            "bool" => Schema::Bool,
            "i8" => Schema::I8,
            "i16" => Schema::I16,
            "i32" => Schema::I32,
            "i64" => Schema::I64,
            "i128" => Schema::I128,
            "u8" => Schema::U8,
            "u16" => Schema::U16,
            "u32" => Schema::U32,
            "u64" => Schema::U64,
            "u128" => Schema::U128,
            "f32" => Schema::F32,
            "f64" => Schema::F64,
            "text" => Schema::Text,
            "bytes" => Schema::Bytes,
            other => panic!("unknown type {other}"),
        };
    }
    let object = json.as_object().expect("a type is a name or an object");
    assert_eq!(object.len(), 1, "a type names one kind: {json}");
    let (kind, value) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "option" => Schema::Option(Box::new(schema(value))),
        "seq" => Schema::Seq(Box::new(schema(value))),
        "map" => Schema::Map(Box::new(schema(&value[0])), Box::new(schema(&value[1]))),
        "struct" => Schema::Struct(fields(value)),
        "enum" => Schema::Enum(
            value
                .as_array()
                .expect("variants")
                .iter()
                .map(|v| Variant {
                    name: leak(v[0].as_str().expect("a variant name")),
                    kind: match v[1].as_str().expect("a variant kind") {
                        "unit" => VariantKind::Unit,
                        "newtype" => VariantKind::Newtype(schema(&v[2])),
                        "tuple" => VariantKind::Tuple(
                            v[2].as_array().expect("types").iter().map(schema).collect(),
                        ),
                        "struct" => VariantKind::Struct(fields(&v[2])),
                        other => panic!("unknown variant kind {other}"),
                    },
                })
                .collect(),
        ),
        other => panic!("unknown type {other}"),
    }
}

fn fields(json: &Json) -> Fields {
    let pairs = json.as_array().expect("fields");
    let names: Vec<&'static str> = pairs
        .iter()
        .map(|p| leak(p[0].as_str().expect("a field name")))
        .collect();
    Fields {
        names: Box::leak(names.into_boxed_slice()),
        types: pairs.iter().map(|p| schema(&p[1])).collect(),
    }
}

thread_local! {
    static SCHEMA: RefCell<Option<Schema>> = const { RefCell::new(None) };
}

/// A value read by the schema [`read_as`] set, for `storage::from_slice`,
/// which takes a type rather than a seed.
#[derive(Debug)]
pub struct Typed(pub Model);

impl<'de> Deserialize<'de> for Typed {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        SCHEMA
            .with(|schema| {
                let schema = schema.borrow();
                schema.as_ref().expect("a schema is set").deserialize(d)
            })
            .map(Typed)
    }
}

/// Read the next [`Typed`] values as `schema`.
pub fn read_as(schema: Schema) {
    SCHEMA.with(|s| *s.borrow_mut() = Some(schema));
}

impl<'de> DeserializeSeed<'de> for &Schema {
    type Value = Model;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Model, D::Error> {
        Ok(match self {
            Schema::Unit => {
                <()>::deserialize(d)?;
                Model::Null
            }
            Schema::Bool => Model::Bool(bool::deserialize(d)?),
            Schema::I8 => Model::I8(i8::deserialize(d)?),
            Schema::I16 => Model::I16(i16::deserialize(d)?),
            Schema::I32 => Model::I32(i32::deserialize(d)?),
            Schema::I64 => Model::I64(i64::deserialize(d)?),
            Schema::I128 => Model::I128(i128::deserialize(d)?),
            Schema::U8 => Model::U8(u8::deserialize(d)?),
            Schema::U16 => Model::U16(u16::deserialize(d)?),
            Schema::U32 => Model::U32(u32::deserialize(d)?),
            Schema::U64 => Model::U64(u64::deserialize(d)?),
            Schema::U128 => Model::U128(u128::deserialize(d)?),
            Schema::F32 => Model::F32(f32::deserialize(d)?.to_bits()),
            Schema::F64 => Model::F64(f64::deserialize(d)?.to_bits()),
            Schema::Text => Model::Text(String::deserialize(d)?),
            Schema::Bytes => Model::Bytes(serde_bytes::ByteBuf::deserialize(d)?.into_vec()),
            Schema::Option(inner) => d.deserialize_option(OptionV(inner))?,
            Schema::Seq(inner) => d.deserialize_seq(SeqV(inner))?,
            Schema::Map(k, v) => d.deserialize_map(MapV(k, v))?,
            Schema::Struct(fields) => d.deserialize_struct("S", fields.names, StructV(fields))?,
            Schema::Enum(variants) => {
                let names: Vec<&'static str> = variants.iter().map(|v| v.name).collect();
                d.deserialize_enum("E", Box::leak(names.into_boxed_slice()), EnumV(variants))?
            }
        })
    }
}

struct OptionV<'s>(&'s Schema);

impl<'de> Visitor<'de> for OptionV<'_> {
    type Value = Model;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an option")
    }
    fn visit_none<E>(self) -> Result<Model, E> {
        Ok(Model::Null)
    }
    fn visit_unit<E>(self) -> Result<Model, E> {
        Ok(Model::Null)
    }
    fn visit_some<D: de::Deserializer<'de>>(self, d: D) -> Result<Model, D::Error> {
        Ok(Model::Some(Box::new(self.0.deserialize(d)?)))
    }
}

struct SeqV<'s>(&'s Schema);

impl<'de> Visitor<'de> for SeqV<'_> {
    type Value = Model;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a sequence")
    }
    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Model, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.0)? {
            items.push(item);
        }
        Ok(Model::Array(items))
    }
}

struct TupleV<'s>(&'s [Schema]);

impl<'de> Visitor<'de> for TupleV<'_> {
    type Value = Model;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a tuple of {}", self.0.len())
    }
    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Model, A::Error> {
        let mut items = Vec::new();
        for (i, schema) in self.0.iter().enumerate() {
            let item = seq
                .next_element_seed(schema)?
                .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            items.push(item);
        }
        Ok(Model::Array(items))
    }
}

struct MapV<'s>(&'s Schema, &'s Schema);

impl<'de> Visitor<'de> for MapV<'_> {
    type Value = Model;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map")
    }
    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Model, A::Error> {
        let mut entries = Vec::new();
        while let Some(key) = map.next_key_seed(self.0)? {
            entries.push((key, map.next_value_seed(self.1)?));
        }
        Ok(Model::Map(entries))
    }
}

/// A struct's field name, or a variant's: its position among `names`, or
/// `None` for a field the struct does not declare.
struct Name(&'static [&'static str]);

impl<'de> DeserializeSeed<'de> for Name {
    type Value = Option<usize>;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Option<usize>, D::Error> {
        d.deserialize_identifier(self)
    }
}

impl<'de> Visitor<'de> for Name {
    type Value = Option<usize>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a name")
    }
    fn visit_str<E>(self, v: &str) -> Result<Option<usize>, E> {
        Ok(self.0.iter().position(|name| *name == v))
    }
}

struct StructV<'s>(&'s Fields);

impl<'de> Visitor<'de> for StructV<'_> {
    type Value = Model;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a struct")
    }
    fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Model, A::Error> {
        let fields = self.0;
        let mut values: Vec<Option<Model>> = fields.types.iter().map(|_| None).collect();
        while let Some(index) = map.next_key_seed(Name(fields.names))? {
            match index {
                Some(i) if values[i].is_some() => {
                    return Err(de::Error::duplicate_field(fields.names[i]));
                }
                Some(i) => values[i] = Some(map.next_value_seed(&fields.types[i])?),
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        let mut entries = Vec::new();
        for ((name, schema), value) in fields.names.iter().zip(&fields.types).zip(values) {
            let value = match (value, schema) {
                (Some(value), _) => value,
                (None, Schema::Option(_)) => Model::Null,
                (None, _) => return Err(de::Error::missing_field(name)),
            };
            entries.push(((*name).to_owned(), value));
        }
        Ok(Model::Object(entries))
    }
}

struct EnumV<'s>(&'s [Variant]);

impl<'de> Visitor<'de> for EnumV<'_> {
    type Value = Model;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an enum")
    }
    fn visit_enum<A: de::EnumAccess<'de>>(self, data: A) -> Result<Model, A::Error> {
        use de::VariantAccess;
        let names: Vec<&'static str> = self.0.iter().map(|v| v.name).collect();
        let names: &'static [&'static str] = Box::leak(names.into_boxed_slice());
        let (index, access) = data.variant_seed(Name(names))?;
        let Some(variant) = index.map(|i| &self.0[i]) else {
            return Err(de::Error::unknown_variant("", names));
        };
        let name = variant.name.to_owned();
        Ok(match &variant.kind {
            VariantKind::Unit => {
                access.unit_variant()?;
                Model::Text(name)
            }
            VariantKind::Newtype(schema) => {
                Model::Object(vec![(name, access.newtype_variant_seed(schema)?)])
            }
            VariantKind::Tuple(types) => Model::Object(vec![(
                name,
                access.tuple_variant(types.len(), TupleV(types))?,
            )]),
            VariantKind::Struct(fields) => Model::Object(vec![(
                name,
                access.struct_variant(fields.names, StructV(fields))?,
            )]),
        })
    }
}
