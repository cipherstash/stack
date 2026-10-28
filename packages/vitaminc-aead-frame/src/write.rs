//! The serde writer, shared by the transport format ([`serde`]) and the
//! storage profile ([`storage`]). One body of code writes both, and a
//! [`Profile`] says which, as it does for the reader.
//!
//! The two write alike but in three places:
//!
//! - A storage blob starts with its header. [`write`] writes the node
//!   alone, and [`storage::to_vec`] puts the header in front of it.
//! - A storage blob marks an `Option`'s `Some` with [`SOME`], a level of
//!   its own, so `Some(())` and `Some(None)` are not `None`. The transport
//!   writes what the `Some` holds, with no marker.
//! - A storage map is a [`MAP`], whose keys are nodes: an integer key keeps
//!   its width, and bytes stay bytes. A transport map is an object, whose
//!   keys are text: a key is written as its text, and a key that has none
//!   is refused.
//!
//! The writer writes straight into the caller's [`Buffer`]. A container's
//! count is patched in at its end, a map's keys are checked for a repeat
//! where they lie in the buffer, and a `Display` value is formatted into the
//! buffer itself, so no copy of a value is kept anywhere else.
//!
//! [`serde`]: crate::serde
//! [`storage`]: crate::storage
//! [`storage::to_vec`]: crate::storage::to_vec

use std::fmt;
use std::marker::PhantomData;
use std::ops::Range;

use ::serde::ser::{self, Serialize};
use vitaminc_aead::frame::{FrameWriteError, ARRAY, MAX_DEPTH, OBJECT};
use vitaminc_aead::leaf::{self, Form, ScalarError};
use vitaminc_aead::plaintext::{Float, Int, Physical};
use vitaminc_aead::tags;
use vitaminc_protected::{Buffer, Controlled};

use crate::serde::{At, Error, Profile, MAP, SOME};
use crate::storage::{distinct, Invalid, MapKey};

/// A [`Profile`] as a type, so the writer is compiled once for each
/// profile and the places they differ are settled at compile time. A
/// profile held at run time cost the storage writer about 5% on a
/// thousand records, from the extra field every writer carries and the
/// branches on it.
pub(crate) trait Profiled {
    const PROFILE: Profile;
}

/// The storage profile, for [`write`].
pub(crate) struct AsStorage;

impl Profiled for AsStorage {
    const PROFILE: Profile = Profile::Storage;
}

/// The transport format, for [`write`].
pub(crate) struct AsTransport;

impl Profiled for AsTransport {
    const PROFILE: Profile = Profile::Transport;
}

/// Write `value` as one node onto the end of `out`, as the profile `P`
/// writes it.
///
/// On an error, `out` holds whatever was written before it; the caller's
/// buffer is wiped when it is dropped.
pub(crate) fn write<P: Profiled, T: Serialize + ?Sized>(
    value: &T,
    out: &mut Buffer,
) -> Result<(), Error> {
    value.serialize(Writer::<P> {
        out,
        depth: 0,
        profile: PhantomData,
    })
}

fn written(error: FrameWriteError) -> Error {
    Error::new(error)
}

/// Appends formatted text to a buffer.
struct Appender<'o>(&'o mut Buffer);

impl fmt::Write for Appender<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

fn write_len(out: &mut Buffer, len: usize) -> Result<(), Error> {
    let len = u32::try_from(len).map_err(|_| written(FrameWriteError::TooLong))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

/// An object's key: a length, then UTF-8.
fn write_key(out: &mut Buffer, key: &str) -> Result<(), Error> {
    out.reserve(key.len().saturating_add(4));
    write_len(out, key.len())?;
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

fn write_scalar(out: &mut Buffer, value: Physical<'_>) -> Result<(), Error> {
    out.reserve(leaf::max_len(&value));
    leaf::write(None, value, Form::Frame, out).map_err(|e| {
        written(match e {
            ScalarError::Invalid => FrameWriteError::Invalid,
            // Text or bytes too long for a `u32` length: a plain scalar
            // has nothing else to refuse.
            _ => FrameWriteError::TooLong,
        })
    })
}

/// Write `value`'s `Display` as a text scalar. It is formatted straight
/// into the buffer, as serde's default would format it into a `String` of
/// its own and free it unwiped.
fn write_display<T: fmt::Display + ?Sized>(out: &mut Buffer, value: &T) -> Result<(), Error> {
    out.reserve(5);
    out.push(tags::STRING);
    write_display_text(out, value)
}

/// Write `value`'s `Display` as a length, then UTF-8: the body of a text
/// scalar, or an object's key. The length is patched in once the text is
/// written.
fn write_display_text<T: fmt::Display + ?Sized>(out: &mut Buffer, value: &T) -> Result<(), Error> {
    let at = out.len();
    out.extend_from_slice(&[0; 4]);
    fmt::write(&mut Appender(out), format_args!("{value}"))
        .map_err(|_| <Error as ser::Error>::custom(""))?;
    let len = out.len() - at - 4;
    let len = u32::try_from(len).map_err(|_| written(FrameWriteError::TooLong))?;
    out.overwrite(at, &len.to_le_bytes());
    Ok(())
}

/// Writes one node onto the end of a buffer, `depth` levels below its root.
struct Writer<'o, P> {
    out: &'o mut Buffer,
    depth: usize,
    profile: PhantomData<P>,
}

impl<'o, P: Profiled> Writer<'o, P> {
    fn check_depth(&self) -> Result<(), Error> {
        if self.depth > MAX_DEPTH {
            return Err(written(FrameWriteError::TooDeep));
        }
        Ok(())
    }

    fn scalar(self, value: Physical<'_>) -> Result<(), Error> {
        self.check_depth()?;
        write_scalar(self.out, value)
    }

    fn int(self, value: Int) -> Result<(), Error> {
        self.scalar(Physical::Int(value))
    }

    /// Open an array, an object or a map whose count is patched in at its
    /// end. `variant` is the enum variant whose payload it is, if any, so
    /// an error inside it is placed under the variant's name.
    fn container(
        self,
        tag: u8,
        expected: Option<usize>,
        variant: Option<&'static str>,
    ) -> Result<Container<'o, P>, Error> {
        self.check_depth()?;
        self.out.reserve(5);
        self.out.push(tag);
        let at = self.out.len();
        self.out.extend_from_slice(&[0; 4]);
        Ok(Container {
            out: self.out,
            depth: self.depth,
            profile: self.profile,
            at,
            n: 0,
            expected,
            variant,
            fields: FieldNames::default(),
        })
    }

    /// The object of one entry that holds a tuple or struct variant: its
    /// count and key are known, so they are written now, and the payload
    /// container is returned open, one level down.
    fn variant(
        self,
        variant: &'static str,
        tag: u8,
        len: usize,
    ) -> Result<Container<'o, P>, Error> {
        self.check_depth()?;
        self.out.reserve(5);
        self.out.push(OBJECT);
        self.out.extend_from_slice(&1u32.to_le_bytes());
        write_key(self.out, variant)?;
        // The transport has never checked a variant's payload against the
        // length its `Serialize` gave, and the storage profile always has.
        // Each keeps what it did, so a value one of them wrote before still
        // writes.
        let expected = match P::PROFILE {
            Profile::Storage => Some(len),
            Profile::Transport => None,
        };
        Writer {
            out: self.out,
            depth: self.depth + 1,
            profile: self.profile,
        }
        .container(tag, expected, Some(variant))
    }
}

/// How many of an object's field names are kept on the stack before the
/// rest go to the heap. Few types have more fields than this.
const INLINE_FIELDS: usize = 16;

/// The field names an object has written, to refuse a repeat. A derived
/// `Serialize` never repeats a name, but a hand-written one can. The names
/// are the type's own, never data, so keeping them copies nothing secret.
/// They are compared one by one: an object has too few for a hash set to
/// pay for its allocation and hashing.
#[derive(Default)]
struct FieldNames {
    inline: [&'static str; INLINE_FIELDS],
    len: usize,
    spilled: Vec<&'static str>,
}

impl FieldNames {
    /// Record `name`; whether it was new.
    fn insert(&mut self, name: &'static str) -> bool {
        let seen = self.inline[..self.len.min(INLINE_FIELDS)]
            .iter()
            .chain(&self.spilled)
            .any(|&known| known == name);
        if seen {
            return false;
        }
        if self.len < INLINE_FIELDS {
            self.inline[self.len] = name;
        } else {
            self.spilled.push(name);
        }
        self.len += 1;
        true
    }
}

/// An array, an object or a map being written.
struct Container<'o, P> {
    out: &'o mut Buffer,
    depth: usize,
    profile: PhantomData<P>,
    /// Where the count goes.
    at: usize,
    n: usize,
    expected: Option<usize>,
    variant: Option<&'static str>,
    /// An object's field names so far; an array writes none.
    fields: FieldNames,
}

impl<P: Profiled> Container<'_, P> {
    /// Write one child. `at` is where an error inside it is placed: an
    /// array's element by index, a struct's field by name, a map's entry
    /// by position only, so a key from the caller's map is never printed.
    fn child<T: Serialize + ?Sized>(&mut self, value: &T, at: At) -> Result<(), Error> {
        self.n += 1;
        value
            .serialize(Writer {
                out: &mut *self.out,
                depth: self.depth + 1,
                profile: self.profile,
            })
            .map_err(|e| {
                let e = e.at(at);
                match self.variant {
                    Some(variant) => e.at(At::Key(variant)),
                    None => e,
                }
            })
    }

    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let index = self.n;
        self.child(value, At::Index(index))
    }

    /// An object's entry: a field or variant name the type declares, then
    /// its value. A name the object has already written is refused.
    fn field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        if !self.fields.insert(key) {
            return Err(written(FrameWriteError::DuplicateKey));
        }
        write_key(self.out, key)?;
        self.child(value, At::Key(key))
    }

    fn end(self) -> Result<(), Error> {
        if self.expected.is_some_and(|e| e != self.n) {
            return Err(written(FrameWriteError::CountMismatch));
        }
        let n = u32::try_from(self.n).map_err(|_| written(FrameWriteError::TooLong))?;
        self.out.overwrite(self.at, &n.to_le_bytes());
        Ok(())
    }
}

/// A map being written. Each key is written the moment it is given, so no
/// copy of it is kept: only where it lies in the buffer, so that a repeat
/// is found among the keys when the map ends.
struct MapWriter<'o, P> {
    c: Container<'o, P>,
    /// Whether a key has been written whose value is next.
    pending: bool,
    /// Where each key lies in the buffer: a storage map's key node, or a
    /// transport object's key (its length, then its text).
    keys: Vec<Range<usize>>,
}

impl<'o, P: Profiled> ser::Serializer for Writer<'o, P> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Container<'o, P>;
    type SerializeTuple = Container<'o, P>;
    type SerializeTupleStruct = Container<'o, P>;
    type SerializeTupleVariant = Container<'o, P>;
    type SerializeMap = MapWriter<'o, P>;
    type SerializeStruct = Container<'o, P>;
    type SerializeStructVariant = Container<'o, P>;

    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        self.scalar(Physical::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        self.int(Int::I8(v))
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        self.int(Int::I16(v))
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        self.int(Int::I32(v))
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        self.int(Int::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        self.int(Int::I128(v))
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        self.int(Int::U8(v))
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        self.int(Int::U16(v))
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        self.int(Int::U32(v))
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        self.int(Int::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        self.int(Int::U128(v))
    }
    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        self.scalar(Physical::Float(Float::F32(v)))
    }
    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        self.scalar(Physical::Float(Float::F64(v)))
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut buf = [0u8; 4];
        self.scalar(Physical::Text(v.encode_utf8(&mut buf)))
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        self.scalar(Physical::Text(v))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        self.scalar(Physical::Bytes(v))
    }
    fn serialize_none(self) -> Result<(), Error> {
        self.scalar(Physical::Null)
    }
    /// The storage profile marks a `Some` with [`SOME`], a level of its
    /// own. The transport has no marker, and writes what it holds.
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        match P::PROFILE {
            Profile::Transport => value.serialize(self),
            Profile::Storage => {
                self.check_depth()?;
                self.out.push(SOME);
                value.serialize(Writer {
                    out: self.out,
                    depth: self.depth + 1,
                    profile: self.profile,
                })
            }
        }
    }
    fn serialize_unit(self) -> Result<(), Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.scalar(Physical::Text(variant))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        let mut object = self.container(OBJECT, Some(1), None)?;
        object.field(variant, value)?;
        object.end()
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Container<'o, P>, Error> {
        self.container(ARRAY, len, None)
    }
    fn serialize_tuple(self, len: usize) -> Result<Container<'o, P>, Error> {
        self.container(ARRAY, Some(len), None)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Container<'o, P>, Error> {
        self.container(ARRAY, Some(len), None)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Container<'o, P>, Error> {
        self.variant(variant, ARRAY, len)
    }
    /// A storage map is a [`MAP`], whose keys are nodes. A transport map is
    /// an object, whose keys are text.
    fn serialize_map(self, len: Option<usize>) -> Result<MapWriter<'o, P>, Error> {
        let tag = match P::PROFILE {
            Profile::Storage => MAP,
            Profile::Transport => OBJECT,
        };
        Ok(MapWriter {
            c: self.container(tag, len, None)?,
            pending: false,
            keys: Vec::with_capacity(len.unwrap_or(0)),
        })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Container<'o, P>, Error> {
        self.container(OBJECT, Some(len), None)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Container<'o, P>, Error> {
        self.variant(variant, OBJECT, len)
    }

    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), Error> {
        self.check_depth()?;
        write_display(self.out, value)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<P: Profiled> ser::SerializeSeq for Container<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl<P: Profiled> ser::SerializeTuple for Container<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl<P: Profiled> ser::SerializeTupleStruct for Container<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl<P: Profiled> ser::SerializeTupleVariant for Container<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl<P: Profiled> ser::SerializeStruct for Container<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl<P: Profiled> ser::SerializeStructVariant for Container<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl<P: Profiled> ser::SerializeMap for MapWriter<'_, P> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        // A second key would leave the first without a value.
        if self.pending {
            return Err(Error::new(
                "a map key was written before the previous value",
            ));
        }
        let index = self.c.n;
        let start = self.c.out.len();
        match P::PROFILE {
            Profile::Storage => key
                .serialize(KeyWriter(&mut *self.c.out))
                .map_err(|e| e.at(At::Entry(index)))?,
            // The transport has always placed a refused key at the map
            // itself, and its tests pin that path.
            Profile::Transport => key.serialize(TextKeyWriter(&mut *self.c.out))?,
        }
        self.keys.push(start..self.c.out.len());
        self.pending = true;
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        if !self.pending {
            return Err(Error::new("a map value was written before its key"));
        }
        self.pending = false;
        let index = self.c.n;
        self.c.child(value, At::Entry(index))
    }
    fn end(mut self) -> Result<(), Error> {
        if self.pending {
            return Err(Error::new("a map key was written without its value"));
        }
        // The buffer only grows while the map is written, so every range
        // still holds its key.
        let out: &[u8] = self.c.out.risky_ref();
        let repeated = match P::PROFILE {
            Profile::Storage => {
                match distinct(self.keys.iter().map(|range| MapKey(&out[range.clone()]))) {
                    Ok(()) => false,
                    Err(Invalid::DuplicateKey) => true,
                    // Every key was written by `KeyWriter`, which writes
                    // only the kinds a key may be.
                    Err(Invalid::Malformed) => unreachable!("a map key the writer wrote reads"),
                }
            }
            // A text key is its length and its bytes, so two are one key
            // exactly when they are byte for byte the same.
            Profile::Transport => {
                self.keys
                    .sort_unstable_by(|a, b| out[a.clone()].cmp(&out[b.clone()]));
                self.keys
                    .windows(2)
                    .any(|pair| out[pair[0].clone()] == out[pair[1].clone()])
            }
        };
        if repeated {
            return Err(written(FrameWriteError::DuplicateKey));
        }
        self.c.end()
    }
}

fn key_refused() -> Error {
    Error::new("a map key must be an integer, text or bytes")
}

/// Writes a storage map's key node: an integer, text or bytes. A `char` and
/// a unit variant's name are text, and a newtype struct is what it holds.
struct KeyWriter<'o>(&'o mut Buffer);

type NoKey = ser::Impossible<(), Error>;

impl ser::Serializer for KeyWriter<'_> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = NoKey;
    type SerializeTuple = NoKey;
    type SerializeTupleStruct = NoKey;
    type SerializeTupleVariant = NoKey;
    type SerializeMap = NoKey;
    type SerializeStruct = NoKey;
    type SerializeStructVariant = NoKey;

    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::I8(v)))
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::I16(v)))
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::I32(v)))
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::I64(v)))
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::I128(v)))
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::U8(v)))
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::U16(v)))
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::U32(v)))
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::U64(v)))
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        write_scalar(self.0, Physical::Int(Int::U128(v)))
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut buf = [0u8; 4];
        write_scalar(self.0, Physical::Text(v.encode_utf8(&mut buf)))
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        write_scalar(self.0, Physical::Text(v))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        write_scalar(self.0, Physical::Bytes(v))
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        write_scalar(self.0, Physical::Text(variant))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), Error> {
        write_display(self.0, value)
    }
    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, _v: bool) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_f32(self, _v: f32) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_f64(self, _v: f64) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_none(self) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), Error> {
        Err(key_refused())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<NoKey, Error> {
        Err(key_refused())
    }
    fn serialize_tuple(self, _len: usize) -> Result<NoKey, Error> {
        Err(key_refused())
    }
    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<NoKey, Error> {
        Err(key_refused())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<NoKey, Error> {
        Err(key_refused())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<NoKey, Error> {
        Err(key_refused())
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<NoKey, Error> {
        Err(key_refused())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<NoKey, Error> {
        Err(key_refused())
    }
}

fn key_not_text() -> Error {
    Error::new("a map key must be a string")
}

/// Writes a transport object's key: a length, then UTF-8. A key is text,
/// a `char` or a unit variant's name, a `Display` value's text, or a
/// newtype struct around one of those; any other key is refused.
///
/// It is human readable (serde's default), so a type with a text form and
/// a compact one, such as a `uuid::Uuid`, writes its text form. The 128-bit
/// integers keep serde's default refusal, as they always have here.
struct TextKeyWriter<'o>(&'o mut Buffer);

impl ser::Serializer for TextKeyWriter<'_> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = NoKey;
    type SerializeTuple = NoKey;
    type SerializeTupleStruct = NoKey;
    type SerializeTupleVariant = NoKey;
    type SerializeMap = NoKey;
    type SerializeStruct = NoKey;
    type SerializeStructVariant = NoKey;

    fn serialize_str(self, v: &str) -> Result<(), Error> {
        write_key(self.0, v)
    }
    /// Formatted straight into the buffer, as a value's `Display` is.
    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), Error> {
        write_display_text(self.0, value)
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut buf = [0u8; 4];
        write_key(self.0, v.encode_utf8(&mut buf))
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        write_key(self.0, variant)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }

    fn serialize_bool(self, _v: bool) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_i8(self, _v: i8) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_i16(self, _v: i16) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_i32(self, _v: i32) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_i64(self, _v: i64) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_u8(self, _v: u8) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_u16(self, _v: u16) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_u32(self, _v: u32) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_u64(self, _v: u64) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_f32(self, _v: f32) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_f64(self, _v: f64) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_none(self) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_unit(self) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), Error> {
        Err(key_not_text())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
    fn serialize_tuple(self, _len: usize) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<NoKey, Error> {
        Err(key_not_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written_as<P: Profiled, T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
        let mut out = Buffer::new();
        write::<P, T>(value, &mut out)?;
        Ok(out.risky_ref().to_vec())
    }

    /// Field names are kept on the stack until an object has more than
    /// fit there, and a repeat is found on either side of that line.
    #[test]
    fn field_names_spill_past_the_inline_ones() {
        const NAMES: [&str; INLINE_FIELDS + 2] = [
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
            "r",
        ];
        let mut fields = FieldNames::default();
        for name in NAMES {
            assert!(fields.insert(name), "{name} is new");
        }
        assert_eq!(
            fields.spilled,
            ["q", "r"],
            "the names past the inline ones spill"
        );
        assert!(!fields.insert("a"), "an inline name repeats");
        assert!(!fields.insert("r"), "a spilled name repeats");
        assert!(fields.insert("s"), "a new name is still new");
    }

    /// The profiles differ in an option's `Some` and in a map, and nowhere
    /// else: a struct, a sequence and a scalar are the same bytes in both.
    #[test]
    fn the_profiles_differ_only_in_some_and_maps() {
        let some = Some(1u8);
        assert_eq!(
            written_as::<AsStorage, _>(&some).expect("writes"),
            [SOME, tags::UINT8, 1],
            "storage marks a Some"
        );
        assert_eq!(
            written_as::<AsTransport, _>(&some).expect("writes"),
            [tags::UINT8, 1],
            "the transport writes what a Some holds"
        );

        let map = std::collections::BTreeMap::from([("k", 1u8)]);
        assert_eq!(
            written_as::<AsStorage, _>(&map).expect("writes"),
            [
                MAP,
                1,
                0,
                0,
                0,
                tags::STRING,
                1,
                0,
                0,
                0,
                b'k',
                tags::UINT8,
                1
            ],
            "a storage map's key is a node"
        );
        assert_eq!(
            written_as::<AsTransport, _>(&map).expect("writes"),
            [OBJECT, 1, 0, 0, 0, 1, 0, 0, 0, b'k', tags::UINT8, 1],
            "a transport map is an object whose key is text"
        );

        let same = (vec![1u8], "x", ());
        assert_eq!(
            written_as::<AsStorage, _>(&same).expect("writes"),
            written_as::<AsTransport, _>(&same).expect("writes"),
            "everything else is written alike"
        );
    }
}
