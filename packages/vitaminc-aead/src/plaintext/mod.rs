//! The plaintext data model: a source describes itself once ([`Encrypt`])
//! to a consumer ([`Sink`]), the way serde splits `Serialize` from
//! `Serializer`.
//!
//! - **Containers are push-style.** [`SeqSink::element`] returns a sink for
//!   the next element rather than taking the element as a value, so the
//!   source drives the whole walk and any number of sinks can share it
//!   (see [`Tee`]).
//! - **Sources can fail.** Every sink error implements [`Error`], so a
//!   source can stop the walk with [`Error::source`] without knowing which
//!   sink it is feeding. That is what lets a native binding walk a live host
//!   object, where a getter can throw, without taking a snapshot first.
//! - **Lengths are optional,** for host iterables that do not know their
//!   size.
//! - **A scalar is a physical value plus an optional logical type.** One
//!   [`Sink::scalar`] method takes a [`Physical`] value and an optional
//!   [`Logical`] type, rather than a method per kind. See [`kinds`].
//!
//! `Sink` is implemented inside vitaminc and its host bindings. Application
//! code implements `Encrypt`, usually by derive.

pub mod depth;
pub mod kinds;
mod path;
mod sources;
mod tee;

pub use kinds::{
    Float, Int, Kind, KnownLogical, Logical, Physical, TimeUnit, UnknownLogical, UnknownLogicalId,
};
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use path::render;
pub use path::{Path, Step};
pub use sources::{Bytes, Raw};

/// What `#[derive(Encrypt)]`'s expansion needs by path. Not an API.
#[doc(hidden)]
pub mod __private {
    pub use super::sources::discard_one;
}
pub use tee::Tee;

/// A value that can describe itself to a [`Sink`].
///
/// Implemented by Rust primitives and containers, by the optional chrono,
/// `rust_decimal` and uuid types, and by host bindings for their own values.
/// A struct implements it by walking its fields into a map, which is what
/// `#[derive(Encrypt)]` generates.
///
/// `Encrypt` and [`Decrypt`](crate::Decrypt) are the pair a type implements
/// to say how it is encrypted and decrypted. Neither does any cryptography:
/// that is the [`Cipher`](crate::Cipher)'s job, and the same walk also
/// feeds sinks that are not ciphers, such as equality terms and the
/// transport frame. This trait replaces the visitor-based `Encrypt` of
/// vitaminc 0.5, which drove a cipher directly.
///
/// # Owned values and `Protected`
///
/// A source implements `Encrypt` for `T` and for `&T`. The by-value walk
/// consumes the value; the borrowed walk hands the sink borrows of what
/// the value holds and leaves it where it is. `Protected<T>` walks as a
/// borrow of what it wraps, so nothing leaves the wrapper during the walk
/// and everything in it, visited or not, is zeroized when it drops. That
/// is why a type that is to sit inside a `Protected`, a derived struct
/// included, needs the borrowed impl; the derive generates it.
///
/// An owned byte or text leaf (`String`, `Vec<u8>`, `[u8; N]`) wraps itself
/// in a `Protected` before the sink sees it, so its buffer is wiped however
/// it arrives. A bare container that is walked by value and stops part way
/// discards the children it did not reach through their own walks, so
/// their owned leaves are wiped too rather than dropped bare. A
/// hand-written leaf that owns a secret buffer should wrap itself the same
/// way, and a hand-written container should not drop unvisited children
/// bare.
pub trait Encrypt {
    /// How deep a value of this type can nest below its own root, when the
    /// type alone fixes it: `Some(0)` for a scalar, one more than its
    /// deepest child for a sequence or map (see [`depth`]). `None`, the
    /// default, when it depends on the value: a recursive type, a frame, a
    /// live host value.
    ///
    /// `#[derive(Encrypt)]` works this out from the fields' depths and fails
    /// to compile a type deeper than [`MAX_DEPTH`](crate::frame::MAX_DEPTH),
    /// whose fully populated values the encrypting sink would always
    /// refuse. A hand-written impl may leave it `None`, which skips the
    /// check for every type that contains it; the walk still refuses a
    /// value that is too deep. It must never be more than the deepest a
    /// value of the type can nest, or a type that is fine fails to compile.
    const DEPTH: Option<usize> = None;

    /// Describe `self` to `sink`, consuming it.
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error>;
}

/// Every sink's error type.
///
/// A source reports its own failure through [`source`](Error::source),
/// without knowing which sink it is feeding.
pub trait Error: Sized {
    /// Wrap a failure that came from the source, not the sink.
    fn source(error: SourceError) -> Self;
}

/// A failure reading the source: a host getter threw, a string had an
/// unpaired surrogate, a big integer was out of range, a timestamp was a
/// leap second.
///
/// Transparent: it displays as the wrapped error, and its `source()` is the
/// wrapped error's, so a reporter that walks the chain sees what lies behind
/// a failed getter.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SourceError(Box<dyn core::error::Error + Send + Sync>);

impl SourceError {
    /// A source error from any error type.
    pub fn new(error: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }

    /// A source error from a message.
    pub fn msg(msg: impl Into<String>) -> Self {
        Self(msg.into().into())
    }

    /// The underlying error, which can be downcast to its concrete type.
    pub fn inner(&self) -> &(dyn core::error::Error + Send + Sync + 'static) {
        &*self.0
    }
}

/// A consumer of one value's description.
///
/// A sink is used once: each method takes `self`. Containers hand back a
/// [`SeqSink`] or [`MapSink`] that produces one child sink per element or
/// entry.
pub trait Sink: Sized {
    /// What the sink produces when the walk ends.
    type Ok;
    /// The sink's error, which can also carry a [`SourceError`].
    type Error: Error;
    /// The sink for a sequence's elements.
    type Seq: SeqSink<Ok = Self::Ok, Error = Self::Error>;
    /// The sink for a map's entries.
    type Map: MapSink<Ok = Self::Ok, Error = Self::Error>;

    /// One scalar: a physical value, and the logical type it represents,
    /// if any. See [`kinds`].
    ///
    /// # Examples
    ///
    /// A plain value has no logical type. A value that means something
    /// more names the type it is stored as, and the sink checks that the
    /// physical value fits it ([`Logical::admits`]).
    ///
    /// ```
    /// use vitaminc_aead::plaintext::{Int, Logical, Physical, Encrypt, Sink};
    ///
    /// struct Celsius(i32);
    ///
    /// impl Encrypt for Celsius {
    ///     fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
    ///         sink.scalar(None, Physical::Int(Int::I32(self.0)))
    ///     }
    /// }
    ///
    /// /// Days since 1970-01-01.
    /// struct Day(i32);
    ///
    /// impl Encrypt for Day {
    ///     fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
    ///         sink.scalar(Some(Logical::Date), Physical::Int(Int::I32(self.0)))
    ///     }
    /// }
    /// ```
    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Self::Ok, Self::Error>;

    /// Start a sequence. `len` is a hint; a source that does not know its
    /// length passes `None`.
    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error>;

    /// Start a map with string keys. `len` is a hint.
    fn map(self, len: Option<usize>) -> Result<Self::Map, Self::Error>;

    /// A subtree that travels in the clear. It is walked like anything
    /// else; the sink decides what "in the clear" means for it.
    ///
    /// The value is `Clone` so that a sink which is really several sinks
    /// (see [`Tee`]) can give the subtree to each of them. Passthrough is
    /// non-sensitive by contract, so the copy carries no secret.
    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<Self::Ok, Self::Error>;
}

/// The sink for a sequence's elements.
pub trait SeqSink: Sized {
    type Ok;
    type Error: Error;
    /// A sink for one element. It borrows the sequence sink and writes
    /// into it; its own `Ok` is incidental.
    type Element<'s>: Sink<Error = Self::Error>
    where
        Self: 's;

    /// A sink for the next element.
    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error>;

    /// Finish the sequence.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// The sink for a map's entries. Keys are strings and travel in the clear.
pub trait MapSink: Sized {
    type Ok;
    type Error: Error;
    /// A sink for one entry's value.
    type Entry<'s>: Sink<Error = Self::Error>
    where
        Self: 's;

    /// A sink for the value under `key`.
    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error>;

    /// Finish the map.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Walk each item into its own element sink: the loop every sequence
/// source writes.
pub fn visit_seq<S, I>(sink: S, len: Option<usize>, items: I) -> Result<S::Ok, S::Error>
where
    S: Sink,
    I: IntoIterator,
    I::Item: Encrypt,
{
    let mut seq = sink.seq(len)?;
    for item in items {
        item.visit(seq.element()?)?;
    }
    seq.end()
}

/// Walk each `(key, value)` into its own entry sink: the loop every map
/// source writes.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use vitaminc_aead::plaintext::{visit_map, Encrypt, Sink};
///
/// struct Scores(BTreeMap<String, u32>);
///
/// impl Encrypt for Scores {
///     fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
///         let len = Some(self.0.len());
///         visit_map(sink, len, self.0.iter().map(|(name, score)| (name.as_str(), *score)))
///     }
/// }
/// ```
pub fn visit_map<'k, S, I, P>(sink: S, len: Option<usize>, entries: I) -> Result<S::Ok, S::Error>
where
    S: Sink,
    I: IntoIterator<Item = (&'k str, P)>,
    P: Encrypt,
{
    let mut map = sink.map(len)?;
    for (key, value) in entries {
        value.visit(map.entry(key)?)?;
    }
    map.end()
}

#[cfg(test)]
pub(crate) mod record {
    //! A sink that records every call, for tests of sources and of sinks
    //! that forward to other sinks.

    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Event {
        Scalar(Option<Logical>, Owned),
        Seq(Option<usize>),
        Element,
        EndSeq,
        Map(Option<usize>),
        Entry(String),
        EndMap,
        Passthrough,
    }

    /// An owned copy of a physical value, so a recording can outlive the
    /// borrow a source handed over.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Owned {
        Null,
        Bool(bool),
        Int(Int),
        Float(Float),
        Text(String),
        Bytes(Vec<u8>),
    }

    impl From<Physical<'_>> for Owned {
        fn from(v: Physical<'_>) -> Self {
            match v {
                Physical::Null => Owned::Null,
                Physical::Bool(b) => Owned::Bool(b),
                Physical::Int(i) => Owned::Int(i),
                Physical::Float(f) => Owned::Float(f),
                Physical::Text(s) => Owned::Text(s.to_owned()),
                Physical::Bytes(b) => Owned::Bytes(b.to_vec()),
            }
        }
    }

    #[derive(Debug)]
    pub struct RecordError(pub String);

    impl Error for RecordError {
        fn source(error: SourceError) -> Self {
            Self(error.to_string())
        }
    }

    /// Records into a shared log. `Ok` is `()`.
    pub struct Record<'l>(pub &'l mut Vec<Event>);

    impl Sink for Record<'_> {
        type Ok = ();
        type Error = RecordError;
        type Seq = Self;
        type Map = Self;

        fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), RecordError> {
            self.0.push(Event::Scalar(ty, value.into()));
            Ok(())
        }

        fn seq(self, len: Option<usize>) -> Result<Self, RecordError> {
            self.0.push(Event::Seq(len));
            Ok(self)
        }

        fn map(self, len: Option<usize>) -> Result<Self, RecordError> {
            self.0.push(Event::Map(len));
            Ok(self)
        }

        fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), RecordError> {
            self.0.push(Event::Passthrough);
            value.visit(Record(self.0))
        }
    }

    impl SeqSink for Record<'_> {
        type Ok = ();
        type Error = RecordError;
        type Element<'s>
            = Record<'s>
        where
            Self: 's;

        fn element(&mut self) -> Result<Record<'_>, RecordError> {
            self.0.push(Event::Element);
            Ok(Record(self.0))
        }

        fn end(self) -> Result<(), RecordError> {
            self.0.push(Event::EndSeq);
            Ok(())
        }
    }

    impl MapSink for Record<'_> {
        type Ok = ();
        type Error = RecordError;
        type Entry<'s>
            = Record<'s>
        where
            Self: 's;

        fn entry(&mut self, key: &str) -> Result<Record<'_>, RecordError> {
            self.0.push(Event::Entry(key.to_owned()));
            Ok(Record(self.0))
        }

        fn end(self) -> Result<(), RecordError> {
            self.0.push(Event::EndMap);
            Ok(())
        }
    }

    /// Walk `p` and return what a sink would have seen.
    pub fn record<P: Encrypt>(p: P) -> Result<Vec<Event>, RecordError> {
        let mut log = Vec::new();
        p.visit(Record(&mut log))?;
        Ok(log)
    }
}
