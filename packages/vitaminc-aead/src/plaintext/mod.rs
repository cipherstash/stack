//! The plaintext data model: a source describes itself once ([`Plaintext`])
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
//! code implements `Plaintext`, usually by derive.

pub mod kinds;
mod sources;
mod tee;

use core::fmt;

use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

pub use kinds::{Float, Int, Logical, Physical, TimeUnit, UnknownLogical};
pub use sources::{Bytes, Raw};
pub use tee::Tee;

/// A value that can describe itself to a [`Sink`].
///
/// Implemented by Rust primitives and containers, by the optional chrono,
/// `rust_decimal` and uuid types, and by host bindings for their own values.
/// A struct implements it by walking its fields into a map; that is what
/// `#[derive(Plaintext)]` will generate.
pub trait Plaintext {
    /// Describe `self` to `sink`, consuming it.
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error>;

    /// Describe a `Protected<Self>` without exposing the inner value.
    ///
    /// This is the seam the blanket `impl Plaintext for Protected<T>` goes
    /// through. The default unwraps `this` and defers to [`visit`], which is
    /// right for composite types: each field re-wraps itself before it
    /// reaches a sink, so the only bare value is the container being taken
    /// apart. Byte leaves (`Vec<u8>`, `[u8; N]`, `String`) override it to
    /// hand the sink a borrow of the still-wrapped value, so the bytes are
    /// wiped when `this` drops.
    ///
    /// [`visit`]: Plaintext::visit
    fn visit_protected<S: Sink>(this: Protected<Self>, sink: S) -> Result<S::Ok, S::Error>
    where
        Self: Sized + Zeroize,
    {
        this.risky_unwrap().visit(sink)
    }
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
#[derive(Debug)]
pub struct SourceError(Box<dyn std::error::Error + Send + Sync>);

impl SourceError {
    /// A source error from any error type.
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }

    /// A source error from a message.
    pub fn msg(msg: impl Into<String>) -> Self {
        Self(msg.into().into())
    }

    /// The underlying error.
    pub fn inner(&self) -> &(dyn std::error::Error + Send + Sync) {
        &*self.0
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SourceError {}

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
    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<Self::Ok, Self::Error>;
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
    I::Item: Plaintext,
{
    let mut seq = sink.seq(len)?;
    for item in items {
        item.visit(seq.element()?)?;
    }
    seq.end()
}

/// Walk each `(key, value)` into its own entry sink: the loop every map
/// source writes.
pub fn visit_map<'k, S, I, P>(sink: S, len: Option<usize>, entries: I) -> Result<S::Ok, S::Error>
where
    S: Sink,
    I: IntoIterator<Item = (&'k str, P)>,
    P: Plaintext,
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

        fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<(), RecordError> {
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
    pub fn record<P: Plaintext>(p: P) -> Result<Vec<Event>, RecordError> {
        let mut log = Vec::new();
        p.visit(Record(&mut log))?;
        Ok(log)
    }
}
