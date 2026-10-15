//! Rust types as [`Plaintext`] sources.
//!
//! Byte strings (`Vec<u8>`, `[u8; N]`, `&[u8]`, `String`, `&str`) are byte
//! and text leaves, as they are for `Encrypt` today. For the same reason as
//! today, `u8` on its own is not a source: if it were, the generic `Vec<T>`
//! sequence impl would overlap the `Vec<u8>` byte leaf. An 8-bit value from
//! a host still arrives as [`Int::U8`]; a Rust caller that needs one uses
//! [`Raw`].

use std::collections::{BTreeMap, HashMap};

use vitaminc_protected::{Controlled, OpaqueDebug, Protected};
use zeroize::Zeroize;

use super::kinds::{Float, Logical, Physical};
use super::{visit_seq, MapSink, Plaintext, SeqSink, Sink};

macro_rules! int {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Plaintext for $ty {
                fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                    sink.scalar(None, Physical::Int(self.into()))
                }
            }

            impl Plaintext for &$ty {
                fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                    (*self).visit(sink)
                }
            }
        )*
    };
}

int!(i8, i16, i32, i64, i128, u16, u32, u64, u128);

impl Plaintext for bool {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bool(self))
    }
}

impl Plaintext for f32 {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Float(Float::F32(self)))
    }
}

impl Plaintext for f64 {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Float(Float::F64(self)))
    }
}

/// A borrowed copy scalar is the same scalar, so a borrowed container of
/// them (`&Vec<u32>`, `&[bool]`, `&Option<f64>`) is a source too.
macro_rules! by_ref {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Plaintext for &$ty {
                fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                    (*self).visit(sink)
                }
            }
        )*
    };
}

by_ref!(bool, f32, f64);

impl Plaintext for &str {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Text(self))
    }
}

/// An owned byte or text leaf wraps itself before the sink sees it, as its
/// `Encrypt` impl does today. So a bare leaf inside a `Protected` container,
/// which the container's default [`Plaintext::visit_protected`] hands over
/// unwrapped, still has its buffer wiped when the walk is done with it.
impl Plaintext for String {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        Self::visit_protected(Protected::new(self), sink)
    }

    fn visit_protected<S: Sink>(this: Protected<Self>, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Text(this.risky_ref()))
        // `this` drops and wipes here.
    }
}

impl Plaintext for &String {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Text(self))
    }
}

impl Plaintext for &[u8] {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(self))
    }
}

/// `Vec<u8>` is a byte leaf, not a sequence of `u8` elements: the same
/// shape `String` describes, and the shape `Vec<u8>` will read back.
impl Plaintext for Vec<u8> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        Self::visit_protected(Protected::new(self), sink)
    }

    fn visit_protected<S: Sink>(this: Protected<Self>, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(this.risky_ref()))
    }
}

impl<const N: usize> Plaintext for [u8; N] {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        Self::visit_protected(Protected::new(self), sink)
    }

    fn visit_protected<S: Sink>(this: Protected<Self>, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(this.risky_ref()))
    }
}

/// Borrowed byte leaves: the caller owns the buffer and its wiping.
impl Plaintext for &Vec<u8> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(self))
    }
}

impl<const N: usize> Plaintext for &[u8; N] {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(self))
    }
}

/// A byte string borrowed from anywhere, for callers holding a slice whose
/// element type would otherwise read as a sequence.
/// `Debug` is redacted, as for every plaintext scalar.
#[derive(Clone, Copy, OpaqueDebug)]
pub struct Bytes<'a>(pub &'a [u8]);

impl Plaintext for Bytes<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(None, Physical::Bytes(self.0))
    }
}

/// Any scalar, as given: a logical type and a physical value.
///
/// `Debug` is redacted, as for every plaintext scalar.
#[derive(Clone, Copy, OpaqueDebug)]
pub struct Raw<'a>(pub Option<Logical>, pub Physical<'a>);

impl Plaintext for Raw<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(self.0, self.1)
    }
}

/// `None` is a null. There is no separate "absent" in the data model, so a
/// host null and a Rust `None` are the same leaf.
impl<T: Plaintext> Plaintext for Option<T> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Some(v) => v.visit(sink),
            None => sink.scalar(None, Physical::Null),
        }
    }
}

impl<'a, T> Plaintext for &'a Option<T>
where
    &'a T: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Some(v) => v.visit(sink),
            None => sink.scalar(None, Physical::Null),
        }
    }
}

/// Goes through [`Plaintext::visit_protected`], so a byte leaf stays
/// wrapped until the sink has seen it.
impl<T: Plaintext + Zeroize> Plaintext for Protected<T> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        T::visit_protected(self, sink)
    }
}

/// An owned sequence takes its elements out one at a time, so a walk that
/// stops part way never drops an unvisited element bare.
///
/// Bare, the elements the walk did not reach are walked into a sink that
/// discards them before they drop, which wipes every owned leaf among them
/// the way a completed walk would. Inside a `Protected`, they stay in the
/// protected vector and are zeroized with it, along with the slots the
/// visited elements were moved out of.
impl<T: Plaintext> Plaintext for Vec<T> {
    fn visit<S: Sink>(mut self, sink: S) -> Result<S::Ok, S::Error> {
        let result = visit_popping(sink, &mut self);
        discard(self);
        result
    }

    fn visit_protected<S: Sink>(mut this: Protected<Self>, sink: S) -> Result<S::Ok, S::Error>
    where
        Self: Sized + Zeroize,
    {
        visit_popping(sink, this.risky_inner_mut())
        // `this` drops here and zeroizes what is left, and the whole buffer.
    }
}

/// Walk `items` in order, popping each element only once its sink exists,
/// so on an error every element not yet visited is still in `items`.
fn visit_popping<S: Sink, T: Plaintext>(sink: S, items: &mut Vec<T>) -> Result<S::Ok, S::Error> {
    items.reverse();
    let mut seq = sink.seq(Some(items.len()))?;
    for _ in 0..items.len() {
        let element = seq.element()?;
        if let Some(item) = items.pop() {
            item.visit(element)?;
        }
    }
    seq.end()
}

/// Visit each of `items` into [`Discard`], so the owned leaves among them
/// wrap themselves and are wiped as they drop.
fn discard<T: Plaintext>(items: Vec<T>) {
    for item in items {
        // `Discard` never fails, and a source error is no longer anyone's
        // concern once the walk has already failed.
        let _ = item.visit(Discard);
    }
}

/// A sink that keeps nothing. Walking a value into it runs the value's own
/// wiping without sending its contents anywhere.
struct Discard;

/// [`Discard`] never fails on its own; this only carries a source's error.
struct Discarded;

impl super::Error for Discarded {
    fn source(_: super::SourceError) -> Self {
        Discarded
    }
}

impl Sink for Discard {
    type Ok = ();
    type Error = Discarded;
    type Seq = Discard;
    type Map = Discard;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), Discarded> {
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Discard, Discarded> {
        Ok(Discard)
    }

    fn map(self, _: Option<usize>) -> Result<Discard, Discarded> {
        Ok(Discard)
    }

    /// Passthrough is cleartext by contract, so it is not walked.
    fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<(), Discarded> {
        Ok(())
    }
}

impl SeqSink for Discard {
    type Ok = ();
    type Error = Discarded;
    type Element<'s> = Discard;

    fn element(&mut self) -> Result<Discard, Discarded> {
        Ok(Discard)
    }

    fn end(self) -> Result<(), Discarded> {
        Ok(())
    }
}

impl MapSink for Discard {
    type Ok = ();
    type Error = Discarded;
    type Entry<'s> = Discard;

    fn entry(&mut self, _: &str) -> Result<Discard, Discarded> {
        Ok(Discard)
    }

    fn end(self) -> Result<(), Discarded> {
        Ok(())
    }
}

impl<'a, T> Plaintext for &'a Vec<T>
where
    &'a T: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        visit_seq(sink, Some(self.len()), self.iter())
    }
}

impl<'a, T> Plaintext for &'a [T]
where
    &'a T: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        visit_seq(sink, Some(self.len()), self.iter())
    }
}

/// One impl covers compile-time keys (`&'static str`) and runtime keys
/// (`String`), as the `Encrypt` impl does today.
impl<K: AsRef<str>, V: Plaintext> Plaintext for HashMap<K, V> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(self.len()))?;
        for (key, value) in self {
            value.visit(map.entry(key.as_ref())?)?;
        }
        map.end()
    }
}

impl<K: AsRef<str>, V: Plaintext> Plaintext for BTreeMap<K, V> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(self.len()))?;
        for (key, value) in self {
            value.visit(map.entry(key.as_ref())?)?;
        }
        map.end()
    }
}

impl<'a, K: AsRef<str>, V> Plaintext for &'a HashMap<K, V>
where
    &'a V: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(self.len()))?;
        for (key, value) in self {
            value.visit(map.entry(key.as_ref())?)?;
        }
        map.end()
    }
}

impl<'a, K: AsRef<str>, V> Plaintext for &'a BTreeMap<K, V>
where
    &'a V: Plaintext,
{
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(Some(self.len()))?;
        for (key, value) in self {
            value.visit(map.entry(key.as_ref())?)?;
        }
        map.end()
    }
}

// The chrono and rust_decimal types are logical types over an int. Each
// source says which, and the int it stands for.

#[cfg(feature = "chrono")]
mod chrono_sources {
    use super::*;
    use crate::plaintext::kinds::{chrono as conv, Int, TimeUnit};
    use crate::plaintext::{Error, SourceError};
    use ::chrono::{DateTime, NaiveDate, Utc};

    impl Plaintext for NaiveDate {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.scalar(
                Some(Logical::Date),
                Physical::Int(Int::I32(conv::date_days(self))),
            )
        }
    }

    /// Stored as nanoseconds, the unit of today's `TIMESTAMP` tag. A leap
    /// second has no count and stops the walk.
    impl Plaintext for DateTime<Utc> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let nanos = conv::timestamp_nanos(self).ok_or_else(|| {
                S::Error::source(SourceError::msg(
                    "a leap second has no count of nanoseconds",
                ))
            })?;
            sink.scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(nanos)),
            )
        }
    }

    impl Plaintext for &NaiveDate {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            (*self).visit(sink)
        }
    }

    impl Plaintext for &DateTime<Utc> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            (*self).visit(sink)
        }
    }
}

#[cfg(feature = "rust_decimal")]
impl Plaintext for rust_decimal::Decimal {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let (scale, mantissa) = super::kinds::decimal::parts(self);
        sink.scalar(
            Some(Logical::Decimal { scale }),
            Physical::Int(super::kinds::Int::I128(mantissa)),
        )
    }
}

#[cfg(feature = "rust_decimal")]
impl Plaintext for &rust_decimal::Decimal {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (*self).visit(sink)
    }
}

#[cfg(feature = "uuid")]
impl Plaintext for uuid::Uuid {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        sink.scalar(Some(Logical::Uuid), Physical::Bytes(self.as_bytes()))
    }
}

#[cfg(feature = "uuid")]
impl Plaintext for &uuid::Uuid {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (*self).visit(sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::kinds::Int;
    use crate::plaintext::record::{record, Event, Owned, RecordError};
    use crate::plaintext::{Error, SeqSink, SourceError};

    fn scalar(v: Owned) -> Event {
        Event::Scalar(None, v)
    }

    #[test]
    fn primitives_are_scalars() {
        assert_eq!(
            record(34u32).expect("ok"),
            [scalar(Owned::Int(Int::U32(34)))]
        );
        assert_eq!(record(-1i8).expect("ok"), [scalar(Owned::Int(Int::I8(-1)))]);
        assert_eq!(record(true).expect("ok"), [scalar(Owned::Bool(true))]);
        assert_eq!(
            record(1.5f64).expect("ok"),
            [scalar(Owned::Float(Float::F64(1.5)))]
        );
        assert_eq!(
            record("hi").expect("ok"),
            [scalar(Owned::Text("hi".into()))]
        );
        assert_eq!(
            record(String::from("hi")).expect("ok"),
            [scalar(Owned::Text("hi".into()))]
        );
    }

    // The borrows are the point: each one picks the reference impl.
    #[allow(clippy::needless_borrows_for_generic_args, clippy::op_ref)]
    #[test]
    fn floats_and_borrowed_scalars_are_scalars() {
        assert_eq!(
            record(1.5f32).expect("ok"),
            [scalar(Owned::Float(Float::F32(1.5)))]
        );
        assert_eq!(record(&1.5f32).expect("ok"), record(1.5f32).expect("ok"));
        assert_eq!(record(&1.5f64).expect("ok"), record(1.5f64).expect("ok"));
        assert_eq!(record(&true).expect("ok"), record(true).expect("ok"));
        assert_eq!(record(&7u64).expect("ok"), record(7u64).expect("ok"));
        let owned = String::from("hi");
        assert_eq!(
            record(&owned).expect("ok"),
            [scalar(Owned::Text("hi".into()))]
        );
    }

    #[test]
    fn a_source_error_keeps_its_cause() {
        use core::error::Error as _;

        #[derive(Debug)]
        struct Getter(std::io::Error);
        impl core::fmt::Display for Getter {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("getter threw")
            }
        }
        impl core::error::Error for Getter {
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let err = SourceError::new(Getter(std::io::Error::other("disk gone")));
        assert_eq!(err.to_string(), "getter threw");
        assert!(err.inner().is::<Getter>());
        assert_eq!(
            err.source().map(|cause| cause.to_string()),
            Some("disk gone".into())
        );
        assert!(SourceError::msg("plain").source().is_none());
    }

    #[test]
    fn byte_strings_are_byte_leaves_not_sequences() {
        assert_eq!(
            record(vec![1u8, 2]).expect("ok"),
            [scalar(Owned::Bytes(vec![1, 2]))]
        );
        assert_eq!(
            record([1u8, 2]).expect("ok"),
            [scalar(Owned::Bytes(vec![1, 2]))]
        );
        assert_eq!(
            record(&[1u8, 2][..]).expect("ok"),
            [scalar(Owned::Bytes(vec![1, 2]))]
        );
        assert_eq!(
            record(Bytes(&[9])).expect("ok"),
            [scalar(Owned::Bytes(vec![9]))]
        );
    }

    #[test]
    fn protected_leaves_reach_the_sink_still_wrapped() {
        // The sink sees the bytes; the only copy is inside `Protected`.
        assert_eq!(
            record(Protected::new(vec![1u8, 2])).expect("ok"),
            [scalar(Owned::Bytes(vec![1, 2]))]
        );
        assert_eq!(
            record(Protected::new(String::from("pw"))).expect("ok"),
            [scalar(Owned::Text("pw".into()))]
        );
        assert_eq!(
            record(Protected::new([7u8; 4])).expect("ok"),
            [scalar(Owned::Bytes(vec![7; 4]))]
        );
        // A composite takes the default path: unwrap, then walk.
        assert_eq!(
            record(Protected::new(vec![1u16, 2])).expect("ok"),
            [
                Event::Seq(Some(2)),
                Event::Element,
                scalar(Owned::Int(Int::U16(1))),
                Event::Element,
                scalar(Owned::Int(Int::U16(2))),
                Event::EndSeq,
            ]
        );
    }

    /// A leaf that wraps itself the way the byte leaves do, and counts
    /// its wipes, so a test can see whether a container's protected path
    /// reaches it.
    #[derive(Clone, Default)]
    struct Counted(std::rc::Rc<std::cell::Cell<usize>>);

    impl Zeroize for Counted {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    impl Plaintext for Counted {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            Self::visit_protected(Protected::new(self), sink)
        }

        fn visit_protected<S: Sink>(_this: Protected<Self>, sink: S) -> Result<S::Ok, S::Error> {
            sink.scalar(None, Physical::Null)
        }
    }

    #[test]
    fn a_protected_container_wipes_each_leaf() {
        let wipes = Counted::default();
        record(Protected::new(vec![wipes.clone(), wipes.clone()])).expect("ok");
        assert_eq!(wipes.0.get(), 2);

        let wipes = Counted::default();
        record(Protected::new(Some(wipes.clone()))).expect("ok");
        assert_eq!(wipes.0.get(), 1);
    }

    /// A leaf that counts its wipes but does not wrap itself when visited,
    /// so only zeroizing the container it sits in can wipe it.
    #[derive(Clone, Default)]
    struct Tracked(std::rc::Rc<std::cell::Cell<usize>>);

    impl Zeroize for Tracked {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    impl Plaintext for Tracked {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.scalar(None, Physical::Null)
        }
    }

    /// A sink that hands out `elements` element sinks in all, across every
    /// sequence in the walk, and fails on the next one.
    struct StopAfter(std::rc::Rc<std::cell::Cell<usize>>);

    impl StopAfter {
        fn new(elements: usize) -> Self {
            Self(std::rc::Rc::new(std::cell::Cell::new(elements)))
        }
    }

    impl Sink for StopAfter {
        type Ok = ();
        type Error = RecordError;
        type Seq = Self;
        type Map = Self;

        fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), RecordError> {
            Ok(())
        }

        fn seq(self, _: Option<usize>) -> Result<Self, RecordError> {
            Ok(self)
        }

        fn map(self, _: Option<usize>) -> Result<Self, RecordError> {
            Ok(self)
        }

        fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<(), RecordError> {
            Ok(())
        }
    }

    impl SeqSink for StopAfter {
        type Ok = ();
        type Error = RecordError;
        type Element<'s> = Self;

        fn element(&mut self) -> Result<Self, RecordError> {
            match self.0.get() {
                0 => Err(RecordError("stopped".into())),
                left => {
                    self.0.set(left - 1);
                    Ok(Self(self.0.clone()))
                }
            }
        }

        fn end(self) -> Result<(), RecordError> {
            Ok(())
        }
    }

    impl MapSink for StopAfter {
        type Ok = ();
        type Error = RecordError;
        type Entry<'s> = Self;

        fn entry(&mut self, _: &str) -> Result<Self, RecordError> {
            Ok(Self(self.0.clone()))
        }

        fn end(self) -> Result<(), RecordError> {
            Ok(())
        }
    }

    #[test]
    fn a_protected_vec_zeroizes_what_a_failed_walk_did_not_reach() {
        // One element is visited, then the sink fails. The two left over
        // are still inside the `Protected` and are zeroized with it.
        let wipes = Tracked::default();
        let items = Protected::new(vec![wipes.clone(), wipes.clone(), wipes.clone()]);
        items.visit(StopAfter::new(1)).expect_err("should stop");
        assert_eq!(wipes.0.get(), 2);

        // A failure before the first element leaves everything protected.
        let wipes = Tracked::default();
        let items = Protected::new(vec![wipes.clone(), wipes.clone()]);
        items.visit(StopAfter::new(0)).expect_err("should stop");
        assert_eq!(wipes.0.get(), 2);
    }

    #[test]
    fn a_protected_vec_wipes_every_leaf_when_the_walk_fails() {
        // The first leaf wipes itself as it is visited; the other two are
        // zeroized with the vector.
        let wipes = Counted::default();
        let items = Protected::new(vec![wipes.clone(), wipes.clone(), wipes.clone()]);
        items.visit(StopAfter::new(1)).expect_err("should stop");
        assert_eq!(wipes.0.get(), 3);
    }

    #[test]
    fn a_failed_walk_still_wipes_the_owned_leaves_it_did_not_reach() {
        // Bare, the leaves the walk did not reach are walked into a
        // discarding sink, which wipes them as a finished walk would.
        let wipes = Counted::default();
        let items = vec![wipes.clone(), wipes.clone(), wipes.clone()];
        items.visit(StopAfter::new(1)).expect_err("should stop");
        assert_eq!(wipes.0.get(), 3);

        // Nested in a protected vector, the inner vector is walked bare
        // once taken out, and fails after its first element.
        let wipes = Counted::default();
        let items = Protected::new(vec![vec![wipes.clone(), wipes.clone(), wipes.clone()]]);
        items.visit(StopAfter::new(2)).expect_err("should stop");
        assert_eq!(wipes.0.get(), 3);
    }

    #[test]
    fn discarding_walks_every_kind_of_node() {
        // Containers, scalars and passthrough all go to the discarding
        // sink without failing.
        let mut map = BTreeMap::new();
        map.insert("k", vec![String::from("v")]);
        assert!(map.visit(Discard).is_ok());
        assert!(Failing.visit(Discard).is_err());
        assert!(Discard.passthrough(1u32).is_ok());
        assert!(Discard.map(None).and_then(MapSink::end).is_ok());
    }

    // The borrows are the point: each one picks the reference impl.
    #[allow(clippy::needless_borrows_for_generic_args)]
    #[test]
    fn borrowed_containers_are_sources() {
        let ints = vec![1u32, 2];
        assert_eq!(
            record(&ints).expect("ok"),
            record(ints.clone()).expect("ok")
        );
        assert_eq!(record(&ints[..]).expect("ok"), record(ints).expect("ok"));
        assert_eq!(
            record(&vec![true]).expect("ok"),
            record(vec![true]).expect("ok")
        );
        assert_eq!(
            record(&Some(1.5f64)).expect("ok"),
            record(Some(1.5f64)).expect("ok")
        );
        assert_eq!(record(&None::<i8>).expect("ok"), [scalar(Owned::Null)]);
        // A borrowed `Vec<u8>` is still a byte leaf, not a sequence.
        assert_eq!(
            record(&vec![1u8, 2]).expect("ok"),
            [scalar(Owned::Bytes(vec![1, 2]))]
        );
        assert_eq!(
            record(&[1u8, 2]).expect("ok"),
            [scalar(Owned::Bytes(vec![1, 2]))]
        );
        let mut hash = HashMap::new();
        hash.insert(String::from("k"), vec![String::from("v")]);
        let borrowed = record(&hash).expect("ok");
        assert_eq!(borrowed, record(hash).expect("ok"));
        let mut tree = BTreeMap::new();
        tree.insert("a", 1i64);
        tree.insert("b", 2i64);
        let borrowed = record(&tree).expect("ok");
        assert_eq!(borrowed, record(tree).expect("ok"));
    }

    #[test]
    fn option_none_is_null() {
        assert_eq!(record(None::<u32>).expect("ok"), [scalar(Owned::Null)]);
        assert_eq!(
            record(Some(1u32)).expect("ok"),
            [scalar(Owned::Int(Int::U32(1)))]
        );
    }

    #[test]
    fn containers_push_each_child_into_its_own_sink() {
        let mut map = BTreeMap::new();
        map.insert("a", vec![1i32]);
        map.insert("b", vec![]);
        assert_eq!(
            record(map).expect("ok"),
            [
                Event::Map(Some(2)),
                Event::Entry("a".into()),
                Event::Seq(Some(1)),
                Event::Element,
                scalar(Owned::Int(Int::I32(1))),
                Event::EndSeq,
                Event::Entry("b".into()),
                Event::Seq(Some(0)),
                Event::EndSeq,
                Event::EndMap,
            ]
        );
        let mut hash = HashMap::new();
        hash.insert(String::from("k"), 2u64);
        assert_eq!(
            record(hash).expect("ok"),
            [
                Event::Map(Some(1)),
                Event::Entry("k".into()),
                scalar(Owned::Int(Int::U64(2))),
                Event::EndMap,
            ]
        );
    }

    #[test]
    fn raw_passes_the_logical_type_through() {
        assert_eq!(
            record(Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 16]))).expect("ok"),
            [Event::Scalar(
                Some(Logical::Uuid),
                Owned::Bytes(vec![0; 16])
            )]
        );
    }

    /// A source that fails part way through, as a host getter might.
    struct Failing;

    impl Plaintext for Failing {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut seq = sink.seq(None)?;
            1u32.visit(seq.element()?)?;
            Err(S::Error::source(SourceError::msg("getter threw")))
        }
    }

    #[test]
    fn a_source_can_stop_the_walk_with_its_own_error() {
        let err = record(Failing).expect_err("should fail");
        assert_eq!(err.0, "getter threw");
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_types_are_logical_types_over_an_int() {
        use crate::plaintext::kinds::TimeUnit;
        use ::chrono::{DateTime, NaiveDate};
        let date = NaiveDate::from_ymd_opt(2000, 3, 1).expect("ok");
        assert_eq!(
            record(date).expect("ok"),
            [Event::Scalar(
                Some(Logical::Date),
                Owned::Int(Int::I32(11_017))
            )]
        );
        let ts = DateTime::from_timestamp(1, 5).expect("ok");
        assert_eq!(
            record(ts).expect("ok"),
            [Event::Scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Owned::Int(Int::I128(1_000_000_005))
            )]
        );
        let leap = NaiveDate::from_ymd_opt(2016, 12, 31)
            .expect("ok")
            .and_hms_nano_opt(23, 59, 59, 1_500_000_000)
            .expect("ok")
            .and_utc();
        assert_eq!(
            record(leap).expect_err("should fail").0,
            "a leap second has no count of nanoseconds"
        );
    }

    // The borrows are the point: each one picks the reference impl.
    #[allow(clippy::needless_borrows_for_generic_args)]
    #[cfg(all(feature = "chrono", feature = "rust_decimal", feature = "uuid"))]
    #[test]
    fn borrowed_logical_sources_walk_as_the_owned_ones() {
        let date = ::chrono::NaiveDate::from_ymd_opt(2000, 3, 1).expect("ok");
        assert_eq!(record(&date).expect("ok"), record(date).expect("ok"));
        let ts = ::chrono::DateTime::from_timestamp(1, 5).expect("ok");
        assert_eq!(record(&ts).expect("ok"), record(ts).expect("ok"));
        let d: rust_decimal::Decimal = "-1.50".parse().expect("ok");
        assert_eq!(record(&d).expect("ok"), record(d).expect("ok"));
        let id = uuid::Uuid::from_bytes([3; 16]);
        assert_eq!(record(&id).expect("ok"), record(id).expect("ok"));
    }

    #[cfg(feature = "rust_decimal")]
    #[test]
    fn decimal_is_a_scale_and_a_mantissa() {
        let d: rust_decimal::Decimal = "1.50".parse().expect("ok");
        assert_eq!(
            record(d).expect("ok"),
            [Event::Scalar(
                Some(Logical::Decimal { scale: 2 }),
                Owned::Int(Int::I128(150))
            )]
        );
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn uuid_is_sixteen_bytes() {
        let id = uuid::Uuid::from_bytes([3; 16]);
        assert_eq!(
            record(id).expect("ok"),
            [Event::Scalar(
                Some(Logical::Uuid),
                Owned::Bytes(vec![3; 16])
            )]
        );
    }
}
