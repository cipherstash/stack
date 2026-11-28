//! Finds the kind of a value for an input error, without copying the value.
//!
//! An input error names the kind of value that the caller passed, as a
//! [`Found`]. This module reads that kind from three places:
//!
//! - A scalar, as a record source describes it ([`Found::scalar`]).
//! - A frame ([`Found::of_frame`]). A frame is the binary encoding of one
//!   value.
//! - One entry of a frame that is an object ([`Found::of_entry`]).
//!
//! The module also lists the keys of a frame that is an object
//! ([`object_keys`]).
//!
//! The code reads each value through vitaminc's [`Sink`] trait. A value
//! describes itself by calling the methods of a `Sink`. The two sinks in
//! this module are [`Probe`] and [`Lookup`]. Both sinks record the kind of
//! a value and the keys of an object. Neither sink copies any part of a
//! value.

use std::cell::{Cell, RefCell};

use vitaminc_aead::frame::{Frame, FrameWriteError};
use vitaminc_aead::plaintext::{
    Encrypt as _, EncryptRef, FixedType, Logical, MapSink, Physical, SeqSink, Sink, ValueKind,
};

use crate::refusal::Found;

impl Found {
    /// The kind of a scalar, from the logical type and the physical value
    /// that the scalar reports.
    ///
    /// The result is the scalar's [`ValueKind`], [`Found::Undefined`], or
    /// [`Found::Unknown`] for a logical type that this build does not
    /// define. A logical type can come with a physical value that the type
    /// does not allow, such as a date with a string value. The result is
    /// then the kind of the physical value, such as a null, a string, or an
    /// int32.
    pub(crate) fn scalar(logical: Option<Logical>, value: &Physical<'_>) -> Self {
        if let Some(kind) = ValueKind::of(logical, value) {
            return Self::Kind(kind);
        }
        match logical {
            Some(Logical::Undefined) => Self::Undefined,
            Some(Logical::Unknown(_)) => Self::Unknown,
            _ => ValueKind::of(None, value).map_or(Self::Null, Self::Kind),
        }
    }

    /// The kind of the value in a frame. Reads only the first node of the
    /// frame.
    pub(crate) fn of_frame(frame: Frame<'_>) -> Self {
        if let Some(kind) = frame.kind() {
            return Self::Kind(kind);
        }
        if frame.is_null() {
            return Self::Null;
        }
        // The frame is a passthrough, `undefined`, or a scalar of a logical
        // type that this build does not define. Each is one node. `Probe`
        // records the kind of the node and reads nothing inside it.
        let found = Cell::new(None);
        let _ = frame.visit(Probe::noting(&found, None));
        found.get().unwrap_or(Self::Unknown)
    }

    /// The kind of the value under `key` in a frame that is an object.
    ///
    /// When that value is an object too, the result also lists its keys, in
    /// order. For a value of any other kind, the list of keys is empty.
    ///
    /// Returns `None` when the frame is not an object, or has no entry
    /// under `key`.
    pub(crate) fn of_entry(frame: Frame<'_>, key: &str) -> Option<(Self, Vec<String>)> {
        let found = Cell::new(None);
        let keys = RefCell::new(Vec::new());
        let _ = frame.visit(Lookup {
            key,
            found: &found,
            keys: &keys,
        });
        found.get().map(|found| (found, keys.into_inner()))
    }
}

/// The keys of a frame that is an object, in order. Returns `None` when
/// the frame is not an object.
///
/// The function reads the frame with [`Probe`], and not with the serde
/// frame reader. The serde frame reader returns an error at a value that it
/// does not read. An example is a typed null: a null that records a type.
/// `Probe` reads every value, so the function returns every key.
pub(crate) fn object_keys(frame: Frame<'_>) -> Option<Vec<String>> {
    let found = Cell::new(None);
    let keys = RefCell::new(Vec::new());
    let _ = frame.visit(Probe::noting(&found, Some(&keys)));
    (found.get() == Some(Found::Kind(ValueKind::Object))).then(|| keys.into_inner())
}

/// A [`Sink`] that reads a value and copies no part of it.
///
/// - With `found` set, the probe stores the kind of the value there.
/// - With `keys` set, the probe adds the keys of the value there, when the
///   value is an object.
///
/// The probe reads the children of a list or an object with neither set.
/// So the probe records nothing about a value inside a container.
struct Probe<'c> {
    found: Option<&'c Cell<Option<Found>>>,
    keys: Option<&'c RefCell<Vec<String>>>,
}

impl<'c> Probe<'c> {
    /// A probe that stores the kind of the value in `found`. With `keys`
    /// given, the probe also stores the keys of an object there.
    fn noting(found: &'c Cell<Option<Found>>, keys: Option<&'c RefCell<Vec<String>>>) -> Self {
        Self {
            found: Some(found),
            keys,
        }
    }

    /// A probe that reads a value and records nothing.
    fn past() -> Self {
        Self {
            found: None,
            keys: None,
        }
    }

    fn note(&self, found: Found) {
        if let Some(cell) = self.found {
            cell.set(Some(found));
        }
    }
}

impl<'c> Sink for Probe<'c> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = Probe<'c>;
    type Map = Probe<'c>;

    fn scalar(self, logical: Option<Logical>, value: Physical<'_>) -> Result<(), FrameWriteError> {
        self.note(Found::scalar(logical, &value));
        Ok(())
    }

    fn typed_null(self, _: FixedType) -> Result<(), FrameWriteError> {
        self.note(Found::Null);
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Probe<'c>, FrameWriteError> {
        self.note(Found::Kind(ValueKind::Array));
        Ok(Probe::past())
    }

    fn map(self, _: Option<usize>) -> Result<Probe<'c>, FrameWriteError> {
        self.note(Found::Kind(ValueKind::Object));
        // The probe for the entries has the `keys` list, so that it records
        // each key.
        Ok(Probe {
            found: None,
            keys: self.keys,
        })
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), FrameWriteError> {
        self.note(Found::Passthrough);
        Ok(())
    }
}

impl<'c> SeqSink for Probe<'c> {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'e>
        = Probe<'c>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Probe<'c>, FrameWriteError> {
        Ok(Probe::past())
    }

    fn end(self) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

impl<'c> MapSink for Probe<'c> {
    type Ok = ();
    type Error = FrameWriteError;
    type Entry<'e>
        = Probe<'c>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Probe<'c>, FrameWriteError> {
        if let Some(keys) = self.keys {
            keys.borrow_mut().push(key.to_owned());
        }
        Ok(Probe::past())
    }

    fn end(self) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

/// A [`Sink`] for an object that records one entry: the entry under `key`.
///
/// The sink stores the kind of the value of that entry in `found`. When
/// the value is an object, the sink stores its keys in `keys`. The sink
/// reads every other entry and records nothing about it.
struct Lookup<'k, 'c> {
    key: &'k str,
    found: &'c Cell<Option<Found>>,
    keys: &'c RefCell<Vec<String>>,
}

impl<'k, 'c> Sink for Lookup<'k, 'c> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = Probe<'c>;
    type Map = Lookup<'k, 'c>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), FrameWriteError> {
        Ok(())
    }

    fn typed_null(self, _: FixedType) -> Result<(), FrameWriteError> {
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Probe<'c>, FrameWriteError> {
        Ok(Probe::past())
    }

    fn map(self, _: Option<usize>) -> Result<Self, FrameWriteError> {
        Ok(self)
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

impl<'c> MapSink for Lookup<'_, 'c> {
    type Ok = ();
    type Error = FrameWriteError;
    type Entry<'e>
        = Probe<'c>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<Probe<'c>, FrameWriteError> {
        if key == self.key {
            Ok(Probe::noting(self.found, Some(self.keys)))
        } else {
            Ok(Probe::past())
        }
    }

    fn end(self) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::plaintext::{Int, Raw};

    /// [`Found::scalar`] returns the kind of a scalar, `Undefined`, or
    /// `Unknown` for a logical type that this build does not define. For a
    /// known logical type with a physical value that the type does not
    /// allow, the result is the kind of the physical value. The result is
    /// never `Unknown`.
    #[test]
    fn a_scalar_is_named_by_what_it_is() {
        let unknown = Logical::from_wire(200, 0).expect("an unknown logical type");
        for (logical, value, want) in [
            (None, Physical::Null, Found::Null),
            (None, Physical::Text("x"), Found::Kind(ValueKind::String)),
            (
                Some(Logical::Date),
                Physical::Int(Int::I32(1)),
                Found::Kind(ValueKind::Date),
            ),
            (Some(Logical::Undefined), Physical::Null, Found::Undefined),
            (Some(unknown), Physical::Int(Int::U32(1)), Found::Unknown),
            (Some(Logical::Date), Physical::Null, Found::Null),
            (
                Some(Logical::Date),
                Physical::Text("x"),
                Found::Kind(ValueKind::String),
            ),
            (
                Some(Logical::Uuid),
                Physical::Int(Int::I64(1)),
                Found::Kind(ValueKind::Int64),
            ),
        ] {
            assert_eq!(
                Found::scalar(logical, &value),
                want,
                "{logical:?} over {value:?}"
            );
        }
    }

    /// The same rule applies through a record source. A row of a batch has
    /// the logical type date and a null value. `split_source` reports the
    /// row as a null, and not as `Unknown`.
    #[test]
    fn a_row_that_is_a_known_logical_over_a_null_is_a_null() {
        struct Rows;
        impl vitaminc_aead::plaintext::Encrypt for &Rows {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(1))?;
                Raw(Some(Logical::Date), Physical::Null).visit(seq.element()?)?;
                seq.end()
            }
        }
        let Ok(super::super::source::SplitSource::Batch(rows)) =
            super::super::source::split_source(&Rows)
        else {
            panic!("a batch");
        };
        assert!(
            matches!(rows.as_slice(), [Err(Found::Null)]),
            "the row is a null"
        );
    }
}
