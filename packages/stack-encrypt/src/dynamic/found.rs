//! What a value an input error is about is, read from the value itself:
//! [`Found`] for a scalar a source describes, a frame, or one entry of an
//! object frame, and the keys of an object frame. The sinks here read past
//! every value and copy none of it.

use std::cell::{Cell, RefCell};

use vitaminc_aead::frame::{Frame, FrameWriteError};
use vitaminc_aead::plaintext::{
    Encrypt as _, EncryptRef, FixedType, Logical, MapSink, Physical, SeqSink, Sink, ValueKind,
};

use crate::refusal::Found;

impl Found {
    /// What a scalar is, from how it describes itself: its kind, or
    /// `undefined`, or a logical type this build does not know. A logical
    /// type over a value it does not admit is named by the value's own
    /// physical kind, as null, a string, an int32 and so on.
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

    /// What a frame holds, reading no more of it than its first node.
    pub(crate) fn of_frame(frame: Frame<'_>) -> Self {
        if let Some(kind) = frame.kind() {
            return Self::Kind(kind);
        }
        if frame.is_null() {
            return Self::Null;
        }
        // A passthrough, `undefined` or a logical type this build does not
        // know: one node, which the probe reads without walking inside it.
        let found = Cell::new(None);
        let _ = frame.visit(Probe::noting(&found, None));
        found.get().unwrap_or(Self::Unknown)
    }

    /// What the entry under `key` holds, for a frame that is an object with
    /// one, and the entry's own keys, in order, when it is an object too.
    /// `None` for a frame that is not an object or has no such key.
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

/// The keys of an object frame, in order; `None` for a frame that is not an
/// object. Read with the probe, so a value the frame reader refuses to read,
/// such as a typed null, does not hide the keys beside it.
pub(crate) fn object_keys(frame: Frame<'_>) -> Option<Vec<String>> {
    let found = Cell::new(None);
    let keys = RefCell::new(Vec::new());
    let _ = frame.visit(Probe::noting(&found, Some(&keys)));
    (found.get() == Some(Found::Kind(ValueKind::Object))).then(|| keys.into_inner())
}

/// A sink that reads past a value and keeps none of it: where it is given
/// a cell, it notes what kind of value the node is, and where it is given
/// a list, the keys of an object it is. Children are read past with
/// neither, so nothing inside a container is noted, and no value is copied.
struct Probe<'c> {
    found: Option<&'c Cell<Option<Found>>>,
    keys: Option<&'c RefCell<Vec<String>>>,
}

impl<'c> Probe<'c> {
    /// A probe that notes the node's kind, and its keys if `keys` is given.
    fn noting(found: &'c Cell<Option<Found>>, keys: Option<&'c RefCell<Vec<String>>>) -> Self {
        Self {
            found: Some(found),
            keys,
        }
    }

    /// A probe that reads past a node and notes nothing.
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
        // The map's entries are read with the keys list, to note their keys.
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

/// A sink that notes what kind of value one entry of an object is, and its
/// keys if it is an object, and reads past everything else.
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

    /// A scalar is named by its kind, `undefined`, or a logical type this
    /// build does not know. A known logical type over a value it does not
    /// admit is named by the value's own physical kind, never as unknown.
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

    /// Through a record source: a batch row that is a date over a null is
    /// a null, not a value of a type this build does not know.
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
