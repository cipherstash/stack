//! Splits the value a caller asks to encrypt into one value per field.
//!
//! A language SDK hands the engine a record as one value: a map from field
//! names to values, such as `{"email": "a@example.com", "age": 34}`. The
//! SDK can also hand over a batch: a sequence of such maps. The engine
//! encrypts each field on its own, with that field's settings from the
//! plan, so the engine first needs each field's value separately.
//!
//! [`split_source`] reads the value once, from start to end. As the split
//! reaches each field, it writes that field's value into an
//! [`OwnedFrame`] of its own. The split copies nothing else.
//!
//! The result has one entry for each record:
//!
//! * A map is one record. The record keeps its fields in the order the
//!   value lists them. A field name that appears twice is kept twice.
//! * A sequence is a batch. Each element of the sequence is one record.
//! * Anything else is not a record: a single value, a null, a passthrough
//!   value, or a sequence inside a batch. The entry for that value is the
//!   kind of value it is ([`Found`]). Nothing inside the value is copied or
//!   checked.
//!
//! This module does not compare the fields with the plan. The caller,
//! `record::source_rows`, refuses a value that is not a record, a missing
//! field, an extra field, and a value of the wrong type.
//!
//! [`split_source`] fails when the frame writer refuses a field's value,
//! such as a date out of range or a map that repeats a key, or when the
//! source fails to describe itself, such as a host getter that throws. The
//! error names the field whose value was being written, and the row of a
//! batch, so the caller can report where it happened. A source that fails
//! outside any field's value names no field.

use std::cell::{Cell, RefCell};

use vitaminc_aead::frame::{FrameWriteError, FrameWriter, OwnedFrame};
use vitaminc_aead::plaintext::{
    Encrypt, EncryptRef, FixedType, Logical, MapSink, Physical, SeqSink, Sink, ValueKind,
};
use vitaminc_protected::Buffer;

use crate::refusal::Found;

/// One record's fields, each name with its value in a frame of its own, in
/// the order the source lists them. The kind of value the source gave
/// instead, when it is not a map, so is not a record.
pub(super) type SourceRecord = Result<Vec<(String, OwnedFrame)>, Found>;

/// A source split by [`split_source`]: one record, or a batch of them.
pub(super) enum SplitSource {
    /// The source was a map, or a value that is not a record.
    One(SourceRecord),
    /// The source was a sequence. Each element is one record.
    Batch(Vec<SourceRecord>),
}

/// Why [`split_source`] failed: the error from the frame writer, or the
/// source's own, the row of a batch the split was in, and the field whose
/// value it was writing, if it was writing one.
#[derive(Debug)]
pub(super) struct SplitRefusal {
    pub(super) row: Option<usize>,
    pub(super) field: Option<String>,
    pub(super) error: FrameWriteError,
}

/// Split a source into its records, writing each field's value into a
/// frame of its own. The [module documentation](self) says what counts as
/// a record and when the split fails.
pub(super) fn split_source<P: Encrypt>(source: P) -> Result<SplitSource, SplitRefusal> {
    let place = Place::default();
    source.visit(TopSink(&place)).map_err(|error| SplitRefusal {
        row: place.row.get(),
        field: place.field.take(),
        error,
    })
}

/// Where the split is: the row of a batch it began last, and the field
/// whose value it is writing. Shared by every sink in a split. Field names
/// are not secret: the plan and the stored record both contain them
/// unencrypted. So the name is not wiped.
#[derive(Default)]
struct Place {
    row: Cell<Option<usize>>,
    field: RefCell<Option<String>>,
}

/// The place shared by every sink in a split.
type Open<'f> = &'f Place;

/// Where a finished record goes: returned to the caller, or added to a
/// batch.
trait PutRecord {
    type Ok;
    fn put(self, record: SourceRecord) -> Self::Ok;
}

/// The top of a source: the record is the result.
struct TopRecord;

impl PutRecord for TopRecord {
    type Ok = SplitSource;
    fn put(self, record: SourceRecord) -> SplitSource {
        SplitSource::One(record)
    }
}

/// The next record of a batch.
struct BatchRecord<'s>(&'s mut Vec<SourceRecord>);

impl PutRecord for BatchRecord<'_> {
    type Ok = ();
    fn put(self, record: SourceRecord) {
        self.0.push(record);
    }
}

/// The top of a source.
struct TopSink<'f>(Open<'f>);

impl<'f> Sink for TopSink<'f> {
    type Ok = SplitSource;
    type Error = FrameWriteError;
    type Seq = BatchSink<'f>;
    type Map = RecordMap<'f, TopRecord>;

    fn scalar(
        self,
        logical: Option<Logical>,
        value: Physical<'_>,
    ) -> Result<SplitSource, FrameWriteError> {
        Ok(SplitSource::One(Err(Found::scalar(logical, &value))))
    }

    fn typed_null(self, _: FixedType) -> Result<SplitSource, FrameWriteError> {
        Ok(SplitSource::One(Err(Found::Null)))
    }

    fn seq(self, _: Option<usize>) -> Result<BatchSink<'f>, FrameWriteError> {
        Ok(BatchSink {
            open: self.0,
            records: Vec::new(),
        })
    }

    fn map(self, _: Option<usize>) -> Result<RecordMap<'f, TopRecord>, FrameWriteError> {
        Ok(RecordMap::new(self.0, TopRecord))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<SplitSource, FrameWriteError> {
        Ok(SplitSource::One(Err(Found::Passthrough)))
    }
}

/// A batch: one record for each element.
struct BatchSink<'f> {
    open: Open<'f>,
    records: Vec<SourceRecord>,
}

impl<'f> SeqSink for BatchSink<'f> {
    type Ok = SplitSource;
    type Error = FrameWriteError;
    type Element<'s>
        = ElementSink<'f, 's>
    where
        Self: 's;

    fn element(&mut self) -> Result<ElementSink<'f, '_>, FrameWriteError> {
        self.open.row.set(Some(self.records.len()));
        Ok(ElementSink {
            open: self.open,
            record: BatchRecord(&mut self.records),
        })
    }

    fn end(self) -> Result<SplitSource, FrameWriteError> {
        Ok(SplitSource::Batch(self.records))
    }
}

/// One element of a batch. A map is a record. Anything else is not a
/// record, and the sink reads past its content.
struct ElementSink<'f, 's> {
    open: Open<'f>,
    record: BatchRecord<'s>,
}

impl<'f, 's> Sink for ElementSink<'f, 's> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = NotARecord<'s>;
    type Map = RecordMap<'f, BatchRecord<'s>>;

    fn scalar(self, logical: Option<Logical>, value: Physical<'_>) -> Result<(), FrameWriteError> {
        self.record.put(Err(Found::scalar(logical, &value)));
        Ok(())
    }

    fn typed_null(self, _: FixedType) -> Result<(), FrameWriteError> {
        self.record.put(Err(Found::Null));
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<NotARecord<'s>, FrameWriteError> {
        Ok(NotARecord {
            record: self.record,
        })
    }

    fn map(self, _: Option<usize>) -> Result<RecordMap<'f, BatchRecord<'s>>, FrameWriteError> {
        Ok(RecordMap::new(self.open, self.record))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), FrameWriteError> {
        self.record.put(Err(Found::Passthrough));
        Ok(())
    }
}

/// A batch element that is a sequence, so is not a record. The source still
/// describes its elements, and [`Discard`] reads past them without copying
/// them. When the sequence ends, the batch notes that it was an array.
struct NotARecord<'s> {
    record: BatchRecord<'s>,
}

impl SeqSink for NotARecord<'_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'e>
        = Discard
    where
        Self: 'e;

    fn element(&mut self) -> Result<Discard, FrameWriteError> {
        Ok(Discard)
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.record.put(Err(Found::Kind(ValueKind::Array)));
        Ok(())
    }
}

/// A sink that keeps nothing: it reads past a value that is not a record,
/// so none of the value's plaintext is copied.
struct Discard;

impl Sink for Discard {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = Discard;
    type Map = Discard;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), FrameWriteError> {
        Ok(())
    }

    fn typed_null(self, _: FixedType) -> Result<(), FrameWriteError> {
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<Discard, FrameWriteError> {
        Ok(Discard)
    }

    fn map(self, _: Option<usize>) -> Result<Discard, FrameWriteError> {
        Ok(Discard)
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

impl SeqSink for Discard {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'e>
        = Discard
    where
        Self: 'e;

    fn element(&mut self) -> Result<Discard, FrameWriteError> {
        Ok(Discard)
    }

    fn end(self) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

impl MapSink for Discard {
    type Ok = ();
    type Error = FrameWriteError;
    type Entry<'e>
        = Discard
    where
        Self: 'e;

    fn entry(&mut self, _: &str) -> Result<Discard, FrameWriteError> {
        Ok(Discard)
    }

    fn end(self) -> Result<(), FrameWriteError> {
        Ok(())
    }
}

/// One record's fields, each value written into its own frame.
struct RecordMap<'f, O> {
    open: Open<'f>,
    out: O,
    // The keys are field names. Field names are not secret, so they are
    // not wiped.
    entries: Vec<(String, Buffer)>,
}

impl<'f, O> RecordMap<'f, O> {
    fn new(open: Open<'f>, out: O) -> Self {
        Self {
            open,
            out,
            entries: Vec::new(),
        }
    }
}

impl<O: PutRecord> MapSink for RecordMap<'_, O> {
    type Ok = O::Ok;
    type Error = FrameWriteError;
    type Entry<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_>, FrameWriteError> {
        *self.open.field.borrow_mut() = Some(key.to_owned());
        self.entries.push((key.to_owned(), Buffer::new()));
        let buffer = match self.entries.last_mut() {
            Some((_, buffer)) => buffer,
            // Pushed on the line above.
            None => unreachable!(),
        };
        Ok(FrameWriter::new(buffer))
    }

    fn end(self) -> Result<O::Ok, FrameWriteError> {
        // The record's values are written: a failure after this is not one
        // of its fields'.
        *self.open.field.borrow_mut() = None;
        let mut record = Vec::with_capacity(self.entries.len());
        for (key, buffer) in self.entries {
            // A source that dropped an entry's sink without writing to it
            // left no frame.
            let value = OwnedFrame::from_buffer(buffer).map_err(|_| {
                *self.open.field.borrow_mut() = Some(key.clone());
                FrameWriteError::Unwritten
            })?;
            record.push((key, value));
        }
        Ok(self.out.put(Ok(record)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;
    use vitaminc_aead::frame::{Frame, ARRAY};
    use vitaminc_aead::plaintext::{Int, Raw, SourceError, Width};

    fn s(value: &str) -> Tree {
        Tree::String(value.into())
    }

    fn obj(entries: Vec<(&str, Tree)>) -> Tree {
        Tree::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// A record's fields as their frames' bytes, in source order, or what
    /// the value was instead of a record.
    fn bytes(record: &SourceRecord) -> Result<Vec<(String, Vec<u8>)>, Found> {
        record.as_ref().map_err(|found| *found).map(|entries| {
            entries
                .iter()
                .map(|(key, value)| (key.clone(), value.frame().as_bytes().to_vec()))
                .collect()
        })
    }

    fn owned(value: &Tree) -> Vec<u8> {
        OwnedFrame::of(value)
            .expect("in the model")
            .frame()
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn a_map_is_one_record_of_its_fields_frames_in_order_with_a_repeat_kept() {
        // A frame holds no repeated key, so the source is the tree itself.
        let source = obj(vec![
            ("b", Tree::UInt32(7)),
            ("a", obj(vec![("k", s("v"))])),
            ("b", Tree::Passthrough(Box::new(s("p")))),
        ]);
        let Ok(SplitSource::One(record)) = split_source(&source) else {
            panic!("one record");
        };
        assert_eq!(
            bytes(&record),
            Ok(vec![
                ("b".to_owned(), owned(&Tree::UInt32(7))),
                ("a".to_owned(), owned(&obj(vec![("k", s("v"))]))),
                ("b".to_owned(), owned(&Tree::Passthrough(Box::new(s("p"))))),
            ]),
            "each field's frame, in source order"
        );
    }

    /// A value that is not a map is not a record: the split notes what
    /// kind of value it is, at the top or as an element of a batch.
    #[test]
    fn a_sequence_is_a_batch_and_what_is_not_a_map_is_not_a_record() {
        let ty = FixedType::new(Some(Logical::Date), Width::I32).expect("fixed");
        let source = Tree::Array(vec![
            obj(vec![("a", Tree::Int32(1))]),
            s("x"),
            Tree::Array(vec![s("y"), obj(vec![("k", Tree::Null)])]),
            Tree::Passthrough(Box::new(obj(vec![]))),
            obj(vec![]),
            Tree::Null,
            Tree::Undefined,
            Tree::UInt32(7),
        ]);
        let Ok(SplitSource::Batch(records)) = split_source(&source) else {
            panic!("a batch");
        };
        let records: Vec<_> = records.iter().map(bytes).collect();
        assert_eq!(
            records,
            [
                Ok(vec![("a".to_owned(), owned(&Tree::Int32(1)))]),
                Err(Found::Kind(ValueKind::String)),
                Err(Found::Kind(ValueKind::Array)),
                Err(Found::Passthrough),
                Ok(vec![]),
                Err(Found::Null),
                Err(Found::Undefined),
                Err(Found::Kind(ValueKind::UInt32)),
            ],
            "a record per map, and the kind of every other element"
        );
        for (top, found) in [
            (s("x"), Found::Kind(ValueKind::String)),
            (Tree::Null, Found::Null),
            (Tree::Passthrough(Box::new(obj(vec![]))), Found::Passthrough),
        ] {
            assert!(
                matches!(split_source(&top), Ok(SplitSource::One(Err(kind))) if kind == found),
                "{found:?} at the top is not a record"
            );
        }

        // A typed null, at the top or as a batch element, is a null.
        let mut one = Vec::new();
        vitaminc_aead::leaf::write_typed_null(ty, &mut one);
        let top = Frame::parse(&one).expect("a frame");
        assert!(
            matches!(split_source(top), Ok(SplitSource::One(Err(Found::Null)))),
            "a typed null at the top is a null"
        );
        let mut batch = vec![ARRAY, 2, 0, 0, 0];
        batch.extend(&one);
        batch.extend(&one);
        let batch = Frame::parse(&batch).expect("a frame");
        assert!(
            matches!(
                split_source(batch),
                Ok(SplitSource::Batch(records))
                    if records.len() == 2 && records.iter().all(|r| matches!(r, Err(Found::Null)))
            ),
            "a typed null in a batch is a null"
        );
    }

    /// A refusal names the field whose value the writer refused, and the
    /// row of a batch it is in.
    #[test]
    fn a_refusal_names_the_field_and_row_being_written() {
        let refused = |source: &Tree| split_source(source).err().expect("refused");
        let bad_date = Tree::Typed(Logical::Date, Box::new(Tree::Int64(i64::MAX)));

        let one = refused(&obj(vec![
            ("ok", Tree::Int32(1)),
            ("when", bad_date.clone()),
        ]));
        assert_eq!(one.field.as_deref(), Some("when"), "the field refused");
        assert_eq!(one.row, None, "a single record has no row");
        assert!(
            matches!(one.error, FrameWriteError::Invalid),
            "{:?}",
            one.error
        );

        let batch = refused(&Tree::Array(vec![
            obj(vec![("when", Tree::Int32(1))]),
            obj(vec![("at", Tree::Array(vec![bad_date.clone()]))]),
        ]));
        assert_eq!(batch.field.as_deref(), Some("at"), "the field refused");
        assert_eq!(batch.row, Some(1), "the second row");

        let repeated = refused(&obj(vec![(
            "doc",
            obj(vec![("k", Tree::Null), ("k", Tree::Null)]),
        )]));
        assert_eq!(repeated.field.as_deref(), Some("doc"), "the field refused");
        assert!(
            matches!(repeated.error, FrameWriteError::DuplicateKey),
            "{:?}",
            repeated.error
        );

        // A batch element that is not a record is read past, not written:
        // a value inside it that no frame could hold is not refused here.
        // The caller refuses the element itself, as not a record.
        let Ok(SplitSource::Batch(records)) = split_source(Tree::Array(vec![
            obj(vec![("a", Tree::Int32(1))]),
            Tree::Array(vec![bad_date]),
        ])) else {
            panic!("a batch");
        };
        assert!(
            matches!(
                records.as_slice(),
                [Ok(_), Err(Found::Kind(ValueKind::Array))]
            ),
            "the second element is an array"
        );
    }

    /// A source that fails as it describes itself keeps its own error, and
    /// the split names the field and the row it was reading. A failure
    /// after a record's fields are written names no field.
    #[test]
    fn a_source_failure_names_the_field_and_row_it_was_reading() {
        /// Describes a batch of `rows` records of one field `a`, and fails
        /// in the last one: inside `a`'s value, or after the record ends.
        struct Fails {
            rows: usize,
            after_the_record: bool,
        }
        impl Encrypt for &Fails {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let fail = || {
                    <S::Error as vitaminc_aead::plaintext::Error>::source(SourceError::msg(
                        "getter threw",
                    ))
                };
                let mut seq = sink.seq(Some(self.rows))?;
                for row in 0..self.rows {
                    let mut map = seq.element()?.map(Some(1))?;
                    let entry = map.entry("a")?;
                    if row + 1 < self.rows || self.after_the_record {
                        Raw(None, Physical::Int(Int::I32(1))).visit(entry)?;
                        map.end()?;
                    } else {
                        return Err(fail());
                    }
                }
                Err(fail())
            }
        }

        let failed = split_source(&Fails {
            rows: 3,
            after_the_record: false,
        })
        .err()
        .expect("refused");
        assert!(
            matches!(&failed.error, FrameWriteError::Source(cause) if cause.to_string() == "getter threw"),
            "the source's own error is kept: {:?}",
            failed.error
        );
        assert_eq!(failed.field.as_deref(), Some("a"), "the field being read");
        assert_eq!(failed.row, Some(2), "the row being read");

        let after = split_source(&Fails {
            rows: 2,
            after_the_record: true,
        })
        .err()
        .expect("refused");
        assert!(
            matches!(after.error, FrameWriteError::Source(_)),
            "{:?}",
            after.error
        );
        assert_eq!(after.field, None, "no field is being read");
        assert_eq!(after.row, Some(1), "the last row begun");
    }

    /// An entry whose sink the source dropped unwritten has no frame: the
    /// record is refused, naming it.
    #[test]
    fn an_unwritten_entry_is_refused_naming_it() {
        struct DropsAnEntry;
        impl Encrypt for &DropsAnEntry {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(None)?;
                let _ = map.entry("dropped")?;
                Raw(None, Physical::Int(Int::I32(1))).visit(map.entry("kept")?)?;
                map.end()
            }
        }
        let refused = split_source(&DropsAnEntry).err().expect("refused");
        assert_eq!(
            refused.field.as_deref(),
            Some("dropped"),
            "the dropped entry"
        );
        assert!(
            matches!(refused.error, FrameWriteError::Unwritten),
            "{:?}",
            refused.error
        );
    }
}
