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
//!   kind of the value, as a [`Found`]. Nothing inside the value is copied
//!   or checked.
//!
//! This module does not compare the fields with the plan. The caller,
//! `record::source_rows`, refuses a value that is not a record, a missing
//! field, an extra field, and a value of the wrong type.
//!
//! [`split_source`] returns an error in two cases:
//!
//! * The split cannot write a field's value into a frame. Examples are a
//!   date out of range, and a map that repeats a key.
//! * The value returns an error of its own while the split reads it. An
//!   example is a property getter in the caller's language that throws.
//!
//! The error names the row of a batch and the field whose value the split
//! was writing. So the caller can report where the error happened. An
//! error that happens outside the value of any field names no field.

use std::cell::{Cell, RefCell};

use vitaminc_aead::frame::{FrameMap, FrameSeq, FrameWriteError, FrameWriter, OwnedFrame};
use vitaminc_aead::plaintext::{
    Encrypt, EncryptRef, FixedType, Logical, MapSink, Physical, SeqSink, Sink, ValueKind,
};
use vitaminc_protected::Buffer;

use crate::refusal::Found;

/// One entry of the result: a record, or the kind of a value that is not
/// a record.
///
/// `Ok` contains the fields of one record, in the order the source lists
/// them. Each field is a name and a value. Each value is in a frame of its
/// own. `Err` contains the kind of a value that is not a map, so is not a
/// record.
pub(super) type SourceRecord = Result<Vec<(String, OwnedFrame)>, Found>;

/// A source split by [`split_source`]: one record, or a batch of them.
pub(super) enum SplitSource {
    /// The source was a map, or a value that is not a record.
    One(SourceRecord),
    /// The source was a sequence. Each element is one record.
    Batch(Vec<SourceRecord>),
}

/// Why [`split_source`] failed, and where.
///
/// - `error` is the error from [`FrameWriter`], or the error that the
///   source returned. `FrameWriter` writes a value into a frame.
/// - `row` is the position of the row that the split was reading, counted
///   from 0. `None` when the source is not a batch, or the split was
///   between two rows.
/// - `field` is the field whose value the split was writing. `None` when
///   the split was not writing the value of a field.
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

/// The current position of the split in the source.
///
/// `row` is the row of a batch that the split is reading. `field` is the
/// field whose value the split is writing.
///
/// The split sets each one when the source starts it, and clears it when
/// the source finishes it. So an error between two rows names no row, and
/// an error between two fields names no field. Every sink in one split
/// shares one `Place`.
///
/// Field names are not secret. The plan and the stored record both contain
/// them unencrypted. So the code does not wipe the name.
#[derive(Default)]
struct Place {
    row: Cell<Option<usize>>,
    field: RefCell<Option<String>>,
}

impl Place {
    /// Clears the field, because the source has finished writing its value.
    fn field_done(&self) {
        *self.field.borrow_mut() = None;
    }
}

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

/// The next record of a batch. [`put`](PutRecord::put) adds the record to
/// the batch and clears the row in [`Place`], because the row is finished.
struct BatchRecord<'s> {
    records: &'s mut Vec<SourceRecord>,
    place: &'s Place,
}

impl PutRecord for BatchRecord<'_> {
    type Ok = ();
    fn put(self, record: SourceRecord) {
        self.records.push(record);
        self.place.row.set(None);
    }
}

/// The top of a source.
struct TopSink<'f>(&'f Place);

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
            place: self.0,
            records: Vec::new(),
            begun: 0,
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
///
/// `begun` counts the elements that the source started. A source can start
/// an element and then drop its sink without writing a value. That element
/// leaves no record, so every later row would move up one position. The
/// split returns an error for that batch instead
/// ([`check_written`](Self::check_written)).
struct BatchSink<'f> {
    place: &'f Place,
    records: Vec<SourceRecord>,
    begun: usize,
}

impl BatchSink<'_> {
    /// Returns an error when the last element that the source started left
    /// no record, because the source dropped its sink without writing a
    /// value. The error names the row of that element.
    fn check_written(&self) -> Result<(), FrameWriteError> {
        if self.records.len() == self.begun {
            return Ok(());
        }
        self.place.row.set(Some(self.records.len()));
        Err(FrameWriteError::Unwritten)
    }
}

impl<'f> SeqSink for BatchSink<'f> {
    type Ok = SplitSource;
    type Error = FrameWriteError;
    type Element<'s>
        = ElementSink<'f, 's>
    where
        Self: 's;

    fn element(&mut self) -> Result<ElementSink<'f, '_>, FrameWriteError> {
        self.check_written()?;
        self.place.row.set(Some(self.begun));
        self.begun += 1;
        Ok(ElementSink {
            place: self.place,
            record: BatchRecord {
                records: &mut self.records,
                place: self.place,
            },
        })
    }

    fn end(self) -> Result<SplitSource, FrameWriteError> {
        self.check_written()?;
        Ok(SplitSource::Batch(self.records))
    }
}

/// One element of a batch. A map is a record. Anything else is not a
/// record, and the sink reads past its content.
struct ElementSink<'f, 's> {
    place: &'f Place,
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
        Ok(RecordMap::new(self.place, self.record))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), FrameWriteError> {
        self.record.put(Err(Found::Passthrough));
        Ok(())
    }
}

/// A batch element that is a sequence, so is not a record. The source still
/// describes its elements, and [`Discard`] reads past them without copying
/// them. When the sequence ends, the batch records that the element was an
/// array.
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
    place: &'f Place,
    out: O,
    // The keys are field names. Field names are not secret, so they are
    // not wiped.
    entries: Vec<(String, Buffer)>,
}

impl<'f, O> RecordMap<'f, O> {
    fn new(place: &'f Place, out: O) -> Self {
        Self {
            place,
            out,
            entries: Vec::new(),
        }
    }
}

impl<'f, O: PutRecord> MapSink for RecordMap<'f, O> {
    type Ok = O::Ok;
    type Error = FrameWriteError;
    type Entry<'s>
        = FieldWriter<'s, 'f>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FieldWriter<'_, 'f>, FrameWriteError> {
        *self.place.field.borrow_mut() = Some(key.to_owned());
        self.entries.push((key.to_owned(), Buffer::new()));
        let buffer = match self.entries.last_mut() {
            Some((_, buffer)) => buffer,
            // Pushed on the line above.
            None => unreachable!(),
        };
        Ok(FieldWriter {
            writer: FrameWriter::new(buffer),
            place: self.place,
        })
    }

    fn end(self) -> Result<O::Ok, FrameWriteError> {
        let mut record = Vec::with_capacity(self.entries.len());
        for (key, buffer) in self.entries {
            // A source that dropped an entry's sink without writing to it
            // left no frame.
            let value = OwnedFrame::from_buffer(buffer).map_err(|_| {
                *self.place.field.borrow_mut() = Some(key.clone());
                FrameWriteError::Unwritten
            })?;
            record.push((key, value));
        }
        Ok(self.out.put(Ok(record)))
    }
}

/// Writes the value of one field into a frame of its own.
///
/// The writer passes every call on to [`FrameWriter`]. When the value is
/// complete, the writer clears the field in [`Place`]. So an error after
/// the value of one field and before the next names no field.
struct FieldWriter<'s, 'f> {
    writer: FrameWriter<'s>,
    place: &'f Place,
}

impl<'s, 'f> Sink for FieldWriter<'s, 'f> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = FieldSeq<'s, 'f>;
    type Map = FieldMap<'s, 'f>;

    fn scalar(self, logical: Option<Logical>, value: Physical<'_>) -> Result<(), FrameWriteError> {
        self.writer.scalar(logical, value)?;
        self.place.field_done();
        Ok(())
    }

    fn typed_null(self, ty: FixedType) -> Result<(), FrameWriteError> {
        self.writer.typed_null(ty)?;
        self.place.field_done();
        Ok(())
    }

    fn seq(self, len: Option<usize>) -> Result<FieldSeq<'s, 'f>, FrameWriteError> {
        Ok(FieldSeq {
            inner: self.writer.seq(len)?,
            place: self.place,
        })
    }

    fn map(self, len: Option<usize>) -> Result<FieldMap<'s, 'f>, FrameWriteError> {
        Ok(FieldMap {
            inner: self.writer.map(len)?,
            place: self.place,
        })
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<(), FrameWriteError> {
        self.writer.passthrough(value)?;
        self.place.field_done();
        Ok(())
    }
}

/// A field's value that is a sequence. The field is finished when the
/// sequence ends.
struct FieldSeq<'s, 'f> {
    inner: FrameSeq<'s>,
    place: &'f Place,
}

impl<'s> SeqSink for FieldSeq<'s, '_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'e>
        = FrameWriter<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<FrameWriter<'_>, FrameWriteError> {
        self.inner.element()
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.inner.end()?;
        self.place.field_done();
        Ok(())
    }
}

/// A field's value that is a map. The field is finished when the map
/// ends.
struct FieldMap<'s, 'f> {
    inner: FrameMap<'s>,
    place: &'f Place,
}

impl<'s> MapSink for FieldMap<'s, '_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Entry<'e>
        = FrameWriter<'e>
    where
        Self: 'e;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_>, FrameWriteError> {
        self.inner.entry(key)
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.inner.end()?;
        self.place.field_done();
        Ok(())
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

    /// The fields of a record as the bytes of their frames, in source
    /// order. For a value that is not a record, the kind of that value.
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

    /// A value that is not a map is not a record. The split reports the
    /// kind of that value, at the top of the source and as an element of a
    /// batch.
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

    /// When the frame writer refuses a value, the error names the field of
    /// that value. For a batch, the error also names the row.
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

    /// When a source returns an error of its own, the split keeps that
    /// error. The split also names the field and the row that it was
    /// reading. An error after the fields of a record are written names no
    /// field.
    #[test]
    fn a_source_failure_names_the_field_and_row_it_was_reading() {
        /// A batch of `rows` records, each with one field `a`. The source
        /// returns an error in the last record: inside the value of `a`, or
        /// after the record ends.
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
        assert_eq!(after.row, None, "every row begun is finished");
    }

    /// The place where a source returns an error decides what the error
    /// names. The error names a field only while the split is writing the
    /// value of that field. The error names a row only while the split is
    /// reading that row. An error names no field when it happens between
    /// two fields, or after the list or map of a field ends. An error
    /// between two rows names no field and no row.
    #[test]
    fn a_source_failure_names_only_the_field_and_row_still_open() {
        /// The place in a batch of records where the source returns an
        /// error.
        #[derive(Clone, Copy, Debug)]
        enum At {
            /// The error happens in row 0, after `age` is written and before
            /// `email` starts.
            BetweenFields,
            /// The error happens in row 0, inside the list `tags`, after its
            /// first element.
            InsideAList,
            /// The error happens in row 0, after the map `tags` has ended.
            AfterAMap,
            /// The error happens after row 0 is finished, before row 1
            /// starts.
            BetweenRows,
        }
        impl Encrypt for &At {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let fail = || {
                    <S::Error as vitaminc_aead::plaintext::Error>::source(SourceError::msg(
                        "getter threw",
                    ))
                };
                let one = || Raw(None, Physical::Int(Int::I32(1)));
                let mut seq = sink.seq(Some(2))?;
                let mut map = seq.element()?.map(Some(2))?;
                one().visit(map.entry("age")?)?;
                match self {
                    At::BetweenFields => Err(fail()),
                    At::InsideAList => {
                        let mut list = map.entry("tags")?.seq(Some(2))?;
                        one().visit(list.element()?)?;
                        Err(fail())
                    }
                    At::AfterAMap => {
                        let mut inner = map.entry("tags")?.map(Some(1))?;
                        one().visit(inner.entry("k")?)?;
                        inner.end()?;
                        Err(fail())
                    }
                    At::BetweenRows => {
                        one().visit(map.entry("email")?)?;
                        map.end()?;
                        Err(fail())
                    }
                }
            }
        }
        for (at, field, row) in [
            (At::BetweenFields, None, Some(0)),
            (At::InsideAList, Some("tags"), Some(0)),
            (At::AfterAMap, None, Some(0)),
            (At::BetweenRows, None, None),
        ] {
            let failed = split_source(&at).err().expect("refused");
            assert!(
                matches!(failed.error, FrameWriteError::Source(_)),
                "{at:?}: {:?}",
                failed.error
            );
            assert_eq!(failed.field.as_deref(), field, "{at:?}: the field");
            assert_eq!(failed.row, row, "{at:?}: the row");
        }
    }

    /// A source can start a batch element and drop its sink without
    /// writing a value. That element leaves no record. The split returns an
    /// error that names the row, when the next element starts or when the
    /// batch ends. The split does not move the later rows up one position.
    #[test]
    fn a_batch_element_left_unwritten_is_refused_naming_its_row() {
        /// A batch of two rows. The source starts row `dropped` and drops
        /// its sink without writing a value.
        struct DropsARow {
            dropped: usize,
        }
        impl Encrypt for &DropsARow {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(2))?;
                for row in 0..2 {
                    let element = seq.element()?;
                    if row != self.dropped {
                        let mut map = element.map(Some(1))?;
                        Raw(None, Physical::Int(Int::I32(1))).visit(map.entry("a")?)?;
                        map.end()?;
                    }
                }
                seq.end()
            }
        }
        for dropped in [0, 1] {
            let refused = split_source(&DropsARow { dropped }).err().expect("refused");
            assert!(
                matches!(refused.error, FrameWriteError::Unwritten),
                "row {dropped}: {:?}",
                refused.error
            );
            assert_eq!(refused.row, Some(dropped), "the row left unwritten");
            assert_eq!(refused.field, None, "no field is being written");
        }
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
