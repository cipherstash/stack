//! A record source, split into its rows and each row's fields, each
//! field's value in a frame of its own.

use std::cell::RefCell;

use vitaminc_aead::frame::{FrameWriteError, FrameWriter, OwnedFrame};
use vitaminc_aead::plaintext::{
    Encrypt, EncryptRef, FixedType, Logical, MapSink, Physical, SeqSink, Sink,
};
use vitaminc_protected::Buffer;

/// One row of a record source: its entries, each value written into its
/// own frame as the source is walked, in source order with a repeated key
/// kept; or `None` for a row that is not a map.
pub(super) type SourceRow = Option<Vec<(String, OwnedFrame)>>;

/// A record source split by [`split_rows`]: one row, or a batch.
pub(super) enum SourceRows {
    /// A map: one row.
    One(SourceRow),
    /// A sequence: each element a row.
    Batch(Vec<SourceRow>),
}

/// Why [`split_rows`] refused a source: the frame writer's refusal, and the
/// field whose value it was writing, if it was writing one.
#[derive(Debug)]
pub(super) struct SplitRefusal {
    pub(super) field: Option<String>,
    pub(super) error: FrameWriteError,
}

/// Walk a record source once, writing each field's value into a frame of
/// its own. The source is a map (one row) or a sequence of maps (a batch);
/// anything else, at the top or as a batch element, is a row that is not a
/// map.
///
/// A value the frame writer refuses fails the walk, naming the field it
/// was written for. A failure of the source itself names no field.
pub(super) fn split_rows<P: Encrypt>(source: P) -> Result<SourceRows, SplitRefusal> {
    // The field whose value is being written. A field name is in the clear
    // in the plan and in the stored record, so it is held unwiped.
    let open = RefCell::new(None);
    source.visit(RowsSink(&open)).map_err(|error| SplitRefusal {
        field: match error {
            FrameWriteError::Source(_) => None,
            _ => open.take(),
        },
        error,
    })
}

/// The field a split is writing.
type Open<'f> = &'f RefCell<Option<String>>;

/// Where a finished row goes: back to the caller, or into a batch.
trait PutRow {
    type Ok;
    fn put(self, row: SourceRow) -> Self::Ok;
}

/// The top of a source: the row is the result.
struct TopRow;

impl PutRow for TopRow {
    type Ok = SourceRows;
    fn put(self, row: SourceRow) -> SourceRows {
        SourceRows::One(row)
    }
}

/// The next row of a batch.
struct BatchRow<'s>(&'s mut Vec<SourceRow>);

impl PutRow for BatchRow<'_> {
    type Ok = ();
    fn put(self, row: SourceRow) {
        self.0.push(row);
    }
}

/// The top of a record source.
struct RowsSink<'f>(Open<'f>);

impl<'f> Sink for RowsSink<'f> {
    type Ok = SourceRows;
    type Error = FrameWriteError;
    type Seq = BatchSink<'f>;
    type Map = RowMap<'f, TopRow>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<SourceRows, FrameWriteError> {
        Ok(SourceRows::One(None))
    }

    fn typed_null(self, _: FixedType) -> Result<SourceRows, FrameWriteError> {
        Ok(SourceRows::One(None))
    }

    fn seq(self, _: Option<usize>) -> Result<BatchSink<'f>, FrameWriteError> {
        Ok(BatchSink {
            open: self.0,
            rows: Vec::new(),
        })
    }

    fn map(self, _: Option<usize>) -> Result<RowMap<'f, TopRow>, FrameWriteError> {
        Ok(RowMap::new(self.0, TopRow))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<SourceRows, FrameWriteError> {
        Ok(SourceRows::One(None))
    }
}

/// A batch: one row per element.
struct BatchSink<'f> {
    open: Open<'f>,
    rows: Vec<SourceRow>,
}

impl<'f> SeqSink for BatchSink<'f> {
    type Ok = SourceRows;
    type Error = FrameWriteError;
    type Element<'s>
        = RowSink<'f, 's>
    where
        Self: 's;

    fn element(&mut self) -> Result<RowSink<'f, '_>, FrameWriteError> {
        Ok(RowSink {
            open: self.open,
            row: BatchRow(&mut self.rows),
        })
    }

    fn end(self) -> Result<SourceRows, FrameWriteError> {
        Ok(SourceRows::Batch(self.rows))
    }
}

/// One element of a batch: a row if it is a map, a row that is not a map
/// otherwise, whose content is walked past.
struct RowSink<'f, 's> {
    open: Open<'f>,
    row: BatchRow<'s>,
}

impl<'f, 's> Sink for RowSink<'f, 's> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = NotARow<'s>;
    type Map = RowMap<'f, BatchRow<'s>>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), FrameWriteError> {
        self.row.put(None);
        Ok(())
    }

    fn typed_null(self, _: FixedType) -> Result<(), FrameWriteError> {
        self.row.put(None);
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<NotARow<'s>, FrameWriteError> {
        Ok(NotARow {
            row: self.row,
            skipped: Buffer::new(),
        })
    }

    fn map(self, _: Option<usize>) -> Result<RowMap<'f, BatchRow<'s>>, FrameWriteError> {
        Ok(RowMap::new(self.open, self.row))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, _: &P) -> Result<(), FrameWriteError> {
        self.row.put(None);
        Ok(())
    }
}

/// A batch element that is a sequence: not a row. Its elements are walked
/// past, written into a buffer that is dropped, and it is recorded when it
/// ends.
struct NotARow<'s> {
    row: BatchRow<'s>,
    skipped: Buffer,
}

impl SeqSink for NotARow<'_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'e>
        = FrameWriter<'e>
    where
        Self: 'e;

    fn element(&mut self) -> Result<FrameWriter<'_>, FrameWriteError> {
        Ok(FrameWriter::new(&mut self.skipped))
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.row.put(None);
        Ok(())
    }
}

/// One row's entries, each written into its own frame.
struct RowMap<'f, O> {
    open: Open<'f>,
    out: O,
    // A row's keys are its field names, which the plan and the stored
    // record both name in the clear, so they are held unwiped.
    entries: Vec<(String, Buffer)>,
}

impl<'f, O> RowMap<'f, O> {
    fn new(open: Open<'f>, out: O) -> Self {
        Self {
            open,
            out,
            entries: Vec::new(),
        }
    }
}

impl<O: PutRow> MapSink for RowMap<'_, O> {
    type Ok = O::Ok;
    type Error = FrameWriteError;
    type Entry<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_>, FrameWriteError> {
        *self.open.borrow_mut() = Some(key.to_owned());
        self.entries.push((key.to_owned(), Buffer::new()));
        let buffer = match self.entries.last_mut() {
            Some((_, buffer)) => buffer,
            // Pushed on the line above.
            None => unreachable!(),
        };
        Ok(FrameWriter::new(buffer))
    }

    fn end(self) -> Result<O::Ok, FrameWriteError> {
        let mut row = Vec::with_capacity(self.entries.len());
        for (key, buffer) in self.entries {
            // A source that dropped an entry's sink unwritten left no frame.
            let value = OwnedFrame::from_buffer(buffer).map_err(|_| {
                *self.open.borrow_mut() = Some(key.clone());
                FrameWriteError::Unwritten
            })?;
            row.push((key, value));
        }
        *self.open.borrow_mut() = None;
        Ok(self.out.put(Some(row)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;
    use vitaminc_aead::frame::{Frame, ARRAY};
    use vitaminc_aead::plaintext::{Int, Width};

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

    /// A row's entries as their frames' bytes, in source order.
    fn bytes(row: &SourceRow) -> Option<Vec<(String, Vec<u8>)>> {
        row.as_ref().map(|entries| {
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
    fn a_map_is_one_row_of_its_entries_frames_in_order_with_a_repeat_kept() {
        // A frame holds no repeated key, so the source is the tree itself.
        let source = obj(vec![
            ("b", Tree::UInt32(7)),
            ("a", obj(vec![("k", s("v"))])),
            ("b", Tree::Passthrough(Box::new(s("p")))),
        ]);
        let Ok(SourceRows::One(row)) = split_rows(&source) else {
            panic!("one row");
        };
        assert_eq!(
            bytes(&row),
            Some(vec![
                ("b".to_owned(), owned(&Tree::UInt32(7))),
                ("a".to_owned(), owned(&obj(vec![("k", s("v"))]))),
                ("b".to_owned(), owned(&Tree::Passthrough(Box::new(s("p"))))),
            ])
        );
    }

    #[test]
    fn a_sequence_is_a_batch_and_what_is_not_a_map_is_no_row() {
        let ty = FixedType::new(Some(Logical::Date), Width::I32).expect("fixed");
        let source = Tree::Array(vec![
            obj(vec![("a", Tree::Int32(1))]),
            s("x"),
            Tree::Array(vec![s("y"), obj(vec![("k", Tree::Null)])]),
            Tree::Passthrough(Box::new(obj(vec![]))),
            obj(vec![]),
        ]);
        let Ok(SourceRows::Batch(rows)) = split_rows(&source) else {
            panic!("a batch");
        };
        let rows: Vec<_> = rows.iter().map(bytes).collect();
        assert_eq!(
            rows,
            [
                Some(vec![("a".to_owned(), owned(&Tree::Int32(1)))]),
                None,
                None,
                None,
                Some(vec![]),
            ]
        );
        for top in [s("x"), Tree::Null, Tree::Passthrough(Box::new(obj(vec![])))] {
            assert!(matches!(split_rows(&top), Ok(SourceRows::One(None))));
        }

        // A typed null, at the top or as a batch element, is a null.
        let mut one = Vec::new();
        vitaminc_aead::leaf::write_typed_null(ty, &mut one);
        let top = Frame::parse(&one).expect("a frame");
        assert!(matches!(split_rows(top), Ok(SourceRows::One(None))));
        let mut batch = vec![ARRAY, 2, 0, 0, 0];
        batch.extend(&one);
        batch.extend(&one);
        let batch = Frame::parse(&batch).expect("a frame");
        assert!(matches!(
            split_rows(batch),
            Ok(SourceRows::Batch(rows)) if rows.len() == 2 && rows.iter().all(Option::is_none)
        ));
    }

    /// A refusal names the field whose value the writer refused, in the
    /// first row or a later one; a source's own failure names none.
    #[test]
    fn a_refusal_names_the_field_being_written() {
        let refused = |source: &Tree| split_rows(source).err().expect("refused");
        let bad_date = Tree::Typed(Logical::Date, Box::new(Tree::Int64(i64::MAX)));

        let one = refused(&obj(vec![
            ("ok", Tree::Int32(1)),
            ("when", bad_date.clone()),
        ]));
        assert_eq!(one.field.as_deref(), Some("when"));
        assert!(matches!(one.error, FrameWriteError::Invalid));

        let batch = refused(&Tree::Array(vec![
            obj(vec![("when", Tree::Int32(1))]),
            obj(vec![("at", Tree::Array(vec![bad_date.clone()]))]),
        ]));
        assert_eq!(batch.field.as_deref(), Some("at"));

        let repeated = refused(&obj(vec![(
            "doc",
            obj(vec![("k", Tree::Null), ("k", Tree::Null)]),
        )]));
        assert_eq!(repeated.field.as_deref(), Some("doc"));
        assert!(matches!(repeated.error, FrameWriteError::DuplicateKey));

        // After a row ends, a refusal outside any row names no field.
        let after = refused(&Tree::Array(vec![
            obj(vec![("a", Tree::Int32(1))]),
            Tree::Array(vec![bad_date]),
        ]));
        assert_eq!(after.field, None);

        struct Fails;
        impl Encrypt for &Fails {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(None)?;
                let _ = map.entry("a")?;
                Err(<S::Error as vitaminc_aead::plaintext::Error>::source(
                    vitaminc_aead::plaintext::SourceError::msg("getter threw"),
                ))
            }
        }
        let failed = split_rows(&Fails).err().expect("refused");
        assert_eq!(failed.field, None);
        assert!(matches!(failed.error, FrameWriteError::Source(_)));
    }

    /// An entry whose sink the source dropped unwritten has no frame: the
    /// row is refused, naming it.
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
        use vitaminc_aead::plaintext::Raw;
        let refused = split_rows(&DropsAnEntry).err().expect("refused");
        assert_eq!(refused.field.as_deref(), Some("dropped"));
        assert!(matches!(refused.error, FrameWriteError::Unwritten));
    }
}
