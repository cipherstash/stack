//! Encryption as a sink.
//!
//! [`EncryptSink`] turns each scalar into tagged leaf plaintext and owns
//! every container rule in one place:
//!
//! - a sequence element is sealed under
//!   [`Context::for_sequence_element`], a map value under
//!   [`Context::for_map_entry`] of its key;
//! - an empty sequence or map is an authenticated empty marker under
//!   [`Context::for_empty_sequence`] or [`Context::for_empty_map`];
//! - a passthrough subtree is framed, in the clear;
//! - the value keeps the [`shape`](crate::shape) rules: no duplicate keys,
//!   at least one leaf sealed in every container with children, no child
//!   sink dropped without a value (as
//!   [`FrameWriter`](crate::frame::FrameWriter) refuses it, so a tee of the
//!   two agrees on every walk), and nothing deeper than
//!   [`MAX_DEPTH`](crate::frame::MAX_DEPTH), counted as the transport
//!   decoder counts it, so every ciphertext planned here can be read back.
//!
//! A refusal is a [`Refusal`]: the rule, and the
//! [`Path`](crate::plaintext::Path) to the node that broke it. Each child
//! sink holds only a borrow of its parent's place and its own index or
//! key, so the path is built only when a value is refused.
//!
//! The sink never calls a cipher. It plans a tree of [`Pending`] leaves,
//! each with its plaintext and the AAD its position derives, and
//! [`seal_all`] or [`seal_all_async`] seals them afterwards. So the walk
//! is synchronous whatever the cipher is, and terms collected by a sink
//! teed with this one are complete before the first await.

use core::future::Future;
use core::marker::PhantomData;

use vitaminc_protected::{Controlled, Protected};

use crate::frame::PassthroughFrame;
use crate::leaf::{self, ScalarError};
use crate::plaintext::{
    Encrypt, Error, Logical, MapSink, Physical, SeqSink, Sink, SourceError, Step,
};
use crate::seal::{
    seal_all, seal_all_async, AsyncCipher, Cipher, LeafCount, Node, Pending, SealError,
};
use crate::shape::{
    self, refuse, Locate, MapRules, Refusal, Root, SeqRules, Settle, Unencryptable,
};
use crate::{CipherText, Context, IntoAad};

/// Why encryption failed.
///
/// A cipher's own error is printed in the message rather than chained as
/// the `source()`, so a cipher error type need not implement `Error`.
///
/// Every failure is an error, never a panic, including the ones that look
/// like contract violations: a value too long for the frame's `u32` length
/// prefixes ([`Unencryptable::Unwritable`],
/// [`Unencryptable::UnframablePassthrough`]) and a cipher that returns the
/// wrong number of leaves ([`EncryptError::Count`]). The value often comes
/// from a host (a JavaScript object, a Go frame) and the cipher may be a
/// remote key provider, so neither is under the caller's control. A panic
/// there would let hostile input or a bad response abort the process: in
/// the Node binding, a panic aborts Node.
///
/// A type that derives `Encrypt` cannot hit most of these. The derive
/// refuses a duplicate key, a struct that seals nothing and a type too deep
/// for [`MAX_DEPTH`](crate::frame::MAX_DEPTH) at compile time, and
/// `Timestamp` (with the `chrono` feature) is a time
/// that cannot be a leap second. What remains is a value deeper than
/// `MAX_DEPTH` through a field whose type does not fix its depth (a
/// recursive type, a frame, a hand-written source), a value too long for
/// the frame, a source's own error (such as a leap second in a
/// `DateTime<Utc>` field, or a passthrough frame that does not parse), a
/// `Raw` leaf whose value does not fit its logical type, and the cipher's
/// own errors.
#[derive(Debug, thiserror::Error)]
pub enum EncryptError<E> {
    /// The cipher refused to seal a leaf.
    #[error("cipher failed: {0}")]
    Cipher(E),
    /// The source stopped the walk, or a sink teed beside this one did
    /// (an index sink refusing a value, say); the error inside says which.
    #[error("source failed: {0}")]
    Source(#[source] SourceError),
    /// The value cannot be encrypted as given: why, and where in the
    /// value. See [`Refusal`].
    #[error("cannot encrypt: {0}")]
    Shape(Refusal),
    /// The cipher returned the wrong number of leaves: a cipher bug, not a
    /// problem with the value.
    #[error("cipher returned {0}")]
    Count(LeafCount),
}

impl<E> Error for EncryptError<E> {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl<E> From<Refusal> for EncryptError<E> {
    fn from(refusal: Refusal) -> Self {
        Self::Shape(refusal)
    }
}

impl<E> From<SealError<E>> for EncryptError<E> {
    fn from(error: SealError<E>) -> Self {
        match error {
            SealError::Cipher(e) => Self::Cipher(e),
            SealError::Count(count) => Self::Count(count),
        }
    }
}

/// Walk a source into a tree of pending leaves. No cipher is involved:
/// this is the whole of the data-model work, and it is synchronous.
pub fn plan<'a, P, E, A>(value: P, aad: A) -> Result<Node<Pending>, EncryptError<E>>
where
    P: Encrypt,
    A: IntoAad<'a>,
{
    value.visit(EncryptSink::root(aad))
}

/// Encrypt any source.
pub fn encrypt<'a, P, C, A>(
    value: P,
    cipher: &C,
    aad: A,
) -> Result<Node<C::Leaf>, EncryptError<C::Error>>
where
    P: Encrypt,
    C: Cipher,
    A: IntoAad<'a>,
{
    Ok(seal_all(cipher, plan(value, aad)?)?)
}

/// Encrypt any source through an async cipher. A cipher with a batch API
/// seals the document in one round trip.
///
/// The walk happens here, before this returns, and the future holds only
/// the planned leaves. So the future is `Send` even when the source is not
/// (a JavaScript object behind a host binding).
pub fn encrypt_async<'a, 'c, P, C, A>(
    value: P,
    cipher: &'c C,
    aad: A,
) -> impl Future<Output = Result<Node<C::Leaf>, EncryptError<C::Error>>> + Send + 'c
where
    P: Encrypt,
    C: AsyncCipher,
    A: IntoAad<'a>,
{
    let planned = plan(value, aad);
    async move { Ok(seal_all_async(cipher, planned?).await?) }
}

/// Where a finished node goes: back to the caller, or into a parent. It
/// also knows where the node sits, for a refusal.
pub trait Slot: Locate {
    type Ok;
    fn put(self, node: Node<Pending>) -> Self::Ok;
}

impl Slot for Root {
    type Ok = Node<Pending>;
    fn put(self, node: Node<Pending>) -> Node<Pending> {
        node
    }
}

/// Tell a container's rules how its child ended.
fn settle(settle: Settle<'_>, node: &Node<Pending>) {
    if matches!(node, CipherText::Passthrough(_)) {
        settle.passthrough();
    } else {
        settle.sealed();
    }
}

/// An element slot in a parent sequence: the parent's items, this
/// element's hold on the parent's rules, and the parent's place.
pub struct Push<'s> {
    items: &'s mut Vec<Node<Pending>>,
    settle: Settle<'s>,
    parent: &'s dyn Locate,
}

impl Locate for Push<'_> {
    fn locate(&self, steps: &mut Vec<Step>) {
        self.settle.locate_under(self.parent, steps);
    }
}

impl Slot for Push<'_> {
    type Ok = ();
    fn put(self, node: Node<Pending>) {
        settle(self.settle, &node);
        self.items.push(node);
    }
}

/// An entry slot in a parent map: the parent's entries, this entry's hold
/// on the parent's rules, which also lends it the key, and the parent's
/// place.
pub struct Entry<'s> {
    entries: &'s mut Vec<(String, Node<Pending>)>,
    settle: Settle<'s>,
    parent: &'s dyn Locate,
}

impl Locate for Entry<'_> {
    fn locate(&self, steps: &mut Vec<Step>) {
        self.settle.locate_under(self.parent, steps);
    }
}

impl Slot for Entry<'_> {
    type Ok = ();
    /// The key stays in the parent's rules until the map ends, and the
    /// entry holds an empty string in its place, which does not allocate.
    fn put(self, node: Node<Pending>) {
        settle(self.settle, &node);
        self.entries.push((String::new(), node));
    }
}

/// The encrypting sink.
///
/// `E` is the cipher's error type, so this sink can be teed with others
/// before any cipher is involved; the sink itself never produces
/// `EncryptError::Cipher`.
pub struct EncryptSink<E, O = Root> {
    aad: Context<'static>,
    out: O,
    /// How far below the root this node sits.
    depth: usize,
    _error: PhantomData<E>,
}

impl<E> EncryptSink<E, Root> {
    /// A sink for a whole value under `aad`. Its `Ok` is the planned tree.
    pub fn root<'a>(aad: impl IntoAad<'a>) -> Self {
        Self {
            aad: aad.into_aad().into_owned(),
            out: Root,
            depth: 0,
            _error: PhantomData,
        }
    }
}

impl<E, O: Slot> EncryptSink<E, O> {
    /// Plan one scalar as one leaf: its tag, then its payload.
    fn leaf(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, EncryptError<E>> {
        shape::scalar(self.depth, ty, &v, &self.out)?;
        // Sized once, so the buffer never regrows and leaves a copy behind.
        let mut plaintext = Protected::new(Vec::with_capacity(leaf::max_len(&v)));
        leaf::write_leaf(ty, v, plaintext.risky_inner_mut()).map_err(|e| {
            refuse(
                &self.out,
                match e {
                    ScalarError::Invalid => Unencryptable::InvalidValue,
                    ScalarError::TooLong | ScalarError::Malformed => Unencryptable::Unwritable,
                },
            )
        })?;
        Ok(self.out.put(CipherText::Single(Pending {
            plaintext,
            aad: self.aad,
        })))
    }
}

fn marker(aad: Context<'static>) -> Pending {
    Pending {
        plaintext: Protected::new(Vec::new()),
        aad,
    }
}

impl<E, O: Slot> Sink for EncryptSink<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Seq = EncryptSeq<E, O>;
    type Map = EncryptMap<E, O>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, Self::Error> {
        self.leaf(ty, v)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, Self::Error> {
        shape::container(self.depth, &self.out)?;
        Ok(EncryptSeq {
            element_aad: self.aad.for_sequence_element(),
            aad: self.aad,
            items: Vec::with_capacity(len.unwrap_or(0).min(1024)),
            rules: SeqRules::new(),
            out: self.out,
            depth: self.depth,
            _error: PhantomData,
        })
    }

    fn map(self, _len: Option<usize>) -> Result<Self::Map, Self::Error> {
        shape::container(self.depth, &self.out)?;
        Ok(EncryptMap {
            aad: self.aad,
            entries: Vec::new(),
            rules: MapRules::new(),
            out: self.out,
            depth: self.depth,
            _error: PhantomData,
        })
    }

    /// Passthrough is non-sensitive by design: it is framed, not sealed.
    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<O::Ok, Self::Error> {
        let frame = shape::frame_passthrough(value, self.depth, &self.out, EncryptError::Shape)?;
        Ok(self.out.put(CipherText::Passthrough(PassthroughFrame(
            frame.risky_ref().to_vec(),
        ))))
    }
}

pub struct EncryptSeq<E, O> {
    aad: Context<'static>,
    element_aad: Context<'static>,
    items: Vec<Node<Pending>>,
    rules: SeqRules,
    out: O,
    depth: usize,
    _error: PhantomData<E>,
}

impl<E, O: Slot> SeqSink for EncryptSeq<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Element<'s>
        = EncryptSink<E, Push<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, Self::Error> {
        Ok(EncryptSink {
            aad: self.element_aad.clone(),
            out: Push {
                settle: self.rules.element(&self.out)?,
                items: &mut self.items,
                parent: &self.out,
            },
            depth: self.depth + 1,
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        self.rules.end(&self.out)?;
        let node = if self.items.is_empty() {
            CipherText::EmptySequence(marker(self.aad.for_empty_sequence()))
        } else {
            CipherText::Sequence(self.items)
        };
        Ok(self.out.put(node))
    }
}

pub struct EncryptMap<E, O> {
    aad: Context<'static>,
    /// Each entry's node, in order, with an empty key until the map ends.
    entries: Vec<(String, Node<Pending>)>,
    /// The only copy of each key, which `end` moves into `entries`.
    rules: MapRules,
    out: O,
    depth: usize,
    _error: PhantomData<E>,
}

impl<E, O: Slot> MapSink for EncryptMap<E, O> {
    type Ok = O::Ok;
    type Error = EncryptError<E>;
    type Entry<'s>
        = EncryptSink<E, Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, Self::Error> {
        Ok(EncryptSink {
            aad: self.aad.for_map_entry(key),
            out: Entry {
                settle: self.rules.entry(key, &self.out)?,
                entries: &mut self.entries,
                parent: &self.out,
            },
            depth: self.depth + 1,
            _error: PhantomData,
        })
    }

    fn end(mut self) -> Result<O::Ok, Self::Error> {
        self.rules.end(&self.out)?;
        for (key, at) in self.rules.into_keys() {
            if let Some((slot, _)) = self.entries.get_mut(at) {
                *slot = key;
            }
        }
        let node = if self.entries.is_empty() {
            CipherText::EmptyMap(marker(self.aad.for_empty_map()))
        } else {
            CipherText::Map(self.entries)
        };
        Ok(self.out.put(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameWriteError, MAX_DEPTH};
    use crate::plaintext::{render, visit_seq, Int, Raw};
    use crate::seal::leaves_with_aad;
    use crate::seal::mock::{Mock, Refused};
    use crate::Tee;
    use std::collections::BTreeMap;

    #[test]
    fn a_source_error_inside_a_passthrough_stays_a_source_error() {
        #[derive(Clone)]
        struct Throws;
        impl Encrypt for Throws {
            fn visit<S: Sink>(self, _: S) -> Result<S::Ok, S::Error> {
                Err(S::Error::source(SourceError::new(core::fmt::Error)))
            }
        }
        struct Doc;
        impl Encrypt for Doc {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough(Throws)
            }
        }
        assert!(matches!(
            plan::<_, (), _>(Doc, "ctx"),
            Err(EncryptError::Source(_))
        ));
    }

    fn planned<P: Encrypt>(p: P) -> Result<Node<Pending>, EncryptError<Refused>> {
        plan(p, "ctx")
    }

    /// Why a plan was refused and where, the path written out by
    /// [`render`], or `None` if it was not refused for its shape.
    fn refusal<T, E>(planned: Result<T, EncryptError<E>>) -> Option<(Unencryptable, String)> {
        match planned {
            Err(EncryptError::Shape(refusal)) => Some((refusal.reason(), render(refusal.path()))),
            _ => None,
        }
    }

    fn refused(reason: Unencryptable, at: &str) -> Option<(Unencryptable, String)> {
        Some((reason, at.to_owned()))
    }

    #[test]
    fn a_scalar_is_one_tagged_leaf_under_the_bare_aad() {
        let node = planned(34u32).expect("plans");
        let leaves = leaves_with_aad(node, &"ctx".into_aad());
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].0.plaintext.risky_ref(), &[0x06, 34, 0, 0, 0]);
        assert_eq!(leaves[0].1, "ctx".into_aad());
    }

    #[test]
    fn none_is_a_null_leaf_not_a_marker() {
        let node = planned(None::<u32>).expect("plans");
        assert!(matches!(node, CipherText::Single(_)));
        let leaves = leaves_with_aad(node, &"ctx".into_aad());
        assert_eq!(leaves[0].0.plaintext.risky_ref(), &[0x00]);
        assert_eq!(leaves[0].1, "ctx".into_aad());
    }

    #[test]
    fn empty_containers_are_markers() {
        let node = planned(Vec::<u32>::new()).expect("plans");
        assert!(matches!(node, CipherText::EmptySequence(_)));
        let node = planned(BTreeMap::<&str, u32>::new()).expect("plans");
        assert!(matches!(node, CipherText::EmptyMap(_)));
    }

    #[test]
    fn duplicate_keys_are_refused() {
        // The path names the entry under the repeated key.
        assert_eq!(
            refusal(planned(Dup)),
            refused(Unencryptable::DuplicateKey, ".k")
        );
    }

    #[test]
    fn an_all_passthrough_container_is_refused() {
        struct Pass;
        impl Encrypt for Pass {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough("public")
            }
        }
        assert_eq!(
            refusal(planned(vec![Pass])),
            refused(Unencryptable::SequenceHasNothingSealed, "")
        );
        let mut map = BTreeMap::new();
        map.insert("note", Pass);
        assert_eq!(
            refusal(planned(map)),
            refused(Unencryptable::MapHasNothingSealed, "")
        );
        // One sealed sibling is enough.
        struct Mixed;
        impl Encrypt for Mixed {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(2))?;
                Pass.visit(seq.element()?)?;
                1u32.visit(seq.element()?)?;
                seq.end()
            }
        }
        let node = planned(Mixed).expect("plans");
        match node {
            CipherText::Sequence(items) => {
                assert!(
                    matches!(items[0], CipherText::Passthrough(ref f) if f.0 == [0x0A, 6, 0, 0, 0, b'p', b'u', b'b', b'l', b'i', b'c'])
                );
                assert!(matches!(items[1], CipherText::Single(_)));
            }
            _ => panic!("expected a sequence"),
        }
    }

    #[test]
    fn an_invalid_logical_value_is_refused() {
        let bad = Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]));
        assert_eq!(
            refusal(planned(bad)),
            refused(Unencryptable::InvalidValue, "")
        );
    }

    #[test]
    fn a_source_error_stops_the_walk() {
        struct Failing;
        impl Encrypt for Failing {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(None)?;
                1u32.visit(seq.element()?)?;
                Err(S::Error::source(SourceError::msg("getter threw")))
            }
        }
        match encrypt(Failing, &Mock, ()) {
            Err(EncryptError::Source(e)) => assert_eq!(e.to_string(), "getter threw"),
            other => panic!("{other:?}"),
        }
    }

    /// A sink generic over its error type, as a terms sink would be, so it
    /// can adopt the encrypt sink's.
    struct Count<'c, E>(&'c mut usize, PhantomData<E>);

    impl<E: Error> Sink for Count<'_, E> {
        type Ok = ();
        type Error = E;
        type Seq = Self;
        type Map = Self;
        fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), E> {
            *self.0 += 1;
            Ok(())
        }
        fn seq(self, _: Option<usize>) -> Result<Self, E> {
            Ok(self)
        }
        fn map(self, _: Option<usize>) -> Result<Self, E> {
            Ok(self)
        }
        fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), E> {
            Ok(())
        }
    }

    impl<E: Error> SeqSink for Count<'_, E> {
        type Ok = ();
        type Error = E;
        type Element<'s>
            = Count<'s, E>
        where
            Self: 's;
        fn element(&mut self) -> Result<Count<'_, E>, E> {
            Ok(Count(self.0, PhantomData))
        }
        fn end(self) -> Result<(), E> {
            Ok(())
        }
    }

    impl<E: Error> MapSink for Count<'_, E> {
        type Ok = ();
        type Error = E;
        type Entry<'s>
            = Count<'s, E>
        where
            Self: 's;
        fn entry(&mut self, _: &str) -> Result<Count<'_, E>, E> {
            Ok(Count(self.0, PhantomData))
        }
        fn end(self) -> Result<(), E> {
            Ok(())
        }
    }

    #[test]
    fn the_sink_can_be_teed_before_any_cipher_exists() {
        let mut scalars = 0;
        let (node, ()) = vec![1u32, 2]
            .visit(Tee(
                EncryptSink::<Refused>::root("ctx"),
                Count(&mut scalars, PhantomData),
            ))
            .expect("walks");
        assert_eq!(scalars, 2);
        assert_eq!(leaves_with_aad(node, &"ctx".into_aad()).len(), 2);
    }

    #[test]
    fn a_length_hint_is_only_a_hint() {
        struct Unsized;
        impl Encrypt for Unsized {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                visit_seq(
                    sink,
                    None,
                    vec![Int::U8(1), Int::U8(2)]
                        .into_iter()
                        .map(|i| Raw(None, Physical::Int(i))),
                )
            }
        }
        let node = planned(Unsized).expect("plans");
        assert_eq!(leaves_with_aad(node, &"ctx".into_aad()).len(), 2);
    }

    /// A source that asks for a child sink and drops it unused.
    #[derive(Clone)]
    struct DropsAChild {
        map: bool,
    }

    impl Encrypt for DropsAChild {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            if self.map {
                let mut map = sink.map(None)?;
                let _ = map.entry("a")?;
                1u16.visit(map.entry("b")?)?;
                map.end()
            } else {
                let mut seq = sink.seq(None)?;
                1u16.visit(seq.element()?)?;
                let _ = seq.element()?;
                seq.end()
            }
        }
    }

    #[test]
    fn a_dropped_child_sink_is_refused_as_the_frame_writer_refuses_it() {
        for map in [false, true] {
            assert_eq!(
                refusal(planned(DropsAChild { map })),
                refused(Unencryptable::DroppedChild, "")
            );
            assert!(matches!(
                crate::frame::to_frame(DropsAChild { map }),
                Err(FrameWriteError::Unwritten)
            ));
        }
        // A dropped element is caught at the next element too.
        struct DropsThenWrites;
        impl Encrypt for DropsThenWrites {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(None)?;
                let _ = seq.element()?;
                1u16.visit(seq.element()?)?;
                seq.end()
            }
        }
        assert_eq!(
            refusal(planned(DropsThenWrites)),
            refused(Unencryptable::DroppedChild, "")
        );
    }

    /// A passthrough that opens a container and never ends it.
    #[derive(Clone)]
    struct Unclosed;

    impl Encrypt for Unclosed {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut outer = sink.seq(None)?;
            let mut inner = outer.element()?.seq(None)?;
            1u32.visit(inner.element()?)?;
            // Dropped without `end`, so its count is never written.
            drop(inner);
            outer.end()
        }
    }

    #[test]
    fn a_passthrough_that_does_not_frame_is_refused_at_encryption() {
        struct Doc;
        impl Encrypt for Doc {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(2))?;
                1u32.visit(seq.element()?)?;
                seq.element()?.passthrough(Unclosed)?;
                seq.end()
            }
        }
        assert!(matches!(
            crate::frame::to_frame(Unclosed),
            Err(FrameWriteError::Unfinished)
        ));
        // The path names the passthrough, not a node inside it.
        assert_eq!(
            refusal(planned(Doc)),
            refused(Unencryptable::UnframablePassthrough, "[1]")
        );
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Seq,
        Map,
        Pass,
        Scalar,
    }

    /// `n` levels of one kind of nesting around an innermost value at
    /// depth `n`: an empty sequence, or for `Scalar`, an int inside
    /// sequences.
    #[derive(Clone, Copy)]
    struct Nest(Kind, usize);

    impl Encrypt for Nest {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let Nest(kind, n) = self;
            if n == 0 {
                return match kind {
                    Kind::Scalar => 1u16.visit(sink),
                    _ => sink.seq(Some(0))?.end(),
                };
            }
            let inner = Nest(kind, n - 1);
            match kind {
                Kind::Seq | Kind::Scalar => {
                    let mut seq = sink.seq(Some(1))?;
                    inner.visit(seq.element()?)?;
                    seq.end()
                }
                Kind::Map => {
                    let mut map = sink.map(Some(1))?;
                    inner.visit(map.entry("k")?)?;
                    map.end()
                }
                Kind::Pass => sink.passthrough(inner),
            }
        }
    }

    #[test]
    fn depth_is_bounded_as_the_transport_decoder_bounds_it() {
        // The path names the node one level too deep; a passthrough that
        // nests too deep is refused as a whole, at its own place.
        for (kind, step) in [
            (Kind::Seq, "[0]"),
            (Kind::Map, ".k"),
            (Kind::Pass, ""),
            (Kind::Scalar, "[0]"),
        ] {
            assert!(planned(Nest(kind, MAX_DEPTH)).is_ok());
            assert_eq!(
                refusal(planned(Nest(kind, MAX_DEPTH + 1))),
                refused(Unencryptable::TooDeep, &step.repeat(MAX_DEPTH + 1))
            );
        }
        // A passthrough below the top counts from the top: one level of
        // sequence around a frame that is itself `MAX_DEPTH` deep is one
        // too many.
        struct Wrapped(usize);
        impl Encrypt for Wrapped {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(2))?;
                1u16.visit(seq.element()?)?;
                seq.element()?.passthrough(Nest(Kind::Seq, self.0))?;
                seq.end()
            }
        }
        assert!(planned(Wrapped(MAX_DEPTH - 2)).is_ok());
        assert_eq!(
            refusal(planned(Wrapped(MAX_DEPTH - 1))),
            refused(Unencryptable::TooDeep, "[1]")
        );
    }

    /// A document whose `users` entry is a sequence of two values, the
    /// second of them `bad`, beside a well-formed `id`.
    struct Users<P>(P);

    impl<P: Encrypt> Encrypt for Users<P> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(Some(2))?;
            1u32.visit(map.entry("id")?)?;
            let mut users = map.entry("users")?.seq(Some(2))?;
            "ada".visit(users.element()?)?;
            self.0.visit(users.element()?)?;
            users.end()?;
            map.end()
        }
    }

    /// A map that gives `k` twice.
    struct Dup;

    impl Encrypt for Dup {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let mut map = sink.map(None)?;
            1u32.visit(map.entry("k")?)?;
            2u32.visit(map.entry("k")?)?;
            map.end()
        }
    }

    /// A container with one passthrough in it and nothing sealed.
    #[derive(Clone)]
    struct OnlyPass {
        map: bool,
    }

    impl Encrypt for OnlyPass {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            if self.map {
                let mut map = sink.map(Some(1))?;
                map.entry("note")?.passthrough("public")?;
                map.end()
            } else {
                let mut seq = sink.seq(Some(1))?;
                seq.element()?.passthrough("public")?;
                seq.end()
            }
        }
    }

    #[test]
    fn a_refusal_names_the_node_below_the_root() {
        let invalid = Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]));
        assert_eq!(
            refusal(planned(Users(invalid))),
            refused(Unencryptable::InvalidValue, ".users[1]")
        );
        assert_eq!(
            refusal(planned(Users(Dup))),
            refused(Unencryptable::DuplicateKey, ".users[1].k")
        );
        assert_eq!(
            refusal(planned(Users(OnlyPass { map: false }))),
            refused(Unencryptable::SequenceHasNothingSealed, ".users[1]")
        );
        assert_eq!(
            refusal(planned(Users(OnlyPass { map: true }))),
            refused(Unencryptable::MapHasNothingSealed, ".users[1]")
        );
        for map in [false, true] {
            assert_eq!(
                refusal(planned(Users(DropsAChild { map }))),
                refused(Unencryptable::DroppedChild, ".users[1]")
            );
        }
        assert_eq!(
            refusal(planned(Users(Nest(Kind::Seq, MAX_DEPTH - 1)))),
            refused(
                Unencryptable::TooDeep,
                &format!(".users[1]{}", "[0]".repeat(MAX_DEPTH - 1))
            )
        );
        // Teed with another sink, the refusal and its path are the same.
        let mut scalars = 0;
        let invalid = Raw(Some(Logical::Uuid), Physical::Bytes(&[0; 3]));
        let teed = Users(invalid).visit(Tee(
            EncryptSink::<Refused>::root("ctx"),
            Count(&mut scalars, PhantomData),
        ));
        assert_eq!(
            refusal(teed),
            refused(Unencryptable::InvalidValue, ".users[1]")
        );
    }

    #[test]
    fn a_refusal_shows_its_path_only_on_request() {
        let err = plan::<_, &str, _>(Users(Dup), "ctx")
            .err()
            .expect("refused");
        // Neither the message nor `Debug` names a key; `Debug` keeps the
        // path's shape.
        assert_eq!(err.to_string(), "cannot encrypt: duplicate key");
        let debug = format!("{err:?}");
        assert!(!debug.contains("users"), "{debug}");
        assert!(debug.contains("DuplicateKey"), "{debug}");
        assert!(debug.contains("Index(1)"), "{debug}");
        assert!(debug.contains("Key(\"***\")"), "{debug}");
        let EncryptError::Shape(refusal) = err else {
            panic!("{err:?}")
        };
        assert_eq!(
            refusal.path().steps(),
            [
                Step::Key("users".into()),
                Step::Index(1),
                Step::Key("k".into())
            ]
        );
    }

    #[test]
    fn errors_say_what_failed_without_the_value() {
        struct Secret;
        impl Locate for Secret {
            fn locate(&self, steps: &mut Vec<Step>) {
                steps.push(Step::Key("secret".into()));
            }
        }
        let shape = |reason| EncryptError::<&str>::Shape(refuse(&Secret, reason)).to_string();
        assert_eq!(
            shape(Unencryptable::DuplicateKey),
            "cannot encrypt: duplicate key"
        );
        assert_eq!(
            shape(Unencryptable::SequenceHasNothingSealed),
            "cannot encrypt: sequence has nothing sealed"
        );
        assert_eq!(
            shape(Unencryptable::MapHasNothingSealed),
            "cannot encrypt: map has nothing sealed"
        );
        assert_eq!(
            shape(Unencryptable::InvalidValue),
            "cannot encrypt: value is not valid for its logical type"
        );
        assert_eq!(
            shape(Unencryptable::Unwritable),
            "cannot encrypt: value cannot be written as a leaf"
        );
        assert_eq!(
            shape(Unencryptable::UnframablePassthrough),
            "cannot encrypt: passthrough subtree cannot be framed"
        );
        assert_eq!(
            shape(Unencryptable::DroppedChild),
            "cannot encrypt: a child sink was dropped without a value"
        );
        assert_eq!(
            shape(Unencryptable::TooDeep),
            "cannot encrypt: value nests deeper than 128 levels"
        );
        assert_eq!(
            EncryptError::<&str>::Count(LeafCount::TooFew).to_string(),
            "cipher returned too few leaves"
        );
        assert_eq!(
            EncryptError::<&str>::Cipher("down").to_string(),
            "cipher failed: down"
        );
        assert_eq!(
            EncryptError::<&str>::Source(SourceError::msg("getter threw")).to_string(),
            "source failed: getter threw"
        );
        fn is_error<E: core::error::Error>(_: &E) {}
        is_error(&EncryptError::<&str>::Cipher("down"));
        // A source's failure is the chained cause; a cipher's is only in
        // the message, so its type need not be an error.
        use core::error::Error as _;
        let sourced = EncryptError::<&str>::Source(SourceError::msg("getter threw"));
        assert_eq!(
            sourced.source().map(|cause| cause.to_string()),
            Some("getter threw".into())
        );
        assert!(EncryptError::<&str>::Cipher("down").source().is_none());
    }
}
