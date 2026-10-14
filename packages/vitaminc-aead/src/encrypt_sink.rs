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
//! - duplicate keys are refused;
//! - a container must seal at least one leaf, because a passthrough
//!   authenticates nothing and an all-passthrough container would decrypt
//!   under any AAD;
//! - a passthrough subtree is framed, in the clear.
//!
//! The sink never calls a cipher. It plans a tree of [`Pending`] leaves,
//! each with its plaintext and the AAD its position derives, and
//! [`seal_all`] or [`seal_all_async`] seals them afterwards. So the walk
//! is synchronous whatever the cipher is, and terms collected by a sink
//! teed with this one are complete before the first await.

use core::future::Future;
use core::marker::PhantomData;
use std::collections::HashSet;

use vitaminc_protected::{Controlled, Protected};

use crate::frame::{to_frame, FrameWriteError, PassthroughFrame};
use crate::leaf::{self, ScalarError};
use crate::plaintext::{Error, Logical, MapSink, Physical, Plaintext, SeqSink, Sink, SourceError};
use crate::seal::{
    seal_all, seal_all_async, AsyncCipher, Cipher, LeafCount, Node, Pending, SealError,
};
use crate::{CipherText, Context, IntoAad};

/// Why encryption failed.
#[derive(Debug)]
pub enum EncryptError<E> {
    /// The cipher refused to seal a leaf.
    Cipher(E),
    /// The source stopped the walk.
    Source(SourceError),
    /// The value cannot be encrypted: a duplicate key, a container with
    /// nothing sealed in it, a value that is not valid for its logical type,
    /// a passthrough subtree that cannot be framed, or a cipher that
    /// returned the wrong number of leaves.
    Shape(&'static str),
}

impl<E> Error for EncryptError<E> {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

impl<E> From<FrameWriteError> for EncryptError<E> {
    fn from(error: FrameWriteError) -> Self {
        match error {
            FrameWriteError::Source(e) => Self::Source(e),
            _ => Self::Shape("passthrough subtree cannot be framed"),
        }
    }
}

impl<E> From<SealError<E>> for EncryptError<E> {
    fn from(error: SealError<E>) -> Self {
        match error {
            SealError::Cipher(e) => Self::Cipher(e),
            SealError::Count(LeafCount::TooFew) => Self::Shape("cipher returned too few leaves"),
            SealError::Count(LeafCount::TooMany) => Self::Shape("cipher returned too many leaves"),
        }
    }
}

/// Walk a source into a tree of pending leaves. No cipher is involved:
/// this is the whole of the data-model work, and it is synchronous.
pub fn plan<'a, P, E, A>(value: P, aad: A) -> Result<Node<Pending>, EncryptError<E>>
where
    P: Plaintext,
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
    P: Plaintext,
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
    P: Plaintext,
    C: AsyncCipher,
    A: IntoAad<'a>,
{
    let planned = plan(value, aad);
    async move { Ok(seal_all_async(cipher, planned?).await?) }
}

/// Where a finished node goes: back to the caller, or into a parent.
pub trait Slot {
    type Ok;
    fn put(self, node: Node<Pending>) -> Self::Ok;
}

/// The top of the tree: the node is the result.
pub struct Root;

impl Slot for Root {
    type Ok = Node<Pending>;
    fn put(self, node: Node<Pending>) -> Node<Pending> {
        node
    }
}

/// An element slot in a parent sequence.
pub struct Push<'s>(&'s mut Vec<Node<Pending>>);

impl Slot for Push<'_> {
    type Ok = ();
    fn put(self, node: Node<Pending>) {
        self.0.push(node);
    }
}

/// An entry slot in a parent map.
pub struct Entry<'s>(&'s mut Vec<(String, Node<Pending>)>, String);

impl Slot for Entry<'_> {
    type Ok = ();
    fn put(self, node: Node<Pending>) {
        self.0.push((self.1, node));
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
    _error: PhantomData<E>,
}

impl<E> EncryptSink<E, Root> {
    /// A sink for a whole value under `aad`. Its `Ok` is the planned tree.
    pub fn root<'a>(aad: impl IntoAad<'a>) -> Self {
        Self {
            aad: aad.into_aad().into_owned(),
            out: Root,
            _error: PhantomData,
        }
    }
}

impl<E, O: Slot> EncryptSink<E, O> {
    /// Plan one scalar as one leaf: its tag, then its payload.
    fn leaf(self, ty: Option<Logical>, v: Physical<'_>) -> Result<O::Ok, EncryptError<E>> {
        // Sized once, so the buffer never regrows and leaves a copy behind.
        let mut plaintext = Protected::new(Vec::with_capacity(leaf::max_len(&v)));
        leaf::write_leaf(ty, v, plaintext.risky_inner_mut()).map_err(|e| match e {
            ScalarError::Invalid => EncryptError::Shape("value is not valid for its logical type"),
            ScalarError::TooLong | ScalarError::Malformed => {
                EncryptError::Shape("value cannot be written as a leaf")
            }
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

fn sealed_any<L>(nodes: impl IntoIterator<Item = impl core::borrow::Borrow<Node<L>>>) -> bool {
    nodes
        .into_iter()
        .any(|n| !matches!(n.borrow(), CipherText::Passthrough(_)))
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
        Ok(EncryptSeq {
            element_aad: self.aad.for_sequence_element(),
            aad: self.aad,
            items: Vec::with_capacity(len.unwrap_or(0).min(1024)),
            out: self.out,
            _error: PhantomData,
        })
    }

    fn map(self, _len: Option<usize>) -> Result<Self::Map, Self::Error> {
        Ok(EncryptMap {
            aad: self.aad,
            entries: Vec::new(),
            seen: HashSet::new(),
            out: self.out,
            _error: PhantomData,
        })
    }

    /// Passthrough is non-sensitive by design: it is framed, not sealed.
    fn passthrough<P: Plaintext + Clone>(self, value: P) -> Result<O::Ok, Self::Error> {
        let frame = to_frame(value)?;
        Ok(self.out.put(CipherText::Passthrough(PassthroughFrame(
            frame.risky_ref().to_vec(),
        ))))
    }
}

pub struct EncryptSeq<E, O> {
    aad: Context<'static>,
    element_aad: Context<'static>,
    items: Vec<Node<Pending>>,
    out: O,
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
            out: Push(&mut self.items),
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        let node = if self.items.is_empty() {
            CipherText::EmptySequence(marker(self.aad.for_empty_sequence()))
        } else if !sealed_any(&self.items) {
            return Err(EncryptError::Shape("sequence has nothing sealed"));
        } else {
            CipherText::Sequence(self.items)
        };
        Ok(self.out.put(node))
    }
}

pub struct EncryptMap<E, O> {
    aad: Context<'static>,
    entries: Vec<(String, Node<Pending>)>,
    seen: HashSet<String>,
    out: O,
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
        if !self.seen.insert(key.to_owned()) {
            return Err(EncryptError::Shape("duplicate key"));
        }
        Ok(EncryptSink {
            aad: self.aad.for_map_entry(key),
            out: Entry(&mut self.entries, key.to_owned()),
            _error: PhantomData,
        })
    }

    fn end(self) -> Result<O::Ok, Self::Error> {
        let node = if self.entries.is_empty() {
            CipherText::EmptyMap(marker(self.aad.for_empty_map()))
        } else if !sealed_any(self.entries.iter().map(|(_, n)| n)) {
            return Err(EncryptError::Shape("map has nothing sealed"));
        } else {
            CipherText::Map(self.entries)
        };
        Ok(self.out.put(node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::{visit_seq, Int, Raw};
    use crate::seal::leaves_with_aad;
    use crate::seal::mock::{Mock, Refused};
    use crate::Tee;
    use std::collections::BTreeMap;

    fn planned<P: Plaintext>(p: P) -> Result<Node<Pending>, EncryptError<Refused>> {
        plan(p, "ctx")
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
        struct Dup;
        impl Plaintext for Dup {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(None)?;
                1u32.visit(map.entry("k")?)?;
                2u32.visit(map.entry("k")?)?;
                map.end()
            }
        }
        assert!(matches!(
            planned(Dup),
            Err(EncryptError::Shape("duplicate key"))
        ));
    }

    #[test]
    fn an_all_passthrough_container_is_refused() {
        struct Pass;
        impl Plaintext for Pass {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough("public")
            }
        }
        assert!(matches!(
            planned(vec![Pass]),
            Err(EncryptError::Shape("sequence has nothing sealed"))
        ));
        let mut map = BTreeMap::new();
        map.insert("note", Pass);
        assert!(matches!(
            planned(map),
            Err(EncryptError::Shape("map has nothing sealed"))
        ));
        // One sealed sibling is enough.
        struct Mixed;
        impl Plaintext for Mixed {
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
        assert!(matches!(
            planned(bad),
            Err(EncryptError::Shape(
                "value is not valid for its logical type"
            ))
        ));
    }

    #[test]
    fn a_source_error_stops_the_walk() {
        struct Failing;
        impl Plaintext for Failing {
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
        fn passthrough<P: Plaintext + Clone>(self, _: P) -> Result<(), E> {
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
        impl Plaintext for Unsized {
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
}
