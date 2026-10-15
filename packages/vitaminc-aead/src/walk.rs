//! Decrypt into any sink.
//!
//! Two steps, mirroring encryption:
//!
//! 1. [`open_all`] or [`open_all_async`]: derive each leaf's AAD from its
//!    position, open every leaf (one `open_many` call for an async cipher),
//!    and put the plaintexts back into the tree.
//! 2. [`walk`]: feed the opened tree to the sink, scalar by scalar,
//!    physical plus logical. A Go guest passes a
//!    [`FrameWriter`](crate::frame::FrameWriter), a Node binding a builder
//!    of JavaScript values, a typed Rust caller the sink its target names.
//!
//! The walk checks the rules the encrypt sink enforced: an empty marker
//! must be empty, a container must have something sealed in it, and map
//! keys must be distinct.

use core::convert::Infallible;
use std::collections::HashSet;

use vitaminc_protected::{Controlled, Protected};

use crate::leaf;
use crate::plaintext::{Error, MapSink, Physical, SeqSink, Sink, SourceError};
use crate::seal::{open_all, open_all_async, AsyncCipher, Cipher, Node, OpenError, Opened};
use crate::{CipherText, IntoAad};

/// Why decryption failed.
///
/// `E` is the sink's error, `C` the cipher's. [`walk`] involves no cipher,
/// so its `C` is [`Infallible`].
#[derive(Debug)]
pub enum DecryptError<E, C = Infallible> {
    /// The cipher refused a leaf. For an AEAD that is a wrong key, a wrong
    /// AAD or a tampered leaf; a remote provider's error type also tells an
    /// outage apart.
    Cipher(C),
    /// An authenticated empty marker carried a payload: tampering the
    /// cipher could not see.
    Auth,
    /// The tree or a leaf's plaintext is not well formed, or the cipher
    /// returned the wrong number of leaves.
    Malformed,
    /// The sink refused what it was given (a typed sink got the wrong kind,
    /// a host builder failed).
    Sink(E),
}

impl<E, C> From<E> for DecryptError<E, C> {
    fn from(e: E) -> Self {
        Self::Sink(e)
    }
}

impl<E> DecryptError<E> {
    /// The same failure, under any cipher error type: a walk's error, as
    /// one step of a decryption.
    pub fn with_cipher<C>(self) -> DecryptError<E, C> {
        match self {
            Self::Cipher(never) => match never {},
            Self::Auth => DecryptError::Auth,
            Self::Malformed => DecryptError::Malformed,
            Self::Sink(e) => DecryptError::Sink(e),
        }
    }
}

fn opening<E, C>(e: OpenError<C>) -> DecryptError<E, C> {
    match e {
        OpenError::Cipher(c) => DecryptError::Cipher(c),
        OpenError::Malformed | OpenError::Count(_) => DecryptError::Malformed,
    }
}

/// Lets a `?` on a sink error inside `walk` also accept source errors.
impl<E: Error, C> Error for DecryptError<E, C> {
    fn source(error: SourceError) -> Self {
        Self::Sink(E::source(error))
    }
}

/// Decrypt into any sink.
pub fn decrypt_into<'a, C, S, A>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: A,
    sink: S,
) -> Result<S::Ok, DecryptError<S::Error, C::Error>>
where
    C: Cipher,
    S: Sink,
    A: IntoAad<'a>,
{
    walk(
        open_all(cipher, node, &aad.into_aad()).map_err(opening)?,
        sink,
    )
    .map_err(DecryptError::with_cipher)
}

/// Decrypt through an async cipher. Every leaf is opened before the sink
/// sees anything, so the sink itself is never awaited.
///
/// The sink is held across the await, so the future is `Send` only if the
/// sink is. A caller with a sink that is not (a builder of JavaScript
/// values) awaits [`open_all_async`] and then calls [`walk`] itself.
pub async fn decrypt_into_async<'a, C, S, A>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: A,
    sink: S,
) -> Result<S::Ok, DecryptError<S::Error, C::Error>>
where
    C: AsyncCipher,
    S: Sink,
    A: IntoAad<'a>,
{
    let opened = open_all_async(cipher, node, &aad.into_aad())
        .await
        .map_err(opening)?;
    walk(opened, sink).map_err(DecryptError::with_cipher)
}

fn sealed_any<'n, L: 'n>(mut nodes: impl Iterator<Item = &'n Node<L>>) -> bool {
    nodes.any(|n| !matches!(n, CipherText::Passthrough(_)))
}

/// Feed an opened tree to a sink.
pub fn walk<S: Sink>(node: Node<Opened>, sink: S) -> Result<S::Ok, DecryptError<S::Error>> {
    let empty_marker = |plaintext: Opened| match plaintext.risky_ref().is_empty() {
        true => Ok(()),
        false => Err(DecryptError::Auth),
    };
    match node {
        CipherText::Single(plaintext) => {
            let (ty, v) =
                leaf::read_leaf(plaintext.risky_ref()).map_err(|_| DecryptError::Malformed)?;
            Ok(sink.scalar(ty, v)?)
            // `plaintext` drops and wipes here.
        }
        CipherText::Sequence(items) => walk_seq(items, sink),
        CipherText::EmptySequence(plaintext) => {
            empty_marker(plaintext)?;
            Ok(sink.seq(Some(0))?.end()?)
        }
        CipherText::Map(entries) => walk_map(entries, sink),
        CipherText::EmptyMap(plaintext) => {
            empty_marker(plaintext)?;
            Ok(sink.map(Some(0))?.end()?)
        }
        // Written only by the `Encrypt` path. The data model has no separate
        // "absent", so it reads as null.
        CipherText::None(plaintext) => {
            empty_marker(plaintext)?;
            Ok(sink.scalar(None, Physical::Null)?)
        }
        CipherText::Passthrough(frame) => {
            let frame = frame.parse().map_err(|_| DecryptError::Malformed)?;
            Ok(sink.passthrough(frame)?)
        }
    }
}

fn walk_seq<S: Sink>(items: Vec<Node<Opened>>, sink: S) -> Result<S::Ok, DecryptError<S::Error>> {
    if !sealed_any(items.iter()) {
        return Err(DecryptError::Malformed);
    }
    let mut seq = sink.seq(Some(items.len()))?;
    for item in items {
        walk(item, seq.element()?)?;
    }
    Ok(seq.end()?)
}

fn walk_map<S: Sink>(
    entries: Vec<(String, Node<Opened>)>,
    sink: S,
) -> Result<S::Ok, DecryptError<S::Error>> {
    let mut seen = HashSet::with_capacity(entries.len());
    if !entries.iter().all(|(k, _)| seen.insert(k.as_str()))
        || !sealed_any(entries.iter().map(|(_, v)| v))
    {
        return Err(DecryptError::Malformed);
    }
    let mut map = sink.map(Some(entries.len()))?;
    for (key, value) in entries {
        walk(value, map.entry(&key)?)?;
    }
    Ok(map.end()?)
}

/// Decrypt into a frame: the Go guest's whole `decrypt`.
///
/// The frame is plaintext, so it is built and returned inside `Protected`
/// and wiped on every error path.
pub fn decrypt_to_frame<'a, C, A>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: A,
) -> Result<Protected<Vec<u8>>, DecryptError<crate::frame::FrameWriteError, C::Error>>
where
    C: Cipher,
    A: IntoAad<'a>,
{
    let mut out = Protected::new(Vec::new());
    decrypt_into(
        cipher,
        node,
        aad,
        crate::frame::FrameWriter::new(out.risky_inner_mut()),
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::record::{record, Event, Owned, Record};
    use crate::seal::leaves_with_aad;
    use crate::seal::mock::{Leaf, Mock};
    use crate::{encrypt, Int, Plaintext};
    use std::collections::BTreeMap;
    use vitaminc_protected::Protected;

    fn sample() -> BTreeMap<&'static str, Vec<Option<u32>>> {
        let mut m = BTreeMap::new();
        m.insert("a", vec![Some(1), None]);
        m.insert("b", vec![]);
        m
    }

    fn round_trip<P: Plaintext + Clone>(p: P) -> Vec<Event> {
        let sealed = encrypt(p, &Mock, "ctx").expect("encrypts");
        let mut log = Vec::new();
        decrypt_into(&Mock, sealed, "ctx", Record(&mut log)).expect("decrypts");
        log
    }

    #[test]
    fn what_goes_in_comes_out() {
        assert_eq!(round_trip(sample()), record(sample()).expect("records"));
        assert_eq!(
            round_trip(34u32),
            [Event::Scalar(None, Owned::Int(Int::U32(34)))]
        );
        assert_eq!(
            round_trip(Vec::<u32>::new()),
            [Event::Seq(Some(0)), Event::EndSeq]
        );
        assert_eq!(
            round_trip(BTreeMap::<&str, u32>::new()),
            [Event::Map(Some(0)), Event::EndMap]
        );
    }

    #[test]
    fn passthrough_comes_back_as_a_walk() {
        #[derive(Clone)]
        struct Doc;
        impl Plaintext for Doc {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(Some(2))?;
                map.entry("id")?.passthrough(vec![7u16])?;
                "secret".visit(map.entry("name")?)?;
                map.end()
            }
        }
        assert_eq!(
            round_trip(Doc),
            [
                Event::Map(Some(2)),
                Event::Entry("id".into()),
                Event::Passthrough,
                Event::Seq(Some(1)),
                Event::Element,
                Event::Scalar(None, Owned::Int(Int::U16(7))),
                Event::EndSeq,
                Event::Entry("name".into()),
                Event::Scalar(None, Owned::Text("secret".into())),
                Event::EndMap,
            ]
        );
    }

    #[test]
    fn a_none_node_from_the_old_path_reads_as_null() {
        let aad = "ctx".into_aad();
        let node: Node<Leaf> = CipherText::None(Leaf {
            aad: aad.for_none().as_bytes().to_vec(),
            plaintext: vec![],
        });
        let mut log = Vec::new();
        decrypt_into(&Mock, node, "ctx", Record(&mut log)).expect("decrypts");
        assert_eq!(log, [Event::Scalar(None, Owned::Null)]);
    }

    #[test]
    fn a_walk_error_keeps_its_kind_under_any_cipher_error() {
        let widen = |e: DecryptError<u8>| e.with_cipher::<&str>();
        assert!(matches!(widen(DecryptError::Auth), DecryptError::Auth));
        assert!(matches!(
            widen(DecryptError::Malformed),
            DecryptError::Malformed
        ));
        assert!(matches!(
            widen(DecryptError::Sink(7)),
            DecryptError::Sink(7)
        ));
    }

    #[test]
    fn a_marker_that_is_not_empty_is_an_auth_failure() {
        let node: Node<Opened> = CipherText::EmptySequence(Protected::new(vec![1]));
        assert!(matches!(
            walk(node, Record(&mut Vec::new())),
            Err(DecryptError::Auth)
        ));
    }

    #[test]
    fn a_malformed_tree_is_refused() {
        let leaf = |bytes: &[u8]| CipherText::Single(Protected::new(bytes.to_vec()));
        // A leaf that is not a scalar.
        assert!(matches!(
            walk(leaf(&[0xFF]), Record(&mut Vec::new())),
            Err(DecryptError::Malformed)
        ));
        // Duplicate keys.
        let node: Node<Opened> = CipherText::Map(vec![
            ("k".into(), leaf(&[0x00])),
            ("k".into(), leaf(&[0x00])),
        ]);
        assert!(matches!(
            walk(node, Record(&mut Vec::new())),
            Err(DecryptError::Malformed)
        ));
        // Nothing sealed.
        let node: Node<Opened> =
            CipherText::Sequence(vec![CipherText::Passthrough(PassthroughFrame(vec![0x00]))]);
        assert!(matches!(
            walk(node, Record(&mut Vec::new())),
            Err(DecryptError::Malformed)
        ));
        // A passthrough that is not a frame.
        let node: Node<Opened> = CipherText::Passthrough(PassthroughFrame(vec![0xF0]));
        assert!(matches!(
            walk(node, Record(&mut Vec::new())),
            Err(DecryptError::Malformed)
        ));
    }

    #[test]
    fn a_leaf_moved_to_another_position_fails_to_open() {
        // Seal `[1]` and try to read its element as a top-level value.
        let sealed = encrypt(vec![1u32], &Mock, "ctx").expect("encrypts");
        let (leaf, _) = leaves_with_aad(sealed, &"ctx".into_aad()).remove(0);
        let moved: Node<Leaf> = CipherText::Single(leaf);
        assert!(matches!(
            decrypt_into(&Mock, moved, "ctx", Record(&mut Vec::new())),
            Err(DecryptError::Cipher(_))
        ));
    }

    #[test]
    fn decrypt_to_frame_is_the_frame_of_the_source() {
        let sealed = encrypt(sample(), &Mock, "ctx").expect("encrypts");
        let frame = decrypt_to_frame(&Mock, sealed, "ctx").expect("decrypts");
        assert_eq!(
            frame.risky_ref(),
            crate::to_frame(sample()).expect("frames").risky_ref()
        );
    }

    use crate::frame::PassthroughFrame;
}
