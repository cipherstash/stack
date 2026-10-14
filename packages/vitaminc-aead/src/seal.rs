//! Sealing and opening leaves: the cipher traits, and the traversals that
//! take a tree apart into leaves and put it back together.
//!
//! A cipher does two things, seal one leaf and open one leaf. Everything
//! about containers (element and entry AAD, the empty markers, duplicate
//! keys, what counts as sealed) lives in
//! [`EncryptSink`](crate::EncryptSink) and [`walk`](crate::walk), so a
//! second cipher cannot diverge on it.
//!
//! [`Cipher`] is synchronous. [`AsyncCipher`] is for anything that has to
//! be awaited: a remote key provider, a KMS, a cloud HSM. Its `seal_many`
//! and `open_many` take every leaf of one document at once, so a provider
//! with a batch API makes one round trip per document. The walk itself is
//! never awaited: encryption plans a tree of [`Pending`] leaves first, and
//! decryption opens every leaf before the sink sees anything.
//!
//! These traits will replace [`Cipher`](crate::Cipher) and
//! [`Decipher`](crate::Decipher). Until those are removed they are reached
//! through this module rather than the crate root.

use core::future::Future;
use std::collections::HashSet;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use vitaminc_protected::Protected;

use crate::frame::PassthroughFrame;
use crate::{CipherText, Context};

/// A ciphertext tree whose passthrough subtrees are frames.
pub type Node<L> = CipherText<L, PassthroughFrame>;

/// A leaf the walk has planned but nobody has sealed: its tagged plaintext
/// and the AAD derived for its place in the tree.
pub struct Pending {
    pub plaintext: Protected<Vec<u8>>,
    pub aad: Context<'static>,
}

/// A leaf after opening: its tagged plaintext.
pub type Opened = Protected<Vec<u8>>;

/// Seal and open one leaf, synchronously.
///
/// The `aad` is the caller-visible context for the leaf's position. The
/// cipher binds the wire version into it itself
/// ([`Context::for_leaf`]) at the AEAD boundary.
pub trait Cipher {
    /// The sealed leaf.
    type Leaf;
    /// Kept opaque: see [`Unspecified`](crate::Unspecified).
    type Error;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: &Context<'_>,
    ) -> Result<Self::Leaf, Self::Error>;

    fn open(&self, leaf: Self::Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Self::Error>;
}

/// Seal and open leaves through something that has to be awaited.
///
/// `seal_many` and `open_many` take every leaf of one document in walk
/// order. The defaults seal each leaf concurrently, at most
/// [`DEFAULT_CONCURRENCY`] at a time; a provider with a batch API
/// overrides them to make one round trip per document. Either way the
/// cipher must return exactly one leaf per leaf it was given, in the same
/// order, or the document is refused.
///
/// `Sync`, because an async cipher is shared across tasks.
pub trait AsyncCipher: Sync {
    type Leaf: Send;
    type Error: Send;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: Context<'static>,
    ) -> impl Future<Output = Result<Self::Leaf, Self::Error>> + Send;

    fn open(
        &self,
        leaf: Self::Leaf,
        aad: Context<'static>,
    ) -> impl Future<Output = Result<Protected<Vec<u8>>, Self::Error>> + Send;

    /// Every pending leaf of one document, in walk order.
    fn seal_many(
        &self,
        leaves: Vec<Pending>,
    ) -> impl Future<Output = Result<Vec<Self::Leaf>, Self::Error>> + Send {
        stream::iter(leaves)
            .map(|p| self.seal(p.plaintext, p.aad))
            .buffered(DEFAULT_CONCURRENCY)
            .try_collect()
    }

    /// Every sealed leaf of one document with the AAD its position derives,
    /// in walk order.
    fn open_many(
        &self,
        leaves: Vec<(Self::Leaf, Context<'static>)>,
    ) -> impl Future<Output = Result<Vec<Protected<Vec<u8>>>, Self::Error>> + Send {
        stream::iter(leaves)
            .map(|(leaf, aad)| self.open(leaf, aad))
            .buffered(DEFAULT_CONCURRENCY)
            .try_collect()
    }
}

/// How many leaves the default `seal_many` and `open_many` have in flight
/// at once, so a large document does not send every leaf to a remote
/// provider at the same moment.
pub const DEFAULT_CONCURRENCY: usize = 32;

/// A cipher returned a different number of leaves than it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafCount {
    TooFew,
    TooMany,
}

/// Seal every pending leaf, one at a time.
pub fn seal_all<C: Cipher>(
    cipher: &C,
    node: Node<Pending>,
) -> Result<Node<C::Leaf>, SealError<C::Error>> {
    let mut pending = Vec::new();
    let shape = split(node, &mut pending);
    let leaves = pending
        .into_iter()
        .map(|p| cipher.seal(p.plaintext, &p.aad))
        .collect::<Result<Vec<_>, _>>()
        .map_err(SealError::Cipher)?;
    fill(shape, leaves).map_err(SealError::Count)
}

/// Seal every pending leaf in one `seal_many` call.
pub async fn seal_all_async<C: AsyncCipher>(
    cipher: &C,
    node: Node<Pending>,
) -> Result<Node<C::Leaf>, SealError<C::Error>> {
    let mut pending = Vec::new();
    let shape = split(node, &mut pending);
    let leaves = cipher.seal_many(pending).await.map_err(SealError::Cipher)?;
    fill(shape, leaves).map_err(SealError::Count)
}

/// Why sealing failed.
#[derive(Debug)]
pub enum SealError<E> {
    Cipher(E),
    Count(LeafCount),
}

/// Open every leaf, one at a time.
///
/// The tree's structure is checked before any leaf is opened, so a
/// malformed tree costs no cipher calls. A cipher's failure is returned as
/// it is: for an AEAD that is wrong key, wrong AAD or tampering, for a
/// remote provider it may also be an outage, and the cipher's error type
/// says which. A leaf count mismatch is a cipher bug.
pub fn open_all<'a, C: Cipher>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: &Context<'a>,
) -> Result<Node<Opened>, OpenError<C::Error>> {
    check_shape(&node)?;
    let mut sealed = Vec::new();
    let shape = split_with_aad(node, aad, &mut sealed);
    let opened = sealed
        .into_iter()
        .map(|(leaf, aad)| cipher.open(leaf, &aad))
        .collect::<Result<Vec<_>, _>>()
        .map_err(OpenError::Cipher)?;
    fill(shape, opened).map_err(OpenError::Count)
}

/// Open every leaf in one `open_many` call, after the same structural
/// check as [`open_all`].
pub async fn open_all_async<'a, C: AsyncCipher>(
    cipher: &C,
    node: Node<C::Leaf>,
    aad: &Context<'a>,
) -> Result<Node<Opened>, OpenError<C::Error>> {
    check_shape(&node)?;
    let mut sealed = Vec::new();
    let shape = split_with_aad(node, aad, &mut sealed);
    let opened = cipher.open_many(sealed).await.map_err(OpenError::Cipher)?;
    fill(shape, opened).map_err(OpenError::Count)
}

/// Why opening failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError<E> {
    /// The cipher refused a leaf.
    Cipher(E),
    /// The tree breaks a container rule: a container with nothing sealed
    /// in it, a repeated map key, or a passthrough that is not a frame.
    Malformed,
    /// The cipher returned the wrong number of leaves.
    Count(LeafCount),
}

/// The container rules `EncryptSink` enforced, checked on the sealed tree
/// so a malformed one is refused before any leaf is opened. `walk`
/// checks them again, since it accepts opened trees from anywhere.
fn check_shape<L, E>(node: &Node<L>) -> Result<(), OpenError<E>> {
    let sealed_any = |mut nodes: core::slice::Iter<'_, Node<L>>| {
        nodes.any(|n| !matches!(n, CipherText::Passthrough(_)))
    };
    match node {
        CipherText::Sequence(items) => {
            if !sealed_any(items.iter()) {
                return Err(OpenError::Malformed);
            }
            items.iter().try_for_each(check_shape)
        }
        CipherText::Map(entries) => {
            let mut seen = HashSet::new();
            if !entries.iter().all(|(k, _)| seen.insert(k.as_str()))
                || !entries
                    .iter()
                    .any(|(_, n)| !matches!(n, CipherText::Passthrough(_)))
            {
                return Err(OpenError::Malformed);
            }
            entries.iter().try_for_each(|(_, n)| check_shape(n))
        }
        CipherText::Passthrough(frame) => {
            frame.parse().map(|_| ()).map_err(|_| OpenError::Malformed)
        }
        CipherText::Single(_)
        | CipherText::EmptySequence(_)
        | CipherText::EmptyMap(_)
        | CipherText::None(_) => Ok(()),
    }
}

/// A tree's shape with its leaves taken out, in walk order.
fn split<L>(node: Node<L>, leaves: &mut Vec<L>) -> Node<()> {
    match node {
        CipherText::Single(leaf) => {
            leaves.push(leaf);
            CipherText::Single(())
        }
        CipherText::Sequence(items) => {
            CipherText::Sequence(items.into_iter().map(|n| split(n, leaves)).collect())
        }
        CipherText::EmptySequence(leaf) => {
            leaves.push(leaf);
            CipherText::EmptySequence(())
        }
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, n)| (k, split(n, leaves)))
                .collect(),
        ),
        CipherText::EmptyMap(leaf) => {
            leaves.push(leaf);
            CipherText::EmptyMap(())
        }
        CipherText::None(leaf) => {
            leaves.push(leaf);
            CipherText::None(())
        }
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    }
}

/// A tree's shape with its leaves taken out, each paired with the AAD its
/// position derives. The derivations are the ones `EncryptSink` used.
fn split_with_aad<L>(
    node: Node<L>,
    aad: &Context<'_>,
    leaves: &mut Vec<(L, Context<'static>)>,
) -> Node<()> {
    match node {
        CipherText::Single(leaf) => {
            leaves.push((leaf, aad.clone().into_owned()));
            CipherText::Single(())
        }
        CipherText::Sequence(items) => {
            let element_aad = aad.for_sequence_element();
            CipherText::Sequence(
                items
                    .into_iter()
                    .map(|n| split_with_aad(n, &element_aad, leaves))
                    .collect(),
            )
        }
        CipherText::EmptySequence(leaf) => {
            leaves.push((leaf, aad.for_empty_sequence()));
            CipherText::EmptySequence(())
        }
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, n)| {
                    let shape = split_with_aad(n, &aad.for_map_entry(&k), leaves);
                    (k, shape)
                })
                .collect(),
        ),
        CipherText::EmptyMap(leaf) => {
            leaves.push((leaf, aad.for_empty_map()));
            CipherText::EmptyMap(())
        }
        // Only a ciphertext written by the `Encrypt` path has this node;
        // the sink writes `None` as a null leaf.
        CipherText::None(leaf) => {
            leaves.push((leaf, aad.for_none()));
            CipherText::None(())
        }
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    }
}

/// Put leaves back into a shape, in walk order.
fn fill<L>(shape: Node<()>, leaves: Vec<L>) -> Result<Node<L>, LeafCount> {
    let mut leaves = leaves.into_iter();
    let node = fill_from(shape, &mut leaves).ok_or(LeafCount::TooFew)?;
    if leaves.next().is_some() {
        return Err(LeafCount::TooMany);
    }
    Ok(node)
}

fn fill_from<L>(shape: Node<()>, leaves: &mut impl Iterator<Item = L>) -> Option<Node<L>> {
    Some(match shape {
        CipherText::Single(()) => CipherText::Single(leaves.next()?),
        CipherText::Sequence(items) => CipherText::Sequence(
            items
                .into_iter()
                .map(|n| fill_from(n, leaves))
                .collect::<Option<_>>()?,
        ),
        CipherText::EmptySequence(()) => CipherText::EmptySequence(leaves.next()?),
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(k, n)| fill_from(n, leaves).map(|n| (k, n)))
                .collect::<Option<_>>()?,
        ),
        CipherText::EmptyMap(()) => CipherText::EmptyMap(leaves.next()?),
        CipherText::None(()) => CipherText::None(leaves.next()?),
        CipherText::Passthrough(p) => CipherText::Passthrough(p),
    })
}

/// Every leaf of a tree, in walk order, with the AAD its position derives.
/// For tests and for ciphers that inspect a plan.
pub fn leaves_with_aad<L>(node: Node<L>, aad: &Context<'_>) -> Vec<(L, Context<'static>)> {
    let mut out = Vec::new();
    split_with_aad(node, aad, &mut out);
    out
}

/// A cipher that stores the plaintext and AAD in the clear, for tests of
/// the traversals and the sink. Opening checks the AAD matches.
#[cfg(test)]
pub(crate) mod mock {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use futures_util::future::try_join_all;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Leaf {
        pub aad: Vec<u8>,
        pub plaintext: Vec<u8>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Refused;

    #[derive(Default)]
    pub struct Mock;

    impl Cipher for Mock {
        type Leaf = Leaf;
        type Error = Refused;

        fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Leaf, Refused> {
            Ok(Leaf {
                aad: aad.as_bytes().to_vec(),
                plaintext: vitaminc_protected::Controlled::risky_unwrap(plaintext),
            })
        }

        fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
            if leaf.aad != aad.as_bytes() {
                return Err(Refused);
            }
            Ok(Protected::new(leaf.plaintext))
        }
    }

    /// The mock behind an await, counting calls. `batch` decides whether
    /// `seal_many`/`open_many` are one call or the per-leaf defaults.
    pub struct Remote {
        pub calls: AtomicUsize,
        pub batch: bool,
    }

    impl Remote {
        pub fn new(batch: bool) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                batch,
            }
        }

        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl AsyncCipher for Remote {
        type Leaf = Leaf;
        type Error = Refused;

        async fn seal(
            &self,
            plaintext: Protected<Vec<u8>>,
            aad: Context<'static>,
        ) -> Result<Leaf, Refused> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Cipher::seal(&Mock, plaintext, &aad)
        }

        async fn open(
            &self,
            leaf: Leaf,
            aad: Context<'static>,
        ) -> Result<Protected<Vec<u8>>, Refused> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Cipher::open(&Mock, leaf, &aad)
        }

        async fn seal_many(&self, leaves: Vec<Pending>) -> Result<Vec<Leaf>, Refused> {
            if !self.batch {
                return try_join_all(leaves.into_iter().map(|p| self.seal(p.plaintext, p.aad)))
                    .await;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            leaves
                .into_iter()
                .map(|p| Cipher::seal(&Mock, p.plaintext, &p.aad))
                .collect()
        }

        async fn open_many(
            &self,
            leaves: Vec<(Leaf, Context<'static>)>,
        ) -> Result<Vec<Protected<Vec<u8>>>, Refused> {
            if !self.batch {
                return try_join_all(leaves.into_iter().map(|(l, aad)| self.open(l, aad))).await;
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            leaves
                .into_iter()
                .map(|(l, aad)| Cipher::open(&Mock, l, &aad))
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{Leaf, Mock, Refused, Remote};
    use super::*;
    use crate::frame::PassthroughFrame;
    use crate::plaintext::record::{record, Event, Owned};
    use crate::{decrypt_into, encrypt, encrypt_async, plan, walk, EncryptError, Int, IntoAad};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use futures_executor::block_on;
    use std::collections::BTreeMap;
    use vitaminc_protected::Controlled;

    fn sample() -> BTreeMap<&'static str, Vec<Option<u32>>> {
        let mut m = BTreeMap::new();
        m.insert("a", vec![Some(1), None, Some(3)]);
        m.insert("b", vec![]);
        m.insert("c", vec![Some(4)]);
        m
    }

    #[test]
    fn leaves_come_out_in_walk_order_with_their_own_aad() {
        let planned = plan::<_, Refused, _>(sample(), "ctx").expect("plans");
        let leaves = leaves_with_aad(planned, &"ctx".into_aad());
        // a: three elements, b: one empty marker, c: one element.
        assert_eq!(leaves.len(), 5);
        let a = "ctx".into_aad().for_map_entry("a").for_sequence_element();
        assert_eq!(leaves[0].1, a);
        assert_eq!(leaves[1].1, a);
        assert_eq!(leaves[2].1, a);
        assert_eq!(
            leaves[3].1,
            "ctx".into_aad().for_map_entry("b").for_empty_sequence()
        );
        assert_eq!(
            leaves[4].1,
            "ctx".into_aad().for_map_entry("c").for_sequence_element()
        );
        // The marker is empty; the null leaf is a NULL tag.
        assert!(leaves[3].0.plaintext.risky_ref().is_empty());
        assert_eq!(leaves[1].0.plaintext.risky_ref(), &[0x00]);
        // And the plan's AAD is what the sealed leaf is bound under.
        let sealed = encrypt(sample(), &Mock, "ctx").expect("encrypts");
        let sealed = leaves_with_aad(sealed, &"ctx".into_aad());
        assert!(sealed.iter().all(|(leaf, aad)| leaf.aad == aad.as_bytes()));
    }

    #[test]
    fn open_then_walk_is_the_original() {
        let sealed = encrypt(sample(), &Mock, "ctx").expect("encrypts");
        let opened = open_all(&Mock, sealed, &"ctx".into_aad()).expect("opens");
        let mut log = Vec::new();
        walk(opened, crate::plaintext::record::Record(&mut log)).expect("walks");
        assert_eq!(log, record(sample()).expect("records"));
    }

    #[test]
    fn a_wrong_aad_fails_to_open() {
        let sealed = encrypt(sample(), &Mock, "ctx").expect("encrypts");
        assert_eq!(
            open_all(&Mock, sealed, &"other".into_aad()).err(),
            Some(OpenError::Cipher(Refused))
        );
    }

    /// Counts opens, so a test can see that a malformed tree costs none.
    struct Counting(core::cell::Cell<usize>);

    impl Cipher for Counting {
        type Leaf = Leaf;
        type Error = Refused;
        fn seal(&self, plaintext: Protected<Vec<u8>>, aad: &Context<'_>) -> Result<Leaf, Refused> {
            Mock.seal(plaintext, aad)
        }
        fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
            self.0.set(self.0.get() + 1);
            Mock.open(leaf, aad)
        }
    }

    #[test]
    fn a_malformed_tree_is_refused_before_any_leaf_is_opened() {
        let leaf = || match encrypt(1u16, &Mock, "ctx").expect("encrypts") {
            CipherText::Single(leaf) => leaf,
            _ => unreachable!(),
        };
        let passthrough = || CipherText::Passthrough(PassthroughFrame(vec![0x00]));
        let malformed: [Node<Leaf>; 4] = [
            CipherText::Map(vec![
                ("k".into(), CipherText::Single(leaf())),
                ("k".into(), CipherText::Single(leaf())),
            ]),
            CipherText::Sequence(vec![passthrough(), passthrough()]),
            CipherText::Sequence(vec![]),
            CipherText::Sequence(vec![
                CipherText::Single(leaf()),
                CipherText::Passthrough(PassthroughFrame(vec![0xEF])),
            ]),
        ];
        for node in malformed {
            let cipher = Counting(core::cell::Cell::new(0));
            assert_eq!(
                open_all(&cipher, node, &"ctx".into_aad()).err(),
                Some(OpenError::Malformed)
            );
            assert_eq!(cipher.0.get(), 0);
        }
    }

    #[test]
    fn a_provider_error_on_open_is_not_reported_as_tampering() {
        struct Down;
        impl AsyncCipher for Down {
            type Leaf = Leaf;
            type Error = &'static str;
            async fn seal(
                &self,
                p: Protected<Vec<u8>>,
                aad: Context<'static>,
            ) -> Result<Leaf, &'static str> {
                Mock.seal(p, &aad).map_err(|_| "refused")
            }
            async fn open(
                &self,
                _: Leaf,
                _: Context<'static>,
            ) -> Result<Protected<Vec<u8>>, &'static str> {
                Err("kms unavailable")
            }
        }
        let sealed = encrypt(34u32, &Mock, ()).expect("encrypts");
        let mut log = Vec::new();
        assert!(matches!(
            block_on(crate::decrypt_into_async(
                &Down,
                sealed,
                (),
                crate::plaintext::record::Record(&mut log)
            )),
            Err(crate::DecryptError::Cipher("kms unavailable"))
        ));
    }

    /// Tracks how many leaves are in flight at once through the default
    /// `seal_many`/`open_many`. Each call yields once, so the stream has to
    /// hold several open to make progress.
    #[derive(Default)]
    struct Concurrency {
        now: AtomicUsize,
        max: AtomicUsize,
    }

    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();
        fn poll(
            mut self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            if self.0 {
                return core::task::Poll::Ready(());
            }
            self.0 = true;
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    }

    impl Concurrency {
        async fn one<T>(&self, f: impl FnOnce() -> T) -> T {
            let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.max.fetch_max(now, Ordering::SeqCst);
            YieldOnce(false).await;
            self.now.fetch_sub(1, Ordering::SeqCst);
            f()
        }
    }

    impl AsyncCipher for Concurrency {
        type Leaf = Leaf;
        type Error = Refused;
        async fn seal(
            &self,
            p: Protected<Vec<u8>>,
            aad: Context<'static>,
        ) -> Result<Leaf, Refused> {
            self.one(|| Mock.seal(p, &aad)).await
        }
        async fn open(
            &self,
            l: Leaf,
            aad: Context<'static>,
        ) -> Result<Protected<Vec<u8>>, Refused> {
            self.one(|| Mock.open(l, &aad)).await
        }
    }

    #[test]
    fn the_default_batch_bounds_how_many_leaves_are_in_flight() {
        let cipher = Concurrency::default();
        let many: Vec<u32> = (0..200).collect();
        let sealed = block_on(encrypt_async(many.clone(), &cipher, "ctx")).expect("encrypts");
        let max = cipher.max.load(Ordering::SeqCst);
        assert!(max > 1 && max <= DEFAULT_CONCURRENCY, "{max}");
        let mut log = Vec::new();
        block_on(crate::decrypt_into_async(
            &cipher,
            sealed,
            "ctx",
            crate::plaintext::record::Record(&mut log),
        ))
        .expect("decrypts");
        assert!(cipher.max.load(Ordering::SeqCst) <= DEFAULT_CONCURRENCY);
        assert_eq!(log, record(many).expect("records"));
    }

    #[test]
    fn encrypt_async_walks_before_returning_a_send_future() {
        // A source a JavaScript binding might hand over: not `Send`.
        #[derive(Clone)]
        struct Local(std::rc::Rc<u32>);
        impl crate::Plaintext for Local {
            fn visit<S: crate::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                (*self.0).visit(sink)
            }
        }
        fn assert_send<T: Send>(t: T) -> T {
            t
        }
        let remote = Remote::new(true);
        let future = assert_send(encrypt_async(Local(std::rc::Rc::new(34)), &remote, "ctx"));
        assert_eq!(remote.calls(), 0);
        block_on(future).expect("encrypts");
        assert_eq!(remote.calls(), 1);
    }

    #[test]
    fn a_cipher_that_miscounts_is_refused() {
        struct DropsOne;
        impl Cipher for DropsOne {
            type Leaf = Leaf;
            type Error = Refused;
            fn seal(
                &self,
                plaintext: Protected<Vec<u8>>,
                aad: &Context<'_>,
            ) -> Result<Leaf, Refused> {
                Mock.seal(plaintext, aad)
            }
            fn open(&self, leaf: Leaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Refused> {
                Mock.open(leaf, aad)
            }
        }
        struct Extra(Remote);
        impl AsyncCipher for Extra {
            type Leaf = Leaf;
            type Error = Refused;
            async fn seal(
                &self,
                plaintext: Protected<Vec<u8>>,
                aad: Context<'static>,
            ) -> Result<Leaf, Refused> {
                self.0.seal(plaintext, aad).await
            }
            async fn open(
                &self,
                leaf: Leaf,
                aad: Context<'static>,
            ) -> Result<Protected<Vec<u8>>, Refused> {
                self.0.open(leaf, aad).await
            }
            async fn seal_many(&self, leaves: Vec<Pending>) -> Result<Vec<Leaf>, Refused> {
                let mut out = self.0.seal_many(leaves).await?;
                out.push(out[0].clone());
                Ok(out)
            }
            async fn open_many(
                &self,
                mut leaves: Vec<(Leaf, Context<'static>)>,
            ) -> Result<Vec<Protected<Vec<u8>>>, Refused> {
                leaves.pop();
                self.0.open_many(leaves).await
            }
        }
        let extra = Extra(Remote::new(true));
        assert!(matches!(
            block_on(encrypt_async(sample(), &extra, "ctx")),
            Err(EncryptError::Shape("cipher returned too many leaves"))
        ));
        let sealed = encrypt(sample(), &DropsOne, "ctx").expect("encrypts");
        assert_eq!(
            block_on(open_all_async(&extra, sealed, &"ctx".into_aad())).err(),
            Some(OpenError::<Refused>::Count(LeafCount::TooFew))
        );
    }

    #[test]
    fn a_batching_cipher_makes_one_round_trip_each_way() {
        let remote = Remote::new(true);
        let sealed = block_on(encrypt_async(sample(), &remote, "ctx")).expect("encrypts");
        assert_eq!(remote.calls(), 1);
        let mut log = Vec::new();
        block_on(crate::decrypt_into_async(
            &remote,
            sealed,
            "ctx",
            crate::plaintext::record::Record(&mut log),
        ))
        .expect("decrypts");
        assert_eq!(remote.calls(), 2);
        assert_eq!(log, record(sample()).expect("records"));
    }

    #[test]
    fn without_a_batch_api_each_leaf_is_its_own_call() {
        let remote = Remote::new(false);
        let sealed = block_on(encrypt_async(sample(), &remote, "ctx")).expect("encrypts");
        assert_eq!(remote.calls(), 5);
        let mut log = Vec::new();
        block_on(crate::decrypt_into_async(
            &remote,
            sealed,
            "ctx",
            crate::plaintext::record::Record(&mut log),
        ))
        .expect("decrypts");
        assert_eq!(remote.calls(), 10);
    }

    #[test]
    fn sync_and_async_ciphers_read_each_others_leaves() {
        let remote = Remote::new(true);
        let sealed = block_on(encrypt_async(34u32, &remote, ())).expect("encrypts");
        let mut log = Vec::new();
        decrypt_into(
            &Mock,
            sealed,
            (),
            crate::plaintext::record::Record(&mut log),
        )
        .expect("decrypts");
        assert_eq!(log, [Event::Scalar(None, Owned::Int(Int::U32(34)))]);
    }

    #[test]
    fn a_cipher_failure_fails_the_document() {
        struct Down;
        impl AsyncCipher for Down {
            type Leaf = Leaf;
            type Error = &'static str;
            async fn seal(
                &self,
                _: Protected<Vec<u8>>,
                _: Context<'static>,
            ) -> Result<Leaf, &'static str> {
                Err("key provider unavailable")
            }
            async fn open(
                &self,
                _: Leaf,
                _: Context<'static>,
            ) -> Result<Protected<Vec<u8>>, &'static str> {
                Err("key provider unavailable")
            }
        }
        assert!(matches!(
            block_on(encrypt_async(34u32, &Down, ())),
            Err(EncryptError::Cipher("key provider unavailable"))
        ));
    }
}
