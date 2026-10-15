//! Context-tagged encryption.
//!
//! This module provides [`ContextTag`], a wrapper that binds additional
//! authenticated data (AAD) to a plaintext value **at the type level**. The
//! AAD is an argument of [`encrypt`](crate::encrypt) and
//! [`decrypt`](crate::decrypt), and a tuple AAD such as `(extra, tag)` is
//! nothing more than [`IntoAad`] composition, but it is opt-in at every call
//! site and easy to forget. `ContextTag` moves the obligation into the type
//! system: a value wrapped in it is encrypted through
//! [`ContextTag::encrypt`] or [`ContextTag::encrypt_with_aad`], which fold the
//! embedded tag in themselves, so it *cannot* be encrypted without its
//! context.
//!
//! Decryption is symmetric. Rebuild the context with [`ContextTag::context`]
//! (and the same [`refine`](ContextTag::refine) chain used at encrypt time),
//! then recover the value with [`ContextTag::decrypt`] or
//! [`ContextTag::decrypt_with_aad`]. Because the tag (and any refinement) is
//! reconstructed by the same code path that bound it, it is never re-typed by
//! hand. For lower-level use against the bare entry points, [`ContextTag::aad`]
//! and [`ContextTag::aad_with`] build the raw AAD tuple the wrapper bound.
//!
//! # AAD encoding
//!
//! The final AAD is the extra AAD and the embedded tag as the tuple
//! `(extra_aad, tag)`, which [`IntoAad`] PAE-encodes:
//!
//! ```text
//! final_aad = PAE(extra_aad, tag)
//! ```
//!
//! PAE (Pre-Authentication Encoding) prefixes each piece with its length,
//! preventing canonicalisation attacks where different inputs could otherwise
//! produce identical byte strings.
//!
//! With [`refine`](ContextTag::refine), the tag itself is a nested tuple that
//! is recursively PAE-encoded:
//!
//! ```text
//! ContextTag::new(data, "a").refine("b")
//!   ──► tag = ("a", "b")
//!   ──► final_aad = PAE(extra_aad, PAE("a", "b"))
//! ```
//!
//! The context keeps its parts intact until it is encoded: `into_context()`
//! on the value the wrapper builds is `List([extra_aad, List(["a", "b"])])`
//! for the example, so a caller that names the parts (a key-management
//! service logging which field a key was issued for) reads them from the
//! tag or the AAD value before encrypting. The cipher itself sees only the
//! encoded bytes of each leaf's derived context ([`Context::for_map_entry`]
//! and the rest apply on top, as for any AAD), not the parts.

use core::future::Future;

use crate::seal::{AsyncCipher, Cipher, Node};
use crate::typed::{DecodeError, Decrypt};
use crate::walk::DecryptError;
use crate::{Context, ContextPiece, EncryptError, IntoAad, IntoContext, Plaintext};

/// Folds a context `tag` and `extra_aad` into the context layout bound by
/// `ContextTag`: the pair `(extra_aad, tag)`.
///
/// This is the layout shared by the type-driven paths: the encrypt methods
/// and the decrypt methods both go through it, so the two sides cannot drift
/// out of sync (a divergence would silently break authentication). The
/// low-level [`ContextTag::aad`] / [`ContextTag::aad_with`] builders reproduce
/// the same `(extra_aad, tag)` layout *by hand* (they must return the
/// unencoded tag for a caller to re-encode), so they are a parallel
/// construction kept in lockstep only by the `aad_helpers_match_the_encrypt_binding`
/// test — if you change the layout here, update those builders too.
///
/// The tag becomes an owned/`'static` [`ContextPiece`] and is re-borrowed for
/// the call's `'a` lifetime (`ContextPiece` is covariant in its lifetime, so
/// `'static: 'a` permits the narrowing). The result is an ordinary pair, so it
/// is a context like any other: its parts are `List([extra_aad, tag])` and its
/// bytes are that list's encoding, written in one allocation.
fn fold_tag_aad<'a, Tag, A>(tag: Tag, extra_aad: A) -> (A, ContextPiece<'a>)
where
    Tag: IntoContext<'static>,
{
    let tag: ContextPiece<'static> = tag.into_context();
    let tag: ContextPiece<'a> = tag;
    (extra_aad, tag)
}

/// A wrapper that pairs a plaintext value with a context tag used as
/// additional authenticated data (AAD).
///
/// `ContextTag` guarantees, at the type level, that `tag` is folded into the
/// AAD whenever `inner` is encrypted. This is the recommended way to enforce
/// that a value is always sealed against a specific context (a user id, table
/// name, column name, …): because the tag is part of the type, the compiler
/// will not let you forget it.
///
/// The tag can be any type that implements [`IntoAad<'static>`](IntoAad) —
/// `&'static str`, `String`, `u64`, `Vec<u8>`, and tuples of these.
/// (Non-`'static` borrowed tags such as a short-lived `&str` are intentionally
/// excluded; promote them to an owned `String` or a `&'static str`.)
///
/// # Encrypting
///
/// ```rust,ignore
/// use vitaminc_aead::ContextTag;
///
/// // `cipher` implements `Cipher` (see `vitaminc_encrypt::Aes256Cipher`).
/// let ciphertext = ContextTag::new("secret message", "user:42").encrypt(&cipher)?;
/// ```
///
/// # Decrypting
///
/// Mirror the encrypt side: rebuild the context with [`ContextTag::context`]
/// (and the same [`refine`](ContextTag::refine) chain, if any), then recover
/// the value with [`decrypt`](ContextTag::decrypt) /
/// [`decrypt_with_aad`](ContextTag::decrypt_with_aad):
///
/// ```rust,ignore
/// use vitaminc_aead::ContextTag;
///
/// let plaintext: String = ContextTag::context("user:42").decrypt(&cipher, ciphertext)?;
/// ```
///
/// # Nesting versus refining
///
/// Layer contexts with [`refine`](ContextTag::refine). Wrapping a
/// `ContextTag` *inside another* would fold the AAD twice, into
/// `((extra, "a"), "b")`, which is not the layout `context("a").refine("b")`
/// decrypts against; it does not compile, because a `ContextTag` is not a
/// [`Plaintext`]:
///
/// ```rust,compile_fail,E0277
/// use vitaminc_aead::{Cipher, ContextTag};
///
/// fn seal<C: Cipher>(cipher: &C) {
///     let _ = ContextTag::new(ContextTag::new("secret", "a"), "b").encrypt(cipher);
/// }
/// ```
///
/// # Async ciphers
///
/// [`encrypt_async`](ContextTag::encrypt_async),
/// [`encrypt_with_aad_async`](ContextTag::encrypt_with_aad_async),
/// [`decrypt_async`](ContextTag::decrypt_async) and
/// [`decrypt_with_aad_async`](ContextTag::decrypt_with_aad_async) are the
/// same methods over an [`AsyncCipher`], binding the same AAD, for a key
/// service that has to be awaited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextTag<Tag, T> {
    inner: T,
    tag: Tag,
}

impl<Tag, T> ContextTag<Tag, T> {
    /// Creates a new `ContextTag` pairing `inner` with the given `tag`.
    ///
    /// The tag is folded into the AAD whenever `inner` is encrypted.
    ///
    /// ```rust
    /// use vitaminc_aead::ContextTag;
    ///
    /// let tagged = ContextTag::new("hello", "my-tag");
    /// # let _ = tagged;
    /// ```
    pub fn new(inner: T, tag: Tag) -> Self {
        ContextTag { inner, tag }
    }

    /// Adds a second layer of context, producing a new `ContextTag` whose tag
    /// is the tuple `(original_tag, tag)`.
    ///
    /// Useful for building hierarchical context such as
    /// `("table:users", "column:email")`. The nested tag is PAE-encoded when
    /// converted to AAD bytes, so distinct hierarchies never collide. `refine`
    /// can be chained to build deeper hierarchies.
    ///
    /// ```rust
    /// use vitaminc_aead::ContextTag;
    ///
    /// let tagged = ContextTag::new("secret", "table:users").refine("column:email");
    /// // The tag is now ("table:users", "column:email").
    /// # let _ = tagged;
    /// ```
    pub fn refine<B>(self, tag: B) -> ContextTag<(Tag, B), T> {
        ContextTag {
            inner: self.inner,
            tag: (self.tag, tag),
        }
    }

    /// Consumes the wrapper, returning the inner value and its tag.
    pub fn into_parts(self) -> (T, Tag) {
        (self.inner, self.tag)
    }
}

impl<Tag, T> ContextTag<Tag, T>
where
    T: Plaintext,
    // The tag is owned by the wrapper, and the AAD lifetime is chosen at the
    // call site. Requiring `IntoAad<'static>` lets the tag become an owned (or
    // `'static`-borrowed) `ContextPiece` that is then re-borrowed for the
    // call's lifetime via covariance. Owned tags (`String`, `u64`, `Vec<u8>`,
    // tuples thereof) and `&'static str` satisfy this; non-`'static` borrows
    // do not — promote them to `String` or a `&'static str`.
    Tag: IntoAad<'static>,
{
    /// Encrypts the inner value, folding the embedded tag into the AAD with
    /// no extra AAD: the bound AAD is `((), tag)`.
    pub fn encrypt<C: Cipher>(self, cipher: &C) -> Result<Node<C::Leaf>, EncryptError<C::Error>> {
        self.encrypt_with_aad(cipher, Context::empty())
    }

    /// Encrypts the inner value, folding the embedded tag into the AAD.
    ///
    /// The final AAD is `(extra_aad, tag)`, PAE-encoded into an unambiguous
    /// byte representation that binds both pieces. The walk derives each
    /// leaf's AAD from it as from any other context.
    pub fn encrypt_with_aad<'a, C, A>(
        self,
        cipher: &C,
        extra_aad: A,
    ) -> Result<Node<C::Leaf>, EncryptError<C::Error>>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let ContextTag { inner, tag } = self;
        crate::encrypt(inner, cipher, fold_tag_aad(tag, extra_aad))
    }

    /// [`encrypt`](ContextTag::encrypt) through an async cipher: the same
    /// AAD, `((), tag)`. The value is walked before this returns, so the
    /// future holds only the planned leaves and is `Send`.
    pub fn encrypt_async<'c, C>(
        self,
        cipher: &'c C,
    ) -> impl Future<Output = Result<Node<C::Leaf>, EncryptError<C::Error>>>
           + Send
           + 'c
           + use<'c, Tag, T, C>
    where
        C: AsyncCipher,
    {
        self.encrypt_with_aad_async(cipher, Context::empty())
    }

    /// [`encrypt_with_aad`](ContextTag::encrypt_with_aad) through an async
    /// cipher: the same AAD, `(extra_aad, tag)`.
    pub fn encrypt_with_aad_async<'a, 'c, C, A>(
        self,
        cipher: &'c C,
        extra_aad: A,
    ) -> impl Future<Output = Result<Node<C::Leaf>, EncryptError<C::Error>>>
           + Send
           + 'c
           + use<'a, 'c, Tag, T, C, A>
    where
        C: AsyncCipher,
        A: IntoAad<'a>,
    {
        let ContextTag { inner, tag } = self;
        crate::encrypt_async(inner, cipher, fold_tag_aad(tag, extra_aad))
    }
}

impl<Tag> ContextTag<Tag, ()> {
    /// Low-level: builds the raw AAD tuple for **decrypting** a value sealed
    /// with `ContextTag::new(value, tag).encrypt(cipher)` (i.e. with no extra
    /// AAD).
    ///
    /// Prefer [`ContextTag::context`] + [`decrypt`](ContextTag::decrypt) — it
    /// folds the AAD for you and reconstructs nested
    /// [`refine`](ContextTag::refine) tags via the same path used at encrypt
    /// time. Reach for `aad` only to drive a bare entry point directly.
    ///
    /// This reproduces the `(empty, tag)` layout the encrypt methods bind, so
    /// a bare entry point authenticates against exactly the same bytes.
    ///
    /// ```rust
    /// use vitaminc_aead::{ContextTag, IntoAad};
    ///
    /// // The AAD recovered for decryption matches what `encrypt` bound at seal time.
    /// let decrypt_aad = ContextTag::aad("user:42");
    /// assert_eq!(
    ///     decrypt_aad.into_aad().as_bytes(),
    ///     ((), "user:42").into_aad().as_bytes(),
    /// );
    /// ```
    pub fn aad(tag: Tag) -> (Context<'static>, Tag) {
        (Context::empty(), tag)
    }

    /// Low-level: builds the raw AAD tuple for **decrypting** a value sealed
    /// with `ContextTag::new(value, tag).encrypt_with_aad(cipher, extra_aad)`.
    ///
    /// Prefer [`ContextTag::context`] + [`decrypt_with_aad`](ContextTag::decrypt_with_aad),
    /// which puts the tag in the receiver so it can't be transposed with
    /// `extra_aad`. This builder takes **both** as positional, same-typed args
    /// (`extra_aad` first, then `tag`) — swapping them silently produces the
    /// wrong AAD, so reach for it only to drive a bare entry point directly.
    ///
    /// Reproduces the `(extra_aad, tag)` layout bound at encrypt time.
    ///
    /// ```rust
    /// use vitaminc_aead::{ContextTag, IntoAad};
    ///
    /// let decrypt_aad = ContextTag::aad_with("row:99", "table:users");
    /// assert_eq!(
    ///     decrypt_aad.into_aad().as_bytes(),
    ///     ("row:99", "table:users").into_aad().as_bytes(),
    /// );
    /// ```
    pub fn aad_with<A>(extra_aad: A, tag: Tag) -> (A, Tag) {
        (extra_aad, tag)
    }

    /// Begins a decrypt-side context carrying `tag` (and no value yet).
    ///
    /// This is the decrypt mirror of [`ContextTag::new`]: build (and
    /// [`refine`](ContextTag::refine)) the tag exactly as you did at encrypt
    /// time, then call [`decrypt`](ContextTag::decrypt) /
    /// [`decrypt_with_aad`](ContextTag::decrypt_with_aad) to recover the value
    /// — so the tag (and any nested refinement) is reconstructed by the same
    /// code path that bound it, never re-typed by hand.
    ///
    /// ```rust
    /// use vitaminc_aead::ContextTag;
    ///
    /// // mirrors `ContextTag::new(value, "table:users").refine("column:email")`
    /// let ctx = ContextTag::context("table:users").refine("column:email");
    /// # let _ = ctx;
    /// ```
    pub fn context(tag: Tag) -> Self {
        ContextTag { inner: (), tag }
    }
}

impl<Tag> ContextTag<Tag, ()>
where
    Tag: IntoAad<'static>,
{
    /// Decrypts a value sealed against this context, authenticating against
    /// the embedded tag (no extra AAD). The decrypt mirror of
    /// [`ContextTag::encrypt`].
    pub fn decrypt<T, C>(
        self,
        cipher: &C,
        node: Node<C::Leaf>,
    ) -> Result<T, DecryptError<DecodeError, C::Error>>
    where
        T: Decrypt,
        C: Cipher,
    {
        self.decrypt_with_aad(cipher, node, Context::empty())
    }

    /// Decrypts a value sealed against this context plus `extra_aad`,
    /// mirroring [`ContextTag::encrypt_with_aad`].
    ///
    /// The tag lives in the receiver and `extra_aad` is the lone AAD argument,
    /// so the two cannot be swapped; the bound AAD is `(extra_aad, tag)` —
    /// byte-identical to what the encrypt side folds in at seal time.
    pub fn decrypt_with_aad<'a, T, C, A>(
        self,
        cipher: &C,
        node: Node<C::Leaf>,
        extra_aad: A,
    ) -> Result<T, DecryptError<DecodeError, C::Error>>
    where
        T: Decrypt,
        C: Cipher,
        A: IntoAad<'a>,
    {
        crate::decrypt(cipher, node, fold_tag_aad(self.tag, extra_aad))
    }

    /// [`decrypt`](ContextTag::decrypt) through an async cipher.
    pub async fn decrypt_async<T, C>(
        self,
        cipher: &C,
        node: Node<C::Leaf>,
    ) -> Result<T, DecryptError<DecodeError, C::Error>>
    where
        T: Decrypt,
        C: AsyncCipher,
    {
        self.decrypt_with_aad_async(cipher, node, Context::empty())
            .await
    }

    /// [`decrypt_with_aad`](ContextTag::decrypt_with_aad) through an async
    /// cipher: the bound AAD is `(extra_aad, tag)`, as on the sync path.
    pub async fn decrypt_with_aad_async<'a, T, C, A>(
        self,
        cipher: &C,
        node: Node<C::Leaf>,
        extra_aad: A,
    ) -> Result<T, DecryptError<DecodeError, C::Error>>
    where
        T: Decrypt,
        C: AsyncCipher,
        A: IntoAad<'a>,
    {
        crate::typed::decrypt_async(cipher, node, fold_tag_aad(self.tag, extra_aad)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::mock::{Leaf, Mock, Refused};
    use crate::{tags, CipherText};
    use std::borrow::Cow;

    /// The one leaf a tagged scalar seals: its AAD bytes and plaintext.
    fn sealed<Tag: IntoAad<'static>>(tagged: ContextTag<Tag, &str>) -> Leaf {
        match tagged.encrypt(&Mock).expect("the mock cannot fail") {
            CipherText::Single(leaf) => leaf,
            other => panic!("a scalar seals as one leaf, got {other:?}"),
        }
    }

    fn sealed_with<'a, Tag: IntoAad<'static>, A: IntoAad<'a>>(
        tagged: ContextTag<Tag, &str>,
        extra: A,
    ) -> Leaf {
        match tagged
            .encrypt_with_aad(&Mock, extra)
            .expect("the mock cannot fail")
        {
            CipherText::Single(leaf) => leaf,
            other => panic!("a scalar seals as one leaf, got {other:?}"),
        }
    }

    /// The AAD the walk derives for a top-level scalar is the bare context,
    /// so a sealed leaf's AAD bytes are the tuple's encoding.
    fn bytes_of<'a>(aad: impl IntoAad<'a>) -> Vec<u8> {
        aad.into_aad().as_bytes().to_vec()
    }

    #[test]
    fn the_context_keeps_its_parts() {
        // The motivating consumer: a cipher that names the parts must find
        // them intact — the tag as a nested list of its refinements, not as
        // pre-encoded bytes.
        let folded = fold_tag_aad(("table:users", "column:email"), "row:99");
        let piece = folded.into_context();
        assert_eq!(
            piece,
            ContextPiece::List(vec![
                ContextPiece::Text(Cow::Borrowed("row:99")),
                ContextPiece::List(vec![
                    ContextPiece::Text(Cow::Borrowed("table:users")),
                    ContextPiece::Text(Cow::Borrowed("column:email")),
                ]),
            ])
        );
        let names: Vec<String> = piece.leaves().map(ToString::to_string).collect();
        assert_eq!(names, ["\"row:99\"", "\"table:users\"", "\"column:email\""]);
        // Both views agree with the tuple: the parts tree re-encoded, and the
        // bytes a byte-oriented cipher gets from the pair `(extra_aad, tag)`.
        let expected = ("row:99", ("table:users", "column:email")).into_aad();
        assert_eq!(piece.into_aad().as_bytes(), expected.as_bytes());
    }

    #[test]
    fn encrypts_inner_value_and_binds_tag() {
        let leaf = sealed_with(ContextTag::new("hello world", "tag_aad"), "extra");
        // The inner value is sealed as its tagged leaf...
        assert_eq!(
            leaf.plaintext,
            [&[tags::STRING][..], b"hello world"].concat()
        );
        // ...and the bound AAD is the pair (extra, tag).
        assert_eq!(leaf.aad, bytes_of(("extra", "tag_aad")));
    }

    #[test]
    fn encrypt_with_no_extra_aad_still_binds_tag() {
        let leaf = sealed(ContextTag::new("secret", "user:42"));
        // `encrypt` supplies an empty extra AAD, so the bound AAD is PAE(empty, tag).
        assert_eq!(leaf.aad, bytes_of(((), "user:42")));
    }

    #[test]
    fn unit_tag_still_binds_nonempty_aad() {
        let leaf = sealed(ContextTag::new("secret", ()));
        // Pins the documented boundary: a `()` tag binds PAE(empty, empty),
        // which is *not* empty AAD — so a bare `decrypt(ct, ())` must fail. A
        // regression that folded a `()` tag to empty AAD would silently break
        // it.
        assert_eq!(leaf.aad, bytes_of(((), ())));
        assert_ne!(leaf.aad, Context::empty().as_bytes());
    }

    #[test]
    fn refine_nests_the_tag() {
        let leaf = sealed_with(
            ContextTag::new("secret", "table:users").refine("column:email"),
            "extra",
        );
        // extra + (table, column) => the nested pair (extra, (table, column)).
        assert_eq!(
            leaf.aad,
            bytes_of(("extra", ("table:users", "column:email")))
        );
    }

    #[test]
    fn chained_refine_builds_left_nested_tuple() {
        let leaf = sealed(ContextTag::new("data", "a").refine("b").refine("c"));
        // tag = (("a", "b"), "c"); no extra AAD.
        assert_eq!(leaf.aad, bytes_of(((), (("a", "b"), "c"))));
    }

    #[test]
    fn owned_and_byte_tags_are_accepted() {
        let leaf = sealed(ContextTag::new("secret", String::from("owned-tag")));
        assert_eq!(leaf.aad, bytes_of(((), "owned-tag")));
        let leaf = sealed(ContextTag::new("secret", vec![0xde_u8, 0xad, 0xbe, 0xef]));
        assert_eq!(leaf.aad, bytes_of(((), vec![0xde_u8, 0xad, 0xbe, 0xef])));
    }

    #[test]
    fn aad_helpers_match_the_encrypt_binding() {
        // The AAD the helpers produce for decryption must equal what the
        // encrypt methods bind.
        let leaf = sealed(ContextTag::new("secret", "user:42"));
        assert_eq!(leaf.aad, bytes_of(ContextTag::aad("user:42")));
        let leaf = sealed_with(ContextTag::new("secret", "table:users"), "row:99");
        assert_eq!(
            leaf.aad,
            bytes_of(ContextTag::aad_with("row:99", "table:users"))
        );
    }

    #[test]
    fn different_tags_produce_different_aad() {
        let a = sealed(ContextTag::new("secret", "user:42"));
        let b = sealed(ContextTag::new("secret", "user:99"));
        assert_ne!(a.aad, b.aad);
    }

    #[test]
    fn into_parts_round_trips() {
        let tagged = ContextTag::new("secret", "ctx");
        let (inner, tag) = tagged.into_parts();
        assert_eq!(inner, "secret");
        assert_eq!(tag, "ctx");
    }

    #[test]
    fn decrypt_mirrors_encrypt_through_the_same_fold() {
        let node = ContextTag::new("secret".to_string(), "table:users")
            .refine("column:email")
            .encrypt_with_aad(&Mock, "row:99")
            .expect("encrypts");
        let back: String = ContextTag::context("table:users")
            .refine("column:email")
            .decrypt_with_aad(&Mock, node, "row:99")
            .expect("decrypts");
        assert_eq!(back, "secret");

        let node = ContextTag::new(vec![1u32, 2], "user:42")
            .encrypt(&Mock)
            .expect("encrypts");
        let back: Vec<u32> = ContextTag::context("user:42")
            .decrypt(&Mock, node)
            .expect("decrypts");
        assert_eq!(back, [1, 2]);
    }

    #[test]
    fn a_different_tag_or_extra_aad_fails_at_the_cipher() {
        let seal = || {
            ContextTag::new("secret".to_string(), "table:users")
                .encrypt_with_aad(&Mock, "row:99")
                .expect("encrypts")
        };
        for attempt in [
            ContextTag::context("table:orders").decrypt_with_aad::<String, _, _>(
                &Mock,
                seal(),
                "row:99",
            ),
            ContextTag::context("table:users").decrypt_with_aad::<String, _, _>(
                &Mock,
                seal(),
                "row:100",
            ),
            // The tag and the extra AAD are not interchangeable.
            ContextTag::context("row:99").decrypt_with_aad::<String, _, _>(
                &Mock,
                seal(),
                "table:users",
            ),
            // Nor is a bare decrypt under the tag alone.
            crate::decrypt::<String, _, _>(&Mock, seal(), "table:users"),
        ] {
            assert!(matches!(attempt, Err(DecryptError::Cipher(Refused))));
        }
    }

    #[test]
    fn the_async_methods_bind_the_same_aad_as_the_sync_ones() {
        use crate::seal::mock::Remote;
        use futures_executor::block_on;

        let remote = Remote::new(false);
        let sync_leaf = sealed_with(ContextTag::new("secret", "user:42"), "row:7");
        let async_node =
            block_on(ContextTag::new("secret", "user:42").encrypt_with_aad_async(&remote, "row:7"))
                .expect("the mock cannot fail");
        let CipherText::Single(async_leaf) = async_node else {
            panic!("a scalar seals as one leaf");
        };
        assert_eq!(async_leaf.aad, sync_leaf.aad);
        assert_eq!(async_leaf.plaintext, sync_leaf.plaintext);

        // And the async decrypt mirrors it, with and without extra AAD.
        let back: String = block_on(ContextTag::context("user:42").decrypt_with_aad_async(
            &remote,
            CipherText::Single(async_leaf),
            "row:7",
        ))
        .expect("decrypts");
        assert_eq!(back, "secret");
        let node = block_on(ContextTag::new("secret", "user:42").encrypt_async(&remote))
            .expect("the mock cannot fail");
        let back: String = block_on(ContextTag::context("user:42").decrypt_async(&remote, node))
            .expect("decrypts");
        assert_eq!(back, "secret");
        let node = block_on(ContextTag::new("secret", "user:42").encrypt_async(&remote))
            .expect("the mock cannot fail");
        assert!(
            block_on(ContextTag::context("other").decrypt_async::<String, _>(&remote, node))
                .is_err(),
            "a different tag is a different AAD"
        );
    }
}
