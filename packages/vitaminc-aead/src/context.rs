//! Context-tagged encryption.
//!
//! This module provides [`ContextTag`], a wrapper that binds additional authenticated data (AAD)
//! to a plaintext value **at the type level**. When a `ContextTag` is encrypted, the embedded tag
//! is automatically folded into the AAD alongside any extra AAD passed to
//! [`encrypt_with_aad`](crate::Encrypt::encrypt_with_aad).
//!
//! The point of the wrapper is the type-level guarantee: a value wrapped in `ContextTag` *cannot*
//! be encrypted without its context. The revised [`Cipher`]/[`Encrypt`] API already accepts tuple
//! AAD (e.g. `value.encrypt_with_aad(cipher, (tag, extra))`), so the byte-level behaviour is
//! nothing more than [`IntoAad`] composition — but tuple AAD is opt-in at every call site and easy
//! to forget. `ContextTag` moves the obligation into the type system so the compiler enforces it.
//!
//! # Where AAD lives in the revised API
//!
//! Encryption threads AAD through [`Encrypt::encrypt_with_aad`](crate::Encrypt::encrypt_with_aad),
//! so `ContextTag` participates by implementing [`Encrypt`]. Decryption is symmetric: the
//! [`Decrypt`]/[`Decipher`] traits thread AAD through the type being decrypted via
//! [`Decrypt::decrypt_with_aad`](crate::Decrypt::decrypt_with_aad), so `ContextTag` mirrors its
//! `Encrypt` impl with [`ContextTag::decrypt`] / [`ContextTag::decrypt_with_aad`].
//!
//! Rebuild the decrypt context with [`ContextTag::context`] (and the same
//! [`refine`](ContextTag::refine) chain used at encrypt time), then drive a [`Decipher`] obtained
//! from the concrete cipher — e.g. `ContextTag::context(tag).decrypt(cipher.decipher(ciphertext))`.
//! Because the tag (and any refinement) is reconstructed by the same code path that bound it, it is
//! never re-typed by hand.
//!
//! For lower-level use directly against a cipher's own decrypt entry point, [`ContextTag::aad`] /
//! [`ContextTag::aad_with`] build the raw AAD tuple the wrapper bound at encrypt time.
//!
//! # AAD encoding
//!
//! When encrypting a `ContextTag`, the final AAD is formed by combining the extra AAD with the
//! embedded tag as the tuple `(extra_aad, tag)`, which [`IntoAad`] PAE-encodes:
//!
//! ```text
//! final_aad = PAE(extra_aad, tag)
//! ```
//!
//! PAE (Pre-Authentication Encoding) prefixes each piece with its length, preventing
//! canonicalisation attacks where different inputs could otherwise produce identical byte strings.
//!
//! With [`refine`](ContextTag::refine), the tag itself is a nested tuple that is recursively
//! PAE-encoded:
//!
//! ```text
//! ContextTag::new(data, "a").refine("b")
//!   ──► tag = ("a", "b")
//!   ──► final_aad = PAE(extra_aad, PAE("a", "b"))
//! ```

use crate::{Aad, Cipher, Decipher, Decrypt, Encrypt, IntoAad};

/// Folds a context `tag` and `extra_aad` into the AAD layout bound by `ContextTag`.
///
/// This is the **single source** of the encrypt/decrypt AAD layout: both the [`Encrypt`] impl and
/// [`ContextTag::decrypt_with_aad`] go through it, so the two sides cannot drift out of sync (a
/// divergence would silently break authentication). The tag is encoded into an owned/`'static`
/// `Aad` and re-borrowed for the call's `'a` lifetime (`Aad` is covariant in its lifetime, so
/// `'static: 'a` permits the narrowing); the result is `(extra_aad, tag)`, which [`IntoAad`]
/// PAE-encodes.
fn fold_tag_aad<'a, Tag, A>(tag: Tag, extra_aad: A) -> (A, Aad<'a>)
where
    Tag: IntoAad<'static>,
{
    let tag_aad: Aad<'static> = tag.into_aad();
    let tag_aad: Aad<'a> = tag_aad;
    (extra_aad, tag_aad)
}

/// A wrapper that pairs a plaintext value with a context tag used as additional authenticated
/// data (AAD).
///
/// `ContextTag` guarantees, at the type level, that `tag` is folded into the AAD whenever `inner`
/// is encrypted. This is the recommended way to enforce that a value is always sealed against a
/// specific context (a user id, table name, column name, …): because the tag is part of the type,
/// the compiler will not let you forget it.
///
/// The tag can be any type that implements [`IntoAad<'static>`](IntoAad) — `&'static str`,
/// `String`, `u64`, `Vec<u8>`, and tuples of these. (Non-`'static` borrowed tags such as a
/// short-lived `&str` are intentionally excluded; promote them to an owned `String` or a
/// `&'static str`.)
///
/// # Encrypting
///
/// `ContextTag` implements [`Encrypt`], so it is encrypted like any other value. The embedded tag
/// is bound automatically:
///
/// ```rust,ignore
/// use vitaminc_aead::{ContextTag, Encrypt};
///
/// // `cipher` implements `Cipher` for `&MyCipher` (see crate docs / `Aes256Cipher`).
/// let tagged = ContextTag::new("secret message", "user:42");
/// let ciphertext = tagged.encrypt(&cipher)?;
/// # Ok::<(), vitaminc_aead::Unspecified>(())
/// ```
///
/// # Decrypting
///
/// Mirror the encrypt side: rebuild the context with [`ContextTag::context`] (and the same
/// [`refine`](ContextTag::refine) chain, if any), then recover the value with
/// [`decrypt`](ContextTag::decrypt) / [`decrypt_with_aad`](ContextTag::decrypt_with_aad),
/// driving a [`Decipher`] obtained from the concrete cipher:
///
/// ```rust,ignore
/// use vitaminc_aead::ContextTag;
///
/// let plaintext: String =
///     ContextTag::context("user:42").decrypt(cipher.decipher(ciphertext))?;
/// # Ok::<(), vitaminc_aead::Unspecified>(())
/// ```
///
/// For lower-level control you can instead build the raw AAD with [`ContextTag::aad`] /
/// [`ContextTag::aad_with`] and pass it to a cipher's own decrypt entry point.
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

    /// Adds a second layer of context, producing a new `ContextTag` whose tag is the tuple
    /// `(original_tag, tag)`.
    ///
    /// Useful for building hierarchical context such as `("table:users", "column:email")`. The
    /// nested tag is PAE-encoded when converted to AAD bytes, so distinct hierarchies never
    /// collide. `refine` can be chained to build deeper hierarchies.
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

impl<Tag> ContextTag<Tag, ()> {
    /// Low-level: builds the raw AAD tuple for **decrypting** a value sealed with
    /// `ContextTag::new(value, tag).encrypt(cipher)` (i.e. with no extra AAD).
    ///
    /// Prefer [`ContextTag::context`] + [`decrypt`](ContextTag::decrypt) where a
    /// [`Decipher`] is available — it folds the AAD for you and reconstructs nested
    /// [`refine`](ContextTag::refine) tags via the same path used at encrypt time. Reach for `aad`
    /// only to drive a cipher's own decrypt entry point directly.
    ///
    /// This reproduces the `(empty, tag)` layout the [`Encrypt`] impl binds, so a concrete cipher's
    /// decrypt entry point authenticates against exactly the same bytes.
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
    pub fn aad(tag: Tag) -> (Aad<'static>, Tag) {
        (Aad::empty(), tag)
    }

    /// Low-level: builds the raw AAD tuple for **decrypting** a value sealed with
    /// `ContextTag::new(value, tag).encrypt_with_aad(cipher, extra_aad)`.
    ///
    /// Prefer [`ContextTag::context`] + [`decrypt_with_aad`](ContextTag::decrypt_with_aad), which
    /// puts the tag in the receiver so it can't be transposed with `extra_aad`. This builder takes
    /// **both** as positional, same-typed args (`extra_aad` first, then `tag`) — swapping them
    /// silently produces the wrong AAD, so reach for it only to drive a cipher's own decrypt entry
    /// point directly.
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
    /// [`refine`](ContextTag::refine)) the tag exactly as you did at encrypt time,
    /// then call [`decrypt`](ContextTag::decrypt) /
    /// [`decrypt_with_aad`](ContextTag::decrypt_with_aad) to recover the value —
    /// so the tag (and any nested refinement) is reconstructed by the same code
    /// path that bound it, never re-typed by hand.
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
    /// Decrypts a value sealed against this context, authenticating against the
    /// embedded tag (no extra AAD). The decrypt mirror of
    /// [`ContextTag::encrypt`](Encrypt::encrypt).
    ///
    /// Obtain `decipher` from a concrete cipher (e.g. `cipher.decipher(ciphertext)`).
    pub fn decrypt<'c, T, D>(self, decipher: D) -> D::Ok<T>
    where
        D: Decipher<'c>,
        T: Decrypt<'c> + 'c,
    {
        self.decrypt_with_aad(decipher, Aad::empty())
    }

    /// Decrypts a value sealed against this context plus `extra_aad`, mirroring
    /// [`ContextTag::encrypt_with_aad`](Encrypt::encrypt_with_aad).
    ///
    /// The tag lives in the receiver and `extra_aad` is the lone argument, so the
    /// two cannot be swapped; the bound AAD is `(extra_aad, tag)` — byte-identical
    /// to what the [`Encrypt`] impl folds in at seal time. Obtain `decipher` from
    /// a concrete cipher (e.g. `cipher.decipher(ciphertext)`).
    pub fn decrypt_with_aad<'c, 'a, T, D, A>(self, decipher: D, extra_aad: A) -> D::Ok<T>
    where
        D: Decipher<'c>,
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        T::decrypt_with_aad(decipher, fold_tag_aad(self.tag, extra_aad))
    }
}

impl<Tag, T> Encrypt for ContextTag<Tag, T>
where
    T: Encrypt,
    // `Encrypt::encrypt_with_aad` chooses the AAD lifetime at the call site, but the tag is owned
    // by the wrapper. Requiring `IntoAad<'static>` lets the tag be encoded into an owned (or
    // `'static`-borrowed) `Aad` that we then re-borrow for the call's lifetime via covariance.
    // Owned tags (`String`, `u64`, `Vec<u8>`, tuples thereof) and `&'static str` satisfy this;
    // non-`'static` borrows do not — promote them to `String` or a `&'static str`.
    Tag: IntoAad<'static>,
{
    /// Encrypts the inner value, folding the embedded tag into the AAD.
    ///
    /// The final AAD is `(extra_aad, tag)`, PAE-encoded by [`IntoAad`] into an unambiguous byte
    /// representation that binds both pieces.
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, extra_aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let ContextTag { inner, tag } = self;
        inner.encrypt_with_aad(cipher, fold_tag_aad(tag, extra_aad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher::{MapCipher, SeqCipher},
        DecipherVisitor, Unspecified,
    };
    use std::any::Any;
    use std::cell::RefCell;
    use std::rc::Rc;
    use vitaminc_protected::{Controlled, Protected};

    /// A minimal [`Cipher`] that records the AAD bytes it is handed and echoes the plaintext back
    /// as its "ciphertext". Only the byte path is exercised by the leaf `Encrypt` impls used in
    /// these tests (`&str`, `String`, `[u8; N]`); the sequence/map sub-ciphers exist solely to
    /// satisfy the trait and are never driven.
    struct MockCipher {
        captured_aad: RefCell<Vec<u8>>,
    }

    impl MockCipher {
        fn new() -> Self {
            MockCipher {
                captured_aad: RefCell::new(Vec::new()),
            }
        }

        fn captured_aad(&self) -> Vec<u8> {
            self.captured_aad.borrow().clone()
        }
    }

    struct UnusedSeq;
    struct UnusedMap;

    impl Cipher for &MockCipher {
        type Ok = Vec<u8>;
        type Error = Unspecified;
        type SeqCipher = UnusedSeq;
        type MapCipher = UnusedMap;

        fn encrypt_bytes_vec<'a, A>(
            self,
            data: Protected<Vec<u8>>,
            aad: A,
        ) -> Result<Self::Ok, Self::Error>
        where
            A: IntoAad<'a>,
        {
            *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
            Ok(data.risky_unwrap())
        }

        fn encrypt_seq(self, _size_hint: Option<usize>) -> Self::SeqCipher {
            UnusedSeq
        }

        fn encrypt_map(self) -> Self::MapCipher {
            UnusedMap
        }

        fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
        where
            A: IntoAad<'a>,
        {
            *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
            Ok(Vec::new())
        }

        fn passthrough<U>(self, _value: U) -> Result<Self::Ok, Self::Error>
        where
            U: Any + Send + 'static,
        {
            Ok(Vec::new())
        }
    }

    impl SeqCipher for UnusedSeq {
        type Ok = Vec<u8>;
        type Error = Unspecified;

        fn encrypt_next<'a, T, A>(self, _data: T, _aad: A) -> Result<Self, Self::Error>
        where
            T: Encrypt,
            A: IntoAad<'a>,
        {
            Ok(self)
        }

        fn passthrough_next<T>(self, _value: T) -> Result<Self, Self::Error>
        where
            T: Any + Send + 'static,
        {
            Ok(self)
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            Ok(Vec::new())
        }
    }

    impl MapCipher for UnusedMap {
        type Ok = Vec<u8>;
        type Error = Unspecified;

        fn encrypt_key(self, _key: &'static str) -> Result<Self, Self::Error> {
            Ok(self)
        }

        fn encrypt_value<'a, T, A>(self, _value: T, _aad: A) -> Result<Self, Self::Error>
        where
            T: Encrypt,
            A: IntoAad<'a>,
        {
            Ok(self)
        }

        fn passthrough_entry<T>(self, _key: &'static str, _value: T) -> Result<Self, Self::Error>
        where
            T: Any + Send + 'static,
        {
            Ok(self)
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn encrypts_inner_value_and_binds_tag() {
        let plaintext = "hello world";
        let cipher = MockCipher::new();

        let ciphertext = ContextTag::new(plaintext, "tag_aad")
            .encrypt_with_aad(&cipher, "extra")
            .expect("encryption should succeed");

        // The inner value is encrypted unchanged...
        assert_eq!(ciphertext, plaintext.as_bytes());
        // ...and the bound AAD is PAE(extra, tag).
        let expected = Aad::pae(&[b"extra", b"tag_aad"]);
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn encrypt_with_no_extra_aad_still_binds_tag() {
        let cipher = MockCipher::new();

        ContextTag::new("secret", "user:42")
            .encrypt(&cipher)
            .expect("encryption should succeed");

        // `encrypt` supplies an empty extra AAD, so the bound AAD is PAE(empty, tag).
        let expected = ((), "user:42").into_aad();
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn refine_nests_the_tag() {
        let cipher = MockCipher::new();

        ContextTag::new("secret", "table:users")
            .refine("column:email")
            .encrypt_with_aad(&cipher, "extra")
            .expect("encryption should succeed");

        // extra + (table, column) => PAE(extra, PAE(table, column)).
        let inner = Aad::pae(&[b"table:users", b"column:email"]);
        let expected = Aad::pae(&[b"extra", inner.as_bytes()]);
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn chained_refine_builds_left_nested_tuple() {
        let cipher = MockCipher::new();

        ContextTag::new("data", "a")
            .refine("b")
            .refine("c")
            .encrypt(&cipher)
            .expect("encryption should succeed");

        // tag = (("a", "b"), "c"); no extra AAD.
        let expected = ((), (("a", "b"), "c")).into_aad();
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn owned_string_tag_is_accepted() {
        let cipher = MockCipher::new();

        ContextTag::new("secret", String::from("owned-tag"))
            .encrypt(&cipher)
            .expect("encryption should succeed");

        let expected = ((), "owned-tag").into_aad();
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn aad_helper_matches_encrypt_binding() {
        // The AAD `ContextTag::aad` produces for decryption must equal what `encrypt` binds.
        let cipher = MockCipher::new();
        ContextTag::new("secret", "user:42")
            .encrypt(&cipher)
            .expect("encryption should succeed");

        let decrypt_aad = ContextTag::aad("user:42").into_aad();
        assert_eq!(cipher.captured_aad(), decrypt_aad.as_bytes());
    }

    #[test]
    fn aad_with_helper_matches_encrypt_binding() {
        let cipher = MockCipher::new();
        ContextTag::new("secret", "table:users")
            .encrypt_with_aad(&cipher, "row:99")
            .expect("encryption should succeed");

        let decrypt_aad = ContextTag::aad_with("row:99", "table:users").into_aad();
        assert_eq!(cipher.captured_aad(), decrypt_aad.as_bytes());
    }

    #[test]
    fn different_tags_produce_different_aad() {
        let cipher_a = MockCipher::new();
        let cipher_b = MockCipher::new();

        ContextTag::new("secret", "user:42")
            .encrypt(&cipher_a)
            .expect("encryption should succeed");
        ContextTag::new("secret", "user:99")
            .encrypt(&cipher_b)
            .expect("encryption should succeed");

        assert_ne!(cipher_a.captured_aad(), cipher_b.captured_aad());
    }

    #[test]
    fn into_parts_round_trips() {
        let tagged = ContextTag::new("secret", "ctx");
        let (inner, tag) = tagged.into_parts();
        assert_eq!(inner, "secret");
        assert_eq!(tag, "ctx");
    }

    /// A minimal [`Decipher`] that records the AAD bytes it is handed via `decrypt_bytes` and
    /// yields nothing. Lets the decrypt-side `ContextTag` helper's folded AAD be pinned
    /// byte-for-byte against an independent expected layout (and against the encrypt binding).
    struct CapturingDecipher {
        captured_aad: Rc<RefCell<Vec<u8>>>,
    }

    impl<'c> Decipher<'c> for CapturingDecipher {
        type Ok<T>
            = Option<T>
        where
            T: Send + 'c;

        fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
        where
            T: Send + 'c,
            U: Send + 'c,
            F: FnOnce(T) -> U,
        {
            ok.map(f)
        }

        fn decrypt_bytes<'a, V, A>(self, _visitor: V, aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
            None
        }

        fn decrypt_seq<'a, V, A>(self, _visitor: V, _aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            None
        }

        fn decrypt_map<'a, V, A>(self, _visitor: V, _aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            None
        }

        fn decrypt_passthrough<T>(self) -> Self::Ok<T>
        where
            T: Any + Send + 'static,
        {
            None
        }

        fn decrypt_option<'a, T, A>(self, _aad: A) -> Self::Ok<Option<T>>
        where
            T: Decrypt<'c> + 'c,
            A: IntoAad<'a>,
        {
            None
        }
    }

    fn captured_helper_aad<F>(build: F) -> Vec<u8>
    where
        F: FnOnce(CapturingDecipher) -> Option<String>,
    {
        let captured = Rc::new(RefCell::new(Vec::new()));
        let _ = build(CapturingDecipher {
            captured_aad: Rc::clone(&captured),
        });
        let bytes = captured.borrow().clone();
        bytes
    }

    // The decrypt helper must fold byte-identical AAD to what the `Encrypt` impl binds. These pin
    // the helper against an *independent* expected layout (not the shared `fold_tag_aad`), so a
    // reorder of the fold would be caught even though both sides share it.

    #[test]
    fn decrypt_helper_folds_empty_extra_plus_tag() {
        let captured =
            captured_helper_aad(|d| ContextTag::context("user:42").decrypt::<String, _>(d));
        assert_eq!(captured, ((), "user:42").into_aad().as_bytes());
    }

    #[test]
    fn decrypt_helper_folds_extra_then_tag() {
        let captured = captured_helper_aad(|d| {
            ContextTag::context("table:users").decrypt_with_aad::<String, _, _>(d, "row:99")
        });
        assert_eq!(captured, ("row:99", "table:users").into_aad().as_bytes());
    }

    #[test]
    fn decrypt_helper_refine_folds_nested_tag() {
        let captured = captured_helper_aad(|d| {
            ContextTag::context("table:users")
                .refine("column:email")
                .decrypt::<String, _>(d)
        });
        assert_eq!(
            captured,
            ((), ("table:users", "column:email")).into_aad().as_bytes()
        );
    }

    #[test]
    fn decrypt_helper_matches_encrypt_binding() {
        // Cross-check: the helper's fold equals what the `Encrypt` impl actually binds.
        let cipher = MockCipher::new();
        ContextTag::new("secret", "table:users")
            .encrypt_with_aad(&cipher, "row:99")
            .expect("encryption should succeed");

        let captured = captured_helper_aad(|d| {
            ContextTag::context("table:users").decrypt_with_aad::<String, _, _>(d, "row:99")
        });
        assert_eq!(captured, cipher.captured_aad());
    }
}
