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
//! so `ContextTag` participates by implementing [`Encrypt`]. Decryption is different: the revised
//! [`Decrypt`]/[`Decipher`] traits do **not** thread AAD through the type being decrypted — the
//! concrete cipher injects the AAD when it constructs the decipher (e.g.
//! `cipher.decrypt_with_aad::<T, _>(ciphertext, aad)`). There is therefore nothing for a
//! `ContextTag` *type* to enforce on the decrypt path; the recovered value is simply `T`.
//!
//! To keep the two sides symmetric without guessing the tuple layout, [`ContextTag::aad`] and
//! [`ContextTag::aad_with`] build the exact AAD the wrapper bound at encrypt time, ready to hand to
//! a concrete cipher's decrypt entry point.
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

use crate::{Aad, Cipher, Encrypt, IntoAad};

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
/// The revised decrypt path takes its AAD from the cipher, not the type, so you recover the plain
/// `T` and supply the matching AAD via [`ContextTag::aad`] / [`ContextTag::aad_with`]:
///
/// ```rust,ignore
/// use vitaminc_aead::ContextTag;
///
/// let plaintext: String =
///     cipher.decrypt_with_aad(ciphertext, ContextTag::aad("user:42"))?;
/// # Ok::<(), vitaminc_aead::Unspecified>(())
/// ```
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
    /// Builds the AAD to supply when **decrypting** a value that was sealed with
    /// `ContextTag::new(value, tag).encrypt(cipher)` (i.e. with no extra AAD).
    ///
    /// This is the symmetric counterpart of the binding performed by [`Encrypt`]: it reproduces
    /// the `(empty, tag)` layout so a concrete cipher's decrypt entry point authenticates against
    /// exactly the same bytes.
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

    /// Builds the AAD to supply when **decrypting** a value that was sealed with
    /// `ContextTag::new(value, tag).encrypt_with_aad(cipher, extra_aad)`.
    ///
    /// Reproduces the `(extra_aad, tag)` layout bound at encrypt time. The argument order
    /// mirrors [`encrypt_with_aad`](crate::Encrypt::encrypt_with_aad): the extra AAD comes
    /// first, then the tag — so the two call sites line up and read in the same order as the
    /// bound tuple.
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
        // Encode the tag into an owned/`'static` `Aad`, then re-borrow it for the call's `'a`
        // lifetime (`Aad` is covariant in its lifetime, so `'static: 'a` permits the narrowing).
        let tag_aad: Aad<'static> = tag.into_aad();
        let tag_aad: Aad<'a> = tag_aad;
        inner.encrypt_with_aad(cipher, (extra_aad, tag_aad))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cipher::{MapCipher, SeqCipher},
        Unspecified,
    };
    use std::any::Any;
    use std::cell::RefCell;
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
}
