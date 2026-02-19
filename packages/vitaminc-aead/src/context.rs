//! Context-tagged encryption.
//!
//! This module provides [`ContextTag`], a wrapper that binds additional authenticated data (AAD)
//! to a plaintext value at the type level. When a `ContextTag` is encrypted, the embedded tag is
//! automatically included as AAD alongside any extra AAD passed to
//! [`encrypt_with_aad`](crate::Encrypt::encrypt_with_aad).
//!
//! This is useful for binding contextual metadata (such as a user ID, table name, or column name)
//! to a ciphertext so that decryption fails unless the same context is provided. Because the tag
//! is part of the type, it is impossible to forget to include it during encryption.
//!
//! # AAD encoding
//!
//! When encrypting a `ContextTag`, the final AAD is formed by PAE-encoding the extra AAD
//! with the embedded tag:
//!
//! ```text
//! final_aad = PAE(extra_aad, tag)
//! ```
//!
//! PAE (Pre-Authentication Encoding) prefixes each piece with its length, preventing
//! canonicalization attacks where different inputs could produce identical byte strings.
//!
//! With [`refine`](ContextTag::refine), the tag itself is a nested tuple that is
//! recursively PAE-encoded:
//!
//! ```text
//! ContextTag::new(data, "a").refine("b")
//!   ──► tag = ("a", "b")
//!   ──► final_aad = PAE(extra_aad, PAE("a", "b"))
//! ```

use crate::{Cipher, Decrypt, Encrypt, IntoAad, Unspecified};

/// A wrapper that pairs a plaintext value with additional authenticated data (AAD).
///
/// `ContextTag` ensures that the given tag is always included as AAD whenever the
/// inner value is encrypted, binding the ciphertext to a specific context. This is
/// the recommended way to enforce that encryption is always performed with the correct
/// AAD, since the compiler guarantees the tag is present.
///
/// The tag can be any type that implements [`IntoAad`]: `&str`, `String`, `u64`,
/// tuples of these, etc.
///
/// # Basic usage
///
/// Encrypt a value with a context tag, then decrypt by providing the same AAD:
///
/// ```
/// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
/// use vitaminc_aead::test_utils::TestCipher;
///
/// let cipher = TestCipher;
///
/// let tagged = ContextTag::new("secret message", "user:42");
/// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
///
/// // To decrypt, supply the same tag
/// let plaintext: String = ContextTag::decrypt(ciphertext, &cipher, "user:42")
///     .expect("decryption failed");
/// assert_eq!(plaintext, "secret message");
/// ```
///
/// # Combining with extra AAD
///
/// Extra AAD passed to [`encrypt_with_aad`](Encrypt::encrypt_with_aad) is prepended
/// to the tag. Both must be provided for decryption to succeed:
///
/// ```
/// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
/// use vitaminc_aead::test_utils::TestCipher;
///
/// let cipher = TestCipher;
///
/// let tagged = ContextTag::new("secret", "table:users");
/// let ciphertext = tagged
///     .encrypt_with_aad(&cipher, "row:99")
///     .expect("encryption failed");
///
/// // Decrypt with the same tag and extra AAD
/// let plaintext: String = ContextTag::decrypt_with_aad(
///     ciphertext,
///     &cipher,
///     "table:users",
///     "row:99",
/// )
/// .expect("decryption failed");
/// assert_eq!(plaintext, "secret");
/// ```
///
/// # Decryption fails with wrong context
///
/// If the AAD does not match what was used during encryption, decryption fails:
///
/// ```
/// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
/// use vitaminc_aead::test_utils::TestCipher;
///
/// let cipher = TestCipher;
///
/// let tagged = ContextTag::new("secret", "user:42");
/// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
///
/// // Wrong context — decryption must fail
/// let result: Result<String, _> = ContextTag::decrypt(ciphertext, &cipher, "user:99");
/// assert!(result.is_err());
/// ```
///
/// # Using `&str` tags
///
/// Because the lifetime `'a` on [`Encrypt<'a>`] is at the trait level, `ContextTag`
/// can accept borrowed tags like `&str` without requiring higher-ranked trait bounds:
///
/// ```
/// use vitaminc_aead::{ContextTag, Encrypt};
/// use vitaminc_aead::test_utils::TestCipher;
///
/// let cipher = TestCipher;
///
/// // &str tags work naturally — no String::from() needed
/// let tagged = ContextTag::new(vec![1u8, 2, 3], "my-context");
/// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
/// ```
pub struct ContextTag<Tag, T> {
    inner: T,
    aad: Tag,
}

impl<Tag, T> ContextTag<Tag, T> {
    /// Creates a new `ContextTag` that pairs `inner` with the given `aad` tag.
    ///
    /// The tag will be included as additional authenticated data (AAD) whenever
    /// `inner` is encrypted.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_aead::{ContextTag, Encrypt};
    /// use vitaminc_aead::test_utils::TestCipher;
    ///
    /// let cipher = TestCipher;
    ///
    /// let tagged = ContextTag::new("hello", "my-tag");
    /// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
    /// ```
    pub fn new(inner: T, aad: Tag) -> Self {
        ContextTag { inner, aad }
    }

    /// Adds a second layer of AAD, producing a new `ContextTag` whose tag is the
    /// tuple `(original_tag, aad)`.
    ///
    /// This is useful for building hierarchical context such as
    /// `("table:users", "column:email")`. The original and refined tags are
    /// PAE-encoded when converted to AAD bytes.
    ///
    /// `refine` can be chained multiple times to build deeper hierarchies.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
    /// use vitaminc_aead::test_utils::TestCipher;
    ///
    /// let cipher = TestCipher;
    ///
    /// let tagged = ContextTag::new("secret", "table:users")
    ///     .refine("column:email");
    ///
    /// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
    ///
    /// // Decrypt with the same refined tag
    /// let plaintext: String = ContextTag::decrypt(
    ///     ciphertext,
    ///     &cipher,
    ///     ("table:users", "column:email"),
    /// )
    /// .expect("decryption failed");
    /// assert_eq!(plaintext, "secret");
    /// ```
    ///
    /// # Chaining multiple refinements
    ///
    /// ```
    /// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
    /// use vitaminc_aead::test_utils::TestCipher;
    ///
    /// let cipher = TestCipher;
    ///
    /// let tagged = ContextTag::new("data", "a")
    ///     .refine("b")
    ///     .refine("c");
    ///
    /// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
    ///
    /// // Decrypt with the same nested tag
    /// let plaintext: String = ContextTag::decrypt(
    ///     ciphertext,
    ///     &cipher,
    ///     (("a", "b"), "c"),
    /// )
    /// .expect("decryption failed");
    /// assert_eq!(plaintext, "data");
    /// ```
    pub fn refine<B>(self, aad: B) -> ContextTag<(Tag, B), T> {
        ContextTag {
            inner: self.inner,
            aad: (self.aad, aad),
        }
    }
}

impl<'a, Tag: IntoAad<'a> + 'a, T: Encrypt<'a>> Encrypt<'a> for ContextTag<Tag, T> {
    type Encrypted = <T as Encrypt<'a>>::Encrypted;

    /// Encrypts the inner value, combining `extra_aad` with the embedded tag.
    ///
    /// The final AAD is `(extra_aad, tag)`, which is PAE-encoded to produce
    /// an unambiguous byte representation.
    fn encrypt_with_aad<C, A>(
        self,
        cipher: &C,
        extra_aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let ContextTag { inner, aad } = self;
        inner.encrypt_with_aad(cipher, (extra_aad, aad))
    }
}

impl<Tag> ContextTag<Tag, ()> {
    /// Decrypts a ciphertext using the given tag as context AAD.
    ///
    /// This is the symmetric counterpart to [`ContextTag::encrypt`](Encrypt::encrypt).
    /// The tag is automatically wrapped as `((), tag)` to match the AAD used during
    /// encryption.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
    /// use vitaminc_aead::test_utils::TestCipher;
    ///
    /// let cipher = TestCipher;
    ///
    /// let tagged = ContextTag::new("secret message", "user:42");
    /// let ciphertext = tagged.encrypt(&cipher).expect("encryption failed");
    ///
    /// let plaintext: String = ContextTag::decrypt(ciphertext, &cipher, "user:42")
    ///     .expect("decryption failed");
    /// assert_eq!(plaintext, "secret message");
    /// ```
    pub fn decrypt<'a, T, C>(
        encrypted: T::Encrypted,
        cipher: &C,
        tag: Tag,
    ) -> Result<T, Unspecified>
    where
        T: Decrypt,
        C: Cipher,
        Tag: IntoAad<'a>,
    {
        Self::decrypt_with_aad(encrypted, cipher, tag, ())
    }

    /// Decrypts a ciphertext using extra AAD combined with the tag.
    ///
    /// This is the symmetric counterpart to
    /// [`ContextTag::encrypt_with_aad`](Encrypt::encrypt_with_aad).
    /// The final AAD is `(extra_aad, tag)`, matching what was used during encryption.
    ///
    /// # Example
    ///
    /// ```
    /// use vitaminc_aead::{ContextTag, Encrypt, Decrypt};
    /// use vitaminc_aead::test_utils::TestCipher;
    ///
    /// let cipher = TestCipher;
    ///
    /// let tagged = ContextTag::new("secret", "table:users");
    /// let ciphertext = tagged
    ///     .encrypt_with_aad(&cipher, "row:99")
    ///     .expect("encryption failed");
    ///
    /// let plaintext: String = ContextTag::decrypt_with_aad(
    ///     ciphertext,
    ///     &cipher,
    ///     "table:users",
    ///     "row:99",
    /// )
    /// .expect("decryption failed");
    /// assert_eq!(plaintext, "secret");
    /// ```
    pub fn decrypt_with_aad<'a, T, C, A>(
        encrypted: T::Encrypted,
        cipher: &C,
        tag: Tag,
        extra_aad: A,
    ) -> Result<T, Unspecified>
    where
        T: Decrypt,
        C: Cipher,
        Tag: IntoAad<'a>,
        A: IntoAad<'a>,
    {
        T::decrypt_with_aad(encrypted, cipher, (extra_aad, tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Aad, LocalCipherText};
    use std::cell::RefCell;

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

    impl Cipher for MockCipher {
        fn encrypt_slice<'a, A>(
            &self,
            plaintext: &'a [u8],
            aad: A,
        ) -> Result<LocalCipherText, Unspecified>
        where
            A: IntoAad<'a>,
        {
            *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
            Ok(LocalCipherText::from(plaintext.to_vec()))
        }

        fn encrypt_vec<'a, A>(
            &self,
            plaintext: Vec<u8>,
            aad: A,
        ) -> Result<LocalCipherText, Unspecified>
        where
            A: IntoAad<'a>,
        {
            *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
            Ok(LocalCipherText::from(plaintext))
        }

        fn decrypt_vec<'a, A>(
            &self,
            ciphertext: LocalCipherText,
            _aad: A,
        ) -> Result<Vec<u8>, Unspecified>
        where
            A: IntoAad<'a>,
        {
            Ok(ciphertext.into_inner().to_vec())
        }
    }

    #[test]
    fn test_context_tag_encrypts_inner_value() {
        let plaintext = vec![1u8, 2, 3, 4];
        let context_tag = ContextTag::new(plaintext.clone(), "tag_aad");

        let cipher = MockCipher::new();
        let result = context_tag.encrypt_with_aad(&cipher, "extra");

        let ciphertext = result.expect("encryption should succeed");
        assert_eq!(ciphertext.as_ref(), &plaintext);
        let expected = Aad::pae(&[b"extra", b"tag_aad"]);
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn test_context_tag_combines_extra_and_tag_aad() {
        let context_tag = ContextTag::new(vec![0u8], "tag");

        let cipher = MockCipher::new();
        context_tag
            .encrypt_with_aad(&cipher, "extra")
            .expect("encryption should succeed");

        // The tuple (extra_aad, tag_aad) is PAE-encoded
        let expected = Aad::pae(&[b"extra", b"tag"]);
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }

    #[test]
    fn test_refine_combines_aad() {
        let plaintext = vec![1u8, 2, 3];
        let context_tag = ContextTag::new(plaintext.clone(), "first").refine("second");

        let cipher = MockCipher::new();
        let ciphertext = context_tag
            .encrypt_with_aad(&cipher, "extra")
            .expect("encryption should succeed");

        assert_eq!(ciphertext.as_ref(), &plaintext);
        // extra + (first, second) => PAE(extra, PAE(first, second))
        let inner = Aad::pae(&[b"first", b"second"]);
        let expected = Aad::pae(&[b"extra", inner.as_bytes()]);
        assert_eq!(cipher.captured_aad(), expected.as_bytes());
    }
}
