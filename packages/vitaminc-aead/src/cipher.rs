use crate::{Encrypt, IntoAad};

/// An error that provides **no information** about the failure.
/// It is crucial when returning an error from a cipher operation
/// that does not reveal any details about the failure as this can lead to side channel attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unspecified;

impl std::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unspecified error")
    }
}

impl std::error::Error for Unspecified {}

/// A driver of an encryption operation, analogous to serde's `Serializer`.
///
/// `Cipher` defines the entry points an [`Encrypt`](crate::Encrypt) implementation
/// can use to encrypt itself. Concrete implementations (e.g. an AES-256-GCM
/// cipher) decide how plaintext is sealed and what ciphertext container is
/// produced via [`Ok`](Cipher::Ok).
///
/// The trait supports three modes:
/// - raw byte plaintext, via [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec) /
///   [`encrypt_bytes_array`](Cipher::encrypt_bytes_array);
/// - structured sequences, via [`encrypt_seq`](Cipher::encrypt_seq) returning
///   a [`SeqCipher`];
/// - structured maps, via [`encrypt_map`](Cipher::encrypt_map) returning a
///   [`MapCipher`].
pub trait Cipher: Sized {
    /// The encrypted output produced by this cipher (e.g. a structured
    /// ciphertext container holding nonce + ciphertext + tag).
    type Ok;
    /// The error type returned on cipher failure. Implementations should keep
    /// this opaque — see [`Unspecified`].
    type Error;
    /// The sub-cipher returned by [`encrypt_seq`](Cipher::encrypt_seq).
    type SeqCipher: SeqCipher<Ok = Self::Ok, Error = Self::Error>;
    /// The sub-cipher returned by [`encrypt_map`](Cipher::encrypt_map).
    type MapCipher: MapCipher<Ok = Self::Ok, Error = Self::Error>;

    /// Encrypt the given byte vector with the supplied associated data.
    fn encrypt_bytes_vec<'a, A>(self, data: Vec<u8>, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>;

    /// Encrypt a fixed-size byte array. The default implementation forwards to
    /// [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec).
    fn encrypt_bytes_array<'a, const N: usize, A>(
        self,
        data: [u8; N],
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // See https://github.com/cipherstash/vitaminc/issues/170 — verify
        // `to_vec` behaviour and zeroize the original stack array.
        self.encrypt_bytes_vec(data.to_vec(), aad)
    }

    /// Begin encrypting a sequence of values. `size_hint` lets the implementation
    /// preallocate when known.
    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher;

    /// Begin encrypting a map of key/value pairs.
    fn encrypt_map(self) -> Self::MapCipher;

    // Tracked: https://github.com/cipherstash/vitaminc/issues/171
    // fn encrypt_some<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    // where
    //     T: Encrypt,
    // {
    //     value.encrypt(self)
    // }
    //
    // fn encrypt_none(self) -> Result<Self::Ok, Self::Error>;
    //
    // fn passthrough<T: 'static>(self, data: T) -> Result<Self::Ok, Self::Error>;
}

/// Sub-cipher driving the encryption of a sequence of values.
///
/// Obtained from [`Cipher::encrypt_seq`]. Each element is encrypted with
/// [`encrypt_next`](SeqCipher::encrypt_next); the caller finalises the sequence
/// with [`end`](SeqCipher::end) to produce the cipher's `Ok` output.
pub trait SeqCipher: Sized {
    /// The final encrypted output produced by [`end`](SeqCipher::end).
    type Ok;
    /// The error type for sequence operations.
    type Error;

    /// Encrypt the next element in the sequence, returning the updated cipher.
    fn encrypt_next<'a, T, A>(self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>;

    /// Finalise the sequence and return the produced ciphertext container.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Sub-cipher driving the encryption of a map of key/value pairs.
///
/// Obtained from [`Cipher::encrypt_map`]. Keys are not encrypted; values are.
/// The expected call order is key → value → key → value → … → `end`, or use
/// the [`encrypt_entry`](MapCipher::encrypt_entry) convenience method.
///
/// # Static keys only
///
/// [`encrypt_key`](MapCipher::encrypt_key) takes a `&'static str`, so maps can
/// only be *encrypted* when their keys are known at compile time. A
/// `HashMap<String, T>` with runtime-derived keys can be *decrypted* (the
/// [`Decrypt`](crate::Decrypt) impl yields `HashMap<String, T>`) but cannot be
/// encrypted directly — only `HashMap<&'static str, T>` implements
/// [`Encrypt`](crate::Encrypt).
pub trait MapCipher: Sized {
    /// The final encrypted output produced by [`end`](MapCipher::end).
    type Ok;
    /// The error type for map operations.
    type Error;

    /// Record the next key. Keys are stored in the clear — only values are
    /// encrypted.
    ///
    /// Must be followed by exactly one [`encrypt_value`](MapCipher::encrypt_value)
    /// before the next `encrypt_key` or [`end`](MapCipher::end). Calling
    /// `encrypt_key` twice with no intervening `encrypt_value` is a trait-contract
    /// violation; implementations should return an error rather than silently
    /// dropping the first key.
    fn encrypt_key(self, key: &'static str) -> Result<Self, Self::Error>;

    /// Encrypt the value associated with the most recently supplied key.
    fn encrypt_value<'a, T, A>(self, value: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>;

    /// Convenience for [`encrypt_key`](MapCipher::encrypt_key) followed by
    /// [`encrypt_value`](MapCipher::encrypt_value).
    fn encrypt_entry<'a, T, A>(
        self,
        key: &'static str,
        value: T,
        aad: A,
    ) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
        Self: Sized,
    {
        self.encrypt_key(key)
            .and_then(|mc| mc.encrypt_value(value, aad))
    }

    /*fn encrypt_passthrough_entry<T>(self, key: &'static str, value: T) -> Self
    where
        T: erased_serde::Serialize + Send + Sync + 'static,
        Self: Sized,
    {
        self.encrypt_key(key).passthrough(value)
    }*/

    /// Finalise the map and return the produced ciphertext container.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}
