use std::any::Any;
use std::borrow::Cow;

use vitaminc_protected::{Controlled, Protected};

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
    ///
    /// The plaintext is taken as `Protected<Vec<u8>>` so the chain of custody
    /// — and the zeroize-on-drop guarantee — survives the trait boundary.
    /// Implementations should keep the value inside `Protected` for the
    /// duration of the encryption and let it drop (and wipe) at end of scope.
    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>;

    /// Encrypt a fixed-size byte array. The default implementation forwards to
    /// [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec).
    ///
    /// As with [`encrypt_bytes_vec`](Cipher::encrypt_bytes_vec), the plaintext
    /// is taken inside `Protected` so the stack array is wiped on drop after
    /// `to_vec` has copied its contents onto the heap.
    fn encrypt_bytes_array<'a, const N: usize, A>(
        self,
        data: Protected<[u8; N]>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // Borrow the protected array so it stays owned by `data` and is
        // wiped by ZeroizeOnDrop at end of scope. A `risky_unwrap` here
        // would partially-move out of `data`, skipping its Drop and
        // leaving the bare `[u8; N]` on the stack — see issue #170.
        let copy = Protected::new(data.risky_ref().to_vec());
        self.encrypt_bytes_vec(copy, aad)
    }

    /// Begin encrypting a sequence of values. `size_hint` lets the implementation
    /// preallocate when known.
    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher;

    /// Begin encrypting a map of key/value pairs.
    fn encrypt_map(self) -> Self::MapCipher;

    /// Encrypt a present optional value. Default forwards to the inner value's
    /// [`Encrypt`] impl — the `Some` discriminator is implicit in the structural
    /// shape of the ciphertext (any non-`None` variant means `Some`).
    fn encrypt_some<'a, T, A>(self, value: T, aad: A) -> Result<Self::Ok, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        value.encrypt_with_aad(self, aad)
    }

    /// Encrypt the absent case of an optional value. Must produce a
    /// cryptographically authenticated marker — distinguishable from any
    /// `Some(_)` ciphertext and bound to `aad` so it cannot be forged.
    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>;

    /// Pass a typed value through the cipher's output container **without**
    /// encrypting it. Intended for fields that need to survive the encryption
    /// envelope in the clear (e.g. a schema version tag).
    ///
    /// The value is typed at the API boundary but stored opaquely by the
    /// cipher; the corresponding [`Decipher::decrypt_passthrough`] checks the
    /// type at runtime.
    ///
    /// # ⚠️ Non-sensitive data only
    ///
    /// Passthrough values travel **in the clear** alongside the ciphertext.
    /// Do not use this for secret-bearing data such as keys, plaintexts, or
    /// credentials — there is no encryption, no zeroize discipline applied
    /// to the boxed value, and no guarantee about when the storage is freed.
    /// For secrets, use [`encrypt_with_aad`](crate::Encrypt::encrypt_with_aad)
    /// (via the [`Encrypt`](crate::Encrypt) trait) or wrap in
    /// [`vitaminc_protected::Protected`].
    fn passthrough<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    where
        T: Any + Send + 'static;
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

    /// Append a passthrough (unencrypted) element to the sequence.
    ///
    /// See [`Cipher::passthrough`] — passthrough values are non-sensitive by
    /// design and must not carry secret data.
    fn passthrough_next<T>(self, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static;

    /// Finalise the sequence and return the produced ciphertext container.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}

/// Sub-cipher driving the encryption of a map of key/value pairs.
///
/// Obtained from [`Cipher::encrypt_map`]. Keys are not encrypted; values are.
/// The expected call order is key → value → key → value → … → `end`, or use
/// the [`encrypt_entry`](MapCipher::encrypt_entry) convenience method.
///
/// Keys may be `&'static str` or owned `String`s (anything
/// `Into<Cow<'static, str>>`), so maps with runtime-derived keys — e.g. values
/// crossing an FFI boundary — can be encrypted as well as decrypted.
///
/// # Key authentication
///
/// Keys travel in the clear, but they are **not** unauthenticated:
/// implementations must bind each entry's key into the AAD its value is sealed
/// against, via [`Aad::for_map_entry`](crate::Aad::for_map_entry). Swapping or
/// renaming keys in a stored ciphertext therefore causes the affected values to
/// fail decryption. [`MapAccess`](crate::MapAccess) implementations perform the
/// symmetric binding on decrypt.
///
/// The exception is [`passthrough_entry`](MapCipher::passthrough_entry): a
/// passthrough value is neither encrypted nor authenticated, so nothing seals
/// its key either.
pub trait MapCipher: Sized {
    /// The final encrypted output produced by [`end`](MapCipher::end).
    type Ok;
    /// The error type for map operations.
    type Error;

    /// Record the next key. Keys are stored in the clear — only values are
    /// encrypted — but each key is bound into its value's AAD (see the
    /// trait-level *Key authentication* notes).
    ///
    /// Must be followed by exactly one [`encrypt_value`](MapCipher::encrypt_value)
    /// before the next `encrypt_key` or [`end`](MapCipher::end). Calling
    /// `encrypt_key` twice with no intervening `encrypt_value` is a trait-contract
    /// violation; implementations should return an error rather than silently
    /// dropping the first key.
    fn encrypt_key<K>(self, key: K) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>;

    /// Encrypt the value associated with the most recently supplied key.
    ///
    /// Implementations **must not** seal the value against `aad` directly:
    /// they must bind the pending key alongside it via
    /// [`Aad::for_map_entry`](crate::Aad::for_map_entry), so that key and value
    /// are cryptographically inseparable in the stored ciphertext.
    fn encrypt_value<'a, T, A>(self, value: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>;

    /// Convenience for [`encrypt_key`](MapCipher::encrypt_key) followed by
    /// [`encrypt_value`](MapCipher::encrypt_value).
    fn encrypt_entry<'a, K, T, A>(self, key: K, value: T, aad: A) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>,
        T: Encrypt,
        A: IntoAad<'a>,
        Self: Sized,
    {
        self.encrypt_key(key)
            .and_then(|mc| mc.encrypt_value(value, aad))
    }

    /// Insert a passthrough (unencrypted) entry under `key`. Equivalent to
    /// [`encrypt_key`](MapCipher::encrypt_key) followed by storing the value
    /// without AEAD treatment.
    ///
    /// See [`Cipher::passthrough`] — passthrough values are non-sensitive by
    /// design and must not carry secret data. Neither the value nor its key is
    /// authenticated.
    fn passthrough_entry<K, T>(self, key: K, value: T) -> Result<Self, Self::Error>
    where
        K: Into<Cow<'static, str>>,
        T: Any + Send + 'static;

    /// Finalise the map and return the produced ciphertext container.
    fn end(self) -> Result<Self::Ok, Self::Error>;
}
