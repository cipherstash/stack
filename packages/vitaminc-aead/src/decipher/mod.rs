pub mod impls;

use std::any::Any;

use vitaminc_protected::Protected;

use crate::{Aad, IntoAad, Unspecified};

/// A trait for types that can decrypt data, driving a [`DecipherVisitor`] to produce values.
///
/// Analogous to serde's `Deserializer`. The [`Ok`](Decipher::Ok) GAT (generic associated type)
/// allows implementations to wrap the output in different containers:
///
/// - **Sync**: `type Ok<T> = Result<T, Unspecified>`
/// - **Async**: `type Ok<T> = BoxFuture<'c, Result<T, Unspecified>>`
///
/// Because `Ok<T>` is a GAT, code that holds a `D::Ok<T>` cannot generically transform the
/// inner `T` (e.g., wrapping it in `Box`, `Protected`, or another newtype). The [`map_ok`]
/// associated function solves this by requiring each `Decipher` implementation to provide a
/// mapping operation over its `Ok` container — essentially a functor `fmap`.
///
/// [`map_ok`]: Decipher::map_ok
pub trait Decipher<'c>: Sized {
    /// The output container produced by a decrypt call. Implementations may
    /// wrap the result in `Result<_, _>` (sync) or `BoxFuture<_, _>` (async).
    ///
    /// The failure mode is carried inside this container (e.g. the `Err`
    /// variant of a `Result`), so there is no separate associated error type —
    /// failures are always reported as [`Unspecified`].
    type Ok<T>
    where
        T: Send + 'c;

    /// Transform the inner value of an [`Ok`](Decipher::Ok) container.
    ///
    /// This enables `Decrypt` implementations for wrapper types (e.g., `Box<T>`, `Protected<T>`)
    /// to decrypt the inner type and then wrap the result. Note the AAD is threaded into the
    /// inner [`decrypt_with_aad`](Decrypt::decrypt_with_aad) — a wrapper must not drop it:
    ///
    /// ```ignore
    /// fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    /// where
    ///     D: Decipher<'c>,
    ///     A: IntoAad<'a>,
    /// {
    ///     D::map_ok(T::decrypt_with_aad(decipher, aad), Wrapper::new)
    /// }
    /// ```
    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
    where
        T: Send + 'c,
        U: Send + 'c,
        F: FnOnce(T) -> U;

    /// Decrypt a single byte-oriented ciphertext authenticated against `aad`,
    /// driving the visitor's [`visit_bytes_vec`](DecipherVisitor::visit_bytes_vec).
    ///
    /// `aad` mirrors [`Cipher::encrypt_bytes_vec`](crate::Cipher::encrypt_bytes_vec): it must
    /// match the associated data bound at encrypt time or decryption fails.
    fn decrypt_bytes<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>;
    /// Decrypt a sequence of ciphertexts authenticated against `aad`, driving the
    /// visitor's [`visit_seq`](DecipherVisitor::visit_seq). `aad` is applied to every
    /// element, mirroring how [`SeqCipher::encrypt_next`](crate::SeqCipher::encrypt_next)
    /// binds it per element.
    fn decrypt_seq<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>;
    /// Decrypt a map of ciphertexts authenticated against `aad`, driving the visitor's
    /// [`visit_map`](DecipherVisitor::visit_map). `aad` is applied to every value,
    /// mirroring [`MapCipher::encrypt_value`](crate::MapCipher::encrypt_value).
    fn decrypt_map<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>;

    /// Recover a value stored via [`Cipher::passthrough`](crate::Cipher::passthrough).
    /// Returns an error if the ciphertext is not a passthrough or the stored
    /// type does not match `T`.
    ///
    /// See [`Cipher::passthrough`] — passthrough values are non-sensitive by
    /// design and must not be used to carry secret data.
    fn decrypt_passthrough<T>(self) -> Self::Ok<T>
    where
        T: Any + Send + 'static;

    /// Decrypt an `Option<T>`, authenticating against `aad`. The decipher inspects the
    /// ciphertext shape: a `None`-marker variant produces `Ok(None)` (after AAD
    /// verification); any other shape is decrypted as `T` and wrapped in `Some`.
    fn decrypt_option<'a, T, A>(self, aad: A) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>;
}

/// A visitor over the structural shape of a ciphertext, analogous to serde's
/// `Visitor`.
///
/// A [`Decrypt`] implementation supplies a `DecipherVisitor` to a [`Decipher`]
/// and overrides the `visit_*` method matching the shape it expects. Unknown
/// shapes default to [`Unspecified`].
pub trait DecipherVisitor<'c>: Sized {
    /// The decoded value produced by this visitor.
    type Value: Send;

    /// Called when the decipher produced raw bytes. Default returns an error.
    ///
    /// The plaintext is delivered inside `Protected<Vec<u8>>` so the
    /// zeroize-on-drop guarantee survives the trait boundary. Visitor
    /// implementations that need to hand a value of a different shape to
    /// their caller should extract via [`Controlled::risky_ref`] /
    /// [`Controlled::risky_unwrap`] only at the explicit boundary where
    /// ownership leaves the cipher pipeline.
    ///
    /// [`Controlled::risky_ref`]: vitaminc_protected::Controlled::risky_ref
    /// [`Controlled::risky_unwrap`]: vitaminc_protected::Controlled::risky_unwrap
    fn visit_bytes_vec(self, _data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }

    /// Called when the decipher produced a sequence. Default returns an error.
    fn visit_seq<A: SeqAccess<'c>>(self, _seq: A) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }

    /// Called when the decipher produced a map. Default returns an error.
    fn visit_map<A: MapAccess<'c>>(self, _map: A) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }
}

/// Pull-style access to elements of a decrypted sequence.
pub trait SeqAccess<'c> {
    /// The error type returned by [`next_element`](SeqAccess::next_element).
    type Error;
    /// Returns the next decrypted element, or `None` when the sequence is exhausted.
    ///
    /// Implementations **must authenticate each element against the sequence's associated
    /// data** — thread the AAD supplied to [`Decipher::decrypt_seq`] into the element's
    /// [`Decrypt::decrypt_with_aad`]. This mirrors how
    /// [`SeqCipher::encrypt_next`](crate::SeqCipher::encrypt_next) binds the AAD to each
    /// element at encrypt time; an implementation that decrypts elements with empty AAD
    /// produces a silently unauthenticated sequence.
    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error>;
}

/// Pull-style access to entries of a decrypted map.
pub trait MapAccess<'c> {
    /// The error type returned by [`next_entry`](MapAccess::next_entry).
    type Error;
    /// Returns the next decrypted `(key, value)` entry, or `None` when the map is exhausted.
    ///
    /// As with [`SeqAccess::next_element`], implementations **must authenticate each value
    /// against the map's associated data** — thread the AAD supplied to
    /// [`Decipher::decrypt_map`] into the value's [`Decrypt::decrypt_with_aad`], mirroring
    /// [`MapCipher::encrypt_value`](crate::MapCipher::encrypt_value).
    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error>;
}

/// The counterpart to `Encrypt` — a type that knows how to decrypt itself using a `Decipher`.
/// Analogous to serde's `Deserialize`.
pub trait Decrypt<'c>: Sized + Send {
    /// Decrypt `Self` from the given decipher with no associated data.
    ///
    /// Convenience wrapper around [`decrypt_with_aad`](Decrypt::decrypt_with_aad), mirroring
    /// [`Encrypt::encrypt`](crate::Encrypt::encrypt).
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        Self::decrypt_with_aad(decipher, Aad::empty())
    }

    /// Decrypt `Self` from the given decipher, authenticating against `aad`.
    ///
    /// This is the method implementations provide; it mirrors
    /// [`Encrypt::encrypt_with_aad`](crate::Encrypt::encrypt_with_aad). The `aad` must match
    /// the associated data bound at encrypt time or decryption fails.
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>;
}
