pub mod impls;

use crate::Unspecified;

/// A trait for types that can decrypt data, driving a [`DecipherVisitor`] to produce values.
///
/// Analogous to serde's `Deserializer`. The [`Ok`](Decipher::Ok) GAT (generic associated type)
/// allows implementations to wrap the output in different containers:
///
/// - **Sync**: `type Ok<T> = Result<T, Unspecified>`
/// - **Async**: `type Ok<T> = BoxFuture<'c, Result<T, Error>>`
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
    type Ok<T>
    where
        T: Send + 'c;
    /// The error type returned on decryption failure. Implementations should
    /// keep this opaque — see [`Unspecified`].
    type Error;

    /// Transform the inner value of an [`Ok`](Decipher::Ok) container.
    ///
    /// This enables `Decrypt` implementations for wrapper types (e.g., `Box<T>`, `Protected<T>`)
    /// to decrypt the inner type and then wrap the result:
    ///
    /// ```ignore
    /// fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
    ///     D::map_ok(T::decrypt(decipher), Wrapper::new)
    /// }
    /// ```
    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
    where
        T: Send + 'c,
        U: Send + 'c,
        F: FnOnce(T) -> U;

    /// Decrypt a single byte-oriented ciphertext, driving the visitor's
    /// [`visit_bytes_vec`](DecipherVisitor::visit_bytes_vec).
    fn decrypt_bytes<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value>;
    /// Decrypt a sequence of ciphertexts, driving the visitor's
    /// [`visit_seq`](DecipherVisitor::visit_seq).
    fn decrypt_seq<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value>;
    /// Decrypt a map of ciphertexts, driving the visitor's
    /// [`visit_map`](DecipherVisitor::visit_map).
    fn decrypt_map<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value>;
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
    fn visit_bytes_vec(self, _data: Vec<u8>) -> Result<Self::Value, Unspecified> {
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
    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error>;
}

/// Pull-style access to entries of a decrypted map.
pub trait MapAccess<'c> {
    /// The error type returned by [`next_entry`](MapAccess::next_entry).
    type Error;
    /// Returns the next decrypted `(key, value)` entry, or `None` when the map is exhausted.
    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error>;
}

/// The counterpart to `Encrypt` — a type that knows how to decrypt itself using a `Decipher`.
/// Analogous to serde's `Deserialize`.
pub trait Decrypt<'c>: Sized + Send {
    /// Decrypt `Self` from the given decipher, returning the decipher's
    /// `Ok` container.
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self>;
}
