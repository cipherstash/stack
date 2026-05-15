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
    type Ok<T>
    where
        T: Send + 'c;
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

    fn decrypt_bytes<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value>;
    fn decrypt_seq<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value>;
    fn decrypt_map<V: DecipherVisitor<'c> + Send + 'c>(self, visitor: V) -> Self::Ok<V::Value>;
}

pub trait DecipherVisitor<'c>: Sized {
    type Value: Send;

    fn visit_bytes_vec(self, _data: Vec<u8>) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }

    fn visit_seq<A: SeqAccess<'c>>(self, _seq: A) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }

    fn visit_map<A: MapAccess<'c>>(self, _map: A) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }
}

pub trait SeqAccess<'c> {
    type Error;
    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error>;
}

pub trait MapAccess<'c> {
    type Error;
    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error>;
}

/// The counterpart to `Encrypt` — a type that knows how to decrypt itself using a `Decipher`.
/// Analogous to serde's `Deserialize`.
pub trait Decrypt<'c>: Sized + Send {
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self>;
}
