//! Cipher-backend traits for the decrypt direction — the mirror of
//! [`cipher`](crate::cipher).
//!
//! [`Decipher`] drives decryption the way [`Cipher`](crate::Cipher) drives
//! encryption, with [`DecipherVisitor`], [`SeqAccess`] and [`MapAccess`] as
//! its sub-protocols. The plaintext-side trait a type implements to decode
//! *itself* lives in [`decrypt`](crate::decrypt), mirroring how
//! [`Encrypt`](crate::Encrypt) sits opposite [`Cipher`](crate::Cipher).

use std::any::Any;

use vitaminc_protected::Protected;

use crate::{decrypt::Decrypt, IntoAad, Unspecified};

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

    /// The payload type returned by
    /// [`decrypt_passthrough`](Decipher::decrypt_passthrough) — matches the
    /// encrypt-side [`Cipher::Passthrough`](crate::Cipher::Passthrough).
    type Passthrough: Send + 'c;

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
    /// visitor's [`visit_seq`](DecipherVisitor::visit_seq). Each element is
    /// verified against [`Aad::for_sequence_element`](crate::Aad::for_sequence_element)
    /// of `aad`, mirroring how [`SeqCipher::encrypt_next`](crate::SeqCipher::encrypt_next)
    /// binds it per element.
    ///
    /// **Caller obligation — order is not authenticated.** Element AAD
    /// carries no positional index (records are retrieved in a different
    /// order than they were inserted), so a permuted sequence still
    /// decrypts. Callers that need positional integrity must bind position
    /// into their own AAD or verify order themselves.
    fn decrypt_seq<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>;
    /// Decrypt a map of ciphertexts authenticated against `aad`, driving the visitor's
    /// [`visit_map`](DecipherVisitor::visit_map). `aad` is applied to every value,
    /// mirroring [`MapCipher::encrypt_value`](crate::MapCipher::encrypt_value).
    ///
    /// **Caller obligation — membership is not authenticated.** Each entry's
    /// key is inseparably bound to its value (via
    /// [`Aad::for_map_entry`](crate::Aad::for_map_entry)), and duplicate
    /// keys are rejected, but the *set* of keys present is not committed:
    /// a column projection (`SELECT foo, bar`) legitimately returns a
    /// subset, so deleting *some* entries from a stored ciphertext still
    /// returns `Ok`. Verify the key set you projected for. The failure
    /// mode is asymmetric — deleting *all* entries **is** caught (an
    /// entry-less `Map` is rejected; emptiness is only provable by the
    /// authenticated empty-map marker) — so do not infer from the
    /// empty-map rejection that partial deletion is covered.
    fn decrypt_map<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>;

    /// Decrypt a ciphertext whose structural shape is **not** known to the
    /// caller, dispatching to the visitor method matching the actual shape:
    /// [`visit_bytes_vec`](DecipherVisitor::visit_bytes_vec) for a single
    /// sealed value, [`visit_seq`](DecipherVisitor::visit_seq) for a
    /// sequence, [`visit_map`](DecipherVisitor::visit_map) for a map, and
    /// [`visit_none`](DecipherVisitor::visit_none) for an authenticated
    /// absent marker (whose AAD binding must be verified before the visitor
    /// is called).
    ///
    /// This is the analog of serde's `deserialize_any`, for self-describing
    /// values such as dynamically typed FFI values, where the plaintext type
    /// is recovered from the ciphertext's shape rather than fixed by the
    /// caller.
    ///
    /// A passthrough ciphertext is dispatched to
    /// [`visit_passthrough`](DecipherVisitor::visit_passthrough), delivering
    /// the stored payload type-erased as `Box<dyn Any + Send>`. Visitors that
    /// do not expect passthrough inherit the default (which errors), so this
    /// remains a rejection for every decoder except a self-describing one that
    /// overrides `visit_passthrough`. A passthrough value is **not**
    /// authenticated, so — unlike [`visit_none`](DecipherVisitor::visit_none) —
    /// there is no AAD binding to verify before the visitor is called.
    fn decrypt_any<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>;

    /// Recover a value stored via [`Cipher::passthrough`](crate::Cipher::passthrough).
    /// Returns an error if the ciphertext is not a passthrough.
    ///
    /// The payload comes back as the decipher's
    /// [`Passthrough`](Decipher::Passthrough) type, exactly as stored —
    /// value-in/value-out. Where that type is `Box<dyn Any + Send>`, as it is
    /// for Rust-native ciphers, callers downcast to a concrete type themselves
    /// (concrete deciphers may offer a typed convenience for this).
    ///
    /// See [`Cipher::passthrough`] — passthrough values are non-sensitive by
    /// design and must not be used to carry secret data.
    fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough>;

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

    /// Called when [`Decipher::decrypt_any`] hit an authenticated absent
    /// marker (see [`Cipher::encrypt_none`](crate::Cipher::encrypt_none)).
    /// The marker's AAD binding has already been verified by the decipher
    /// when this is called. Default returns an error.
    ///
    /// Self-describing visitors (e.g. a dynamically typed FFI value) can
    /// override this to map absence onto their own null representation.
    fn visit_none(self) -> Result<Self::Value, Unspecified> {
        Err(Unspecified)
    }

    /// Called when [`Decipher::decrypt_any`] hit a passthrough value (see
    /// [`Cipher::passthrough`](crate::Cipher::passthrough)). The payload is
    /// delivered **type-erased** as `Box<dyn Any + Send>` — a self-describing
    /// visitor downcasts it to its own value type, returning [`Unspecified`]
    /// for a foreign payload rather than panicking. Default returns an error,
    /// so decoders that do not expect passthrough reject it.
    ///
    /// # ⚠️ Unauthenticated
    ///
    /// The payload is covered by no AEAD tag; a stored passthrough value can be
    /// altered undetectably. Never treat it as authenticated input.
    fn visit_passthrough(
        self,
        _value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Value, Unspecified> {
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
    /// data** — derive the effective AAD by passing the AAD supplied to
    /// [`Decipher::decrypt_seq`] through
    /// [`Aad::for_sequence_element`](crate::Aad::for_sequence_element) and thread it into
    /// the element's [`Decrypt::decrypt_with_aad`]. This mirrors how
    /// [`SeqCipher::encrypt_next`](crate::SeqCipher::encrypt_next) binds the derived AAD to
    /// each element at encrypt time; an implementation that decrypts elements with the bare
    /// (or empty) AAD produces a sequence that fails to decrypt conforming ciphertexts —
    /// or, worse, silently accepts re-homed leaves.
    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error>;
}

/// Pull-style access to entries of a decrypted map.
pub trait MapAccess<'c> {
    /// The error type returned by [`next_entry`](MapAccess::next_entry).
    type Error;
    /// Advance to the next entry and return its key, leaving the value
    /// undecrypted until [`next_value`](MapAccess::next_value) is called.
    ///
    /// The split exists because a map's values are not necessarily
    /// homogeneous: a struct decoder cannot name the type to decrypt into
    /// until it has seen which field the key names. Reading key-first also
    /// makes the decode order-independent, which matters because the *order*
    /// of entries in a stored ciphertext is not authenticated.
    ///
    /// Returns `None` when the map is exhausted. Calling `next_key` twice
    /// without an intervening `next_value` is a contract violation:
    /// implementations must return an error rather than silently discarding
    /// the skipped value, since a discarded value is an unverified one.
    ///
    /// # ⚠️ The key is not yet authenticated
    ///
    /// A key is bound into the AAD its value is sealed against, so a swapped or
    /// renamed key does not survive — but that binding is only *checked* when
    /// [`next_value`](MapAccess::next_value) opens the value. The key this
    /// method returns is the raw stored one, verified by nothing.
    ///
    /// It is therefore safe to use for what it is for: choosing which field to
    /// decode next, since a wrong choice fails at `next_value`. It is not safe
    /// to act on before then. A visitor that branches on the key and returns
    /// early, selects a code path, or records the key somewhere without
    /// reaching `next_value` has acted on attacker-modifiable input. Where a
    /// decision must depend on the key, make it after the value opens.
    fn next_key(&mut self) -> Result<Option<String>, Self::Error>;

    /// Decrypt the value belonging to the key most recently returned by
    /// [`next_key`](MapAccess::next_key), consuming the pending entry.
    ///
    /// As with [`SeqAccess::next_element`], implementations **must authenticate each value
    /// against the map's associated data** — and additionally against the entry's own key.
    /// Derive the effective AAD by passing the AAD supplied to [`Decipher::decrypt_map`]
    /// through [`Aad::for_map_entry`](crate::Aad::for_map_entry) with the entry key, mirroring
    /// the binding [`MapCipher::encrypt_value`](crate::MapCipher::encrypt_value) performs at
    /// encrypt time. An implementation that decrypts values against the bare map AAD leaves
    /// keys swappable in stored ciphertext (and will fail to decrypt conforming ciphertexts).
    ///
    /// Calling this without a pending key is a contract violation;
    /// implementations must return an error.
    fn next_value<T: Decrypt<'c> + 'c>(&mut self) -> Result<T, Self::Error>;

    /// Take the value belonging to the key most recently returned by
    /// [`next_key`](MapAccess::next_key) as a **passthrough** payload,
    /// consuming the pending entry.
    ///
    /// The counterpart of
    /// [`MapCipher::passthrough_entry_boxed`](crate::MapCipher::passthrough_entry_boxed),
    /// and type-erased for the same reason: a decoder generic over every
    /// decipher cannot name the payload type. The caller downcasts.
    ///
    /// Implementations must return an error when there is no pending key, and
    /// when the pending entry is an *encrypted* value rather than a
    /// passthrough — reading a sealed value through this method would hand back
    /// a payload whose tag was never checked.
    ///
    /// # ⚠️ Unauthenticated data
    ///
    /// Unlike [`next_value`](MapAccess::next_value), nothing here is verified.
    /// A passthrough entry carries no tag, and — unlike an encrypted entry's
    /// key — its key is not bound into anything either, so a stored passthrough
    /// entry can be edited, retargeted at another key, added, or removed with
    /// no effect on whether the rest of the map decrypts. That independence is
    /// the point: it is what lets a passthrough value be a plain database
    /// column that other queries read and write on their own. Treat what comes
    /// back as untrusted input, exactly as you would treat that column.
    fn next_passthrough(&mut self) -> Result<Box<dyn Any + Send + 'static>, Self::Error>;

    /// Returns the next decrypted `(key, value)` entry, or `None` when the map is exhausted.
    ///
    /// Convenience for [`next_key`](MapAccess::next_key) followed by
    /// [`next_value`](MapAccess::next_value) — the right entry point for a
    /// homogeneous map (e.g. `HashMap<String, T>`), where the value type is
    /// known before the key is read.
    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error> {
        match self.next_key()? {
            Some(key) => self.next_value::<T>().map(|value| Some((key, value))),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockMapAccess;

    /// `next_entry` is a default method over `next_key` + `next_value`, so
    /// nothing but this pins it down: a homogeneous consumer such as
    /// `HashMap`'s `Decrypt` impl reaches every entry through it, and a
    /// version that reported the map exhausted would decode silently to an
    /// empty map rather than failing.
    #[test]
    fn next_entry_default_yields_every_entry_then_none() {
        let mut map = MockMapAccess::new([("first", "a"), ("second", "b")]);

        assert_eq!(
            MapAccess::<'static>::next_entry::<String>(&mut map),
            Ok(Some(("first".to_string(), "a".to_string())))
        );
        assert_eq!(
            MapAccess::<'static>::next_entry::<String>(&mut map),
            Ok(Some(("second".to_string(), "b".to_string())))
        );
        assert_eq!(
            MapAccess::<'static>::next_entry::<String>(&mut map),
            Ok(None)
        );
    }

    /// The default must not paper over the contract the split imposes:
    /// `next_value` with no pending key is an error, and it propagates.
    #[test]
    fn next_value_without_a_key_is_an_error() {
        let mut map = MockMapAccess::new([("first", "a")]);

        assert_eq!(
            MapAccess::<'static>::next_value::<String>(&mut map),
            Err(Unspecified)
        );
    }

    /// Skipping a value leaves its AAD binding unverified, so a second
    /// `next_key` must fail rather than discard the pending entry.
    #[test]
    fn skipping_a_value_is_an_error() {
        let mut map = MockMapAccess::new([("first", "a"), ("second", "b")]);

        assert_eq!(
            MapAccess::<'static>::next_key(&mut map),
            Ok(Some("first".to_string()))
        );
        assert_eq!(MapAccess::<'static>::next_key(&mut map), Err(Unspecified));
    }
}
