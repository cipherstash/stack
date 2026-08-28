//! [`Passthrough`], a wrapper that carries a value through the ciphertext
//! container **without encrypting it** — the typed front door to the
//! [`Cipher::passthrough_boxed`] / [`DecipherVisitor::visit_passthrough`]
//! channel.
//!
//! # Why carry a field in the clear
//!
//! Not every column of a table needs encrypting. A record usually has a few
//! fields that other queries select, filter, or update without holding the
//! key — a display name, a schema version, a plain `id` column — beside the
//! ones that must be sealed. Encrypt those too and the storage layer can no
//! longer index, filter, or interpret the row without a decryption key.
//!
//! Passthrough stores such a field as a cleartext entry of the *same*
//! ciphertext container as the encrypted ones, so the record still seals,
//! moves, and round-trips as a single unit while that field stays an ordinary
//! column. The alternative — storing it beside the ciphertext — splits one
//! record into two things that can drift apart.
//!
//! This is exactly what [`#[aead(passthrough)]`](crate::Encrypt#aeadpassthrough)
//! does for a derived impl; `Passthrough<T>` is its hand-written equivalent,
//! and carries the same contract — see the warning below.
//!
//! # Why this type rather than the cipher's own hooks
//!
//! [`Cipher::passthrough`](crate::Cipher::passthrough) and its map/sequence
//! siblings already provide the channel, but reaching them means naming the
//! cipher's own [`Cipher::Passthrough`](crate::Cipher::Passthrough) payload
//! type — which only code written against one concrete cipher can do.
//!
//! A struct's [`Encrypt`] / [`Decrypt`] impl is generic over *every* cipher,
//! so it cannot name that type and has no way to call
//! [`MapCipher::passthrough_entry`](crate::MapCipher::passthrough_entry)
//! or [`SeqCipher::passthrough_next`](crate::SeqCipher::passthrough_next)
//! with a value it owns (an impl cannot add bounds the trait lacks). The
//! type-erased hooks close that gap at the trait level; this wrapper packages
//! them so a field can be declared "stored in the clear" with one type
//! annotation and driven through the ordinary
//! [`encrypt_entry`](crate::MapCipher::encrypt_entry) /
//! [`encrypt_next`](crate::SeqCipher::encrypt_next) /
//! [`next_entry`](crate::MapAccess::next_entry) calls like any other field:
//!
//! ```ignore
//! cipher
//!     .encrypt_map(aad)
//!     .encrypt_entry("id", Passthrough(self.id))?        // in the clear
//!     .encrypt_entry("email", self.email)?               // encrypted
//!     .end()
//! ```
//!
//! On decrypt, the visitor downcasts the erased payload back to `T`; a
//! foreign payload type is an [`Unspecified`] error, never a panic.
//!
//! # ⚠️ No security guarantees whatsoever
//!
//! Identical contract to [`Cipher::passthrough`](crate::Cipher::passthrough)
//! and to [`#[aead(passthrough)]`](crate::Encrypt#aeadpassthrough), which
//! documents it in full. In short: the value travels **in the clear** and is
//! **not authenticated** — a stored passthrough value (and, for map entries,
//! its key) can be read, edited, added, or removed undetectably, and every
//! encrypted field beside it still decrypts. Treat what comes back as
//! untrusted input.
//!
//! So: non-sensitive, non-security-deciding data only. Never a field the
//! program then trusts to make an authorization choice — a tenant, a role, a
//! scope — nor one used to select which encrypted record to trust. Anything
//! secret-bearing belongs in [`Protected`](vitaminc_protected::Protected) and
//! gets encrypted; anything that must be tamper-evident but readable belongs
//! in the AAD, not in a passthrough.
//!
//! This is the dynamic-path counterpart of `hlist::Passthrough` (behind the
//! `hlist` feature), which serves the opt-in statically-shaped encoding.

use std::any::Any;
use std::marker::PhantomData;

use crate::{
    cipher::Cipher,
    decipher::{Decipher, DecipherVisitor},
    decrypt::Decrypt,
    encrypt::Encrypt,
    IntoAad, Unspecified,
};

/// A value carried through the ciphertext container **in the clear**: neither
/// encrypted nor authenticated. For non-sensitive routing/display data only —
/// identifiers, schema versions, display names. A struct field typed
/// `Passthrough<T>` drives the type-erased passthrough channel through the
/// ordinary `encrypt_entry` / `next_entry` calls, so a cipher-generic
/// [`Encrypt`] / [`Decrypt`] impl can mix clear and encrypted fields without
/// naming any cipher's payload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Passthrough<T>(pub T);

impl<T> Passthrough<T> {
    /// Consume the wrapper, returning the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Passthrough<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> Encrypt for Passthrough<T>
where
    T: Send + 'static,
{
    /// Hands the value to [`Cipher::passthrough_boxed`]. The AAD is ignored:
    /// a passthrough value is neither encrypted nor authenticated.
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, _aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.passthrough_boxed(Box::new(self.0))
    }
}

impl<'c, T> Decrypt<'c> for Passthrough<T>
where
    T: Send + 'static,
{
    /// Expects a passthrough node and downcasts its payload to `T`. Any other
    /// node shape, or a payload of a different type, is [`Unspecified`].
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        struct PassthroughVisitor<T>(PhantomData<fn() -> T>);

        impl<'c, T> DecipherVisitor<'c> for PassthroughVisitor<T>
        where
            T: Send + 'static,
        {
            type Value = Passthrough<T>;

            fn visit_passthrough(
                self,
                value: Box<dyn Any + Send + 'static>,
            ) -> Result<Self::Value, Unspecified> {
                value
                    .downcast::<T>()
                    .map(|v| Passthrough(*v))
                    .map_err(|_| Unspecified)
            }
        }

        decipher.decrypt_any(PassthroughVisitor(PhantomData), aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{MapCipher, SeqCipher};
    use std::cell::RefCell;

    // A cipher that records what reaches the passthrough channel.
    struct SpyCipher {
        boxed: RefCell<Option<Box<dyn Any + Send + 'static>>>,
    }

    struct Unused;

    impl Cipher for &SpyCipher {
        type Ok = ();
        type Error = Unspecified;
        type Passthrough = ();
        type SeqCipher = Unused;
        type MapCipher = Unused;

        fn encrypt_bytes_vec<'a, A>(
            self,
            _data: vitaminc_protected::Protected<Vec<u8>>,
            _aad: A,
        ) -> Result<Self::Ok, Self::Error>
        where
            A: IntoAad<'a>,
        {
            // A passthrough must never take the encrypted path.
            Err(Unspecified)
        }

        fn encrypt_seq<'a, A>(self, _size_hint: Option<usize>, _aad: A) -> Self::SeqCipher
        where
            A: IntoAad<'a>,
        {
            Unused
        }

        fn encrypt_map<'a, A>(self, _aad: A) -> Self::MapCipher
        where
            A: IntoAad<'a>,
        {
            Unused
        }

        fn encrypt_none<'a, A>(self, _aad: A) -> Result<Self::Ok, Self::Error>
        where
            A: IntoAad<'a>,
        {
            Err(Unspecified)
        }

        fn passthrough(self, _value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
            Err(Unspecified)
        }

        fn passthrough_boxed(
            self,
            value: Box<dyn Any + Send + 'static>,
        ) -> Result<Self::Ok, Self::Error> {
            *self.boxed.borrow_mut() = Some(value);
            Ok(())
        }
    }

    impl SeqCipher for Unused {
        type Ok = ();
        type Error = Unspecified;
        type Passthrough = ();
        fn encrypt_next<T: Encrypt>(self, _data: T) -> Result<Self, Self::Error> {
            Err(Unspecified)
        }
        fn passthrough_next(self, _value: Self::Passthrough) -> Result<Self, Self::Error> {
            Err(Unspecified)
        }
        fn end(self) -> Result<Self::Ok, Self::Error> {
            Err(Unspecified)
        }
    }

    impl MapCipher for Unused {
        type Ok = ();
        type Error = Unspecified;
        type Passthrough = ();
        fn encrypt_key<K>(self, _key: K) -> Result<Self, Self::Error>
        where
            K: Into<std::borrow::Cow<'static, str>>,
        {
            Err(Unspecified)
        }
        fn encrypt_value<T: Encrypt>(self, _value: T) -> Result<Self, Self::Error> {
            Err(Unspecified)
        }
        fn passthrough_entry<K>(
            self,
            _key: K,
            _value: Self::Passthrough,
        ) -> Result<Self, Self::Error>
        where
            K: Into<std::borrow::Cow<'static, str>>,
        {
            Err(Unspecified)
        }
        fn passthrough_entry_boxed<K>(
            self,
            _key: K,
            _value: Box<dyn Any + Send + 'static>,
        ) -> Result<Self, Self::Error>
        where
            K: Into<std::borrow::Cow<'static, str>>,
        {
            Err(Unspecified)
        }
        fn end(self) -> Result<Self::Ok, Self::Error> {
            Err(Unspecified)
        }
    }

    // A decipher holding one passthrough node.
    struct PassthroughDecipher(RefCell<Option<Box<dyn Any + Send + 'static>>>);

    impl<'c> Decipher<'c> for &PassthroughDecipher {
        type Ok<T>
            = Result<T, Unspecified>
        where
            T: Send + 'c;
        type Passthrough = ();

        fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
        where
            T: Send + 'c,
            U: Send + 'c,
            F: FnOnce(T) -> U,
        {
            ok.map(f)
        }

        fn decrypt_bytes<'a, V, A>(self, _visitor: V, _aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            Err(Unspecified)
        }

        fn decrypt_seq<'a, V, A>(self, _visitor: V, _aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            Err(Unspecified)
        }

        fn decrypt_map<'a, V, A>(self, _visitor: V, _aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            Err(Unspecified)
        }

        fn decrypt_any<'a, V, A>(self, visitor: V, _aad: A) -> Self::Ok<V::Value>
        where
            V: DecipherVisitor<'c> + Send + 'c,
            A: IntoAad<'a>,
        {
            let value = self.0.borrow_mut().take().ok_or(Unspecified)?;
            visitor.visit_passthrough(value)
        }

        fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough> {
            Err(Unspecified)
        }

        fn decrypt_option<'a, T, A>(self, _aad: A) -> Self::Ok<Option<T>>
        where
            T: Decrypt<'c> + 'c,
            A: IntoAad<'a>,
        {
            Err(Unspecified)
        }
    }

    #[test]
    fn encrypt_routes_through_the_boxed_passthrough_channel() {
        let cipher = SpyCipher {
            boxed: RefCell::new(None),
        };
        Passthrough(7u32)
            .encrypt_with_aad(&cipher, "ignored")
            .expect("passthrough must not fail");

        let boxed = cipher
            .boxed
            .borrow_mut()
            .take()
            .expect("value reached passthrough_boxed");
        assert_eq!(
            *boxed
                .downcast::<u32>()
                .expect("payload is the original type"),
            7
        );
    }

    #[test]
    fn decrypt_downcasts_the_payload_to_t() {
        let decipher = PassthroughDecipher(RefCell::new(Some(Box::new(String::from("alice")))));
        let got: Passthrough<String> =
            Passthrough::decrypt(&decipher).expect("matching payload type decrypts");
        assert_eq!(got, Passthrough("alice".to_string()));
    }

    #[test]
    fn decrypt_rejects_a_foreign_payload_type() {
        let decipher = PassthroughDecipher(RefCell::new(Some(Box::new(7u32))));
        let got: Result<Passthrough<String>, _> = Passthrough::decrypt(&decipher);
        assert!(
            got.is_err(),
            "a payload of another type must be an error, not a panic"
        );
    }
}
