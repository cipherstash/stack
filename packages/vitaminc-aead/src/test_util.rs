//! Test-only spy doubles shared by wrapper-type unit tests (`ContextTag`,
//! `Element`): they record the AAD bytes they are handed so a test can assert
//! the exact derivation a wrapper binds, without any real cryptography.

use std::any::Any;
use std::cell::RefCell;

use vitaminc_protected::{Controlled, Protected};

use crate::{
    cipher::{Cipher, MapCipher, SeqCipher},
    decipher::{Decipher, DecipherVisitor, MapAccess},
    Encrypt, IntoAad, Unspecified,
};

/// A minimal [`Cipher`] that records the AAD bytes it is handed and echoes the
/// plaintext back as its "ciphertext". Only the byte path is exercised by the
/// leaf `Encrypt` impls used in tests (`&str`, `String`, `[u8; N]`); the
/// sequence/map sub-ciphers exist solely to satisfy the trait and are never
/// driven.
pub(crate) struct MockCipher {
    captured_aad: RefCell<Vec<u8>>,
}

impl MockCipher {
    pub(crate) fn new() -> Self {
        MockCipher {
            captured_aad: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn captured_aad(&self) -> Vec<u8> {
        self.captured_aad.borrow().clone()
    }
}

pub(crate) struct UnusedSeq;
pub(crate) struct UnusedMap;

impl Cipher for &MockCipher {
    type Ok = Vec<u8>;
    type Error = Unspecified;
    type Passthrough = ();
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

    fn encrypt_seq<'a, A>(self, _size_hint: Option<usize>, _aad: A) -> Self::SeqCipher
    where
        A: IntoAad<'a>,
    {
        UnusedSeq
    }

    fn encrypt_map<'a, A>(self, _aad: A) -> Self::MapCipher
    where
        A: IntoAad<'a>,
    {
        UnusedMap
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
        Ok(Vec::new())
    }

    fn passthrough(self, _value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }

    fn passthrough_boxed(
        self,
        _value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
}

impl SeqCipher for UnusedSeq {
    type Ok = Vec<u8>;
    type Error = Unspecified;
    type Passthrough = ();

    fn encrypt_next<T>(self, _data: T) -> Result<Self, Self::Error>
    where
        T: Encrypt,
    {
        Ok(self)
    }

    fn passthrough_next(self, _value: Self::Passthrough) -> Result<Self, Self::Error> {
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
}

impl MapCipher for UnusedMap {
    type Ok = Vec<u8>;
    type Error = Unspecified;
    type Passthrough = ();

    fn encrypt_key<K>(self, _key: K) -> Result<Self, Self::Error>
    where
        K: Into<std::borrow::Cow<'static, str>>,
    {
        Ok(self)
    }

    fn encrypt_value<T>(self, _value: T) -> Result<Self, Self::Error>
    where
        T: Encrypt,
    {
        Ok(self)
    }

    fn passthrough_entry<K>(self, _key: K, _value: Self::Passthrough) -> Result<Self, Self::Error>
    where
        K: Into<std::borrow::Cow<'static, str>>,
    {
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(Vec::new())
    }
}

/// The decrypt-side counterpart to [`MockCipher`]: records the AAD bytes a
/// `Decrypt` impl presents and delivers a fixed byte payload to the visitor's
/// byte path. Only `decrypt_bytes` is live; the other shapes reject, which is
/// enough for wrapper tests driving a byte-leaf inner type (`String`,
/// `Vec<u8>`).
pub(crate) struct MockDecipher {
    payload: Vec<u8>,
    captured_aad: RefCell<Vec<u8>>,
}

impl MockDecipher {
    pub(crate) fn new(payload: impl Into<Vec<u8>>) -> Self {
        MockDecipher {
            payload: payload.into(),
            captured_aad: RefCell::new(Vec::new()),
        }
    }

    pub(crate) fn captured_aad(&self) -> Vec<u8> {
        self.captured_aad.borrow().clone()
    }
}

impl<'c> Decipher<'c> for &MockDecipher {
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

    fn decrypt_bytes<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
        visitor.visit_bytes_vec(Protected::new(self.payload.clone()))
    }

    fn decrypt_seq<'a, V, A>(self, _visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
        Err(Unspecified)
    }

    fn decrypt_map<'a, V, A>(self, _visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
        Err(Unspecified)
    }

    fn decrypt_any<'a, V, A>(self, _visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
        Err(Unspecified)
    }

    fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough> {
        Err(Unspecified)
    }

    fn decrypt_option<'a, T, A>(self, aad: A) -> Self::Ok<Option<T>>
    where
        T: crate::Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        *self.captured_aad.borrow_mut() = aad.into_aad().as_bytes().to_vec();
        Err(Unspecified)
    }
}

/// A minimal [`MapAccess`] over an in-memory list of `(key, payload)` pairs.
///
/// Enough to drive the trait's own default method — [`MapAccess::next_entry`],
/// which is defined in terms of [`MapAccess::next_key`] and
/// [`MapAccess::next_value`] — without a real cipher. Each value is handed to
/// a fresh [`MockDecipher`], so any byte-leaf `Decrypt` type works as the
/// value type.
pub(crate) struct MockMapAccess {
    entries: std::vec::IntoIter<(String, Vec<u8>)>,
    /// Mirrors the contract a real implementation must uphold: a key handed
    /// out by `next_key` stays pending until `next_value` consumes it.
    pending: Option<Vec<u8>>,
}

impl MockMapAccess {
    pub(crate) fn new<K, V>(entries: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<Vec<u8>>,
    {
        MockMapAccess {
            entries: entries
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect::<Vec<_>>()
                .into_iter(),
            pending: None,
        }
    }
}

impl<'c> MapAccess<'c> for MockMapAccess {
    type Error = Unspecified;

    fn next_key(&mut self) -> Result<Option<String>, Self::Error> {
        if self.pending.is_some() {
            return Err(Unspecified);
        }
        match self.entries.next() {
            Some((key, payload)) => {
                self.pending = Some(payload);
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    fn next_value<T: crate::Decrypt<'c> + 'c>(&mut self) -> Result<T, Self::Error> {
        let payload = self.pending.take().ok_or(Unspecified)?;
        let decipher = MockDecipher::new(payload);
        T::decrypt_with_aad(&decipher, crate::Aad::empty())
    }
}
