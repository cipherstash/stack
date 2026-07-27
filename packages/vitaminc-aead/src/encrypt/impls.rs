use super::{Cipher, Encrypt};
use crate::{
    cipher::{MapCipher, SeqCipher},
    Aad, IntoAad,
};
use std::collections::HashMap;
use vitaminc_protected::{Controlled, Equatable, Protected};
use zeroize::Zeroize;

impl Encrypt for u32 {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_array(Protected::new(self.to_le_bytes()), aad)
    }
}

impl Encrypt for String {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_vec(Protected::new(self.into_bytes()), aad)
    }
}

impl Encrypt for &str {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_vec(Protected::new(self.as_bytes().to_vec()), aad)
    }
}

impl<T> Encrypt for Vec<T>
where
    T: Encrypt,
{
    /// All entries in the vec are encrypted with the same Aad.
    /// Passing `aad` as a reference otherwise the value will be cloned for each element
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(
        self,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error> {
        let aad: Aad = aad.into_aad();
        let len = self.len();

        self.into_iter()
            .try_fold(cipher.encrypt_seq(Some(len)), |c, item| {
                c.encrypt_next(item, aad.clone())
            })?
            .end(aad)
    }
}

impl<const N: usize> Encrypt for [u8; N] {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_array(Protected::new(self), aad)
    }
}

impl<T> Encrypt for HashMap<&'static str, T>
where
    T: Encrypt,
{
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(
        self,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error> {
        let aad: Aad = aad.into_aad();

        self.into_iter()
            .try_fold(cipher.encrypt_map(), |c, (k, v)| {
                c.encrypt_key(k)
                    .and_then(|c| c.encrypt_value(v, aad.clone()))
            })?
            .end(aad)
    }
}

/// The runtime-keyed counterpart of the `HashMap<&'static str, T>` impl above,
/// for maps whose keys are not known at compile time (e.g. values arriving
/// across an FFI boundary). Round-trips with the `Decrypt` impl for
/// `HashMap<String, T>`.
impl<T> Encrypt for HashMap<String, T>
where
    T: Encrypt,
{
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(
        self,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error> {
        let aad: Aad = aad.into_aad();

        self.into_iter()
            .try_fold(cipher.encrypt_map(), |c, (k, v)| {
                c.encrypt_key(k)
                    .and_then(|c| c.encrypt_value(v, aad.clone()))
            })?
            .end(aad)
    }
}

impl<T> Encrypt for Protected<T>
where
    T: Encrypt + Zeroize,
{
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        // SAFETY: chain of custody. Every built-in leaf `Encrypt` impl
        // (`[u8; N]`, `Vec<T>`, `String`, `&str`, `u32`, …) rewraps its byte
        // payload in `Protected` before crossing the `Cipher` trait
        // boundary, so the bare-`T` stack window opened here is bounded by
        // the inner `Encrypt::encrypt_with_aad` call. Custom `Encrypt` impls
        // are responsible for their own discipline.
        self.risky_unwrap().encrypt_with_aad(cipher, aad)
    }
}

impl<T> Encrypt for Equatable<T>
where
    // Deliberately no `Zeroize` bound, unlike the sibling `Protected<T>` impl
    // above (`T: Encrypt + Zeroize`): `Controlled` already governs the zeroize
    // chain for `T`, and the inner value is re-wrapped in `Protected` by the leaf
    // impl before it crosses the cipher boundary (see below), so an extra bound
    // here would over-constrain callers without adding protection. The divergence
    // is a conscious choice, not drift.
    T: Controlled,
    T::Inner: Encrypt,
{
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        // `Equatable` is an in-memory constant-time-equality wrapper; it adds
        // nothing to the ciphertext — an `Equatable<Protected<T>>` ciphertext is
        // interchangeable with a `Protected<T>` one, as the ciphertext does not
        // attest the wrapper. Mirror the `Protected<T>` impl above: unwrap to the
        // inner value and let the leaf `Encrypt` impl re-wrap it in `Protected`
        // before crossing the cipher boundary, preserving the zeroize chain of
        // custody. The `Equatable` layer is reconstructed structurally on decrypt
        // (see the `Decrypt` impl).
        self.risky_unwrap().encrypt_with_aad(cipher, aad)
    }
}

impl<T> Encrypt for Option<T>
where
    T: Encrypt,
{
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        match self {
            Some(v) => cipher.encrypt_some(v, aad),
            None => cipher.encrypt_none(aad),
        }
    }
}
