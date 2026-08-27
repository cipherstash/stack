use super::{Cipher, Encrypt};
use crate::{
    cipher::{MapCipher, SeqCipher},
    IntoAad,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::Hash;
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
    /// Every element is encrypted under the sequence's AAD, which
    /// [`Cipher::encrypt_seq`] captures once.
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(
        self,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error> {
        let len = self.len();

        self.into_iter()
            .try_fold(cipher.encrypt_seq(Some(len), aad), |c, item| {
                c.encrypt_next(item)
            })?
            .end()
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

    /// An already-wrapped array goes straight to the cipher's array entry
    /// point: no unwrap, no bare stack copy, no re-wrap. This is what makes a
    /// `Protected<[u8; 32]>` key — or a newtype deriving `Encrypt` around
    /// one — seal without the key material ever leaving `Protected`.
    fn encrypt_protected<'a, C, A>(
        this: Protected<Self>,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_array(this, aad)
    }
}

/// `Vec<u8>` is a byte leaf, not a sequence of `u8` elements — the same
/// shape `String` seals to, and the shape `Vec<u8>: Decrypt` reads back.
/// (The generic `Vec<T>` impl below cannot apply: `u8` is not `Encrypt`, and
/// this leaf is what keeps it that way.)
impl Encrypt for Vec<u8> {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_vec(Protected::new(self), aad)
    }

    /// An already-wrapped buffer goes straight to
    /// [`Cipher::encrypt_bytes_vec`] — see `[u8; N]` above.
    fn encrypt_protected<'a, C, A>(
        this: Protected<Self>,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_bytes_vec(this, aad)
    }
}

/// One impl covers both compile-time keys (`&'static str`) and runtime keys
/// (`String`, e.g. values arriving across an FFI boundary) — anything
/// [`MapCipher::encrypt_key`](crate::MapCipher::encrypt_key) accepts. A single
/// impl keeps the two key shapes on one map-encryption protocol: a change
/// applied to one cannot silently miss the other.
impl<K, T> Encrypt for HashMap<K, T>
where
    K: Into<Cow<'static, str>> + Eq + Hash,
    T: Encrypt,
{
    fn encrypt_with_aad<'a, C: Cipher, A: IntoAad<'a>>(
        self,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error> {
        self.into_iter()
            .try_fold(cipher.encrypt_map(aad), |c, (k, v)| {
                c.encrypt_key(k).and_then(|c| c.encrypt_value(v))
            })?
            .end()
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
        // Chain of custody is `T`'s call, through `Encrypt::encrypt_protected`.
        // Byte leaves (`[u8; N]`, `Vec<u8>`) hand `self` to the cipher still
        // wrapped; everything else takes the default, which unwraps here and
        // relies on each inner leaf re-wrapping its own payload before it
        // crosses the `Cipher` boundary. Custom `Encrypt` impls are
        // responsible for their own discipline.
        T::encrypt_protected(self, cipher, aad)
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
        // attest the wrapper. Unwrap to the innermost value and let the leaf
        // `Encrypt` impl re-wrap it in `Protected` before crossing the cipher
        // boundary. Unlike `Protected<T>` above, this cannot yet take the
        // `encrypt_protected` seam: `Equatable` exposes no way to peel only its
        // own layer and hand the `Protected<T>` beneath it on intact, so the
        // innermost value is briefly bare here. The `Equatable` layer is
        // reconstructed structurally on decrypt (see the `Decrypt` impl).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockCipher;

    // `MockCipher` echoes the plaintext bytes back as its ciphertext from the
    // byte entry points, and returns an empty `Vec` from the sequence
    // sub-cipher — so a leaf that wrongly took the sequence path is visible
    // in the output, not just in a spy counter.

    #[test]
    fn vec_u8_seals_as_a_byte_leaf_not_a_sequence() {
        let cipher = MockCipher::new();
        let ct = vec![1u8, 2, 3]
            .encrypt(&cipher)
            .expect("byte leaf should encrypt");
        assert_eq!(ct, vec![1, 2, 3]);
        assert_eq!(cipher.array_entry_hits(), 0);
    }

    #[test]
    fn protected_vec_u8_seals_as_a_byte_leaf() {
        let cipher = MockCipher::new();
        let ct = Protected::new(vec![1u8, 2, 3])
            .encrypt(&cipher)
            .expect("byte leaf should encrypt");
        assert_eq!(ct, vec![1, 2, 3]);
    }

    // A wrapped array reaches the cipher through the array entry point — not
    // through `Vec<T>`'s sequence path, and not through the default
    // `encrypt_bytes_array` forwarding. Whether an intermediate bare copy
    // existed on the way is not observable from the cipher side; that
    // property rests on `[u8; N]::encrypt_protected` handing `this` over
    // untouched, which is a one-line read.
    #[test]
    fn protected_array_reaches_the_array_entry_point() {
        let cipher = MockCipher::new();
        let ct = Protected::new([9u8, 8, 7, 6])
            .encrypt(&cipher)
            .expect("byte leaf should encrypt");
        assert_eq!(ct, vec![9, 8, 7, 6]);
        assert_eq!(cipher.array_entry_hits(), 1);
    }

    #[test]
    fn protected_array_and_bare_array_share_a_wire_shape() {
        let cipher = MockCipher::new();
        let wrapped = Protected::new([1u8, 2])
            .encrypt_with_aad(&cipher, "ctx")
            .expect("encrypt");
        let wrapped_aad = cipher.captured_aad();
        let bare = [1u8, 2].encrypt_with_aad(&cipher, "ctx").expect("encrypt");
        assert_eq!(wrapped, bare);
        assert_eq!(wrapped_aad, cipher.captured_aad());
    }

    // A type without an override takes the default `encrypt_protected`: it is
    // unwrapped and its own `encrypt_with_aad` runs — here `String`, which
    // re-wraps its bytes and seals through the vec entry point.
    #[test]
    fn protected_value_without_an_override_takes_the_default_path() {
        let cipher = MockCipher::new();
        let ct = Protected::new(String::from("hi"))
            .encrypt(&cipher)
            .expect("encrypt");
        assert_eq!(ct, b"hi".to_vec());
        assert_eq!(cipher.array_entry_hits(), 0);
    }
}
