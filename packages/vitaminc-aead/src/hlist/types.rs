use crate::{Context, IntoAad, LocalCipherText};

use super::HList;

/// A single sealed value (nonce + ciphertext + tag).
///
/// The inner `LocalCipherText` is private: leaves are produced by a cipher
/// backend's `StaticCipher` impl (or, in future, a derive macro) via
/// [`Encrypted::from_local`] rather than constructed field-wise by arbitrary
/// callers. This is encapsulation, not unforgeability — `LocalCipherText:
/// From<Vec<u8>>` is public and the constructor must be reachable cross-crate,
/// so the cipher's tag verification on `open` remains the real authenticity
/// guard.
#[derive(Debug)]
pub struct Encrypted(LocalCipherText);

impl Encrypted {
    /// Wrap a sealed `LocalCipherText`. Plumbing for cipher backends and derive
    /// macros — not part of the stable public surface.
    #[doc(hidden)]
    pub fn from_local(ct: LocalCipherText) -> Self {
        Self(ct)
    }

    /// Consume the leaf, yielding the inner `LocalCipherText` for decryption.
    #[doc(hidden)]
    pub fn into_local(self) -> LocalCipherText {
        self.0
    }
}

/// An authenticated "no value" marker — empty plaintext sealed under AAD.
///
/// Inner field is private for the same reason as [`Encrypted`].
#[derive(Debug)]
pub struct Absent(LocalCipherText);

impl Absent {
    /// Wrap a sealed `LocalCipherText`. Plumbing for cipher backends and derive
    /// macros — not part of the stable public surface.
    #[doc(hidden)]
    pub fn from_local(ct: LocalCipherText) -> Self {
        Self(ct)
    }

    /// Consume the marker, yielding the inner `LocalCipherText` for verification.
    #[doc(hidden)]
    pub fn into_local(self) -> LocalCipherText {
        self.0
    }
}

/// A typed value carried through the ciphertext container without
/// encryption. Holds `T` directly — no `Box`, no `Any`.
#[derive(Debug)]
pub struct Passthrough<T>(pub T);

/// A map of typed `(key, value)` entries. The HList `L` encodes the
/// structural shape of the map at the type level.
#[derive(Debug)]
pub struct Map<L: HList>(pub L);

/// A heterogeneous sequence — length and per-element type known at compile
/// time. For homogeneous, runtime-length sequences use a plain `Vec` of
/// leaf types (e.g. `Vec<Encrypted>`).
#[derive(Debug)]
pub struct Seq<L: HList>(pub L);

/// One map entry. `key` is a `&'static str`; `value` is one of the leaf
/// or composite types above.
#[derive(Debug)]
pub struct Entry<V> {
    pub key: &'static str,
    pub value: V,
}

impl<Inner: HList> Entry<Map<Inner>> {
    /// Derives the AAD this nested map's entries were built against —
    /// [`Context::for_map_entry`](crate::Context::for_map_entry) of the enclosing
    /// map's AAD and this entry's key. The open-side counterpart to
    /// [`StaticMapBuilder::nested_entry`](super::StaticMapBuilder::nested_entry):
    /// pass the result (or a further derivation of it) when opening each
    /// inner entry, so a renamed outer key or a spliced-in foreign nested
    /// map fails inner verification.
    pub fn nested_aad<'a, A: IntoAad<'a>>(&self, aad: A) -> Context<'static> {
        aad.into_aad().for_map_entry(self.key)
    }
}
