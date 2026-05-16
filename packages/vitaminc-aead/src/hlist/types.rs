use crate::LocalCipherText;

use super::HList;

/// A single sealed value (nonce + ciphertext + tag).
#[derive(Debug)]
pub struct Encrypted(pub LocalCipherText);

/// An authenticated "no value" marker — empty plaintext sealed under AAD.
#[derive(Debug)]
pub struct Absent(pub LocalCipherText);

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
