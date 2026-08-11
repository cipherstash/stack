// The growing-HList builder return types are intentionally large — that's
// the whole design. Suppress the lint at module scope rather than smearing
// it across each method signature.
#![allow(clippy::type_complexity)]

use vitaminc_protected::Protected;

use crate::{Aad, IntoAad};

use super::types::{Absent, Encrypted, Entry, Map, Passthrough};
use super::{HCons, HList, HNil};

/// Statically-shaped counterpart to [`Cipher`](crate::Cipher).
///
/// Each operation produces a leaf or builder whose Rust type fully
/// describes its content — no `Cipher::Ok` associated type, because the
/// output type changes per call.
///
/// Implement for a reference type (e.g. `&MyCipher`) so the cipher can be
/// reused across the builder chain; the trait requires `Copy` for this
/// reason.
pub trait StaticCipher: Sized + Copy {
    /// Opaque error type — typically `Unspecified`.
    type Error;

    /// Seal `data` under the supplied AAD.
    ///
    /// The plaintext is taken as `Protected<Vec<u8>>` so the chain of custody
    /// survives the trait boundary, matching
    /// [`Cipher::encrypt_bytes_vec`](crate::Cipher::encrypt_bytes_vec). The
    /// zeroize-on-drop guarantee is not yet in effect — `Protected<T>` has no
    /// `Drop` impl today; that is tracked in #181.
    fn encrypt_bytes<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Encrypted, Self::Error>
    where
        A: IntoAad<'a>;

    /// Produce an authenticated "no value" marker bound to `aad`.
    fn encrypt_none<'a, A>(self, aad: A) -> Result<Absent, Self::Error>
    where
        A: IntoAad<'a>;

    /// Wrap `value` for passthrough — never fails, never encrypts.
    fn passthrough<T>(self, value: T) -> Passthrough<T> {
        Passthrough(value)
    }

    /// Begin building a typed map.
    fn encrypt_map(self) -> StaticMapBuilder<Self, HNil> {
        StaticMapBuilder {
            cipher: self,
            list: HNil,
        }
    }
}

/// HList-growing builder for typed maps. Each entry method consumes
/// `self` and returns a builder whose HList parameter is one cell longer.
pub struct StaticMapBuilder<C, L> {
    cipher: C,
    list: L,
}

impl<C, L> StaticMapBuilder<C, L>
where
    C: StaticCipher,
    L: HList,
{
    /// Add an encrypted entry.
    ///
    /// The value is sealed against [`Aad::for_map_entry`](crate::Aad::for_map_entry)
    /// of the caller's AAD and `key` — the same contract as the dynamic
    /// [`MapCipher`](crate::MapCipher) — so a stored entry's cleartext key
    /// cannot be swapped or renamed undetected. Open with a counterpart that
    /// derives the same binding (e.g. `Aes256Cipher::open_entry`).
    pub fn encrypt_entry<'a, A>(
        self,
        key: &'static str,
        value: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<StaticMapBuilder<C, HCons<Entry<Encrypted>, L>>, C::Error>
    where
        A: IntoAad<'a>,
    {
        let entry_aad = aad.into_aad().for_map_entry(key);
        let encrypted = self.cipher.encrypt_bytes(value, entry_aad)?;
        Ok(StaticMapBuilder {
            cipher: self.cipher,
            list: HCons(
                Entry {
                    key,
                    value: encrypted,
                },
                self.list,
            ),
        })
    }

    /// Add a passthrough entry whose value stays typed end-to-end.
    pub fn passthrough_entry<T>(
        self,
        key: &'static str,
        value: T,
    ) -> StaticMapBuilder<C, HCons<Entry<Passthrough<T>>, L>> {
        StaticMapBuilder {
            cipher: self.cipher,
            list: HCons(
                Entry {
                    key,
                    value: Passthrough(value),
                },
                self.list,
            ),
        }
    }

    /// Add an authenticated absent entry, key-bound like
    /// [`encrypt_entry`](StaticMapBuilder::encrypt_entry).
    pub fn none_entry<'a, A>(
        self,
        key: &'static str,
        aad: A,
    ) -> Result<StaticMapBuilder<C, HCons<Entry<Absent>, L>>, C::Error>
    where
        A: IntoAad<'a>,
    {
        let entry_aad = aad.into_aad().for_map_entry(key);
        let absent = self.cipher.encrypt_none(entry_aad)?;
        Ok(StaticMapBuilder {
            cipher: self.cipher,
            list: HCons(Entry { key, value: absent }, self.list),
        })
    }

    /// Add a nested map entry — the value is itself a [`Map<Inner>`], built
    /// inside `build` against the AAD this method derives.
    ///
    /// A nested map has no leaf of its own to seal, so its outer cleartext
    /// `key` can only be authenticated *through* its entries: `build`
    /// receives [`Aad::for_map_entry`](crate::Aad::for_map_entry) of the
    /// caller's AAD and `key`, and every inner entry must be sealed against
    /// (a derivation of) it — the same chain the dynamic
    /// [`MapCipher`](crate::MapCipher) composes when it encrypts a nested
    /// map inside an entry. Renaming the outer key, or splicing in a nested
    /// map sealed under another record's AAD, then fails at every inner
    /// open. Open with the counterpart derivation
    /// ([`Entry::nested_aad`](super::Entry::nested_aad)).
    ///
    /// An attacher that accepted a pre-built `Map<Inner>` could not enforce
    /// any of this — the closure shape is what puts the derived AAD in the
    /// builder's hands at the only moment binding is possible.
    pub fn nested_entry<'a, A, Inner, F>(
        self,
        key: &'static str,
        aad: A,
        build: F,
    ) -> Result<StaticMapBuilder<C, HCons<Entry<Map<Inner>>, L>>, C::Error>
    where
        A: IntoAad<'a>,
        Inner: HList,
        F: FnOnce(StaticMapBuilder<C, HNil>, Aad<'static>) -> Result<Map<Inner>, C::Error>,
    {
        let nested_aad = aad.into_aad().for_map_entry(key);
        let value = build(self.cipher.encrypt_map(), nested_aad)?;
        Ok(StaticMapBuilder {
            cipher: self.cipher,
            list: HCons(Entry { key, value }, self.list),
        })
    }

    /// Finalise the builder into a [`Map<L>`] container.
    pub fn end(self) -> Map<L> {
        Map(self.list)
    }
}
