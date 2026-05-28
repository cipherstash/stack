// The growing-HList builder return types are intentionally large — that's
// the whole design. Suppress the lint at module scope rather than smearing
// it across each method signature.
#![allow(clippy::type_complexity)]

use vitaminc_protected::Protected;

use crate::IntoAad;

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
    /// — and the zeroize-on-drop guarantee — survives the trait boundary,
    /// matching [`Cipher::encrypt_bytes_vec`](crate::Cipher::encrypt_bytes_vec).
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
    pub fn encrypt_entry<'a, A>(
        self,
        key: &'static str,
        value: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<StaticMapBuilder<C, HCons<Entry<Encrypted>, L>>, C::Error>
    where
        A: IntoAad<'a>,
    {
        let encrypted = self.cipher.encrypt_bytes(value, aad)?;
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

    /// Add an authenticated absent entry.
    pub fn none_entry<'a, A>(
        self,
        key: &'static str,
        aad: A,
    ) -> Result<StaticMapBuilder<C, HCons<Entry<Absent>, L>>, C::Error>
    where
        A: IntoAad<'a>,
    {
        let absent = self.cipher.encrypt_none(aad)?;
        Ok(StaticMapBuilder {
            cipher: self.cipher,
            list: HCons(Entry { key, value: absent }, self.list),
        })
    }

    /// Add a nested map entry — the value is itself a [`Map<Inner>`].
    pub fn nested_entry<Inner>(
        self,
        key: &'static str,
        value: Map<Inner>,
    ) -> StaticMapBuilder<C, HCons<Entry<Map<Inner>>, L>>
    where
        Inner: HList,
    {
        StaticMapBuilder {
            cipher: self.cipher,
            list: HCons(Entry { key, value }, self.list),
        }
    }

    /// Finalise the builder into a [`Map<L>`] container.
    pub fn end(self) -> Map<L> {
        Map(self.list)
    }
}
