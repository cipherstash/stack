//! Keyset selection: turning the keyset a caller names into the key
//! provider that serves it.
//!
//! A [`KeysetRegistry`] is the deployment's map. ZeroKMS's implementation
//! asks the service and gets a keyset back; a vendor deployment's reads a
//! static table of backend keys it was configured with. Either way the
//! answer is one [`vitaminc_kms::provider::KeyProvider`] bound to one
//! backend key, which is the only shape `vitaminc-kms` offers — selection
//! is this crate's business, not that crate's. See cipherstash/vitaminc
//! ADR 0004 for why the boundary sits here.
//!
//! Registries do no caching. [`StackCipher`](crate::StackCipher) holds the
//! LRU and the name TTL, so every backend inherits one tested
//! implementation of them rather than writing its own.

use std::fmt;
use std::future::Future;

use uuid::Uuid;
use vitaminc_kms::provider::MaybeSend;

/// The vitaminc types a [`KeysetRegistry`] implementor has to name.
/// Re-exported so that implementing one needs no direct dependency on
/// `vitaminc-kms` — and, more to the point, no second copy of it: a
/// differently-sourced `vitaminc-kms` is a different `KeyProvider` trait at
/// compile time, and an impl written against it would not satisfy this one.
pub use vitaminc_kms::provider::{
    Binding, BindingSupport, IndexKeyProvider, KeyProvider, MaybeSend as ProviderMaybeSend,
};
pub use vitaminc_kms::{
    GeneratedDataKey, IndexKeyMaterial, KeyId, KeyIsolation, KeyReconstruction,
};
/// The `Protected` those traits carry key material in.
pub use vitaminc_protected_kms::Protected as ProviderProtected;

#[cfg(any(test, feature = "test-support"))]
pub mod fake;
#[cfg(feature = "zerokms")]
mod zerokms;

/// A keyset's identity: globally unique, carried in every sealed leaf, and
/// never re-checked once resolved.
///
/// A newtype over `Uuid` rather than a bare one, so a client id or a
/// workspace id cannot be passed where a keyset id belongs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct KeysetId(Uuid);

impl KeysetId {
    pub const fn new(id: Uuid) -> Self {
        Self(id)
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for KeysetId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl fmt::Display for KeysetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How a caller names the keyset it wants.
///
/// [`Default`](Self::Default) is a case rather than a separate entry point:
/// ZeroKMS's wire protocol already spells "the client's default keyset" as
/// an absent id, which its server resolves for the request, and a vendor
/// registry answers it from configuration. One selector covers all three.
///
/// An id is an identity and is never re-checked. A name is a *lookup the
/// registry answers*, and answers can change — ZeroKMS allows renames — so
/// a resolved name is trusted only for a bounded window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetRef {
    Default,
    Id(KeysetId),
    Name(String),
}

impl KeysetRef {
    /// The name this reference selects by, if it selects by name.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            Self::Default | Self::Id(_) => None,
        }
    }
}

impl From<KeysetId> for KeysetRef {
    fn from(id: KeysetId) -> Self {
        Self::Id(id)
    }
}

impl From<Uuid> for KeysetRef {
    fn from(id: Uuid) -> Self {
        Self::Id(KeysetId::new(id))
    }
}

impl From<String> for KeysetRef {
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl From<&str> for KeysetRef {
    fn from(name: &str) -> Self {
        Self::Name(name.to_owned())
    }
}

/// What a registry hands back: the keyset's resolved identity, the name it
/// was selected by if it was selected by one, and the provider that serves
/// it.
///
/// The name is the *asked* name, not a property of the keyset. A selection
/// by id or by default carries none, because nothing was looked up.
pub struct Resolved<P> {
    pub id: KeysetId,
    pub name: Option<String>,
    pub provider: P,
}

/// The deployment's map from a keyset reference to the provider that serves
/// it.
///
/// One associated `Provider` type, not a boxed one: `KeyProvider` is generic
/// over `const N` and returns `impl Future`, so it is not dyn-compatible and
/// there is no `Box<dyn KeyProvider>` to hand back.
///
/// Resolving may cost a round trip, so it is async, and
/// [`StackCipher`](crate::StackCipher) does it outside its cache lock.
pub trait KeysetRegistry {
    /// The provider this registry produces. It must serve both data keys and
    /// the keyset's one index key: a keyset with no index key would fail at
    /// the first query rather than at resolution, and a freshly minted index
    /// key makes every term written under the old one unfindable.
    type Provider: KeyProvider<32> + IndexKeyProvider<32>;

    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolve `keyset`, or report that this deployment has no such keyset.
    ///
    /// The three outcomes are deliberately distinct, because the name cache
    /// treats them differently. `Ok(Some(_))` is an answer. `Ok(None)` is
    /// *also* an answer — a definite "no keyset by that name or id" — and it
    /// unbinds a name the cache had bound, so a stale binding cannot
    /// outlive the registry's own denial. `Err(_)` is **not** an answer: a
    /// transport failure or an expired credential says nothing about the
    /// name, and leaves the cache exactly as it was.
    ///
    /// Folding the negative into `Self::Error` would make that distinction
    /// unreachable — the cache would have to match on a backend-specific
    /// error variant it cannot name.
    fn resolve(
        &self,
        keyset: &KeysetRef,
    ) -> impl Future<Output = Result<Option<Resolved<Self::Provider>>, Self::Error>> + MaybeSend;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A keyset id reaches a caller through error messages and logs, so its
    /// rendering is the uuid and nothing else — not a newtype wrapper, and
    /// not empty.
    #[test]
    fn a_keyset_id_renders_as_its_uuid() {
        let uuid = Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        let id = KeysetId::new(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
        assert_eq!(id.to_string(), "01234567-89ab-cdef-0123-456789abcdef");
    }
}
