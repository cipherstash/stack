//! A [`KeysetRegistry`] over a fixed table of keysets, for a deployment
//! whose backend has no keyset service of its own.
//!
//! On ZeroKMS a keyset is a service-side object. On AWS KMS, Azure Key
//! Vault, Cloud KMS or Vault Transit there is no such object, so a keyset is
//! a deployment configuration entry: an id, an optional name, and a
//! provider bound to one backend key together with the persisted `KeyId` of
//! that key's index key. `vitaminc-kms`'s
//! [`FixedIndexKeySource`](super::FixedIndexKeySource) is exactly that
//! provider. See ADR 0007.
//!
//! This module has no vendor dependency. It is generic over the provider,
//! so the vendor SDK is the caller's dependency, through `vitaminc-kms` and
//! the vendor feature the caller turns on.

use std::sync::Arc;

use super::{
    Binding, BindingSupport, GeneratedDataKey, IndexKeyMaterial, IndexKeyProvider, KeyId,
    KeyIsolation, KeyProvider, KeyReconstruction, KeysetId, KeysetRef, KeysetRegistry,
    ProviderProtected, Resolved,
};

/// One entry of a [`StaticKeysetRegistry`]: a keyset id, an optional name,
/// and the provider that serves the keyset.
pub struct StaticKeyset<P> {
    id: KeysetId,
    name: Option<String>,
    provider: P,
}

impl<P> StaticKeyset<P> {
    /// A keyset with this id and no name. It resolves by id only.
    ///
    /// The id is what every leaf sealed under the keyset carries. Choose it
    /// once, and keep it with the provider's backend key and index `KeyId`:
    /// a leaf whose keyset id the registry does not know fails with
    /// [`Error::UnknownKeyset`](crate::Error::UnknownKeyset).
    pub fn new(id: impl Into<KeysetId>, provider: P) -> Self {
        Self {
            id: id.into(),
            name: None,
            provider,
        }
    }

    /// Give the keyset a name, so that it also resolves by that name.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Why a [`StaticKeysetRegistry`] refused a keyset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StaticRegistryError {
    /// Two keysets have the same id. A leaf names its keyset by id, so the
    /// id must select one keyset only.
    #[error("two keysets have the id {0}")]
    DuplicateId(KeysetId),
    /// Two keysets have the same name.
    #[error("two keysets have the name {0:?}")]
    DuplicateName(String),
}

/// A provider that a [`StaticKeysetRegistry`] holds once and hands out on
/// every resolution.
///
/// A registry gives a provider by value each time it resolves a keyset, and
/// a provider such as `FixedIndexKeySource` is not `Clone`. This wrapper
/// shares one provider through an `Arc`, so each resolution is the same
/// provider, with the same client and the same connection pool. It
/// forwards every call, and the three capability constants, to that
/// provider.
pub struct SharedProvider<P>(Arc<P>);

impl<P> Clone for SharedProvider<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<P> SharedProvider<P> {
    /// The provider this shares.
    pub fn inner(&self) -> &P {
        &self.0
    }
}

impl<const N: usize, P> KeyProvider<N> for SharedProvider<P>
where
    P: KeyProvider<N> + Send + Sync,
{
    type Error = P::Error;

    const RECONSTRUCTION: KeyReconstruction = P::RECONSTRUCTION;
    const ISOLATION: KeyIsolation = P::ISOLATION;
    const BINDING: BindingSupport = P::BINDING;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<N>>, Self::Error> {
        self.0.generate_keys(bindings).await
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<ProviderProtected<[u8; N]>>, Self::Error> {
        self.0.retrieve_keys(keys).await
    }
}

impl<const N: usize, P> IndexKeyProvider<N> for SharedProvider<P>
where
    P: IndexKeyProvider<N> + Send + Sync,
{
    type Error = P::Error;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<N>, Self::Error> {
        self.0.load_index_key().await
    }
}

struct Entry<P> {
    id: KeysetId,
    name: Option<String>,
    provider: SharedProvider<P>,
}

impl<P> From<StaticKeyset<P>> for Entry<P> {
    fn from(keyset: StaticKeyset<P>) -> Self {
        Self {
            id: keyset.id,
            name: keyset.name,
            provider: SharedProvider(Arc::new(keyset.provider)),
        }
    }
}

/// A [`KeysetRegistry`] over a fixed table of keysets, all served by one
/// provider type.
///
/// The first keyset is the default: [`KeysetRef::Default`] resolves to it,
/// and [`StackCipher`](crate::StackCipher) loads it when the cipher is
/// built. A keyset resolves by its id, and by its name if it has one. Any
/// other reference is `Ok(None)`, which the cipher reports as
/// [`Error::UnknownKeyset`](crate::Error::UnknownKeyset). The registry
/// never fails to answer, so its error type is
/// [`Infallible`](std::convert::Infallible).
///
/// It does not read format-1 leaves
/// ([`READS_V1_LEAVES`](KeysetRegistry::READS_V1_LEAVES) is `false`): only
/// ZeroKMS wrote them.
///
/// ```
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use stack_encrypt::registry::{
///     Binding, FixedIndexKeySource, KeyProvider, ProviderProtected, StaticKeyset,
///     StaticKeysetRegistry,
/// };
/// use stack_encrypt::{nonempty, StackCipherBuilder};
/// use uuid::Uuid;
///
/// // A data key source bound to one backend key. In a deployment this is,
/// // for example, `vitaminc_kms::AwsDataKeySource<32>`.
/// let source = vitaminc_kms::provider::FakeKeyProvider::<32>::with_index_key(
///     ProviderProtected::new([7; 32]),
/// );
///
/// // Provision the index key once: generate one data key and store its
/// // `KeyId` with the deployment's configuration. Every later run reads
/// // that `KeyId` back. A new one makes all earlier index terms unfindable.
/// let index_key_id = source.generate_keys(&[Binding::EMPTY]).await?.remove(0).key_id;
///
/// let registry = StaticKeysetRegistry::new(
///     StaticKeyset::new(Uuid::from_u128(1), FixedIndexKeySource::new(source, index_key_id))
///         .named("main"),
/// );
/// let cipher = StackCipherBuilder::new().registry(registry).init().await?;
/// let sealed = cipher
///     .keyset("main")
///     .await?
///     .encrypt("hello".to_string(), nonempty!("greeting"))
///     .await?;
/// let opened: String = cipher.decrypt(sealed, nonempty!("greeting")).await?;
/// assert_eq!(opened, "hello");
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
pub struct StaticKeysetRegistry<P> {
    /// The default keyset first, then the others in the order they were
    /// added. A deployment has a few keysets, so a scan is enough.
    keysets: Vec<Entry<P>>,
}

impl<P> StaticKeysetRegistry<P> {
    /// A registry whose default keyset is `default`.
    pub fn new(default: StaticKeyset<P>) -> Self {
        Self {
            keysets: vec![default.into()],
        }
    }

    /// Add a keyset that a caller selects by id or by name.
    ///
    /// A keyset whose id or name is already in the registry is refused: an
    /// id or a name must select one keyset only.
    pub fn with_keyset(mut self, keyset: StaticKeyset<P>) -> Result<Self, StaticRegistryError> {
        if self.keysets.iter().any(|entry| entry.id == keyset.id) {
            return Err(StaticRegistryError::DuplicateId(keyset.id));
        }
        if let Some(name) = &keyset.name {
            if self.find_name(name).is_some() {
                return Err(StaticRegistryError::DuplicateName(name.clone()));
            }
        }
        self.keysets.push(keyset.into());
        Ok(self)
    }

    /// The id of the default keyset.
    pub fn default_id(&self) -> KeysetId {
        self.default_entry().id
    }

    fn default_entry(&self) -> &Entry<P> {
        // `new` puts the default first, and nothing removes an entry.
        &self.keysets[0]
    }

    fn find_name(&self, name: &str) -> Option<&Entry<P>> {
        self.keysets
            .iter()
            .find(|entry| entry.name.as_deref() == Some(name))
    }

    fn find(&self, keyset: &KeysetRef) -> Option<&Entry<P>> {
        match keyset {
            KeysetRef::Default => Some(self.default_entry()),
            KeysetRef::Id(id) => self.keysets.iter().find(|entry| entry.id == *id),
            KeysetRef::Name(name) => self.find_name(name),
        }
    }
}

impl<P> KeysetRegistry for StaticKeysetRegistry<P>
where
    P: KeyProvider<32> + IndexKeyProvider<32> + Send + Sync,
{
    type Provider = SharedProvider<P>;
    type Error = std::convert::Infallible;

    // Only ZeroKMS wrote format-1 leaves, and their key id is ZeroKMS's
    // `iv ‖ tag`, which no other backend parses.
    const READS_V1_LEAVES: bool = false;

    async fn resolve(
        &self,
        keyset: &KeysetRef,
    ) -> Result<Option<Resolved<Self::Provider>>, Self::Error> {
        Ok(self.find(keyset).map(|entry| Resolved {
            id: entry.id,
            // The name asked for, not a property of the keyset: a selection
            // by id or by default looked nothing up and carries none.
            name: keyset.name().map(str::to_owned),
            provider: entry.provider.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use vitaminc_kms::provider::FakeKeyProvider;
    use vitaminc_protected_kms::Protected;

    fn provider(seed: u8) -> FakeKeyProvider<32> {
        FakeKeyProvider::with_index_key(Protected::new([seed; 32]))
    }

    fn id(n: u128) -> KeysetId {
        KeysetId::new(Uuid::from_u128(n))
    }

    async fn resolved(
        registry: &StaticKeysetRegistry<FakeKeyProvider<32>>,
        keyset: impl Into<KeysetRef>,
    ) -> Option<(KeysetId, Option<String>)> {
        let Ok(found) = registry.resolve(&keyset.into()).await;
        found.map(|resolved| (resolved.id, resolved.name))
    }

    fn registry() -> StaticKeysetRegistry<FakeKeyProvider<32>> {
        StaticKeysetRegistry::new(StaticKeyset::new(id(1), provider(1)).named("main"))
            .with_keyset(StaticKeyset::new(id(2), provider(2)).named("acme"))
            .unwrap()
            .with_keyset(StaticKeyset::new(id(3), provider(3)))
            .unwrap()
    }

    #[tokio::test]
    async fn the_default_is_the_first_keyset() {
        let registry = registry();
        assert_eq!(registry.default_id(), id(1));
        assert_eq!(
            resolved(&registry, KeysetRef::Default).await,
            Some((id(1), None)),
            "a selection by default looked no name up"
        );
    }

    #[tokio::test]
    async fn a_keyset_resolves_by_its_id() {
        let registry = registry();
        for n in 1..=3 {
            assert_eq!(resolved(&registry, id(n)).await, Some((id(n), None)));
        }
    }

    #[tokio::test]
    async fn a_named_keyset_resolves_by_its_name_and_carries_it() {
        let registry = registry();
        assert_eq!(
            resolved(&registry, "acme").await,
            Some((id(2), Some("acme".to_owned())))
        );
        assert_eq!(
            resolved(&registry, "main").await,
            Some((id(1), Some("main".to_owned()))),
            "the default keyset resolves by its name too"
        );
    }

    #[tokio::test]
    async fn anything_else_is_the_registrys_own_no() {
        let registry = registry();
        assert_eq!(resolved(&registry, id(4)).await, None);
        assert_eq!(resolved(&registry, "other").await, None);
        assert_eq!(
            resolved(&registry, "").await,
            None,
            "a keyset with no name does not answer to the empty name"
        );
    }

    #[test]
    fn an_id_or_a_name_selects_one_keyset_only() {
        assert_eq!(
            registry()
                .with_keyset(StaticKeyset::new(id(3), provider(9)))
                .err(),
            Some(StaticRegistryError::DuplicateId(id(3)))
        );
        assert_eq!(
            registry()
                .with_keyset(StaticKeyset::new(id(9), provider(9)).named("main"))
                .err(),
            Some(StaticRegistryError::DuplicateName("main".to_owned()))
        );
        assert!(
            registry()
                .with_keyset(StaticKeyset::new(id(9), provider(9)))
                .is_ok(),
            "two keysets with no name do not collide"
        );
    }

    #[test]
    fn vendor_keysets_do_not_read_format_1_leaves() {
        const {
            assert!(!<StaticKeysetRegistry<FakeKeyProvider<32>> as KeysetRegistry>::READS_V1_LEAVES)
        };
    }
}
