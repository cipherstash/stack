//! A [`KeysetRegistry`] for tests: many keysets, no network, and a record
//! of every binding sent to each.
//!
//! Each keyset gets its **own** [`FakeKeyProvider`], so two keysets have
//! distinct index keys and distinct key material. That is what makes the
//! foreign-keyset refusal, the keyset merge rule and the per-keyset
//! grouping in `dispatch` testable at all — a registry that handed the same
//! provider to every keyset would pass those tests without them meaning
//! anything.
//!
//! `FakeKeyProvider` declares `BINDING = Bound`, so retrieving a key under
//! a descriptor it was not minted with fails here exactly as it would at
//! ZeroKMS. It models no authorization, auditing or reconstruction
//! semantics beyond that.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use uuid::Uuid;
use vitaminc_kms::provider::{
    Binding, BindingSupport, FakeKeyProvider, FakeKeyProviderError, IndexKeyProvider, KeyProvider,
};
use vitaminc_kms::{GeneratedDataKey, IndexKeyMaterial, KeyId, KeyIsolation, KeyReconstruction};
use vitaminc_protected_kms::Protected;

use super::{KeysetId, KeysetRef, KeysetRegistry, Resolved};

/// Every binding a fake keyset was sent, grouped by the call it arrived in.
///
/// Grouped by call, not flattened, because the claim these tests exist to
/// hold is that an assembly of any size settles in **one** batched call per
/// request kind. A flat list of bindings cannot tell one call of ten from
/// ten calls of one.
#[derive(Debug, Clone, Default)]
pub struct Calls {
    pub generate: Vec<Vec<String>>,
    pub retrieve: Vec<Vec<String>>,
}

impl Calls {
    /// Every generate-side binding, all calls flattened.
    pub fn generated(&self) -> Vec<String> {
        self.generate.iter().flatten().cloned().collect()
    }

    /// Every retrieve-side binding, all calls flattened.
    pub fn retrieved(&self) -> Vec<String> {
        self.retrieve.iter().flatten().cloned().collect()
    }
}

fn record(bindings: impl Iterator<Item = Vec<u8>>) -> Vec<String> {
    bindings
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .collect()
}

/// One fake keyset's provider. Cloning shares the keys and the call record,
/// so the copy the cipher caches and the handle a test holds are the same
/// keyset.
pub struct FakeProvider {
    keys: Arc<FakeKeyProvider<32>>,
    calls: Arc<Mutex<Calls>>,
}

impl Clone for FakeProvider {
    fn clone(&self) -> Self {
        Self {
            keys: Arc::clone(&self.keys),
            calls: Arc::clone(&self.calls),
        }
    }
}

impl FakeProvider {
    fn new(index_key: Protected<[u8; 32]>) -> Self {
        Self {
            keys: Arc::new(FakeKeyProvider::with_index_key(index_key)),
            calls: Arc::new(Mutex::new(Calls::default())),
        }
    }

    /// What this keyset has been sent.
    pub fn calls(&self) -> Calls {
        self.lock().clone()
    }

    /// How many batched calls of each kind this keyset has served, as
    /// `(generate, retrieve)`.
    pub fn call_counts(&self) -> (usize, usize) {
        let calls = self.lock();
        (calls.generate.len(), calls.retrieve.len())
    }

    /// Forget every call recorded so far, so a test can assert on what
    /// happens after a setup step only.
    pub fn clear(&self) {
        *self.lock() = Calls::default();
    }

    /// A poisoned lock only means another test thread panicked mid-record;
    /// the record is still a valid record.
    fn lock(&self) -> MutexGuard<'_, Calls> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl KeyProvider<32> for FakeProvider {
    type Error = FakeKeyProviderError;

    const RECONSTRUCTION: KeyReconstruction =
        <FakeKeyProvider<32> as KeyProvider<32>>::RECONSTRUCTION;
    const ISOLATION: KeyIsolation = <FakeKeyProvider<32> as KeyProvider<32>>::ISOLATION;
    const BINDING: BindingSupport = <FakeKeyProvider<32> as KeyProvider<32>>::BINDING;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<32>>, Self::Error> {
        self.lock()
            .generate
            .push(record(bindings.iter().map(|b| b.as_bytes().to_vec())));
        self.keys.generate_keys(bindings).await
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<Protected<[u8; 32]>>, Self::Error> {
        self.lock()
            .retrieve
            .push(record(keys.iter().map(|(_, b)| b.as_bytes().to_vec())));
        self.keys.retrieve_keys(keys).await
    }
}

impl IndexKeyProvider<32> for FakeProvider {
    type Error = FakeKeyProviderError;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<32>, Self::Error> {
        self.keys.load_index_key().await
    }
}

/// The error a fake registry reports. It never fails to *answer* — an
/// unknown keyset is `Ok(None)`, the registry's denial — so this exists
/// only to satisfy the trait.
#[derive(Debug, thiserror::Error)]
#[error("the fake keyset registry does not fail")]
pub struct FakeRegistryError;

/// Many keysets, none of them real.
///
/// A reference this registry has not seen mints a keyset for it, seeded
/// deterministically by what was asked for — so two ciphers built
/// separately agree on what "acme" means, which is what lets one test stand
/// in for a write path and a query path in another process. That mirrors
/// the source it replaced.
///
/// [`deny`](Self::deny) makes a name resolve to `Ok(None)` instead: the
/// registry's own denial, which is what `Error::UnknownKeyset` is made
/// from. Minting on demand and denying on request are the two halves — a
/// registry that could only deny would make every test register first, and
/// one that could only mint would put the denial path out of reach.
///
/// There is deliberately no "register this name first" builder. A name's id
/// is a function of the name, so registering one could only record what
/// resolution already computes — state that cannot differ from its own
/// fallback. Reach for [`keyset`](Self::keyset) to get a handle on a
/// provider before the cipher touches it.
#[derive(Default)]
pub struct FakeKeysetRegistry {
    seeds: Mutex<HashMap<KeysetId, FakeProvider>>,
    denied: Mutex<HashMap<String, ()>>,
    resolves: Arc<AtomicUsize>,
}

/// A keyset id derived from what was asked for, so the same name always
/// means the same keyset.
fn derived_id(seed: &str) -> KeysetId {
    let mut bytes = [0u8; 16];
    // FNV-1a over the name, spread across the 16 bytes. Not a hash anyone
    // depends on — only that it is a function of the name.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seed.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    bytes[..8].copy_from_slice(&hash.to_le_bytes());
    bytes[8..].copy_from_slice(&hash.rotate_left(17).to_le_bytes());
    KeysetId::new(Uuid::from_bytes(bytes))
}

impl FakeKeysetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The id the default keyset always has.
    pub const DEFAULT_ID: Uuid = Uuid::from_u128(1);

    fn lock_seeds(&self) -> MutexGuard<'_, HashMap<KeysetId, FakeProvider>> {
        self.seeds.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The provider for `id`, minting one seeded by `seed` if this is the
    /// first time it has been asked for.
    fn provider_for(&self, id: KeysetId, seed: &str) -> FakeProvider {
        self.lock_seeds()
            .entry(id)
            .or_insert_with(|| {
                let mut material = [0u8; 32];
                for (slot, byte) in material.iter_mut().zip(seed.as_bytes().iter().cycle()) {
                    *slot = *byte;
                }
                // A seed of "" would key every keyset alike; the id is
                // always in the mix so it cannot.
                for (slot, byte) in material.iter_mut().zip(id.as_uuid().as_bytes()) {
                    *slot ^= byte;
                }
                FakeProvider::new(Protected::new(material))
            })
            .clone()
    }

    /// Every lookup of `name` from now on answers "no such keyset".
    pub fn deny(&self, name: &str) {
        let _ = self
            .denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_owned(), ());
    }

    /// Undo [`deny`](Self::deny).
    pub fn allow(&self, name: &str) {
        let _ = self
            .denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name);
    }

    fn is_denied(&self, name: &str) -> bool {
        self.denied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(name)
    }

    /// The default keyset's id, and the provider serving it.
    pub fn default_keyset(&self) -> (KeysetId, FakeProvider) {
        let id = KeysetId::new(Self::DEFAULT_ID);
        (id, self.provider_for(id, "default"))
    }

    /// The counter of [`resolve`](KeysetRegistry::resolve) calls: what
    /// loading a keyset by id or name asks the backend. A test holds the
    /// handle and reads it after the cipher has run.
    pub fn resolves(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.resolves)
    }

    /// The id and provider a name resolves to.
    pub fn keyset(&self, name: &str) -> Option<(KeysetId, FakeProvider)> {
        let id = derived_id(name);
        Some((id, self.provider_for(id, name)))
    }
}

impl KeysetRegistry for FakeKeysetRegistry {
    type Provider = FakeProvider;
    type Error = FakeRegistryError;

    async fn resolve(
        &self,
        keyset: &KeysetRef,
    ) -> Result<Option<Resolved<Self::Provider>>, Self::Error> {
        let _ = self.resolves.fetch_add(1, Ordering::SeqCst);
        let (id, name, seed) = match keyset {
            KeysetRef::Default => {
                let (id, _) = self.default_keyset();
                (id, None, "default".to_owned())
            }
            KeysetRef::Id(id) => (*id, None, id.to_string()),
            KeysetRef::Name(name) => {
                if self.is_denied(name) {
                    return Ok(None);
                }
                (derived_id(name), Some(name.clone()), name.clone())
            }
        };

        let provider = self.provider_for(id, &seed);
        Ok(Some(Resolved { id, name, provider }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn resolve(registry: &FakeKeysetRegistry, name: &str) -> Option<KeysetId> {
        registry
            .resolve(&KeysetRef::Name(name.to_owned()))
            .await
            .expect("the fake never fails to answer")
            .map(|resolved| resolved.id)
    }

    /// Minting on demand and denying on request are the two halves the fake
    /// exists for: without the first every test must register, and without
    /// the second `Error::UnknownKeyset` is unreachable.
    #[tokio::test]
    async fn a_denied_name_has_no_keyset_until_it_is_allowed_again() {
        let registry = FakeKeysetRegistry::new();

        let before = resolve(&registry, "acme")
            .await
            .expect("an unknown name mints a keyset");

        registry.deny("acme");
        assert!(
            registry.is_denied("acme"),
            "deny must record the name it was given"
        );
        assert_eq!(
            resolve(&registry, "acme").await,
            None,
            "a denied name is the registry's own `Ok(None)`, not an error"
        );
        assert!(
            resolve(&registry, "other").await.is_some(),
            "denying one name must not deny every name"
        );

        registry.allow("acme");
        assert!(!registry.is_denied("acme"));
        assert_eq!(
            resolve(&registry, "acme").await,
            Some(before),
            "allowing a name restores the same keyset, not a fresh one"
        );
    }

    /// The handle a test holds and the keyset the cipher resolves must be the
    /// same keyset, or a test that asserts on what a provider was sent is
    /// asserting about a provider nothing used.
    #[tokio::test]
    async fn the_handle_a_test_holds_is_the_keyset_the_cipher_resolves() {
        let registry = FakeKeysetRegistry::new();
        let (id, _) = registry.keyset("acme").expect("minted on demand");
        assert_eq!(resolve(&registry, "acme").await, Some(id));
    }

    /// Two ciphers built in separate processes have to agree on what a name
    /// means, which is the whole reason the id is derived rather than
    /// counted. Pinned, because a hash that is merely *a* function of the
    /// name is not enough — it must be the *same* function every run.
    #[test]
    fn a_name_always_derives_the_same_id() {
        assert_eq!(
            derived_id("acme").to_string(),
            "0fdef6f4-83d3-2407-490e-1ebcede907a7"
        );
        assert_ne!(derived_id("acme"), derived_id("acme2"));
        assert_ne!(derived_id(""), derived_id("a"));
    }
}
