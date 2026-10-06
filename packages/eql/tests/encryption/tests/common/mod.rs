use stack_encrypt::registry::fake::{FakeKeysetRegistry, FakeProvider};
use stack_encrypt::{StackCipher, StackCipherBuilder};

/// A cipher over the fake keyset registry, and the provider of its default
/// keyset. The provider records every binding (descriptor) it is sent,
/// grouped by call: `provider.calls().generate` and `.retrieve`.
pub async fn cipher() -> (StackCipher<FakeKeysetRegistry>, FakeProvider) {
    let registry = FakeKeysetRegistry::new();
    let (_, provider) = registry.default_keyset();
    let cipher = StackCipherBuilder::new()
        .registry(registry)
        .init()
        .await
        .unwrap();
    (cipher, provider)
}
