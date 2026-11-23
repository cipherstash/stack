//! A context type that implements `IntoContext` is enough to seal a
//! ciphertext, so it must be enough for a derived record made only of
//! ciphertexts: `#[stash(context_type = AeadContext)]` declares that, and the
//! record then accepts exactly what the canonical `StackCipherText` path
//! accepts. `tests/ui/owned_aead_record_with_term.rs` pins the record such a
//! context cannot declare.
use stack_encrypt::target::{AeadContext, DecryptSource, EncryptTarget};
use stack_encrypt::{
    ContextPiece, DecryptFrom, EncryptInto, IntoContext, KeysetCipher, MaybeEmpty, NonEmpty,
    StackCipherText,
};
use stack_kms::FakeDataKeySource;

/// Declared through `AeadContext` below: it can seal, but the record
/// derives no term under it.
#[derive(Clone, Debug, PartialEq)]
struct Tenant(String);
impl MaybeEmpty for Tenant {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl<'a> IntoContext<'a> for Tenant {
    fn into_context(self) -> ContextPiece<'a> {
        self.0.into_context()
    }
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct Sealed {
    c: StackCipherText,
}

/// Two ciphertexts under the one AEAD-only context the caller passes, with
/// `decrypt` choosing the one the record opens.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct Shadowed {
    #[stash(decrypt)]
    c: StackCipherText,
    shadow: StackCipherText,
}

fn tenant() -> NonEmpty<Tenant> {
    NonEmpty::new(Tenant("acme".into())).unwrap()
}

async fn canonical(keyset: &KeysetCipher<'_, FakeDataKeySource>, value: String) {
    let leaf: StackCipherText = value
        .encrypt_into_with_context(keyset, tenant())
        .await
        .unwrap();
    let _: String = String::decrypt_from_with_context(leaf, keyset, tenant())
        .await
        .unwrap();
}

async fn derived(keyset: &KeysetCipher<'_, FakeDataKeySource>, value: String) {
    let record: Sealed = value
        .clone()
        .encrypt_into_with_context(keyset, tenant())
        .await
        .unwrap();
    let _: String = String::decrypt_from_with_context(record, keyset, tenant())
        .await
        .unwrap();
    let record: Shadowed = value
        .clone()
        .encrypt_into_with_context(keyset, tenant())
        .await
        .unwrap();
    let _: String = String::decrypt_from_with_context(record, keyset, tenant())
        .await
        .unwrap();
    let column: Vec<Sealed> = vec![value]
        .encrypt_into_with_context(keyset, tenant())
        .await
        .unwrap();
    let _: Vec<String> = Vec::decrypt_from_with_context(column, keyset, tenant())
        .await
        .unwrap();
}

fn main() {
    let _ = canonical;
    let _ = derived;
}
