//! A context type that implements `IntoContext` is enough to seal a
//! ciphertext, so it must be enough for a derived record made only of
//! ciphertexts: `#[stash(context_type = AeadContext)]` declares that, and the
//! record then accepts exactly what the canonical `StackCipherText` path
//! accepts. `tests/ui/aead_context_with_term.rs` pins the record such a
//! context cannot declare.
use stack_encrypt::target::{AeadContext, DecryptFrom, EncryptInto};
use stack_encrypt::{ContextPiece, DecryptInto, EncryptFrom, IntoContext, KeysetCipher, MaybeEmpty, NonEmpty, StackCipherText};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

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

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = AeadContext)]
struct Sealed {
    c: StackCipherText,
}

/// Two ciphertexts under the one AEAD-only context the caller passes, with
/// `decrypt` choosing the one the record opens.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = AeadContext)]
struct Shadowed {
    #[stash(decrypt)]
    c: StackCipherText,
    shadow: StackCipherText,
}

fn tenant() -> NonEmpty<Tenant> {
    NonEmpty::new(Tenant("acme".into())).unwrap()
}

async fn canonical(cipher: &KeysetCipher<'_, FakeKeysetRegistry>, value: &String) {
    let leaf: StackCipherText = value.encrypt_into_with_context(cipher, tenant()).await.unwrap();
    let _: String = leaf.decrypt_into(cipher, tenant()).await.unwrap();
}

async fn derived(cipher: &KeysetCipher<'_, FakeKeysetRegistry>, value: &String) {
    let record: Sealed = value.encrypt_into_with_context(cipher, tenant()).await.unwrap();
    let _: String = record.decrypt_into(cipher, tenant()).await.unwrap();
    let record: Shadowed = value.encrypt_into_with_context(cipher, tenant()).await.unwrap();
    let _ = String::decrypt_from_with_context(record, cipher, tenant()).await.unwrap();
    let column: Vec<Sealed> = vec![value.clone()].encrypt_into_with_context(cipher, tenant()).await.unwrap();
    let _: Vec<String> = column.decrypt_into(cipher, tenant()).await.unwrap();
}

fn main() {
    let _ = canonical;
    let _ = derived;
}
