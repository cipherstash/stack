//! A context type that implements `IntoContext` is enough to seal a
//! ciphertext, so it must be enough for a derived record made only of
//! ciphertexts: `#[stash(context_type = AeadContext)]` declares that, and the
//! record then accepts exactly what the canonical `StackCipherText` path
//! accepts. `tests/ui/aead_context_with_term.rs` pins the record such a
//! context cannot declare.
use stack_encrypt::target::{AeadContext};
use stack_encrypt::{ContextPiece, DecryptInto, EncryptFrom, IntoContext, KeysetCipher, MaybeEmpty, NonEmpty, StackCipherText};
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

async fn canonical(cipher: &KeysetCipher<'_, FakeDataKeySource>, value: &String) {
    let leaf: StackCipherText = cipher.encrypt_as(value, tenant().into()).await.unwrap();
    let _: String = cipher.decrypt_as(leaf, tenant().into()).await.unwrap();
}

async fn derived(cipher: &KeysetCipher<'_, FakeDataKeySource>, value: &String) {
    let record: Sealed = cipher.encrypt_as(value, tenant().into()).await.unwrap();
    let _: String = cipher.decrypt_as(record, tenant().into()).await.unwrap();
    let record: Shadowed = cipher.encrypt_as(value, tenant().into()).await.unwrap();
    let _ = cipher.decrypt_as::<String, _>(record, tenant().into()).await.unwrap();
    let column: Vec<Sealed> = cipher.encrypt_as(&vec![value.clone()], tenant().into()).await.unwrap();
    let _: Vec<String> = cipher.decrypt_as(column, tenant().into()).await.unwrap();
}

fn main() {
    let _ = canonical;
    let _ = derived;
}
