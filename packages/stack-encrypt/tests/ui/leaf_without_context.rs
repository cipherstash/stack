//! A leaf, a record that hands the caller's context to one, and a column of
//! either all need a `NonEmpty<_>` context: the context-free `encrypt_into`
//! / `decrypt_from` pass `()`, which no leaf accepts.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{DecryptInto, EncryptFrom, KeysetCipher, StackCipher, StackCipherText};
use stack_encrypt::registry::fake::FakeKeysetRegistry;

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn encrypt(cipher: &KeysetCipher<'_, FakeKeysetRegistry>) {
    let _term: EqualityTerm = "alice".encrypt_into(cipher).await.unwrap();
    let _record: EncryptedAge = 42u32.encrypt_into(cipher).await.unwrap();
    let _column: Vec<StackCipherText> = vec![1u32].encrypt_into(cipher).await.unwrap();
}

async fn decrypt(cipher: &StackCipher<FakeKeysetRegistry>, record: EncryptedAge) {
    let _age = u32::decrypt_from(record, cipher).await.unwrap();
}

async fn decrypt_leaf(cipher: &StackCipher<FakeKeysetRegistry>, record: EncryptedAge) {
    let _age: u32 = record.decrypt_into(cipher, ()).await.unwrap();
}

fn main() {}
