//! A leaf, a record that hands the caller's context to one, and a column of
//! either all need a `NonEmpty<_>` context: a default context, or `()`, is
//! not one, so no leaf accepts it.
use stack_encrypt::sem::EqualityTerm;

use stack_encrypt::{DecryptInto, EncryptFrom, KeysetCipher, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn encrypt(cipher: &KeysetCipher<'_, FakeDataKeySource>) {
    let _term: EqualityTerm = cipher.encrypt_as(&"alice", Default::default()).await.unwrap();
    let _record: EncryptedAge = cipher.encrypt_as(&42u32, Default::default()).await.unwrap();
    let _column: Vec<StackCipherText> =
        cipher.encrypt_as(&vec![1u32], Default::default()).await.unwrap();
}

async fn decrypt(cipher: &StackCipher<FakeDataKeySource>, record: EncryptedAge) {
    let _age: u32 = cipher.decrypt_as(record, Default::default()).await.unwrap();
}

async fn decrypt_leaf(cipher: &StackCipher<FakeDataKeySource>, record: EncryptedAge) {
    let _age: u32 = cipher.decrypt_as(record, ().into()).await.unwrap();
}

fn main() {}
