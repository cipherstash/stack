//! A leaf, a record that hands the caller's context to one, and a column of
//! either all need a `NonEmpty<_>` context. A call that leaves the context
//! out does not compile, and `()` is not a context, so no leaf accepts it.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{DecryptFrom, EncryptInto, KeysetCipher, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn encrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>) {
    let _term: EqualityTerm = String::from("alice").encrypt_into(keyset).await.unwrap();
    let _record: EncryptedAge = 42u32.encrypt_into(keyset).await.unwrap();
    let _column: Vec<StackCipherText> = vec![1u32].encrypt_into(keyset).await.unwrap();
}

async fn decrypt(cipher: &StackCipher<FakeDataKeySource>, record: EncryptedAge) {
    let _age = u32::decrypt_from(record, cipher).await.unwrap();
}

async fn empty(keyset: &KeysetCipher<'_, FakeDataKeySource>, record: EncryptedAge) {
    let _term: EqualityTerm = String::from("alice")
        .encrypt_into_with_context(keyset, ())
        .await
        .unwrap();
    let _age = u32::decrypt_from_with_context(record, keyset, ())
        .await
        .unwrap();
}

fn main() {}
