//! A context converts from a `NonEmpty<_>`: a `nonempty!(..)` literal, a
//! `NonEmpty::new(..)?` value, or a bare integer. It does not convert from
//! anything unchecked. A `&str` is not a context until it has been checked,
//! so passing one does not compile, and the value never reaches a leaf.
//! This holds on every path to a leaf: a term, a `plaintext` record, a
//! record that stores its context, and a leaf sealed or opened directly. So
//! the check cannot be skipped by passing the raw value.
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

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct StoredEmail {
    #[stash(context_field)]
    column: &'static str,
    c: StackCipherText,
}

async fn encrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>) {
    let _term: EqualityTerm = String::from("alice")
        .encrypt_into_with_context(keyset, "users/email")
        .await
        .unwrap();
    let _record: EncryptedAge = 42u32
        .encrypt_into_with_context(keyset, "users/age")
        .await
        .unwrap();
    let _stored: StoredEmail = String::from("alice")
        .encrypt_into_with_context(keyset, "users/email")
        .await
        .unwrap();
    let _leaf: StackCipherText = 42u32
        .encrypt_into_with_context(keyset, "users/age")
        .await
        .unwrap();
}

async fn decrypt(
    cipher: &StackCipher<FakeDataKeySource>,
    record: EncryptedAge,
    sealed: StackCipherText,
) {
    let _age = u32::decrypt_from_with_context(record, cipher, "users/age")
        .await
        .unwrap();
    let _age = u32::decrypt_from_with_context(sealed, cipher, "users/age")
        .await
        .unwrap();
}

fn main() {}
