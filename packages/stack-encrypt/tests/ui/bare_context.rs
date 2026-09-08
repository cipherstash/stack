//! The `_with_context` forms take anything that converts into a
//! `NonEmpty<_>` — a `nonempty!(..)` literal, a `NonEmpty::new(..)?` value,
//! a bare integer — and nothing unproven: a `&str` is not a context until it
//! has been checked, so it is turned away at the call, not at a leaf. That
//! holds on every path that reaches a leaf — a term, a struct record, a
//! plaintext-derived record, a leaf opened directly — so the proof cannot be
//! skipped by passing the raw value.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{DecryptInto, EncryptFrom, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

struct User {
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn encrypt(cipher: &StackCipher<FakeDataKeySource>, user: User) {
    let _term: EqualityTerm = "alice"
        .encrypt_into_with_context(cipher, "users/email")
        .await
        .unwrap();
    let _row: EncryptedUser = user
        .encrypt_into_with_context(cipher, "tenant/acme")
        .await
        .unwrap();
    let _record: EncryptedAge = 42u32
        .encrypt_into_with_context(cipher, "users/age")
        .await
        .unwrap();
}

async fn decrypt(
    cipher: &StackCipher<FakeDataKeySource>,
    row: EncryptedUser,
    sealed: StackCipherText,
) {
    let _user = User::decrypt_from_with_context(row, cipher, "tenant/acme")
        .await
        .unwrap();
    let _age: u32 = sealed.decrypt_into(cipher, "users/age").await.unwrap();
}

fn main() {}
