//! The `_with_context` forms take anything that converts into a
//! `NonEmpty<_>` — a `nonempty!(..)` literal, a `NonEmpty::new(..)?` value,
//! a bare integer — and nothing unproven: a `&str` is not a context until it
//! has been checked, so it is turned away at the call, not at a leaf. That
//! holds on every path that reaches a leaf — a term, a struct record, a
//! plaintext-derived record, a leaf opened directly — so the proof cannot be
//! skipped by passing the raw value.
use stack_encrypt::sem::EqualityTerm;

use stack_encrypt::{DecryptInto, EncryptFrom, KeysetCipher, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

struct User {
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: StackCipherText,
}

#[derive(EncryptFrom)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
}

async fn encrypt(cipher: &KeysetCipher<'_, FakeDataKeySource>, user: User) {
    let _term: EqualityTerm = cipher.encrypt_as(&"alice", "users/email".into())
        .await
        .unwrap();
    let _row: EncryptedUser = cipher.encrypt_as(&user, "tenant/acme".into())
        .await
        .unwrap();
    let _record: EncryptedAge = cipher.encrypt_as(&42u32, "users/age".into())
        .await
        .unwrap();
}

async fn decrypt(
    cipher: &StackCipher<FakeDataKeySource>,
    row: EncryptedUser,
    sealed: StackCipherText,
) {
    let _user = cipher.decrypt_as::<User, _>(row, "tenant/acme".into())
        .await
        .unwrap();
    let _age: u32 = cipher.decrypt_as(sealed, "users/age".into()).await.unwrap();
}

fn main() {}
