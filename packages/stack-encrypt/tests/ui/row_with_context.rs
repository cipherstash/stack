//! A row whose fields all carry their own context is implemented for `()`
//! alone: the `_with_context` forms do not compile against it, since the
//! context would go nowhere.
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{DecryptInto, EncryptFrom, StackCipher, StackCipherText};
use stack_kms::FakeDataKeySource;

struct User {
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = User)]
struct EncryptedUser {
    #[stash(from = email, context = "users/email")]
    email: StackCipherText,
}

async fn encrypt(cipher: &StackCipher<FakeDataKeySource>, user: User) {
    let _row: EncryptedUser = user
        .encrypt_into_with_context(cipher, "tenant/acme")
        .await
        .unwrap();
}

async fn decrypt(cipher: &StackCipher<FakeDataKeySource>, row: EncryptedUser) {
    let _user = User::decrypt_from_with_context(row, cipher, "tenant/acme")
        .await
        .unwrap();
}

fn main() {}
