//! A `struct = ..` record takes no caller context. Each field's context is
//! the record's name, then the field's name. A part the caller supplies must
//! be declared on the record first, so passing one to a record that declares
//! none is a compile error, to encrypt and to decrypt.
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};
use zeroize::Zeroize;

#[derive(Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: Ciphertext,
}

fn supplied<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>, stored: EncryptedUser) {
    let user = User {
        email: "alice@example.com".to_owned(),
    };
    let _ = user.encrypt_into_with_context::<EncryptedUser, _>(keyset, 42u64);
    let _ = User::decrypt_from_with_context(stored, keyset, 42u64);
}

fn main() {}
