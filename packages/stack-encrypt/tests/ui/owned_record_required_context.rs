//! An owned record with `plaintext` requires the caller's context. A call that
//! leaves it out is a compile error, to encrypt and to decrypt, even if the
//! context type implements `Default`.
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}

fn omitted<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>, stored: SearchableEmail) {
    let _ = String::from("alice@example.com").encrypt_into::<SearchableEmail, _>(keyset);
    let _ = String::decrypt_from(stored, keyset);
}

fn main() {}
