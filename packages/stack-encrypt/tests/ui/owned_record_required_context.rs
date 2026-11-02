//! A `plaintext` owned record requires the caller's context: omitting it is
//! refused at the call, on both sides, however `Default` the context type is.
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
