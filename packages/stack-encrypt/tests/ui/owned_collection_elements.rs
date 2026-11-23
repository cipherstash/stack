//! A collection's elements must be opaque scalars. `u8` is not one: Vitamin
//! C keeps `Vec<u8>` one byte leaf and gives `u8` no source of its own, so a
//! byte vector is one `Ciphertext` (`tests/ui/pass/owned_collections.rs`),
//! never a column of bytes. A nullable element and a borrowed element are
//! not opaque scalars either. No vector of scalars encrypts into one
//! `Ciphertext`. On the decrypt side `u8` is refused, because it does not
//! decrypt at all. A nullable element compiles there, and opens as present
//! (`tests/scalar.rs`).
use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto};
fn unsupported<K: 'static>(keyset: &stack_encrypt::KeysetCipher<'_, K>, column: Vec<Ciphertext>) {
    let _ = vec![1u8, 2].encrypt_into::<Vec<Ciphertext>, _>(keyset);
    let _ = vec![Some(1i32), None].encrypt_into::<Vec<Ciphertext>, _>(keyset);
    let _ = EncryptInto::encrypt_into::<Vec<Ciphertext>, _>(vec!["borrowed", "plaintext"], keyset);
    let _ = vec![1i32, 2].encrypt_into::<Ciphertext, _>(keyset);
    let _ = Vec::<u8>::decrypt_from(column, keyset);
}
fn main() {}
